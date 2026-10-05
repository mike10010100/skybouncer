//! Challenger 2 Empirical Test Suite: Dynamic State Machine Lifecycle & Firehose Synchronization.
//!
//! # Challenge Dimensions Tested:
//! 1. Rapid follow/unfollow state machine oscillations with strict classifier call-count accounting.
//! 2. Duplicate follow creation with distinct `rkey`s pointing to the same followed DID (multi-rkey retention).
//! 3. Deletion commits for non-existent, untracked, empty, or foreign `rkey`s returning `FollowSyncEvent::Ignored`.
//! 4. Multi-target posts where one target follows and another does not (friend vs stranger independent decisions).
//! 5. Multi-target posts containing self-interactions, friends, and strangers evaluated concurrently.
//! 6. Single post multi-vector deduplication (reply + mention + quote targeting same protected user).
//! 7. Dynamic follow `CommitOperation::Update` subject replacement and reverse index cleanup.
//! 8. Malformed follow payloads (missing subject, invalid types, empty strings).
//! 9. High-frequency concurrent race conditions between dynamic firehose mutations and candidate evaluations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    clippy::needless_range_loop
)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::json;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};
use skybouncer::classifier::{Classifier, MockClassifier};
use skybouncer::matcher::{
    BypassReason, FollowGraph, FollowSyncEvent, GateDecision, InteractionType, NonFollowedGate,
    TargetMatcher,
};

const PROTECTED_ALICE: &str = "did:plc:protected_alice";
const PROTECTED_BOB: &str = "did:plc:protected_bob";
const CANDIDATE_CHARLIE: &str = "did:plc:candidate_charlie";
const STRANGER_DAVE: &str = "did:plc:stranger_dave";

/// Helper building a commit that mentions multiple DIDs simultaneously.
fn make_multi_mention_commit(
    author_did: &str,
    mentioned_dids: &[&str],
    rkey: &str,
    text: &str,
) -> JetstreamCommit {
    let mut facets = Vec::new();
    let mut byte_offset = 0;

    for did in mentioned_dids {
        let length = did.len();
        facets.push(json!({
            "index": {
                "byteStart": byte_offset,
                "byteEnd": byte_offset + length
            },
            "features": [
                {
                    "$type": "app.bsky.richtext.facet#mention",
                    "did": did
                }
            ]
        }));
        byte_offset += length + 1;
    }

    JetstreamCommit {
        did: author_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafymultimentioncid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "facets": facets,
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

/// Helper building an app.bsky.graph.follow update commit.
fn make_follow_update_commit(
    follower_did: &str,
    followed_did: &str,
    rkey: &str,
) -> JetstreamCommit {
    JetstreamCommit {
        did: follower_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Update,
        cid: Some("bafyfollowupdatecid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.graph.follow",
            "subject": followed_did,
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

// ============================================================================
// 1. Rapid Follow/Unfollow State Machine Oscillations
// ============================================================================

#[tokio::test]
async fn test_rapid_follow_unfollow_single_account_oscillations() {
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    let target_author = CANDIDATE_CHARLIE;
    let cycles = 50;
    let mut expected_classifier_calls = 0;

    for i in 0..cycles {
        // --- Phase A: Author is UNFOLLOWED ---
        assert!(
            !graph.is_following(PROTECTED_ALICE, target_author),
            "Cycle {i}: Must not be following before follow event"
        );

        let unfollowed_commit = make_reply_commit(
            target_author,
            PROTECTED_ALICE,
            &format!("unfollowed_post_{i}"),
            "p0",
            "Unfollowed post",
        );
        let interaction_unfollowed =
            TargetMatcher::match_interaction(&unfollowed_commit, &protected_dids)
                .expect("interaction must match");
        let candidate = gate
            .filter(interaction_unfollowed)
            .expect("must pass gate as candidate");
        let _ = classifier.classify(&candidate).await.expect("classify ok");
        expected_classifier_calls += 1;
        assert_eq!(
            classifier.call_count(),
            expected_classifier_calls,
            "Cycle {i}: Unfollowed candidate must increment classifier call count"
        );

        // --- Phase B: Follow Event Ingested ---
        let rkey = format!("rapid_rkey_{i}");
        let follow_commit = make_follow_create_commit(PROTECTED_ALICE, target_author, &rkey);
        let event = graph.handle_commit(&follow_commit, &protected_dids);
        assert_eq!(
            event,
            FollowSyncEvent::FollowAdded {
                protected_did: PROTECTED_ALICE.to_string(),
                rkey: rkey.clone(),
                followed_did: target_author.to_string(),
            }
        );
        assert!(
            graph.is_following(PROTECTED_ALICE, target_author),
            "Cycle {i}: Must be following after follow event"
        );

        // --- Phase C: Author is FOLLOWED -> Bypassed ---
        let followed_commit = make_reply_commit(
            target_author,
            PROTECTED_ALICE,
            &format!("followed_post_{i}"),
            "p0",
            "Followed post",
        );
        let interaction_followed =
            TargetMatcher::match_interaction(&followed_commit, &protected_dids)
                .expect("interaction must match");
        let bypassed = gate.filter(interaction_followed);
        assert!(
            bypassed.is_none(),
            "Cycle {i}: Followed author must be bypassed with $0 cost"
        );
        assert_eq!(
            classifier.call_count(),
            expected_classifier_calls,
            "Cycle {i}: Bypassed author must NOT increment classifier call count"
        );

        // --- Phase D: Unfollow Event Ingested (Delete commit with record: None) ---
        let unfollow_commit = make_follow_delete_commit(PROTECTED_ALICE, &rkey);
        let del_event = graph.handle_commit(&unfollow_commit, &protected_dids);
        assert_eq!(
            del_event,
            FollowSyncEvent::FollowRemoved {
                protected_did: PROTECTED_ALICE.to_string(),
                rkey,
                followed_did: target_author.to_string(),
            }
        );
        assert!(
            !graph.is_following(PROTECTED_ALICE, target_author),
            "Cycle {i}: Must not be following after unfollow event"
        );
    }

    // Verify final state
    assert_eq!(classifier.call_count(), cycles);
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
    assert_eq!(graph.total_follows_count(), 0);

    // Architectural observation: FollowGraph retains the outer key for Alice in guard.follows
    // even when its inner HashSet is empty. Thus total_protected_users() remains 1 and is_empty()
    // is false until clear() is explicitly called.
    assert_eq!(graph.total_protected_users(), 1);
    assert!(!graph.is_empty());

    graph.clear();
    assert!(graph.is_empty());
    assert_eq!(graph.total_protected_users(), 0);
}

#[tokio::test]
async fn test_rapid_interleaved_multi_account_state_machine() {
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    let authors = [
        "did:plc:author_alpha",
        "did:plc:author_beta",
        "did:plc:author_gamma",
    ];

    let mut expected_calls = 0;

    for step in 0..60 {
        let author_idx = step % authors.len();
        let author = authors[author_idx];

        let currently_following = graph.is_following(PROTECTED_ALICE, author);

        if currently_following {
            // Unfollow author
            let active_rkey = format!("active_rk_{author_idx}");
            let unfollow_commit = make_follow_delete_commit(PROTECTED_ALICE, &active_rkey);
            let event = graph.handle_commit(&unfollow_commit, &protected_dids);
            assert!(matches!(event, FollowSyncEvent::FollowRemoved { .. }));
        } else {
            // Follow author
            let active_rkey = format!("active_rk_{author_idx}");
            let follow_commit = make_follow_create_commit(PROTECTED_ALICE, author, &active_rkey);
            let event = graph.handle_commit(&follow_commit, &protected_dids);
            assert!(matches!(event, FollowSyncEvent::FollowAdded { .. }));
        }

        // Now test interaction from each of the 3 authors
        for (idx, a) in authors.iter().enumerate() {
            let commit = make_reply_commit(
                a,
                PROTECTED_ALICE,
                &format!("interleaved_post_{step}_{idx}"),
                "root",
                "Interleaved message",
            );
            let interaction = TargetMatcher::match_interaction(&commit, &protected_dids)
                .expect("interaction match");
            let decision = gate.evaluate(interaction);

            if graph.is_following(PROTECTED_ALICE, a) {
                assert!(
                    decision.is_bypassed(),
                    "Author {a} is followed and must be bypassed at step {step}"
                );
            } else {
                assert!(
                    decision.is_candidate(),
                    "Author {a} is unfollowed and must be candidate at step {step}"
                );
                let cand = decision.into_candidate().expect("candidate exists");
                let _ = classifier.classify(&cand).await.expect("classify ok");
                expected_calls += 1;
            }
        }

        assert_eq!(classifier.call_count(), expected_calls);
    }
}

// ============================================================================
// 2. Duplicate Follows with Distinct Rkeys (Multi-Rkey Retention)
// ============================================================================

#[tokio::test]
async fn test_duplicate_follows_with_distinct_rkeys_retention_and_deletion() {
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    let subject = CANDIDATE_CHARLIE;

    // 1. Initial interaction: subject is unfollowed -> candidate
    let commit0 = make_reply_commit(subject, PROTECTED_ALICE, "p0", "root", "Hello");
    let match0 = TargetMatcher::match_interaction(&commit0, &protected_dids).expect("match");
    let cand0 = gate.filter(match0).expect("candidate");
    let _ = classifier.classify(&cand0).await.expect("classify ok");
    assert_eq!(classifier.call_count(), 1);

    // 2. Add 3 distinct follow records for the SAME subject (simulating multi-device or sync race)
    let follow1 = make_follow_create_commit(PROTECTED_ALICE, subject, "rkey_alpha");
    let follow2 = make_follow_create_commit(PROTECTED_ALICE, subject, "rkey_beta");
    let follow3 = make_follow_create_commit(PROTECTED_ALICE, subject, "rkey_gamma");

    assert_eq!(
        graph.handle_commit(&follow1, &protected_dids),
        FollowSyncEvent::FollowAdded {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "rkey_alpha".to_string(),
            followed_did: subject.to_string(),
        }
    );
    assert_eq!(
        graph.handle_commit(&follow2, &protected_dids),
        FollowSyncEvent::FollowAdded {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "rkey_beta".to_string(),
            followed_did: subject.to_string(),
        }
    );
    assert_eq!(
        graph.handle_commit(&follow3, &protected_dids),
        FollowSyncEvent::FollowAdded {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "rkey_gamma".to_string(),
            followed_did: subject.to_string(),
        }
    );

    // Only 1 unique followed DID, but 3 tracked rkeys
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);
    assert!(graph.contains_rkey(PROTECTED_ALICE, "rkey_alpha"));
    assert!(graph.contains_rkey(PROTECTED_ALICE, "rkey_beta"));
    assert!(graph.contains_rkey(PROTECTED_ALICE, "rkey_gamma"));
    assert!(graph.is_following(PROTECTED_ALICE, subject));

    // Interaction while followed -> bypassed -> classifier calls = 1
    let commit1 = make_reply_commit(subject, PROTECTED_ALICE, "p1", "root", "Followed message");
    let match1 = TargetMatcher::match_interaction(&commit1, &protected_dids).expect("match");
    assert!(gate.filter(match1).is_none());
    assert_eq!(classifier.call_count(), 1);

    // 3. Delete FIRST rkey (`rkey_alpha`)
    let del1 = make_follow_delete_commit(PROTECTED_ALICE, "rkey_alpha");
    let event1 = graph.handle_commit(&del1, &protected_dids);
    assert_eq!(
        event1,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "rkey_alpha".to_string(),
            followed_did: subject.to_string(),
        }
    );
    assert!(!graph.contains_rkey(PROTECTED_ALICE, "rkey_alpha"));

    // CRITICAL INVARIANT: Subject MUST REMAIN FOLLOWED because rkey_beta and rkey_gamma still exist!
    assert!(
        graph.is_following(PROTECTED_ALICE, subject),
        "Subject must remain followed as other rkeys exist"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Interaction after 1st delete -> still bypassed -> classifier calls = 1
    let commit2 = make_reply_commit(subject, PROTECTED_ALICE, "p2", "root", "Still followed");
    let match2 = TargetMatcher::match_interaction(&commit2, &protected_dids).expect("match");
    assert!(gate.filter(match2).is_none());
    assert_eq!(classifier.call_count(), 1);

    // 4. Delete SECOND rkey (`rkey_beta`)
    let del2 = make_follow_delete_commit(PROTECTED_ALICE, "rkey_beta");
    let event2 = graph.handle_commit(&del2, &protected_dids);
    assert_eq!(
        event2,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "rkey_beta".to_string(),
            followed_did: subject.to_string(),
        }
    );
    assert!(!graph.contains_rkey(PROTECTED_ALICE, "rkey_beta"));

    // CRITICAL INVARIANT: Subject STILL REMAINS FOLLOWED because rkey_gamma still exists!
    assert!(
        graph.is_following(PROTECTED_ALICE, subject),
        "Subject must remain followed as rkey_gamma exists"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Interaction after 2nd delete -> still bypassed -> classifier calls = 1
    let commit3 = make_reply_commit(subject, PROTECTED_ALICE, "p3", "root", "Still followed 2");
    let match3 = TargetMatcher::match_interaction(&commit3, &protected_dids).expect("match");
    assert!(gate.filter(match3).is_none());
    assert_eq!(classifier.call_count(), 1);

    // 5. Delete THIRD and FINAL rkey (`rkey_gamma`)
    let del3 = make_follow_delete_commit(PROTECTED_ALICE, "rkey_gamma");
    let event3 = graph.handle_commit(&del3, &protected_dids);
    assert_eq!(
        event3,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "rkey_gamma".to_string(),
            followed_did: subject.to_string(),
        }
    );
    assert!(!graph.contains_rkey(PROTECTED_ALICE, "rkey_gamma"));

    // NOW subject is completely unfollowed
    assert!(
        !graph.is_following(PROTECTED_ALICE, subject),
        "Subject must now be unfollowed"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);

    // Interaction after final delete -> candidate -> classifier called!
    let commit4 = make_reply_commit(subject, PROTECTED_ALICE, "p4", "root", "Now stranger");
    let match4 = TargetMatcher::match_interaction(&commit4, &protected_dids).expect("match");
    let cand4 = gate.filter(match4).expect("must pass gate as candidate");
    let _ = classifier.classify(&cand4).await.expect("classify ok");
    assert_eq!(
        classifier.call_count(),
        2,
        "Classifier call count must increment to 2"
    );

    // 6. Redundant delete of already deleted rkey -> Ignored, no panic
    let del_redundant = make_follow_delete_commit(PROTECTED_ALICE, "rkey_alpha");
    assert_eq!(
        graph.handle_commit(&del_redundant, &protected_dids),
        FollowSyncEvent::Ignored
    );
    assert_eq!(classifier.call_count(), 2);
}

#[test]
fn test_duplicate_follow_same_rkey_reinsert_idempotence() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    let subject = CANDIDATE_CHARLIE;

    // Follow with rkey_1
    let follow1 = make_follow_create_commit(PROTECTED_ALICE, subject, "rkey_1");
    graph.handle_commit(&follow1, &protected_dids);
    assert!(graph.is_following(PROTECTED_ALICE, subject));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Re-insert exact same rkey and subject (duplicate commit from replayed firehose)
    let follow_dup = make_follow_create_commit(PROTECTED_ALICE, subject, "rkey_1");
    graph.handle_commit(&follow_dup, &protected_dids);
    assert!(graph.is_following(PROTECTED_ALICE, subject));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Delete rkey_1 -> must cleanly remove subject
    let del = make_follow_delete_commit(PROTECTED_ALICE, "rkey_1");
    let event = graph.handle_commit(&del, &protected_dids);
    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "rkey_1".to_string(),
            followed_did: subject.to_string(),
        }
    );
    assert!(!graph.is_following(PROTECTED_ALICE, subject));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
}

// ============================================================================
// 3. Deletion Commits for Non-Existent or Untracked Rkeys
// ============================================================================

#[test]
fn test_deletion_of_untracked_rkey_scenarios() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());
    protected_dids.insert(PROTECTED_BOB.to_string());

    // Populate Alice with an active follow
    graph.add_follow(PROTECTED_ALICE, "valid_rk_1", CANDIDATE_CHARLIE);
    assert!(graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Scenario 1: Delete non-existent rkey on protected user WITH active follows
    let del1 = make_follow_delete_commit(PROTECTED_ALICE, "non_existent_rkey_999");
    assert_eq!(
        graph.handle_commit(&del1, &protected_dids),
        FollowSyncEvent::Ignored
    );
    // Active follow must remain completely intact
    assert!(graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Scenario 2: Delete non-existent rkey on protected user with NO follows
    let del2 = make_follow_delete_commit(PROTECTED_BOB, "rk_for_bob");
    assert_eq!(
        graph.handle_commit(&del2, &protected_dids),
        FollowSyncEvent::Ignored
    );
    assert_eq!(graph.follow_count(PROTECTED_BOB), 0);

    // Scenario 3: Delete commit from a DID NOT in protected_dids
    let del3 = make_follow_delete_commit("did:plc:untracked_stranger", "rk_stranger");
    assert_eq!(
        graph.handle_commit(&del3, &protected_dids),
        FollowSyncEvent::Ignored
    );

    // Scenario 4: Delete commit with empty string rkey
    let del4 = make_follow_delete_commit(PROTECTED_ALICE, "");
    assert_eq!(
        graph.handle_commit(&del4, &protected_dids),
        FollowSyncEvent::Ignored
    );
    assert!(graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));

    // Scenario 5: Delete commit with special characters and unicode rkey
    let del5 = make_follow_delete_commit(PROTECTED_ALICE, "🔥_🦀_unicode_rkey_!@#$%^&*()");
    assert_eq!(
        graph.handle_commit(&del5, &protected_dids),
        FollowSyncEvent::Ignored
    );
    assert!(graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));

    // Direct removal by rkey returns None
    assert_eq!(
        graph.remove_follow_by_rkey(PROTECTED_ALICE, "ghost_rkey"),
        None
    );
    assert_eq!(
        graph.remove_follow_by_rkey("did:plc:unregistered", "ghost_rkey"),
        None
    );
}

// ============================================================================
// 4. Multi-Target Posts: Friend vs Stranger Independent Evaluation
// ============================================================================

#[tokio::test]
async fn test_multi_target_post_one_friend_one_stranger_independent_decisions() {
    let graph = Arc::new(FollowGraph::new());
    // Alice follows Charlie (friend)
    graph.add_follow(PROTECTED_ALICE, "rk_charlie", CANDIDATE_CHARLIE);
    // Bob does NOT follow Charlie (stranger)

    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());
    protected_dids.insert(PROTECTED_BOB.to_string());

    // Charlie posts a single message mentioning both Alice and Bob
    let multi_commit = make_multi_mention_commit(
        CANDIDATE_CHARLIE,
        &[PROTECTED_ALICE, PROTECTED_BOB],
        "multi_post_1",
        "Hello @alice and @bob, check this out!",
    );

    // TargetMatcher should extract 2 distinct interactions
    let interactions = TargetMatcher::match_all_interactions(&multi_commit, &protected_dids);
    assert_eq!(
        interactions.len(),
        2,
        "Single post targeting 2 protected users must produce 2 interactions"
    );

    let mut evaluated_candidates = Vec::new();
    let mut bypassed_count = 0;

    for interaction in interactions {
        let decision = gate.evaluate(interaction);
        match decision {
            GateDecision::Candidate(cand) => {
                let _ = classifier.classify(&cand).await.expect("classify ok");
                evaluated_candidates.push(cand);
            }
            GateDecision::Bypassed {
                reason,
                interaction,
            } => {
                assert_eq!(reason, BypassReason::FollowedAuthor);
                assert_eq!(interaction.target_did, PROTECTED_ALICE);
                bypassed_count += 1;
            }
        }
    }

    // Assertions:
    // 1. Alice's interaction was bypassed (0 classifier calls)
    assert_eq!(bypassed_count, 1, "Alice's interaction must be bypassed");

    // 2. Bob's interaction was evaluated as candidate
    assert_eq!(
        evaluated_candidates.len(),
        1,
        "Bob's interaction must be evaluated"
    );
    assert_eq!(evaluated_candidates[0].target_did, PROTECTED_BOB);
    assert_eq!(evaluated_candidates[0].author_did, CANDIDATE_CHARLIE);

    // 3. MockClassifier call count MUST be strictly 1
    assert_eq!(
        classifier.call_count(),
        1,
        "MockClassifier must be called strictly once for the stranger target"
    );
}

#[tokio::test]
async fn test_multi_target_post_both_friends_zero_classifier_calls() {
    let graph = Arc::new(FollowGraph::new());
    // Both Alice and Bob follow Charlie
    graph.add_follow(PROTECTED_ALICE, "rk_a", CANDIDATE_CHARLIE);
    graph.add_follow(PROTECTED_BOB, "rk_b", CANDIDATE_CHARLIE);

    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());
    protected_dids.insert(PROTECTED_BOB.to_string());

    let multi_commit = make_multi_mention_commit(
        CANDIDATE_CHARLIE,
        &[PROTECTED_ALICE, PROTECTED_BOB],
        "multi_post_2",
        "Hello mutual friends @alice and @bob",
    );

    let interactions = TargetMatcher::match_all_interactions(&multi_commit, &protected_dids);
    assert_eq!(interactions.len(), 2);

    for interaction in interactions {
        if let Some(candidate) = gate.filter(interaction) {
            let _ = classifier.classify(&candidate).await.expect("classify ok");
        }
    }

    // Both interactions bypassed at $0 cost -> zero classifier calls!
    assert_eq!(
        classifier.call_count(),
        0,
        "When all targets follow the author, classifier call count must strictly be 0"
    );
}

#[tokio::test]
async fn test_multi_target_post_both_strangers_two_classifier_calls() {
    let graph = Arc::new(FollowGraph::new());
    // Neither Alice nor Bob follows Charlie

    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());
    protected_dids.insert(PROTECTED_BOB.to_string());

    let multi_commit = make_multi_mention_commit(
        CANDIDATE_CHARLIE,
        &[PROTECTED_ALICE, PROTECTED_BOB],
        "multi_post_3",
        "Spamming both @alice and @bob",
    );

    let interactions = TargetMatcher::match_all_interactions(&multi_commit, &protected_dids);
    assert_eq!(interactions.len(), 2);

    for interaction in interactions {
        if let Some(candidate) = gate.filter(interaction) {
            let _ = classifier.classify(&candidate).await.expect("classify ok");
        }
    }

    assert_eq!(
        classifier.call_count(),
        2,
        "When neither target follows author, classifier call count must strictly be 2"
    );
}

#[tokio::test]
async fn test_multi_target_post_with_self_interaction_and_friend_and_stranger() {
    let graph = Arc::new(FollowGraph::new());
    // Alice is author and protected.
    // Bob is protected and follows Alice.
    // Dave is protected and does NOT follow Alice.
    graph.add_follow(PROTECTED_BOB, "rk_b_a", PROTECTED_ALICE);

    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());
    protected_dids.insert(PROTECTED_BOB.to_string());
    protected_dids.insert(STRANGER_DAVE.to_string());

    // Alice writes a post mentioning herself (@alice), her friend Bob (@bob), and stranger Dave (@dave)
    let commit = make_multi_mention_commit(
        PROTECTED_ALICE,
        &[PROTECTED_ALICE, PROTECTED_BOB, STRANGER_DAVE],
        "alice_trio_post",
        "Trip report with @alice, @bob, and @dave",
    );

    let interactions = TargetMatcher::match_all_interactions(&commit, &protected_dids);
    assert_eq!(interactions.len(), 3);

    let mut self_bypassed = 0;
    let mut friend_bypassed = 0;
    let mut candidate_count = 0;

    for interaction in interactions {
        let decision = gate.evaluate(interaction);
        match decision {
            GateDecision::Candidate(cand) => {
                assert_eq!(cand.target_did, STRANGER_DAVE);
                assert_eq!(cand.author_did, PROTECTED_ALICE);
                let _ = classifier.classify(&cand).await.expect("classify ok");
                candidate_count += 1;
            }
            GateDecision::Bypassed {
                reason,
                interaction,
            } => match reason {
                BypassReason::SelfInteraction => {
                    assert_eq!(interaction.target_did, PROTECTED_ALICE);
                    assert_eq!(interaction.author_did, PROTECTED_ALICE);
                    self_bypassed += 1;
                }
                BypassReason::FollowedAuthor => {
                    assert_eq!(interaction.target_did, PROTECTED_BOB);
                    assert_eq!(interaction.author_did, PROTECTED_ALICE);
                    friend_bypassed += 1;
                }
                BypassReason::FollowerAuthor => {
                    panic!("Unexpected incoming follower in this test");
                }
                BypassReason::AllowlistedAuthor => {
                    panic!("Unexpected allowlisted author in this test");
                }
            },
        }
    }

    assert_eq!(self_bypassed, 1, "Alice self-interaction must be bypassed");
    assert_eq!(friend_bypassed, 1, "Bob followed-author must be bypassed");
    assert_eq!(candidate_count, 1, "Dave stranger must be candidate");
    assert_eq!(classifier.call_count(), 1, "Exact 1 classifier call");
}

// ============================================================================
// 5. Single Post Multi-Vector Deduplication
// ============================================================================

#[test]
fn test_single_post_multi_vector_same_target_deduplication() {
    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    // Author Charlie posts a single message that:
    // 1. Direct replies to Alice's post
    // 2. Mentions Alice in facets
    // 3. Quotes Alice's post in embed
    let commit = JetstreamCommit {
        did: CANDIDATE_CHARLIE.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: "multi_vector_1".to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafymultivectorcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": "Replying to @alice and quoting her",
            "reply": {
                "parent": {
                    "uri": format!("at://{PROTECTED_ALICE}/app.bsky.feed.post/alice_p1"),
                    "cid": "bafyparent"
                },
                "root": {
                    "uri": format!("at://{PROTECTED_ALICE}/app.bsky.feed.post/alice_p1"),
                    "cid": "bafyparent"
                }
            },
            "facets": [
                {
                    "index": { "byteStart": 12, "byteEnd": 18 },
                    "features": [{ "$type": "app.bsky.richtext.facet#mention", "did": PROTECTED_ALICE }]
                }
            ],
            "embed": {
                "$type": "app.bsky.embed.record",
                "record": {
                    "uri": format!("at://{PROTECTED_ALICE}/app.bsky.feed.post/alice_p1"),
                    "cid": "bafyquoted"
                }
            },
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    };

    let interactions = TargetMatcher::match_all_interactions(&commit, &protected_dids);
    // Must produce EXACTLY 1 interaction for Alice, prioritizing direct reply
    assert_eq!(
        interactions.len(),
        1,
        "Multiple vectors targeting the same user must be deduplicated to 1"
    );
    assert_eq!(interactions[0].target_did, PROTECTED_ALICE);
    assert_eq!(
        interactions[0].interaction_type,
        InteractionType::DirectReply
    );
}

// ============================================================================
// 6. Dynamic Follow CommitOperation::Update Subject Replacement
// ============================================================================

#[tokio::test]
async fn test_follow_commit_update_operation_replaces_subject() {
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    let rkey = "modifiable_follow_rkey";

    // Step 1: Alice follows Bob with `rkey`
    let create_commit = make_follow_create_commit(PROTECTED_ALICE, PROTECTED_BOB, rkey);
    graph.handle_commit(&create_commit, &protected_dids);
    assert!(graph.is_following(PROTECTED_ALICE, PROTECTED_BOB));
    assert!(!graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));

    // Bob post is bypassed; Charlie post is candidate
    let bob_commit = make_reply_commit(PROTECTED_BOB, PROTECTED_ALICE, "b1", "r", "Hey");
    let match_bob = TargetMatcher::match_interaction(&bob_commit, &protected_dids).expect("match");
    assert!(gate.filter(match_bob).is_none());
    assert_eq!(classifier.call_count(), 0);

    let charlie_commit = make_reply_commit(CANDIDATE_CHARLIE, PROTECTED_ALICE, "c1", "r", "Hello");
    let match_charlie =
        TargetMatcher::match_interaction(&charlie_commit, &protected_dids).expect("match");
    let cand_charlie = gate.filter(match_charlie).expect("candidate");
    let _ = classifier.classify(&cand_charlie).await.expect("classify");
    assert_eq!(classifier.call_count(), 1);

    // Step 2: Ingest CommitOperation::Update changing subject of `rkey` from Bob to Charlie
    let update_commit = make_follow_update_commit(PROTECTED_ALICE, CANDIDATE_CHARLIE, rkey);
    let event = graph.handle_commit(&update_commit, &protected_dids);
    assert_eq!(
        event,
        FollowSyncEvent::FollowAdded {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: rkey.to_string(),
            followed_did: CANDIDATE_CHARLIE.to_string(),
        }
    );

    // INVARIANT: Alice now follows Charlie and NO LONGER follows Bob!
    assert!(
        graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE),
        "Charlie is now followed"
    );
    assert!(
        !graph.is_following(PROTECTED_ALICE, PROTECTED_BOB),
        "Bob is no longer followed"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Step 3: Now Charlie is bypassed, and Bob is candidate!
    let charlie_commit2 = make_reply_commit(
        CANDIDATE_CHARLIE,
        PROTECTED_ALICE,
        "c2",
        "r",
        "Followed now",
    );
    let match_charlie2 =
        TargetMatcher::match_interaction(&charlie_commit2, &protected_dids).expect("match");
    assert!(
        gate.filter(match_charlie2).is_none(),
        "Charlie must now be bypassed"
    );
    assert_eq!(classifier.call_count(), 1);

    let bob_commit2 = make_reply_commit(PROTECTED_BOB, PROTECTED_ALICE, "b2", "r", "Stranger now");
    let match_bob2 =
        TargetMatcher::match_interaction(&bob_commit2, &protected_dids).expect("match");
    let cand_bob2 = gate
        .filter(match_bob2)
        .expect("Bob must now pass gate as candidate");
    let _ = classifier.classify(&cand_bob2).await.expect("classify");
    assert_eq!(
        classifier.call_count(),
        2,
        "Classifier call count must increment to 2 for Bob"
    );
}

// ============================================================================
// 7. Malformed Follow Commit Payloads Ingestion Resilience
// ============================================================================

#[test]
fn test_malformed_follow_commits_handled_gracefully() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    // 1. Missing record payload
    let commit1 = JetstreamCommit {
        did: PROTECTED_ALICE.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: "bad_rk_1".to_string(),
        operation: CommitOperation::Create,
        cid: None,
        record: None,
    };
    assert_eq!(
        graph.handle_commit(&commit1, &protected_dids),
        FollowSyncEvent::Ignored
    );

    // 2. Missing "subject" field in record
    let commit2 = JetstreamCommit {
        did: PROTECTED_ALICE.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: "bad_rk_2".to_string(),
        operation: CommitOperation::Create,
        cid: None,
        record: Some(json!({
            "$type": "app.bsky.graph.follow",
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    };
    assert_eq!(
        graph.handle_commit(&commit2, &protected_dids),
        FollowSyncEvent::Ignored
    );

    // 3. Null "subject" field
    let commit3 = JetstreamCommit {
        did: PROTECTED_ALICE.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: "bad_rk_3".to_string(),
        operation: CommitOperation::Create,
        cid: None,
        record: Some(json!({
            "$type": "app.bsky.graph.follow",
            "subject": null,
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    };
    assert_eq!(
        graph.handle_commit(&commit3, &protected_dids),
        FollowSyncEvent::Ignored
    );

    // 4. Integer "subject" field (type confusion)
    let commit4 = JetstreamCommit {
        did: PROTECTED_ALICE.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: "bad_rk_4".to_string(),
        operation: CommitOperation::Create,
        cid: None,
        record: Some(json!({
            "$type": "app.bsky.graph.follow",
            "subject": 123456,
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    };
    assert_eq!(
        graph.handle_commit(&commit4, &protected_dids),
        FollowSyncEvent::Ignored
    );

    // 5. Wrong collection NSID
    let commit5 = JetstreamCommit {
        did: PROTECTED_ALICE.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.block".to_string(),
        rkey: "bad_rk_5".to_string(),
        operation: CommitOperation::Create,
        cid: None,
        record: Some(json!({
            "subject": "did:plc:someone"
        })),
    };
    assert_eq!(
        graph.handle_commit(&commit5, &protected_dids),
        FollowSyncEvent::Ignored
    );

    assert!(graph.is_empty());
}

// ============================================================================
// 8. Concurrent Race Condition: Dynamic Firehose Mutations & Candidate Accounting
// ============================================================================

#[tokio::test]
async fn test_concurrent_race_condition_firehose_and_candidate_accounting() {
    let graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(graph.clone()));
    let classifier = Arc::new(MockClassifier::default());

    let mut protected_dids_set = HashSet::new();
    protected_dids_set.insert(PROTECTED_ALICE.to_string());
    let protected_dids = Arc::new(protected_dids_set);

    let candidates = [
        "did:plc:worker_author_0",
        "did:plc:worker_author_1",
        "did:plc:worker_author_2",
        "did:plc:worker_author_3",
    ];

    let total_candidates_emitted = Arc::new(AtomicUsize::new(0));
    let total_bypassed = Arc::new(AtomicUsize::new(0));

    // Spawn 1 mutator task that toggles follow states rapidly
    let graph_mutator = graph.clone();
    let protected_mutator = protected_dids.clone();
    let mutator_handle = tokio::spawn(async move {
        for cycle in 0..150 {
            for (idx, author) in candidates.iter().enumerate() {
                let rkey = format!("race_rk_{idx}_{cycle}");
                let follow = make_follow_create_commit(PROTECTED_ALICE, author, &rkey);
                graph_mutator.handle_commit(&follow, &protected_mutator);

                tokio::task::yield_now().await;

                let unfollow = make_follow_delete_commit(PROTECTED_ALICE, &rkey);
                graph_mutator.handle_commit(&unfollow, &protected_mutator);
            }
        }
    });

    // Spawn 4 concurrent worker tasks evaluating incoming posts
    let mut worker_handles = Vec::new();
    for worker_id in 0..4 {
        let gate_w = gate.clone();
        let classifier_w = classifier.clone();
        let protected_w = protected_dids.clone();
        let emitted_counter = total_candidates_emitted.clone();
        let bypassed_counter = total_bypassed.clone();

        let handle = tokio::spawn(async move {
            let author = candidates[worker_id];
            for post_id in 0..100 {
                let commit = make_reply_commit(
                    author,
                    PROTECTED_ALICE,
                    &format!("w_{worker_id}_p_{post_id}"),
                    "p_root",
                    "Stress post",
                );
                let interaction =
                    TargetMatcher::match_interaction(&commit, &protected_w).expect("match");
                let decision = gate_w.evaluate(interaction);

                match decision {
                    GateDecision::Candidate(cand) => {
                        emitted_counter.fetch_add(1, Ordering::SeqCst);
                        let _ = classifier_w
                            .classify(&cand)
                            .await
                            .expect("classify must succeed");
                    }
                    GateDecision::Bypassed { .. } => {
                        bypassed_counter.fetch_add(1, Ordering::SeqCst);
                    }
                }

                if post_id % 10 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
        worker_handles.push(handle);
    }

    // Await all tasks to finish
    mutator_handle.await.expect("mutator ok");
    for handle in worker_handles {
        handle.await.expect("worker ok");
    }

    let emitted = total_candidates_emitted.load(Ordering::SeqCst);
    let bypassed = total_bypassed.load(Ordering::SeqCst);
    let call_count = classifier.call_count();

    println!(
        "\n⚡ [Concurrent Race Accounting] Emitted Candidates: {emitted} | Bypassed: {bypassed} | Total: {} | Classifier Calls: {call_count}",
        emitted + bypassed
    );

    // Invariants:
    // 1. Total processed must equal exactly 4 workers * 100 posts = 400
    assert_eq!(
        emitted + bypassed,
        400,
        "All 400 posts must be accounted for as either Candidate or Bypassed"
    );

    // 2. Classifier calls MUST STRICTLY EQUAL the number of emitted candidates
    assert_eq!(
        call_count, emitted,
        "MockClassifier call count must strictly match emitted candidates"
    );

    // 3. Under race conditions with follow/unfollow, both candidates and bypasses occurred
    assert!(emitted > 0, "Expected some candidates to be emitted");
}

// ============================================================================
// 9. Additional Advanced Edge Cases & State Transition Attacks
// ============================================================================

#[tokio::test]
async fn test_out_of_order_delete_commit_before_create_commit() {
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    let future_rkey = "future_rkey_out_of_order";

    // 1. Delete commit arrives BEFORE create commit (network reordering / firehose catchup)
    let early_delete = make_follow_delete_commit(PROTECTED_ALICE, future_rkey);
    let del_event = graph.handle_commit(&early_delete, &protected_dids);
    assert_eq!(
        del_event,
        FollowSyncEvent::Ignored,
        "Premature delete for untracked rkey must be cleanly Ignored"
    );
    assert!(!graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));

    // Post while unfollowed -> candidate
    let commit1 = make_reply_commit(
        CANDIDATE_CHARLIE,
        PROTECTED_ALICE,
        "p1",
        "r",
        "Still stranger",
    );
    let match1 = TargetMatcher::match_interaction(&commit1, &protected_dids).expect("match");
    let cand1 = gate.filter(match1).expect("candidate");
    let _ = classifier.classify(&cand1).await.expect("classify");
    assert_eq!(classifier.call_count(), 1);

    // 2. Delayed create commit arrives later
    let delayed_create = make_follow_create_commit(PROTECTED_ALICE, CANDIDATE_CHARLIE, future_rkey);
    let create_event = graph.handle_commit(&delayed_create, &protected_dids);
    assert_eq!(
        create_event,
        FollowSyncEvent::FollowAdded {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: future_rkey.to_string(),
            followed_did: CANDIDATE_CHARLIE.to_string(),
        }
    );
    assert!(graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));

    // Post while followed -> bypassed
    let commit2 = make_reply_commit(CANDIDATE_CHARLIE, PROTECTED_ALICE, "p2", "r", "Now friend");
    let match2 = TargetMatcher::match_interaction(&commit2, &protected_dids).expect("match");
    assert!(gate.filter(match2).is_none());
    assert_eq!(classifier.call_count(), 1);
}

#[tokio::test]
async fn test_duplicate_follow_with_rkey_update_to_new_subject() {
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    // Alice follows Bob with rk_1 and rk_2
    graph.add_follow(PROTECTED_ALICE, "rk_1", PROTECTED_BOB);
    graph.add_follow(PROTECTED_ALICE, "rk_2", PROTECTED_BOB);
    assert!(graph.is_following(PROTECTED_ALICE, PROTECTED_BOB));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Update rk_1 to point to Charlie instead of Bob
    let update_commit = make_follow_update_commit(PROTECTED_ALICE, CANDIDATE_CHARLIE, "rk_1");
    let event = graph.handle_commit(&update_commit, &protected_dids);
    assert_eq!(
        event,
        FollowSyncEvent::FollowAdded {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "rk_1".to_string(),
            followed_did: CANDIDATE_CHARLIE.to_string(),
        }
    );

    // INVARIANT: Bob MUST STILL BE FOLLOWED because rk_2 still points to Bob!
    // AND Charlie is now followed because rk_1 points to Charlie!
    assert!(
        graph.is_following(PROTECTED_ALICE, PROTECTED_BOB),
        "Bob must remain followed via rk_2"
    );
    assert!(
        graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE),
        "Charlie is followed via rk_1"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 2);

    // Interactions from both Bob and Charlie must be bypassed
    let post_bob = make_reply_commit(PROTECTED_BOB, PROTECTED_ALICE, "pb1", "r", "From bob");
    let match_bob = TargetMatcher::match_interaction(&post_bob, &protected_dids).expect("match");
    assert!(gate.filter(match_bob).is_none());

    let post_charlie = make_reply_commit(
        CANDIDATE_CHARLIE,
        PROTECTED_ALICE,
        "pc1",
        "r",
        "From charlie",
    );
    let match_charlie =
        TargetMatcher::match_interaction(&post_charlie, &protected_dids).expect("match");
    assert!(gate.filter(match_charlie).is_none());
    assert_eq!(classifier.call_count(), 0);

    // Delete rk_2 -> Bob is now unfollowed, but Charlie remains followed!
    let del_rk2 = make_follow_delete_commit(PROTECTED_ALICE, "rk_2");
    graph.handle_commit(&del_rk2, &protected_dids);
    assert!(
        !graph.is_following(PROTECTED_ALICE, PROTECTED_BOB),
        "Bob is now unfollowed"
    );
    assert!(
        graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE),
        "Charlie remains followed"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Now Bob post is candidate -> evaluated
    let post_bob2 = make_reply_commit(PROTECTED_BOB, PROTECTED_ALICE, "pb2", "r", "Bob stranger");
    let match_bob2 = TargetMatcher::match_interaction(&post_bob2, &protected_dids).expect("match");
    let cand_bob = gate.filter(match_bob2).expect("candidate");
    let _ = classifier.classify(&cand_bob).await.expect("classify");
    assert_eq!(classifier.call_count(), 1);

    // Delete rk_1 -> Charlie is now also unfollowed
    let del_rk1 = make_follow_delete_commit(PROTECTED_ALICE, "rk_1");
    graph.handle_commit(&del_rk1, &protected_dids);
    assert!(!graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);

    let post_charlie2 = make_reply_commit(
        CANDIDATE_CHARLIE,
        PROTECTED_ALICE,
        "pc2",
        "r",
        "Charlie stranger",
    );
    let match_charlie2 =
        TargetMatcher::match_interaction(&post_charlie2, &protected_dids).expect("match");
    let cand_charlie = gate.filter(match_charlie2).expect("candidate");
    let _ = classifier.classify(&cand_charlie).await.expect("classify");
    assert_eq!(classifier.call_count(), 2);
}

#[test]
fn test_cross_user_rkey_collision_isolation() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());
    protected_dids.insert(PROTECTED_BOB.to_string());

    // Both Alice and Bob use the same rkey name `follow_shared_key`
    graph.add_follow(PROTECTED_ALICE, "follow_shared_key", CANDIDATE_CHARLIE);
    graph.add_follow(PROTECTED_BOB, "follow_shared_key", STRANGER_DAVE);

    assert!(graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));
    assert!(graph.is_following(PROTECTED_BOB, STRANGER_DAVE));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);
    assert_eq!(graph.follow_count(PROTECTED_BOB), 1);

    // Delete follow_shared_key on Alice
    let del_alice = make_follow_delete_commit(PROTECTED_ALICE, "follow_shared_key");
    let event = graph.handle_commit(&del_alice, &protected_dids);
    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "follow_shared_key".to_string(),
            followed_did: CANDIDATE_CHARLIE.to_string(),
        }
    );

    // INVARIANT: Alice's follow is deleted, but Bob's follow with the SAME rkey is unaffected!
    assert!(!graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));
    assert!(
        graph.is_following(PROTECTED_BOB, STRANGER_DAVE),
        "Bob's follow must be completely isolated from Alice's deletion"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
    assert_eq!(graph.follow_count(PROTECTED_BOB), 1);
}

#[tokio::test]
async fn test_multi_target_post_pentagram_five_protected_users() {
    let graph = Arc::new(FollowGraph::new());
    let u1 = "did:plc:protected_1";
    let u2 = "did:plc:protected_2";
    let u3 = "did:plc:protected_3";
    let u4 = "did:plc:protected_4";
    let u5 = "did:plc:protected_5";

    let mut protected_dids = HashSet::new();
    for u in &[u1, u2, u3, u4, u5] {
        protected_dids.insert(u.to_string());
    }

    let author = "did:plc:mass_mentioner";

    // Setup: u1 and u3 follow author; u2, u4, u5 do NOT follow author
    graph.add_follow(u1, "rk1", author);
    graph.add_follow(u3, "rk3", author);

    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    // Mass mention post
    let commit = make_multi_mention_commit(
        author,
        &[u1, u2, u3, u4, u5],
        "pentagram_post",
        "Broadcasting to @u1, @u2, @u3, @u4, and @u5",
    );

    let interactions = TargetMatcher::match_all_interactions(&commit, &protected_dids);
    assert_eq!(
        interactions.len(),
        5,
        "Must extract all 5 targeted protected users"
    );

    let mut candidate_dids = Vec::new();
    let mut bypassed_dids = Vec::new();

    for interaction in interactions {
        let decision = gate.evaluate(interaction);
        match decision {
            GateDecision::Candidate(cand) => {
                let _ = classifier.classify(&cand).await.expect("classify");
                candidate_dids.push(cand.target_did);
            }
            GateDecision::Bypassed { interaction, .. } => {
                bypassed_dids.push(interaction.target_did);
            }
        }
    }

    assert_eq!(
        bypassed_dids.len(),
        2,
        "2 targets follow author -> bypassed"
    );
    assert!(bypassed_dids.contains(&u1.to_string()));
    assert!(bypassed_dids.contains(&u3.to_string()));

    assert_eq!(
        candidate_dids.len(),
        3,
        "3 targets do not follow -> candidate"
    );
    assert!(candidate_dids.contains(&u2.to_string()));
    assert!(candidate_dids.contains(&u4.to_string()));
    assert!(candidate_dids.contains(&u5.to_string()));

    // Strict accounting assertion
    assert_eq!(
        classifier.call_count(),
        3,
        "MockClassifier call count must strictly equal 3"
    );
}

#[test]
fn test_hydrate_batch_duplicate_rkeys_and_partial_removal() {
    let graph = FollowGraph::new();

    // Cold-start hydration with duplicate rkeys pointing to the same followed DID
    let batch = vec![
        ("hydrated_rk_1".to_string(), CANDIDATE_CHARLIE.to_string()),
        ("hydrated_rk_2".to_string(), CANDIDATE_CHARLIE.to_string()),
    ];

    let hydrated = graph.hydrate_batch(PROTECTED_ALICE, batch);
    assert_eq!(hydrated, 2);
    assert!(graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);
    assert!(graph.contains_rkey(PROTECTED_ALICE, "hydrated_rk_1"));
    assert!(graph.contains_rkey(PROTECTED_ALICE, "hydrated_rk_2"));

    // Remove first hydrated rkey
    let removed1 = graph.remove_follow_by_rkey(PROTECTED_ALICE, "hydrated_rk_1");
    assert_eq!(removed1, Some(CANDIDATE_CHARLIE.to_string()));
    // Still followed because hydrated_rk_2 remains
    assert!(graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));
    assert!(!graph.contains_rkey(PROTECTED_ALICE, "hydrated_rk_1"));
    assert!(graph.contains_rkey(PROTECTED_ALICE, "hydrated_rk_2"));

    // Remove second hydrated rkey
    let removed2 = graph.remove_follow_by_rkey(PROTECTED_ALICE, "hydrated_rk_2");
    assert_eq!(removed2, Some(CANDIDATE_CHARLIE.to_string()));
    assert!(!graph.is_following(PROTECTED_ALICE, CANDIDATE_CHARLIE));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
    assert!(!graph.contains_rkey(PROTECTED_ALICE, "hydrated_rk_2"));
}
