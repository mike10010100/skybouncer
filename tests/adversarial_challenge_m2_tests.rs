//! Adversarial empirical test harness for Milestone M2 (Requirement R3: Follow Graph Cold Hydration TID Reconciliation).
//!
//! Stress-tests edge cases:
//! 1. Synthetic `hydrate_N` vs real ATProto TID follow deletion across cold hydration.
//! 2. Empty follow graph deletion behavior (zero follows, untracked users, no panics).
//! 3. Multiple hydrated follows: sequential real TID unfollows until exhaustion, followed by ignored excess.
//! 4. Mixed real and synthetic follows: real TID deletes only target real records, untracked deletes fall back to synthetic.
//! 5. Repeated unfollows (idempotence): duplicate delete commits are safely ignored after first removal.
//! 6. Aliased follows: same DID referenced by multiple rkeys (real + synthetic); removing one preserves active follow.
//! 7. Synthetic `seed_{did}` keys created by `hydrate_dids` reconciled by untracked delete commits.
//! 8. Fallback Tier 2: delete commit with untracked rkey but containing subject in record payload.
//! 9. Fallback Tier 3: delete commit with rkey directly containing `did:plc:...`.
//! 10. End-to-end SkybouncerEngine integration: Followed account bypassed -> Unfollow commit processed -> Account evaluated by classifier.
//! 11. Multi-threaded concurrency stress test: concurrent readers, writers, and synthetic fallback deletes.
//! 12. Sub-microsecond latency SLA invariant check after hydration and reconciliation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use common::*;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};
use skybouncer::classifier::{MockClassifier, RuleRubric, Sensitivity};
use skybouncer::engine::{
    InteractionOutcome, ProcessCommitResult, SkybouncerConfig, SkybouncerEngine,
};
use skybouncer::matcher::{BypassReason, FollowGraph, FollowSyncEvent};

const PROTECTED_ALICE: &str = "did:plc:alice_protected";
const USER_BOB: &str = "did:plc:bob_user";
const USER_CHARLIE: &str = "did:plc:charlie_user";
const USER_DAVE: &str = "did:plc:dave_user";
const USER_EVE: &str = "did:plc:eve_user";

// ============================================================================
// 1. Synthetic vs Real TID Deletion across Cold Hydration
// ============================================================================

#[test]
fn test_adversarial_synthetic_hydrate_idx_reconciliation() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    // Cold-start hydration using synthetic hydrate_0 rkey
    graph.add_follow(PROTECTED_ALICE, "hydrate_0", USER_BOB);
    assert!(graph.is_following(PROTECTED_ALICE, USER_BOB));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);
    assert!(graph.contains_rkey(PROTECTED_ALICE, "hydrate_0"));

    // Real ATProto delete commit arrives with real PDS TID
    let real_tid = "3l5u4vh2k6s2y";
    let delete_commit = make_follow_delete_commit(PROTECTED_ALICE, real_tid);

    let event = graph.handle_commit(&delete_commit, &protected);

    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: real_tid.to_string(),
            followed_did: USER_BOB.to_string(),
        },
        "Must reconcile synthetic hydrate_0 with incoming real TID delete commit"
    );

    assert!(
        !graph.is_following(PROTECTED_ALICE, USER_BOB),
        "Bob must no longer be followed"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
    assert!(!graph.contains_rkey(PROTECTED_ALICE, "hydrate_0"));
}

// ============================================================================
// 2. Empty Follow Graph Edge Cases
// ============================================================================

#[test]
fn test_adversarial_empty_follow_graph_edge_cases() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    // Case A: Delete commit for protected user who has 0 follows
    let delete_commit = make_follow_delete_commit(PROTECTED_ALICE, "3l5u4random_tid");
    let event = graph.handle_commit(&delete_commit, &protected);
    assert_eq!(
        event,
        FollowSyncEvent::Ignored,
        "Empty follow graph must safely ignore delete commits without panic"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);

    // Case B: Commit for non-protected stranger user
    let stranger_commit = make_follow_delete_commit("did:plc:stranger", "3l5u4random_tid");
    let event_stranger = graph.handle_commit(&stranger_commit, &protected);
    assert_eq!(
        event_stranger,
        FollowSyncEvent::Ignored,
        "Non-protected DID commits must be immediately ignored"
    );

    // Case C: Unrelated collection (e.g. app.bsky.feed.post) with Delete op
    let post_delete = JetstreamCommit {
        did: PROTECTED_ALICE.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: "3l5u4post".to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };
    let event_post = graph.handle_commit(&post_delete, &protected);
    assert_eq!(
        event_post,
        FollowSyncEvent::Ignored,
        "Non-follow collections must be ignored"
    );
}

// ============================================================================
// 3. Multiple Hydrated Follows: Exhaustion and Post-Exhaustion
// ============================================================================

#[test]
fn test_adversarial_multiple_hydrated_follows_exhaustion() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    // Hydrate 5 follows
    let users = [
        "did:plc:user_0",
        "did:plc:user_1",
        "did:plc:user_2",
        "did:plc:user_3",
        "did:plc:user_4",
    ];
    for (idx, u) in users.iter().enumerate() {
        graph.add_follow(PROTECTED_ALICE, format!("hydrate_{idx}"), *u);
    }
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 5);

    let mut removed_dids = HashSet::new();

    // Stream 5 real TID delete commits
    for i in 0..5 {
        let tid = format!("3l5u_tid_{i}");
        let commit = make_follow_delete_commit(PROTECTED_ALICE, &tid);
        let event = graph.handle_commit(&commit, &protected);

        match event {
            FollowSyncEvent::FollowRemoved {
                protected_did,
                rkey,
                followed_did,
            } => {
                assert_eq!(protected_did, PROTECTED_ALICE);
                assert_eq!(rkey, tid);
                assert!(
                    users.contains(&followed_did.as_str()),
                    "Removed DID must be one of the hydrated users"
                );
                assert!(
                    removed_dids.insert(followed_did.clone()),
                    "Each removal must target a unique account"
                );
                assert!(
                    !graph.is_following(PROTECTED_ALICE, &followed_did),
                    "Account must no longer be followed"
                );
            }
            FollowSyncEvent::Ignored => {
                panic!("Expected FollowRemoved for commit {i}, got Ignored");
            }
            FollowSyncEvent::FollowAdded { .. } => unreachable!(),
        }

        assert_eq!(graph.follow_count(PROTECTED_ALICE), 5 - (i + 1));
    }

    // All 5 must have been removed
    assert_eq!(removed_dids.len(), 5);
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);

    // 6th delete commit arrives: must safely evaluate to Ignored
    let extra_commit = make_follow_delete_commit(PROTECTED_ALICE, "3l5u_extra_tid");
    let event_extra = graph.handle_commit(&extra_commit, &protected);
    assert_eq!(
        event_extra,
        FollowSyncEvent::Ignored,
        "Excess delete commits once follow graph is exhausted must be ignored"
    );
}

// ============================================================================
// 4. Mixed Real and Synthetic Follows
// ============================================================================

#[test]
fn test_adversarial_mixed_real_and_synthetic_follows() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    let real_tid_bob = "3l5u_real_bob";
    let real_tid_dave = "3l5u_real_dave";

    // Alice follows Bob (real TID), Charlie (synthetic hydrate), Dave (real TID), Eve (synthetic seed)
    graph.add_follow(PROTECTED_ALICE, real_tid_bob, USER_BOB);
    graph.add_follow(PROTECTED_ALICE, "hydrate_0", USER_CHARLIE);
    graph.add_follow(PROTECTED_ALICE, real_tid_dave, USER_DAVE);
    graph.hydrate_dids(PROTECTED_ALICE, vec![USER_EVE]); // creates seed_did:plc:eve_user

    assert_eq!(graph.follow_count(PROTECTED_ALICE), 4);

    // Step 1: Unfollow Bob with exact real TID
    let commit_bob = make_follow_delete_commit(PROTECTED_ALICE, real_tid_bob);
    let event_bob = graph.handle_commit(&commit_bob, &protected);
    assert_eq!(
        event_bob,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: real_tid_bob.to_string(),
            followed_did: USER_BOB.to_string(),
        }
    );
    assert!(!graph.is_following(PROTECTED_ALICE, USER_BOB));
    // Verify that Charlie, Dave, Eve remain followed and synthetic keys are NOT stolen
    assert!(graph.is_following(PROTECTED_ALICE, USER_CHARLIE));
    assert!(graph.is_following(PROTECTED_ALICE, USER_DAVE));
    assert!(graph.is_following(PROTECTED_ALICE, USER_EVE));
    assert!(graph.contains_rkey(PROTECTED_ALICE, "hydrate_0"));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 3);

    // Step 2: Unfollow with an untracked TID (targeting a synthetic follow)
    let untracked_tid_1 = "3l5u_untracked_1";
    let commit_untracked = make_follow_delete_commit(PROTECTED_ALICE, untracked_tid_1);
    let event_untracked = graph.handle_commit(&commit_untracked, &protected);

    match event_untracked {
        FollowSyncEvent::FollowRemoved {
            protected_did,
            rkey,
            followed_did,
        } => {
            assert_eq!(protected_did, PROTECTED_ALICE);
            assert_eq!(rkey, untracked_tid_1);
            // Must have removed either Charlie or Eve (one of the synthetic follows)
            assert!(
                followed_did == USER_CHARLIE || followed_did == USER_EVE,
                "Must remove a synthetic follow, got {followed_did}"
            );
        }
        _ => panic!("Expected FollowRemoved via synthetic fallback"),
    }
    // Real TID Dave MUST still be followed!
    assert!(
        graph.is_following(PROTECTED_ALICE, USER_DAVE),
        "Real follow Dave must remain intact"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 2);

    // Step 3: Delete Dave using Dave's exact real TID
    let commit_dave = make_follow_delete_commit(PROTECTED_ALICE, real_tid_dave);
    let event_dave = graph.handle_commit(&commit_dave, &protected);
    assert_eq!(
        event_dave,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: real_tid_dave.to_string(),
            followed_did: USER_DAVE.to_string(),
        }
    );
    assert!(!graph.is_following(PROTECTED_ALICE, USER_DAVE));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);

    // Step 4: Untracked delete removes the last remaining synthetic follow
    let untracked_tid_2 = "3l5u_untracked_2";
    let commit_untracked_2 = make_follow_delete_commit(PROTECTED_ALICE, untracked_tid_2);
    let event_untracked_2 = graph.handle_commit(&commit_untracked_2, &protected);
    assert!(matches!(
        event_untracked_2,
        FollowSyncEvent::FollowRemoved { .. }
    ));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);

    // Step 5: Untracked delete when graph has 0 follows left
    let untracked_tid_3 = "3l5u_untracked_3";
    let commit_untracked_3 = make_follow_delete_commit(PROTECTED_ALICE, untracked_tid_3);
    let event_untracked_3 = graph.handle_commit(&commit_untracked_3, &protected);
    assert_eq!(event_untracked_3, FollowSyncEvent::Ignored);
}

// ============================================================================
// 5. Repeated Unfollows (Idempotence & Duplicate Commits)
// ============================================================================

#[test]
fn test_adversarial_repeated_unfollows_idempotence() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    graph.add_follow(PROTECTED_ALICE, "hydrate_0", USER_BOB);
    assert!(graph.is_following(PROTECTED_ALICE, USER_BOB));

    let real_tid = "3l5u_repeat_tid";
    let commit = make_follow_delete_commit(PROTECTED_ALICE, real_tid);

    // First arrival: successfully removes synthetic follow
    let first = graph.handle_commit(&commit, &protected);
    assert_eq!(
        first,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: real_tid.to_string(),
            followed_did: USER_BOB.to_string(),
        }
    );
    assert!(!graph.is_following(PROTECTED_ALICE, USER_BOB));

    // Second arrival: exactly same commit -> Ignored
    let second = graph.handle_commit(&commit, &protected);
    assert_eq!(
        second,
        FollowSyncEvent::Ignored,
        "Duplicate delete commit must evaluate to Ignored"
    );

    // Third arrival: still Ignored
    let third = graph.handle_commit(&commit, &protected);
    assert_eq!(
        third,
        FollowSyncEvent::Ignored,
        "Triplicate delete commit must evaluate to Ignored"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
}

// ============================================================================
// 6. Aliased Follows: Same DID Referenced by Multiple Rkeys
// ============================================================================

#[test]
fn test_adversarial_aliased_follows_same_did_multiple_rkeys() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    // Alice follows Bob under both synthetic hydrate_0 AND real TID 3l5u_real
    graph.add_follow(PROTECTED_ALICE, "hydrate_0", USER_BOB);
    graph.add_follow(PROTECTED_ALICE, "3l5u_real", USER_BOB);
    assert!(graph.is_following(PROTECTED_ALICE, USER_BOB));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1); // 1 distinct followed account

    // Delete commit arrives with an untracked TID: triggers synthetic fallback
    let untracked_commit = make_follow_delete_commit(PROTECTED_ALICE, "3l5u_untracked");
    let event = graph.handle_commit(&untracked_commit, &protected);

    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "3l5u_untracked".to_string(),
            followed_did: USER_BOB.to_string(),
        }
    );

    // CRITICAL INVARIANT: Bob MUST STILL BE FOLLOWED because 3l5u_real still references Bob!
    assert!(
        graph.is_following(PROTECTED_ALICE, USER_BOB),
        "Bob must still be followed because 3l5u_real still exists in reverse index"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 1);
    assert!(!graph.contains_rkey(PROTECTED_ALICE, "hydrate_0"));
    assert!(graph.contains_rkey(PROTECTED_ALICE, "3l5u_real"));

    // Now delete commit arrives for 3l5u_real
    let real_commit = make_follow_delete_commit(PROTECTED_ALICE, "3l5u_real");
    let event_real = graph.handle_commit(&real_commit, &protected);

    assert_eq!(
        event_real,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "3l5u_real".to_string(),
            followed_did: USER_BOB.to_string(),
        }
    );

    // Now Bob is completely unfollowed
    assert!(
        !graph.is_following(PROTECTED_ALICE, USER_BOB),
        "Bob must be completely unfollowed after last reference is deleted"
    );
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
}

// ============================================================================
// 7. Synthetic `seed_{did}` Keys from `hydrate_dids`
// ============================================================================

#[test]
fn test_adversarial_seed_did_synthetic_keys() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    // Hydrate via hydrate_dids
    let count = graph.hydrate_dids(PROTECTED_ALICE, vec![USER_BOB]);
    assert_eq!(count, 1);
    assert!(graph.is_following(PROTECTED_ALICE, USER_BOB));
    assert!(graph.contains_rkey(PROTECTED_ALICE, &format!("seed_{USER_BOB}")));

    // Real TID delete commit arrives
    let commit = make_follow_delete_commit(PROTECTED_ALICE, "3l5u_seed_delete");
    let event = graph.handle_commit(&commit, &protected);

    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "3l5u_seed_delete".to_string(),
            followed_did: USER_BOB.to_string(),
        }
    );
    assert!(!graph.is_following(PROTECTED_ALICE, USER_BOB));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
}

// ============================================================================
// 8. Fallback Tier 2: Delete Commit with Subject in Record Payload
// ============================================================================

#[test]
fn test_adversarial_fallback_tier2_payload_subject() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    graph.add_follow(PROTECTED_ALICE, "custom_key_123", USER_BOB);
    assert!(graph.is_following(PROTECTED_ALICE, USER_BOB));

    // Delete commit with untracked rkey but containing subject in record payload
    let commit = JetstreamCommit {
        did: PROTECTED_ALICE.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: "different_rkey_999".to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: Some(serde_json::json!({ "subject": USER_BOB })),
    };

    let event = graph.handle_commit(&commit, &protected);
    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "different_rkey_999".to_string(),
            followed_did: USER_BOB.to_string(),
        }
    );
    assert!(!graph.is_following(PROTECTED_ALICE, USER_BOB));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
}

// ============================================================================
// 9. Fallback Tier 3: Delete Commit with Rkey Directly as DID
// ============================================================================

#[test]
fn test_adversarial_fallback_tier3_rkey_as_did() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    graph.add_follow(PROTECTED_ALICE, "any_rkey", USER_BOB);
    assert!(graph.is_following(PROTECTED_ALICE, USER_BOB));

    // Delete commit where rkey is literally "did:plc:bob_user"
    let commit = make_follow_delete_commit(PROTECTED_ALICE, USER_BOB);
    let event = graph.handle_commit(&commit, &protected);

    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: USER_BOB.to_string(),
            followed_did: USER_BOB.to_string(),
        }
    );
    assert!(!graph.is_following(PROTECTED_ALICE, USER_BOB));
    assert_eq!(graph.follow_count(PROTECTED_ALICE), 0);
}

// ============================================================================
// 10. End-to-End Engine Pipeline Integration: NonFollowedGate Transition
// ============================================================================

#[tokio::test]
async fn test_adversarial_e2e_engine_non_followed_gate_transition() {
    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    let config = SkybouncerConfig::new(
        protected_dids,
        RuleRubric::new("Default rules", Sensitivity::Medium),
    );

    // Mock classifier tracks number of classification invocations
    let mock_classifier = Arc::new(MockClassifier::permitted());
    let engine = SkybouncerEngine::builder(config)
        .with_classifier(mock_classifier.clone())
        .build()
        .unwrap();

    // 1. Cold-start hydration with synthetic rkeys
    let count = engine.hydrate_follows(PROTECTED_ALICE, vec![USER_BOB]);
    assert_eq!(count, 1);
    assert!(engine.is_following(PROTECTED_ALICE, USER_BOB));

    // 2. Bob mentions Alice in a post commit
    let mention_commit = make_mention_commit(
        USER_BOB,
        PROTECTED_ALICE,
        "3l5u_post_1",
        "@alice hello friend!",
    );

    let result_1 = engine.process_commit(&mention_commit).await.unwrap();
    match result_1 {
        ProcessCommitResult::InteractionsProcessed(outcomes) => {
            assert_eq!(outcomes.len(), 1);
            match &outcomes[0] {
                InteractionOutcome::Bypassed {
                    reason, author_did, ..
                } => {
                    assert_eq!(*reason, BypassReason::FollowedAuthor);
                    assert_eq!(author_did, USER_BOB);
                }
                other => panic!("Expected Bypassed(FollowedAuthor), got {other:?}"),
            }
        }
        other => panic!("Expected InteractionsProcessed, got {other:?}"),
    }
    // Classifier must NOT have been called ($0 cost gate)
    assert_eq!(
        mock_classifier.call_count(),
        0,
        "Non-followed gate must short-circuit before classifier invocation"
    );

    // 3. Alice unfollows Bob on Bluesky: Jetstream transmits real TID delete commit
    let real_unfollow_tid = "3l5u_unfollow_tid";
    let unfollow_commit = make_follow_delete_commit(PROTECTED_ALICE, real_unfollow_tid);

    let unfollow_result = engine.process_commit(&unfollow_commit).await.unwrap();
    match unfollow_result {
        ProcessCommitResult::FollowSynced(FollowSyncEvent::FollowRemoved {
            protected_did,
            rkey,
            followed_did,
        }) => {
            assert_eq!(protected_did, PROTECTED_ALICE);
            assert_eq!(rkey, real_unfollow_tid);
            assert_eq!(followed_did, USER_BOB);
        }
        other => panic!("Expected FollowSynced(FollowRemoved), got {other:?}"),
    }

    // Engine is_following check now returns false!
    assert!(
        !engine.is_following(PROTECTED_ALICE, USER_BOB),
        "Bob must no longer be followed"
    );

    // 4. Bob mentions Alice again in a second post commit
    let mention_commit_2 = make_mention_commit(
        USER_BOB,
        PROTECTED_ALICE,
        "3l5u_post_2",
        "@alice you unfollowed me!",
    );

    let result_2 = engine.process_commit(&mention_commit_2).await.unwrap();
    match result_2 {
        ProcessCommitResult::InteractionsProcessed(outcomes) => {
            assert_eq!(outcomes.len(), 1);
            match &outcomes[0] {
                InteractionOutcome::Permitted { author_did, .. } => {
                    assert_eq!(author_did, USER_BOB);
                }
                other => panic!("Expected Permitted outcome, got {other:?}"),
            }
        }
        other => panic!("Expected InteractionsProcessed, got {other:?}"),
    }

    // Classifier was invoked now!
    assert_eq!(
        mock_classifier.call_count(),
        1,
        "Classifier must be called after account is unfollowed"
    );
}

// ============================================================================
// 11. Multi-Threaded Concurrency Stress Test
// ============================================================================

#[test]
fn test_adversarial_concurrency_stress_readers_writers_fallback() {
    let graph = Arc::new(FollowGraph::new());
    let mut protected_set = HashSet::new();
    protected_set.insert(PROTECTED_ALICE.to_string());
    let protected = Arc::new(protected_set);

    // Pre-hydrate 50 accounts
    for i in 0..50 {
        graph.add_follow(
            PROTECTED_ALICE,
            format!("hydrate_{i}"),
            format!("did:plc:user_{i}"),
        );
    }

    let running = Arc::new(AtomicBool::new(true));
    let read_ops = Arc::new(AtomicUsize::new(0));
    let write_ops = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    // 10 reader threads
    for _ in 0..10 {
        let g = graph.clone();
        let r = running.clone();
        let reads = read_ops.clone();
        handles.push(std::thread::spawn(move || {
            let mut i: usize = 0;
            while r.load(Ordering::Relaxed) {
                let target = format!("did:plc:user_{}", i % 60);
                let _ = g.is_following(PROTECTED_ALICE, &target);
                let _ = g.follow_count(PROTECTED_ALICE);
                reads.fetch_add(2, Ordering::Relaxed);
                i += 1;
            }
        }));
    }

    // 10 writer threads executing mixed creates, exact deletes, and synthetic fallback deletes
    for worker_id in 0..10 {
        let g = graph.clone();
        let p = protected.clone();
        let r = running.clone();
        let writes = write_ops.clone();
        handles.push(std::thread::spawn(move || {
            let mut i: usize = 0;
            while r.load(Ordering::Relaxed) {
                match i % 3 {
                    0 => {
                        // Create
                        let rkey = format!("3l5u_w{worker_id}_{i}");
                        let did = format!("did:plc:dyn_{worker_id}_{i}");
                        let create_commit = make_follow_create_commit(PROTECTED_ALICE, &did, &rkey);
                        g.handle_commit(&create_commit, &p);
                    }
                    1 => {
                        // Exact real TID delete
                        let rkey = format!("3l5u_w{worker_id}_{}", i.saturating_sub(1));
                        let delete_commit = make_follow_delete_commit(PROTECTED_ALICE, &rkey);
                        g.handle_commit(&delete_commit, &p);
                    }
                    2 => {
                        // Synthetic fallback delete
                        let rkey = format!("3l5u_fallback_{worker_id}_{i}");
                        let delete_commit = make_follow_delete_commit(PROTECTED_ALICE, &rkey);
                        g.handle_commit(&delete_commit, &p);
                    }
                    _ => unreachable!(),
                }
                writes.fetch_add(1, Ordering::Relaxed);
                i += 1;
            }
        }));
    }

    // Run for 300ms under high load
    std::thread::sleep(std::time::Duration::from_millis(300));
    running.store(false, Ordering::Relaxed);

    for h in handles {
        h.join().unwrap();
    }

    assert!(
        read_ops.load(Ordering::Relaxed) > 1000,
        "High reader throughput required"
    );
    assert!(
        write_ops.load(Ordering::Relaxed) > 500,
        "High writer throughput required"
    );
}

// ============================================================================
// 12. Sub-Microsecond Gate Latency SLA Verification
// ============================================================================

#[test]
fn test_adversarial_latency_sla_under_hydrated_and_reconciled_graph() {
    let graph = FollowGraph::new();
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    // Hydrate 1,000 follows
    for i in 0..1_000 {
        graph.add_follow(
            PROTECTED_ALICE,
            format!("hydrate_{i}"),
            format!("did:plc:benchmark_user_{i}"),
        );
    }

    // Reconcile 200 follows via delete commits
    for i in 0..200 {
        let commit = make_follow_delete_commit(PROTECTED_ALICE, &format!("3l5u_bench_tid_{i}"));
        graph.handle_commit(&commit, &protected);
    }

    // Measure 100,000 lookup queries
    let iterations = 100_000;
    let start = Instant::now();
    for i in 0..iterations {
        let candidate = format!("did:plc:benchmark_user_{}", i % 1500);
        let _ = graph.is_following(PROTECTED_ALICE, &candidate);
    }
    let elapsed = start.elapsed();
    let latency_per_op = elapsed.as_nanos() as f64 / iterations as f64;

    // Latency SLA is < 1,000 ns (1 µs)
    assert!(
        latency_per_op < 1_000.0,
        "SLA Violation: latency per follow check was {latency_per_op:.2}ns (must be < 1000ns)"
    );
}
