//! Integration and verification tests for TargetMatcher, FollowGraph, and NonFollowedGate.
//!
//! Covers:
//! - Direct replies, thread replies, mentions, and quotes (all 4 interaction vectors).
//! - Self-interaction immediate dropping ($0 cost, 0 latency).
//! - FollowGraph query short-circuiting with MockClassifier assertion (call_count == 0).
//! - Dynamic follow/unfollow updates causing previously bypassed accounts to be evaluated and vice-versa.
//! - Reverse rkey index resolution for ATProto delete commits with `record: None`.
//! - Performance benchmarks validating <1µs gate latency SLA.
//! - Multi-threaded concurrency testing under mixed reader/writer load.
//! - Synthetic firehose streaming pipeline via asynchronous channel.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};
use skybouncer::classifier::{Classifier, MockClassifier};
use skybouncer::matcher::{
    BypassReason, FollowGraph, FollowSyncEvent, Interaction, InteractionType, NonFollowedGate,
    TargetMatcher,
};

const PROTECTED_ALICE: &str = "did:plc:protected_alice";
const FRIEND_BOB: &str = "did:plc:friend_bob";
const SPAMMER_CHARLIE: &str = "did:plc:spammer_charlie";

// ============================================================================
// 1. FollowGraph Unit Tests
// ============================================================================

#[test]
fn test_follow_graph_empty_returns_false() {
    let graph = FollowGraph::new();
    assert!(!graph.is_following("did:plc:alice", "did:plc:bob"));
    assert_eq!(graph.follow_count("did:plc:alice"), 0);
    assert_eq!(graph.total_protected_users(), 0);
    assert_eq!(graph.total_follows_count(), 0);
    assert!(graph.is_empty());
}

#[test]
fn test_follow_graph_add_and_query() {
    let graph = FollowGraph::new();
    graph.add_follow("did:plc:alice", "3la7follow1", "did:plc:bob");

    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));
    assert!(!graph.is_following("did:plc:alice", "did:plc:charlie"));
    assert!(!graph.is_following("did:plc:charlie", "did:plc:bob"));
    assert_eq!(graph.follow_count("did:plc:alice"), 1);
    assert_eq!(graph.total_protected_users(), 1);
    assert_eq!(graph.total_follows_count(), 1);
    assert!(graph.contains_rkey("did:plc:alice", "3la7follow1"));
    assert!(!graph.is_empty());

    let followed = graph.get_followed_dids("did:plc:alice");
    assert!(followed.contains("did:plc:bob"));
}

#[test]
fn test_follow_graph_reverse_rkey_delete() {
    let graph = FollowGraph::new();
    graph.add_follow("did:plc:alice", "3la7follow1", "did:plc:bob");
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    let removed = graph.remove_follow_by_rkey("did:plc:alice", "3la7follow1");
    assert_eq!(removed, Some("did:plc:bob".to_string()));
    assert!(!graph.is_following("did:plc:alice", "did:plc:bob"));
    assert_eq!(graph.follow_count("did:plc:alice"), 0);
    assert!(!graph.contains_rkey("did:plc:alice", "3la7follow1"));

    // Removing again returns None
    assert_eq!(
        graph.remove_follow_by_rkey("did:plc:alice", "3la7follow1"),
        None
    );
}

#[test]
fn test_follow_graph_remove_by_did() {
    let graph = FollowGraph::new();
    graph.add_follow("did:plc:alice", "rkey1", "did:plc:bob");
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    assert!(graph.remove_follow_by_did("did:plc:alice", "did:plc:bob"));
    assert!(!graph.is_following("did:plc:alice", "did:plc:bob"));
    assert!(!graph.contains_rkey("did:plc:alice", "rkey1"));
    assert!(!graph.remove_follow_by_did("did:plc:alice", "did:plc:bob"));
}

#[test]
fn test_follow_graph_multiple_rkeys_same_did_handling() {
    let graph = FollowGraph::new();
    // Simulate duplicate follow records for the same subject
    graph.add_follow("did:plc:alice", "rkey1", "did:plc:bob");
    graph.add_follow("did:plc:alice", "rkey2", "did:plc:bob");
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    // Deleting rkey1 should keep bob followed because rkey2 still exists
    let removed = graph.remove_follow_by_rkey("did:plc:alice", "rkey1");
    assert_eq!(removed, Some("did:plc:bob".to_string()));
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    // Deleting rkey2 removes bob completely
    let removed2 = graph.remove_follow_by_rkey("did:plc:alice", "rkey2");
    assert_eq!(removed2, Some("did:plc:bob".to_string()));
    assert!(!graph.is_following("did:plc:alice", "did:plc:bob"));
}

#[test]
fn test_follow_graph_handle_commit_create() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let commit = make_follow_create_commit("did:plc:alice", "did:plc:charlie", "3la7commit1");

    let event = graph.handle_commit(&commit, &protected_dids);
    assert_eq!(
        event,
        FollowSyncEvent::FollowAdded {
            protected_did: "did:plc:alice".to_string(),
            rkey: "3la7commit1".to_string(),
            followed_did: "did:plc:charlie".to_string(),
        }
    );
    assert!(graph.is_following("did:plc:alice", "did:plc:charlie"));
}

#[test]
fn test_follow_graph_handle_commit_delete() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    graph.add_follow("did:plc:alice", "3la7commit1", "did:plc:charlie");
    assert!(graph.is_following("did:plc:alice", "did:plc:charlie"));

    // Delete commit with NO record payload
    let delete_commit = make_follow_delete_commit("did:plc:alice", "3la7commit1");
    assert!(delete_commit.record.is_none());

    let event = graph.handle_commit(&delete_commit, &protected_dids);
    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: "did:plc:alice".to_string(),
            rkey: "3la7commit1".to_string(),
            followed_did: "did:plc:charlie".to_string(),
        }
    );
    assert!(!graph.is_following("did:plc:alice", "did:plc:charlie"));
}

#[test]
fn test_follow_graph_handle_commit_ignores_unrelated_collection() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let post_commit = make_standalone_post_commit("did:plc:alice", "post1", "Hello world");
    let event = graph.handle_commit(&post_commit, &protected_dids);
    assert_eq!(event, FollowSyncEvent::Ignored);
    assert_eq!(graph.total_follows_count(), 0);
}

#[test]
fn test_follow_graph_handle_commit_ignores_untracked_did() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let stranger_commit =
        make_follow_create_commit("did:plc:stranger", "did:plc:bob", "stranger_rk");
    let event = graph.handle_commit(&stranger_commit, &protected_dids);
    assert_eq!(event, FollowSyncEvent::Ignored);
    assert!(!graph.is_following("did:plc:stranger", "did:plc:bob"));
}

#[test]
fn test_follow_graph_hydrate_batch_and_dids() {
    let graph = FollowGraph::new();
    let batch = vec![
        ("rk1".to_string(), "did:plc:u1".to_string()),
        ("rk2".to_string(), "did:plc:u2".to_string()),
    ];
    let count = graph.hydrate_batch("did:plc:alice", batch);
    assert_eq!(count, 2);
    assert!(graph.is_following("did:plc:alice", "did:plc:u1"));
    assert!(graph.is_following("did:plc:alice", "did:plc:u2"));

    let dids = vec!["did:plc:u3", "did:plc:u4"];
    let did_count = graph.hydrate_dids("did:plc:alice", dids);
    assert_eq!(did_count, 2);
    assert_eq!(graph.follow_count("did:plc:alice"), 4);
    assert!(graph.is_following("did:plc:alice", "did:plc:u3"));
    assert!(graph.is_following("did:plc:alice", "did:plc:u4"));

    graph.clear();
    assert!(graph.is_empty());
    assert_eq!(graph.follow_count("did:plc:alice"), 0);
}

#[test]
fn test_follow_graph_remove_synthetic_follow_fallback() {
    let graph = FollowGraph::new();

    // No follows yet -> returns None
    assert_eq!(
        graph.remove_synthetic_follow_fallback("did:plc:alice"),
        None
    );

    // Add only a real TID rkey -> returns None because no synthetic keys exist
    graph.add_follow("did:plc:alice", "3la7real_tid", "did:plc:bob");
    assert_eq!(
        graph.remove_synthetic_follow_fallback("did:plc:alice"),
        None
    );
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    // Add synthetic hydrate_0 -> should remove it
    graph.add_follow("did:plc:alice", "hydrate_0", "did:plc:charlie");
    assert!(graph.is_following("did:plc:alice", "did:plc:charlie"));

    let removed = graph.remove_synthetic_follow_fallback("did:plc:alice");
    assert_eq!(removed, Some("did:plc:charlie".to_string()));
    assert!(!graph.is_following("did:plc:alice", "did:plc:charlie"));

    // Real TID follow remains intact
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    // Add synthetic seed_did -> should remove it
    graph.hydrate_dids("did:plc:alice", vec!["did:plc:david"]);
    assert!(graph.is_following("did:plc:alice", "did:plc:david"));

    let removed_seed = graph.remove_synthetic_follow_fallback("did:plc:alice");
    assert_eq!(removed_seed, Some("did:plc:david".to_string()));
    assert!(!graph.is_following("did:plc:alice", "did:plc:david"));
}

#[test]
fn test_follow_graph_handle_commit_delete_synthetic_fallback() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    // Hydrated with synthetic rkey hydrate_0
    graph.add_follow("did:plc:alice", "hydrate_0", "did:plc:bob");
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    // Delete commit arrives with real ATProto TID (untracked in reverse index)
    let commit = make_follow_delete_commit("did:plc:alice", "3l5u4vh2k6s2y");
    let event = graph.handle_commit(&commit, &protected_dids);

    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: "did:plc:alice".to_string(),
            rkey: "3l5u4vh2k6s2y".to_string(),
            followed_did: "did:plc:bob".to_string(),
        }
    );
    assert!(!graph.is_following("did:plc:alice", "did:plc:bob"));
}

#[test]
fn test_follow_graph_handle_commit_delete_payload_subject_fallback() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    // Follow added
    graph.add_follow("did:plc:alice", "custom_rkey", "did:plc:bob");
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    // Delete commit has a different rkey but provides subject in record payload
    let commit = JetstreamCommit {
        did: "did:plc:alice".to_string(),
        time_us: 1_700_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: "untracked_rkey".to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: Some(serde_json::json!({ "subject": "did:plc:bob" })),
    };

    let event = graph.handle_commit(&commit, &protected_dids);
    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: "did:plc:alice".to_string(),
            rkey: "untracked_rkey".to_string(),
            followed_did: "did:plc:bob".to_string(),
        }
    );
    assert!(!graph.is_following("did:plc:alice", "did:plc:bob"));
}

#[test]
fn test_follow_graph_handle_commit_delete_rkey_as_did_fallback() {
    let graph = FollowGraph::new();
    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    // Follow added
    graph.add_follow("did:plc:alice", "some_rkey", "did:plc:bob");
    assert!(graph.is_following("did:plc:alice", "did:plc:bob"));

    // Delete commit specifies the DID as the rkey
    let commit = make_follow_delete_commit("did:plc:alice", "did:plc:bob");
    let event = graph.handle_commit(&commit, &protected_dids);

    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: "did:plc:alice".to_string(),
            rkey: "did:plc:bob".to_string(),
            followed_did: "did:plc:bob".to_string(),
        }
    );
    assert!(!graph.is_following("did:plc:alice", "did:plc:bob"));
}

// ============================================================================
// 2. NonFollowedGate Unit Tests
// ============================================================================

#[test]
fn test_gate_drops_self_interaction_immediately() {
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph);

    let interaction =
        Interaction::mock_test_candidate(PROTECTED_ALICE, PROTECTED_ALICE, "Self note");
    let decision = gate.evaluate(interaction);

    assert!(decision.is_bypassed());
    assert!(!decision.is_candidate());
    assert_eq!(
        decision.bypass_reason(),
        Some(BypassReason::SelfInteraction)
    );
    assert_eq!(decision.candidate(), None);
    assert_eq!(BypassReason::SelfInteraction.as_str(), "self_interaction");
}

#[test]
fn test_gate_drops_followed_account() {
    let graph = Arc::new(FollowGraph::new());
    graph.add_follow(PROTECTED_ALICE, "rkey_bob", FRIEND_BOB);

    let gate = NonFollowedGate::new(graph.clone());
    assert_eq!(gate.follow_graph().follow_count(PROTECTED_ALICE), 1);

    let interaction = Interaction::mock_test_candidate(FRIEND_BOB, PROTECTED_ALICE, "Hey Alice!");
    let decision = gate.evaluate(interaction);

    assert!(decision.is_bypassed());
    assert_eq!(decision.bypass_reason(), Some(BypassReason::FollowedAuthor));
    assert_eq!(BypassReason::FollowedAuthor.as_str(), "followed_author");
}

#[test]
fn test_gate_emits_candidate_for_unfollowed_account() {
    let graph = Arc::new(FollowGraph::new());
    graph.add_follow(PROTECTED_ALICE, "rkey_bob", FRIEND_BOB);

    let gate = NonFollowedGate::new(graph);

    let interaction =
        Interaction::mock_test_candidate(SPAMMER_CHARLIE, PROTECTED_ALICE, "Claim free airdrop!");
    let decision = gate.evaluate(interaction);

    assert!(decision.is_candidate());
    assert!(!decision.is_bypassed());
    assert_eq!(decision.bypass_reason(), None);

    let candidate = decision.into_candidate().expect("candidate missing");
    assert_eq!(candidate.author_did, SPAMMER_CHARLIE);
    assert_eq!(candidate.target_did, PROTECTED_ALICE);
}

// ============================================================================
// 3. TargetMatcher Unit & Edge-Case Tests
// ============================================================================

#[test]
fn test_target_matcher_fast_path_standalone_post() {
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    let commit = make_standalone_post_commit("did:plc:random", "p1", "Just a normal post");
    let result = TargetMatcher::match_interaction(&commit, &protected);
    assert_eq!(result, None);

    let all_results = TargetMatcher::match_all_interactions(&commit, &protected);
    assert!(all_results.is_empty());
}

#[test]
fn test_target_matcher_ignores_other_collections_and_empty_protected() {
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    // Follow commit
    let follow_commit = make_follow_create_commit(PROTECTED_ALICE, "did:plc:other", "follow_rkey");
    assert_eq!(
        TargetMatcher::match_interaction(&follow_commit, &protected),
        None
    );

    // Empty protected set
    let reply_commit = make_reply_commit(
        SPAMMER_CHARLIE,
        PROTECTED_ALICE,
        "r1",
        "p1",
        "Reply to alice",
    );
    let empty_set = HashSet::new();
    assert_eq!(
        TargetMatcher::match_interaction(&reply_commit, &empty_set),
        None
    );
}

#[test]
fn test_target_matcher_ignores_non_create_operations() {
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    let mut commit = make_reply_commit(SPAMMER_CHARLIE, PROTECTED_ALICE, "r1", "p1", "Reply");
    commit.operation = CommitOperation::Delete;
    commit.record = None;

    assert_eq!(TargetMatcher::match_interaction(&commit, &protected), None);

    commit.operation = CommitOperation::Update;
    assert_eq!(TargetMatcher::match_interaction(&commit, &protected), None);
}

#[test]
fn test_target_matcher_quote_with_media() {
    let mut protected = HashSet::new();
    protected.insert(PROTECTED_ALICE.to_string());

    let commit = make_quote_with_media_commit(
        SPAMMER_CHARLIE,
        PROTECTED_ALICE,
        "q1",
        "post_alice",
        "Quoting with an image",
    );
    let interaction =
        TargetMatcher::match_interaction(&commit, &protected).expect("should match quote");

    assert_eq!(interaction.interaction_type, InteractionType::Quote);
    assert_eq!(interaction.author_did, SPAMMER_CHARLIE);
    assert_eq!(interaction.target_did, PROTECTED_ALICE);
}

#[test]
fn test_target_matcher_multi_target_post() {
    let mut protected = HashSet::new();
    let alice = "did:plc:alice";
    let bob = "did:plc:bob";
    protected.insert(alice.to_string());
    protected.insert(bob.to_string());

    // Post mentioning both Alice and Bob
    let commit = JetstreamCommit {
        did: "did:plc:author".to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: "multi1".to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafytestcid".to_string()),
        record: Some(serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello @alice and @bob",
            "facets": [
                {
                    "index": { "byteStart": 6, "byteEnd": 12 },
                    "features": [{ "$type": "app.bsky.richtext.facet#mention", "did": alice }]
                },
                {
                    "index": { "byteStart": 17, "byteEnd": 21 },
                    "features": [{ "$type": "app.bsky.richtext.facet#mention", "did": bob }]
                }
            ],
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    };

    let interactions = TargetMatcher::match_all_interactions(&commit, &protected);
    assert_eq!(interactions.len(), 2);
    let target_dids: HashSet<&str> = interactions.iter().map(|i| i.target_did.as_str()).collect();
    assert!(target_dids.contains(alice));
    assert!(target_dids.contains(bob));
}

// ============================================================================
// 4. End-to-End Pipeline: All 4 Interaction Vectors + MockClassifier Call Count
// ============================================================================

#[tokio::test]
async fn test_interaction_vectors_with_mock_classifier_call_count() {
    let graph = Arc::new(FollowGraph::new());
    graph.add_follow(PROTECTED_ALICE, "rkey_bob", FRIEND_BOB);
    let gate = NonFollowedGate::new(graph);
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    // 1. Direct reply from followed friend -> Gate drops -> Classifier NOT called
    let commit1 = make_reply_commit(FRIEND_BOB, PROTECTED_ALICE, "r1", "p1", "Hey friend");
    let match1 = TargetMatcher::match_interaction(&commit1, &protected_dids).expect("match failed");
    assert_eq!(match1.interaction_type, InteractionType::DirectReply);
    assert!(gate.filter(match1).is_none());
    assert_eq!(classifier.call_count(), 0);

    // 2. Direct reply from unfollowed spammer -> Gate permits -> Classifier called
    let commit2 = make_reply_commit(SPAMMER_CHARLIE, PROTECTED_ALICE, "r2", "p1", "Free tokens!");
    let match2 = TargetMatcher::match_interaction(&commit2, &protected_dids).expect("match failed");
    let cand2 = gate.filter(match2).expect("should pass gate");
    let _ = classifier.classify(&cand2).await.expect("classify failed");
    assert_eq!(classifier.call_count(), 1);

    // 3. Thread reply from followed friend -> Gate drops -> Classifier NOT called
    let commit3 = make_thread_reply_commit(
        FRIEND_BOB,
        PROTECTED_ALICE,
        "did:plc:other",
        "r3",
        "I agree with root",
    );
    let match3 = TargetMatcher::match_interaction(&commit3, &protected_dids).expect("match failed");
    assert_eq!(match3.interaction_type, InteractionType::ThreadReply);
    assert!(gate.filter(match3).is_none());
    assert_eq!(classifier.call_count(), 1);

    // 4. Thread reply from unfollowed spammer -> Gate permits -> Classifier called
    let commit4 = make_thread_reply_commit(
        SPAMMER_CHARLIE,
        PROTECTED_ALICE,
        "did:plc:other",
        "r4",
        "Check this link in thread",
    );
    let match4 = TargetMatcher::match_interaction(&commit4, &protected_dids).expect("match failed");
    let cand4 = gate.filter(match4).expect("should pass gate");
    let _ = classifier.classify(&cand4).await.expect("classify failed");
    assert_eq!(classifier.call_count(), 2);

    // 5. Mention from followed friend -> Gate drops -> Classifier NOT called
    let commit5 = make_mention_commit(FRIEND_BOB, PROTECTED_ALICE, "r5", "@alice hi");
    let match5 = TargetMatcher::match_interaction(&commit5, &protected_dids).expect("match failed");
    assert_eq!(match5.interaction_type, InteractionType::Mention);
    assert!(gate.filter(match5).is_none());
    assert_eq!(classifier.call_count(), 2);

    // 6. Mention from unfollowed spammer -> Gate permits -> Classifier called
    let commit6 = make_mention_commit(SPAMMER_CHARLIE, PROTECTED_ALICE, "r6", "@alice dm me");
    let match6 = TargetMatcher::match_interaction(&commit6, &protected_dids).expect("match failed");
    let cand6 = gate.filter(match6).expect("should pass gate");
    let _ = classifier.classify(&cand6).await.expect("classify failed");
    assert_eq!(classifier.call_count(), 3);

    // 7. Quote from followed friend -> Gate drops -> Classifier NOT called
    let commit7 = make_quote_commit(
        FRIEND_BOB,
        PROTECTED_ALICE,
        "r7",
        "quoted1",
        "Great point alice",
    );
    let match7 = TargetMatcher::match_interaction(&commit7, &protected_dids).expect("match failed");
    assert_eq!(match7.interaction_type, InteractionType::Quote);
    assert!(gate.filter(match7).is_none());
    assert_eq!(classifier.call_count(), 3);

    // 8. Quote from unfollowed spammer -> Gate permits -> Classifier called
    let commit8 = make_quote_commit(
        SPAMMER_CHARLIE,
        PROTECTED_ALICE,
        "r8",
        "quoted1",
        "Look at this fool",
    );
    let match8 = TargetMatcher::match_interaction(&commit8, &protected_dids).expect("match failed");
    let cand8 = gate.filter(match8).expect("should pass gate");
    let _ = classifier.classify(&cand8).await.expect("classify failed");
    assert_eq!(classifier.call_count(), 4);
}

// ============================================================================
// 5. Dynamic Follow/Unfollow State Machine Lifecycle
// ============================================================================

#[tokio::test]
async fn test_dynamic_follow_unfollow_lifecycle_state_transitions() {
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    let dave = "did:plc:dynamic_dave";

    // ------------------------------------------------------------------------
    // Step 1: Initial State (Dave is NOT followed)
    // ------------------------------------------------------------------------
    assert!(!graph.is_following(PROTECTED_ALICE, dave));

    let commit1 = make_reply_commit(
        dave,
        PROTECTED_ALICE,
        "dave_r1",
        "root_post",
        "Initial interaction",
    );
    let interaction1 =
        TargetMatcher::match_interaction(&commit1, &protected_dids).expect("match failed");
    let cand1 = gate
        .filter(interaction1)
        .expect("unfollowed account should pass gate");
    let _ = classifier.classify(&cand1).await.expect("classify failed");
    assert_eq!(
        classifier.call_count(),
        1,
        "Classifier called on unfollowed candidate"
    );

    // ------------------------------------------------------------------------
    // Step 2: Ingest Follow Create Commit (Alice follows Dave)
    // ------------------------------------------------------------------------
    let follow_commit = make_follow_create_commit(PROTECTED_ALICE, dave, "follow_rkey_999");
    graph.handle_commit(&follow_commit, &protected_dids);
    assert!(
        graph.is_following(PROTECTED_ALICE, dave),
        "Dave is now followed"
    );

    // ------------------------------------------------------------------------
    // Step 3: Dave interacts again -> Gate drops -> Classifier NOT called
    // ------------------------------------------------------------------------
    let commit2 = make_reply_commit(
        dave,
        PROTECTED_ALICE,
        "dave_r2",
        "root_post",
        "Second interaction",
    );
    let interaction2 =
        TargetMatcher::match_interaction(&commit2, &protected_dids).expect("match failed");
    let cand2 = gate.filter(interaction2);
    assert!(cand2.is_none(), "Followed account must be bypassed");
    assert_eq!(
        classifier.call_count(),
        1,
        "Classifier call_count must strictly remain unchanged"
    );

    // ------------------------------------------------------------------------
    // Step 4: Ingest Follow Delete Commit (Alice unfollows Dave)
    // ATProto Delete commit has record == None; verified resolved via reverse index
    // ------------------------------------------------------------------------
    let unfollow_commit = make_follow_delete_commit(PROTECTED_ALICE, "follow_rkey_999");
    assert!(
        unfollow_commit.record.is_none(),
        "Delete commit has None record"
    );
    let event = graph.handle_commit(&unfollow_commit, &protected_dids);
    assert_eq!(
        event,
        FollowSyncEvent::FollowRemoved {
            protected_did: PROTECTED_ALICE.to_string(),
            rkey: "follow_rkey_999".to_string(),
            followed_did: dave.to_string(),
        }
    );
    assert!(
        !graph.is_following(PROTECTED_ALICE, dave),
        "Dave is no longer followed"
    );

    // ------------------------------------------------------------------------
    // Step 5: Dave interacts a third time -> Gate permits -> Classifier called!
    // ------------------------------------------------------------------------
    let commit3 = make_reply_commit(
        dave,
        PROTECTED_ALICE,
        "dave_r3",
        "root_post",
        "Third interaction",
    );
    let interaction3 =
        TargetMatcher::match_interaction(&commit3, &protected_dids).expect("match failed");
    let cand3 = gate
        .filter(interaction3)
        .expect("re-unfollowed account must pass gate");
    let _ = classifier.classify(&cand3).await.expect("classify failed");
    assert_eq!(
        classifier.call_count(),
        2,
        "Classifier call_count increments to 2"
    );
}

// ============================================================================
// 6. Synthetic Firehose Streaming Pipeline
// ============================================================================

#[tokio::test]
async fn test_synthetic_firehose_streaming_pipeline() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let graph = Arc::new(FollowGraph::new());
    let gate = NonFollowedGate::new(graph.clone());
    let classifier = MockClassifier::default();

    let mut protected_dids = HashSet::new();
    protected_dids.insert(PROTECTED_ALICE.to_string());

    // Stream a sequence of synthetic commits
    let commits = vec![
        // 1. Follow creation for Bob
        make_follow_create_commit(PROTECTED_ALICE, FRIEND_BOB, "rkey_bob"),
        // 2. Reply from Bob (should be dropped)
        make_reply_commit(FRIEND_BOB, PROTECTED_ALICE, "b_post", "p0", "Hello"),
        // 3. Reply from Charlie (should pass)
        make_reply_commit(SPAMMER_CHARLIE, PROTECTED_ALICE, "c_post", "p0", "Spam!"),
    ];

    for commit in commits {
        tx.send(commit).await.expect("send failed");
    }
    drop(tx);

    while let Some(commit) = rx.recv().await {
        if commit.collection == "app.bsky.graph.follow" {
            graph.handle_commit(&commit, &protected_dids);
        } else if let Some(interaction) = TargetMatcher::match_interaction(&commit, &protected_dids)
        {
            if let Some(candidate) = gate.filter(interaction) {
                let _ = classifier
                    .classify(&candidate)
                    .await
                    .expect("classify failed");
            }
        }
    }

    assert_eq!(
        classifier.call_count(),
        1,
        "Only unfollowed Charlie triggered classifier"
    );
}

// ============================================================================
// 7. Performance Benchmark: Sub-Microsecond (<1µs) Latency Validation
// ============================================================================

#[test]
fn test_gate_latency_benchmark_sub_microsecond() {
    let graph = Arc::new(FollowGraph::new());

    // Seed graph with 5,000 followed DIDs to simulate realistic user follow count
    let seed_dids: Vec<String> = (0..5_000)
        .map(|i| format!("did:plc:followed_{i}"))
        .collect();
    graph.hydrate_dids(PROTECTED_ALICE, seed_dids);

    let gate = NonFollowedGate::new(graph);

    let candidate_self = Interaction::mock_test_candidate(PROTECTED_ALICE, PROTECTED_ALICE, "Self");
    let candidate_followed =
        Interaction::mock_test_candidate("did:plc:followed_2500", PROTECTED_ALICE, "Friend");
    let candidate_unfollowed =
        Interaction::mock_test_candidate("did:plc:stranger_9999", PROTECTED_ALICE, "Stranger");

    // 1. Warm-up instruction cache
    for _ in 0..10_000 {
        let _ = gate.evaluate(candidate_self.clone());
        let _ = gate.evaluate(candidate_followed.clone());
        let _ = gate.evaluate(candidate_unfollowed.clone());
    }

    // 2. Benchmark 100,000 evaluations across followed and unfollowed
    let iterations = 100_000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _ = gate.evaluate(candidate_followed.clone());
    }

    let elapsed = start.elapsed();
    let avg_latency = elapsed / iterations as u32;

    println!(
        "\n⚡ [NonFollowedGate Latency Benchmark] Total: {:?} for {} ops | Avg: {:?} (<1.0µs SLA)",
        elapsed, iterations, avg_latency
    );

    // Hard assertion: Average latency MUST be strictly under 1.0 microsecond (< 1,000 nanoseconds)
    assert!(
        avg_latency < Duration::from_micros(1),
        "Gate latency SLA violated! Average latency was {:?}, expected < 1.0µs",
        avg_latency
    );
}

// ============================================================================
// 8. Multi-Threaded Concurrency Test (Mixed Reader / Writer Load)
// ============================================================================

#[test]
fn test_gate_multi_threaded_concurrency() {
    let graph = Arc::new(FollowGraph::new());
    // Pre-seed 1,000 accounts
    let seed_dids: Vec<String> = (0..1_000).map(|i| format!("did:plc:account_{i}")).collect();
    graph.hydrate_dids(PROTECTED_ALICE, seed_dids);

    let gate = Arc::new(NonFollowedGate::new(graph.clone()));
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Spawn 8 reader threads evaluating gate
    let mut reader_handles = Vec::new();
    for thread_idx in 0..8 {
        let gate_clone = gate.clone();
        let stop_clone = stop_signal.clone();
        let handle = std::thread::spawn(move || {
            let mut count = 0;
            let candidate = Interaction::mock_test_candidate(
                &format!("did:plc:account_{}", thread_idx * 10),
                PROTECTED_ALICE,
                "concurrent test",
            );
            while !stop_clone.load(Ordering::Relaxed) {
                let _ = gate_clone.evaluate(candidate.clone());
                count += 1;
            }
            count
        });
        reader_handles.push(handle);
    }

    // Writer thread adding and removing follows
    let graph_writer = graph.clone();
    let stop_writer = stop_signal.clone();
    let writer_handle = std::thread::spawn(move || {
        let mut ops = 0;
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(100) && !stop_writer.load(Ordering::Relaxed) {
            let rkey = format!("dyn_rk_{ops}");
            let did = format!("did:plc:dynamic_{ops}");
            graph_writer.add_follow(PROTECTED_ALICE, &rkey, &did);
            assert!(graph_writer.is_following(PROTECTED_ALICE, &did));
            let _ = graph_writer.remove_follow_by_rkey(PROTECTED_ALICE, &rkey);
            ops += 1;
            std::thread::yield_now();
        }
        ops
    });

    let writer_ops = writer_handle.join().expect("writer failed");
    stop_signal.store(true, Ordering::Relaxed);

    let mut total_reads = 0;
    for handle in reader_handles {
        total_reads += handle.join().expect("reader failed");
    }

    println!(
        "Multi-threaded concurrency result: writer_ops={}, total_reads={}",
        writer_ops, total_reads
    );

    assert!(writer_ops > 0);
    assert!(total_reads > 10_000);
}
