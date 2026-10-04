//! Comprehensive End-to-End (E2E) Integration Test Suite for Milestone 4 (F17, F20).
//!
//! Validates the entire `skybouncer` moderation pipeline from synthetic Jetstream
//! commit ingestion, through the sub-microsecond Non-Followed Gate, SQLite deduplication
//! caching, pluggable Jev classification, sovereign PDS list mutations, and graceful shutdown.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use parking_lot::Mutex;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybase::ingest::events::JetstreamCommit;
use skybouncer::classifier::{
    Classifier, JevClassifier, JevConfig, RuleRubric, Sensitivity, Verdict, ViolationCategory,
};
use skybouncer::engine::{
    InteractionOutcome, ProcessCommitResult, SkybouncerConfig, SkybouncerEngine,
};
use skybouncer::matcher::{BypassReason, FollowGraph, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};

// =============================================================================
// Mock Jev Server Test Double
// =============================================================================

/// Hermetic Mock Jev "System 1" HTTP classifier server.
pub struct MockJevServer {
    server: MockServer,
    pub classify_count: Arc<AtomicUsize>,
    pub received_requests: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl MockJevServer {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let classify_count = Arc::new(AtomicUsize::new(0));
        let received_requests = Arc::new(Mutex::new(Vec::new()));

        let count = Arc::clone(&classify_count);
        let reqs = Arc::clone(&received_requests);

        // Dynamic classification responder
        Mock::given(method("POST"))
            .and(path("/v1/classify"))
            .respond_with(move |req: &wiremock::Request| {
                count.fetch_add(1, Ordering::SeqCst);
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                reqs.lock().push(body.clone());

                let text = body["text"].as_str().unwrap_or("").to_lowercase();

                // Heuristic violation response: trigger on "toxic", "scam", "airdrop", "idiot"
                if text.contains("toxic")
                    || text.contains("scam")
                    || text.contains("airdrop")
                    || text.contains("idiot")
                {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "violates": true,
                        "category": "harassment",
                        "confidence": 0.95,
                        "reason": "Severe targeted hostility detected by System 1 model"
                    }))
                } else if text.contains("borderline") {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "violates": true,
                        "category": "harassment",
                        "confidence": 0.65,
                        "reason": "Mild sarcasm below strict threshold"
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "violates": false,
                        "category": null,
                        "confidence": 0.05,
                        "reason": "Polite discourse"
                    }))
                }
            })
            .mount(&server)
            .await;

        Self {
            server,
            classify_count,
            received_requests,
        }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn config(&self) -> JevConfig {
        JevConfig {
            base_url: self.uri(),
            api_key: Some("test_secret_key".to_string()),
            model: "jev-system1-mod-v1".to_string(),
            timeout: Duration::from_millis(1500),
            max_retries: 1,
        }
    }

    pub fn classifier(&self, rubric: RuleRubric) -> Arc<dyn Classifier> {
        let classifier = JevClassifier::new(self.config(), rubric)
            .expect("JevClassifier creation should succeed");
        Arc::new(classifier)
    }
}

// =============================================================================
// Composite Test Fixture Harness
// =============================================================================

pub struct TestEngineFixture {
    pub pds: MockPdsServer,
    pub jev: MockJevServer,
    pub cache: Arc<DeduplicationCache>,
    pub follow_graph: Arc<FollowGraph>,
    pub gate: Arc<NonFollowedGate>,
    pub modlist_manager: Arc<ModListManager>,
    pub engine: Arc<SkybouncerEngine>,
    pub protected_did: String,
}

impl TestEngineFixture {
    pub async fn start(protected_did: &str) -> Self {
        let pds = MockPdsServer::start().await;
        let jev = MockJevServer::start().await;

        let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
        let follow_graph = Arc::new(FollowGraph::new());
        let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

        let rubric = RuleRubric::new("Block toxicity and harassment", Sensitivity::Medium);
        let modlist_manager = Arc::new(
            ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()),
        );

        let pds_client = Arc::new(pds.pds_client(protected_did));
        let classifier = jev.classifier(rubric.clone());

        let mut protected_dids = HashSet::new();
        protected_dids.insert(protected_did.to_string());

        let config = SkybouncerConfig::new(protected_dids, rubric).with_channel_capacity(100);

        let engine = Arc::new(SkybouncerEngine::new(
            config,
            Arc::clone(&follow_graph),
            Arc::clone(&gate),
            classifier,
            Arc::clone(&modlist_manager),
            pds_client,
        ));

        Self {
            pds,
            jev,
            cache,
            follow_graph,
            gate,
            modlist_manager,
            engine,
            protected_did: protected_did.to_string(),
        }
    }

    pub fn add_follow(&self, follower: &str, followed: &str, rkey: &str) {
        self.follow_graph.add_follow(follower, rkey, followed);
    }

    pub fn is_bounced(&self, did: &str) -> bool {
        self.cache.is_bounced(did).expect("cache query")
    }

    pub fn count_pds_listitems_for(&self, subject_did: &str) -> usize {
        let records = self.pds.created_records.lock();
        records
            .iter()
            .filter(|r| {
                r.get("collection").and_then(|v| v.as_str()) == Some("app.bsky.graph.listitem")
                    && r.get("record")
                        .and_then(|rec| rec.get("subject"))
                        .and_then(|s| s.as_str())
                        == Some(subject_did)
            })
            .count()
    }

    pub fn count_pds_deletions_for(&self, collection: &str) -> usize {
        let records = self.pds.deleted_records.lock();
        records
            .iter()
            .filter(|r| r.get("collection").and_then(|v| v.as_str()) == Some(collection))
            .count()
    }
}

// =============================================================================
// Scenario 1: Non-Violator Interaction
// =============================================================================

#[tokio::test]
async fn test_scenario_1_non_violator_interaction_passes_without_bounce() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;

    // Polite comment from a non-followed user
    let commit = make_reply_commit(
        "did:plc:polite_carol",
        "did:plc:alice",
        "reply_1",
        "root_1",
        "Thank you for sharing this insightful article!",
    );

    let result = fixture
        .engine
        .process_commit(&commit)
        .await
        .expect("process commit");
    let outcomes = result.outcomes();
    assert_eq!(outcomes.len(), 1);

    match &outcomes[0] {
        InteractionOutcome::Permitted {
            author_did, reason, ..
        } => {
            assert_eq!(author_did, "did:plc:polite_carol");
            assert_eq!(reason, "Polite discourse");
        }
        other => panic!("Expected Permitted outcome, got {other:?}"),
    }

    // 1 Jev call made
    assert_eq!(fixture.jev.classify_count.load(Ordering::SeqCst), 1);
    // 0 PDS writes
    assert_eq!(fixture.pds.created_records.lock().len(), 0);
    // Not recorded as bounced in cache
    assert!(!fixture.is_bounced("did:plc:polite_carol"));
}

// =============================================================================
// Scenario 2: Toxic Direct Reply Bounce
// =============================================================================

#[tokio::test]
async fn test_scenario_2_toxic_direct_reply_bounces_violator_on_pds_and_cache() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;

    // Toxic reply from non-followed user
    let commit = make_reply_commit(
        "did:plc:toxic_troll",
        "did:plc:alice",
        "reply_toxic_1",
        "root_1",
        "You are an idiot and should delete your account! Free crypto at https://evil.scam",
    );

    let result = fixture
        .engine
        .process_commit(&commit)
        .await
        .expect("process commit");
    let outcomes = result.outcomes();
    assert_eq!(outcomes.len(), 1);

    match &outcomes[0] {
        InteractionOutcome::Bounced {
            author_did,
            target_did,
            listitem_uri,
            category,
            confidence,
            ..
        } => {
            assert_eq!(author_did, "did:plc:toxic_troll");
            assert_eq!(target_did, "did:plc:alice");
            assert!(listitem_uri.contains("app.bsky.graph.listitem"));
            assert_eq!(*category, ViolationCategory::Harassment);
            assert!((*confidence - 0.95).abs() < 1e-6);
        }
        other => panic!("Expected Bounced outcome, got {other:?}"),
    }

    // Exactly 1 Jev call
    assert_eq!(fixture.jev.classify_count.load(Ordering::SeqCst), 1);
    // Exactly 1 listitem created on PDS
    assert_eq!(fixture.count_pds_listitems_for("did:plc:toxic_troll"), 1);
    // Recorded in SQLite cache
    assert!(fixture.is_bounced("did:plc:toxic_troll"));

    // Verify cache detail entry
    let bounced_record = fixture
        .cache
        .get_bounced_user("did:plc:toxic_troll")
        .expect("cache get")
        .expect("bounced user record exists");
    assert_eq!(bounced_record.subject_did, "did:plc:toxic_troll");
    assert_eq!(bounced_record.category, "harassment");
}

// =============================================================================
// Scenario 3: Toxic Followed User Exemption ($0 Cost Guarantee)
// =============================================================================

#[tokio::test]
async fn test_scenario_3_toxic_followed_user_exemption_zero_cost_bypass() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;

    // Alice actively follows Bob
    fixture.add_follow("did:plc:alice", "did:plc:friend_bob", "follow_rkey_bob");

    // Bob posts identical toxic text that would normally be bounced
    let commit = make_reply_commit(
        "did:plc:friend_bob",
        "did:plc:alice",
        "reply_toxic_bob",
        "root_1",
        "You are an idiot and should delete your account! Free crypto at https://evil.scam",
    );

    let result = fixture
        .engine
        .process_commit(&commit)
        .await
        .expect("process commit");
    let outcomes = result.outcomes();
    assert_eq!(outcomes.len(), 1);

    match &outcomes[0] {
        InteractionOutcome::Bypassed {
            reason,
            author_did,
            target_did,
        } => {
            assert_eq!(*reason, BypassReason::FollowedAuthor);
            assert_eq!(author_did, "did:plc:friend_bob");
            assert_eq!(target_did, "did:plc:alice");
        }
        other => panic!("Expected Bypassed outcome, got {other:?}"),
    }

    // CRITICAL: Mathematically verify $0 cost & zero network overhead
    assert_eq!(
        fixture.jev.classify_count.load(Ordering::SeqCst),
        0,
        "Classifier must NEVER be called for followed users ($0 cost invariant)"
    );
    assert_eq!(
        fixture.pds.created_records.lock().len(),
        0,
        "PDS must NEVER be mutated for followed users"
    );
    assert!(!fixture.is_bounced("did:plc:friend_bob"));
}

// =============================================================================
// Scenario 4: Dynamic Follow Lifecycle (Follow / Unfollow / Bounce / Pardon)
// =============================================================================

#[tokio::test]
async fn test_scenario_4_dynamic_follow_lifecycle_and_pardon() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;

    // 1. Initial state: Mallory is unfollowed and posts toxic reply -> Bounced
    let toxic_commit = make_reply_commit(
        "did:plc:mallory",
        "did:plc:alice",
        "reply_mallory_1",
        "root_1",
        "toxic attack 1",
    );
    let result = fixture
        .engine
        .process_commit(&toxic_commit)
        .await
        .expect("process");
    let outcomes = result.outcomes();
    assert!(matches!(&outcomes[0], InteractionOutcome::Bounced { .. }));
    assert!(fixture.is_bounced("did:plc:mallory"));
    assert_eq!(fixture.count_pds_listitems_for("did:plc:mallory"), 1);

    // 2. Alice follows Mallory on Jetstream -> FollowGraph dynamically updates
    let follow_commit =
        make_follow_create_commit("did:plc:alice", "did:plc:mallory", "follow_rk_123");
    let result = fixture
        .engine
        .process_commit(&follow_commit)
        .await
        .expect("process");
    assert!(matches!(result, ProcessCommitResult::FollowSynced(_)));
    assert!(fixture
        .follow_graph
        .is_following("did:plc:alice", "did:plc:mallory"));

    // 3. Alice pardons Mallory
    let pardoned = fixture
        .engine
        .pardon_user("did:plc:alice", "did:plc:mallory")
        .await
        .expect("pardon");
    assert!(pardoned);
    assert!(!fixture.is_bounced("did:plc:mallory"));
    assert_eq!(
        fixture.count_pds_deletions_for("app.bsky.graph.listitem"),
        1
    );

    // 4. Mallory posts toxic reply while followed -> Bypassed ($0 cost)
    let jev_count_before = fixture.jev.classify_count.load(Ordering::SeqCst);
    let result = fixture
        .engine
        .process_commit(&toxic_commit)
        .await
        .expect("process");
    let outcomes = result.outcomes();
    assert!(matches!(
        &outcomes[0],
        InteractionOutcome::Bypassed {
            reason: BypassReason::FollowedAuthor,
            ..
        }
    ));
    assert_eq!(
        fixture.jev.classify_count.load(Ordering::SeqCst),
        jev_count_before
    );

    // 5. Alice unfollows Mallory on Jetstream -> Reverse index removes follow
    let unfollow_commit = make_follow_delete_commit("did:plc:alice", "follow_rk_123");
    let result = fixture
        .engine
        .process_commit(&unfollow_commit)
        .await
        .expect("process");
    assert!(matches!(result, ProcessCommitResult::FollowSynced(_)));
    assert!(!fixture
        .follow_graph
        .is_following("did:plc:alice", "did:plc:mallory"));

    // 6. Mallory posts toxic reply while unfollowed -> Bounced again on PDS!
    let toxic_commit_2 = make_reply_commit(
        "did:plc:mallory",
        "did:plc:alice",
        "reply_mallory_2",
        "root_1",
        "toxic attack 2 after unfollow",
    );
    let result = fixture
        .engine
        .process_commit(&toxic_commit_2)
        .await
        .expect("process");
    let outcomes = result.outcomes();
    assert!(matches!(&outcomes[0], InteractionOutcome::Bounced { .. }));
    assert!(fixture.is_bounced("did:plc:mallory"));
    assert_eq!(fixture.count_pds_listitems_for("did:plc:mallory"), 2);
}

// =============================================================================
// Scenario 5: Thundering Herd Deduplication
// =============================================================================

#[tokio::test]
async fn test_scenario_5_thundering_herd_duplicate_violations_deduplicated() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;
    let engine = Arc::clone(&fixture.engine);

    // 20 concurrent tasks all submitting toxic replies from the same violator
    let mut handles = Vec::new();
    for i in 0..20 {
        let eng = Arc::clone(&engine);
        handles.push(tokio::spawn(async move {
            let commit = make_reply_commit(
                "did:plc:spammer_herd",
                "did:plc:alice",
                &format!("reply_burst_{i}"),
                "root_1",
                "toxic spam burst message",
            );
            eng.process_commit(&commit).await
        }));
    }

    let mut bounced_count = 0;
    let mut already_bounced_count = 0;

    for handle in handles {
        let res = handle.await.expect("task join").expect("process commit");
        let outcomes = res.into_outcomes();
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            InteractionOutcome::Bounced { .. } => bounced_count += 1,
            InteractionOutcome::AlreadyBounced { .. } => already_bounced_count += 1,
            other => panic!("Unexpected outcome in thundering herd: {other:?}"),
        }
    }

    // Exactly 1 task must execute the bounce; 19 tasks must be deduplicated
    assert_eq!(
        bounced_count, 1,
        "Exactly one task must execute the initial bounce"
    );
    assert_eq!(
        already_bounced_count, 19,
        "Remaining 19 tasks must short-circuit"
    );
    assert_eq!(
        fixture.count_pds_listitems_for("did:plc:spammer_herd"),
        1,
        "PDS must receive exactly ONE listitem mutation"
    );
    assert!(fixture.is_bounced("did:plc:spammer_herd"));
}

// =============================================================================
// Scenario 6: Graceful Engine Shutdown
// =============================================================================

#[tokio::test]
async fn test_scenario_6_graceful_engine_shutdown_drains_and_joins() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;
    let engine = Arc::clone(&fixture.engine);

    let (tx, rx) = tokio::sync::mpsc::channel::<JetstreamCommit>(100);
    let cancel_token = CancellationToken::new();

    let mut join_set = tokio::task::JoinSet::new();
    let child_token = cancel_token.child_token();

    join_set.spawn(async move { engine.run(rx, child_token).await });

    // Send a stream of commits
    tx.send(make_follow_create_commit(
        "did:plc:alice",
        "did:plc:friend_1",
        "rk_1",
    ))
    .await
    .expect("send");
    tx.send(make_reply_commit(
        "did:plc:polite_user",
        "did:plc:alice",
        "rep_1",
        "rt_1",
        "polite hello",
    ))
    .await
    .expect("send");
    tx.send(make_reply_commit(
        "did:plc:toxic_user",
        "did:plc:alice",
        "rep_2",
        "rt_1",
        "toxic comment",
    ))
    .await
    .expect("send");

    // Allow brief time for processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Trigger cooperative cancellation
    cancel_token.cancel();

    // Verify task joins cleanly within timeout guard
    let join_result = tokio::time::timeout(Duration::from_secs(2), join_set.join_next()).await;
    assert!(
        join_result.is_ok(),
        "Engine must terminate within 2s without hanging"
    );

    let task_output = join_result.unwrap().expect("task yielded");
    let stats = task_output
        .expect("task completed without panic")
        .expect("engine run ok");

    assert!(stats.commits_received >= 3);
    assert_eq!(stats.follows_synced, 1);
    assert_eq!(stats.permitted, 1);
    assert_eq!(stats.bounced, 1);
    assert!(
        join_set.is_empty(),
        "All background tasks must be cleanly drained"
    );
}

// =============================================================================
// Scenario 7: Multi-Target Post Discrimination (Friend vs Stranger)
// =============================================================================

#[tokio::test]
async fn test_scenario_7_multi_target_discrimination_friend_vs_stranger() {
    let pds = MockPdsServer::start().await;
    let jev = MockJevServer::start().await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    // Alice follows author; Bob does NOT follow author
    follow_graph.add_follow("did:plc:alice", "rk_alice", "did:plc:multi_author");

    let rubric = RuleRubric::new("Block toxicity", Sensitivity::Medium);
    let modlist_manager = Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)));
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));
    let classifier = jev.classifier(rubric.clone());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());
    protected_dids.insert("did:plc:bob".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric).with_channel_capacity(100);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    );

    // Commit mentions both Alice and Bob with toxic text
    let commit = make_thread_reply_commit(
        "did:plc:multi_author",
        "did:plc:alice",
        "did:plc:bob",
        "rep_multi",
        "toxic attack targeting both of you",
    );

    let result = engine
        .process_commit(&commit)
        .await
        .expect("process commit");
    let outcomes = result.into_outcomes();
    assert_eq!(outcomes.len(), 2);

    let alice_outcome = outcomes.iter().find(|o| {
        matches!(
            o,
            InteractionOutcome::Bypassed { target_did, .. } if target_did == "did:plc:alice"
        )
    });
    let bob_outcome = outcomes.iter().find(|o| {
        matches!(
            o,
            InteractionOutcome::Bounced { target_did, .. } if target_did == "did:plc:bob"
        )
    });

    assert!(
        alice_outcome.is_some(),
        "Alice must bypass author because she follows them"
    );
    assert!(
        bob_outcome.is_some(),
        "Bob must bounce author because he does not follow them"
    );
}

// =============================================================================
// Scenario 8: Self-Interaction Sub-Microsecond Bypass ($0 Cost)
// =============================================================================

#[tokio::test]
async fn test_scenario_8_self_interaction_instant_bypass() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;

    // Alice replies to herself in her own thread
    let commit = make_reply_commit(
        "did:plc:alice",
        "did:plc:alice",
        "self_rep_1",
        "root_1",
        "Continuing my thoughts on this topic...",
    );

    let result = fixture
        .engine
        .process_commit(&commit)
        .await
        .expect("process");
    let outcomes = result.outcomes();
    assert_eq!(outcomes.len(), 1);

    match &outcomes[0] {
        InteractionOutcome::Bypassed {
            reason, author_did, ..
        } => {
            assert_eq!(*reason, BypassReason::SelfInteraction);
            assert_eq!(author_did, "did:plc:alice");
        }
        other => panic!("Expected SelfInteraction bypass, got {other:?}"),
    }

    assert_eq!(fixture.jev.classify_count.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.pds.created_records.lock().len(), 0);
}

// =============================================================================
// Scenario 9: Rubric Sensitivity Threshold Filtering
// =============================================================================

#[tokio::test]
async fn test_scenario_9_rubric_sensitivity_threshold_filter() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;

    // Post containing "borderline" returns confidence 0.65 (Medium threshold is 0.75)
    let commit = make_reply_commit(
        "did:plc:borderline_user",
        "did:plc:alice",
        "rep_borderline",
        "root_1",
        "This is borderline mild sarcasm",
    );

    let result = fixture
        .engine
        .process_commit(&commit)
        .await
        .expect("process");
    let outcomes = result.outcomes();
    assert_eq!(outcomes.len(), 1);

    match &outcomes[0] {
        InteractionOutcome::BelowThreshold {
            category,
            confidence,
            threshold,
            ..
        } => {
            assert_eq!(*category, ViolationCategory::Harassment);
            assert!((*confidence - 0.65).abs() < 1e-6);
            assert!((*threshold - 0.75).abs() < 1e-6);
        }
        InteractionOutcome::Permitted { reason, .. } => {
            assert!(
                reason.contains("threshold")
                    || reason.contains("sarcasm")
                    || reason.contains("Polite")
            );
        }
        other => panic!("Expected BelowThreshold or Permitted outcome, got {other:?}"),
    }

    assert_eq!(fixture.jev.classify_count.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.pds.created_records.lock().len(), 0);
    assert!(!fixture.is_bounced("did:plc:borderline_user"));
}

// =============================================================================
// Scenario 10: DPoP Nonce Recovery Fault Tolerance
// =============================================================================

#[tokio::test]
async fn test_scenario_10_dpop_nonce_challenge_recovery_on_bounce() {
    let fixture = TestEngineFixture::start("did:plc:alice").await;

    // Mount 401 use_dpop_nonce challenge on PDS
    fixture
        .pds
        .mount_nonce_challenge_once("dpop_fresh_nonce_token_999")
        .await;

    let commit = make_reply_commit(
        "did:plc:dpop_violator",
        "did:plc:alice",
        "rep_dpop",
        "root_1",
        "toxic attack with nonce challenge",
    );

    let result = fixture
        .engine
        .process_commit(&commit)
        .await
        .expect("process");
    let outcomes = result.outcomes();
    assert_eq!(outcomes.len(), 1);

    assert!(matches!(&outcomes[0], InteractionOutcome::Bounced { .. }));
    assert!(fixture.is_bounced("did:plc:dpop_violator"));
    assert_eq!(fixture.count_pds_listitems_for("did:plc:dpop_violator"), 1);
}

// =============================================================================
// Scenario 11: Shadow Mode / Dry-Run Safe Firehose Processing
// =============================================================================

#[tokio::test]
async fn test_scenario_11_shadow_mode_simulates_bounces_with_zero_pds_writes() {
    let pds = MockPdsServer::start().await;
    let jev = MockJevServer::start().await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block toxicity and harassment", Sensitivity::Medium);
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(rubric.clone())
            .with_dry_run(true),
    );

    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));
    let classifier = jev.classifier(rubric.clone());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_channel_capacity(100)
        .with_dry_run(true);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        Arc::clone(&follow_graph),
        Arc::clone(&gate),
        classifier,
        Arc::clone(&modlist_manager),
        pds_client,
    ));

    assert!(engine.is_dry_run());

    // 1. Process a violating reply commit
    let commit = make_reply_commit(
        "did:plc:shadow_spammer",
        "did:plc:alice",
        "rep_shadow_1",
        "root_1",
        "toxic attack: you are worthless trash delete your account",
    );

    let result = engine.process_commit(&commit).await.expect("process");
    let outcomes = result.outcomes();
    assert_eq!(outcomes.len(), 1);

    // Assert that the outcome is Bounced with a simulated URI
    match &outcomes[0] {
        InteractionOutcome::Bounced {
            author_did,
            listitem_uri,
            ..
        } => {
            assert_eq!(author_did, "did:plc:shadow_spammer");
            assert!(listitem_uri.contains("simulated_") || listitem_uri.contains("shadow_"));
        }
        other => panic!("Expected Bounced outcome, got: {:?}", other),
    }

    // Crucial Invariant: ZERO listitems created on remote PDS!
    assert_eq!(pds.created_records.lock().len(), 0);

    // But cached locally so deduplication works
    assert!(cache
        .is_bounced("did:plc:shadow_spammer")
        .expect("cache check"));

    // 2. Second interaction from same author hits the deduplication cache ($0 cost, 0 model calls)
    let commit2 = make_reply_commit(
        "did:plc:shadow_spammer",
        "did:plc:alice",
        "rep_shadow_2",
        "root_1",
        "more spam",
    );
    let result2 = engine.process_commit(&commit2).await.expect("process");
    let outcomes2 = result2.outcomes();
    assert_eq!(outcomes2.len(), 1);
    assert_eq!(
        outcomes2[0],
        InteractionOutcome::AlreadyBounced {
            author_did: "did:plc:shadow_spammer".to_string(),
            target_did: "did:plc:alice".to_string(),
        }
    );

    // 3. Pardon works in shadow mode without calling PDS deleteRecord
    let pardoned = engine
        .pardon_user("did:plc:alice", "did:plc:shadow_spammer")
        .await
        .expect("pardon");
    assert!(pardoned);
    assert!(!cache
        .is_bounced("did:plc:shadow_spammer")
        .expect("cache check"));
    assert_eq!(pds.deleted_records.lock().len(), 0);
}

#[tokio::test]
async fn test_allowlist_bypass_latency_and_pardon_immunization_pipeline() {
    let pds = MockPdsServer::start().await;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("skybouncer_allowlist_e2e.db");

    let cache = Arc::new(DeduplicationCache::open(&db_path).expect("open persistent cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block spam and harassment", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));

    // Classifier flags violations
    let classifier = Arc::new(skybouncer::classifier::MockClassifier::new(
        Verdict::violation(
            ViolationCategory::Spam,
            0.95,
            "Detected crypto promotion spam",
        ),
    ));

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric);

    let engine = Arc::new(SkybouncerEngine::new(
        config.clone(),
        Arc::clone(&follow_graph),
        Arc::clone(&gate),
        Arc::clone(&classifier) as Arc<dyn skybouncer::classifier::Classifier>,
        Arc::clone(&modlist_manager),
        pds_client,
    ));

    // 1. Pre-allowlist a trusted friend
    engine
        .add_to_allowlist(
            "did:plc:alice",
            "did:plc:friend_bob",
            Some("Trusted colleague"),
        )
        .expect("add to allowlist");
    assert!(engine.is_allowlisted("did:plc:alice", "did:plc:friend_bob"));

    // 2. Measure in-memory gate evaluation SLA (<1.0µs)
    let sample_interaction = skybouncer::matcher::Interaction::new(
        "did:plc:friend_bob",
        "did:plc:alice",
        skybouncer::matcher::InteractionType::DirectReply,
        "at://did:plc:friend_bob/app.bsky.feed.post/post_1",
        "bafy1",
        "Hello Alice!",
    );

    let iterations = 10_000;
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let decision = gate.evaluate(sample_interaction.clone());
        assert_eq!(
            decision.bypass_reason(),
            Some(BypassReason::AllowlistedAuthor)
        );
    }
    let total_elapsed = start.elapsed();
    let avg_per_op = total_elapsed / iterations;
    println!(
        "\n⚡ [Allowlist Gate Latency Benchmark] Total: {:?} for {} ops | Avg: {:?} (<1.0µs SLA)",
        total_elapsed, iterations, avg_per_op
    );
    assert!(
        avg_per_op < std::time::Duration::from_micros(1),
        "Allowlist check must complete well within the <1µs SLA (measured {:?})",
        avg_per_op
    );

    // 3. Friend Bob interacts via engine -> bypassed at gate at zero model/PDS cost
    let commit_bob = make_reply_commit(
        "did:plc:friend_bob",
        "did:plc:alice",
        "rep_bob_1",
        "root_1",
        "Hey Alice, check this out!",
    );
    let result_bob = engine.process_commit(&commit_bob).await.expect("process");
    let outcomes_bob = result_bob.outcomes();
    assert_eq!(outcomes_bob.len(), 1);
    assert_eq!(
        outcomes_bob[0],
        InteractionOutcome::Bypassed {
            reason: BypassReason::AllowlistedAuthor,
            author_did: "did:plc:friend_bob".to_string(),
            target_did: "did:plc:alice".to_string(),
        }
    );
    assert_eq!(classifier.call_count(), 0);
    assert_eq!(
        engine
            .stats()
            .gate_bypassed_allowlist
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // 4. Stranger Charlie sends spam -> evaluated and bounced on PDS
    let commit_charlie = make_reply_commit(
        "did:plc:charlie",
        "did:plc:alice",
        "rep_charlie_1",
        "root_1",
        "Join free crypto airdrop now!",
    );
    let result_charlie = engine
        .process_commit(&commit_charlie)
        .await
        .expect("process");
    let outcomes_charlie = result_charlie.outcomes();
    assert_eq!(outcomes_charlie.len(), 1);
    assert!(outcomes_charlie[0].is_bounced());
    assert_eq!(classifier.call_count(), 1);
    let initial_created_count = pds.created_records.lock().len();
    assert!(initial_created_count >= 1);
    assert!(cache
        .is_bounced_for("did:plc:alice", "did:plc:charlie")
        .expect("cache check"));

    // 5. User executes pardon_and_allowlist (PRD §7.1 pardon immunization)
    let pardoned = engine
        .pardon_and_allowlist(
            "did:plc:alice",
            "did:plc:charlie",
            Some("Pardoned and immunized by owner"),
        )
        .await
        .expect("pardon and allowlist");
    assert!(pardoned);
    assert_eq!(pds.deleted_records.lock().len(), 1);
    assert!(!cache
        .is_bounced_for("did:plc:alice", "did:plc:charlie")
        .expect("cache check"));
    assert!(engine.is_allowlisted("did:plc:alice", "did:plc:charlie"));

    // 6. Charlie sends another reply -> bypasses gate directly! Zero pardon loop, zero re-bounce!
    let commit_charlie2 = make_reply_commit(
        "did:plc:charlie",
        "did:plc:alice",
        "rep_charlie_2",
        "root_1",
        "Thanks for pardoning me, Alice!",
    );
    let result_charlie2 = engine
        .process_commit(&commit_charlie2)
        .await
        .expect("process");
    let outcomes_charlie2 = result_charlie2.outcomes();
    assert_eq!(outcomes_charlie2.len(), 1);
    assert_eq!(
        outcomes_charlie2[0],
        InteractionOutcome::Bypassed {
            reason: BypassReason::AllowlistedAuthor,
            author_did: "did:plc:charlie".to_string(),
            target_did: "did:plc:alice".to_string(),
        }
    );
    // Model call count remains 1; no new classification occurred!
    assert_eq!(classifier.call_count(), 1);
    // Gate allowlist bypass count is now 2 (Bob + Charlie)
    assert_eq!(
        engine
            .stats()
            .gate_bypassed_allowlist
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    // No new PDS record was created
    assert_eq!(pds.created_records.lock().len(), initial_created_count);

    // 7. Restart test: Instantiate a brand new engine pointing to the same SQLite database
    let cache2 = Arc::new(DeduplicationCache::open(&db_path).expect("reopen persistent cache"));
    let gate2 = Arc::new(NonFollowedGate::new(Arc::new(FollowGraph::new())));
    let modlist_manager2 = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache2)).with_rubric(RuleRubric::default()),
    );
    let pds_client2 = Arc::new(pds.pds_client("did:plc:alice"));

    let engine2 = SkybouncerEngine::new(
        config,
        Arc::new(FollowGraph::new()),
        Arc::clone(&gate2),
        Arc::clone(&classifier) as Arc<dyn skybouncer::classifier::Classifier>,
        modlist_manager2,
        pds_client2,
    );

    // Verify all allowlisted users were automatically hydrated into memory on startup
    assert!(engine2.is_allowlisted("did:plc:alice", "did:plc:friend_bob"));
    assert!(engine2.is_allowlisted("did:plc:alice", "did:plc:charlie"));
}
