//! Concurrency, Thundering Herd, Throughput, and Cancellation Stress Test Suite for Milestone 4.
//!
//! Empirically challenges and stress-tests:
//! 1. **High Concurrency & Thundering Herd**: Overlapping and non-overlapping author bursts
//!    across 50+ concurrent tasks, verifying strictly 1 PDS listitem write per violator DID.
//! 2. **Lock Striping & Shard Collision**: Two distinct violator DIDs colliding on the exact same
//!    `StripedAsyncLocks` shard execute without deadlocks, false deduplication, or race conditions.
//! 3. **Cancellation & Queue Drain Under Heavy Load**: Flooding the channel with thousands of commits,
//!    verifying graceful drain, bounded shutdown timeout, and zero task leaks in `JoinSet`.
//! 4. **Severe Channel Backpressure**: Bounded channel capacity of 2 under 30+ concurrent producers
//!    guarantees forward progress without deadlocks or thread pool starvation.
//! 5. **Concurrent Bounce & Pardon Races**: Interleaved mutations for the same subject DID maintain
//!    consistent state across SQLite cache and PDS repository mutations.
//! 6. **Periodic Maintenance Loop Cancellation**: Cancellation under active cache operations
//!    terminates cleanly without task leaks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    clippy::needless_collect,
    dead_code
)]

mod common;

use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybase::ingest::events::JetstreamCommit;
use skybouncer::classifier::{
    Classifier, JevClassifier, JevConfig, MockClassifier, RuleRubric, Sensitivity, Verdict,
};
use skybouncer::engine::{InteractionOutcome, SkybouncerConfig, SkybouncerEngine};
use skybouncer::limiter::RateLimiterConfig;
use skybouncer::matcher::{BypassReason, FollowGraph, NonFollowedGate};
use skybouncer::modlist::manager::NUM_LOCK_SHARDS;
use skybouncer::modlist::{DeduplicationCache, ModListManager};

// =============================================================================
// Wiremock Jev Mock Server for Stress Testing
// =============================================================================

struct StressMockJevServer {
    server: MockServer,
    pub classify_count: Arc<AtomicUsize>,
}

impl StressMockJevServer {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let classify_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&classify_count);

        Mock::given(method("POST"))
            .and(path("/v1/classify"))
            .respond_with(move |req: &wiremock::Request| {
                count.fetch_add(1, Ordering::SeqCst);
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let text = body["text"].as_str().unwrap_or("").to_lowercase();

                if text.contains("toxic") || text.contains("scam") || text.contains("airdrop") {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "violates": true,
                        "category": "harassment",
                        "confidence": 0.95,
                        "reason": "Hostile attack detected"
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "violates": false,
                        "category": null,
                        "confidence": 0.05,
                        "reason": "Permitted discourse"
                    }))
                }
            })
            .mount(&server)
            .await;

        Self {
            server,
            classify_count,
        }
    }

    fn config(&self) -> JevConfig {
        JevConfig {
            base_url: self.server.uri(),
            api_key: Some("stress_test_key".to_string()),
            model: "jev-stress-model".to_string(),
            timeout: Duration::from_millis(3000),
            max_retries: 2,
        }
    }

    fn classifier(&self, rubric: RuleRubric) -> Arc<dyn Classifier> {
        let classifier = JevClassifier::new(self.config(), rubric)
            .expect("JevClassifier creation should succeed");
        Arc::new(classifier)
    }
}

// =============================================================================
// Composite Stress Fixture
// =============================================================================

struct StressFixture {
    pds: MockPdsServer,
    _jev: StressMockJevServer,
    cache: Arc<DeduplicationCache>,
    follow_graph: Arc<FollowGraph>,
    engine: Arc<SkybouncerEngine>,
}

impl StressFixture {
    async fn start(protected_did: &str, channel_capacity: usize) -> Self {
        let pds = MockPdsServer::start().await;
        let jev = StressMockJevServer::start().await;
        let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
        let follow_graph = Arc::new(FollowGraph::new());
        let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

        let rubric = RuleRubric::new("Block toxicity and spam", Sensitivity::Medium);
        let modlist_manager = Arc::new(
            ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()),
        );

        let pds_client = Arc::new(pds.pds_client(protected_did));
        let classifier = jev.classifier(rubric.clone());

        let mut protected_dids = HashSet::new();
        protected_dids.insert(protected_did.to_string());

        let config =
            SkybouncerConfig::new(protected_dids, rubric).with_channel_capacity(channel_capacity);

        let engine = Arc::new(SkybouncerEngine::new(
            config,
            Arc::clone(&follow_graph),
            gate,
            classifier,
            modlist_manager,
            pds_client,
        ));

        Self {
            pds,
            _jev: jev,
            cache,
            follow_graph,
            engine,
        }
    }

    fn count_pds_listitems_for(&self, subject_did: &str) -> usize {
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

    fn count_pds_lists(&self) -> usize {
        let records = self.pds.created_records.lock();
        records
            .iter()
            .filter(|r| r.get("collection").and_then(|v| v.as_str()) == Some("app.bsky.graph.list"))
            .count()
    }
}

/// Helper that creates an in-memory fast fixture backed by `MockClassifier`
/// (eliminating HTTP wiremock overhead for pure throughput/cancellation stress).
async fn make_fast_engine(
    protected_did: &str,
    channel_capacity: usize,
    mock_classifier: MockClassifier,
) -> (
    Arc<SkybouncerEngine>,
    Arc<DeduplicationCache>,
    MockPdsServer,
) {
    let pds = MockPdsServer::start().await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block toxicity and spam", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));

    let pds_client = Arc::new(pds.pds_client(protected_did));
    let classifier = Arc::new(mock_classifier);

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected_did.to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_channel_capacity(channel_capacity)
        .with_evaluation_queue_capacity(4096)
        .with_rate_limiter_config(RateLimiterConfig::unlimited());

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    ));

    (engine, cache, pds)
}

// =============================================================================
// 1. High Concurrency & Thundering Herd: 50+ Overlapping & Non-Overlapping Tasks
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_thundering_herd_multi_violator_50_tasks() {
    let target_did = "did:plc:alice_protected";
    let fixture = StressFixture::start(target_did, 200).await;
    let engine = Arc::clone(&fixture.engine);

    // Setup follow state: alice follows 5 accounts
    for i in 0..5 {
        fixture.follow_graph.add_follow(
            target_did,
            format!("rk_follow_{i}"),
            format!("did:plc:friend_{i}"),
        );
    }

    // 5 distinct violator DIDs, each attacked by 10 concurrent tasks (50 violator tasks)
    let num_violators = 5;
    let tasks_per_violator = 10;
    let mut handles = Vec::new();

    // 1. Spawn 50 violator tasks (overlapping bursts)
    for v_idx in 0..num_violators {
        let violator_did = format!("did:plc:spammer_burst_{v_idx}");
        for t_idx in 0..tasks_per_violator {
            let eng = Arc::clone(&engine);
            let v_did = violator_did.clone();
            handles.push(tokio::spawn(async move {
                let commit = make_reply_commit(
                    &v_did,
                    "did:plc:alice_protected",
                    &format!("rep_{v_idx}_{t_idx}"),
                    "root_1",
                    "toxic attack message burst",
                );
                eng.process_commit(&commit).await
            }));
        }
    }

    // 2. Spawn 15 polite non-violator tasks (non-overlapping)
    for p_idx in 0..15 {
        let eng = Arc::clone(&engine);
        let polite_did = format!("did:plc:polite_user_{p_idx}");
        handles.push(tokio::spawn(async move {
            let commit = make_reply_commit(
                &polite_did,
                "did:plc:alice_protected",
                &format!("rep_polite_{p_idx}"),
                "root_1",
                "hello friend good morning",
            );
            eng.process_commit(&commit).await
        }));
    }

    // 3. Spawn 15 followed friend tasks (should bypass at gate at $0 cost)
    for f_idx in 0..15 {
        let eng = Arc::clone(&engine);
        let friend_did = format!("did:plc:friend_{}", f_idx % 5);
        handles.push(tokio::spawn(async move {
            let commit = make_reply_commit(
                &friend_did,
                "did:plc:alice_protected",
                &format!("rep_friend_{f_idx}"),
                "root_1",
                "toxic or friendly message from followed friend",
            );
            eng.process_commit(&commit).await
        }));
    }

    // Total tasks = 50 + 15 + 15 = 80 concurrent tasks
    assert_eq!(handles.len(), 80);

    let mut total_bounced = 0;
    let mut total_already_bounced = 0;
    let mut total_permitted = 0;
    let mut total_bypassed = 0;

    for handle in handles {
        let res = handle
            .await
            .expect("task must not panic")
            .expect("process_commit must succeed");
        let outcomes = res.into_outcomes();
        assert_eq!(outcomes.len(), 1, "Expected exactly 1 interaction outcome");

        match &outcomes[0] {
            InteractionOutcome::Bounced { .. } => total_bounced += 1,
            InteractionOutcome::AlreadyBounced { .. } => total_already_bounced += 1,
            InteractionOutcome::Permitted { .. } => total_permitted += 1,
            InteractionOutcome::Bypassed {
                reason: BypassReason::FollowedAuthor,
                ..
            } => total_bypassed += 1,
            other => panic!("Unexpected outcome in thundering herd stress: {other:?}"),
        }
    }

    // INVARIANT 1: Exactly 1 bounce per violator DID across all 50 violator tasks!
    assert_eq!(
        total_bounced, num_violators,
        "Exactly 5 tasks (1 per violator DID) must execute the initial bounce"
    );
    assert_eq!(
        total_already_bounced,
        (num_violators * tasks_per_violator) - num_violators,
        "Remaining 45 violator tasks must receive AlreadyBounced"
    );

    // INVARIANT 2: Non-violators must all be permitted
    assert_eq!(total_permitted, 15);

    // INVARIANT 3: Followed accounts must all be bypassed at gate ($0 cost)
    assert_eq!(total_bypassed, 15);

    // INVARIANT 4: Sovereign PDS received strictly 1 listitem write per violator DID
    for v_idx in 0..num_violators {
        let violator_did = format!("did:plc:spammer_burst_{v_idx}");
        assert_eq!(
            fixture.count_pds_listitems_for(&violator_did),
            1,
            "PDS must receive strictly 1 listitem creation for {violator_did}"
        );
        assert!(
            fixture.cache.is_bounced(&violator_did).unwrap(),
            "Cache must record {violator_did} as bounced"
        );
    }

    // INVARIANT 5: Exactly 1 parent moderation list created for the protected user
    assert_eq!(
        fixture.count_pds_lists(),
        1,
        "Exactly 1 parent moderation list must be provisioned"
    );
}

// =============================================================================
// 2. Lock Striping & Shard Collision: Non-Interference Between Colliding Keys
// =============================================================================

/// Helper finding two distinct DIDs that hash to the exact same shard index in `StripedAsyncLocks`.
fn find_colliding_dids(target_shard: usize) -> (String, String) {
    let mut found = Vec::new();
    for i in 0..100_000 {
        let did = format!("did:plc:violator_shard_{i}");
        let mut hasher = DefaultHasher::new();
        did.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % NUM_LOCK_SHARDS;
        if idx == target_shard {
            found.push(did);
            if found.len() == 2 {
                return (found[0].clone(), found[1].clone());
            }
        }
    }
    panic!("Could not find colliding DIDs for shard {target_shard}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_striped_async_locks_shard_collision_non_interference() {
    let target_did = "did:plc:bob_protected";
    let fixture = StressFixture::start(target_did, 100).await;
    let engine = Arc::clone(&fixture.engine);

    // Find two distinct DIDs that hash to shard 42
    let (did_a, did_b) = find_colliding_dids(42);
    assert_ne!(did_a, did_b);

    // Verify they indeed map to the same shard index
    let shard_a = {
        let mut h = DefaultHasher::new();
        did_a.hash(&mut h);
        (h.finish() as usize) % NUM_LOCK_SHARDS
    };
    let shard_b = {
        let mut h = DefaultHasher::new();
        did_b.hash(&mut h);
        (h.finish() as usize) % NUM_LOCK_SHARDS
    };
    assert_eq!(shard_a, 42);
    assert_eq!(shard_b, 42);

    // Launch 15 concurrent tasks for did_a and 15 concurrent tasks for did_b (30 total)
    let mut handles = Vec::new();
    for i in 0..15 {
        let eng_a = Arc::clone(&engine);
        let da = did_a.clone();
        handles.push(tokio::spawn(async move {
            let commit = make_reply_commit(
                &da,
                "did:plc:bob_protected",
                &format!("rep_a_{i}"),
                "root_1",
                "toxic attack from A",
            );
            eng_a.process_commit(&commit).await
        }));

        let eng_b = Arc::clone(&engine);
        let db = did_b.clone();
        handles.push(tokio::spawn(async move {
            let commit = make_reply_commit(
                &db,
                "did:plc:bob_protected",
                &format!("rep_b_{i}"),
                "root_1",
                "toxic attack from B",
            );
            eng_b.process_commit(&commit).await
        }));
    }

    let mut bounced_a = 0;
    let mut already_bounced_a = 0;
    let mut bounced_b = 0;
    let mut already_bounced_b = 0;

    for handle in handles {
        let res = handle.await.expect("join").expect("process");
        let outcomes = res.into_outcomes();
        assert_eq!(outcomes.len(), 1);
        let outcome = &outcomes[0];

        if outcome.author_did() == did_a {
            match outcome {
                InteractionOutcome::Bounced { .. } => bounced_a += 1,
                InteractionOutcome::AlreadyBounced { .. } => already_bounced_a += 1,
                other => panic!("Unexpected outcome for A: {other:?}"),
            }
        } else if outcome.author_did() == did_b {
            match outcome {
                InteractionOutcome::Bounced { .. } => bounced_b += 1,
                InteractionOutcome::AlreadyBounced { .. } => already_bounced_b += 1,
                other => panic!("Unexpected outcome for B: {other:?}"),
            }
        } else {
            panic!("Unexpected author: {}", outcome.author_did());
        }
    }

    // Both distinct violators must be bounced exactly once, even though they share the shard lock!
    assert_eq!(
        bounced_a, 1,
        "Violator A must be bounced exactly once despite shard collision"
    );
    assert_eq!(already_bounced_a, 14, "14 tasks for A must short-circuit");

    assert_eq!(
        bounced_b, 1,
        "Violator B must be bounced exactly once despite shard collision"
    );
    assert_eq!(already_bounced_b, 14, "14 tasks for B must short-circuit");

    // PDS must receive strictly 1 write for A and 1 write for B
    assert_eq!(fixture.count_pds_listitems_for(&did_a), 1);
    assert_eq!(fixture.count_pds_listitems_for(&did_b), 1);
}

// =============================================================================
// 3. Multi-Target Protected Account Discrimination Under Concurrency
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_multi_protected_targets_high_concurrency() {
    let pds = MockPdsServer::start().await;
    let jev = StressMockJevServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block toxicity and spam", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));

    let pds_client = Arc::new(pds.pds_client("did:plc:target_0"));
    let classifier = jev.classifier(rubric.clone());

    // 4 protected targets
    let mut protected_dids = HashSet::new();
    for i in 0..4 {
        protected_dids.insert(format!("did:plc:target_{i}"));
    }

    let config = SkybouncerConfig::new(protected_dids, rubric).with_channel_capacity(200);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    ));

    // Launch 40 concurrent tasks attacking across the 4 protected targets
    let mut handles = Vec::new();
    for i in 0..40 {
        let eng = Arc::clone(&engine);
        let target = format!("did:plc:target_{}", i % 4);
        let violator = format!("did:plc:spammer_multi_{}", i / 4); // 10 distinct violators
        handles.push(tokio::spawn(async move {
            let commit = make_reply_commit(
                &violator,
                &target,
                &format!("rep_multi_{i}"),
                "root_1",
                "toxic attack on multi target",
            );
            eng.process_commit(&commit).await
        }));
    }

    for handle in handles {
        let res = handle.await.expect("join").expect("process");
        let outcomes = res.into_outcomes();
        assert_eq!(outcomes.len(), 1);
    }

    // Verify stats
    let stats = engine.stats().snapshot();
    assert_eq!(stats.commits_received, 40);
    assert_eq!(stats.interactions_matched, 40);
    assert_eq!(stats.bounces_executed, 10);
    assert_eq!(stats.dedup_cache_hits, 30);
}

// =============================================================================
// 4. Cancellation & Drain Under Load: Buffered Queue Drain
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_cancellation_drain_buffered_queue() {
    let mock_classifier = MockClassifier::permitted();
    let (engine, _cache, _pds) = make_fast_engine("did:plc:carol", 2500, mock_classifier).await;

    let (tx, rx) = tokio::sync::mpsc::channel::<JetstreamCommit>(2500);
    let cancel = CancellationToken::new();

    // Pre-buffer 1,000 commits in channel before starting engine
    let num_commits = 1000;
    for i in 0..num_commits {
        let commit = if i % 2 == 0 {
            make_reply_commit(
                &format!("did:plc:user_{i}"),
                "did:plc:carol",
                &format!("rep_{i}"),
                "rt_1",
                "polite prebuffered comment",
            )
        } else {
            make_standalone_post_commit(
                &format!("did:plc:user_{i}"),
                &format!("post_{i}"),
                "standalone post",
            )
        };
        tx.try_send(commit)
            .expect("try_send into pre-buffered channel");
    }

    // Now trigger cancellation BEFORE engine runs!
    cancel.cancel();

    // Run engine: it must detect cancellation, drain all 1000 prebuffered commits, and return!
    let run_timeout = tokio::time::timeout(Duration::from_secs(5), engine.run(rx, cancel)).await;
    assert!(
        run_timeout.is_ok(),
        "Engine run must finish draining buffered commits within 5s"
    );

    let stats = run_timeout.unwrap().expect("engine run ok");
    assert_eq!(
        stats.commits_received, num_commits as u64,
        "Engine must have drained and processed all 1,000 buffered commits"
    );
    assert_eq!(stats.permitted, (num_commits / 2) as u64);
}

// =============================================================================
// 5. Cancellation & Drain Under Load: Continuous High Throughput Stream
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_cancellation_under_heavy_continuous_throughput() {
    let mock_classifier = MockClassifier::permitted();
    let (engine, _cache, _pds) = make_fast_engine("did:plc:dave", 1000, mock_classifier).await;

    let (tx, rx) = tokio::sync::mpsc::channel::<JetstreamCommit>(1000);
    let cancel = CancellationToken::new();

    let mut join_set = tokio::task::JoinSet::new();
    let child_cancel = cancel.child_token();
    let eng_clone = Arc::clone(&engine);

    join_set.spawn(async move { eng_clone.run(rx, child_cancel).await });

    // Spawn 8 continuous producer tasks pushing thousands of commits
    let mut producer_handles = Vec::new();
    let producer_cancel = cancel.child_token();

    for p in 0..8 {
        let p_tx = tx.clone();
        let p_cancel = producer_cancel.clone();
        producer_handles.push(tokio::spawn(async move {
            let mut seq = 0;
            loop {
                if p_cancel.is_cancelled() {
                    break;
                }
                let commit = make_reply_commit(
                    &format!("did:plc:producer_{p}_{seq}"),
                    "did:plc:dave",
                    &format!("rep_{p}_{seq}"),
                    "rt_1",
                    "rapid fire comment",
                );
                if p_tx.send(commit).await.is_err() {
                    break;
                }
                seq += 1;
            }
        }));
    }
    drop(tx); // Drop original tx so channel closes when producers stop

    // Let pipeline process high throughput for 200ms
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Trigger graceful drain and shutdown with a 3-second timeout guard
    let shutdown_result =
        SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(3)).await;

    assert!(
        shutdown_result.is_ok(),
        "drain_and_shutdown must succeed without error"
    );

    // Verify JoinSet is completely empty (zero task leaks!)
    assert!(
        join_set.is_empty(),
        "JoinSet must be completely drained and empty"
    );

    // Await producers exit
    for h in producer_handles {
        let _ = h.await;
    }

    // Engine must have processed at least hundreds of commits before clean shutdown
    let stats = engine.stats().snapshot();
    assert!(
        stats.commits_received > 50,
        "Engine should have processed high commit volume (observed {})",
        stats.commits_received
    );
}

// =============================================================================
// 6. Severe Channel Backpressure: Tiny Capacity (2) Under 32 Producers
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_extreme_channel_saturation_and_backpressure() {
    let mock_classifier = MockClassifier::permitted();
    let (engine, _cache, _pds) = make_fast_engine("did:plc:eve", 2, mock_classifier).await;

    // Channel capacity of only 2!
    let (tx, rx) = tokio::sync::mpsc::channel::<JetstreamCommit>(2);
    let cancel = CancellationToken::new();

    let mut join_set = tokio::task::JoinSet::new();
    let child_cancel = cancel.child_token();
    let eng_clone = Arc::clone(&engine);

    join_set.spawn(async move { eng_clone.run(rx, child_cancel).await });

    // 32 concurrent producers each sending 30 commits = 960 commits under intense backpressure
    let num_producers = 32;
    let commits_per_producer = 30;
    let mut prod_handles = Vec::new();

    for p in 0..num_producers {
        let p_tx = tx.clone();
        prod_handles.push(tokio::spawn(async move {
            for c in 0..commits_per_producer {
                let commit = make_reply_commit(
                    &format!("did:plc:backpressure_{p}_{c}"),
                    "did:plc:eve",
                    &format!("rep_{p}_{c}"),
                    "rt_1",
                    "backpressure message",
                );
                p_tx.send(commit).await.expect("send under backpressure");
            }
        }));
    }
    drop(tx); // Drop root sender

    // Wait for all 32 producers to successfully finish pushing through backpressure
    for h in prod_handles {
        h.await.expect("producer finished");
    }

    // Drain and shutdown
    let shutdown_res =
        SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(4)).await;
    assert!(shutdown_res.is_ok());

    let stats = engine.stats().snapshot();
    let expected_commits = (num_producers * commits_per_producer) as u64;
    assert_eq!(
        stats.commits_received, expected_commits,
        "All 960 commits must be processed despite extreme channel backpressure"
    );
    assert_eq!(stats.permitted, expected_commits);
}

// =============================================================================
// 7. Concurrent Bounce and Pardon Races on Same Subject DID
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_concurrent_bounce_and_pardon_lifecycle() {
    let target_did = "did:plc:frank_protected";
    let fixture = StressFixture::start(target_did, 100).await;
    let engine = Arc::clone(&fixture.engine);
    let violator_did = "did:plc:target_violator_race";

    // Launch 10 bounce attempts and 10 pardon attempts concurrently on the exact same DID
    let mut handles = Vec::new();
    for i in 0..10 {
        let eng_b = Arc::clone(&engine);
        let v_did = violator_did.to_string();
        handles.push(tokio::spawn(async move {
            let commit = make_reply_commit(
                &v_did,
                "did:plc:frank_protected",
                &format!("rep_race_{i}"),
                "root_1",
                "toxic message in bounce pardon race",
            );
            let _ = eng_b.process_commit(&commit).await;
        }));

        let eng_p = Arc::clone(&engine);
        let v_did = violator_did.to_string();
        handles.push(tokio::spawn(async move {
            let _ = eng_p.pardon_user("did:plc:frank_protected", &v_did).await;
        }));
    }

    // All tasks must resolve without deadlocks or panics
    for handle in handles {
        handle.await.expect("task join");
    }

    // Verify cache integrity: checking is_bounced must not error
    let is_bounced = fixture.cache.is_bounced(violator_did).expect("cache query");

    if is_bounced {
        // If final state is bounced: there must be a bounced record in cache
        let bounced_user = fixture
            .cache
            .get_bounced_user(violator_did)
            .expect("bounced user record");
        assert!(bounced_user.is_some());
    } else {
        // If final state is pardoned: bounced record must be None
        let bounced_user = fixture
            .cache
            .get_bounced_user(violator_did)
            .expect("bounced user record");
        assert!(bounced_user.is_none());
    }
}

// =============================================================================
// 8. Maintenance Task Cancellation Under High Cache Activity
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_engine_maintenance_loop_cancellation() {
    let mock_classifier = MockClassifier::permitted();
    let (engine, cache, _pds) = make_fast_engine("did:plc:grace", 100, mock_classifier).await;

    let cancel = CancellationToken::new();
    let maintenance_cancel = cancel.child_token();
    let eng_clone = Arc::clone(&engine);

    // Spawn maintenance loop running every 5ms
    let maintenance_handle = tokio::spawn(async move {
        eng_clone
            .run_maintenance(Duration::from_millis(5), maintenance_cancel)
            .await
    });

    // Concurrently write 100 evaluation entries that expire immediately (TTL = 0)
    for i in 0..100 {
        let post_uri = format!("at://did:plc:writer/app.bsky.feed.post/{i}");
        let verdict = Verdict::permitted("fast entry");
        cache
            .set_evaluation(&post_uri, "did:plc:writer", &verdict, Duration::ZERO)
            .expect("cache set");
    }

    // Let maintenance task run several ticks
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Cancel maintenance task
    cancel.cancel();

    // Verify maintenance task exits cleanly within 2 seconds
    let res = tokio::time::timeout(Duration::from_secs(2), maintenance_handle).await;
    assert!(res.is_ok(), "Maintenance task must exit promptly on cancel");

    let pruned = res.unwrap().expect("join ok").expect("maintenance ok");
    assert!(
        pruned > 0,
        "Maintenance task should have pruned expired evaluations (pruned {pruned})"
    );
}

#[tokio::test]
async fn test_engine_builder_with_tiered_classifier() {
    let pds = MockPdsServer::start().await;
    let protected_did = "did:plc:protected_target";
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let rubric = RuleRubric::new("Block hate speech", Sensitivity::Medium);
    let modlist = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(rubric.clone())
            .with_dry_run(true),
    );
    let pds_client = Arc::new(pds.pds_client(protected_did));

    // Primary returns borderline/uncertain score (0.50)
    let primary = Arc::new(MockClassifier::new(Verdict::permitted_with_confidence(
        "Borderline insult",
        0.50,
    )));
    // Fallback returns high-confidence violation (0.95)
    let fallback = Arc::new(MockClassifier::violation(
        skybouncer::classifier::ViolationCategory::Harassment,
        0.95,
        "System-2 confirmed targeted harassment",
    ));

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected_did.to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_dry_run(true)
        .with_certainty_config(skybouncer::classifier::CertaintyConfig::new(
            0.40, 0.85, true,
        ));

    let engine = SkybouncerEngine::builder(config)
        .with_cache(cache)
        .with_modlist_manager(modlist)
        .with_pds_client(pds_client)
        .with_classifier(primary.clone())
        .with_fallback_classifier(fallback.clone())
        .build()
        .expect("engine build must succeed");

    let interaction = skybouncer::matcher::Interaction {
        post_uri: "at://did:plc:attacker/app.bsky.feed.post/123".to_string(),
        post_cid: Some("bafyreitest".to_string()),
        author_did: "did:plc:attacker".to_string(),
        target_did: protected_did.to_string(),
        text: "Borderline insult targeting you".to_string(),
        interaction_type: skybouncer::matcher::InteractionType::DirectReply,
        parent_uri: Some(format!("at://{protected_did}/app.bsky.feed.post/root")),
        root_uri: Some(format!("at://{protected_did}/app.bsky.feed.post/root")),
        created_at_us: 1_700_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
    };

    let verdict = engine
        .primary_classifier()
        .classify(&interaction)
        .await
        .unwrap();
    assert!(verdict.is_violation());
    assert_eq!(verdict.confidence(), Some(0.95));
    assert_eq!(primary.call_count(), 1);
    assert_eq!(fallback.call_count(), 1);
}
