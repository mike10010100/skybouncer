//! Comprehensive Test Suite for the Decoupled Candidate Evaluation Queue.
//!
//! Validates:
//! 1. Non-blocking candidate dispatch (`QueuedForEvaluation`) and asynchronous background processing.
//! 2. Controlled concurrency (defaulting to 1 worker) preventing compute exhaustion against single Ollama/Jev instance.
//! 3. Bounded queue overflow load-shedding (`QueueOverflow`, `eval_queue_overflows` metric) to protect Jetstream ingestion.
//! 4. In-worker deduplication double-check: skipping redundant model calls when previous queued candidate already bounced user.
//! 5. Graceful draining of in-flight evaluations during shutdown without leaking background tasks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    rust_2018_idioms
)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use serde_json::json;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybouncer::classifier::{JevClassifier, JevConfig, RuleRubric, Sensitivity};
use skybouncer::engine::{SkybouncerConfig, SkybouncerEngine};
use skybouncer::matcher::{FollowGraph, Interaction, InteractionType, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};

/// Mock server tracking maximum concurrency observed.
struct ConcurrencyTrackingServer {
    server: MockServer,
    pub _active_evaluations: Arc<AtomicUsize>,
    pub max_concurrent_observed: Arc<AtomicUsize>,
    pub total_calls: Arc<AtomicUsize>,
}

impl ConcurrencyTrackingServer {
    async fn start(delay: Duration) -> Self {
        let server = MockServer::start().await;
        let active = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));

        let active_clone = Arc::clone(&active);
        let max_clone = Arc::clone(&max_observed);
        let total_clone = Arc::clone(&total);

        Mock::given(method("POST"))
            .and(path("/v1/classify"))
            .respond_with(move |_req: &wiremock::Request| {
                total_clone.fetch_add(1, Ordering::SeqCst);
                let cur = active_clone.fetch_add(1, Ordering::SeqCst) + 1;
                max_clone.fetch_max(cur, Ordering::SeqCst);

                // Small delay to simulate inference time
                std::thread::sleep(delay);

                active_clone.fetch_sub(1, Ordering::SeqCst);

                ResponseTemplate::new(200).set_body_json(json!({
                    "violates": true,
                    "category": "spam",
                    "confidence": 0.95,
                    "reason": "Cryptocurrency airdrop spam bot"
                }))
            })
            .mount(&server)
            .await;

        Self {
            server,
            _active_evaluations: active,
            max_concurrent_observed: max_observed,
            total_calls: total,
        }
    }

    fn jev_config(&self) -> JevConfig {
        JevConfig {
            base_url: self.server.uri(),
            api_key: Some("test-key".to_string()),
            model: "jev-test".to_string(),
            timeout: Duration::from_secs(5),
            max_retries: 0,
        }
    }
}

#[tokio::test]
async fn test_queue_enqueued_and_processed_successfully() {
    let pds = MockPdsServer::start().await;
    let jev = ConcurrencyTrackingServer::start(Duration::from_millis(10)).await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(rubric.clone())
            .with_dry_run(true),
    );
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));
    let classifier = Arc::new(JevClassifier::new(jev.jev_config(), rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_evaluation_queue_capacity(16)
        .with_evaluation_concurrency(1)
        .with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    );

    let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(100);
    let cancel = CancellationToken::new();

    let mut join_set = JoinSet::new();
    let eng_clone = engine.clone();
    let cancel_clone = cancel.clone();
    join_set.spawn(async move { eng_clone.run(commit_rx, cancel_clone).await });

    // Send a candidate interaction commit
    let commit = make_reply_commit(
        "did:plc:spammer_1",
        "did:plc:alice",
        "post_rkey_1",
        "root_1",
        "claim your free crypto airdrop tokens now!",
    );
    commit_tx.send(commit).await.unwrap();

    // Give background worker time to dequeue and evaluate
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Shutdown cleanly
    cancel.cancel();
    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let stats = engine.stats().snapshot();
    assert_eq!(stats.commits_received, 1);
    assert_eq!(stats.eval_queue_enqueued, 1);
    assert_eq!(stats.eval_queue_processed, 1);
    assert_eq!(stats.eval_queue_overflows, 0);
    assert_eq!(stats.bounces_executed, 1);
    assert_eq!(jev.total_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_queue_overflow_shedding_under_saturation() {
    let pds = MockPdsServer::start().await;
    // Server with 50ms delay per inference call
    let jev = ConcurrencyTrackingServer::start(Duration::from_millis(50)).await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(rubric.clone())
            .with_dry_run(true),
    );
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));
    let classifier = Arc::new(JevClassifier::new(jev.jev_config(), rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    // Small queue capacity = 2, concurrency = 1
    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_evaluation_queue_capacity(2)
        .with_evaluation_concurrency(1)
        .with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    );

    // Directly test process_interaction_queued with an artificial bounded queue channel
    let (eval_tx, _eval_rx) = tokio::sync::mpsc::channel(2);

    let interaction1 = Interaction::new(
        "did:plc:user1",
        "did:plc:alice",
        InteractionType::DirectReply,
        "at://did:plc:user1/app.bsky.feed.post/1",
        "bafy_cid_1",
        "first candidate",
    );
    let interaction2 = Interaction::new(
        "did:plc:user2",
        "did:plc:alice",
        InteractionType::DirectReply,
        "at://did:plc:user2/app.bsky.feed.post/2",
        "bafy_cid_2",
        "second candidate",
    );
    let interaction3 = Interaction::new(
        "did:plc:user3",
        "did:plc:alice",
        InteractionType::DirectReply,
        "at://did:plc:user3/app.bsky.feed.post/3",
        "bafy_cid_3",
        "third candidate overflowing queue",
    );

    let o1 = engine
        .process_interaction_queued(interaction1, &eval_tx)
        .await
        .unwrap();
    let o2 = engine
        .process_interaction_queued(interaction2, &eval_tx)
        .await
        .unwrap();
    let o3 = engine
        .process_interaction_queued(interaction3, &eval_tx)
        .await
        .unwrap();

    assert!(o1.is_queued());
    assert!(o2.is_queued());
    // 3rd item overflows because channel capacity is 2 and nothing has drained yet!
    assert!(o3.is_queue_overflow());

    let stats = engine.stats().snapshot();
    assert_eq!(stats.eval_queue_enqueued, 2);
    assert_eq!(stats.eval_queue_overflows, 1);
}

#[tokio::test]
async fn test_queue_strictly_enforces_concurrency_1() {
    let pds = MockPdsServer::start().await;
    // 60ms delay per request to guarantee overlap if concurrency > 1
    let jev = ConcurrencyTrackingServer::start(Duration::from_millis(60)).await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(rubric.clone())
            .with_dry_run(true),
    );
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));
    let classifier = Arc::new(JevClassifier::new(jev.jev_config(), rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_evaluation_queue_capacity(64)
        .with_evaluation_concurrency(1)
        .with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    );

    let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(100);
    let cancel = CancellationToken::new();

    let mut join_set = JoinSet::new();
    let eng_clone = engine.clone();
    let cancel_clone = cancel.clone();
    join_set.spawn(async move { eng_clone.run(commit_rx, cancel_clone).await });

    // Blast 5 different candidate commits into the channel simultaneously
    for i in 0..5 {
        let commit = make_reply_commit(
            &format!("did:plc:spammer_{i}"),
            "did:plc:alice",
            &format!("post_{i}"),
            "root_1",
            "spam text",
        );
        commit_tx.send(commit).await.unwrap();
    }

    // Wait long enough for all 5 to complete (5 * 60ms = 300ms + buffer)
    tokio::time::sleep(Duration::from_millis(500)).await;

    cancel.cancel();
    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let stats = engine.stats().snapshot();
    assert_eq!(stats.eval_queue_enqueued, 5);
    assert_eq!(stats.eval_queue_processed, 5);
    assert_eq!(stats.bounces_executed, 5);

    // CRITICAL: Max concurrent requests observed by Jev MUST BE EXACTLY 1!
    let max_concurrency = jev.max_concurrent_observed.load(Ordering::SeqCst);
    assert_eq!(
        max_concurrency, 1,
        "Concurrency must never exceed 1 when evaluation_concurrency is 1"
    );
}

#[tokio::test]
async fn test_in_worker_dedup_double_check_skips_redundant_model_calls() {
    let pds = MockPdsServer::start().await;
    // 40ms delay per request
    let jev = ConcurrencyTrackingServer::start(Duration::from_millis(40)).await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(rubric.clone())
            .with_dry_run(true),
    );
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));
    let classifier = Arc::new(JevClassifier::new(jev.jev_config(), rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_evaluation_queue_capacity(32)
        .with_evaluation_concurrency(1)
        .with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    );

    let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(100);
    let cancel = CancellationToken::new();

    let mut join_set = JoinSet::new();
    let eng_clone = engine.clone();
    let cancel_clone = cancel.clone();
    join_set.spawn(async move { eng_clone.run(commit_rx, cancel_clone).await });

    // Blast 3 interactions from the SAME spammer DID simultaneously.
    // They will all get enqueued because the spammer is not yet bounced.
    for i in 0..3 {
        let commit = make_reply_commit(
            "did:plc:burst_spammer",
            "did:plc:alice",
            &format!("burst_post_{i}"),
            "root_1",
            "spam text payload",
        );
        commit_tx.send(commit).await.unwrap();
    }

    // Allow worker to drain
    tokio::time::sleep(Duration::from_millis(300)).await;

    cancel.cancel();
    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let stats = engine.stats().snapshot();
    assert_eq!(stats.eval_queue_enqueued, 3);
    assert_eq!(stats.eval_queue_processed, 3);

    // CRITICAL: First candidate bounced user; remaining 2 candidates must hit dedup cache
    // inside the worker and NEVER call the model!
    assert_eq!(stats.bounces_executed, 1);
    assert_eq!(
        jev.total_calls.load(Ordering::SeqCst),
        1,
        "Only 1 model call should occur; subsequent queued candidates must hit dedup double check!"
    );
    assert!(stats.dedup_cache_hits >= 2);
}
