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
            supports_images: false,
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
    )
    .expect("evaluation queue test engine");

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
    )
    .expect("evaluation queue test engine");

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
    )
    .expect("evaluation queue test engine");

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
    )
    .expect("evaluation queue test engine");

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

#[tokio::test]
async fn test_queue_holds_and_retries_candidates_while_classifier_offline_then_drains() {
    let pds = MockPdsServer::start().await;
    let server = MockServer::start().await;
    let is_online = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let is_online_clone = Arc::clone(&is_online);
    let total_calls = Arc::new(AtomicUsize::new(0));
    let total_calls_clone = Arc::clone(&total_calls);

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(move |_req: &wiremock::Request| {
            total_calls_clone.fetch_add(1, Ordering::SeqCst);
            if !is_online_clone.load(Ordering::SeqCst) {
                ResponseTemplate::new(502).set_body_string("Bad Gateway: nmo offline")
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "violates": true,
                    "category": "spam",
                    "confidence": 0.95,
                    "reason": "Evaluated after nmo came back online"
                }))
            }
        })
        .mount(&server)
        .await;

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
    let jev_config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-test".to_string(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        supports_images: false,
    };
    let classifier = Arc::new(JevClassifier::new(jev_config, rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_evaluation_queue_capacity(32)
        .with_evaluation_concurrency(1)
        .with_hold_queue_on_classifier_unavailable(true)
        .with_classifier_retry_backoff(Duration::from_millis(50))
        .with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    )
    .expect("evaluation queue test engine");

    let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(100);
    let cancel = CancellationToken::new();

    let mut join_set = JoinSet::new();
    let eng_clone = engine.clone();
    let cancel_clone = cancel.clone();
    join_set.spawn(async move { eng_clone.run(commit_rx, cancel_clone).await });

    // Enqueue 3 distinct candidates while the classifier (nmo) is offline (502)
    for i in 0..3 {
        let commit = make_reply_commit(
            &format!("did:plc:offline_spammer_{i}"),
            "did:plc:alice",
            &format!("offline_post_{i}"),
            "root_1",
            "crypto scam during outage",
        );
        commit_tx.send(commit).await.unwrap();
    }

    // Let the worker attempt and hold the queue while offline
    tokio::time::sleep(Duration::from_millis(120)).await;

    let offline_stats = engine.stats().snapshot();
    assert_eq!(offline_stats.eval_queue_enqueued, 3);
    assert_eq!(
        offline_stats.eval_queue_processed, 0,
        "No candidates should be dropped/completed while classifier is offline"
    );
    assert!(
        offline_stats.errors_encountered >= 1,
        "Transient outage errors must be recorded while retrying"
    );

    // Now bring classifier (nmo) back online!
    is_online.store(true, Ordering::SeqCst);

    // Wait for backoff retry to wake up and drain all 3 queued candidates
    tokio::time::sleep(Duration::from_millis(250)).await;

    cancel.cancel();
    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let final_stats = engine.stats().snapshot();
    assert_eq!(final_stats.eval_queue_enqueued, 3);
    assert_eq!(final_stats.eval_queue_processed, 3);
    assert_eq!(
        final_stats.bounces_executed, 3,
        "All 3 queued candidates must be evaluated and bounced once classifier recovers"
    );
}

#[tokio::test]
async fn test_queue_caps_per_candidate_timeout_retries_without_head_of_line_blocking() {
    let pds = MockPdsServer::start().await;
    let server = MockServer::start().await;
    let slow_calls = Arc::new(AtomicUsize::new(0));
    let slow_calls_clone = Arc::clone(&slow_calls);
    let fast_calls = Arc::new(AtomicUsize::new(0));
    let fast_calls_clone = Arc::clone(&fast_calls);

    // Post 1 always stalls past the 50ms client timeout.
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(wiremock::matchers::body_string_contains("slow_poison_post"))
        .respond_with(move |_req: &wiremock::Request| {
            slow_calls_clone.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!({
                    "violates": false,
                    "category": null,
                    "confidence": 0.99,
                    "reason": "Too slow"
                }))
        })
        .mount(&server)
        .await;

    // Post 2 responds immediately with an actionable violation.
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(wiremock::matchers::body_string_contains(
            "fast_followup_post",
        ))
        .respond_with(move |_req: &wiremock::Request| {
            fast_calls_clone.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({
                "violates": true,
                "category": "spam",
                "confidence": 0.96,
                "reason": "Fast spam evaluation after slow post released permit"
            }))
        })
        .mount(&server)
        .await;

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
    let jev_config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-test".to_string(),
        timeout: Duration::from_millis(50),
        max_retries: 0,
        supports_images: false,
    };
    let classifier = Arc::new(JevClassifier::new(jev_config, rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_evaluation_queue_capacity(32)
        .with_evaluation_concurrency(1)
        .with_hold_queue_on_classifier_unavailable(true)
        .with_classifier_retry_backoff(Duration::from_millis(10))
        .with_max_classifier_timeout_retries(1)
        .with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    )
    .expect("evaluation queue test engine");

    let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(100);
    let cancel = CancellationToken::new();

    let mut join_set = JoinSet::new();
    let eng_clone = engine.clone();
    let cancel_clone = cancel.clone();
    join_set.spawn(async move { eng_clone.run(commit_rx, cancel_clone).await });

    // Enqueue the stalling post first, then a fast follow-up post behind it.
    commit_tx
        .send(make_reply_commit(
            "did:plc:slow_author",
            "did:plc:alice",
            "slow_post_1",
            "root_1",
            "slow_poison_post that times out",
        ))
        .await
        .unwrap();
    commit_tx
        .send(make_reply_commit(
            "did:plc:fast_author",
            "did:plc:alice",
            "fast_post_2",
            "root_1",
            "fast_followup_post spam behind slow post",
        ))
        .await
        .unwrap();

    // Poll bounded wait until both queued candidates finish processing (1 initial + 1 timeout retry = 2 calls).
    for _ in 0..80 {
        if engine.stats().snapshot().eval_queue_processed >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    cancel.cancel();
    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let final_stats = engine.stats().snapshot();
    assert_eq!(final_stats.eval_queue_enqueued, 2);
    assert_eq!(final_stats.eval_queue_processed, 2);
    assert_eq!(
        slow_calls.load(Ordering::SeqCst),
        2,
        "1 initial timeout + 1 timeout retry before releasing worker permit"
    );
    assert_eq!(fast_calls.load(Ordering::SeqCst), 1);
    assert_eq!(final_stats.bounces_executed, 1);
    assert!(final_stats.errors_encountered >= 2);
}

#[tokio::test]
async fn test_pr2_http_500_bounded_retries_and_recovers() {
    let pds = MockPdsServer::start().await;
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_clone = Arc::clone(&calls);

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = calls_clone.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                ResponseTemplate::new(500).set_body_string("malformed prompt context")
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "violates": true,
                    "category": "spam",
                    "confidence": 0.96,
                    "reason": "spam"
                }))
            }
        })
        .mount(&server)
        .await;

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
    let jev_config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-test".to_string(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        supports_images: false,
    };
    let classifier = Arc::new(JevClassifier::new(jev_config, rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_evaluation_queue_capacity(16)
        .with_evaluation_concurrency(1)
        .with_hold_queue_on_classifier_unavailable(true)
        .with_classifier_retry_backoff(Duration::from_millis(5))
        .with_max_classifier_500_retries(2)
        .with_classifier_circuit_breaker_cooldown(Duration::from_secs(30))
        .with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    )
    .unwrap();

    let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(16);
    let cancel = CancellationToken::new();
    let mut join_set = JoinSet::new();
    let eng_clone = engine.clone();
    let cancel_clone = cancel.clone();
    join_set.spawn(async move { eng_clone.run(commit_rx, cancel_clone).await });

    commit_tx
        .send(make_reply_commit(
            "did:plc:spam_500",
            "did:plc:alice",
            "p1",
            "root_1",
            "buy scam",
        ))
        .await
        .unwrap();

    for _ in 0..80 {
        if engine.stats().snapshot().eval_queue_processed >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    cancel.cancel();
    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "1 initial + 2 bounded HTTP 500 retries inside eval worker"
    );
    let stats = engine.stats().snapshot();
    assert_eq!(stats.bounces_executed, 1);
    assert_eq!(stats.errors_encountered, 2);
}

#[tokio::test]
async fn test_pr2_circuit_breaker_trips_on_consecutive_500s_and_503_does_not_trip() {
    let pds = MockPdsServer::start().await;
    let server = MockServer::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_clone = Arc::clone(&calls);

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(move |_req: &wiremock::Request| {
            let n = calls_clone.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // First call returns 503: transient infrastructure error must NOT trip 500 breaker
                ResponseTemplate::new(503).set_body_string("upstream restarting")
            } else if n <= 3 {
                // Next 3 calls return HTTP 500: reach threshold (3) and trip breaker
                ResponseTemplate::new(500).set_body_string("poison payload")
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "violates": false,
                    "confidence": 0.95,
                    "reason": "ok"
                }))
            }
        })
        .mount(&server)
        .await;

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
    let jev_config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-test".to_string(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        supports_images: false,
    };
    let classifier = Arc::new(JevClassifier::new(jev_config, rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());

    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_hold_queue_on_classifier_unavailable(false)
        .with_classifier_circuit_breaker_cooldown(Duration::from_millis(80))
        .with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    )
    .unwrap();

    let mk = |idx: usize| Interaction {
        post_uri: format!("at://did:plc:a{idx}/app.bsky.feed.post/p{idx}"),
        post_cid: Some(format!("c{idx}")),
        author_did: format!("did:plc:a{idx}"),
        target_did: "did:plc:alice".to_string(),
        text: "hello".to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: Some("at://did:plc:alice/app.bsky.feed.post/root".to_string()),
        root_uri: Some("at://did:plc:alice/app.bsky.feed.post/root".to_string()),
        quote_uri: None,
        created_at_us: 1_720_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    };

    // Call 1: 503 does NOT trip breaker (and if we had only 2 500s afterward, breaker stays closed)
    assert!(engine.evaluate_candidate(mk(0)).await.is_err());
    // Calls 2..=4: 3 consecutive HTTP 500s open the circuit breaker
    for idx in 1..=3 {
        assert!(engine.evaluate_candidate(mk(idx)).await.is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);

    // Call 5 during cooldown short-circuits BEFORE HTTP (0 extra calls)
    let cb_err = engine.evaluate_candidate(mk(4)).await.unwrap_err();
    assert!(
        cb_err.to_string().contains("circuit breaker open"),
        "expected circuit breaker error, got: {cb_err}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);

    // Wait past 80ms cooldown -> half-open/closed recovery succeeds
    tokio::time::sleep(Duration::from_millis(100)).await;
    let ok = engine.evaluate_candidate(mk(5)).await.unwrap();
    assert!(ok.is_permitted());
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn test_pr2_rate_limiter_is_exhausted_skips_enricher_check_relationship() {
    use async_trait::async_trait;
    use skybouncer::engine::SkybouncerEngineBuilder;
    use skybouncer::enricher::{ContextEnricher, EnrichedContext};
    use skybouncer::limiter::{EvaluationRateLimiter, RateLimiterConfig};

    struct SpyEnricher {
        rel_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ContextEnricher for SpyEnricher {
        async fn enrich(&self, _interaction: &Interaction) -> EnrichedContext {
            EnrichedContext::empty()
        }

        async fn check_relationship(
            &self,
            _target_did: &str,
            _candidate_did: &str,
        ) -> (bool, bool) {
            self.rel_calls.fetch_add(1, Ordering::SeqCst);
            (false, false)
        }
    }

    let pds = MockPdsServer::start().await;
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
    let classifier = Arc::new(skybouncer::classifier::MockClassifier::permitted());

    let rel_calls = Arc::new(AtomicUsize::new(0));
    let spy = Arc::new(SpyEnricher {
        rel_calls: Arc::clone(&rel_calls),
    });

    // Limit to 1 evaluation per target window
    let limiter = Arc::new(EvaluationRateLimiter::new(RateLimiterConfig {
        max_evaluations: 1,
        window_duration: Duration::from_secs(60),
    }));
    assert!(!limiter.is_exhausted("did:plc:alice", 1));

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric).with_dry_run(true);

    let engine = SkybouncerEngineBuilder::new(config)
        .with_cache(cache)
        .with_follow_graph(follow_graph)
        .with_gate(gate)
        .with_classifier(classifier)
        .with_modlist_manager(modlist_manager)
        .with_pds_client(pds_client)
        .with_enricher(spy)
        .with_rate_limiter(Arc::clone(&limiter))
        .build()
        .unwrap();

    let mk = |idx: usize| Interaction {
        post_uri: format!("at://did:plc:rl_{idx}/app.bsky.feed.post/p{idx}"),
        post_cid: Some(format!("c{idx}")),
        author_did: format!("did:plc:rl_{idx}"),
        target_did: "did:plc:alice".to_string(),
        text: "hello".to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: Some("at://did:plc:alice/app.bsky.feed.post/root".to_string()),
        root_uri: Some("at://did:plc:alice/app.bsky.feed.post/root".to_string()),
        quote_uri: None,
        created_at_us: 1_720_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    };

    let out1 = engine.evaluate_candidate(mk(1)).await.unwrap();
    assert!(out1.is_permitted());
    assert_eq!(rel_calls.load(Ordering::SeqCst), 1);
    assert!(limiter.is_exhausted("did:plc:alice", 1));

    // Second evaluation hits rate limiter BEFORE check_relationship() -> zero extra relationship calls!
    let out2 = engine.evaluate_candidate(mk(2)).await.unwrap();
    assert!(matches!(
        out2,
        skybouncer::engine::ProcessOutcome::RateLimited { .. }
    ));
    assert_eq!(rel_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_pr2_shared_ollama_semaphore_serializes_eval_and_stance_workers() {
    use skybouncer::classifier::Classifier;
    use skybouncer::dogpile::{
        LlmStormStanceClassifier, StormMetrics, StormStanceClassifier, StormStanceInput,
    };

    let server = MockServer::start().await;
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let active_clone = Arc::clone(&active);
    let max_clone = Arc::clone(&max_active);

    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(move |_req: &wiremock::Request| {
            let cur = active_clone.fetch_add(1, Ordering::SeqCst) + 1;
            max_clone.fetch_max(cur, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(60));
            active_clone.fetch_sub(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({
                "message": {
                    "role": "assistant",
                    "content": "{\"violates\": false, \"collective_hostility\": false, \"classification\": \"benign_viral\", \"confidence\": 0.92, \"reason\": \"ok\"}"
                }
            }))
        })
        .mount(&server)
        .await;

    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let ollama = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/api/chat", server.uri()),
            api_key: None,
            model: "qwen3.5:9b".to_string(),
            timeout: Duration::from_secs(2),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap()
    .with_inference_semaphore(Arc::clone(&sem));

    let stance = LlmStormStanceClassifier::new(JevConfig {
        base_url: format!("{}/api/chat", server.uri()),
        api_key: None,
        model: "qwen3.5:9b".to_string(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        supports_images: false,
    })
    .unwrap()
    .with_inference_semaphore(sem);

    let inter = Interaction {
        post_uri: "at://did:plc:auth/app.bsky.feed.post/1".to_string(),
        post_cid: None,
        author_did: "did:plc:auth".to_string(),
        target_did: "did:plc:alice".to_string(),
        text: "test".to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: None,
        root_uri: None,
        quote_uri: None,
        created_at_us: 1_720_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    };
    let bundle = StormStanceInput {
        target_did: "did:plc:alice".to_string(),
        target_handle: None,
        focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/root".to_string(),
        focal_post: None,
        top_quotes: vec![],
        sample_replies: vec![],
        metrics: StormMetrics::default(),
    };

    let (r1, r2) = tokio::join!(ollama.classify(&inter), stance.classify_storm(&bundle));
    assert!(r1.is_ok());
    assert!(r2.is_ok());
    assert_eq!(
        max_active.load(Ordering::SeqCst),
        1,
        "shared Ollama semaphore must serialize eval and stance workers to max 1 in-flight call"
    );
}

#[tokio::test]
async fn test_pr2_engine_tier2_image_escalation_and_rubric_below_threshold_stats() {
    use skybouncer::classifier::{
        CertaintyConfig, MockClassifier, TieredClassifier, Verdict, ViolationCategory,
    };

    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let low_rubric = RuleRubric::new("Strict bar", Sensitivity::Low); // threshold 0.90
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(low_rubric.clone())
            .with_dry_run(true),
    );
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));

    // Primary permits (0.95) on an image post -> escalates strictly via VisualMedia to Tier 2,
    // which returns Harassment at 0.88 -> below Low sensitivity (0.90) -> BelowThreshold!
    let primary = Arc::new(MockClassifier::new(Verdict::Permitted {
        confidence: Some(0.95),
        reason: "text ok".to_string(),
    }));
    let fallback = Arc::new(MockClassifier::new(Verdict::Violation {
        category: ViolationCategory::Harassment,
        confidence: 0.88,
        reason: "marginal image attack".to_string(),
    }));
    let tiered: Arc<dyn skybouncer::classifier::Classifier> = Arc::new(TieredClassifier::new(
        primary,
        fallback,
        CertaintyConfig::default().with_escalate_on_images(true),
    ));

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());
    let config = SkybouncerConfig::new(protected_dids, low_rubric).with_dry_run(true);

    let engine = SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        tiered,
        modlist_manager,
        pds_client,
    )
    .unwrap();

    let inter = Interaction {
        post_uri: "at://did:plc:img_author/app.bsky.feed.post/p1".to_string(),
        post_cid: Some("cid_img".to_string()),
        author_did: "did:plc:img_author".to_string(),
        target_did: "did:plc:alice".to_string(),
        text: "look".to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: Some("at://did:plc:alice/app.bsky.feed.post/root".to_string()),
        root_uri: Some("at://did:plc:alice/app.bsky.feed.post/root".to_string()),
        quote_uri: None,
        created_at_us: 1_720_000_000_000_000,
        image_cids: vec!["bafyrei_img".to_string()],
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    };

    let outcome = engine.evaluate_candidate(inter).await.unwrap();
    assert!(matches!(
        outcome,
        skybouncer::engine::ProcessOutcome::BelowThreshold { .. }
    ));

    let stats = engine.stats().snapshot();
    assert_eq!(stats.tier2_evaluations, 1);
    assert_eq!(stats.tier2_image_escalations, 1);
    assert_eq!(stats.bounces_skipped_rubric, 1);
}
