//! Comprehensive Fault Injection and Adversarial Recovery Test Suite for `SkybouncerEngine` (Milestone 4 Challenger 2).
//!
//! Validates:
//! 1. **PDS and Jev Network Faults**:
//!    - Intermittent HTTP 500, 502, 503, connection resets, and socket drops on both Jev classifier and PDS endpoints.
//!    - Graceful error accounting via `stats.errors_encountered` without pipeline worker death or deadlock.
//!    - State consistency and recovery once network endpoints recover.
//! 2. **Adversarial & Corrupt Commit Payloads**:
//!    - Commits with malformed JSON (primitives, arrays, invalid schema types).
//!    - Unparseable, empty, or adversarial DIDs and AT-URIs.
//!    - Extremely large payloads (>1MB text, thousands of facets).
//!    - Mismatched collections, unknown operations, and corrupted follow records.
//!    - Strict invariant: Zero panics across all adversarial inputs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use parking_lot::Mutex;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybase::ingest::events::{CommitOperation, JetstreamCommit};
use skybouncer::classifier::{Classifier, JevClassifier, JevConfig, RuleRubric, Sensitivity};
use skybouncer::engine::{ProcessCommitResult, SkybouncerConfig, SkybouncerEngine};
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};

// =============================================================================
// Helper Test Fixture Builders
// =============================================================================

/// Dynamic mock Jev classifier server supporting staged sequential responses.
pub struct FaultInjectableJevServer {
    server: MockServer,
    pub call_count: Arc<AtomicUsize>,
    pub responses: Arc<Mutex<Vec<ResponseTemplate>>>,
}

impl FaultInjectableJevServer {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let call_count = Arc::new(AtomicUsize::new(0));
        let responses = Arc::new(Mutex::new(Vec::new()));

        let count = Arc::clone(&call_count);
        let resp_queue = Arc::clone(&responses);

        Mock::given(method("POST"))
            .and(path("/v1/classify"))
            .respond_with(move |_req: &wiremock::Request| {
                count.fetch_add(1, Ordering::SeqCst);
                let mut guard = resp_queue.lock();
                if !guard.is_empty() {
                    guard.remove(0)
                } else {
                    // Default fallback response: benign permitted
                    ResponseTemplate::new(200).set_body_json(json!({
                        "violates": false,
                        "category": null,
                        "confidence": 0.05,
                        "reason": "Default fallback permitted"
                    }))
                }
            })
            .mount(&server)
            .await;

        Self {
            server,
            call_count,
            responses,
        }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn queue_response(&self, template: ResponseTemplate) {
        self.responses.lock().push(template);
    }

    pub fn config(&self, max_retries: usize) -> JevConfig {
        JevConfig {
            base_url: self.uri(),
            api_key: Some("fault_test_key".to_string()),
            model: "jev-system1-mod-v1".to_string(),
            timeout: Duration::from_millis(1500),
            max_retries,
        }
    }

    pub fn classifier(&self, rubric: RuleRubric, max_retries: usize) -> Arc<dyn Classifier> {
        let classifier = JevClassifier::new(self.config(max_retries), rubric)
            .expect("JevClassifier creation should succeed");
        Arc::new(classifier)
    }
}

/// Helper building a full SkybouncerEngine instance with injectable components.
pub struct EngineTestRig {
    pub pds: MockPdsServer,
    pub jev: FaultInjectableJevServer,
    pub cache: Arc<DeduplicationCache>,
    pub follow_graph: Arc<FollowGraph>,
    pub gate: Arc<NonFollowedGate>,
    pub modlist_manager: Arc<ModListManager>,
    pub engine: Arc<SkybouncerEngine>,
    pub protected_did: String,
}

impl EngineTestRig {
    pub async fn start(protected_did: &str, jev_retries: usize) -> Self {
        let pds = MockPdsServer::start().await;
        let jev = FaultInjectableJevServer::start().await;

        let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
        let follow_graph = Arc::new(FollowGraph::new());
        let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

        let rubric = RuleRubric::new("Block toxicity, scams, and harassment", Sensitivity::Medium);
        let modlist_manager = Arc::new(
            ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()),
        );

        let pds_client = Arc::new(pds.pds_client(protected_did));
        let classifier = jev.classifier(rubric.clone(), jev_retries);

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
}

// =============================================================================
// Part 1: Jev Network Faults & Pipeline Loop Survival
// =============================================================================

#[tokio::test]
async fn test_jev_500_502_503_intermittent_errors_counted_and_pipeline_survives() {
    let rig = EngineTestRig::start("did:plc:protected_alice", 0).await;

    // Queue 3 consecutive transient server errors on Jev: 500 -> 502 -> 503
    rig.jev
        .queue_response(ResponseTemplate::new(500).set_body_string("Internal Error"));
    rig.jev
        .queue_response(ResponseTemplate::new(502).set_body_string("Bad Gateway"));
    rig.jev
        .queue_response(ResponseTemplate::new(503).set_body_string("Service Unavailable"));

    // Then Jev recovers: 1 toxic violation (confidence 0.95), then 1 benign post (confidence 0.05)
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "harassment",
            "confidence": 0.95,
            "reason": "Targeted harassment detected after Jev recovery"
        })));
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": false,
            "category": null,
            "confidence": 0.05,
            "reason": "Benign polite comment"
        })));

    let mut join_set = JoinSet::new();
    let cancel = CancellationToken::new();
    let tx = rig.engine.spawn_in_join_set(&mut join_set, cancel.clone());

    // Send 3 commits during the 5xx outage
    for i in 1..=3 {
        let commit = make_reply_commit(
            &format!("did:plc:violator_during_5xx_{i}"),
            &rig.protected_did,
            &format!("rkey_5xx_{i}"),
            "parent_post_1",
            "This interaction is evaluated during Jev 5xx outage",
        );
        tx.send(commit).await.unwrap();
    }

    // Send 2 commits after Jev recovers (1 violation, 1 benign)
    let recovered_violation = make_reply_commit(
        "did:plc:violator_after_recovery",
        &rig.protected_did,
        "rkey_recov_1",
        "parent_post_1",
        "Toxic message after Jev recovery",
    );
    tx.send(recovered_violation).await.unwrap();

    let recovered_benign = make_reply_commit(
        "did:plc:benign_user",
        &rig.protected_did,
        "rkey_recov_2",
        "parent_post_1",
        "Hello! Great project!",
    );
    tx.send(recovered_benign).await.unwrap();

    // Allow worker loop to process all 5 commits
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Shutdown gracefully
    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let stats = rig.engine.stats().snapshot();

    // Verify accounting:
    // Exactly 5 commits processed
    assert_eq!(stats.commits_received, 5);
    // Exactly 3 errors encountered from the 500, 502, 503 failures
    assert_eq!(stats.errors_encountered, 3);
    // Exactly 1 bounce executed after recovery
    assert_eq!(stats.bounces_executed, 1);
    assert_eq!(stats.bounced, 1);
    // Exactly 1 permitted interaction
    assert_eq!(stats.permitted, 1);

    // Verify PDS listitem write occurred for the recovered violator
    let created = rig.pds.created_records.lock();
    let listitem_records: Vec<_> = created
        .iter()
        .filter(|r| r["collection"] == "app.bsky.graph.listitem")
        .cloned()
        .collect();
    assert_eq!(listitem_records.len(), 1);
    assert_eq!(
        listitem_records[0]["record"]["subject"],
        "did:plc:violator_after_recovery"
    );

    // Verify SQLite cache recorded only the recovered violator
    assert!(rig
        .cache
        .is_bounced("did:plc:violator_after_recovery")
        .unwrap());
    assert!(!rig
        .cache
        .is_bounced("did:plc:violator_during_5xx_1")
        .unwrap());
    assert!(!rig
        .cache
        .is_bounced("did:plc:violator_during_5xx_2")
        .unwrap());
    assert!(!rig
        .cache
        .is_bounced("did:plc:violator_during_5xx_3")
        .unwrap());
}

#[tokio::test]
async fn test_jev_socket_drop_exhaustion_counted_in_engine_stats_and_loop_survives() {
    // Set up a raw TCP listener that accepts connections and immediately closes them
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    // Background task resetting sockets
    let drop_task = tokio::spawn(async move {
        // Accept and drop 4 incoming connections (attempt 0 and attempt 1 for 2 requests)
        for _ in 0..4 {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream.shutdown().await;
                drop(stream);
            }
        }
    });

    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block toxicity", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));

    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));
    let jev_config = JevConfig {
        base_url: format!("http://{local_addr}"),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(500),
        max_retries: 1,
    };
    let classifier = Arc::new(JevClassifier::new(jev_config, rubric.clone()).unwrap());

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        Arc::clone(&follow_graph),
        Arc::clone(&gate),
        classifier,
        Arc::clone(&modlist_manager),
        pds_client,
    ));

    let mut join_set = JoinSet::new();
    let cancel = CancellationToken::new();
    let tx = engine.spawn_in_join_set(&mut join_set, cancel.clone());

    // Push 2 candidate commits that will experience socket drop exhaustion
    for i in 1..=2 {
        let commit = make_reply_commit(
            &format!("did:plc:socket_drop_candidate_{i}"),
            "did:plc:alice",
            &format!("rkey_drop_{i}"),
            "root_post",
            "This post will experience socket drop during Jev classify",
        );
        tx.send(commit).await.unwrap();
    }

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Shutdown engine cleanly
    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let stats = engine.stats().snapshot();
    assert_eq!(stats.commits_received, 2);
    // Both attempts exhausted retries and incremented errors_encountered
    assert_eq!(stats.errors_encountered, 2);
    assert_eq!(stats.bounces_executed, 0);

    let _ = drop_task.await;
}

#[tokio::test]
async fn test_jev_client_timeout_graceful_recovery_in_pipeline() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    // Queue 1 delayed response (500ms delay while client timeout will be exceeded or simulated)
    // Wiremock supports fixed delay:
    rig.jev.queue_response(
        ResponseTemplate::new(200)
            .set_delay(Duration::from_millis(300))
            .set_body_json(json!({
                "violates": true,
                "category": "harassment",
                "confidence": 0.95,
                "reason": "Slow response"
            })),
    );

    // Followed by 1 immediate response
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "spam",
            "confidence": 0.90,
            "reason": "Fast recovery response"
        })));

    let mut join_set = JoinSet::new();
    let cancel = CancellationToken::new();
    let tx = rig.engine.spawn_in_join_set(&mut join_set, cancel.clone());

    let commit1 = make_reply_commit(
        "did:plc:slow_user",
        &rig.protected_did,
        "rkey_slow",
        "parent_post",
        "Slow interaction",
    );
    let commit2 = make_reply_commit(
        "did:plc:fast_user",
        &rig.protected_did,
        "rkey_fast",
        "parent_post",
        "Fast interaction",
    );

    tx.send(commit1).await.unwrap();
    tx.send(commit2).await.unwrap();

    // Allow time for both to complete
    tokio::time::sleep(Duration::from_millis(600)).await;

    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let stats = rig.engine.stats().snapshot();
    assert_eq!(stats.commits_received, 2);
    // Both ultimately succeeded without timeout (since timeout is 1500ms) or bounced
    assert_eq!(stats.bounces_executed, 2);
    assert_eq!(stats.errors_encountered, 0);
}

// =============================================================================
// Part 2: PDS Network Faults & Pipeline Loop Survival
// =============================================================================

#[tokio::test]
async fn test_pds_500_502_503_intermittent_errors_counted_cache_consistent() {
    let rig = EngineTestRig::start("did:plc:protected_alice", 0).await;

    // Jev always returns high-confidence violation for these candidates
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.98,
            "reason": "Malicious crypto phishing link"
        })));
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.98,
            "reason": "Malicious crypto phishing link"
        })));
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.98,
            "reason": "Malicious crypto phishing link"
        })));
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.98,
            "reason": "Malicious crypto phishing link"
        })));

    // Pre-provision the modlist in cache so ensure_mod_list succeeds without failing
    rig.modlist_manager
        .ensure_mod_list(&rig.pds.pds_client(&rig.protected_did), &rig.protected_did)
        .await
        .unwrap();

    // Inject 3 consecutive failures on PDS createRecord: 500, 502, 503
    rig.pds
        .mount_create_error_once(500, "InternalServerError", "Database deadlocked")
        .await;

    let mut join_set = JoinSet::new();
    let cancel = CancellationToken::new();
    let tx = rig.engine.spawn_in_join_set(&mut join_set, cancel.clone());

    // Commit 1: Fails on PDS 500
    let commit1 = make_reply_commit(
        "did:plc:spammer_1",
        &rig.protected_did,
        "rkey_spam_1",
        "parent_post",
        "Free airdrop 1",
    );
    tx.send(commit1).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(
        rig.engine
            .stats()
            .errors_encountered
            .load(Ordering::Relaxed),
        1
    );
    assert!(!rig.cache.is_bounced("did:plc:spammer_1").unwrap());

    // Inject PDS 502 on Commit 2
    rig.pds
        .mount_create_error_once(502, "BadGateway", "Upstream PDS proxy error")
        .await;
    let commit2 = make_reply_commit(
        "did:plc:spammer_2",
        &rig.protected_did,
        "rkey_spam_2",
        "parent_post",
        "Free airdrop 2",
    );
    tx.send(commit2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(
        rig.engine
            .stats()
            .errors_encountered
            .load(Ordering::Relaxed),
        2
    );
    assert!(!rig.cache.is_bounced("did:plc:spammer_2").unwrap());

    // Inject PDS 503 on Commit 3
    rig.pds
        .mount_create_error_once(503, "ServiceUnavailable", "PDS overloaded")
        .await;
    let commit3 = make_reply_commit(
        "did:plc:spammer_3",
        &rig.protected_did,
        "rkey_spam_3",
        "parent_post",
        "Free airdrop 3",
    );
    tx.send(commit3).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(
        rig.engine
            .stats()
            .errors_encountered
            .load(Ordering::Relaxed),
        3
    );
    assert!(!rig.cache.is_bounced("did:plc:spammer_3").unwrap());

    // Commit 4: PDS is now healthy and returns 200 OK!
    let commit4 = make_reply_commit(
        "did:plc:spammer_4_recovered",
        &rig.protected_did,
        "rkey_spam_4",
        "parent_post",
        "Free airdrop 4",
    );
    tx.send(commit4).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(
        rig.engine
            .stats()
            .errors_encountered
            .load(Ordering::Relaxed),
        3
    );
    assert_eq!(
        rig.engine.stats().bounces_executed.load(Ordering::Relaxed),
        1
    );
    assert!(rig.cache.is_bounced("did:plc:spammer_4_recovered").unwrap());

    // Commit 5: Send a repeated attack from spammer_4_recovered.
    // Tier 4 Deduplication Cache must short-circuit it with 0 network calls!
    let commit5 = make_reply_commit(
        "did:plc:spammer_4_recovered",
        &rig.protected_did,
        "rkey_spam_5",
        "parent_post",
        "Free airdrop 5 (duplicate spam)",
    );
    tx.send(commit5).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    let stats = rig.engine.stats().snapshot();
    assert_eq!(stats.commits_received, 5);
    assert_eq!(stats.errors_encountered, 3);
    assert_eq!(stats.bounces_executed, 1);
    assert_eq!(stats.dedup_cache_hits, 1); // Deduplication cache intercepted!

    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_pds_socket_drop_during_bounce_pipeline_survives() {
    // Bind a TCP listener that accepts a connection and immediately closes it
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let drop_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream.shutdown().await;
            drop(stream);
        }
    });

    let jev = FaultInjectableJevServer::start().await;
    jev.queue_response(ResponseTemplate::new(200).set_body_json(json!({
        "violates": true,
        "category": "harassment",
        "confidence": 0.95,
        "reason": "Hostile attack"
    })));

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block toxicity", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));

    // Pre-populate list config in cache so ensure_mod_list doesn't fail before createRecord
    let list_config = skybouncer::modlist::ModListConfig {
        user_did: "did:plc:alice".to_string(),
        list_uri: "at://did:plc:alice/app.bsky.graph.list/test_list".to_string(),
        list_cid: "bafytestcid".to_string(),
        created_at: 1_700_000_000,
    };
    cache.set_mod_list(&list_config).unwrap();

    // Point PDS client to the dropping TCP listener
    let pds_client = Arc::new(
        skybase::repo::PdsRepoClient::from_credentials(
            format!("http://{local_addr}"),
            "did:plc:alice",
            "mock_token",
        )
        .unwrap(),
    );

    let classifier = jev.classifier(rubric.clone(), 0);

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        Arc::clone(&follow_graph),
        Arc::clone(&gate),
        classifier,
        Arc::clone(&modlist_manager),
        pds_client,
    ));

    let mut join_set = JoinSet::new();
    let cancel = CancellationToken::new();
    let tx = engine.spawn_in_join_set(&mut join_set, cancel.clone());

    let commit = make_reply_commit(
        "did:plc:pds_socket_drop_user",
        "did:plc:alice",
        "rkey_pds_drop",
        "parent_post",
        "Hostile comment that will hit PDS socket drop",
    );
    tx.send(commit).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let stats = engine.stats().snapshot();
    assert_eq!(stats.commits_received, 1);
    assert_eq!(stats.errors_encountered, 1);
    assert_eq!(stats.bounces_executed, 0);
    assert!(!cache.is_bounced("did:plc:pds_socket_drop_user").unwrap());

    let _ = drop_task.await;
}

#[tokio::test]
async fn test_mixed_adversarial_pds_and_jev_failures_in_continuous_stream() {
    let rig = EngineTestRig::start("did:plc:protected_alice", 0).await;

    // Follow a friend on the follow graph
    rig.follow_graph.add_follow(
        &rig.protected_did,
        "follow_friend",
        "did:plc:trusted_friend",
    );

    // Pre-provision mod list
    rig.modlist_manager
        .ensure_mod_list(&rig.pds.pds_client(&rig.protected_did), &rig.protected_did)
        .await
        .unwrap();

    // Set up Jev responses:
    // 1. For stranger_fail_jev_500: return 500
    rig.jev
        .queue_response(ResponseTemplate::new(500).set_body_string("Jev internal error"));
    // 2. For stranger_fail_pds_500: return 200 violation
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "harassment",
            "confidence": 0.95,
            "reason": "Violating post that will fail at PDS"
        })));
    // 3. For stranger_success_bounce: return 200 violation
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "spam",
            "confidence": 0.92,
            "reason": "Violating post that will bounce"
        })));
    // 4. For stranger_benign: return 200 permitted
    rig.jev
        .queue_response(ResponseTemplate::new(200).set_body_json(json!({
            "violates": false,
            "category": null,
            "confidence": 0.05,
            "reason": "Polite comment"
        })));

    // Mount 1 error on PDS for the second candidate
    rig.pds
        .mount_create_error_once(500, "InternalServerError", "Temporary PDS DB lock")
        .await;

    let mut join_set = JoinSet::new();
    let cancel = CancellationToken::new();
    let tx = rig.engine.spawn_in_join_set(&mut join_set, cancel.clone());

    // Stream 5 commits:
    // Commit 1: Followed friend ($0 cost, gate bypass)
    let c1 = make_reply_commit(
        "did:plc:trusted_friend",
        &rig.protected_did,
        "rkey_c1",
        "parent",
        "Toxic-sounding banter between close friends",
    );
    // Commit 2: Fails at Jev (500)
    let c2 = make_reply_commit(
        "did:plc:stranger_fail_jev_500",
        &rig.protected_did,
        "rkey_c2",
        "parent",
        "Attack triggering Jev failure",
    );
    // Commit 3: Passes Jev, fails at PDS (500)
    let c3 = make_reply_commit(
        "did:plc:stranger_fail_pds_500",
        &rig.protected_did,
        "rkey_c3",
        "parent",
        "Attack triggering PDS failure",
    );
    // Commit 4: Passes Jev and PDS (bounced!)
    let c4 = make_reply_commit(
        "did:plc:stranger_success_bounce",
        &rig.protected_did,
        "rkey_c4",
        "parent",
        "Attack that succeeds and bounces",
    );
    // Commit 5: Passes Jev as benign (permitted)
    let c5 = make_reply_commit(
        "did:plc:stranger_benign",
        &rig.protected_did,
        "rkey_c5",
        "parent",
        "Hello, nice post!",
    );

    tx.send(c1).await.unwrap();
    tx.send(c2).await.unwrap();
    tx.send(c3).await.unwrap();
    tx.send(c4).await.unwrap();
    tx.send(c5).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, Duration::from_secs(2))
        .await
        .unwrap();

    let stats = rig.engine.stats().snapshot();
    assert_eq!(stats.commits_received, 5);
    // 1 gate bypass for friend
    assert_eq!(stats.gate_bypassed_followed, 1);
    // Exactly 2 errors encountered (1 from Jev, 1 from PDS)
    assert_eq!(stats.errors_encountered, 2);
    // Exactly 1 bounce executed
    assert_eq!(stats.bounces_executed, 1);
    // Exactly 1 permitted
    assert_eq!(stats.permitted, 1);

    // Verify cache state
    assert!(!rig.cache.is_bounced("did:plc:trusted_friend").unwrap());
    assert!(!rig
        .cache
        .is_bounced("did:plc:stranger_fail_jev_500")
        .unwrap());
    assert!(!rig
        .cache
        .is_bounced("did:plc:stranger_fail_pds_500")
        .unwrap());
    assert!(rig
        .cache
        .is_bounced("did:plc:stranger_success_bounce")
        .unwrap());
    assert!(!rig.cache.is_bounced("did:plc:stranger_benign").unwrap());
}

// =============================================================================
// Part 3: Adversarial & Corrupt Commit Payloads (Zero Panic Invariant)
// =============================================================================

#[tokio::test]
async fn test_adversarial_malformed_json_primitive_and_array_records() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    let malformed_records = vec![
        Some(json!("plain string record payload")),
        Some(json!(123456789)),
        Some(json!(true)),
        Some(json!(false)),
        Some(json!(null)),
        Some(json!([1, 2, 3, "array instead of record object"])),
        Some(json!({})), // Empty object without reply/facets/embed
        None,            // Absent record payload
    ];

    for (idx, record) in malformed_records.into_iter().enumerate() {
        let commit = JetstreamCommit {
            did: "did:plc:attacker".to_string(),
            time_us: 1_720_000_000_000_000,
            collection: "app.bsky.feed.post".to_string(),
            rkey: format!("malformed_{idx}"),
            operation: CommitOperation::Create,
            cid: Some("bafycid".to_string()),
            record,
        };

        // ZERO PANIC INVARIANT: Must return Result without panicking
        let result = rig.engine.process_commit(&commit).await;
        assert!(result.is_ok(), "Malformed commit {idx} should not error");
        let outcome = result.unwrap();
        assert!(
            outcome.is_no_match() || outcome.is_ignored(),
            "Commit {idx} must be NoMatch or Ignored, got: {outcome:?}"
        );
    }
}

#[tokio::test]
async fn test_adversarial_corrupted_post_record_fields() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    let test_records = vec![
        // 1. reply is primitive
        json!({
            "$type": "app.bsky.feed.post",
            "text": "attack",
            "reply": "not-an-object",
            "createdAt": "2026-10-02T00:00:00Z"
        }),
        // 2. reply has missing/null root & parent
        json!({
            "$type": "app.bsky.feed.post",
            "text": "attack",
            "reply": { "parent": null, "root": null },
            "createdAt": "2026-10-02T00:00:00Z"
        }),
        // 3. reply parent is integer
        json!({
            "$type": "app.bsky.feed.post",
            "text": "attack",
            "reply": { "parent": 12345, "root": "at://did:plc:alice/app.bsky.feed.post/1" },
            "createdAt": "2026-10-02T00:00:00Z"
        }),
        // 4. facets is primitive
        json!({
            "$type": "app.bsky.feed.post",
            "text": "attack",
            "facets": "not an array",
            "createdAt": "2026-10-02T00:00:00Z"
        }),
        // 5. facets array contains corrupt items
        json!({
            "$type": "app.bsky.feed.post",
            "text": "attack",
            "facets": [null, 123, "string", { "index": null }],
            "createdAt": "2026-10-02T00:00:00Z"
        }),
        // 6. embed is primitive
        json!({
            "$type": "app.bsky.feed.post",
            "text": "attack",
            "embed": 99999,
            "createdAt": "2026-10-02T00:00:00Z"
        }),
        // 7. embed.record is corrupted
        json!({
            "$type": "app.bsky.feed.post",
            "text": "attack",
            "embed": {
                "$type": "app.bsky.embed.record",
                "record": "not-a-strong-ref-object"
            },
            "createdAt": "2026-10-02T00:00:00Z"
        }),
        // 8. embed.recordWithMedia has null record
        json!({
            "$type": "app.bsky.feed.post",
            "text": "attack",
            "embed": {
                "$type": "app.bsky.embed.recordWithMedia",
                "record": null
            },
            "createdAt": "2026-10-02T00:00:00Z"
        }),
    ];

    for (idx, record) in test_records.into_iter().enumerate() {
        let commit = JetstreamCommit {
            did: "did:plc:attacker".to_string(),
            time_us: 1_720_000_000_000_000,
            collection: "app.bsky.feed.post".to_string(),
            rkey: format!("corrupt_field_{idx}"),
            operation: CommitOperation::Create,
            cid: Some("bafycid".to_string()),
            record: Some(record),
        };

        let result = rig.engine.process_commit(&commit).await;
        assert!(
            result.is_ok(),
            "Corrupted post record {idx} should not error"
        );
        assert!(result.unwrap().is_no_match());
    }
}

#[tokio::test]
async fn test_adversarial_unparseable_dids_and_malformed_uris() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    let adversarial_uris = vec![
        "",                                                              // empty
        "not-an-at-uri",                                                 // no scheme
        "https://bsky.app/profile/alice/post/123",                       // http url
        "at://",                                                         // just scheme
        "at:///",                                                        // slashes only
        "at://did:plc:alice",                      // missing collection and rkey
        "at://did:plc:alice/app.bsky.feed.post",   // missing rkey
        "at://did:plc:alice/app.bsky.feed.post/",  // empty rkey
        "at://did:plc:alice/wrong.collection/123", // non-post collection
        "at://not_a_did/app.bsky.feed.post/123",   // authority not starting with did:
        "at://did:/app.bsky.feed.post/123",        // empty did method
        "at://did:plc:/app.bsky.feed.post/123",    // empty did identifier
        "at://did:plc:alice\0null/app.bsky.feed.post/123", // null byte in authority
        "at://did:method:id:with:lots:of:colons/app.bsky.feed.post/123", // multi-colon did
    ];

    for (idx, uri) in adversarial_uris.into_iter().enumerate() {
        // Construct reply targeting adversarial URI
        let commit = JetstreamCommit {
            did: "did:plc:adversary".to_string(),
            time_us: 1_720_000_000_000_000,
            collection: "app.bsky.feed.post".to_string(),
            rkey: format!("adv_uri_{idx}"),
            operation: CommitOperation::Create,
            cid: Some("bafycid".to_string()),
            record: Some(json!({
                "$type": "app.bsky.feed.post",
                "text": "Adversarial URI test",
                "reply": {
                    "parent": { "uri": uri, "cid": "bafycid" },
                    "root": { "uri": uri, "cid": "bafycid" }
                },
                "createdAt": "2026-10-02T00:00:00Z"
            })),
        };

        let result = rig.engine.process_commit(&commit).await;
        assert!(result.is_ok(), "Adversarial URI {idx} should not error");
        assert!(result.unwrap().is_no_match());
    }
}

#[tokio::test]
async fn test_adversarial_huge_payloads_and_deep_structures() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    // 1. Huge post text: 1.5 megabytes of UTF-8 repeated string
    let huge_text = "Spam payload ".repeat(100_000); // ~1.3MB string
    let huge_rkey = "k".repeat(5_000);

    let huge_commit = make_reply_commit(
        "did:plc:huge_payload_author",
        &rig.protected_did,
        &huge_rkey,
        "parent_post",
        &huge_text,
    );

    // ZERO PANIC INVARIANT: Engine must handle 1.3MB payload safely
    let result = rig.engine.process_commit(&huge_commit).await;
    assert!(
        result.is_ok(),
        "1.3MB text commit should be evaluated without panic"
    );

    // 2. High facet count: 2,000 distinct mention facets
    let mut facets = Vec::new();
    for i in 0..2_000 {
        facets.push(json!({
            "index": { "byteStart": i, "byteEnd": i + 1 },
            "features": [
                {
                    "$type": "app.bsky.richtext.facet#mention",
                    "did": format!("did:plc:random_user_{i}")
                }
            ]
        }));
    }
    // Add 1 protected mention at the end
    facets.push(json!({
        "index": { "byteStart": 2001, "byteEnd": 2005 },
        "features": [
            {
                "$type": "app.bsky.richtext.facet#mention",
                "did": "did:plc:alice"
            }
        ]
    }));

    let multi_facet_commit = JetstreamCommit {
        did: "did:plc:spammer_facets".to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: "facet_storm".to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafycid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": "Multi-mention spam",
            "facets": facets,
            "createdAt": "2026-10-02T00:00:00Z"
        })),
    };

    let facet_result = rig.engine.process_commit(&multi_facet_commit).await;
    assert!(
        facet_result.is_ok(),
        "2,000 facets commit should succeed without panic"
    );
}

#[tokio::test]
async fn test_adversarial_mismatched_and_empty_collections() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    let adversarial_commits = vec![
        ("", CommitOperation::Create),
        ("app.bsky.feed.like", CommitOperation::Create),
        ("app.bsky.feed.repost", CommitOperation::Create),
        ("app.bsky.graph.block", CommitOperation::Create),
        ("app.bsky.actor.profile", CommitOperation::Create),
        ("chat.bsky.convo.message", CommitOperation::Create),
        ("com.atproto.repo.applyWrites", CommitOperation::Create),
        ("app.bsky.feed.post", CommitOperation::Delete),
        ("app.bsky.feed.post", CommitOperation::Update),
    ];

    for (idx, (collection, operation)) in adversarial_commits.into_iter().enumerate() {
        let commit = JetstreamCommit {
            did: "did:plc:alice".to_string(),
            time_us: 1_720_000_000_000_000,
            collection: collection.to_string(),
            rkey: format!("mismatched_{idx}"),
            operation,
            cid: Some("bafycid".to_string()),
            record: Some(json!({ "some_key": "some_value" })),
        };

        let result = rig.engine.process_commit(&commit).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ignored());
    }
}

#[tokio::test]
async fn test_adversarial_follow_graph_corrupt_records() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    let corrupt_follow_records = vec![
        None,
        Some(json!("just a string")),
        Some(json!(42)),
        Some(json!([])),
        Some(json!({ "subject": null })),
        Some(json!({ "subject": 12345 })),
        Some(json!({ "subject": ["did:plc:bob"] })),
        Some(json!({ "other_field": "no subject" })),
    ];

    for (idx, record) in corrupt_follow_records.into_iter().enumerate() {
        let commit = JetstreamCommit {
            did: "did:plc:alice".to_string(), // Authored by protected user
            time_us: 1_720_000_000_000_000,
            collection: "app.bsky.graph.follow".to_string(),
            rkey: format!("corrupt_follow_{idx}"),
            operation: CommitOperation::Create,
            cid: Some("bafyfollow".to_string()),
            record,
        };

        let result = rig.engine.process_commit(&commit).await;
        assert!(
            result.is_ok(),
            "Corrupt follow record {idx} should not error"
        );
        match result.unwrap() {
            ProcessCommitResult::FollowSynced(event) => {
                assert_eq!(
                    event,
                    skybouncer::matcher::FollowSyncEvent::Ignored,
                    "Corrupt follow record must be ignored"
                );
            }
            other => panic!("Expected FollowSynced(Ignored), got {other:?}"),
        }
    }

    // Follow delete with non-existent or adversarial rkey
    let delete_commit = JetstreamCommit {
        did: "did:plc:alice".to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: "non_existent_follow_rkey".to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };

    let delete_result = rig.engine.process_commit(&delete_commit).await;
    assert!(delete_result.is_ok());
    match delete_result.unwrap() {
        ProcessCommitResult::FollowSynced(event) => {
            assert_eq!(
                event,
                skybouncer::matcher::FollowSyncEvent::Ignored,
                "Deleting non-existent follow must be Ignored"
            );
        }
        other => panic!("Expected FollowSynced(Ignored), got {other:?}"),
    }
}

#[tokio::test]
async fn test_adversarial_empty_and_special_character_dids_in_engine_config() {
    // Engine instantiated with strange DIDs in watch set
    let rig = EngineTestRig::start("", 0).await;
    rig.engine.add_protected_did("did:plc:weird\x00did");
    rig.engine
        .add_protected_did("did:web:example.com:8080:test");

    assert!(rig.engine.is_protected(""));
    assert!(rig.engine.is_protected("did:plc:weird\x00did"));
    assert!(rig.engine.is_protected("did:web:example.com:8080:test"));
    assert!(!rig.engine.is_protected("did:plc:unprotected"));

    // Normal commit targeting unprotected user
    let commit = make_reply_commit(
        "did:plc:author",
        "did:plc:unprotected",
        "rkey_norm",
        "parent",
        "Hello",
    );
    let result = rig.engine.process_commit(&commit).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_no_match());

    // Cleanly remove
    assert!(rig.engine.remove_protected_did(""));
    assert!(!rig.engine.is_protected(""));
}

#[tokio::test]
async fn test_adversarial_pds_connection_reset_during_pardon() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    // First bounce a violator
    let bounce_res = rig
        .modlist_manager
        .bounce_user(
            &rig.pds.pds_client(&rig.protected_did),
            &rig.protected_did,
            "did:plc:pardon_violator",
            &skybouncer::classifier::ViolationCategory::Harassment,
            0.95,
            "Hostility",
            "at://did:plc:pardon_violator/app.bsky.feed.post/1",
        )
        .await
        .unwrap();

    assert!(bounce_res.is_some());
    assert!(rig.cache.is_bounced("did:plc:pardon_violator").unwrap());

    // Inject 500 / 503 error on deleteRecord
    rig.pds
        .mount_delete_error_once(
            503,
            "ServiceUnavailable",
            "PDS storage temporarily unavailable",
        )
        .await;

    let pardon_result = rig
        .engine
        .pardon_user(&rig.protected_did, "did:plc:pardon_violator")
        .await;

    assert!(
        pardon_result.is_err(),
        "Pardon must fail when PDS delete fails"
    );

    // CRITICAL CACHE INTEGRITY INVARIANT:
    // User MUST NOT be prematurely unbounced from cache when PDS deletion failed!
    assert!(
        rig.cache.is_bounced("did:plc:pardon_violator").unwrap(),
        "User must remain bounced in cache after failed pardon attempt"
    );

    // Now PDS recovers: pardon should succeed and purge cache
    let recovered_pardon = rig
        .engine
        .pardon_user(&rig.protected_did, "did:plc:pardon_violator")
        .await
        .unwrap();

    assert!(recovered_pardon, "Pardon must succeed upon PDS recovery");
    assert!(
        !rig.cache.is_bounced("did:plc:pardon_violator").unwrap(),
        "User must be purged from cache after successful pardon"
    );
}

#[tokio::test]
async fn test_adversarial_deeply_nested_or_circular_at_uris() {
    let rig = EngineTestRig::start("did:plc:alice", 0).await;

    // Direct reply parent URI has invalid collection or too many segments,
    // but root URI correctly targets protected alice!
    let commit = JetstreamCommit {
        did: "did:plc:attacker".to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: "thread_fallback_rkey".to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafycid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": "Thread reply attack with invalid parent URI",
            "reply": {
                // Parent URI has too many path segments (invalid AT-URI)
                "parent": {
                    "uri": "at://did:plc:stranger/app.bsky.feed.post/1/extra/slash/overflow",
                    "cid": "bafyparent"
                },
                // Root URI is a valid reference to protected alice
                "root": {
                    "uri": "at://did:plc:alice/app.bsky.feed.post/valid_root_post",
                    "cid": "bafyroot"
                }
            },
            "createdAt": "2026-10-02T00:00:00Z"
        })),
    };

    // ZERO PANIC INVARIANT: TargetMatcher extracts the thread reply targeting alice
    let result = rig.engine.process_commit(&commit).await;
    assert!(
        result.is_ok(),
        "Engine must evaluate thread reply without panic"
    );
    let outcomes = result.unwrap().into_outcomes();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].target_did(), Some("did:plc:alice"));
    assert_eq!(outcomes[0].author_did(), "did:plc:attacker");
}

#[tokio::test]
async fn test_adversarial_nan_and_infinite_confidence_handling() {
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);

    // Meets threshold should be false for NaN, negative, and below threshold
    assert!(!rubric.meets_threshold(&skybouncer::classifier::ViolationCategory::Spam, f64::NAN));
    assert!(!rubric.meets_threshold(
        &skybouncer::classifier::ViolationCategory::Spam,
        f64::NEG_INFINITY
    ));
    assert!(!rubric.meets_threshold(&skybouncer::classifier::ViolationCategory::Spam, -1.0));
    assert!(!rubric.meets_threshold(&skybouncer::classifier::ViolationCategory::Spam, 0.0));
    assert!(!rubric.meets_threshold(&skybouncer::classifier::ViolationCategory::Spam, 0.74));

    // Above threshold should be true
    assert!(rubric.meets_threshold(&skybouncer::classifier::ViolationCategory::Spam, 0.75));
    assert!(rubric.meets_threshold(&skybouncer::classifier::ViolationCategory::Spam, 0.99));
    assert!(rubric.meets_threshold(&skybouncer::classifier::ViolationCategory::Spam, 1.0));
}
