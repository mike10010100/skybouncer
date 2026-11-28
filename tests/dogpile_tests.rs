//! Integration tests for Personal Dogpile Radar, Storm Mode, and On-Demand PDS Shields.
//!
//! Covers:
//! - SQLite `dogpile_events` persistence, transitions, and counters
//! - End-to-end engine surge detection, AppView enrichment, bundled Stage 3 stance check,
//!   Storm Mode digest suppression, 3x Tier-4 rate-limit headroom, and defensive Jetstream signals
//! - Sovereign `app.bsky.feed.threadgate` / `app.bsky.feed.postgate` PDS shields (live & dry-run)
//! - DM bot commands (`storms`, `storm on/off`, `lock`, `unlock`, `detach`) and authorization
//! - Authenticated REST API `/api/storms*` endpoints, tenant isolation, Prometheus counters,
//!   Dashboard HTML assets, and CLI telemetry formatting

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use common::*;
use parking_lot::Mutex;
use serde_json::json;
use skyauth::client::OAuthClientMetadata;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};
use skybase::repo::PdsRepoClient;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybouncer::classifier::{MockClassifier, RuleRubric, Sensitivity, Verdict, ViolationCategory};
use skybouncer::cli::format_final_telemetry;
use skybouncer::dogpile::{
    CatalystInfo, DogpileConfig, MockStormStanceClassifier, PostEngagementSnapshot, StormEvent,
    StormMetrics, StormSeverity, StormStanceVerdict, StormStatus, SurgeCandidate, ThreadgatePolicy,
};
use skybouncer::engine::{EngineStatsSnapshot, SkybouncerConfig, SkybouncerEngineBuilder};
use skybouncer::enricher::{AuthorContext, MockContextEnricher};
use skybouncer::limiter::{EvaluationRateLimiter, RateLimiterConfig};
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};
use skybouncer::time::current_time_us;
use skybouncer::web::{
    create_web_router, DismissStormResponse, ShieldActionResponse, StormModeResponse,
    StormsResponse, DASHBOARD_HTML,
};
use skybouncer::BotCommandHandler;

type StoredRecordMap = Arc<Mutex<HashMap<(String, String, String), serde_json::Value>>>;
type WriteOpLog = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;

struct GateMockPds {
    server: MockServer,
    stored_records: StoredRecordMap,
    write_ops: WriteOpLog,
}

impl GateMockPds {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let stored_records: StoredRecordMap = Arc::new(Mutex::new(HashMap::new()));
        let write_ops: WriteOpLog = Arc::new(Mutex::new(Vec::new()));

        let store_create = Arc::clone(&stored_records);
        let ops_create = Arc::clone(&write_ops);
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.createRecord"))
            .respond_with(move |req: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let repo = body["repo"].as_str().unwrap_or("did:plc:mock").to_string();
                let collection = body["collection"].as_str().unwrap_or("unknown").to_string();
                let rkey = body["rkey"].as_str().unwrap_or("rkey_gen").to_string();
                let uri = format!("at://{repo}/{collection}/{rkey}");
                let cid = format!("bafy{rkey}cid");
                store_create.lock().insert(
                    (repo, collection.clone(), rkey.clone()),
                    body["record"].clone(),
                );
                ops_create
                    .lock()
                    .push(("createRecord".to_string(), collection, body));
                ResponseTemplate::new(200).set_body_json(json!({ "uri": uri, "cid": cid }))
            })
            .mount(&server)
            .await;

        let store_put = Arc::clone(&stored_records);
        let ops_put = Arc::clone(&write_ops);
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.putRecord"))
            .respond_with(move |req: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let repo = body["repo"].as_str().unwrap_or("did:plc:mock").to_string();
                let collection = body["collection"].as_str().unwrap_or("unknown").to_string();
                let rkey = body["rkey"].as_str().unwrap_or("rkey_put").to_string();
                let uri = format!("at://{repo}/{collection}/{rkey}");
                let cid = format!("bafy{rkey}putcid");
                store_put.lock().insert(
                    (repo, collection.clone(), rkey.clone()),
                    body["record"].clone(),
                );
                ops_put
                    .lock()
                    .push(("putRecord".to_string(), collection, body));
                ResponseTemplate::new(200).set_body_json(json!({ "uri": uri, "cid": cid }))
            })
            .mount(&server)
            .await;

        let store_get = Arc::clone(&stored_records);
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .respond_with(move |req: &wiremock::Request| {
                let mut repo = String::new();
                let mut collection = String::new();
                let mut rkey = String::new();
                for (k, v) in req.url.query_pairs() {
                    match k.as_ref() {
                        "repo" => repo = v.to_string(),
                        "collection" => collection = v.to_string(),
                        "rkey" => rkey = v.to_string(),
                        _ => {}
                    }
                }
                let guard = store_get.lock();
                if let Some(val) = guard.get(&(repo.clone(), collection.clone(), rkey.clone())) {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "uri": format!("at://{repo}/{collection}/{rkey}"),
                        "cid": format!("bafy{rkey}getcid"),
                        "value": val
                    }))
                } else {
                    ResponseTemplate::new(400).set_body_json(json!({
                        "error": "RecordNotFound",
                        "message": "Record does not exist"
                    }))
                }
            })
            .mount(&server)
            .await;

        let store_del = Arc::clone(&stored_records);
        let ops_del = Arc::clone(&write_ops);
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.deleteRecord"))
            .respond_with(move |req: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                let repo = body["repo"].as_str().unwrap_or("").to_string();
                let collection = body["collection"].as_str().unwrap_or("").to_string();
                let rkey = body["rkey"].as_str().unwrap_or("").to_string();
                store_del.lock().remove(&(repo, collection.clone(), rkey));
                ops_del
                    .lock()
                    .push(("deleteRecord".to_string(), collection, body));
                ResponseTemplate::new(200).set_body_json(json!({}))
            })
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.listRecords"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "records": [] })))
            .mount(&server)
            .await;

        Self {
            server,
            stored_records,
            write_ops,
        }
    }

    fn client(&self, did: &str) -> PdsRepoClient {
        PdsRepoClient::from_credentials(self.server.uri(), did, "mock_token")
            .unwrap()
            .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true))
    }
}

fn build_test_engine(
    protected_did: &str,
    pds: &GateMockPds,
    enricher: Arc<MockContextEnricher>,
    stance: MockStormStanceClassifier,
    dogpile_cfg: DogpileConfig,
    max_evals: usize,
    dry_run: bool,
) -> Arc<skybouncer::SkybouncerEngine> {
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block harassment and spam", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let classifier = Arc::new(MockClassifier::new(Verdict::Violation {
        category: ViolationCategory::CryptoSpam,
        confidence: 0.95,
        reason: "Hostile coordinated reply".to_string(),
    }));
    let rate_limiter = Arc::new(EvaluationRateLimiter::new(RateLimiterConfig {
        max_evaluations: max_evals,
        window_duration: Duration::from_secs(3600),
    }));

    let mut protected = HashSet::new();
    protected.insert(protected_did.to_string());
    let mut cfg = SkybouncerConfig::new(protected, rubric)
        .with_dry_run(dry_run)
        .with_enable_heuristic_prefilter(false)
        .with_dogpile_config(dogpile_cfg)
        .with_admin_did(protected_did);
    cfg.pds_endpoint = Some(pds.server.uri());

    let engine = SkybouncerEngineBuilder::new(cfg)
        .with_cache(cache)
        .with_follow_graph(follow_graph)
        .with_gate(gate)
        .with_classifier(classifier)
        .with_modlist_manager(modlist_manager)
        .with_pds_client(Arc::new(pds.client(protected_did)))
        .with_rate_limiter(rate_limiter)
        .with_enricher(enricher)
        .with_storm_stance_classifier(Arc::new(stance))
        .build()
        .unwrap();

    Arc::new(engine)
}

#[test]
fn test_sqlite_dogpile_events_crud_and_transitions() {
    let cache = DeduplicationCache::open_in_memory().unwrap();
    let base_event = StormEvent {
        id: 0,
        target_did: "did:plc:alice".to_string(),
        target_handle: Some("alice.bsky.social".to_string()),
        focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3kfocal".to_string(),
        focal_post_snippet: "Pineapple belongs on pizza".to_string(),
        status: StormStatus::Active,
        severity: StormSeverity::Elevated,
        started_at_us: 100_000,
        updated_at_us: 100_000,
        resolved_at_us: None,
        metrics: StormMetrics {
            unique_authors_short: 18,
            unique_oon_authors_short: 16,
            out_of_network_ratio: 0.88,
            direct_ratio: 4.5,
            dunk_ratio: 12.0,
            power_asymmetry: 50.0,
            structural_score: 0.72,
            composite_score: 0.78,
            ..Default::default()
        },
        top_catalyst: Some(CatalystInfo {
            post_uri: "at://did:plc:big/app.bsky.feed.post/3kqt1".to_string(),
            author_did: "did:plc:big".to_string(),
            author_handle: Some("big.bsky.social".to_string()),
            author_followers: Some(45_000),
            like_count: 600,
            repost_count: 80,
            quote_count: 15,
            dunk_ratio: 12.0,
            text_snippet: "Get a load of this".to_string(),
        }),
        catalyst_qt_uris: vec!["at://did:plc:big/app.bsky.feed.post/3kqt1".to_string()],
        stance: Some(StormStanceVerdict::new(
            true,
            0.88,
            "dogpile",
            "Hostile quote-driven pile-on",
            "mock",
        )),
        bounces_during_storm: 0,
        threadgate_applied: false,
        postgate_detaches_applied: 0,
    };

    let id = cache.upsert_active_storm(&base_event).unwrap();
    assert!(id > 0);
    cache
        .increment_storm_bounces("did:plc:alice", Some(&base_event.focal_post_uri), 3)
        .unwrap();
    cache
        .mark_storm_threadgate_applied("did:plc:alice", &base_event.focal_post_uri, true)
        .unwrap();
    cache
        .increment_storm_postgate_detaches("did:plc:alice", &base_event.focal_post_uri, 2)
        .unwrap();

    // Updating the active storm preserves cumulative counters & threadgate flag
    let mut escalated = base_event.clone();
    escalated.severity = StormSeverity::Critical;
    escalated.updated_at_us = 200_000;
    escalated.metrics.composite_score = 0.93;
    let id2 = cache.upsert_active_storm(&escalated).unwrap();
    assert_eq!(id, id2);

    let fetched = cache.get_storm(id).unwrap().unwrap();
    assert_eq!(fetched.severity, StormSeverity::Critical);
    assert_eq!(fetched.bounces_during_storm, 3);
    assert!(fetched.threadgate_applied);
    assert_eq!(fetched.postgate_detaches_applied, 2);

    let active = cache
        .get_active_storm_by_focal_uri("did:plc:alice", &base_event.focal_post_uri)
        .unwrap()
        .unwrap();
    assert_eq!(active.id, id);

    let latest = cache
        .get_latest_active_storm_for("did:plc:alice")
        .unwrap()
        .unwrap();
    assert_eq!(latest.id, id);

    assert!(cache
        .update_storm_status(
            Some("did:plc:alice"),
            id,
            StormStatus::Dismissed,
            Some(300_000),
        )
        .unwrap());
    assert!(cache
        .list_storms(Some("did:plc:alice"), true, 10)
        .unwrap()
        .is_empty());
    assert_eq!(
        cache
            .list_storms(Some("did:plc:alice"), false, 10)
            .unwrap()
            .len(),
        1
    );

    // Unscoped list_storms(None, ...) + fallback increment_storm_bounces(did, None, ...)
    let second_id = cache
        .upsert_active_storm(&StormEvent {
            focal_post_uri: "at://did:plc:bob/app.bsky.feed.post/3kbob".to_string(),
            target_did: "did:plc:bob".to_string(),
            ..base_event.clone()
        })
        .unwrap();
    cache
        .increment_storm_bounces("did:plc:bob", None, 2)
        .unwrap();
    assert_eq!(
        cache
            .get_storm(second_id)
            .unwrap()
            .unwrap()
            .bounces_during_storm,
        2
    );
    assert_eq!(cache.list_storms(None, true, 10).unwrap().len(), 1);
    assert_eq!(cache.list_storms(None, false, 10).unwrap().len(), 2);
    assert!(cache
        .update_storm_status(None, second_id, StormStatus::Resolved, Some(400_000))
        .unwrap());
    assert!(cache.list_storms(None, true, 10).unwrap().is_empty());
}

#[tokio::test]
async fn test_engine_dogpile_pipeline_storm_mode_digests_headroom_and_benign_suppression() {
    let pds = GateMockPds::start().await;
    let enricher = Arc::new(MockContextEnricher::new());
    let target_did = "did:plc:alice";
    let focal_uri = "at://did:plc:alice/app.bsky.feed.post/3kfocal";
    let qt_uri = "at://did:plc:catalyst/app.bsky.feed.post/3kcatqt";
    let benign_uri = "at://did:plc:alice/app.bsky.feed.post/3kbenign";

    enricher.set_target(
        target_did,
        AuthorContext {
            handle: Some("alice.bsky.social".to_string()),
            followers_count: Some(120),
            ..Default::default()
        },
    );
    enricher.set_post_engagement(PostEngagementSnapshot {
        uri: focal_uri.to_string(),
        author_did: target_did.to_string(),
        author_handle: Some("alice.bsky.social".to_string()),
        author_followers: Some(120),
        text: "Original target post".to_string(),
        reply_count: 60,
        quote_count: 15,
        like_count: 5,
        repost_count: 1,
    });
    enricher.set_post_engagement(PostEngagementSnapshot {
        uri: qt_uri.to_string(),
        author_did: "did:plc:catalyst".to_string(),
        author_handle: Some("bigdunk.bsky.social".to_string()),
        author_followers: Some(40_000),
        text: "Look at this bozo".to_string(),
        reply_count: 35,
        quote_count: 10,
        like_count: 900,
        repost_count: 120,
    });
    enricher.set_post_engagement(PostEngagementSnapshot {
        uri: benign_uri.to_string(),
        author_did: target_did.to_string(),
        author_handle: Some("alice.bsky.social".to_string()),
        author_followers: Some(120),
        text: "Look at this wholesome puppy".to_string(),
        reply_count: 40,
        quote_count: 5,
        like_count: 2_500,
        repost_count: 400,
    });

    let dogpile_cfg = DogpileConfig::default()
        .with_min_unique_authors(4)
        .with_min_out_of_network_ratio(0.75)
        .with_defensive_block_burst(2)
        .with_defensive_detach_burst(2)
        .with_structural_trigger_score(0.35)
        .with_confirmed_score_threshold(0.65)
        .with_structural_fallback_threshold(0.70);

    let stance = MockStormStanceClassifier::new(StormStanceVerdict::new(
        true,
        0.92,
        "dogpile",
        "Coordinated hostile quote-dunk swarm",
        "mock-stance",
    ));

    // Base hourly evaluation budget = 2 -> Storm Mode 3x headroom allows 6 evaluations!
    let engine = build_test_engine(target_did, &pds, enricher, stance, dogpile_cfg, 2, false);
    let mut storm_rx = engine.subscribe_storm_alerts();
    let mut bounce_rx = engine.subscribe_bounces();
    let mut digest_rx = engine.subscribe_storm_digests();

    let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(64);
    let cancel = tokio_util::sync::CancellationToken::new();
    let run_eng = Arc::clone(&engine);
    let run_cancel = cancel.clone();
    let runner = tokio::spawn(async move { run_eng.run(commit_rx, run_cancel).await });

    // 1. Feed 1 catalyst quote post + 3 OON replies with fresh current timestamps
    let now_us = current_time_us();
    let mut quote_commit = make_quote_commit(
        "did:plc:catalyst",
        target_did,
        "3kcatqt",
        "3kfocal",
        "Dunking!",
    );
    quote_commit.time_us = now_us;
    commit_tx.send(quote_commit).await.unwrap();

    for idx in 1..=3 {
        let mut reply = make_reply_commit(
            &format!("did:plc:oon{idx}"),
            target_did,
            &format!("3krep{idx}"),
            "3kfocal",
            "Ratio + pile-on",
        );
        reply.time_us = now_us + idx;
        commit_tx.send(reply).await.unwrap();
    }

    // 2. Also stream target's defensive distress signals (block + postgate commits + duplicate update)
    let block_commit_1 = JetstreamCommit {
        did: target_did.to_string(),
        time_us: current_time_us(),
        collection: "app.bsky.graph.block".to_string(),
        rkey: "blk1".to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyblk1".to_string()),
        record: Some(json!({ "subject": "did:plc:troll99" })),
    };
    let block_commit_2 = JetstreamCommit {
        rkey: "blk2".to_string(),
        ..block_commit_1.clone()
    };
    let postgate_commit = JetstreamCommit {
        did: target_did.to_string(),
        time_us: current_time_us(),
        collection: "app.bsky.feed.postgate".to_string(),
        rkey: "3kfocal".to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafypg1".to_string()),
        record: Some(json!({
            "post": focal_uri,
            "detachedEmbeddingUris": [qt_uri, "at://did:plc:other/app.bsky.feed.post/q2"]
        })),
    };
    let postgate_dup = JetstreamCommit {
        operation: CommitOperation::Update,
        ..postgate_commit.clone()
    };

    for c in [
        block_commit_1,
        block_commit_2,
        postgate_commit,
        postgate_dup,
    ] {
        commit_tx.send(c).await.unwrap();
    }

    // Drop sender so engine.run drains both evaluation and storm workers cleanly
    drop(commit_tx);
    runner
        .await
        .expect("engine runner join")
        .expect("engine run ok");

    let storm_notif = tokio::time::timeout(Duration::from_secs(2), storm_rx.recv())
        .await
        .expect("storm alert recv timeout")
        .expect("storm alert present");
    assert_eq!(storm_notif.storm.focal_post_uri, focal_uri);
    assert_eq!(
        storm_notif.storm.top_catalyst.as_ref().unwrap().post_uri,
        qt_uri
    );
    assert!(engine.is_storm_mode_active(target_did));
    assert_eq!(engine.stats().snapshot().dogpiles_detected, 1);
    assert!(engine.stats().snapshot().storm_alerts_emitted >= 1);
    assert!(engine.stats().snapshot().defensive_signals_observed >= 3);

    // Drain any pre-Storm-Mode individual bounce alerts emitted before storm_worker finished
    while bounce_rx.try_recv().is_ok() {}

    // Now test 3x rate-limit headroom (base=2 -> effective=6). Send OON replies until 3x ceiling hits
    let mut outcomes = Vec::new();
    for idx in 4..=8 {
        let mut reply = make_reply_commit(
            &format!("did:plc:oon{idx}"),
            target_did,
            &format!("3krep{idx}"),
            "3kfocal",
            "More pile-on",
        );
        reply.time_us = current_time_us();
        if let skybouncer::engine::ProcessCommitResult::InteractionsProcessed(mut res) =
            engine.process_commit(&reply).await.unwrap()
        {
            outcomes.append(&mut res);
        }
    }
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, skybouncer::engine::InteractionOutcome::Bounced { .. })),
        "At least one bounce must succeed during Storm Mode (3x headroom)"
    );
    assert!(outcomes.iter().any(|o| matches!(
        o,
        skybouncer::engine::InteractionOutcome::RateLimited { .. }
    )));
    assert!(
        bounce_rx.try_recv().is_err(),
        "Individual bounce DMs must be suppressed while Storm Mode is active"
    );

    // Exiting Storm Mode & flushing emits the StormDigestNotification
    engine.set_storm_mode(target_did, false);
    let digest = digest_rx
        .try_recv()
        .expect("digest should flush on deactivation");
    assert!(digest.bounced_count >= 1);
    assert!(!digest.storm_still_active);
    assert!(engine.stats().snapshot().storm_bounces_digested >= 1);

    // 3. Test benign viral post suppression (structural low direct_ratio + non-hostile verdict)
    let pds_benign = GateMockPds::start().await;
    let enricher_benign = Arc::new(MockContextEnricher::new());
    enricher_benign.set_post_engagement(PostEngagementSnapshot {
        uri: benign_uri.to_string(),
        author_did: target_did.to_string(),
        author_handle: Some("alice.bsky.social".to_string()),
        author_followers: Some(120),
        text: "Look at this wholesome puppy".to_string(),
        reply_count: 10,
        quote_count: 2,
        like_count: 5_000,
        repost_count: 800,
    });
    let benign_engine = build_test_engine(
        target_did,
        &pds_benign,
        enricher_benign,
        MockStormStanceClassifier::new(StormStanceVerdict::new(
            false,
            0.95,
            "benign_viral",
            "Cheerful replies about a cute puppy",
            "mock-stance",
        )),
        DogpileConfig::default()
            .with_min_unique_authors(4)
            .with_confirmed_score_threshold(0.65),
        100,
        false,
    );
    let suppressed = benign_engine
        .evaluate_storm_candidate(SurgeCandidate {
            target_did: target_did.to_string(),
            focal_post_uri: benign_uri.to_string(),
            observed_at_us: current_time_us(),
            initial_metrics: StormMetrics {
                unique_authors_short: 25,
                unique_oon_authors_short: 22,
                out_of_network_ratio: 0.88,
                structural_score: 0.45,
                ..Default::default()
            },
            sample_replies: vec![],
            recent_quote_uris: vec![],
        })
        .await
        .unwrap();
    assert!(suppressed.is_none());
    assert!(benign_engine
        .list_storms_for(Some(target_did), false, 10)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_engine_threadgate_and_postgate_live_and_dry_run() {
    let pds = GateMockPds::start().await;
    let enricher = Arc::new(MockContextEnricher::new());
    let alice = "did:plc:alice";
    enricher.set_handle("alice.bsky.social", alice);

    let focal_uri = "at://did:plc:alice/app.bsky.feed.post/3klock";
    let stored_qt = "at://did:plc:dunk/app.bsky.feed.post/3kqt1";
    let manual_qt = "at://did:plc:dunk2/app.bsky.feed.post/3kqt2";

    let live_engine = build_test_engine(
        alice,
        &pds,
        Arc::clone(&enricher),
        MockStormStanceClassifier::new(StormStanceVerdict::new(
            true, 0.9, "dogpile", "hostile", "mock",
        )),
        DogpileConfig::default(),
        100,
        false,
    );

    // Seed an active storm so detach_quotes with qt_uris=None pulls stored_qt
    live_engine
        .cache()
        .upsert_active_storm(&StormEvent {
            id: 0,
            target_did: alice.to_string(),
            target_handle: Some("alice.bsky.social".to_string()),
            focal_post_uri: focal_uri.to_string(),
            focal_post_snippet: "Locked post".to_string(),
            status: StormStatus::Active,
            severity: StormSeverity::High,
            started_at_us: 1000,
            updated_at_us: 1000,
            resolved_at_us: None,
            metrics: StormMetrics::default(),
            top_catalyst: None,
            catalyst_qt_uris: vec![stored_qt.to_string()],
            stance: None,
            bounces_during_storm: 0,
            threadgate_applied: false,
            postgate_detaches_applied: 0,
        })
        .unwrap();

    // Lock using Bluesky @handle web URL -> verifies handle resolution + putRecord
    let (tg_uri, post_uri) = live_engine
        .lock_thread(
            alice,
            "https://bsky.app/profile/alice.bsky.social/post/3klock",
            ThreadgatePolicy::FollowingOnly,
        )
        .await
        .unwrap();
    assert_eq!(post_uri, focal_uri);
    assert_eq!(tg_uri, "at://did:plc:alice/app.bsky.feed.threadgate/3klock");
    assert!(live_engine.list_storms_for(Some(alice), true, 5).unwrap()[0].threadgate_applied);

    // Detach stored catalyst QT, then merge a second explicit QT, preserving stored_qt
    let (pg_uri, _, count1) = live_engine
        .detach_quotes(alice, "3klock", None, false)
        .await
        .unwrap();
    assert_eq!(pg_uri, "at://did:plc:alice/app.bsky.feed.postgate/3klock");
    assert_eq!(count1, 1);

    let (_, _, count2) = live_engine
        .detach_quotes(alice, focal_uri, Some(&[manual_qt.to_string()]), true)
        .await
        .unwrap();
    assert_eq!(count2, 2);

    let pg_record = pds
        .stored_records
        .lock()
        .get(&(
            alice.to_string(),
            "app.bsky.feed.postgate".to_string(),
            "3klock".to_string(),
        ))
        .unwrap()
        .clone();
    let detached_arr = pg_record["detachedEmbeddingUris"].as_array().unwrap();
    assert_eq!(detached_arr.len(), 2);
    assert!(!pg_record["embeddingRules"].as_array().unwrap().is_empty());

    // Unlock deletes the threadgate record
    let unlocked = live_engine.unlock_thread(alice, "3klock").await.unwrap();
    assert_eq!(unlocked, focal_uri);
    assert!(!live_engine.list_storms_for(Some(alice), true, 5).unwrap()[0].threadgate_applied);

    // Ownership violation rejected
    assert!(live_engine
        .lock_thread(
            alice,
            "at://did:plc:bob/app.bsky.feed.post/other",
            ThreadgatePolicy::Nobody,
        )
        .await
        .is_err());

    // Dry-run engine performs zero PDS writes
    let dry_pds = GateMockPds::start().await;
    let dry_engine = build_test_engine(
        alice,
        &dry_pds,
        enricher,
        MockStormStanceClassifier::new(StormStanceVerdict::new(
            true, 0.9, "dogpile", "hostile", "mock",
        )),
        DogpileConfig::default(),
        100,
        true,
    );
    let _ = dry_engine
        .lock_thread(alice, "3kdry", ThreadgatePolicy::Nobody)
        .await
        .unwrap();
    let _ = dry_engine.unlock_thread(alice, "3kdry").await.unwrap();
    let _ = dry_engine
        .detach_quotes(alice, "3kdry", Some(&[stored_qt.to_string()]), false)
        .await
        .unwrap();
    assert!(dry_pds.write_ops.lock().is_empty());

    // Resolved/Dismissed storm fallback lookup in detach_quotes, multi-QT sort + expired storm maintenance,
    // and failing PDS error counter tracking
    live_engine
        .cache()
        .upsert_active_storm(&StormEvent {
            id: 0,
            target_did: alice.to_string(),
            target_handle: None,
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3kdiss".to_string(),
            focal_post_snippet: "old".to_string(),
            status: StormStatus::Active,
            severity: StormSeverity::Elevated,
            started_at_us: 50,
            updated_at_us: 50,
            resolved_at_us: None,
            metrics: StormMetrics::default(),
            top_catalyst: None,
            catalyst_qt_uris: vec![stored_qt.to_string()],
            stance: None,
            bounces_during_storm: 0,
            threadgate_applied: false,
            postgate_detaches_applied: 0,
        })
        .unwrap();
    let diss_id = live_engine
        .cache()
        .get_active_storm_by_focal_uri(alice, "at://did:plc:alice/app.bsky.feed.post/3kdiss")
        .unwrap()
        .unwrap()
        .id;
    live_engine.dismiss_storm(Some(alice), diss_id).unwrap();
    let (_, _, diss_cnt) = live_engine
        .detach_quotes(alice, "3kdiss", None, false)
        .await
        .unwrap();
    assert_eq!(diss_cnt, 1);

    // Multi-QT sorting + TTL storm expiration in flush_storm_maintenance
    let sort_pds = GateMockPds::start().await;
    let sort_enricher = Arc::new(MockContextEnricher::new());
    sort_enricher.set_author(
        "did:plc:cat_big",
        AuthorContext {
            handle: Some("catbig.bsky.social".to_string()),
            followers_count: Some(80_000),
            ..Default::default()
        },
    );
    sort_enricher.set_post_engagement(PostEngagementSnapshot {
        uri: "at://did:plc:alice/app.bsky.feed.post/3ksort".to_string(),
        author_did: alice.to_string(),
        author_handle: None,
        author_followers: Some(100),
        text: "Sort post".to_string(),
        reply_count: 50,
        quote_count: 10,
        like_count: 5,
        repost_count: 1,
    });
    sort_enricher.set_post_engagement(PostEngagementSnapshot {
        uri: "at://did:plc:cat_small/app.bsky.feed.post/qlow".to_string(),
        author_did: "did:plc:cat_small".to_string(),
        author_handle: None,
        author_followers: Some(200),
        text: "small qt".to_string(),
        reply_count: 1,
        quote_count: 0,
        like_count: 10,
        repost_count: 1,
    });
    sort_enricher.set_post_engagement(PostEngagementSnapshot {
        uri: "at://did:plc:cat_big/app.bsky.feed.post/qhigh".to_string(),
        author_did: "did:plc:cat_big".to_string(),
        author_handle: None,
        author_followers: None,
        text: "big qt".to_string(),
        reply_count: 40,
        quote_count: 5,
        like_count: 1500,
        repost_count: 200,
    });
    let ttl_cfg = DogpileConfig {
        storm_mode_ttl: Duration::from_millis(1),
        ..Default::default()
    };
    let ttl_engine = build_test_engine(
        alice,
        &sort_pds,
        sort_enricher,
        MockStormStanceClassifier::new(StormStanceVerdict::new(
            true, 0.9, "dogpile", "hostile", "mock",
        )),
        ttl_cfg,
        100,
        false,
    );
    let old_ts = current_time_us().saturating_sub(5_000_000);
    let ev = ttl_engine
        .evaluate_storm_candidate(SurgeCandidate {
            target_did: alice.to_string(),
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3ksort".to_string(),
            observed_at_us: old_ts,
            initial_metrics: StormMetrics {
                unique_authors_short: 25,
                unique_oon_authors_short: 24,
                out_of_network_ratio: 0.96,
                structural_score: 0.7,
                ..Default::default()
            },
            sample_replies: vec![],
            recent_quote_uris: vec![
                "at://did:plc:cat_small/app.bsky.feed.post/qlow".to_string(),
                "at://did:plc:cat_big/app.bsky.feed.post/qhigh".to_string(),
            ],
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ev.top_catalyst.as_ref().unwrap().post_uri,
        "at://did:plc:cat_big/app.bsky.feed.post/qhigh"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
    ttl_engine.flush_storm_maintenance().unwrap();
    let after_flush = ttl_engine.cache().get_storm(ev.id).unwrap().unwrap();
    assert_eq!(after_flush.status, StormStatus::Resolved);

    // PDS failure paths increment errors_encountered on lock/unlock/detach
    let bad_pds_srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("pds err"))
        .mount(&bad_pds_srv)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string("pds err"))
        .mount(&bad_pds_srv)
        .await;
    let err_pds_client = PdsRepoClient::from_credentials(bad_pds_srv.uri(), alice, "tok")
        .unwrap()
        .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true));
    let cache_err = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let mut protected_set = HashSet::new();
    protected_set.insert(alice.to_string());
    let rubric_err = RuleRubric::new("rules", Sensitivity::Medium);
    let err_engine = SkybouncerEngineBuilder::new(SkybouncerConfig::new(protected_set, rubric_err))
        .with_cache(Arc::clone(&cache_err))
        .with_classifier(Arc::new(MockClassifier::new(Verdict::permitted("ok"))))
        .with_modlist_manager(Arc::new(ModListManager::from_shared_cache(cache_err)))
        .with_pds_client(Arc::new(err_pds_client))
        .build()
        .unwrap();
    assert!(err_engine
        .lock_thread(alice, "3err", ThreadgatePolicy::Nobody)
        .await
        .is_err());
    assert!(err_engine.unlock_thread(alice, "3err").await.is_err());
    assert!(err_engine
        .detach_quotes(alice, "3err", None, true)
        .await
        .is_err());
    assert!(err_engine.stats().snapshot().errors_encountered >= 3);
}

#[tokio::test]
async fn test_bot_storm_commands_and_authorization() {
    let pds = GateMockPds::start().await;
    let enricher = Arc::new(MockContextEnricher::new());
    let alice = "did:plc:alice";
    enricher.set_handle("catalyst.bsky.social", "did:plc:catalyst");
    let engine = build_test_engine(
        alice,
        &pds,
        enricher,
        MockStormStanceClassifier::new(StormStanceVerdict::new(
            true, 0.9, "dogpile", "hostile", "mock",
        )),
        DogpileConfig::default(),
        100,
        false,
    );

    let bot = BotCommandHandler::new(Arc::clone(&engine), "did:plc:bot");

    // Unauthorized sender gets onboarding prompt on storm commands
    let unauth = bot
        .handle_command("did:plc:stranger", "storms")
        .await
        .unwrap();
    assert!(unauth.contains("do not have an active bouncer session"));
    assert!(bot
        .handle_command("did:plc:stranger", "lock latest")
        .await
        .unwrap()
        .contains("active bouncer session"));

    // Help preserves required title and mentions new storm commands
    let help = bot.handle_command(alice, "help").await.unwrap();
    assert!(help.contains("Skybouncer Bot Commands:"));
    assert!(help.contains("storms"));
    assert!(help.contains("lock"));
    assert!(help.contains("detach"));

    // Initially no storms
    let empty_storms = bot.handle_command(alice, "storms").await.unwrap();
    assert!(empty_storms.contains("None detected right now"));

    // Manual Storm Mode toggle + status
    let mode_on = bot.handle_command(alice, "storm on").await.unwrap();
    assert!(mode_on.contains("Storm Mode ENABLED"));
    let status = bot.handle_command(alice, "status").await.unwrap();
    assert!(status.contains("Storm Mode: ⛈️ Active"));
    let mode_off = bot.handle_command(alice, "storm off").await.unwrap();
    assert!(mode_off.contains("Storm Mode DISABLED"));

    // Seed an active _mentions storm and ensure friendly lock refusal
    engine
        .cache()
        .upsert_active_storm(&StormEvent {
            id: 0,
            target_did: alice.to_string(),
            target_handle: None,
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/_mentions".to_string(),
            focal_post_snippet: String::new(),
            status: StormStatus::Active,
            severity: StormSeverity::Elevated,
            started_at_us: 10,
            updated_at_us: 10,
            resolved_at_us: None,
            metrics: StormMetrics::default(),
            top_catalyst: None,
            catalyst_qt_uris: vec![],
            stance: None,
            bounces_during_storm: 0,
            threadgate_applied: false,
            postgate_detaches_applied: 0,
        })
        .unwrap();
    let mentions_lock = bot.handle_command(alice, "lock").await.unwrap();
    assert!(mentions_lock.contains("@mentions surge"));

    // Seed a concrete active storm later in time -> latest points to it
    engine
        .cache()
        .upsert_active_storm(&StormEvent {
            id: 0,
            target_did: alice.to_string(),
            target_handle: Some("alice.bsky.social".to_string()),
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3kbottest".to_string(),
            focal_post_snippet: "Hello Bluesky".to_string(),
            status: StormStatus::Active,
            severity: StormSeverity::High,
            started_at_us: 200,
            updated_at_us: 200,
            resolved_at_us: None,
            metrics: StormMetrics {
                unique_oon_authors_short: 21,
                out_of_network_ratio: 0.91,
                composite_score: 0.85,
                ..Default::default()
            },
            top_catalyst: None,
            catalyst_qt_uris: vec!["at://did:plc:catalyst/app.bsky.feed.post/3kqtb".to_string()],
            stance: None,
            bounces_during_storm: 4,
            threadgate_applied: false,
            postgate_detaches_applied: 0,
        })
        .unwrap();

    let listed = bot.handle_command(alice, "storms").await.unwrap();
    assert!(listed.contains("Active Dogpile Storms"));
    assert!(listed.contains("Hello Bluesky"));

    assert!(bot
        .handle_command(alice, "lock 3kbottest invalidpolicy")
        .await
        .unwrap()
        .contains("Invalid lock policy"));

    let locked = bot.handle_command(alice, "lock nobody").await.unwrap();
    assert!(locked.contains("Thread replies locked"));

    let detached = bot
        .handle_command(
            alice,
            "detach latest https://bsky.app/profile/catalyst.bsky.social/post/3kqt_url",
        )
        .await
        .unwrap();
    assert!(detached.contains("postgate"));

    let detached_all = bot.handle_command(alice, "detach all").await.unwrap();
    assert!(detached_all.contains("disabled all future quote-posts"));

    let unlocked = bot.handle_command(alice, "unlock latest").await.unwrap();
    assert!(unlocked.contains("Thread replies unlocked"));

    // Error/usage/unauthorized branches across storm bot commands
    assert!(bot
        .handle_command("did:plc:stranger", "storm on")
        .await
        .unwrap()
        .contains("active bouncer session"));
    assert!(bot
        .handle_command("did:plc:stranger", "unlock")
        .await
        .unwrap()
        .contains("active bouncer session"));
    assert!(bot
        .handle_command("did:plc:stranger", "detach")
        .await
        .unwrap()
        .contains("active bouncer session"));
    assert!(bot
        .handle_command(
            alice,
            "lock https://bsky.app/profile/did:plc:bobbbbbbbbbbbbbbbbbbbbbb/post/3other"
        )
        .await
        .unwrap()
        .contains("Failed to lock"));
    assert!(bot
        .handle_command(
            alice,
            "unlock https://bsky.app/profile/did:plc:bobbbbbbbbbbbbbbbbbbbbbb/post/3other"
        )
        .await
        .unwrap()
        .contains("Failed to unlock"));
    assert!(bot
        .handle_command(alice, "detach 3kbottest not-a-url")
        .await
        .unwrap()
        .contains("Expected an `at://`"));
    assert!(bot
        .handle_command(alice, "lock followers")
        .await
        .unwrap()
        .contains("Thread replies locked"));
    assert!(bot
        .handle_command(alice, "lock mentions")
        .await
        .unwrap()
        .contains("Thread replies locked"));

    // Dry-run lock/unlock/detach messages + fleet admin status output
    let admin_status = bot.handle_command(alice, "status").await.unwrap();
    assert!(admin_status.contains("Admin Fleet View"));
    assert!(admin_status.contains("Dogpiles Detected"));
}

#[tokio::test]
async fn test_web_api_storms_endpoints_auth_prometheus_and_cli() {
    let pds = GateMockPds::start().await;
    let enricher = Arc::new(MockContextEnricher::new());
    let alice = "did:plc:alice";
    let bob = "did:plc:bob";

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block harassment", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let mut protected = HashSet::new();
    protected.insert(alice.to_string());
    protected.insert(bob.to_string());

    // alice is admin, bob is regular tenant
    let cfg = SkybouncerConfig::new(protected, rubric).with_admin_did(alice);
    let engine = Arc::new(
        SkybouncerEngineBuilder::new(cfg)
            .with_cache(cache)
            .with_follow_graph(follow_graph)
            .with_gate(gate)
            .with_classifier(Arc::new(MockClassifier::new(Verdict::permitted("ok"))))
            .with_modlist_manager(modlist_manager)
            .with_pds_client(Arc::new(pds.client(alice)))
            .with_enricher(enricher)
            .build()
            .unwrap(),
    );

    // Give bob a dummy tenant record so resolve_pds_client_for can build a client or fail cleanly without missing tenant
    let _ = engine
        .tenant_registry()
        .register_or_update(&skybouncer::Tenant::new(alice).with_handle("alice.bsky.social"));
    let _ = engine
        .tenant_registry()
        .register_or_update(&skybouncer::Tenant::new(bob).with_handle("bob.bsky.social"));

    let alice_storm_id = engine
        .cache()
        .upsert_active_storm(&StormEvent {
            id: 0,
            target_did: alice.to_string(),
            target_handle: Some("alice.bsky.social".to_string()),
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3kapialice".to_string(),
            focal_post_snippet: "Alice focal".to_string(),
            status: StormStatus::Active,
            severity: StormSeverity::High,
            started_at_us: 100,
            updated_at_us: 100,
            resolved_at_us: None,
            metrics: StormMetrics::default(),
            top_catalyst: None,
            catalyst_qt_uris: vec!["at://did:plc:q/app.bsky.feed.post/q1".to_string()],
            stance: None,
            bounces_during_storm: 2,
            threadgate_applied: false,
            postgate_detaches_applied: 0,
        })
        .unwrap();

    let bob_storm_id = engine
        .cache()
        .upsert_active_storm(&StormEvent {
            id: 0,
            target_did: bob.to_string(),
            target_handle: Some("bob.bsky.social".to_string()),
            focal_post_uri: "at://did:plc:bob/app.bsky.feed.post/3kapibob".to_string(),
            focal_post_snippet: "Bob focal".to_string(),
            status: StormStatus::Active,
            severity: StormSeverity::Elevated,
            started_at_us: 200,
            updated_at_us: 200,
            resolved_at_us: None,
            metrics: StormMetrics::default(),
            top_catalyst: None,
            catalyst_qt_uris: vec![],
            stance: None,
            bounces_during_storm: 0,
            threadgate_applied: false,
            postgate_detaches_applied: 0,
        })
        .unwrap();

    let alice_tok = engine
        .tenant_registry()
        .create_web_session(alice, Duration::from_secs(3600))
        .unwrap();
    let bob_tok = engine
        .tenant_registry()
        .create_web_session(bob, Duration::from_secs(3600))
        .unwrap();

    let metadata = OAuthClientMetadata::new(
        "http://127.0.0.1:3000/oauth/client-metadata.json",
        "http://127.0.0.1:3000/oauth/callback",
    );
    let app = create_web_router(Arc::clone(&engine), None, metadata);

    // 1. Unauthenticated access rejected with 401
    let unauth_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/storms")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);

    // 2. Non-admin Bob cannot read or mutate Alice's storms (403)
    let bob_snoop = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/storms?user_did={alice}"))
                .header(header::AUTHORIZATION, format!("Bearer {bob_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_snoop.status(), StatusCode::FORBIDDEN);

    let bob_dismiss_alice = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/dismiss")
                .header(header::AUTHORIZATION, format!("Bearer {bob_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "storm_id": alice_storm_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_dismiss_alice.status(), StatusCode::FORBIDDEN);

    let bob_lock_alice = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/lock")
                .header(header::AUTHORIZATION, format!("Bearer {bob_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "post_uri": "3kapialice",
                        "protected_did": alice
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_lock_alice.status(), StatusCode::FORBIDDEN);

    // 3. Valid GET /api/storms scoped to Bob returns only Bob's storm
    let bob_storms_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/storms")
                .header(header::AUTHORIZATION, format!("Bearer {bob_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_storms_res.status(), StatusCode::OK);
    let bob_bytes = axum::body::to_bytes(bob_storms_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let bob_parsed: StormsResponse = serde_json::from_slice(&bob_bytes).unwrap();
    assert_eq!(bob_parsed.storms.len(), 1);
    assert_eq!(bob_parsed.storms[0].id, bob_storm_id);

    // 4. Alice toggles Storm Mode, locks, detaches, unlocks, and dismisses
    let mode_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/mode")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "enabled": true })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mode_res.status(), StatusCode::OK);
    let mode_body: StormModeResponse = serde_json::from_slice(
        &axum::body::to_bytes(mode_res.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(mode_body.storm_mode_active);

    let lock_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/lock")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "post_uri": "at://did:plc:alice/app.bsky.feed.post/3kapialice",
                        "policy": "following"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lock_res.status(), StatusCode::OK);
    let lock_body: ShieldActionResponse = serde_json::from_slice(
        &axum::body::to_bytes(lock_res.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(lock_body.action, "lock");
    assert!(lock_body.record_uri.is_some());

    let detach_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/detach")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "post_uri": "3kapialice",
                        "disable_all_quotes": false
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detach_res.status(), StatusCode::OK);
    let detach_body: ShieldActionResponse = serde_json::from_slice(
        &axum::body::to_bytes(detach_res.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(detach_body.detached_count, Some(1));

    let unlock_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/unlock")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "post_uri": "3kapialice" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlock_res.status(), StatusCode::OK);

    let dismiss_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/dismiss")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "storm_id": alice_storm_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dismiss_res.status(), StatusCode::OK);
    let dismiss_body: DismissStormResponse = serde_json::from_slice(
        &axum::body::to_bytes(dismiss_res.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(dismiss_body.dismissed);

    // 5. Validation errors return 400
    let bad_lock = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/lock")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "post_uri": "3kapialice",
                        "policy": "bogus"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_lock.status(), StatusCode::BAD_REQUEST);

    let bad_dismiss = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/dismiss")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "storm_id": 0 })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_dismiss.status(), StatusCode::BAD_REQUEST);

    // 5b. Additional auth & validation branches across /api/storms*
    for (uri_path, payload) in [
        ("/api/storms/mode", json!({ "enabled": true })),
        ("/api/storms/dismiss", json!({ "storm_id": alice_storm_id })),
        ("/api/storms/lock", json!({ "post_uri": "3x" })),
        ("/api/storms/unlock", json!({ "post_uri": "3x" })),
        (
            "/api/storms/detach",
            json!({ "post_uri": "3x", "disable_all_quotes": true }),
        ),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri_path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "401 on {uri_path}");
    }

    for (uri_path, payload) in [
        (
            "/api/storms/mode",
            json!({ "enabled": true, "target_did": alice }),
        ),
        (
            "/api/storms/unlock",
            json!({ "post_uri": "3x", "protected_did": alice }),
        ),
        (
            "/api/storms/detach",
            json!({ "post_uri": "3x", "protected_did": alice, "disable_all_quotes": true }),
        ),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri_path)
                    .header(header::AUTHORIZATION, format!("Bearer {bob_tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "403 on {uri_path}");
    }

    for (uri_path, payload) in [
        ("/api/storms/lock", json!({ "post_uri": "   " })),
        ("/api/storms/unlock", json!({ "post_uri": "" })),
        ("/api/storms/detach", json!({ "post_uri": "   " })),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri_path)
                    .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "400 on {uri_path}");
    }

    // Admin querying fleet-wide + active_only, and non-existent storm dismiss -> dismissed=false
    let fleet_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/storms?active_only=true&limit=10")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fleet_res.status(), StatusCode::OK);

    let missing_dismiss = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/dismiss")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "storm_id": 999_999 })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_dismiss.status(), StatusCode::OK);
    let missing_body: DismissStormResponse = serde_json::from_slice(
        &axum::body::to_bytes(missing_dismiss.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!missing_body.dismissed);

    // Detach with nonexistent catalysts -> 400 BAD_REQUEST
    let no_qt_detach = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/storms/detach")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "post_uri": "3unknownpost",
                        "disable_all_quotes": false
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_qt_detach.status(), StatusCode::BAD_REQUEST);

    // 6. Prometheus metrics & Dashboard HTML & CLI summary telemetry
    let metrics_res = app
        .oneshot(
            Request::builder()
                .uri("/api/metrics")
                .header(header::AUTHORIZATION, format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metrics_res.status(), StatusCode::OK);
    let metrics_text = String::from_utf8(
        axum::body::to_bytes(metrics_res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    for counter_name in [
        "skybouncer_dogpiles_detected_total",
        "skybouncer_storm_alerts_emitted_total",
        "skybouncer_storm_bounces_digested_total",
        "skybouncer_defensive_signals_observed_total",
        "skybouncer_threadgates_applied_total",
        "skybouncer_postgate_detaches_applied_total",
    ] {
        assert!(
            metrics_text.contains(counter_name),
            "missing {counter_name}"
        );
    }

    assert!(DASHBOARD_HTML.contains("active-storm-banner"));
    assert!(DASHBOARD_HTML.contains("storms-card"));
    assert!(DASHBOARD_HTML.contains("loadStorms"));

    let summary = format_final_telemetry(&EngineStatsSnapshot {
        dogpiles_detected: 2,
        storm_alerts_emitted: 3,
        storm_bounces_digested: 14,
        ..Default::default()
    });
    assert!(summary.contains("Dogpiles Detected:            2"));
    assert!(summary.contains("Storm Alerts Emitted:         3"));
    assert!(summary.contains("Storm Bounces Digested:       14"));
}

#[tokio::test]
async fn test_pr2_dogpile_lifecycle_rehydration_high_water_and_dedup() {
    use skybouncer::time::monotonic_time_us;

    let alice = "did:plc:alice";
    let focal_active = "at://did:plc:alice/app.bsky.feed.post/3kactive";
    let focal_expired = "at://did:plc:alice/app.bsky.feed.post/3kexpired";
    let pds = GateMockPds::start().await;

    // 1. Seed shared cache with one expired 'active' storm row and one fresh 'active' storm row
    let shared_cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let now_mono = monotonic_time_us();

    let expired_ev = StormEvent {
        id: 0,
        target_did: alice.to_string(),
        target_handle: None,
        focal_post_uri: focal_expired.to_string(),
        focal_post_snippet: "old post".to_string(),
        status: StormStatus::Active,
        severity: StormSeverity::High,
        started_at_us: now_mono.saturating_sub(3_600_000_000),
        updated_at_us: now_mono.saturating_sub(3_600_000_000),
        resolved_at_us: None,
        metrics: StormMetrics::default(),
        top_catalyst: None,
        catalyst_qt_uris: vec![],
        stance: None,
        bounces_during_storm: 2,
        threadgate_applied: false,
        postgate_detaches_applied: 0,
    };
    let (exp_id, inserted) = shared_cache
        .upsert_active_storm_with_status(&expired_ev)
        .unwrap();
    assert!(inserted);

    let fresh_ev = StormEvent {
        id: 0,
        target_did: alice.to_string(),
        target_handle: None,
        focal_post_uri: focal_active.to_string(),
        focal_post_snippet: "hot post".to_string(),
        status: StormStatus::Active,
        severity: StormSeverity::Critical,
        started_at_us: now_mono.saturating_sub(5_000_000),
        updated_at_us: now_mono,
        resolved_at_us: None,
        metrics: StormMetrics {
            composite_score: 0.91,
            ..Default::default()
        },
        top_catalyst: None,
        catalyst_qt_uris: vec![],
        stance: None,
        bounces_during_storm: 4,
        threadgate_applied: false,
        postgate_detaches_applied: 0,
    };
    let (fresh_id, inserted2) = shared_cache
        .upsert_active_storm_with_status(&fresh_ev)
        .unwrap();
    assert!(inserted2);

    // High-water severity check: upserting Elevated over Critical preserves Critical
    let lower_sev = StormEvent {
        severity: StormSeverity::Elevated,
        metrics: StormMetrics {
            composite_score: 0.40,
            ..Default::default()
        },
        ..fresh_ev.clone()
    };
    let (same_id, inserted3) = shared_cache
        .upsert_active_storm_with_status(&lower_sev)
        .unwrap();
    assert!(!inserted3);
    assert_eq!(same_id, fresh_id);
    assert_eq!(
        shared_cache.get_storm(fresh_id).unwrap().unwrap().severity,
        StormSeverity::Critical
    );

    // 2. Startup reconciliation via SkybouncerEngineBuilder::build()
    let mut protected = HashSet::new();
    protected.insert(alice.to_string());
    let rubric = RuleRubric::new("rules", Sensitivity::Medium);
    let mut cfg = SkybouncerConfig::new(protected.clone(), rubric.clone())
        .with_dry_run(true)
        .with_dogpile_config(DogpileConfig {
            storm_mode_ttl: Duration::from_secs(600),
            ..Default::default()
        });
    cfg.pds_endpoint = Some(pds.server.uri());

    let engine_builder = SkybouncerEngineBuilder::new(cfg.clone())
        .with_cache(Arc::clone(&shared_cache))
        .with_classifier(Arc::new(MockClassifier::permitted()))
        .with_modlist_manager(Arc::new(ModListManager::from_shared_cache(Arc::clone(
            &shared_cache,
        ))))
        .with_pds_client(Arc::new(
            PdsRepoClient::from_credentials(pds.server.uri(), alice, "tok").unwrap(),
        ))
        .build()
        .unwrap();

    assert_eq!(
        shared_cache.get_storm(exp_id).unwrap().unwrap().status,
        StormStatus::Resolved,
        "expired SQLite active storm must be resolved on builder startup"
    );
    assert!(
        engine_builder.is_storm_mode_active(alice),
        "unexpired SQLite active storm must rehydrate into DogpileTracker on builder startup"
    );

    // 3. Startup reconciliation ALSO runs in SkybouncerEngine::new()
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let engine_new = skybouncer::SkybouncerEngine::new(
        cfg,
        follow_graph,
        gate,
        Arc::new(MockClassifier::permitted()),
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&shared_cache))),
        Arc::new(PdsRepoClient::from_credentials(pds.server.uri(), alice, "tok").unwrap()),
    )
    .unwrap();
    assert!(engine_new.is_storm_mode_active(alice));

    // 4. set_storm_mode(alice, false) resolves active SQLite storm rows immediately
    engine_builder.set_storm_mode(alice, false);
    assert!(!engine_builder.is_storm_mode_active(alice));
    assert_eq!(
        shared_cache.get_storm(fresh_id).unwrap().unwrap().status,
        StormStatus::Resolved
    );
    assert!(shared_cache
        .list_storms(Some(alice), true, 10)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_pr2_dogpile_concurrent_dedup_missing_focal_dunk_ratio_and_detach_count() {
    use async_trait::async_trait;
    use skybouncer::dogpile::{StormStanceClassifier, StormStanceInput};
    use skybouncer::time::monotonic_time_us;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SlowStance {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl StormStanceClassifier for SlowStance {
        async fn classify_storm(
            &self,
            _input: &StormStanceInput,
        ) -> Result<StormStanceVerdict, skybouncer::SkybouncerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(StormStanceVerdict::new(
                true,
                0.95,
                "dogpile",
                "hostile",
                "coordinated quote cascade",
            ))
        }
    }

    let alice = "did:plc:alice";
    let focal = "at://did:plc:alice/app.bsky.feed.post/3kmissing_focal";
    let qt_low = "at://did:plc:q1/app.bsky.feed.post/q1";
    let qt_high = "at://did:plc:q2/app.bsky.feed.post/q2";
    let pds = GateMockPds::start().await;

    // Deliberately omit focal post snapshot (focal_post == None) and provide 2 quote snaps
    let enricher = Arc::new(MockContextEnricher::new());
    enricher.set_post_engagement(PostEngagementSnapshot {
        uri: qt_low.to_string(),
        author_did: "did:plc:q1".to_string(),
        author_handle: None,
        author_followers: Some(200),
        text: "low dunk".to_string(),
        like_count: 50,
        repost_count: 10,
        reply_count: 0,
        quote_count: 0,
    });
    enricher.set_post_engagement(PostEngagementSnapshot {
        uri: qt_high.to_string(),
        author_did: "did:plc:q2".to_string(),
        author_handle: None,
        author_followers: Some(500),
        text: "huge dunk".to_string(),
        like_count: 400,
        repost_count: 50,
        reply_count: 0,
        quote_count: 0,
    });

    let stance_calls = Arc::new(AtomicUsize::new(0));
    let dogpile_cfg = DogpileConfig {
        storm_mode_ttl: Duration::from_secs(120),
        structural_trigger_score: 0.25,
        confirmed_score_threshold: 0.35,
        ..Default::default()
    };

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block harassment and spam", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let mut protected = HashSet::new();
    protected.insert(alice.to_string());
    let mut cfg = SkybouncerConfig::new(protected, rubric)
        .with_dry_run(false)
        .with_enable_heuristic_prefilter(false)
        .with_dogpile_config(dogpile_cfg)
        .with_admin_did(alice);
    cfg.pds_endpoint = Some(pds.server.uri());

    let engine = SkybouncerEngineBuilder::new(cfg)
        .with_cache(cache)
        .with_follow_graph(follow_graph)
        .with_gate(gate)
        .with_classifier(Arc::new(MockClassifier::permitted()))
        .with_modlist_manager(modlist_manager)
        .with_pds_client(Arc::new(pds.client(alice)))
        .with_enricher(enricher)
        .with_storm_stance_classifier(Arc::new(SlowStance {
            calls: Arc::clone(&stance_calls),
        }))
        .build()
        .unwrap();

    let candidate = SurgeCandidate {
        target_did: alice.to_string(),
        focal_post_uri: focal.to_string(),
        observed_at_us: monotonic_time_us(),
        initial_metrics: StormMetrics {
            burst_z_score: 6.0,
            direct_ratio: 2.0,
            unique_authors_short: 40,
            unique_oon_authors_short: 38,
            out_of_network_ratio: 0.95,
            structural_score: 0.90,
            ..Default::default()
        },
        sample_replies: vec![],
        recent_quote_uris: vec![qt_low.to_string(), qt_high.to_string()],
    };

    // Concurrent Stage 2/3 evaluation dedup: second caller gets Ok(None) while first runs
    let (r1, r2) = tokio::join!(
        engine.evaluate_storm_candidate(candidate.clone()),
        engine.evaluate_storm_candidate(candidate)
    );
    let ev1 = r1.unwrap();
    let ev2 = r2.unwrap();
    let winners: Vec<StormEvent> = [ev1, ev2].into_iter().flatten().collect();
    assert_eq!(winners.len(), 1, "concurrent evaluations must deduplicate");
    assert_eq!(stance_calls.load(Ordering::SeqCst), 1);
    // Missing focal_post must NOT synthesize dunk_ratio (must remain 0.0)
    assert!(winners[0].metrics.dunk_ratio.abs() < f64::EPSILON);

    // detach_quotes returns total detached count (2), while stats & SQLite postgate_detaches_applied
    // increment ONLY by newly added detaches (2 first time, +0 on duplicate)!
    let (_, _, total_1) = engine
        .detach_quotes(
            alice,
            focal,
            Some(&[qt_low.to_string(), qt_high.to_string()]),
            false,
        )
        .await
        .unwrap();
    assert_eq!(total_1, 2);
    assert_eq!(engine.stats().snapshot().postgate_detaches_applied, 2);
    assert_eq!(
        engine
            .cache()
            .get_storm(winners[0].id)
            .unwrap()
            .unwrap()
            .postgate_detaches_applied,
        2
    );
    let (_, _, total_2) = engine
        .detach_quotes(
            alice,
            focal,
            Some(&[qt_low.to_string(), qt_high.to_string()]),
            false,
        )
        .await
        .unwrap();
    assert_eq!(total_2, 2);
    assert_eq!(engine.stats().snapshot().postgate_detaches_applied, 2);
    assert_eq!(
        engine
            .cache()
            .get_storm(winners[0].id)
            .unwrap()
            .unwrap()
            .postgate_detaches_applied,
        2
    );
}

#[tokio::test]
async fn test_pr2_dogpile_stale_commit_clock_and_heuristic_prefilter_recording() {
    use skybouncer::dogpile::MockStormStanceClassifier;
    use tokio_util::sync::CancellationToken;

    let alice = "did:plc:alice";
    let focal = "at://did:plc:alice/app.bsky.feed.post/3kstale";
    let pds = GateMockPds::start().await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(rubric.clone())
            .with_dry_run(true),
    );
    let mut protected = HashSet::new();
    protected.insert(alice.to_string());

    let dogpile_cfg = DogpileConfig::default()
        .with_min_unique_authors(3)
        .with_min_out_of_network_ratio(0.5)
        .with_structural_trigger_score(0.25)
        .with_confirmed_score_threshold(0.55);
    let mut cfg = SkybouncerConfig::new(protected, rubric)
        .with_dry_run(true)
        .with_enable_heuristic_prefilter(true)
        .with_dogpile_config(dogpile_cfg);
    cfg.pds_endpoint = Some(pds.server.uri());

    let engine = SkybouncerEngineBuilder::new(cfg)
        .with_cache(cache)
        .with_follow_graph(follow_graph)
        .with_gate(gate)
        .with_classifier(Arc::new(MockClassifier::permitted()))
        .with_modlist_manager(modlist_manager)
        .with_pds_client(Arc::new(pds.client(alice)))
        .with_storm_stance_classifier(Arc::new(MockStormStanceClassifier::new(
            StormStanceVerdict::new(true, 0.9, "dogpile", "hostile", "mock"),
        )))
        .build()
        .unwrap();

    // Pre-seed heuristic pre-filter bounce on `focal` BEFORE the surge commits run so
    // `dogpile_tracker.eval_outcomes` holds the recorded heuristic violation when surge triggers!
    let heur_inter = skybouncer::matcher::Interaction {
        post_uri: "at://did:plc:heur/app.bsky.feed.post/h1".to_string(),
        post_cid: Some("cidh1".to_string()),
        author_did: "did:plc:heur".to_string(),
        target_did: alice.to_string(),
        text: "CLAIM FREE AIRDROP CONNECT WALLET NOW http://scam.example".to_string(),
        interaction_type: skybouncer::matcher::InteractionType::DirectReply,
        parent_uri: Some(focal.to_string()),
        root_uri: Some(focal.to_string()),
        quote_uri: None,
        created_at_us: 1_650_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    };
    let fast_out = engine.process_interaction(heur_inter).await.unwrap();
    assert!(fast_out.is_bounced());

    // Now feed additional replies with stale 2022 timestamps (time_us = 1_650_000_000_000_000):
    // local monotonic clock activates Storm Mode AND the storm event carries violation_rate > 0!
    let mut storm_rx = engine.subscribe_storm_alerts();
    let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(32);
    let cancel = CancellationToken::new();
    let eng_clone = engine.clone();
    let cancel_clone = cancel.clone();
    let runner = tokio::spawn(async move { eng_clone.run(commit_rx, cancel_clone).await });

    for i in 0..4 {
        let mut c = make_reply_commit(
            &format!("did:plc:stale_{i}"),
            alice,
            &format!("r{i}"),
            "3kstale",
            "hostile reply",
        );
        c.time_us = 1_650_000_000_000_000;
        commit_tx.send(c).await.unwrap();
    }
    drop(commit_tx);
    runner.await.unwrap().unwrap();

    let storm_notif = tokio::time::timeout(Duration::from_secs(2), storm_rx.recv())
        .await
        .expect("storm notification timeout")
        .expect("storm notification present");
    assert_eq!(storm_notif.storm.focal_post_uri, focal);
    assert!(engine.is_storm_mode_active(alice));
    assert!(
        storm_notif.storm.metrics.violation_rate > 0.0,
        "heuristic pre-filter violation must be recorded into dogpile_tracker eval_outcomes"
    );
}
