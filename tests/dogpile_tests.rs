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
        PdsRepoClient::from_credentials(self.server.uri(), did, "mock_token").unwrap()
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

    // 6. Prometheus metrics & Dashboard HTML & CLI summary telemetry
    let metrics_res = app
        .oneshot(
            Request::builder()
                .uri("/api/metrics")
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
