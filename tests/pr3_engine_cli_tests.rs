//! Regression tests for PR 3 engine pipeline offload, cancellation discipline,
//! multi-target error isolation, sovereign record guards, and CLI subcommand hardening.

#![cfg(all(
    feature = "web",
    feature = "stream",
    feature = "bot",
    feature = "telemetry"
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::MockPdsServer;
use serde_json::json;
use skybase::ingest::{CommitOperation, JetstreamCommit};
use skybouncer::app::{run_cli_pardon, run_cli_simulate};
use skybouncer::classifier::{MockClassifier, RuleRubric, Sensitivity, Verdict, ViolationCategory};
use skybouncer::engine::{
    InteractionOutcome, ProcessCommitResult, SkybouncerConfig, SkybouncerEngine,
};
use skybouncer::enricher::MockContextEnricher;
use skybouncer::error::SkybouncerError;
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn make_engine_with_cache(
    protected_dids: impl IntoIterator<Item = &str>,
    pds: &MockPdsServer,
    cache: Arc<DeduplicationCache>,
    dry_run: bool,
) -> Arc<SkybouncerEngine> {
    let dids: HashSet<String> = protected_dids.into_iter().map(str::to_string).collect();
    let first_did = dids.iter().next().cloned().unwrap_or_default();
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block harassment", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client(&first_did));
    let classifier = Arc::new(MockClassifier::new(Verdict::permitted("ok")));
    let config = SkybouncerConfig::new(dids, rubric)
        .with_dry_run(dry_run)
        .with_enable_heuristic_prefilter(true);

    Arc::new(
        SkybouncerEngine::builder(config)
            .with_follow_graph(follow_graph)
            .with_gate(gate)
            .with_cache(cache)
            .with_modlist_manager(modlist)
            .with_pds_client(pds_client)
            .with_classifier(classifier)
            .with_enricher(Arc::new(MockContextEnricher::new()))
            .build()
            .unwrap(),
    )
}

#[tokio::test]
async fn test_pr3_fast_path_offloads_remote_pds_io_and_worker_stops_dequeuing_on_cancel() {
    let pds = MockServer::start().await;
    let alice = "did:plc:alice_fast";

    // Provision list and listblock lookups fast; createRecord incurs a 75ms network delay.
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .and(wiremock::matchers::query_param(
            "collection",
            "app.bsky.graph.list",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [{
                "uri": format!("at://{alice}/app.bsky.graph.list/list1"),
                "cid": "bafylist1",
                "value": {
                    "$type": "app.bsky.graph.list",
                    "name": skybouncer::modlist::DEFAULT_MOD_LIST_NAME,
                    "purpose": "app.bsky.graph.defs#modlist",
                    "createdAt": "2026-11-28T00:00:00Z"
                }
            }],
            "cursor": null
        })))
        .mount(&pds)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .and(wiremock::matchers::query_param(
            "collection",
            "app.bsky.graph.listblock",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [{
                "uri": format!("at://{alice}/app.bsky.graph.listblock/lb1"),
                "cid": "bafylb1",
                "value": { "subject": format!("at://{alice}/app.bsky.graph.list/list1") }
            }],
            "cursor": null
        })))
        .mount(&pds)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "RecordNotFound",
            "message": "Record not found"
        })))
        .mount(&pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.repo.putRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": format!("at://{alice}/social.skybouncer.config/self"),
            "cid": "bafycfg"
        })))
        .mount(&pds)
        .await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.repo.createRecord"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(75))
                .set_body_json(json!({
                    "uri": format!("at://{alice}/app.bsky.graph.listitem/li1"),
                    "cid": "bafyli1"
                })),
        )
        .mount(&pds)
        .await;

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(
        skybase::repo::PdsRepoClient::from_credentials(pds.uri(), alice, "tok-1")
            .unwrap()
            .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true)),
    );
    let config = SkybouncerConfig::new([alice], rubric)
        .with_dry_run(false)
        .with_enable_heuristic_prefilter(true);

    let engine = Arc::new(
        SkybouncerEngine::builder(config)
            .with_follow_graph(follow_graph)
            .with_gate(gate)
            .with_cache(Arc::clone(&cache))
            .with_modlist_manager(modlist)
            .with_pds_client(pds_client)
            .with_classifier(Arc::new(MockClassifier::permitted()))
            .with_enricher(Arc::new(MockContextEnricher::new()))
            .build()
            .unwrap(),
    );

    // Pre-seed eval cache hit on post1; post2 triggers heuristic prefilter.
    cache
        .set_evaluation(
            &format!("at://did:plc:evalhit/app.bsky.feed.post/p1:{alice}"),
            "did:plc:evalhit",
            &Verdict::violation(ViolationCategory::Spam, 0.99, "cached spam"),
            Duration::from_secs(300),
        )
        .unwrap();

    // Ensure process_commit_queued itself performs zero remote PDS I/O (< 20ms despite 75ms PDS delay).
    let (ev_tx, mut ev_rx) = mpsc::channel(16);
    let cached_hit_commit = JetstreamCommit {
        did: "did:plc:evalhit".to_string(),
        time_us: 1_700_000_000_000_000,
        operation: CommitOperation::Create,
        collection: "app.bsky.feed.post".to_string(),
        rkey: "p1".to_string(),
        cid: Some("bafyp1".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": "Hey there",
            "createdAt": "2026-11-28T00:00:00Z",
            "reply": {
                "parent": { "uri": format!("at://{alice}/app.bsky.feed.post/root"), "cid": "c" },
                "root": { "uri": format!("at://{alice}/app.bsky.feed.post/root"), "cid": "c" }
            }
        })),
    };
    let t0 = std::time::Instant::now();
    let res = engine
        .process_commit_queued(&cached_hit_commit, &ev_tx)
        .await
        .unwrap();
    assert!(
        t0.elapsed() < Duration::from_millis(30),
        "fast-path offload must not await 75ms PDS I/O inline"
    );
    assert!(matches!(
        res,
        ProcessCommitResult::InteractionsProcessed(ref outs)
            if matches!(outs.first(), Some(InteractionOutcome::QueuedForEvaluation { .. }))
    ));
    assert!(ev_rx.try_recv().is_ok());

    // Now test engine.run end-to-end with heuristic commit + fast_action_worker executing the PDS bounce,
    // and then cancelling immediately after sending another commit (which cancel breaks cleanly).
    let (commit_tx, commit_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let run_engine = Arc::clone(&engine);
    let run_cancel = cancel.clone();
    let handle = tokio::spawn(async move { run_engine.run(commit_rx, run_cancel).await });

    let heur_commit = JetstreamCommit {
        did: "did:plc:heurspammer".to_string(),
        time_us: 1_700_000_000_000_001,
        operation: CommitOperation::Create,
        collection: "app.bsky.feed.post".to_string(),
        rkey: "h1".to_string(),
        cid: Some("bafyh1".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": "CLAIM FREE AIRDROP CONNECT WALLET NOW http://scam.example",
            "createdAt": "2026-11-28T00:00:00Z",
            "reply": {
                "parent": { "uri": format!("at://{alice}/app.bsky.feed.post/root"), "cid": "c" },
                "root": { "uri": format!("at://{alice}/app.bsky.feed.post/root"), "cid": "c" }
            }
        })),
    };
    commit_tx.send(heur_commit).await.unwrap();

    // Wait briefly so fast_action_worker picks up heur_commit and finishes the 75ms PDS write.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !cache.is_bounced_for(alice, "did:plc:heurspammer").unwrap() {
        if std::time::Instant::now() >= deadline {
            let reqs: Vec<String> = pds
                .received_requests()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| format!("{} {}", r.method, r.url))
                .collect();
            panic!(
                "fast_action_worker must execute deferred heuristic PDS bounce; stats={:?}; reqs={reqs:?}",
                engine.stats().snapshot()
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    cancel.cancel();
    drop(commit_tx);
    let snap = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("engine.run drains cleanly")
        .unwrap()
        .unwrap();
    assert!(snap.bounces_executed >= 1);
}

#[tokio::test]
async fn test_pr3_multi_target_error_isolation_in_process_commit_and_queued() {
    let pds = MockPdsServer::start().await;
    let alice = "did:plc:alice_iso";
    let bob = "did:plc:bob_iso";

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client(bob));
    let classifier = Arc::new(MockClassifier::new(Verdict::violation(
        ViolationCategory::Harassment,
        0.95,
        "insult",
    )));

    let config = SkybouncerConfig::new([alice, bob], rubric)
        .with_dry_run(false)
        .with_enable_heuristic_prefilter(false);
    let engine = Arc::new(
        SkybouncerEngine::builder(config)
            .with_follow_graph(follow_graph)
            .with_gate(gate)
            .with_cache(Arc::clone(&cache))
            .with_modlist_manager(modlist)
            .with_pds_client(pds_client)
            .with_classifier(classifier)
            .with_enricher(Arc::new(MockContextEnricher::new()))
            .build()
            .unwrap(),
    );

    // Pause Alice? No, induce a real SQLite error for a whitespace/empty target interaction?
    // Even simpler: configure Bob with a session whose PDS fails vs Alice succeeding, OR directly
    // test multi-mention where Alice hits invalid empty target/DB error while Bob succeeds.
    // Let's register Bob with valid credentials and Alice with a failing PDS endpoint override
    // via a second failing tenant session.
    let failing_pds = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .respond_with(ResponseTemplate::new(500).set_body_string("PDS down"))
        .mount(&failing_pds)
        .await;

    let session_fail = skyauth::OAuthSession::new(
        alice,
        "tok-fail",
        None,
        "DPoP",
        None,
        Some(3600),
        skyauth::DPoPKey::generate(),
        Some(failing_pds.uri()),
        None,
        None,
    )
    .unwrap();
    engine
        .tenant_registry()
        .register_or_update(&skybouncer::tenant::Tenant::new(alice).with_session(session_fail))
        .unwrap();

    // Commit mentions BOTH alice (whose tenant PDS is SSRF-blocked/failing -> Err) and bob
    // (who uses the engine's SsrfFilter-enabled MockPdsServer client and succeeds).
    let dual_mention = JetstreamCommit {
        did: "did:plc:attacker".to_string(),
        time_us: 1_700_000_000_000_000,
        operation: CommitOperation::Create,
        collection: "app.bsky.feed.post".to_string(),
        rkey: "dual1".to_string(),
        cid: Some("bafydual1".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": "Both @alice and @bob are awful",
            "createdAt": "2026-11-28T00:00:00Z",
            "facets": [
                {
                    "index": { "byteStart": 5, "byteEnd": 11 },
                    "features": [{ "$type": "app.bsky.richtext.facet#mention", "did": alice }]
                },
                {
                    "index": { "byteStart": 16, "byteEnd": 20 },
                    "features": [{ "$type": "app.bsky.richtext.facet#mention", "did": bob }]
                }
            ]
        })),
    };

    let res = engine.process_commit(&dual_mention).await.unwrap();
    assert!(matches!(
        res,
        ProcessCommitResult::InteractionsProcessed(ref outs) if outs.len() == 1
    ));
    assert!(
        cache.is_bounced_for(bob, "did:plc:attacker").unwrap(),
        "Bob must still be protected even when Alice's PDS failed"
    );
    assert!(engine.stats().snapshot().errors_encountered >= 1);

    // Queued path also continues when one target fails (e.g. closed eval channel? Here test 2 targets queued).
    let (ev_tx, mut ev_rx) = mpsc::channel(8);
    let q_res = engine
        .process_commit_queued(&dual_mention, &ev_tx)
        .await
        .unwrap();
    assert!(matches!(
        q_res,
        ProcessCommitResult::InteractionsProcessed(ref outs) if outs.len() == 2
    ));
    assert!(ev_rx.try_recv().is_ok());
}

#[tokio::test]
async fn test_pr3_sovereign_config_rkey_and_list_purpose_guards() {
    let pds = MockPdsServer::start().await;
    let alice = "did:plc:alice_guard";
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let engine = make_engine_with_cache([alice], &pds, cache, true).await;

    // 1. Sovereign config commit with rkey != "self" MUST be ignored.
    let non_self_config = JetstreamCommit {
        did: alice.to_string(),
        time_us: 1_700_000_000_000_000,
        operation: CommitOperation::Create,
        collection: skybouncer::modlist::SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: "not-self".to_string(),
        cid: Some("bafycfg1".to_string()),
        record: Some(json!({
            "$type": "social.skybouncer.config",
            "rules": "Injected rules",
            "sensitivity": "high",
            "updatedAt": "2026-11-28T00:00:00Z"
        })),
    };
    assert_eq!(
        engine.process_commit(&non_self_config).await.unwrap(),
        ProcessCommitResult::Ignored
    );
    assert_eq!(engine.rubric_for(alice).prompt, "Block harassment");

    // 2. Sovereign config commit with rkey == "self" IS applied.
    let self_config = JetstreamCommit {
        rkey: skybouncer::modlist::SOVEREIGN_CONFIG_RKEY.to_string(),
        ..non_self_config
    };
    assert!(matches!(
        engine.process_commit(&self_config).await.unwrap(),
        ProcessCommitResult::SovereignConfigSynced(_)
    ));
    assert_eq!(engine.rubric_for(alice).prompt, "Injected rules");

    // 3. app.bsky.graph.list with purpose != app.bsky.graph.defs#modlist (e.g. curatelist) MUST be ignored.
    let curatelist = JetstreamCommit {
        did: alice.to_string(),
        time_us: 1_700_000_000_000_001,
        operation: CommitOperation::Update,
        collection: "app.bsky.graph.list".to_string(),
        rkey: "curate1".to_string(),
        cid: Some("bafylistc".to_string()),
        record: Some(json!({
            "$type": "app.bsky.graph.list",
            "name": "Cool Accounts",
            "purpose": "app.bsky.graph.defs#curatelist",
            "description": "[skybouncer:rules] Should never apply [sensitivity:low]"
        })),
    };
    assert_eq!(
        engine.process_commit(&curatelist).await.unwrap(),
        ProcessCommitResult::Ignored
    );
    assert_eq!(engine.rubric_for(alice).prompt, "Injected rules");

    // 4. app.bsky.graph.list with purpose == app.bsky.graph.defs#modlist IS applied.
    let updated_desc = skybouncer::modlist::format_list_description_with_rubric(
        "My list",
        &RuleRubric::new("Updated via modlist", Sensitivity::Low),
    );
    let modlist_commit = JetstreamCommit {
        record: Some(json!({
            "$type": "app.bsky.graph.list",
            "name": "Skybouncer",
            "purpose": "app.bsky.graph.defs#modlist",
            "description": updated_desc
        })),
        ..curatelist
    };
    assert!(matches!(
        engine.process_commit(&modlist_commit).await.unwrap(),
        ProcessCommitResult::SovereignConfigSynced(_)
    ));
    assert_eq!(engine.rubric_for(alice).prompt, "Updated via modlist");
}

#[tokio::test]
async fn test_pr3_cli_pardon_query_encoding_and_simulate_error_and_offline_image_url() {
    // 1. Daemon returns HTTP 400 on /api/simulate -> CLI MUST return Err (NOT silently fall back offline).
    let bad_app = Router::new().route(
        "/api/simulate",
        post(|| async { (StatusCode::BAD_REQUEST, "Invalid draft_prompt") }),
    );
    let bad_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = bad_listener.local_addr().unwrap();
    let bad_srv = tokio::spawn(async move { axum::serve(bad_listener, bad_app).await });

    let sim_err = run_cli_simulate(&[
        "hello".to_string(),
        "--url".to_string(),
        format!("http://{bad_addr}"),
    ])
    .await
    .expect_err("non-2xx /api/simulate response must error instead of offline fallback");
    assert!(matches!(sim_err, SkybouncerError::Config(ref m) if m.contains("400")));
    bad_srv.abort();

    // 2. Offline --image <URL> rejects private/loopback IP cleanly via SSRF filter (proving URL fetch runs offline).
    let ssrf_err = run_cli_simulate(&[
        "check image".to_string(),
        "--offline".to_string(),
        "--image".to_string(),
        "http://127.0.0.1:9/evil.png".to_string(),
    ])
    .await
    .expect_err("offline --image <URL> must invoke SSRF-hardened image fetch");
    assert!(
        ssrf_err.to_string().contains("offline simulation image"),
        "unexpected error: {ssrf_err}"
    );

    // 3. run_cli_pardon encodes handle parameter safely via url::Url.
    let resolve_app = Router::new()
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(
                |axum::extract::Query(q): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    let h = q.get("handle").cloned().unwrap_or_default();
                    Json(json!({ "did": format!("did:plc:{h}") }))
                },
            ),
        )
        .route(
            "/api/pardon",
            post(|| async {
                Json(json!({
                    "pardoned": true,
                    "allowlisted": false,
                    "subject_did": "did:plc:alice&evil=1.bsky.social",
                    "message": "ok"
                }))
            }),
        );
    let p_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p_addr = p_listener.local_addr().unwrap();
    let p_srv = tokio::spawn(async move { axum::serve(p_listener, resolve_app).await });

    std::env::set_var(
        "SKYBOUNCER_RESOLVE_HANDLE_URL",
        format!("http://{p_addr}/xrpc/com.atproto.identity.resolveHandle"),
    );
    let pardon_res = run_cli_pardon(&[
        "@alice&evil=1.bsky.social".to_string(),
        "--url".to_string(),
        format!("http://{p_addr}"),
    ])
    .await;
    std::env::remove_var("SKYBOUNCER_RESOLVE_HANDLE_URL");
    p_srv.abort();
    assert!(pardon_res.is_ok(), "run_cli_pardon failed: {pardon_res:?}");
}

#[tokio::test]
async fn test_pr3_engine_new_parity_maintenance_ticks_reauth_skip_and_queued_cache_hit() {
    let pds = MockPdsServer::start().await;
    let alice = "did:plc:alice_maint";
    let reauth_did = "did:plc:reauth_skip";

    // Build via SkybouncerEngine::new with admin_did + fallback_jev_config (LlmStormStanceClassifier).
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist = Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)));

    let mut cfg = SkybouncerConfig::new([alice], rubric.clone())
        .with_dry_run(true)
        .with_enable_heuristic_prefilter(true)
        .with_admin_did("did:plc:admin_new");
    cfg.fallback_jev_config = Some(skybouncer::classifier::JevConfig {
        base_url: "http://127.0.0.1:9".to_string(),
        model: "gemma3:4b".to_string(),
        ..Default::default()
    });

    let engine = SkybouncerEngine::new(
        cfg,
        follow_graph,
        gate,
        Arc::new(MockClassifier::permitted()),
        modlist,
        Arc::new(pds.pds_client(alice)),
    )
    .unwrap();
    assert!(engine.is_protected("did:plc:admin_new"));

    // Enroll a tenant flagged reauth_required with an expired temporary bounce.
    let session = skyauth::OAuthSession::new(
        reauth_did,
        "at-exp",
        None,
        "DPoP",
        None,
        Some(3600),
        skyauth::DPoPKey::generate(),
        Some(pds.uri()),
        None,
        None,
    )
    .unwrap();
    engine
        .tenant_registry()
        .register_or_update(
            &skybouncer::tenant::Tenant::new(reauth_did)
                .with_rubric(rubric)
                .with_session(session),
        )
        .unwrap();
    engine
        .tenant_registry()
        .mark_reauth_required(reauth_did)
        .unwrap();
    cache
        .record_bounce(&skybouncer::modlist::BouncedUser {
            subject_did: "did:plc:temp_violator".to_string(),
            protected_did: reauth_did.to_string(),
            listitem_uri: format!("at://{reauth_did}/app.bsky.graph.listitem/rk1"),
            listitem_rkey: "rk1".to_string(),
            listitem_cid: "bafyrk1".to_string(),
            category: "spam".to_string(),
            confidence: 0.99,
            reason: "spam".to_string(),
            post_uri: "at://did:plc:temp_violator/app.bsky.feed.post/1".to_string(),
            post_text: "spam".to_string(),
            reply_to_uri: None,
            bounced_at: 100,
            expires_at: Some(1000),
        })
        .unwrap();

    // prune_expired_bounces_with_cancel MUST skip reauth_required tenants cleanly.
    let pruned = engine
        .prune_expired_bounces_with_cancel(&CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(pruned, 0);
    assert!(cache
        .is_bounced_for(reauth_did, "did:plc:temp_violator")
        .unwrap());

    // Cancelled hydration & provision_pds_resources skip cancelled / reauth_required tenants.
    let enricher =
        skybouncer::enricher::AppViewContextEnricher::with_endpoint("http://127.0.0.1:9");
    let pre_cancel = CancellationToken::new();
    pre_cancel.cancel();
    assert_eq!(
        skybouncer::daemon::hydrate_cold_start_with_cancel(
            &engine,
            &enricher,
            &HashSet::new(),
            &pre_cancel
        )
        .await,
        0
    );
    assert_eq!(
        skybouncer::daemon::provision_pds_resources(&engine, &HashSet::new()).await,
        0
    );

    // Run 12+ maintenance ticks to exercise spawn_blocking retention + incremental_vacuum + optimize.
    let maint_cancel = CancellationToken::new();
    let maint_eng = engine.clone();
    let maint_tok = maint_cancel.clone();
    let maint_handle = tokio::spawn(async move {
        maint_eng
            .run_maintenance(Duration::from_millis(5), maint_tok)
            .await
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    maint_cancel.cancel();
    let _ = maint_handle.await.unwrap().unwrap();

    // Exercise evaluate_candidate_queued hitting eval_cache (deferred eval_tx path without LLM/enricher).
    let post_uri = "at://did:plc:evalq/app.bsky.feed.post/p9";
    cache
        .set_evaluation(
            &format!("{post_uri}:{alice}"),
            "did:plc:evalq",
            &Verdict::violation(ViolationCategory::Spam, 0.99, "cached"),
            Duration::from_secs(60),
        )
        .unwrap();
    let inter = skybouncer::matcher::Interaction::new(
        "did:plc:evalq",
        alice,
        skybouncer::matcher::InteractionType::DirectReply,
        post_uri,
        "bafyp9",
        "spam",
    );
    let outcome = engine
        .evaluate_candidate_queued(inter, &CancellationToken::new())
        .await
        .unwrap();
    assert!(outcome.is_bounced());
}

#[tokio::test]
async fn test_pr3_meta_cache_cold_open_cli_simulate_200_and_enricher_resolve_did() {
    // 1. Persisted TenantRegistry re-open hydrates meta_cache and resolves handle/status/rubric with zero decrypt.
    let dir =
        std::env::temp_dir().join(format!("skybouncer_pr3_meta_reopen_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("tenants.db");

    {
        let reg = skybouncer::tenant::TenantRegistry::open(&db_path).unwrap();
        let t = skybouncer::tenant::Tenant::new("did:plc:reopen_user")
            .with_handle("reopen.bsky.social")
            .with_rubric(RuleRubric::new("Custom reopen rules", Sensitivity::High));
        reg.register_or_update(&t).unwrap();
    }
    let reg2 = skybouncer::tenant::TenantRegistry::open(&db_path).unwrap();
    assert_eq!(
        reg2.get_handle("did:plc:reopen_user").unwrap().as_deref(),
        Some("reopen.bsky.social")
    );
    assert_eq!(
        reg2.get_rubric("did:plc:reopen_user")
            .unwrap()
            .unwrap()
            .prompt,
        "Custom reopen rules"
    );
    assert!(
        reg2.get_status("did:plc:reopen_user")
            .unwrap()
            .unwrap()
            .is_active
    );
    let _ = std::fs::remove_dir_all(&dir);

    // 2. CLI simulate 200 OK prints result from daemon cleanly.
    let ok_app = Router::new().route(
        "/api/simulate",
        post(|| async {
            Json(json!({
                "violates": false,
                "category": null,
                "confidence": 0.1,
                "reason": "Benign test post",
                "evaluator": "mock",
                "meets_threshold": false,
                "threshold": 0.75,
                "images_evaluated": 0
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = tokio::spawn(async move { axum::serve(listener, ok_app).await });
    let ok_res = run_cli_simulate(&[
        "hello world".to_string(),
        "--url".to_string(),
        format!("http://{addr}"),
    ])
    .await;
    srv.abort();
    assert!(ok_res.is_ok(), "run_cli_simulate 200 OK failed: {ok_res:?}");

    // 3. AppViewContextEnricher reusable IdentityResolver resolve_did & resolve_handle via AppView mock.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": "did:plc:res1",
            "handle": "Resolved.Bsky.Social"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.identity.resolveHandle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": "did:plc:res1"
        })))
        .mount(&server)
        .await;
    let enricher = skybouncer::enricher::AppViewContextEnricher::with_endpoint(server.uri());
    let trait_enricher: &dyn skybouncer::enricher::ContextEnricher = &enricher;
    assert_eq!(
        trait_enricher.resolve_did("did:plc:res1").await.as_deref(),
        Some("resolved.bsky.social")
    );
    assert_eq!(
        trait_enricher
            .resolve_handle("resolved.bsky.social")
            .await
            .as_deref(),
        Some("did:plc:res1")
    );
    let _ = trait_enricher
        .check_relationship("did:plc:res1", "did:plc:other")
        .await;
    let _ = trait_enricher
        .fetch_image_base64("did:plc:res1", "bafkmissing")
        .await;
    let _ = trait_enricher
        .fetch_post_engagements(&["at://did:plc:res1/app.bsky.feed.post/1".to_string()])
        .await;
    let _ = trait_enricher
        .fetch_actor_followers_count("did:plc:res1")
        .await;

    // 4. Test SkybouncerEngine::new with jev_config-only LlmStormStanceClassifier and active tenant rubric,
    // plus fast_path BelowThreshold heuristic logging and closed eval_tx handling.
    let cache2 = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let reg_pre = skybouncer::tenant::TenantRegistry::from_connection(cache2.connection()).unwrap();
    reg_pre
        .register_or_update(
            &skybouncer::tenant::Tenant::new("did:plc:pre_tenant")
                .with_rubric(RuleRubric::new("Custom", Sensitivity::Low)),
        )
        .unwrap();
    let fg2 = Arc::new(FollowGraph::new());
    let gate2 = Arc::new(NonFollowedGate::new(Arc::clone(&fg2)));
    let pds2 = MockPdsServer::start().await;
    let mut cfg2 = SkybouncerConfig::new(["did:plc:alice2"], RuleRubric::default())
        .with_dry_run(true)
        .with_enable_heuristic_prefilter(true);
    cfg2.jev_config = Some(skybouncer::classifier::JevConfig::default());
    let eng2 = SkybouncerEngine::new(
        cfg2,
        fg2,
        gate2,
        Arc::new(MockClassifier::permitted()),
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache2))),
        Arc::new(pds2.pds_client("did:plc:alice2")),
    )
    .unwrap();
    assert!(eng2.is_protected("did:plc:pre_tenant"));

    // Closed eval_tx returns Ingestion error on enqueue.
    let (closed_tx, closed_rx) = mpsc::channel(1);
    drop(closed_rx);
    let enqueue_inter = skybouncer::matcher::Interaction::new(
        "did:plc:stranger2",
        "did:plc:alice2",
        skybouncer::matcher::InteractionType::DirectReply,
        "at://did:plc:stranger2/app.bsky.feed.post/q2",
        "bafyq2",
        "normal reply",
    );
    assert!(eng2
        .process_interaction_queued(enqueue_inter, &closed_tx)
        .await
        .is_err());

    // Sync heuristic bounce executes cleanly via fast_path(defer_remote_io = false).
    let heur_low_inter = skybouncer::matcher::Interaction::new(
        "did:plc:heur_sync",
        "did:plc:alice2",
        skybouncer::matcher::InteractionType::DirectReply,
        "at://did:plc:heur_sync/app.bsky.feed.post/hb1",
        "bafyhb1",
        "CLAIM FREE AIRDROP NOW",
    );
    eng2.set_rubric(RuleRubric::new("LowSens", Sensitivity::Low));
    let sync_out = eng2.process_interaction(heur_low_inter).await.unwrap();
    assert!(sync_out.is_bounced());
}
