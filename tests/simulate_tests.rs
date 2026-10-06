//! Direct tests for `SkybouncerEngine::run_simulation` (the shared dry-run pipeline
//! used by the web `/api/simulate` handler and the CLI `simulate --offline` path).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::MockPdsServer;
use skybouncer::classifier::{
    CertaintyConfig, MockClassifier, RuleRubric, Sensitivity, TieredClassifier, Verdict,
};
use skybouncer::engine::simulate::SimulationInputs;
use skybouncer::engine::{SkybouncerConfig, SkybouncerEngine};

use skybouncer::modlist::{DeduplicationCache, ModListManager};

struct Rig {
    engine: Arc<SkybouncerEngine>,
    cache: Arc<DeduplicationCache>,
    _pds: MockPdsServer,
    protected: String,
}

async fn build_rig(primary: Verdict, fallback: Option<Verdict>, prefilter: bool) -> Rig {
    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let rubric = RuleRubric::new("Block toxicity and crypto spam", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let protected = "did:plc:alice".to_string();
    let classifier: Arc<dyn skybouncer::classifier::Classifier> = match fallback {
        Some(fb) => Arc::new(TieredClassifier::new(
            Arc::new(MockClassifier::new(primary)),
            Arc::new(MockClassifier::new(fb)),
            CertaintyConfig::new(0.40, 0.85, true),
        )),
        None => Arc::new(MockClassifier::new(primary)),
    };

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected.clone());
    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_enable_heuristic_prefilter(prefilter)
        .with_dry_run(true);

    let engine = Arc::new(
        SkybouncerEngine::builder(config)
            .with_classifier(classifier)
            .with_cache(Arc::clone(&cache))
            .with_modlist_manager(Arc::clone(&modlist_manager))
            .build()
            .expect("engine build"),
    );

    Rig {
        engine,
        cache,
        _pds: pds,
        protected,
    }
}

#[tokio::test]
async fn simulation_permitted_no_persist_leaves_cache_empty() {
    let rig = build_rig(Verdict::permitted("benign"), None, false).await;
    let inputs = SimulationInputs::new("hello world", "did:plc:author", &rig.protected);
    let result = rig.engine.run_simulation(inputs).await.expect("simulate");

    assert!(!result.violates);
    assert!(result.category.is_none());
    assert_eq!(result.evaluator, "primary_classifier");
    assert_eq!(result.images_evaluated, 0);
    assert!(!result.fetched_url_image);
    assert!(result.tier1.is_some());
    assert!(result.tier2.is_some());
    assert!(!result.created_at.is_empty());
    // persist_log defaults to false.
    assert_eq!(rig.cache.count_evaluation_logs(None, None).unwrap(), 0);
}

#[tokio::test]
async fn simulation_violation_persists_audit_log_when_requested() {
    let rig = build_rig(
        Verdict::violation(
            skybouncer::classifier::ViolationCategory::CryptoSpam,
            0.97,
            "airdrop scam",
        ),
        None,
        false,
    )
    .await;
    let inputs = SimulationInputs::new("free airdrop", "did:plc:spammer", &rig.protected)
        .with_persist_log(true);
    let result = rig.engine.run_simulation(inputs).await.expect("simulate");

    assert!(result.violates);
    assert_eq!(result.category.as_deref(), Some("crypto_spam"));
    assert!(result.meets_threshold);
    assert_eq!(result.evaluator, "primary_classifier");

    let logs = rig.cache.list_evaluation_logs(None, None, 10, 0).unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].source, "simulation");
    assert_eq!(logs[0].author_did, "did:plc:spammer");
}

#[tokio::test]
async fn simulation_with_base64_image_counts_image_and_sets_uri() {
    let rig = build_rig(Verdict::permitted("ok"), None, false).await;
    let inputs = SimulationInputs::new("look at this", "did:plc:author", &rig.protected)
        .with_image(Some("aGVsbG8=".to_string()), false);
    let result = rig.engine.run_simulation(inputs).await.expect("simulate");

    assert_eq!(result.images_evaluated, 1);
    assert!(!result.fetched_url_image);
    // Multimodal evaluator label.
    assert_eq!(result.evaluator, "primary_classifier (multimodal)");
}

#[tokio::test]
async fn simulation_with_url_image_marks_provenance() {
    let rig = build_rig(Verdict::permitted("ok"), None, false).await;
    let inputs = SimulationInputs::new("remote image", "did:plc:author", &rig.protected)
        .with_image(Some("aGVsbG8=".to_string()), true)
        .with_persist_log(true);
    let result = rig.engine.run_simulation(inputs).await.expect("simulate");

    assert_eq!(result.images_evaluated, 1);
    assert!(result.fetched_url_image);

    // The persisted log for a URL image uses the `simulated` post URI.
    let logs = rig.cache.list_evaluation_logs(None, None, 10, 0).unwrap();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].post_uri.ends_with("/simulated"));
}

#[tokio::test]
async fn simulation_blank_image_is_ignored() {
    let rig = build_rig(Verdict::permitted("ok"), None, false).await;
    let inputs = SimulationInputs::new("text only", "did:plc:author", &rig.protected)
        .with_image(Some("   ".to_string()), false);
    let result = rig.engine.run_simulation(inputs).await.expect("simulate");
    assert_eq!(result.images_evaluated, 0);
}

#[tokio::test]
async fn simulation_heuristic_prefilter_short_circuits_and_logs() {
    // Enable the heuristic prefilter and feed text that trips the default crypto rule.
    let rig = build_rig(Verdict::permitted("unused"), None, true).await;
    let inputs = SimulationInputs::new(
        "Claim your free airdrop now, connect wallet to claim tokens",
        "did:plc:spammer",
        &rig.protected,
    )
    .with_persist_log(true);
    let result = rig.engine.run_simulation(inputs).await.expect("simulate");

    // The zero-cost pre-filter must resolve this without invoking the model.
    assert!(
        result.violates,
        "airdrop text must trip the heuristic prefilter"
    );
    assert_eq!(result.evaluator, "heuristic_prefilter");
    assert_eq!(result.category.as_deref(), Some("crypto_spam"));

    // Tier stages are the "bypassed" placeholders.
    let t1 = result.tier1.expect("tier1");
    assert_eq!(t1.status, "bypassed");
    let t2 = result.tier2.expect("tier2");
    assert_eq!(t2.status, "bypassed");

    // A heuristic audit log was written.
    let logs = rig.cache.list_evaluation_logs(None, None, 10, 0).unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].source, "simulation");
    assert!(logs[0].primary_model.contains("heuristic"));
}

#[tokio::test]
async fn simulation_escalates_to_fallback_tier() {
    // Primary borderline 0.65 (in 0.40..0.85 band), fallback decisive.
    let rig = build_rig(
        Verdict::permitted_with_confidence("borderline", 0.65),
        Some(Verdict::permitted_with_confidence("decisive", 0.95)),
        false,
    )
    .await;
    let inputs = SimulationInputs::new("hmm?", "did:plc:author", &rig.protected);
    let result = rig.engine.run_simulation(inputs).await.expect("simulate");

    assert!(!result.violates);
    assert_eq!(result.confidence, 0.95);
    assert_eq!(result.evaluator, "fallback_uncertainty_classifier");
    let t1 = result.tier1.expect("tier1");
    assert_eq!(t1.status, "escalated");
    let t2 = result.tier2.expect("tier2");
    assert_eq!(t2.status, "resolved");
}

#[tokio::test]
async fn simulation_permitted_without_confidence_defaults_to_point_zero_five() {
    let rig = build_rig(
        Verdict::Permitted {
            reason: "no confidence".to_string(),
            confidence: None,
        },
        None,
        false,
    )
    .await;
    let inputs = SimulationInputs::new("plain", "did:plc:author", &rig.protected);
    let result = rig.engine.run_simulation(inputs).await.expect("simulate");
    assert!(!result.violates);
    assert_eq!(result.confidence, 0.05);
}

#[tokio::test]
async fn engine_accessors_and_hydration_paths() {
    let rig = build_rig(Verdict::permitted("ok"), None, false).await;
    let engine = &rig.engine;

    // Protected-DID accessors.
    assert!(engine.is_protected(&rig.protected));
    assert!(engine.protected_dids().contains(&rig.protected));
    engine.add_protected_did("did:plc:new");
    assert!(engine.is_protected("did:plc:new"));
    assert!(engine.remove_protected_did("did:plc:new"));

    // Component accessors return the shared handles.
    let _ = engine.is_dry_run();
    let _ = engine.config();
    let _ = engine.rubric();
    let _ = engine.heuristic_classifier();
    let _ = engine.primary_classifier();
    let _ = engine.follow_graph();
    let _ = engine.gate();
    let _ = engine.cache();
    let _ = engine.pds_client();
    let _ = engine.stats();
    let _ = engine.rate_limiter();
    let _ = engine.enricher();
    let _ = engine.tenant_registry();
    let _ = engine.subscribe_bounces();

    // Pause/resume lifecycle.
    let _ = engine.pause();
    assert!(engine.is_paused());
    let _ = engine.resume();
    assert!(!engine.is_paused());

    // Bypass flag round-trip.
    engine.set_bypass_incoming_followers(&rig.protected, false);
    assert!(!engine.bypass_incoming_followers(&rig.protected));
    engine.set_bypass_incoming_followers(&rig.protected, true);
    assert!(engine.bypass_incoming_followers(&rig.protected));

    // Hydration helpers.
    let n = engine.hydrate_follows("did:plc:h", ["did:plc:a", "did:plc:b"]);
    assert_eq!(n, 2);
    assert!(engine.is_following("did:plc:h", "did:plc:a"));

    let n =
        engine.hydrate_follow_records("did:plc:h2", [("rk1", "did:plc:c"), ("rk2", "did:plc:d")]);
    assert_eq!(n, 2);
    assert!(engine.is_following("did:plc:h2", "did:plc:c"));

    let n = engine.hydrate_followers("did:plc:h3", ["did:plc:e"]);
    assert_eq!(n, 1);

    // Persist stats returns Ok on the in-memory cache.
    engine.persist_stats().expect("persist stats");
}

#[tokio::test]
async fn engine_tenant_ops_paths() {
    let rig = build_rig(Verdict::permitted("ok"), None, false).await;
    let engine = &rig.engine;

    // is_admin: configured admin only; empty/unknown are not admin.
    assert!(!engine.is_admin(""));
    assert!(!engine.is_admin("did:plc:someone"));

    // Enroll a tenant, then it is enrolled and its rubric is returned.
    use skybouncer::tenant::Tenant;
    let tenant =
        Tenant::new("did:plc:enrolled").with_rubric(skybouncer::classifier::RuleRubric::new(
            "Enrolled rules",
            skybouncer::classifier::Sensitivity::High,
        ));
    engine.enroll_tenant(tenant).expect("enroll");
    assert!(engine.is_enrolled("did:plc:enrolled"));
    assert_eq!(
        engine.rubric_for("did:plc:enrolled").prompt,
        "Enrolled rules"
    );
    // Unknown DID falls back to engine default rubric.
    assert_eq!(
        engine.rubric_for("did:plc:nobody").prompt,
        engine.rubric().prompt
    );

    // is_tenant_paused: engine-wide pause affects any tenant.
    let _ = engine.pause();
    assert!(engine.is_tenant_paused("did:plc:enrolled"));
    let _ = engine.resume();
    assert!(!engine.is_tenant_paused("did:plc:nobody"));

    // resolve_pds_client_for: the fallback client DID resolves directly.
    let fallback_did = engine.pds_client().did().to_string();
    assert!(engine.resolve_pds_client_for(&fallback_did).await.is_ok());
    // pds_client_for always returns a client (fallback on error).
    let _ = engine.pds_client_for("did:plc:unknown").await;
}

#[tokio::test]
async fn engine_lifecycle_run_pipeline_spawn_and_drain() {
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;

    let rig = build_rig(Verdict::permitted("ok"), None, false).await;
    let engine = &rig.engine;

    // run_pipeline: feed no commits and cancel immediately.
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let _ = engine.run_pipeline(rx, cancel).await;

    // spawn_in_join_set returns a sender; drain_and_shutdown cancels the worker.
    let mut join_set: JoinSet<
        Result<skybouncer::engine::EngineStatsSnapshot, skybouncer::SkybouncerError>,
    > = JoinSet::new();
    let cancel2 = CancellationToken::new();
    let _tx = engine.spawn_in_join_set(&mut join_set, cancel2.clone());
    cancel2.cancel();
    skybouncer::engine::SkybouncerEngine::drain_and_shutdown(
        &mut join_set,
        &cancel2,
        std::time::Duration::from_secs(2),
    )
    .await
    .expect("drain");
}

#[tokio::test]
async fn engine_lifecycle_maintenance_and_prune() {
    use tokio_util::sync::CancellationToken;

    let rig = build_rig(Verdict::permitted("ok"), None, false).await;
    let engine = &rig.engine;

    // No expired bounces => prune returns 0.
    assert_eq!(engine.prune_expired_bounces().await.unwrap(), 0);

    // run_maintenance runs at least one tick then stops on cancel.
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    let maint = tokio::spawn({
        let engine = rig.engine.clone();
        async move {
            let _ = engine
                .run_maintenance(std::time::Duration::from_millis(10), c2)
                .await;
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    cancel.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), maint).await;

    // persist_stats is callable on an in-memory cache.
    engine.persist_stats().expect("persist");
}

#[test]
fn config_from_env_reads_fallback_model_and_flags() {
    // Isolate and set the fallback-model + heuristic env vars.
    for k in [
        "FALLBACK_MODEL",
        "SKYBOUNCER_FALLBACK_MODEL",
        "FALLBACK_API_BASE_URL",
        "FALLBACK_API_KEY",
        "FALLBACK_TIMEOUT_MS",
        "FALLBACK_MAX_RETRIES",
        "ENABLE_HEURISTIC_PREFILTER",
        "SKYBOUNCER_ENABLE_HEURISTIC_PREFILTER",
        "DRY_RUN",
        "SKYBOUNCER_DRY_RUN",
        "PROTECTED_DIDS",
        "SKYBOUNCER_PROTECTED_DIDS",
        "ADMIN_DID",
        "SKYBOUNCER_ADMIN_DID",
    ] {
        std::env::remove_var(k);
    }
    std::env::set_var("FALLBACK_MODEL", "vision-model");
    std::env::set_var("FALLBACK_API_BASE_URL", "http://localhost:9999");
    std::env::set_var("FALLBACK_TIMEOUT_MS", "1234");
    std::env::set_var("FALLBACK_MAX_RETRIES", "3");
    std::env::set_var("ENABLE_HEURISTIC_PREFILTER", "1");
    std::env::set_var("DRY_RUN", "true");
    std::env::set_var("PROTECTED_DIDS", "did:plc:a, did:plc:b");

    let cfg = SkybouncerConfig::from_env().expect("from_env");
    let fb = cfg.fallback_jev_config.expect("fallback configured");
    assert_eq!(fb.model, "vision-model");
    assert_eq!(fb.base_url, "http://localhost:9999");
    assert_eq!(fb.timeout.as_millis(), 1234);
    assert_eq!(fb.max_retries, 3);
    assert!(cfg.enable_heuristic_prefilter);
    assert!(cfg.dry_run);
    assert_eq!(cfg.protected_dids.len(), 2);

    for k in [
        "FALLBACK_MODEL",
        "FALLBACK_API_BASE_URL",
        "FALLBACK_TIMEOUT_MS",
        "FALLBACK_MAX_RETRIES",
        "ENABLE_HEURISTIC_PREFILTER",
        "DRY_RUN",
        "PROTECTED_DIDS",
    ] {
        std::env::remove_var(k);
    }
}

#[tokio::test]
async fn engine_new_direct_constructor_branches() {
    use skybouncer::matcher::{FollowGraph, NonFollowedGate};
    use skybouncer::modlist::{DeduplicationCache, ModListManager};

    let pds = common::MockPdsServer::start().await;
    let cache = std::sync::Arc::new(DeduplicationCache::open_in_memory().unwrap());
    // Preload an allowlist entry so the constructor's allowlist-loading loop runs.
    cache
        .add_to_allowlist("did:plc:alice", "did:plc:trusted", Some("t"))
        .unwrap();

    let follow_graph = std::sync::Arc::new(FollowGraph::new());
    let gate = std::sync::Arc::new(NonFollowedGate::new(std::sync::Arc::clone(&follow_graph)));
    let mut rubric = skybouncer::classifier::RuleRubric::new("Block spam", Sensitivity::Medium);
    rubric.bypass_incoming_followers = true;
    // Non-dry-run manager + dry_run config => constructor force-enables manager dry-run.
    let modlist = std::sync::Arc::new(
        ModListManager::from_shared_cache(std::sync::Arc::clone(&cache))
            .with_rubric(rubric.clone()),
    );
    let pds_client = std::sync::Arc::new(pds.pds_client("did:plc:alice"));
    let classifier = std::sync::Arc::new(MockClassifier::new(Verdict::permitted("ok")));

    let mut dids = HashSet::new();
    dids.insert("did:plc:alice".to_string());
    let config = SkybouncerConfig::new(dids, rubric).with_dry_run(true);

    let engine = SkybouncerEngine::new(config, follow_graph, gate, classifier, modlist, pds_client);
    assert!(engine.is_dry_run());
    assert!(engine.is_allowlisted("did:plc:alice", "did:plc:trusted"));
}
