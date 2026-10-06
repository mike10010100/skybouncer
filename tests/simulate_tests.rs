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
