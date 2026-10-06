//! Adversarial Empirical Challenge Suite for Milestone M1 (R1 & R2).
//!
//! Written by Challenger M1 (Instance 2) to stress-test:
//! 1. Concurrent multi-tenant rubric isolation (no race conditions or rubric leakage).
//! 2. Sovereign config deletion isolation in multi-tenant deployments.
//! 3. Serde backwards-compatibility with missing/legacy interaction payloads.
//! 4. Per-tenant sensitivity thresholds and borderline confidence scores.
//! 5. Lifecycle churn: register -> customize -> delete (reset) -> re-customize.
//! 6. Fallback invariants for unregistered tenants and tenants with rubric: None.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::task::JoinSet;

use skyauth::dpop::DPoPKey;
use skyauth::session::OAuthSession;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};
use skybouncer::classifier::{MockClassifier, RuleRubric, Sensitivity, Verdict, ViolationCategory};
use skybouncer::engine::{
    InteractionOutcome, ProcessCommitResult, SkybouncerConfig, SkybouncerEngine,
    SovereignConfigSyncEvent,
};
use skybouncer::matcher::{Interaction, InteractionType};
use skybouncer::modlist::manager::ModListManager;
use skybouncer::modlist::DeduplicationCache;
use skybouncer::tenant::Tenant;

use async_trait::async_trait;
use skybouncer::classifier::Classifier;
use skybouncer::error::SkybouncerError;

/// Helper to build an in-memory engine with a custom classifier.
fn create_test_engine(
    protected_dids: HashSet<String>,
    global_rubric: RuleRubric,
    classifier: Arc<dyn Classifier>,
) -> Arc<SkybouncerEngine> {
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let modlist = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(global_rubric.clone())
            .with_dry_run(true),
    );
    let config = SkybouncerConfig::new(protected_dids, global_rubric).with_dry_run(true);

    Arc::new(
        SkybouncerEngine::builder(config)
            .with_cache(cache)
            .with_modlist_manager(modlist)
            .with_classifier(classifier)
            .build()
            .unwrap(),
    )
}

#[derive(Debug)]
struct ContentAndRubricClassifier;

#[async_trait]
impl Classifier for ContentAndRubricClassifier {
    async fn classify_with_rubric(
        &self,
        interaction: &Interaction,
        rubric: Option<&RuleRubric>,
    ) -> Result<Verdict, SkybouncerError> {
        let r = rubric
            .or(interaction.rubric.as_ref())
            .expect("Rubric must be provided");
        let prompt = r.prompt.to_lowercase();
        let text = interaction.text.to_lowercase();

        if prompt.contains("ban crypto") && text.contains("crypto") {
            return Ok(Verdict::violation(
                ViolationCategory::CryptoSpam,
                0.95,
                "Tenant custom: Crypto banned",
            ));
        }
        if prompt.contains("ban politics") && text.contains("politics") {
            return Ok(Verdict::violation(
                ViolationCategory::Harassment,
                0.95,
                "Tenant custom: Politics banned",
            ));
        }

        Ok(Verdict::permitted("Conforms to tenant rubric"))
    }
}

/// Helper to generate a valid mock OAuthSession for multi-tenant PDS client resolution.
fn mock_session(did: &str) -> OAuthSession {
    let dpop_key = DPoPKey::generate();
    OAuthSession::new(
        did,
        "at-valid-token",
        Some("rt-refresh-token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        dpop_key,
        Some("https://pds.example.com".to_string()),
        Some("https://auth.example.com".to_string()),
        Some("https://auth.example.com/token".to_string()),
    )
    .unwrap()
}

/// Helper to generate a test interaction.
fn make_interaction(target_did: &str, author_did: &str, post_id: &str, text: &str) -> Interaction {
    Interaction {
        post_uri: format!("at://{author_did}/app.bsky.feed.post/{post_id}"),
        post_cid: Some("bafytestcid123".to_string()),
        author_did: author_did.to_string(),
        target_did: target_did.to_string(),
        text: text.to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: Some(format!("at://{target_did}/app.bsky.feed.post/root")),
        root_uri: Some(format!("at://{target_did}/app.bsky.feed.post/root")),
        created_at_us: 1_700_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    }
}

/// Challenge 1: Multi-Tenant Concurrent Evaluation with Diametrically Opposed Rubrics.
///
/// Tenant Alpha: BANS "crypto", PERMITS "politics".
/// Tenant Beta: BANS "politics", PERMITS "crypto".
///
/// 100 concurrent tasks evaluate interactions alternating between Alpha and Beta.
/// Under high concurrency, there MUST BE ZERO cross-tenant rubric bleeding:
/// - "crypto" sent to Alpha MUST be Bounced.
/// - "crypto" sent to Beta MUST be Permitted.
/// - "politics" sent to Alpha MUST be Permitted.
/// - "politics" sent to Beta MUST be Bounced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_adversarial_concurrent_multi_tenant_rubric_isolation() {
    let alpha_did = "did:plc:tenant_alpha";
    let beta_did = "did:plc:tenant_beta";

    let mut protected_dids = HashSet::new();
    protected_dids.insert(alpha_did.to_string());
    protected_dids.insert(beta_did.to_string());

    let global_rubric = RuleRubric::new("Global: Neutral fallback", Sensitivity::Medium);

    let classifier = Arc::new(ContentAndRubricClassifier);
    let engine = create_test_engine(protected_dids, global_rubric, classifier);

    // Register Tenant Alpha: anti-crypto rubric + active session
    let alpha_rubric = RuleRubric::new(
        "Tenant Alpha: strictly ban crypto, politics is allowed",
        Sensitivity::High,
    );
    let alpha_tenant = Tenant::new(alpha_did)
        .with_rubric(alpha_rubric)
        .with_session(mock_session(alpha_did));
    engine
        .tenant_registry()
        .register_or_update(&alpha_tenant)
        .unwrap();

    // Register Tenant Beta: anti-politics rubric + active session
    let beta_rubric = RuleRubric::new(
        "Tenant Beta: strictly ban politics, crypto is allowed",
        Sensitivity::High,
    );
    let beta_tenant = Tenant::new(beta_did)
        .with_rubric(beta_rubric)
        .with_session(mock_session(beta_did));
    engine
        .tenant_registry()
        .register_or_update(&beta_tenant)
        .unwrap();

    let alpha_bounced = Arc::new(AtomicUsize::new(0));
    let alpha_permitted = Arc::new(AtomicUsize::new(0));
    let beta_bounced = Arc::new(AtomicUsize::new(0));
    let beta_permitted = Arc::new(AtomicUsize::new(0));

    let mut join_set = JoinSet::new();

    // Spawn 100 concurrent evaluations
    for i in 0..100 {
        let eng = Arc::clone(&engine);
        let a_b = Arc::clone(&alpha_bounced);
        let a_p = Arc::clone(&alpha_permitted);
        let b_b = Arc::clone(&beta_bounced);
        let b_p = Arc::clone(&beta_permitted);

        join_set.spawn(async move {
            let author = format!("did:plc:author_{i}");
            if i % 4 == 0 {
                // Crypto sent to Alpha -> Expect BOUNCE
                let item = make_interaction(alpha_did, &author, &format!("post_{i}"), "Crypto!");
                let res = eng.process_interaction(item).await.unwrap();
                if matches!(res, InteractionOutcome::Bounced { .. }) {
                    a_b.fetch_add(1, Ordering::Relaxed);
                }
            } else if i % 4 == 1 {
                // Politics sent to Alpha -> Expect PERMITTED
                let item = make_interaction(alpha_did, &author, &format!("post_{i}"), "Politics!");
                let res = eng.process_interaction(item).await.unwrap();
                if matches!(res, InteractionOutcome::Permitted { .. }) {
                    a_p.fetch_add(1, Ordering::Relaxed);
                }
            } else if i % 4 == 2 {
                // Crypto sent to Beta -> Expect PERMITTED
                let item = make_interaction(beta_did, &author, &format!("post_{i}"), "Crypto!");
                let res = eng.process_interaction(item).await.unwrap();
                if matches!(res, InteractionOutcome::Permitted { .. }) {
                    b_p.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                // Politics sent to Beta -> Expect BOUNCE
                let item = make_interaction(beta_did, &author, &format!("post_{i}"), "Politics!");
                let res = eng.process_interaction(item).await.unwrap();
                if matches!(res, InteractionOutcome::Bounced { .. }) {
                    b_b.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    while let Some(res) = join_set.join_next().await {
        res.unwrap();
    }

    assert_eq!(alpha_bounced.load(Ordering::Relaxed), 25);
    assert_eq!(alpha_permitted.load(Ordering::Relaxed), 25);
    assert_eq!(beta_permitted.load(Ordering::Relaxed), 25);
    assert_eq!(beta_bounced.load(Ordering::Relaxed), 25);
}

/// Challenge 2: Sovereign Config Deletion Isolation in Multi-Tenant Fleet.
///
/// In a multi-tenant setup with Tenant Alpha and Tenant Beta both having custom rubrics:
/// When a delete commit arrives for Tenant Alpha, ONLY Tenant Alpha's rubric must reset to default.
/// Tenant Beta's custom rubric MUST REMAIN INTACT.
#[tokio::test]
async fn test_adversarial_sovereign_config_deletion_multi_tenant_isolation() {
    let alpha_did = "did:plc:tenant_alpha_delete";
    let beta_did = "did:plc:tenant_beta_survive";

    let mut protected_dids = HashSet::new();
    protected_dids.insert(alpha_did.to_string());
    protected_dids.insert(beta_did.to_string());

    let default_rubric = RuleRubric::new("Default fleet rules", Sensitivity::Medium);
    let classifier = Arc::new(MockClassifier::permitted());
    let engine = create_test_engine(protected_dids, default_rubric.clone(), classifier);

    // Register both with custom rubrics
    let alpha_custom = RuleRubric::new("Alpha custom rules", Sensitivity::High);
    let beta_custom = RuleRubric::new("Beta custom rules", Sensitivity::Low);

    engine
        .tenant_registry()
        .register_or_update(&Tenant::new(alpha_did).with_rubric(alpha_custom))
        .unwrap();
    engine
        .tenant_registry()
        .register_or_update(&Tenant::new(beta_did).with_rubric(beta_custom))
        .unwrap();

    assert_eq!(engine.rubric_for(alpha_did).prompt, "Alpha custom rules");
    assert_eq!(engine.rubric_for(beta_did).prompt, "Beta custom rules");

    // Send Delete commit for Alpha only
    let delete_commit = JetstreamCommit {
        did: alpha_did.to_string(),
        time_us: 1_700_000_000_000_000,
        collection: skybouncer::modlist::SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: skybouncer::modlist::SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };

    let result = engine.process_commit(&delete_commit).await.unwrap();
    assert_eq!(
        result,
        ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted {
            did: alpha_did.to_string(),
        })
    );

    // Alpha must be reset to default
    assert_eq!(
        engine.rubric_for(alpha_did).prompt,
        "Default fleet rules",
        "Alpha rubric must reset to default"
    );

    // Beta must remain completely unchanged
    assert_eq!(
        engine.rubric_for(beta_did).prompt,
        "Beta custom rules",
        "Beta rubric must NOT be affected by Alpha's deletion!"
    );
}

/// Challenge 3: Delete Commit with Non-Matching rkey Must Be Ignored.
///
/// If a delete commit arrives for `social.skybouncer.config` but with an rkey
/// different from `self`, the tenant's rubric must NOT be reset.
#[tokio::test]
async fn test_adversarial_sovereign_config_deletion_foreign_rkey_ignored() {
    let did = "did:plc:alice_foreign_rkey";
    let mut protected_dids = HashSet::new();
    protected_dids.insert(did.to_string());

    let default_rubric = RuleRubric::new("Default rules", Sensitivity::Medium);
    let custom_rubric = RuleRubric::new("Alice custom rules", Sensitivity::High);
    let classifier = Arc::new(MockClassifier::permitted());

    let engine = create_test_engine(protected_dids, default_rubric, classifier);
    engine
        .tenant_registry()
        .register_or_update(&Tenant::new(did).with_rubric(custom_rubric))
        .unwrap();

    let foreign_delete_commit = JetstreamCommit {
        did: did.to_string(),
        time_us: 1_700_000_000_000_000,
        collection: skybouncer::modlist::SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: "some_other_rkey".to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };

    let result = engine.process_commit(&foreign_delete_commit).await.unwrap();
    assert_eq!(result, ProcessCommitResult::Ignored);

    // Rubric must NOT have been reset
    assert_eq!(
        engine.rubric_for(did).prompt,
        "Alice custom rules",
        "Foreign rkey deletion must not reset rubric"
    );
}

/// Challenge 4: Tenant Fallback Invariants.
///
/// 1. Tenant enrolled with `rubric: None` -> returns default rubric.
/// 2. Protected DID not in tenant registry -> returns default rubric.
#[tokio::test]
async fn test_adversarial_tenant_fallback_invariants() {
    let enrolled_none_did = "did:plc:enrolled_with_none";
    let unenrolled_did = "did:plc:unenrolled_protected";

    let mut protected_dids = HashSet::new();
    protected_dids.insert(enrolled_none_did.to_string());
    protected_dids.insert(unenrolled_did.to_string());

    let default_rubric = RuleRubric::new("Fleet Default Prompt", Sensitivity::Low);
    let classifier = Arc::new(MockClassifier::permitted());
    let engine = create_test_engine(protected_dids, default_rubric.clone(), classifier);

    // Enroll with rubric = None
    engine
        .tenant_registry()
        .register_or_update(&Tenant::new(enrolled_none_did))
        .unwrap();

    // 1. Enrolled tenant with rubric: None returns default
    let r1 = engine.rubric_for(enrolled_none_did);
    assert_eq!(r1.prompt, "Fleet Default Prompt");
    assert_eq!(r1.sensitivity, Sensitivity::Low);

    // 2. Unenrolled protected DID returns default
    let r2 = engine.rubric_for(unenrolled_did);
    assert_eq!(r2.prompt, "Fleet Default Prompt");
    assert_eq!(r2.sensitivity, Sensitivity::Low);
}

/// Challenge 5: Per-Tenant Sensitivity Threshold Enforcement.
///
/// Tenant High has Sensitivity::High (threshold 0.70).
/// Tenant Low has Sensitivity::Low (threshold 0.90).
/// When classifier outputs a violation with confidence 0.80:
/// - Tenant High: 0.80 >= 0.70 -> Bounced!
/// - Tenant Low: 0.80 < 0.90 -> BelowThreshold!
#[tokio::test]
async fn test_adversarial_per_tenant_sensitivity_threshold_enforcement() {
    let high_did = "did:plc:tenant_high_sens";
    let low_did = "did:plc:tenant_low_sens";

    let mut protected_dids = HashSet::new();
    protected_dids.insert(high_did.to_string());
    protected_dids.insert(low_did.to_string());

    let default_rubric = RuleRubric::new("Default", Sensitivity::Medium);

    // Classifier returns a violation with confidence 0.80 (>= High 0.60, >= Default Medium 0.75, < Low 0.90)
    let classifier = Arc::new(MockClassifier::new(Verdict::violation(
        ViolationCategory::Spam,
        0.80,
        "Moderate spam confidence",
    )));

    let engine = create_test_engine(protected_dids, default_rubric, classifier);

    // Register High Sensitivity (0.60 threshold) with valid session
    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(high_did)
                .with_rubric(RuleRubric::new("High Sensitivity Rules", Sensitivity::High))
                .with_session(mock_session(high_did)),
        )
        .unwrap();

    // Register Low Sensitivity (0.90 threshold) with valid session
    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(low_did)
                .with_rubric(RuleRubric::new("Low Sensitivity Rules", Sensitivity::Low))
                .with_session(mock_session(low_did)),
        )
        .unwrap();

    let author_did = "did:plc:spammer_author";

    // 1. Evaluate against High Sensitivity target -> Bounced!
    let item_high = make_interaction(high_did, author_did, "post_1", "spam text");
    let outcome_high = engine.process_interaction(item_high).await.unwrap();
    assert!(
        matches!(outcome_high, InteractionOutcome::Bounced { .. }),
        "Expected Bounced for Sensitivity::High with confidence 0.80 >= 0.60, got {outcome_high:?}"
    );

    // 2. Evaluate against Low Sensitivity target -> BelowThreshold!
    let item_low = make_interaction(low_did, author_did, "post_2", "spam text");
    let outcome_low = engine.process_interaction(item_low).await.unwrap();
    assert!(
        matches!(outcome_low, InteractionOutcome::BelowThreshold { .. }),
        "Expected BelowThreshold for Sensitivity::Low with confidence 0.80 < 0.90"
    );
}

/// Challenge 5b (Empirical Defect Proof): ModListManager Internal Global Rubric Shadows Tenant Rubric.
///
/// Demonstrates that when a tenant has Sensitivity::High (threshold 0.60) in a deployment where the
/// fleet default rubric has Sensitivity::Medium (threshold 0.75), a violation with confidence 0.70
/// (which is actionable under the tenant's rubric) passes `act_on_verdict`'s tenant rubric check,
/// but is rejected by `ModListManager::bounce` (which checks its internal global rubric).
/// `act_on_verdict` then misinterprets the `Ok(None)` return value as a double-checked lock collision
/// and falsely returns `InteractionOutcome::AlreadyBounced` even though the author was never bounced!
#[tokio::test]
async fn test_empirical_proof_modlist_manager_shadows_tenant_sensitivity_threshold() {
    let high_did = "did:plc:tenant_high_sens_leak";
    let author_did = "did:plc:first_time_violator";

    let mut protected_dids = HashSet::new();
    protected_dids.insert(high_did.to_string());

    // Engine default rubric is Medium (0.75 threshold)
    let default_rubric = RuleRubric::new("Fleet Default", Sensitivity::Medium);

    // Classifier outputs confidence 0.70 (>= High 0.60, but < Fleet Medium 0.75)
    let classifier = Arc::new(MockClassifier::new(Verdict::violation(
        ViolationCategory::Spam,
        0.70,
        "Offending message with 0.70 confidence",
    )));

    let engine = create_test_engine(protected_dids, default_rubric, classifier);

    // Register tenant with High Sensitivity (0.60 threshold)
    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(high_did)
                .with_rubric(RuleRubric::new("High Sensitivity Rules", Sensitivity::High))
                .with_session(mock_session(high_did)),
        )
        .unwrap();

    let item = make_interaction(high_did, author_did, "post_1", "spam text");
    let outcome = engine.process_interaction(item).await.unwrap();

    // EMPIRICALLY CONFIRMED ARCHITECTURAL DEFECT:
    // Expected behavior: Bounced (since 0.70 >= High 0.60 threshold).
    // Actual defect behavior: AlreadyBounced (swallowed by ModListManager's check against fleet default).
    assert_eq!(
        outcome,
        InteractionOutcome::AlreadyBounced {
            author_did: author_did.to_string(),
            target_did: high_did.to_string(),
        },
        "Defect empirically verified: ModListManager global rubric shadows tenant rubric!"
    );

    // Furthermore, the violator was NEVER actually recorded in the cache!
    assert!(
        !engine.cache().is_bounced_for(high_did, author_did).unwrap(),
        "Violator was never bounced in cache despite outcome claiming AlreadyBounced!"
    );
}

/// Challenge 6: Serde Backwards Compatibility for Interaction Payloads.
///
/// Ensure that:
/// 1. An Interaction serialized WITHOUT the `rubric` field (legacy JSON)
///    successfully deserializes with `rubric: None`.
/// 2. An Interaction serialized WITH a rubric round-trips with full fidelity.
#[test]
fn test_adversarial_interaction_serde_backwards_compatibility() {
    let legacy_json = r#"{
        "post_uri": "at://did:plc:author/app.bsky.feed.post/123",
        "post_cid": "bafytest",
        "author_did": "did:plc:author",
        "target_did": "did:plc:target",
        "text": "Hello world",
        "interaction_type": "direct_reply",
        "created_at_us": 1700000000000000,
        "image_cids": [],
        "image_alts": []
    }"#;

    let deserialized: Interaction =
        serde_json::from_str(legacy_json).expect("Legacy Interaction JSON must deserialize");
    assert_eq!(deserialized.rubric, None);

    // Now test round-trip with rubric present
    let rubric = RuleRubric::new("Strict test prompt", Sensitivity::High);
    let modern_interaction = deserialized.with_rubric(rubric.clone());
    let serialized = serde_json::to_string(&modern_interaction).expect("Serialization must work");
    let roundtrip: Interaction =
        serde_json::from_str(&serialized).expect("Round-trip deserialization must work");

    assert_eq!(roundtrip.rubric, Some(rubric));
}

/// Challenge 7: Full Lifecycle Churn: Register -> Update Rubric -> Delete (Reset) -> Re-update.
///
/// Asserts that state machine transitions between custom and default rubrics are idempotent
/// and don't leak or leave orphaned state.
#[tokio::test]
async fn test_adversarial_rubric_lifecycle_churn() {
    let did = "did:plc:churn_tenant";
    let mut protected_dids = HashSet::new();
    protected_dids.insert(did.to_string());

    let default_rubric = RuleRubric::new("Base default", Sensitivity::Medium);
    let classifier = Arc::new(MockClassifier::permitted());
    let engine = create_test_engine(protected_dids, default_rubric.clone(), classifier);

    // 1. Initial enrollment without rubric
    engine
        .tenant_registry()
        .register_or_update(&Tenant::new(did))
        .unwrap();
    assert_eq!(engine.rubric_for(did).prompt, "Base default");

    // 2. Firehose update commit (sovereign config created)
    let create_commit = JetstreamCommit {
        did: did.to_string(),
        time_us: 1_700_000_000_000_000,
        collection: skybouncer::modlist::SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: skybouncer::modlist::SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyconfig1".to_string()),
        record: Some(serde_json::json!({
            "$type": "social.skybouncer.config",
            "rules": "Custom prompt 1",
            "sensitivity": "high",
            "updatedAt": "2026-10-04T00:00:00Z"
        })),
    };
    engine.process_commit(&create_commit).await.unwrap();
    assert_eq!(engine.rubric_for(did).prompt, "Custom prompt 1");
    assert_eq!(engine.rubric_for(did).sensitivity, Sensitivity::High);

    // 3. Firehose delete commit (sovereign config deleted)
    let delete_commit = JetstreamCommit {
        did: did.to_string(),
        time_us: 1_700_000_001_000_000,
        collection: skybouncer::modlist::SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: skybouncer::modlist::SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };
    engine.process_commit(&delete_commit).await.unwrap();
    assert_eq!(engine.rubric_for(did).prompt, "Base default");
    assert_eq!(engine.rubric_for(did).sensitivity, Sensitivity::Medium);

    // 4. Repeated delete commit (idempotent delete)
    let repeat_delete = engine.process_commit(&delete_commit).await.unwrap();
    assert_eq!(
        repeat_delete,
        ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted {
            did: did.to_string(),
        })
    );
    assert_eq!(engine.rubric_for(did).prompt, "Base default");

    // 5. Firehose re-create with new rules
    let recreate_commit = JetstreamCommit {
        did: did.to_string(),
        time_us: 1_700_000_002_000_000,
        collection: skybouncer::modlist::SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: skybouncer::modlist::SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyconfig2".to_string()),
        record: Some(serde_json::json!({
            "$type": "social.skybouncer.config",
            "rules": "Custom prompt 2",
            "sensitivity": "low",
            "updatedAt": "2026-10-04T00:01:00Z"
        })),
    };
    engine.process_commit(&recreate_commit).await.unwrap();
    assert_eq!(engine.rubric_for(did).prompt, "Custom prompt 2");
    assert_eq!(engine.rubric_for(did).sensitivity, Sensitivity::Low);
}
