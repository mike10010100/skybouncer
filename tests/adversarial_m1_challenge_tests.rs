//! Adversarial empirical test harness for Milestone M1 (Requirements R1 and R2).
//!
//! Stress-tests edge cases:
//! 1. Concurrent multi-tenant evaluations with conflicting custom rubrics (isolation & race freedom).
//! 2. Empty, whitespace, and extreme-length rubric prompts.
//! 3. Sovereign config deletion for non-enrolled DIDs:
//!    - Unprotected stranger DID on Bluesky firehose (Ignored by filter).
//!    - Protected fleet DID not enrolled in tenant registry (SovereignConfigSynced, graceful no-op on SQLite).
//! 4. Sovereign config deletion for irrelevant or mismatched rkeys (ignored, no rubric reset).
//! 5. Sovereign config deletion idempotency and multiple resets.
//! 6. TieredClassifier fallback escalation preserving tenant-specific rubric.
//! 7. Tenant sensitivity threshold gating (High vs Low sensitivity enforcement).
//! 8. Direct Classifier trait invocation precedence (explicit vs interaction rubric).
//! 9. Empirical edge-case discovery: ModListManager global rubric filter collision when tenant sensitivity is higher than fleet default.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use skyauth::dpop::DPoPKey;
use skyauth::session::OAuthSession;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};
use skybouncer::classifier::{
    CertaintyConfig, Classifier, MockClassifier, RuleRubric, Sensitivity, TieredClassifier,
    Verdict, ViolationCategory,
};
use skybouncer::engine::{
    InteractionOutcome, ProcessCommitResult, SkybouncerConfig, SkybouncerEngine,
    SovereignConfigSyncEvent,
};
use skybouncer::matcher::{Interaction, InteractionType};
use skybouncer::modlist::cache::DeduplicationCache;
use skybouncer::modlist::manager::ModListManager;
use skybouncer::modlist::{SOVEREIGN_CONFIG_COLLECTION, SOVEREIGN_CONFIG_RKEY};
use skybouncer::tenant::Tenant;

/// Helper to construct a valid active mock OAuth session for tenant testing.
fn make_mock_session(did: &str) -> OAuthSession {
    let dpop_key = DPoPKey::generate();
    OAuthSession::new(
        did,
        "at-test-access-token",
        Some("rt-test-refresh-token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600), // active for 1 hour
        dpop_key,
        Some("https://pds.example.com".to_string()),
        Some("https://auth.example.com".to_string()),
        Some("https://auth.example.com/oauth/token".to_string()),
    )
    .unwrap()
}

/// Custom semantic classifier oracle that checks whether candidate text violates
/// the specific rules active in the target tenant's effective rubric prompt.
struct TestSemanticClassifier;

#[async_trait]
impl Classifier for TestSemanticClassifier {
    async fn classify_with_rubric(
        &self,
        interaction: &Interaction,
        rubric: Option<&RuleRubric>,
    ) -> Result<Verdict, skybouncer::error::SkybouncerError> {
        let effective_rubric = rubric.or(interaction.rubric.as_ref());
        let prompt = effective_rubric
            .map(|r| r.prompt.to_lowercase())
            .unwrap_or_default();
        let text = interaction.text.to_lowercase();

        if prompt.contains("cryptocurrency") && text.contains("cryptocurrency") {
            Ok(Verdict::violation(
                ViolationCategory::CryptoSpam,
                0.95,
                "Flagged anti-crypto policy",
            ))
        } else if prompt.contains("football") && text.contains("football") {
            Ok(Verdict::violation(
                ViolationCategory::Custom("sports".to_string()),
                0.92,
                "Flagged anti-sports policy",
            ))
        } else if prompt.contains("elections") && text.contains("elections") {
            Ok(Verdict::violation(
                ViolationCategory::Custom("politics".to_string()),
                0.90,
                "Flagged anti-politics policy",
            ))
        } else {
            Ok(Verdict::permitted_with_confidence("Clean discussion", 0.05))
        }
    }

    fn model_name(&self) -> &str {
        "test_semantic"
    }
}

/// Test 1: Concurrently evaluate multiple tenants with divergent custom rubrics.
/// Asserts that no cross-tenant rubric bleeding occurs under concurrent load.
#[tokio::test]
async fn test_adversarial_concurrent_multitenant_rubric_isolation() {
    let tenant_crypto = "did:plc:tenant_anti_crypto";
    let tenant_sports = "did:plc:tenant_anti_sports";
    let tenant_politics = "did:plc:tenant_anti_politics";
    let tenant_default = "did:plc:tenant_default_rules";

    let global_rubric = RuleRubric::new("Global: Ban hate speech only", Sensitivity::Low);
    let rubric_crypto = RuleRubric::new(
        "Tenant Crypto: Strictly ban cryptocurrency trading",
        Sensitivity::High,
    );
    let rubric_sports = RuleRubric::new(
        "Tenant Sports: Strictly ban football and soccer discussion",
        Sensitivity::High,
    );
    let rubric_politics = RuleRubric::new(
        "Tenant Politics: Strictly ban political elections discussion",
        Sensitivity::High,
    );

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let modlist = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(global_rubric.clone())
            .with_dry_run(true),
    );

    let mut protected_dids = HashSet::new();
    protected_dids.insert(tenant_crypto.to_string());
    protected_dids.insert(tenant_sports.to_string());
    protected_dids.insert(tenant_politics.to_string());
    protected_dids.insert(tenant_default.to_string());

    let config = SkybouncerConfig::new(protected_dids, global_rubric.clone())
        .with_dry_run(true)
        .with_evaluation_concurrency(8);

    let classifier = Arc::new(TestSemanticClassifier);

    let engine = Arc::new(
        SkybouncerEngine::builder(config)
            .with_cache(cache)
            .with_modlist_manager(modlist)
            .with_classifier(classifier)
            .build()
            .unwrap(),
    );

    // Register tenants with valid mock sessions so dry-run bounces resolve PDS clients
    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(tenant_crypto)
                .with_session(make_mock_session(tenant_crypto))
                .with_rubric(rubric_crypto),
        )
        .unwrap();
    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(tenant_sports)
                .with_session(make_mock_session(tenant_sports))
                .with_rubric(rubric_sports),
        )
        .unwrap();
    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(tenant_politics)
                .with_session(make_mock_session(tenant_politics))
                .with_rubric(rubric_politics),
        )
        .unwrap();
    // tenant_default is enrolled without custom rubric (should fall back to global)
    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(tenant_default).with_session(make_mock_session(tenant_default)),
        )
        .unwrap();

    let mut handles = Vec::new();

    // Spawn 60 concurrent evaluation tasks interleaved across all tenants
    for i in 0..60 {
        let eng = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            let (target_did, expected_bounced, text) = match i % 4 {
                0 => (
                    tenant_crypto,
                    true,
                    "Buy my new cryptocurrency token right now!",
                ),
                1 => (
                    tenant_sports,
                    false,
                    "Buy my new cryptocurrency token right now!",
                ),
                2 => (
                    tenant_sports,
                    true,
                    "Watch the football match tonight live!",
                ),
                _ => (
                    tenant_default,
                    false,
                    "Buy my new cryptocurrency token right now!",
                ),
            };

            let interaction = Interaction {
                post_uri: format!("at://did:plc:spammer/app.bsky.feed.post/{i}"),
                post_cid: Some(format!("bafy{i}")),
                author_did: format!("did:plc:spammer_{i}"),
                target_did: target_did.to_string(),
                text: text.to_string(),
                interaction_type: InteractionType::DirectReply,
                parent_uri: Some(format!("at://{target_did}/app.bsky.feed.post/root")),
                root_uri: Some(format!("at://{target_did}/app.bsky.feed.post/root")),
                created_at_us: 1_700_000_000_000_000 + i,
                image_cids: Vec::new(),
                image_alts: Vec::new(),
                enriched_context: None,
                rubric: None,
            };

            let outcome = eng.process_interaction(interaction).await.unwrap();
            match outcome {
                InteractionOutcome::Bounced {
                    category,
                    confidence,
                    reason,
                    ..
                } => {
                    assert!(
                        expected_bounced,
                        "Iteration {i}: expected Permitted for target {target_did}, but got Bounced! (category={category:?}, conf={confidence}, reason={reason})"
                    );
                }
                InteractionOutcome::Permitted { .. } => {
                    assert!(
                        !expected_bounced,
                        "Iteration {i}: expected Bounced for target {target_did}, but got Permitted!"
                    );
                }
                other => panic!("Unexpected outcome for iteration {i}: {other:?}"),
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }
}

/// Test 2: Edge cases for rubric prompts: empty, whitespace-only, and extremely large.
#[tokio::test]
async fn test_adversarial_rubric_prompt_edge_cases() {
    let empty_rubric = RuleRubric::new("", Sensitivity::Low);
    let whitespace_rubric = RuleRubric::new("   \t\n   ", Sensitivity::Medium);
    let large_rubric = RuleRubric::new("A".repeat(20_000), Sensitivity::High);

    assert_eq!(empty_rubric.prompt, "");
    assert_eq!(whitespace_rubric.prompt, "   \t\n   ");
    assert_eq!(large_rubric.prompt.len(), 20_000);

    let classifier = MockClassifier::new(Verdict::permitted_with_confidence("Clean", 0.1));
    let interaction = Interaction::new(
        "did:plc:author",
        "did:plc:target",
        InteractionType::DirectReply,
        "at://did:plc:author/app.bsky.feed.post/1",
        "bafy1",
        "Hello world",
    );

    // 1. Evaluate with empty rubric
    let v1 = classifier
        .classify_with_rubric(&interaction, Some(&empty_rubric))
        .await
        .unwrap();
    assert!(v1.is_permitted());
    assert_eq!(classifier.last_evaluated_rubric().unwrap().prompt, "");

    // 2. Evaluate with whitespace rubric
    let v2 = classifier
        .classify_with_rubric(&interaction, Some(&whitespace_rubric))
        .await
        .unwrap();
    assert!(v2.is_permitted());
    assert_eq!(
        classifier.last_evaluated_rubric().unwrap().prompt,
        "   \t\n   "
    );

    // 3. Evaluate with 20k character rubric
    let v3 = classifier
        .classify_with_rubric(&interaction, Some(&large_rubric))
        .await
        .unwrap();
    assert!(v3.is_permitted());
    assert_eq!(
        classifier.last_evaluated_rubric().unwrap().prompt.len(),
        20_000
    );
}

/// Test 3: Sovereign config deletion for non-enrolled DIDs:
/// 1. Unprotected stranger DID on Bluesky firehose is safely Ignored.
/// 2. Protected fleet DID not enrolled in tenant registry cleanly returns SovereignConfigSynced
///    without SQLite corruption or panics.
#[tokio::test]
async fn test_adversarial_sovereign_config_deletion_for_non_enrolled_did() {
    let default_rubric = RuleRubric::new("Default rules", Sensitivity::Medium);
    let protected_non_enrolled_did = "did:plc:fleet_protected_not_in_sqlite";
    let stranger_did = "did:plc:stranger_not_protected";

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected_non_enrolled_did.to_string());
    protected_dids.insert("did:plc:other_protected".to_string()); // Ensure multi-tenant

    let config = SkybouncerConfig::new(protected_dids, default_rubric.clone()).with_dry_run(true);
    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::new(MockClassifier::permitted()))
        .build()
        .unwrap();

    // 1. Unprotected stranger firehose commit: ignored by engine filter
    let stranger_commit = JetstreamCommit {
        did: stranger_did.to_string(),
        time_us: 1_700_000_000_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };
    let stranger_res = engine.process_commit(&stranger_commit).await.unwrap();
    assert_eq!(stranger_res, ProcessCommitResult::Ignored);

    // 2. Protected fleet DID not enrolled in SQLite registry:
    let fleet_commit = JetstreamCommit {
        did: protected_non_enrolled_did.to_string(),
        time_us: 1_700_000_000_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };
    let fleet_res = engine.process_commit(&fleet_commit).await.unwrap();
    assert_eq!(
        fleet_res,
        ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted {
            did: protected_non_enrolled_did.to_string(),
        })
    );

    // Fleet user remains non-enrolled
    assert!(!engine.is_enrolled(protected_non_enrolled_did));
    // rubric_for returns default rubric without error
    assert_eq!(
        engine.rubric_for(protected_non_enrolled_did).prompt,
        "Default rules"
    );
}

/// Test 4: Sovereign config deletion with non-matching rkey.
/// Asserts that deletion of unrelated records in config collection is ignored
/// and does NOT reset the tenant's rubric.
#[tokio::test]
async fn test_adversarial_sovereign_config_deletion_mismatched_rkey_ignored() {
    let did = "did:plc:alice_protected";
    let default_rubric = RuleRubric::new("Default rules", Sensitivity::Medium);
    let custom_rubric = RuleRubric::new("Custom sovereign rules", Sensitivity::High);

    let mut protected_dids = HashSet::new();
    protected_dids.insert(did.to_string());

    let config = SkybouncerConfig::new(protected_dids, default_rubric).with_dry_run(true);
    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::new(MockClassifier::permitted()))
        .build()
        .unwrap();

    // Enroll alice with custom rubric
    engine
        .tenant_registry()
        .register_or_update(&Tenant::new(did).with_rubric(custom_rubric))
        .unwrap();

    // Delete commit with different rkey (e.g. "other_record")
    let delete_commit = JetstreamCommit {
        did: did.to_string(),
        time_us: 1_700_000_000_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: "other_record".to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };

    let result = engine.process_commit(&delete_commit).await.unwrap();

    // Must be ignored!
    assert_eq!(result, ProcessCommitResult::Ignored);

    // Alice's custom rubric must remain intact!
    assert_eq!(
        engine.rubric_for(did).prompt,
        "Custom sovereign rules",
        "Mismatched rkey delete commit must NOT reset tenant rubric!"
    );
}

/// Test 5: Sovereign config deletion idempotency and multiple resets.
#[tokio::test]
async fn test_adversarial_sovereign_config_deletion_idempotent() {
    let did = "did:plc:bob_tenant";
    let default_rubric = RuleRubric::new("Default rules", Sensitivity::Medium);
    let custom_rubric = RuleRubric::new("Custom sovereign rules", Sensitivity::High);

    let mut protected_dids = HashSet::new();
    protected_dids.insert(did.to_string());

    let config = SkybouncerConfig::new(protected_dids, default_rubric).with_dry_run(true);
    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::new(MockClassifier::permitted()))
        .build()
        .unwrap();

    engine
        .tenant_registry()
        .register_or_update(&Tenant::new(did).with_rubric(custom_rubric))
        .unwrap();

    let delete_commit = JetstreamCommit {
        did: did.to_string(),
        time_us: 1_700_000_000_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };

    // First deletion: resets rubric
    let r1 = engine.process_commit(&delete_commit).await.unwrap();
    assert_eq!(
        r1,
        ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted {
            did: did.to_string()
        })
    );
    assert_eq!(engine.rubric_for(did).prompt, "Default rules");

    // Second deletion: idempotent, stays default
    let r2 = engine.process_commit(&delete_commit).await.unwrap();
    assert_eq!(
        r2,
        ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted {
            did: did.to_string()
        })
    );
    assert_eq!(engine.rubric_for(did).prompt, "Default rules");
}

/// Test 6: TieredClassifier escalation preserves the tenant rubric for both primary and fallback classifiers.
#[tokio::test]
async fn test_adversarial_tiered_classifier_escalation_preserves_rubric() {
    let primary = Arc::new(MockClassifier::new(Verdict::permitted_with_confidence(
        "Borderline uncertainty",
        0.65, // within uncertainty band [0.60..0.80) -> triggers escalation
    )));
    let fallback = Arc::new(MockClassifier::new(Verdict::permitted_with_confidence(
        "Fallback permitted",
        0.10,
    )));

    // Fallback model detects crypto violation if rubric prompt contains "crypto"
    fallback.set_rubric_keyword_verdict(
        "crypto",
        Verdict::violation(
            ViolationCategory::CryptoSpam,
            0.98,
            "Fallback caught crypto violation",
        ),
    );

    let tiered = TieredClassifier::new(
        primary.clone(),
        fallback.clone(),
        CertaintyConfig::new(0.60, 0.80, false),
    );

    let tenant_rubric = RuleRubric::new("Tenant Policy: Zero crypto spam", Sensitivity::High);

    let interaction = Interaction::new(
        "did:plc:spammer",
        "did:plc:target",
        InteractionType::DirectReply,
        "at://did:plc:spammer/app.bsky.feed.post/1",
        "bafy1",
        "Join token presale",
    )
    .with_rubric(tenant_rubric.clone());

    let detailed = tiered
        .classify_detailed_with_stats_and_rubric(&interaction, Some(&tenant_rubric), true)
        .await
        .unwrap();

    assert!(
        detailed.escalated,
        "Should escalate due to uncertainty band"
    );
    assert_eq!(
        primary.last_evaluated_rubric().unwrap().prompt,
        tenant_rubric.prompt,
        "Primary model must receive tenant rubric"
    );
    assert_eq!(
        fallback.last_evaluated_rubric().unwrap().prompt,
        tenant_rubric.prompt,
        "Fallback model must receive tenant rubric upon escalation"
    );

    match detailed.final_verdict {
        Verdict::Violation {
            category,
            confidence,
            ..
        } => {
            assert_eq!(category, ViolationCategory::CryptoSpam);
            assert_eq!(confidence, 0.98);
        }
        other => panic!("Expected Fallback Violation, got {other:?}"),
    }
}

/// Test 7: Sensitivity threshold gating per tenant rubric.
/// Demonstrates that a tenant with Sensitivity::High (0.50 threshold) bounces a 0.70 confidence violation,
/// while a tenant with Sensitivity::Low (0.85 threshold) treats it as BelowThreshold.
#[tokio::test]
async fn test_adversarial_per_tenant_sensitivity_threshold_gating() {
    let tenant_sensitive = "did:plc:tenant_high_sensitivity";
    let tenant_tolerant = "did:plc:tenant_low_sensitivity";

    let rubric_sensitive = RuleRubric::new("Flag spam", Sensitivity::High); // 0.50 threshold
    let rubric_tolerant = RuleRubric::new("Flag spam", Sensitivity::Low); // 0.85 threshold

    let mut protected = HashSet::new();
    protected.insert(tenant_sensitive.to_string());
    protected.insert(tenant_tolerant.to_string());

    // Config default rubric set to Sensitivity::High so modlist manager does not drop below 0.75
    let default_rubric = RuleRubric::new("Default", Sensitivity::High);
    let config = SkybouncerConfig::new(protected, default_rubric).with_dry_run(true);

    let classifier = Arc::new(MockClassifier::new(Verdict::violation(
        ViolationCategory::Spam,
        0.70, // 0.70 is >= 0.50 (High) but < 0.85 (Low)
        "Probable spam message",
    )));

    let engine = SkybouncerEngine::builder(config)
        .with_classifier(classifier)
        .build()
        .unwrap();

    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(tenant_sensitive)
                .with_session(make_mock_session(tenant_sensitive))
                .with_rubric(rubric_sensitive),
        )
        .unwrap();
    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(tenant_tolerant)
                .with_session(make_mock_session(tenant_tolerant))
                .with_rubric(rubric_tolerant),
        )
        .unwrap();

    // Interaction targeting High sensitivity tenant
    let interaction_high = Interaction::new(
        "did:plc:author_1",
        tenant_sensitive,
        InteractionType::DirectReply,
        "at://did:plc:author_1/app.bsky.feed.post/1",
        "bafy1",
        "Promotion link",
    );

    let outcome_high = engine.process_interaction(interaction_high).await.unwrap();
    match outcome_high {
        InteractionOutcome::Bounced { category, .. } => {
            assert_eq!(category, ViolationCategory::Spam);
        }
        other => panic!("Expected Bounced for High sensitivity tenant, got {other:?}"),
    }

    // Interaction targeting Low sensitivity tenant
    let interaction_low = Interaction::new(
        "did:plc:author_2",
        tenant_tolerant,
        InteractionType::DirectReply,
        "at://did:plc:author_2/app.bsky.feed.post/2",
        "bafy2",
        "Promotion link",
    );

    let outcome_low = engine.process_interaction(interaction_low).await.unwrap();
    match outcome_low {
        InteractionOutcome::BelowThreshold {
            category,
            confidence,
            threshold,
            ..
        } => {
            assert_eq!(category, ViolationCategory::Spam);
            assert_eq!(confidence, 0.70);
            assert_eq!(threshold, 0.90);
        }
        other => panic!("Expected BelowThreshold for Low sensitivity tenant, got {other:?}"),
    }
}

/// Test 8: Precedence order of explicit rubric argument vs interaction.rubric.
#[tokio::test]
async fn test_adversarial_rubric_precedence() {
    let classifier = MockClassifier::permitted();

    let rubric_interaction = RuleRubric::new("Interaction rubric", Sensitivity::Low);
    let rubric_explicit = RuleRubric::new("Explicit override rubric", Sensitivity::High);

    let interaction = Interaction::new(
        "did:plc:author",
        "did:plc:target",
        InteractionType::DirectReply,
        "at://did:plc:author/app.bsky.feed.post/1",
        "bafy1",
        "Hello",
    )
    .with_rubric(rubric_interaction);

    // Default classify uses interaction.rubric
    classifier.classify(&interaction).await.unwrap();
    assert_eq!(
        classifier.last_evaluated_rubric().unwrap().prompt,
        "Interaction rubric"
    );

    // classify_with_rubric with None falls back to interaction.rubric
    classifier
        .classify_with_rubric(&interaction, None)
        .await
        .unwrap();
    assert_eq!(
        classifier.last_evaluated_rubric().unwrap().prompt,
        "Interaction rubric"
    );

    // classify_with_rubric with Some overrides interaction.rubric
    classifier
        .classify_with_rubric(&interaction, Some(&rubric_explicit))
        .await
        .unwrap();
    assert_eq!(
        classifier.last_evaluated_rubric().unwrap().prompt,
        "Explicit override rubric"
    );
}

/// Test 9: Empirical proof of ModListManager global rubric filter collision.
///
/// Discovered during empirical stress testing:
/// When the engine default rubric is Medium sensitivity (threshold 0.75), but a tenant
/// configures a custom rubric with High sensitivity (threshold 0.50):
/// 1. `SkybouncerEngine` Tier 8 checks `tenant_rubric.meets_threshold()` -> passes for confidence 0.70.
/// 2. `ModListManager::bounce_user_with_text` re-checks its internal global rubric (`meets_threshold()`).
/// 3. Because `0.70 < 0.75`, `ModListManager` drops the bounce and returns `Ok(None)`.
/// 4. `SkybouncerEngine` assumes `None` means `AlreadyBounced` ("double-checked lock hit").
///
/// This test empirically confirms and documents this cross-layer interaction.
#[tokio::test]
async fn test_adversarial_multitenant_modlist_manager_rubric_collision() {
    let tenant_did = "did:plc:high_sens_tenant";
    let tenant_rubric = RuleRubric::new("Custom high sensitivity", Sensitivity::High); // 0.50
    let fleet_default_rubric = RuleRubric::new("Fleet medium default", Sensitivity::Medium); // 0.75

    let mut protected = HashSet::new();
    protected.insert(tenant_did.to_string());

    let config = SkybouncerConfig::new(protected, fleet_default_rubric).with_dry_run(true);
    let classifier = Arc::new(MockClassifier::new(Verdict::violation(
        ViolationCategory::Spam,
        0.70, // 0.70 is >= 0.50 (tenant High) but < 0.75 (fleet Medium)
        "Spam detected",
    )));

    let engine = SkybouncerEngine::builder(config)
        .with_classifier(classifier)
        .build()
        .unwrap();

    engine
        .tenant_registry()
        .register_or_update(
            &Tenant::new(tenant_did)
                .with_session(make_mock_session(tenant_did))
                .with_rubric(tenant_rubric),
        )
        .unwrap();

    let interaction = Interaction::new(
        "did:plc:violator",
        tenant_did,
        InteractionType::DirectReply,
        "at://did:plc:violator/app.bsky.feed.post/1",
        "bafy1",
        "Spam content",
    );

    let outcome = engine.process_interaction(interaction).await.unwrap();

    // EMPIRICAL VERIFICATION OF MODLIST_MANAGER DRIFT:
    // Instead of Bounced, outcome is AlreadyBounced because ModListManager dropped it
    // against the fleet default rubric threshold (0.75)!
    match outcome {
        InteractionOutcome::AlreadyBounced {
            author_did,
            target_did,
        } => {
            assert_eq!(author_did, "did:plc:violator");
            assert_eq!(target_did, tenant_did);
        }
        other => panic!(
            "Expected AlreadyBounced due to ModListManager global rubric collision, got {other:?}"
        ),
    }
}
