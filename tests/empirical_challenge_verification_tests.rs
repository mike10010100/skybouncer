//! Empirical Challenge Verification Test Suite for Challenger 1.
//!
//! Empirically tests the 5 defects and state machine drift conditions
//! cataloged in Sections 3 and 4 of `docs/ONTOLOGY_REVIEW.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skyauth::client::{AtprotoOAuthClient, OAuthClientMetadata};
use skyauth::dpop::DPoPKey;
use skyauth::session::OAuthSession;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};
use skybouncer::classifier::{RuleRubric, Sensitivity, Verdict};
use skybouncer::engine::{
    ProcessCommitResult, SkybouncerConfig, SkybouncerEngine, SovereignConfigSyncEvent,
};
use skybouncer::error::SkybouncerError;
use skybouncer::matcher::follow_graph::FollowSyncEvent;
use skybouncer::modlist::cache::DeduplicationCache;
use skybouncer::modlist::manager::ModListManager;
use skybouncer::tenant::{Tenant, TenantRegistry};

/// Claim 1 (Remediated): Per-tenant custom rubric inference
/// (`src/classifier/jev.rs`, `src/engine.rs:1522`, `src/matcher/interaction.rs`).
///
/// Verifies that:
/// 1. The target tenant's custom `RuleRubric` is resolved and attached to the `Interaction`.
/// 2. In `engine.process_interaction` (or `evaluate_candidate`), the classifier receives the tenant's rubric.
/// 3. The classifier evaluates the interaction against the tenant's custom prompt rules,
///    correctly taking moderation action (DryRunBounced) on violations.
#[tokio::test]
async fn test_claim_1_classifier_uses_global_rubric_ignoring_tenant_custom_prompt() {
    use skybouncer::classifier::{MockClassifier, ViolationCategory};
    use skybouncer::matcher::Interaction;

    let target_did = "did:plc:tenant_with_custom_rubric";
    let author_did = "did:plc:commenter_violator";

    let global_rubric = RuleRubric::new(
        "Global Default: Block extreme hate speech",
        Sensitivity::Low,
    );
    let tenant_custom_rubric = RuleRubric::new(
        "Tenant Custom: Strictly ban any mention of cryptocurrency or NFT trading",
        Sensitivity::High,
    );

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let modlist = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache))
            .with_rubric(global_rubric.clone())
            .with_dry_run(true),
    );

    let mut protected_dids = HashSet::new();
    protected_dids.insert(target_did.to_string());

    let config = SkybouncerConfig::new(protected_dids, global_rubric.clone()).with_dry_run(true);

    // Mock classifier: by default returns Permitted, but if effective rubric prompt mentions
    // "cryptocurrency", it flags a CryptoSpam violation with 0.95 confidence.
    let classifier = Arc::new(MockClassifier::new(Verdict::permitted_with_confidence(
        "No extreme hate speech found in text",
        0.10,
    )));
    classifier.set_rubric_keyword_verdict(
        "cryptocurrency",
        Verdict::violation(
            ViolationCategory::CryptoSpam,
            0.95,
            "Violates tenant custom anti-crypto rule",
        ),
    );

    let engine = SkybouncerEngine::builder(config)
        .with_cache(cache)
        .with_modlist_manager(modlist)
        .with_classifier(classifier.clone())
        .build()
        .unwrap();

    // Register tenant with custom anti-crypto rubric in tenant registry
    let tenant = Tenant::new(target_did).with_rubric(tenant_custom_rubric.clone());
    engine
        .tenant_registry()
        .register_or_update(&tenant)
        .unwrap();

    // Verify tenant registry has the custom rubric
    let tenant_rubric = engine.rubric_for(target_did);
    assert_eq!(
        tenant_rubric.prompt,
        "Tenant Custom: Strictly ban any mention of cryptocurrency or NFT trading"
    );

    // Interaction contains crypto spam
    let interaction = Interaction {
        post_uri: "at://did:plc:commenter_violator/app.bsky.feed.post/1".to_string(),
        post_cid: Some("bafyreitest".to_string()),
        author_did: author_did.to_string(),
        target_did: target_did.to_string(),
        text: "Buy my new Solana NFT memecoin token right now!".to_string(),
        interaction_type: skybouncer::matcher::InteractionType::DirectReply,
        parent_uri: Some(format!("at://{target_did}/app.bsky.feed.post/root")),
        root_uri: Some(format!("at://{target_did}/app.bsky.feed.post/root")),
        created_at_us: 1_700_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    };

    // Evaluate interaction
    let outcome = engine.process_interaction(interaction).await.unwrap();

    // Verify remediated behavior:
    // Classifier evaluated against tenant's custom rubric, flagged crypto violation,
    // and resulted in Bounced!
    match outcome {
        skybouncer::engine::InteractionOutcome::Bounced {
            category,
            confidence,
            reason,
            ..
        } => {
            assert_eq!(category, ViolationCategory::CryptoSpam);
            assert_eq!(confidence, 0.95);
            assert_eq!(reason, "Violates tenant custom anti-crypto rule");
        }
        other => {
            panic!("Expected Bounced due to tenant custom rubric evaluation, got {other:?}")
        }
    }

    assert_eq!(
        classifier.last_evaluated_rubric().unwrap().prompt,
        tenant_custom_rubric.prompt,
        "Classifier must evaluate using the tenant-specific rubric"
    );
}

/// Claim 2 (Remediated): Sovereign config deletion reset (`src/engine.rs:2372-2384`).
///
/// Verifies that when a `social.skybouncer.config` record is deleted from PDS via firehose,
/// `handle_sovereign_config_commit` receives `CommitOperation::Delete`, and resets the tenant's
/// rubric in `tenant_registry` and engine state back to the default `RuleRubric`.
#[tokio::test]
async fn test_claim_2_sovereign_config_deletion_omits_rubric_reset() {
    let did = "did:plc:alice_tenant";
    let default_rubric = RuleRubric::new("Default rules", Sensitivity::Medium);
    let custom_rubric = RuleRubric::new("Custom sovereign rules", Sensitivity::High);

    let mut protected_dids = HashSet::new();
    protected_dids.insert(did.to_string());

    let config = SkybouncerConfig::new(protected_dids, default_rubric.clone()).with_dry_run(true);
    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::permitted()))
        .build()
        .unwrap();

    // Enroll tenant and set custom rubric
    let tenant = Tenant::new(did).with_rubric(custom_rubric.clone());
    engine
        .tenant_registry()
        .register_or_update(&tenant)
        .unwrap();

    // Verify engine returns custom rubric
    assert_eq!(engine.rubric_for(did).prompt, "Custom sovereign rules");

    // Construct Jetstream Commit deleting the sovereign config record
    let delete_commit = JetstreamCommit {
        did: did.to_string(),
        time_us: 1_700_000_000_000_000,
        collection: skybouncer::modlist::SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: skybouncer::modlist::SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };

    // Process delete commit
    let result = engine.process_commit(&delete_commit).await.unwrap();

    // Confirm the commit was recognized as a delete event
    assert_eq!(
        result,
        ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted {
            did: did.to_string(),
        })
    );

    // REMEDIATED BEHAVIOR VERIFIED:
    // The tenant's rubric was reset back to default in both tenant_registry and engine state!
    let current_tenant = engine.tenant_registry().get(did).unwrap().unwrap();
    assert_eq!(
        current_tenant.rubric.unwrap().prompt,
        "Default rules",
        "Tenant rubric in registry must be reset to default on config deletion"
    );
    assert_eq!(
        engine.rubric_for(did).prompt,
        "Default rules",
        "engine.rubric_for() must return default rubric after config deletion"
    );
}

/// Claim 3: Follow graph synthetic `hydrate_{idx}` TID desync reconciliation
/// (`src/engine.rs:1827`, `src/matcher/follow_graph.rs:180-275`).
///
/// Verifies that when `engine.hydrate_follows` is used on cold start with synthetic rkeys
/// (`hydrate_0`, `hydrate_1`, ...), and a real ATProto unfollow delete commit arrives with
/// the actual TID rkey, the follow graph's synthetic fallback mechanism reconciles the
/// deletion, removes the followed account, and emits `FollowSyncEvent::FollowRemoved`.
#[tokio::test]
async fn test_claim_3_follow_graph_synthetic_hydrate_idx_desync() {
    let alice_did = "did:plc:alice_protected";
    let bob_did = "did:plc:bob_followed";

    let mut protected_dids = HashSet::new();
    protected_dids.insert(alice_did.to_string());

    let config = SkybouncerConfig::new(
        protected_dids,
        RuleRubric::new("Default", Sensitivity::Medium),
    );
    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::permitted()))
        .build()
        .unwrap();

    // Cold-start hydration using synthetic rkeys (src/engine.rs:1827)
    let hydrated_count = engine.hydrate_follows(alice_did, vec![bob_did]);
    assert_eq!(hydrated_count, 1);

    // Bob is followed
    assert!(engine.is_following(alice_did, bob_did));

    // Alice unfollows Bob on Bluesky: Jetstream emits delete commit with real ATProto TID
    let real_tid_rkey = "3l5u4vh2k6s2y"; // Realistic TID from Bluesky PDS
    let unfollow_commit = JetstreamCommit {
        did: alice_did.to_string(),
        time_us: 1_700_000_001_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: real_tid_rkey.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };

    // Process unfollow commit through follow graph
    let sync_event = engine
        .follow_graph()
        .handle_commit(&unfollow_commit, &engine.protected_dids());

    // REMEDIATED BEHAVIOR VERIFIED:
    // The follow graph reconciled the synthetic hydrate rkey with the real TID delete commit!
    assert_eq!(
        sync_event,
        FollowSyncEvent::FollowRemoved {
            protected_did: alice_did.to_string(),
            rkey: real_tid_rkey.to_string(),
            followed_did: bob_did.to_string(),
        },
        "Follow deletion must reconcile synthetic hydration rkey with incoming real TID delete commit"
    );

    // Bob is no longer followed
    assert!(
        !engine.is_following(alice_did, bob_did),
        "Bob must no longer be followed after unfollow delete commit is processed"
    );
}

/// Claim 4 (Remediated): Handle cache resolution TTL (`src/engine.rs:2045`, `src/tenant/registry.rs:486`).
///
/// Verifies that:
/// 1. `resolve_handle()` and `tenant_registry.get_by_handle_with_ttl()` enforce TTL expiration.
/// 2. Expired handle lookups (e.g. TTL 0) return `None`, preventing stale identity shadowing.
/// 3. Invalidation via `engine.invalidate_handle()` purges both in-memory and SQLite handle mappings.
#[tokio::test]
async fn test_claim_4_handle_cache_resolution_lacks_ttl() {
    let alice_did = "did:plc:alice_old_owner";
    let shared_handle = "alice.bsky.social";

    let mut protected_dids = HashSet::new();
    protected_dids.insert(alice_did.to_string());

    let config = SkybouncerConfig::new(
        protected_dids,
        RuleRubric::new("Default", Sensitivity::Medium),
    );
    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::permitted()))
        .build()
        .unwrap();

    // Alice registers as tenant with handle @alice.bsky.social
    let tenant = Tenant::new(alice_did).with_handle(shared_handle);
    engine
        .tenant_registry()
        .register_or_update(&tenant)
        .unwrap();

    // 1. Engine resolves handle to Alice with active default TTL
    let resolved = engine.resolve_handle(shared_handle).await;
    assert_eq!(resolved, Some(alice_did.to_string()));

    // Direct DID returns immediately without lookup
    let did_resolve = engine.resolve_handle("did:plc:alice_old_owner").await;
    assert_eq!(did_resolve, Some(alice_did.to_string()));

    // In-memory cache clearing works (re-resolves from tenant registry)
    engine.clear_handle_cache();
    let re_resolved = engine.resolve_handle(shared_handle).await;
    assert_eq!(re_resolved, Some(alice_did.to_string()));

    // 2. Direct lookup with TTL 0 returns None because the entry is considered expired
    let expired_lookup = engine
        .tenant_registry()
        .get_by_handle_with_ttl(shared_handle, Duration::ZERO)
        .unwrap();
    assert!(
        expired_lookup.is_none(),
        "Lookup with TTL 0 must return None to indicate expired handle mapping"
    );

    // 3. Invalidation clears both in-memory cache and SQLite mapping
    engine.invalidate_handle(shared_handle);

    let registry_after_invalidation = engine
        .tenant_registry()
        .get_by_handle(shared_handle)
        .unwrap();
    assert!(
        registry_after_invalidation.is_none(),
        "Tenant registry must return None after handle invalidation"
    );

    let engine_after_invalidation = engine.resolve_handle(shared_handle).await;
    assert!(
        engine_after_invalidation.is_none(),
        "Engine resolve_handle must return None after handle invalidation"
    );
}

/// Claim 5 (Remediated): Session refresh failure handling & dead client eviction (`src/tenant/registry.rs:900-950`).
///
/// Verifies that when an OAuth session is expired and `refresh_session` fails (e.g. 400 Bad Request):
/// 1. `get_pds_client` returns a typed error: `Err(SkybouncerError::Auth(...))`.
/// 2. The expired client is immediately evicted from the in-memory `pds_clients` cache,
///    preventing dead-client pollution.
#[tokio::test]
async fn test_claim_5_session_refresh_failure_caches_expired_client() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    // OAuth server returns 400 Bad Request (e.g. invalid_grant / revoked refresh token)
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Refresh token has been revoked"
        })))
        .mount(&mock_server)
        .await;

    let oauth_client = Arc::new(
        AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(
                "https://skybouncer.example.com/client-metadata.json",
                "https://skybouncer.example.com/oauth/callback",
            ))
            .allow_insecure_localhost(true)
            .build()
            .unwrap(),
    );

    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(Arc::clone(&oauth_client));

    let tenant_did = "did:plc:revoked_tenant";
    let dpop_key = DPoPKey::generate();

    // Expired session (expires_in = Some(0))
    let expired_session = OAuthSession::new(
        tenant_did,
        "at-expired-stale-token",
        Some("rt-revoked-refresh-token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(0),
        dpop_key,
        Some("https://pds.example.com".to_string()),
        Some(mock_server.uri()),
        Some(token_endpoint),
    )
    .unwrap();

    assert!(expired_session.is_expired());

    let tenant = Tenant::new(tenant_did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    // Calling get_pds_client encounters refresh error (400 Bad Request)
    let client_result = registry.get_pds_client(tenant_did, None).await;

    // REMEDIATED BEHAVIOR VERIFIED:
    // 1. get_pds_client returns typed Err(SkybouncerError::Auth(...))
    assert!(
        client_result.is_err(),
        "get_pds_client must return Err when token refresh fails on expired session"
    );
    assert!(
        matches!(
            client_result,
            Err(SkybouncerError::Auth(ref msg))
                if msg.contains("Failed to refresh") || msg.contains("expired")
        ),
        "Error must be SkybouncerError::Auth indicating refresh failure"
    );

    // 2. The dead client is evicted from cache
    assert!(
        registry.pds_clients.read().get(tenant_did).is_none(),
        "Expired client must be evicted from pds_clients cache upon refresh failure"
    );
}

/// Tier 4/5 fast-path cache tests: pre-seeded bounce and evaluation caches must
/// short-circuit `process_interaction` with zero model/network calls.
#[tokio::test]
async fn test_fast_path_dedup_and_eval_cache_short_circuits() {
    use skybouncer::classifier::{MockClassifier, ViolationCategory};
    use skybouncer::matcher::Interaction;
    use skybouncer::modlist::cache::BouncedUser;

    let target_did = "did:plc:fastpath_tenant";
    let author_did = "did:plc:fastpath_author";

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let classifier = Arc::new(MockClassifier::permitted());
    let mut protected_dids = HashSet::new();
    protected_dids.insert(target_did.to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric).with_dry_run(true);

    let engine = SkybouncerEngine::builder(config)
        .with_cache(Arc::clone(&cache))
        .with_modlist_manager(modlist)
        .with_classifier(classifier)
        .build()
        .unwrap();

    let make = |uri: &str| Interaction {
        post_uri: uri.to_string(),
        post_cid: Some("bafyfast".to_string()),
        author_did: author_did.to_string(),
        target_did: target_did.to_string(),
        text: "perfectly benign message".to_string(),
        interaction_type: skybouncer::matcher::InteractionType::DirectReply,
        parent_uri: Some(format!("at://{target_did}/app.bsky.feed.post/root")),
        root_uri: Some(format!("at://{target_did}/app.bsky.feed.post/root")),
        created_at_us: 1_700_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    };

    // Tier 4: pre-seed a bounce for (protected, subject) -> AlreadyBounced.
    cache
        .record_bounce(&BouncedUser {
            subject_did: author_did.to_string(),
            protected_did: target_did.to_string(),
            listitem_uri: "at://list/1".to_string(),
            listitem_rkey: "1".to_string(),
            listitem_cid: "bafy".to_string(),
            category: "CryptoSpam".to_string(),
            confidence: 0.99,
            reason: "seed".to_string(),
            post_uri: "at://seed".to_string(),
            post_text: "seed".to_string(),
            bounced_at: 1_700_000_000_000_000,
            expires_at: None,
        })
        .unwrap();
    let bounced_out = engine
        .process_interaction(make(
            "at://did:plc:fastpath_author/app.bsky.feed.post/tier4",
        ))
        .await
        .unwrap();
    assert!(matches!(
        bounced_out,
        skybouncer::engine::InteractionOutcome::AlreadyBounced { .. }
    ));

    // Clear the bounce so we can reach Tier 5.
    cache.remove_bounce(author_did).unwrap();

    // Tier 5: pre-seed an evaluation verdict -> eval-cache hit resolves directly.
    let eval_uri = "at://did:plc:fastpath_author/app.bsky.feed.post/tier5";
    let eval_key = format!("{eval_uri}:{target_did}");
    cache
        .set_evaluation(
            &eval_key,
            author_did,
            &Verdict::violation(ViolationCategory::CryptoSpam, 0.97, "cached verdict"),
            Duration::from_secs(600),
        )
        .unwrap();
    let eval_out = engine.process_interaction(make(eval_uri)).await.unwrap();
    assert!(matches!(
        eval_out,
        skybouncer::engine::InteractionOutcome::Bounced { .. }
    ));

    let stats = engine.stats().snapshot();
    assert!(stats.dedup_cache_hits >= 1);
    assert!(stats.eval_cache_hits >= 1);
}
