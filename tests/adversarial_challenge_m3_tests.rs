//! Adversarial Empirical Challenge Suite for Milestone M3 (R4 & R5).
//!
//! Stress-tests and empirical verification for:
//! 1. Requirement R4: Handle resolution caching TTL, invalidation, clock-warp resilience,
//!    case/symbol normalization, rotation shadowing prevention, three-tier resolution hierarchy.
//! 2. Requirement R5: OAuth session refresh failure handling, typed `SkybouncerError::Auth` error propagation,
//!    dead client cache eviction from `pds_clients`, single-flight concurrency synchronization (thundering herd).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unused_imports
)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skyauth::client::{AtprotoOAuthClient, OAuthClientMetadata};
use skyauth::dpop::DPoPKey;
use skyauth::session::OAuthSession;
use skybouncer::classifier::{MockClassifier, RuleRubric, Sensitivity};
use skybouncer::engine::{SkybouncerConfig, SkybouncerEngine};
use skybouncer::enricher::{ContextEnricher, EnrichedContext};
use skybouncer::error::SkybouncerError;
use skybouncer::matcher::Interaction;
use skybouncer::tenant::{Tenant, TenantRegistry, DEFAULT_HANDLE_TTL};

// ============================================================================
// Helper Mock Context Enricher
// ============================================================================

#[derive(Default)]
struct DynamicTestEnricher {
    handle_map: RwLock<HashMap<String, String>>,
    resolve_calls: AtomicUsize,
}

impl DynamicTestEnricher {
    fn new() -> Self {
        Self::default()
    }

    fn set_mapping(&self, handle: &str, did: &str) {
        let clean = handle.trim().trim_start_matches('@').to_string();
        self.handle_map.write().insert(clean, did.to_string());
    }

    fn calls(&self) -> usize {
        self.resolve_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ContextEnricher for DynamicTestEnricher {
    async fn enrich(&self, _interaction: &Interaction) -> EnrichedContext {
        EnrichedContext::empty()
    }

    async fn resolve_handle(&self, handle: &str) -> Option<String> {
        self.resolve_calls.fetch_add(1, Ordering::SeqCst);
        let clean = handle.trim().trim_start_matches('@');
        self.handle_map.read().get(clean).cloned()
    }
}

fn create_test_oauth_client() -> Arc<AtprotoOAuthClient> {
    Arc::new(
        AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(
                "https://skybouncer.example.com/client-metadata.json",
                "https://skybouncer.example.com/oauth/callback",
            ))
            .allow_insecure_localhost(true)
            .build()
            .unwrap(),
    )
}

fn create_expired_session(
    did: &str,
    mock_server_uri: &str,
    token_endpoint: &str,
    refresh_token: Option<String>,
) -> OAuthSession {
    let dpop_key = DPoPKey::generate();
    OAuthSession::new(
        did,
        "at-stale-expired-token",
        refresh_token,
        "DPoP",
        Some("atproto".to_string()),
        Some(0), // expires_in = 0 makes it instantly expired
        dpop_key,
        Some("https://pds.example.com".to_string()),
        Some(mock_server_uri.to_string()),
        Some(token_endpoint.to_string()),
    )
    .unwrap()
}

// ============================================================================
// PART 1: REQUIREMENT R4 (Handle Resolution Caching TTL & Invalidation)
// ============================================================================

/// Stress-test zero TTL, sub-millisecond TTL, and normal TTL on SQLite tenant registry.
#[tokio::test]
async fn test_adversarial_handle_ttl_zero_and_near_zero() {
    let registry = TenantRegistry::open_in_memory().unwrap();
    let did = "did:plc:alice_ttl_test";
    let handle = "alice.bsky.social";

    let tenant = Tenant::new(did).with_handle(handle);
    registry.register_or_update(&tenant).unwrap();

    // Sleep briefly to ensure microsecond difference between updated_at and query cutoff
    tokio::time::sleep(Duration::from_millis(5)).await;

    // 1. Zero TTL must consider the handle expired
    let lookup_zero = registry
        .get_by_handle_with_ttl(handle, Duration::ZERO)
        .unwrap();
    assert!(
        lookup_zero.is_none(),
        "Lookup with Duration::ZERO must return None (expired)"
    );

    // 2. 100-microsecond TTL must also consider the entry expired (after 5ms sleep)
    let lookup_short = registry
        .get_by_handle_with_ttl(handle, Duration::from_micros(100))
        .unwrap();
    assert!(
        lookup_short.is_none(),
        "Lookup with expired microsecond TTL must return None"
    );

    // 3. Generous TTL (1 hour) must return the valid tenant
    let lookup_valid = registry
        .get_by_handle_with_ttl(handle, Duration::from_secs(3600))
        .unwrap();
    assert!(lookup_valid.is_some());
    assert_eq!(lookup_valid.unwrap().did, did);

    // 4. Default TTL (DEFAULT_HANDLE_TTL) must also succeed
    assert_eq!(DEFAULT_HANDLE_TTL, Duration::from_secs(3600));
    let lookup_default = registry.get_by_handle(handle).unwrap();
    assert!(lookup_default.is_some());
    assert_eq!(lookup_default.unwrap().did, did);
}

/// Stress-test arithmetic saturation with extreme TTLs (Duration::MAX, massive durations).
#[test]
fn test_adversarial_handle_ttl_saturation_and_max() {
    let registry = TenantRegistry::open_in_memory().unwrap();
    let did = "did:plc:sat_test";
    let handle = "sat.bsky.social";

    let tenant = Tenant::new(did).with_handle(handle);
    registry.register_or_update(&tenant).unwrap();

    // Test Duration::MAX does not overflow, panic, or underflow
    let lookup_max = registry
        .get_by_handle_with_ttl(handle, Duration::MAX)
        .unwrap();
    assert!(
        lookup_max.is_some(),
        "Duration::MAX must not panic and must resolve successfully"
    );
    assert_eq!(lookup_max.unwrap().did, did);

    // Test massive 1000-year duration
    let lookup_century = registry
        .get_by_handle_with_ttl(handle, Duration::from_secs(365 * 24 * 3600 * 1000))
        .unwrap();
    assert!(lookup_century.is_some());
}

/// Stress-test handle normalization: multiple '@' prefixes, whitespace, mixed-case lookups, and invalidation.
#[test]
fn test_adversarial_handle_normalization_whitespace_and_at_signs() {
    let registry = TenantRegistry::open_in_memory().unwrap();
    let did = "did:plc:charlie_norm";
    let handle = "Charlie.Bsky.Social";

    let tenant = Tenant::new(did).with_handle(handle);
    registry.register_or_update(&tenant).unwrap();

    // Lookups with varying whitespace and casing
    let variants = [
        "charlie.bsky.social",
        "CHARLIE.BSKY.SOCIAL",
        "@charlie.bsky.social",
        "@Charlie.Bsky.Social",
        "@@charlie.bsky.social",
        "   @charlie.bsky.social   ",
        "  CHARLIE.BSKY.SOCIAL  ",
    ];

    for variant in variants {
        let res = registry.get_by_handle(variant).unwrap();
        assert!(
            res.is_some(),
            "Variant '{variant}' must resolve to enrolled tenant"
        );
        assert_eq!(res.unwrap().did, did);
    }

    // Invalidation with uppercase and leading @
    let invalidated = registry
        .invalidate_handle("  @CHARLIE.BSKY.SOCIAL  ")
        .unwrap();
    assert!(
        invalidated,
        "Invalidation must succeed for normalized handle"
    );

    // All variants must now return None
    for variant in variants {
        let res = registry.get_by_handle(variant).unwrap();
        assert!(
            res.is_none(),
            "After invalidation, variant '{variant}' must return None"
        );
    }
}

/// Stress-test identity shadowing prevention on handle rotation:
/// When an enrolled handle is rotated away on Bluesky, TTL expiration allows
/// re-resolution via remote enricher, preventing permanent identity shadowing.
#[tokio::test]
async fn test_adversarial_handle_rotation_identity_shadowing_prevented() {
    let alice_did = "did:plc:alice_original_owner";
    let bob_did = "did:plc:bob_new_owner";
    let contested_handle = "popular-handle.bsky.social";

    let enricher = Arc::new(DynamicTestEnricher::new());
    // Initially remote AppView resolves to Alice
    enricher.set_mapping(contested_handle, alice_did);

    let config = SkybouncerConfig::new(
        vec![alice_did.to_string(), bob_did.to_string()],
        RuleRubric::new("Default", Sensitivity::Medium),
    )
    .with_handle_cache_ttl(Duration::from_millis(50)); // Short TTL for fast test

    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::new(MockClassifier::permitted()))
        .with_enricher(Arc::clone(&enricher) as Arc<dyn ContextEnricher>)
        .build()
        .unwrap();

    // Alice registers handle in tenant registry
    let alice_tenant = Tenant::new(alice_did).with_handle(contested_handle);
    engine
        .tenant_registry()
        .register_or_update(&alice_tenant)
        .unwrap();

    // 1. Initial resolution returns Alice
    let resolved_1 = engine.resolve_handle(contested_handle).await;
    assert_eq!(resolved_1, Some(alice_did.to_string()));

    // 2. Handle rotation happens on ATProto! Alice releases handle, Bob claims it.
    // Remote AppView now resolves the handle to Bob.
    enricher.set_mapping(contested_handle, bob_did);

    // 3. Immediately (before TTL expiration), in-memory cache still returns Alice
    let resolved_cached = engine.resolve_handle(contested_handle).await;
    assert_eq!(resolved_cached, Some(alice_did.to_string()));

    // 4. Invalidate handle explicitly (e.g. via identity update event or administrative command)
    engine.invalidate_handle(contested_handle);

    // 5. Re-resolution now immediately bypasses stale Alice and resolves to Bob!
    let resolved_after_invalidation = engine.resolve_handle(contested_handle).await;
    assert_eq!(
        resolved_after_invalidation,
        Some(bob_did.to_string()),
        "After invalidation, handle must resolve to new owner (Bob)"
    );

    // 6. Test natural TTL expiration without explicit invalidation:
    // Bob changes handle to Dave on remote AppView
    let dave_did = "did:plc:dave_third_owner";
    enricher.set_mapping(contested_handle, dave_did);

    // Wait for in-memory and SQLite TTL to expire (50ms configured)
    tokio::time::sleep(Duration::from_millis(60)).await;

    let resolved_after_ttl = engine.resolve_handle(contested_handle).await;
    assert_eq!(
        resolved_after_ttl,
        Some(dave_did.to_string()),
        "After TTL expiration, engine must query enricher and resolve to Dave"
    );
}

/// Stress-test the three-tier resolution hierarchy in `SkybouncerEngine`:
/// Tier 1: In-memory monotonic cache (Instant::now())
/// Tier 2: TenantRegistry SQLite with TTL
/// Tier 3: Remote enricher fallback
/// Also verifies direct DID bypass (`did:plc:...`, `did:web:...`).
#[tokio::test]
async fn test_adversarial_engine_three_tier_resolution_hierarchy() {
    let enricher = Arc::new(DynamicTestEnricher::new());
    let config = SkybouncerConfig::new(
        HashSet::<String>::new(),
        RuleRubric::new("Default", Sensitivity::Medium),
    )
    .with_handle_cache_ttl(Duration::from_secs(3600));

    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::new(MockClassifier::permitted()))
        .with_enricher(Arc::clone(&enricher) as Arc<dyn ContextEnricher>)
        .build()
        .unwrap();

    // 1. Direct DIDs bypass all lookups immediately
    assert_eq!(
        engine.resolve_handle("did:plc:direct_alice").await,
        Some("did:plc:direct_alice".to_string())
    );
    assert_eq!(
        engine.resolve_handle("  did:web:example.com  ").await,
        Some("did:web:example.com".to_string())
    );
    assert_eq!(
        enricher.calls(),
        0,
        "Direct DIDs must never query the remote enricher"
    );

    // 2. Tenant in SQLite resolves via Tier 2 and populates Tier 1 cache
    let tenant_did = "did:plc:tier2_tenant";
    let tenant_handle = "tenant.bsky.social";
    let tenant = Tenant::new(tenant_did).with_handle(tenant_handle);
    engine
        .tenant_registry()
        .register_or_update(&tenant)
        .unwrap();

    let res_tier2 = engine.resolve_handle(tenant_handle).await;
    assert_eq!(res_tier2, Some(tenant_did.to_string()));
    assert_eq!(
        enricher.calls(),
        0,
        "SQLite hit must never query the remote enricher"
    );

    // Subsequent resolution hits Tier 1 in-memory cache
    let res_tier1 = engine.resolve_handle(tenant_handle).await;
    assert_eq!(res_tier1, Some(tenant_did.to_string()));
    assert_eq!(enricher.calls(), 0);

    // 3. Non-tenant handle resolves via Tier 3 (remote enricher)
    let stranger_did = "did:plc:stranger_user";
    let stranger_handle = "stranger.bsky.social";
    enricher.set_mapping(stranger_handle, stranger_did);

    let res_tier3 = engine.resolve_handle(stranger_handle).await;
    assert_eq!(res_tier3, Some(stranger_did.to_string()));
    assert_eq!(
        enricher.calls(),
        1,
        "Non-tenant handle must query remote enricher"
    );

    // Subsequent call for stranger hits Tier 1 in-memory cache (calls remains 1)
    let res_stranger_cached = engine.resolve_handle(stranger_handle).await;
    assert_eq!(res_stranger_cached, Some(stranger_did.to_string()));
    assert_eq!(
        enricher.calls(),
        1,
        "Subsequent call must hit in-memory cache without querying enricher again"
    );

    // 4. Unknown handle returns None
    let res_unknown = engine.resolve_handle("nonexistent.bsky.social").await;
    assert!(res_unknown.is_none());
    assert_eq!(enricher.calls(), 2);
}

/// Stress-test concurrent multi-threaded handle resolution and invalidations.
#[tokio::test]
async fn test_adversarial_concurrent_handle_resolution_stress() {
    let enricher = Arc::new(DynamicTestEnricher::new());
    for i in 0..10 {
        enricher.set_mapping(&format!("user{i}.bsky.social"), &format!("did:plc:user{i}"));
    }

    let config = SkybouncerConfig::new(
        HashSet::<String>::new(),
        RuleRubric::new("Default", Sensitivity::Medium),
    )
    .with_handle_cache_ttl(Duration::from_millis(50));

    let engine = Arc::new(
        SkybouncerEngine::builder(config)
            .with_classifier(Arc::new(MockClassifier::permitted()))
            .with_enricher(Arc::clone(&enricher) as Arc<dyn ContextEnricher>)
            .build()
            .unwrap(),
    );

    // Spawn 20 concurrent tasks performing resolution, clearing, and invalidation
    let mut tasks = Vec::new();
    for thread_idx in 0..20 {
        let engine_clone = Arc::clone(&engine);
        tasks.push(tokio::spawn(async move {
            for iter in 0..50 {
                let user_num = (thread_idx + iter) % 10;
                let handle = format!("user{user_num}.bsky.social");
                let expected_did = format!("did:plc:user{user_num}");

                if iter % 10 == 0 {
                    engine_clone.clear_handle_cache();
                } else if iter % 7 == 0 {
                    engine_clone.invalidate_handle(&handle);
                } else {
                    let resolved = engine_clone.resolve_handle(&handle).await;
                    assert_eq!(resolved, Some(expected_did));
                }
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}

// ============================================================================
// PART 2: REQUIREMENT R5 (OAuth Session Refresh Failure & Cache Eviction)
// ============================================================================

/// Stress-test token refresh failure due to 400 Bad Request (revoked refresh token):
/// 1. `get_pds_client` returns `Err(SkybouncerError::Auth(...))`.
/// 2. Evicts client from `pds_clients`.
#[tokio::test]
async fn test_adversarial_session_refresh_400_invalid_grant_evicts_cache() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Refresh token was revoked or expired"
        })))
        .mount(&mock_server)
        .await;

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did = "did:plc:revoked_grant_tenant";
    let expired_session = create_expired_session(
        did,
        &mock_server.uri(),
        &token_endpoint,
        Some("rt-revoked".to_string()),
    );

    let tenant = Tenant::new(did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    let result = registry.get_pds_client(did, None).await;

    // Assert typed Auth error
    assert!(result.is_err());
    match result {
        Err(SkybouncerError::Auth(msg)) => {
            assert!(
                msg.contains("Failed to refresh") || msg.contains("expired"),
                "Error message must describe token refresh failure: {msg}"
            );
        }
        Err(e) => panic!("Expected SkybouncerError::Auth, got {e}"),
        Ok(_) => panic!("Expected Err, got Ok"),
    }

    // In-memory cache MUST NOT contain the tenant
    assert!(
        registry.pds_clients.read().get(did).is_none(),
        "Eviction invariant: pds_clients must not cache dead client"
    );
}

/// Stress-test token refresh failure due to 500 Internal Server Error:
/// Typed Auth error returned and client evicted from cache.
#[tokio::test]
async fn test_adversarial_session_refresh_500_server_error_evicts_cache() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did = "did:plc:server_error_tenant";
    let expired_session = create_expired_session(
        did,
        &mock_server.uri(),
        &token_endpoint,
        Some("rt-server-error".to_string()),
    );

    let tenant = Tenant::new(did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    let result = registry.get_pds_client(did, None).await;

    assert!(result.is_err());
    assert!(matches!(result, Err(SkybouncerError::Auth(_))));
    assert!(registry.pds_clients.read().get(did).is_none());
}

/// Stress-test expired session when NO OAuth client is configured:
/// Typed Auth error returned and client evicted from cache.
#[tokio::test]
async fn test_adversarial_session_refresh_missing_oauth_client() {
    let registry = TenantRegistry::open_in_memory().unwrap();
    let did = "did:plc:no_oauth_client_tenant";

    // Expired session created without setting oauth_client on registry
    let expired_session = create_expired_session(
        did,
        "https://pds.example.com",
        "https://pds.example.com/oauth/token",
        Some("rt-unused".to_string()),
    );

    let tenant = Tenant::new(did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    let result = registry.get_pds_client(did, None).await;

    assert!(result.is_err());
    match result {
        Err(SkybouncerError::Auth(msg)) => {
            assert!(
                msg.contains("no OAuth client is configured"),
                "Must report missing OAuth client: {msg}"
            );
        }
        Err(e) => panic!("Expected SkybouncerError::Auth, got {e}"),
        Ok(_) => panic!("Expected Err, got Ok"),
    }
    assert!(registry.pds_clients.read().get(did).is_none());
}

/// Stress-test expired session when NO refresh token is present in the session:
/// Typed Auth error returned and client evicted from cache.
#[tokio::test]
async fn test_adversarial_session_refresh_missing_refresh_token() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did = "did:plc:no_refresh_token_tenant";
    // Session with refresh_token: None
    let expired_session = create_expired_session(did, &mock_server.uri(), &token_endpoint, None);

    let tenant = Tenant::new(did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    let result = registry.get_pds_client(did, None).await;

    assert!(result.is_err());
    match result {
        Err(SkybouncerError::Auth(msg)) => {
            assert!(
                msg.contains("has no refresh token"),
                "Must report missing refresh token: {msg}"
            );
        }
        Err(e) => panic!("Expected SkybouncerError::Auth, got {e}"),
        Ok(_) => panic!("Expected Err, got Ok"),
    }
    assert!(registry.pds_clients.read().get(did).is_none());
}

/// Stress-test defensive check: if session remains expired after refresh,
/// it must be evicted and return typed error.
#[tokio::test]
async fn test_adversarial_session_refresh_still_expired_after_refresh() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    // OAuth server returns 200 OK but with expires_in: 0 (still expired)
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "nonce-123")
                .set_body_json(json!({
                    "access_token": "at-still-expired",
                    "token_type": "DPoP",
                    "expires_in": 0,
                    "refresh_token": "rt-still-expired",
                    "scope": "atproto",
                    "sub": "did:plc:still_expired_tenant"
                })),
        )
        .mount(&mock_server)
        .await;

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did = "did:plc:still_expired_tenant";
    let expired_session = create_expired_session(
        did,
        &mock_server.uri(),
        &token_endpoint,
        Some("rt-initial".to_string()),
    );

    let tenant = Tenant::new(did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    let result = registry.get_pds_client(did, None).await;

    assert!(result.is_err());
    match result {
        Err(SkybouncerError::Auth(msg)) => {
            assert!(
                msg.contains("remains expired"),
                "Must report session remains expired: {msg}"
            );
        }
        Err(e) => panic!("Expected SkybouncerError::Auth, got {e}"),
        Ok(_) => panic!("Expected Err, got Ok"),
    }
    assert!(registry.pds_clients.read().get(did).is_none());
}

/// Stress-test eviction of an existing pre-cached client when its session expires
/// and subsequent refresh fails.
#[tokio::test]
async fn test_adversarial_pre_cached_dead_client_evicted_on_refresh_failure() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    // Server returns 400 Bad Request
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant"
        })))
        .mount(&mock_server)
        .await;

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did = "did:plc:precached_tenant";
    let expired_session = create_expired_session(
        did,
        &mock_server.uri(),
        &token_endpoint,
        Some("rt-precached".to_string()),
    );

    // Manually construct and inject a client into pds_clients cache
    let session_arc = Arc::new(expired_session.clone());
    let dead_client = Arc::new(
        skybase::repo::PdsRepoClient::new(session_arc, registry.oauth_client().unwrap()).unwrap(),
    );
    registry
        .pds_clients
        .write()
        .insert(did.to_string(), dead_client);

    // Verify it is initially present in the cache
    assert!(registry.pds_clients.read().get(did).is_some());

    // Register tenant in SQLite
    let tenant = Tenant::new(did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    // Calling get_pds_client detects expiration, attempts refresh, fails, and must EVICT pre-cached client
    let result = registry.get_pds_client(did, None).await;

    assert!(result.is_err());
    assert!(
        registry.pds_clients.read().get(did).is_none(),
        "Pre-cached dead client must be evicted from pds_clients"
    );
}

/// Stress-test single-flight concurrency lock (thundering herd prevention):
/// 25 concurrent requests for the SAME expired tenant MUST issue only 1 network refresh call!
#[tokio::test]
async fn test_adversarial_thundering_herd_single_flight_refresh() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "fresh-nonce")
                .set_body_json(json!({
                    "access_token": "at-thundering-herd-success",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-thundering-herd-success",
                    "scope": "atproto",
                    "sub": "did:plc:thundering_herd_tenant"
                })),
        )
        .expect(1) // EXACTLY 1 HTTP refresh request allowed!
        .mount(&mock_server)
        .await;

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did = "did:plc:thundering_herd_tenant";
    let expired_session = create_expired_session(
        did,
        &mock_server.uri(),
        &token_endpoint,
        Some("rt-thundering-herd".to_string()),
    );

    let tenant = Tenant::new(did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    // Spawn 25 concurrent calls to get_pds_client for the same DID
    let mut tasks = Vec::new();
    for _ in 0..25 {
        let reg = registry.clone();
        tasks.push(tokio::spawn(
            async move { reg.get_pds_client(did, None).await },
        ));
    }

    for task in tasks {
        let res = task.await.unwrap();
        assert!(res.is_ok(), "Concurrent request must succeed");
        let client = res.unwrap().unwrap();
        assert_eq!(
            client.session().access_token(),
            "at-thundering-herd-success"
        );
    }

    // MockServer expectation: exactly 1 request verified by mock_server dropped / verified
    mock_server.verify().await;

    // Cache contains the refreshed client
    assert!(registry.pds_clients.read().get(did).is_some());
}

/// Stress-test concurrent failure isolation:
/// 25 concurrent requests for an expired tenant when refresh fails with 400 Bad Request.
/// All 25 must receive typed Err(SkybouncerError::Auth) and cache remains clean.
#[tokio::test]
async fn test_adversarial_thundering_herd_failure_isolation() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Revoked grant"
        })))
        .mount(&mock_server)
        .await;

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did = "did:plc:thundering_fail_tenant";
    let expired_session = create_expired_session(
        did,
        &mock_server.uri(),
        &token_endpoint,
        Some("rt-fail".to_string()),
    );

    let tenant = Tenant::new(did).with_session(expired_session);
    registry.register_or_update(&tenant).unwrap();

    let mut tasks = Vec::new();
    for _ in 0..25 {
        let reg = registry.clone();
        tasks.push(tokio::spawn(
            async move { reg.get_pds_client(did, None).await },
        ));
    }

    for task in tasks {
        let res = task.await.unwrap();
        assert!(res.is_err(), "All concurrent requests must return Err");
        assert!(matches!(res, Err(SkybouncerError::Auth(_))));
    }

    // Cache must remain empty
    assert!(registry.pds_clients.read().get(did).is_none());
}

/// Stress-test multi-tenant session isolation under concurrent mixed outcomes:
/// - Tenant A: expired session, refresh fails (400 Bad Request)
/// - Tenant B: valid, active session (cached, zero network calls)
/// - Tenant C: expired session, refresh succeeds (200 OK)
/// 30 concurrent tasks across all 3 tenants must maintain strict isolation.
#[tokio::test]
async fn test_adversarial_multi_tenant_concurrent_isolation_mixed_outcomes() {
    let mock_server = MockServer::start().await;

    // Tenant A token endpoint -> 400 Bad Request
    Mock::given(method("POST"))
        .and(path("/oauth/token_a"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "Tenant A revoked"
        })))
        .mount(&mock_server)
        .await;

    // Tenant C token endpoint -> 200 OK
    Mock::given(method("POST"))
        .and(path("/oauth/token_c"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "fresh-nonce-c")
                .set_body_json(json!({
                    "access_token": "at-refreshed-tenant-c",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-fresh-tenant-c",
                    "scope": "atproto",
                    "sub": "did:plc:isolated_tenant_c"
                })),
        )
        .mount(&mock_server)
        .await;

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did_a = "did:plc:isolated_tenant_a";
    let did_b = "did:plc:isolated_tenant_b";
    let did_c = "did:plc:isolated_tenant_c";

    // Register Tenant A (failing expired)
    let token_endpoint_a = format!("{}/oauth/token_a", mock_server.uri());
    let session_a = create_expired_session(
        did_a,
        &mock_server.uri(),
        &token_endpoint_a,
        Some("rt-a".to_string()),
    );
    registry
        .register_or_update(&Tenant::new(did_a).with_session(session_a))
        .unwrap();

    // Register Tenant B (active valid)
    let dpop_b = DPoPKey::generate();
    let session_b = OAuthSession::new(
        did_b,
        "at-active-token-b",
        Some("rt-b".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        dpop_b,
        Some("https://pds.example.com".to_string()),
        Some(mock_server.uri()),
        Some(format!("{}/oauth/token_b", mock_server.uri())),
    )
    .unwrap();
    registry
        .register_or_update(&Tenant::new(did_b).with_session(session_b))
        .unwrap();

    // Register Tenant C (succeeding expired)
    let token_endpoint_c = format!("{}/oauth/token_c", mock_server.uri());
    let session_c = create_expired_session(
        did_c,
        &mock_server.uri(),
        &token_endpoint_c,
        Some("rt-c".to_string()),
    );
    registry
        .register_or_update(&Tenant::new(did_c).with_session(session_c))
        .unwrap();

    let reg_arc = Arc::new(registry);
    let mut tasks = Vec::new();

    // Spawn 10 concurrent requests for each tenant (30 total)
    for i in 0..30 {
        let r = Arc::clone(&reg_arc);
        tasks.push(tokio::spawn(async move {
            match i % 3 {
                0 => {
                    let res = r.get_pds_client(did_a, None).await;
                    assert!(res.is_err(), "Tenant A must always fail with auth error");
                    assert!(matches!(res, Err(SkybouncerError::Auth(_))));
                }
                1 => {
                    let res = r.get_pds_client(did_b, None).await;
                    assert!(res.is_ok(), "Tenant B must always succeed");
                    let client = res.unwrap().unwrap();
                    assert_eq!(client.session().access_token(), "at-active-token-b");
                }
                _ => {
                    let res = r.get_pds_client(did_c, None).await;
                    if let Err(ref e) = res {
                        eprintln!("TENANT C ERROR: {e:?}");
                    }
                    assert!(res.is_ok(), "Tenant C must always succeed");
                    let client = res.unwrap().unwrap();
                    assert_eq!(client.session().access_token(), "at-refreshed-tenant-c");
                }
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    // Verify cache isolation
    assert!(
        reg_arc.pds_clients.read().get(did_a).is_none(),
        "Tenant A must remain evicted"
    );
    assert!(
        reg_arc.pds_clients.read().get(did_b).is_some(),
        "Tenant B must be cached"
    );
    assert!(
        reg_arc.pds_clients.read().get(did_c).is_some(),
        "Tenant C must be cached"
    );
}

/// Stress-test self-healing / session recovery after credential remediation:
/// 1. Tenant fails refresh and is evicted.
/// 2. Tenant updates session with a valid credential.
/// 3. Subsequent get_pds_client call succeeds immediately and caches client.
#[tokio::test]
async fn test_adversarial_session_recovery_after_remediation() {
    let mock_server = MockServer::start().await;
    let token_endpoint = format!("{}/oauth/token", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant"
        })))
        .mount(&mock_server)
        .await;

    let oauth_client = create_test_oauth_client();
    let registry = TenantRegistry::open_in_memory().unwrap();
    registry.set_oauth_client(oauth_client);

    let did = "did:plc:healing_tenant";
    let expired_session = create_expired_session(
        did,
        &mock_server.uri(),
        &token_endpoint,
        Some("rt-failed".to_string()),
    );
    registry
        .register_or_update(&Tenant::new(did).with_session(expired_session))
        .unwrap();

    // Step 1: Initial resolution encounters 400 error and evicts client
    let res1 = registry.get_pds_client(did, None).await;
    assert!(res1.is_err());
    assert!(registry.pds_clients.read().get(did).is_none());

    // Step 2: Tenant re-authenticates and updates session in registry
    let dpop = DPoPKey::generate();
    let fresh_session = OAuthSession::new(
        did,
        "at-freshly-logged-in-token",
        Some("rt-fresh".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        dpop,
        Some("https://pds.example.com".to_string()),
        Some(mock_server.uri()),
        Some(token_endpoint),
    )
    .unwrap();
    registry
        .register_or_update(&Tenant::new(did).with_session(fresh_session))
        .unwrap();

    // Step 3: Next resolution succeeds immediately without network error
    let res2 = registry.get_pds_client(did, None).await;
    assert!(res2.is_ok());
    let client = res2.unwrap().unwrap();
    assert_eq!(
        client.session().access_token(),
        "at-freshly-logged-in-token"
    );

    // Step 4: Successfully cached
    assert!(registry.pds_clients.read().get(did).is_some());
}
