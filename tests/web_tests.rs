//! Comprehensive integration test suite for the Sovereign Web Dashboard & REST API.
//!
//! Validates:
//! - Embedded Single-Page Application (SPA) delivery (`GET /`).
//! - System operational telemetry and KPIs (`GET /api/status`).
//! - Live rubric and sensitivity threshold updates (`GET /api/rules`, `POST /api/rules`).
//! - Bounced audit feed and one-click sovereign pardons (`GET /api/bounces`, `POST /api/pardon`).
//! - Interactive dry-run rule simulator (`POST /api/simulate`).
//! - ATProto OAuth 2.0 PKCE metadata, login, and callback endpoints (`/oauth/*`).
//! - Real HTTP server lifecycle, connection handling, and graceful shutdown (`run_web_server`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use skyauth::client::OAuthClientMetadata;
use skybouncer::classifier::{RuleRubric, Sensitivity, Verdict};
use skybouncer::engine::{SkybouncerConfig, SkybouncerEngine};
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{AllowlistEntry, BouncedUser, DeduplicationCache, ModListManager};
use skybouncer::web::{
    create_web_router, run_web_server, AddAllowlistResponse, PardonResponse,
    RemoveAllowlistResponse, RulesResponse, SimulateResponse, StatusResponse, WebServerConfig,
};

// =============================================================================
// Test Harness Fixtures
// =============================================================================

async fn setup_test_web_environment(
    protected_did: &str,
) -> (
    Arc<SkybouncerEngine>,
    Arc<DeduplicationCache>,
    MockPdsServer,
    axum::Router,
) {
    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new(
        "Block hate speech, harassment, and crypto scams",
        Sensitivity::Medium,
    );
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client(protected_did));
    let classifier = Arc::new(skybouncer::classifier::MockClassifier::new(
        Verdict::permitted("Default test verdict: benign interaction"),
    ));

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected_did.to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_enable_heuristic_prefilter(true)
        .with_admin_did(protected_did);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    ));

    let metadata = OAuthClientMetadata::new(
        "http://127.0.0.1:3000/oauth/client-metadata.json",
        "http://127.0.0.1:3000/oauth/callback",
    )
    .with_client_name("Skybouncer Test Dashboard");

    let router = create_web_router(Arc::clone(&engine), None, metadata);

    (engine, cache, pds, router)
}

fn create_test_session(engine: &SkybouncerEngine, did: &str) -> String {
    engine
        .tenant_registry()
        .create_web_session(did, Duration::from_secs(3600))
        .expect("create test session")
}

// =============================================================================
// Dashboard UI Delivery Tests
// =============================================================================

#[tokio::test]
async fn test_serve_dashboard_html() {
    let (_engine, _cache, _pds, app) = setup_test_web_environment("did:plc:protected123").await;

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(content_type.contains("text/html"));

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);

    assert!(body_str.contains("Skybouncer"));
    assert!(body_str.contains("Sovereign"));
    assert!(body_str.contains("color-scheme"));
    assert!(body_str.contains("Simulator"));
    assert!(body_str.contains("Recently Bounced"));
    assert!(body_str.contains("Evaluation Queue"));
    assert!(body_str.contains("Queue Overflows"));
    assert!(body_str.contains("Users Monitored"));
    assert!(body_str.contains("kpi-monitored-card"));
    assert!(body_str.contains("bskyProfileUrl"));
    assert!(body_str.contains("bskyPostUrl"));
    assert!(body_str.contains("formatDid"));
}

#[tokio::test]
async fn test_health_endpoints() {
    let (_engine, _cache, _pds, app) = setup_test_web_environment("did:plc:protected123").await;

    // 1. Test /healthz
    let res1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res1.status(), StatusCode::OK);
    let bytes1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
        .await
        .unwrap();
    let health1: skybouncer::web::HealthResponse = serde_json::from_slice(&bytes1).unwrap();
    assert_eq!(health1.status, "healthy");
    assert_eq!(health1.version, env!("CARGO_PKG_VERSION"));

    // 2. Test /api/health
    let res2 = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res2.status(), StatusCode::OK);
    let bytes2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
        .await
        .unwrap();
    let health2: skybouncer::web::HealthResponse = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(health2.status, "healthy");
    assert_eq!(health2.version, env!("CARGO_PKG_VERSION"));
}

// =============================================================================
// Telemetry & Status API Tests
// =============================================================================

#[tokio::test]
async fn test_api_status_endpoint() {
    let (engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;

    // Simulate some engine stats
    let stats = engine.stats();
    stats.commits_received.fetch_add(1, Ordering::Relaxed);
    stats.interactions_matched.fetch_add(1, Ordering::Relaxed);
    stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);

    // Unauthenticated status call redacts protected_dids and stats (privacy hardening M8)
    let unauth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::OK);
    let unauth_bytes = axum::body::to_bytes(unauth_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let unauth_status: StatusResponse = serde_json::from_slice(&unauth_bytes).unwrap();
    assert!(unauth_status.protected_dids.is_empty());
    assert_eq!(unauth_status.stats.commits_received, 0);

    let alice_token = create_test_session(&engine, "did:plc:alice");

    // Authenticated status call returns full protected_dids and stats
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header("cookie", format!("skybouncer_session={alice_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let status: StatusResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(status.protected_dids, vec!["did:plc:alice"]);
    assert_eq!(status.stats.commits_received, 1);
    assert_eq!(status.stats.interactions_matched, 1);
    assert_eq!(status.stats.dedup_cache_hits, 1);
    assert_eq!(status.rubric.sensitivity, Sensitivity::Medium);
    assert_eq!(status.rubric.threshold, 0.75);
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
}

// =============================================================================
// Rules Configuration API Tests
// =============================================================================

#[tokio::test]
async fn test_api_get_and_update_rules() {
    let (engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;
    let alice_token = create_test_session(&engine, "did:plc:alice");

    // 0. Unauthenticated GET /api/rules returns 401 Unauthorized
    let unauth_req = Request::builder()
        .uri("/api/rules")
        .body(Body::empty())
        .unwrap();
    let unauth_resp = app.clone().oneshot(unauth_req).await.unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 0b. Spoofed x-skybouncer-did without valid session returns 401 Unauthorized
    let spoof_req = Request::builder()
        .uri("/api/rules")
        .header("x-skybouncer-did", "did:plc:alice")
        .body(Body::empty())
        .unwrap();
    let spoof_resp = app.clone().oneshot(spoof_req).await.unwrap();
    assert_eq!(spoof_resp.status(), StatusCode::UNAUTHORIZED);

    // 1. Authenticated GET /api/rules returns initial rubric
    let get_req = Request::builder()
        .uri("/api/rules")
        .header("cookie", format!("skybouncer_session={alice_token}"))
        .body(Body::empty())
        .unwrap();
    let get_resp = app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let initial_rules: RulesResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(initial_rules.sensitivity, Sensitivity::Medium);

    // 2. Unauthenticated POST /api/rules returns 401 Unauthorized
    let unauth_post = Request::builder()
        .method("POST")
        .uri("/api/rules")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "prompt": "Test unauth update",
                "sensitivity": "High"
            }))
            .unwrap(),
        ))
        .unwrap();
    let unauth_post_resp = app.clone().oneshot(unauth_post).await.unwrap();
    assert_eq!(unauth_post_resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Authenticated POST /api/rules updates rubric to High sensitivity
    let update_payload = json!({
        "prompt": "Strict anti-spam policy: drop all unsolicited promotions",
        "sensitivity": "High"
    });
    let post_req = Request::builder()
        .method("POST")
        .uri("/api/rules")
        .header("cookie", format!("skybouncer_session={alice_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&update_payload).unwrap()))
        .unwrap();
    let post_resp = app.clone().oneshot(post_req).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_bytes = axum::body::to_bytes(post_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let updated_rules: RulesResponse = serde_json::from_slice(&post_bytes).unwrap();
    assert_eq!(updated_rules.sensitivity, Sensitivity::High);
    assert_eq!(updated_rules.threshold, 0.60);
    assert_eq!(
        updated_rules.prompt,
        "Strict anti-spam policy: drop all unsolicited promotions"
    );

    // 4. Verify underlying engine reflects update
    let active_rubric = engine.rubric();
    assert_eq!(active_rubric.sensitivity, Sensitivity::High);
    assert_eq!(
        active_rubric.prompt,
        "Strict anti-spam policy: drop all unsolicited promotions"
    );

    // 5. Verify bad request on empty prompt
    let invalid_payload = json!({
        "prompt": "   ",
        "sensitivity": "Low"
    });
    let bad_req = Request::builder()
        .method("POST")
        .uri("/api/rules")
        .header("cookie", format!("skybouncer_session={alice_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&invalid_payload).unwrap()))
        .unwrap();
    let bad_resp = app.oneshot(bad_req).await.unwrap();
    assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
}

// =============================================================================
// Bounces & Sovereign Pardon API Tests
// =============================================================================

#[tokio::test]
async fn test_api_bounces_feed_and_pardon_lifecycle() {
    let (engine, cache, pds, app) = setup_test_web_environment("did:plc:protected-owner").await;

    // Ensure list exists on mock PDS
    let list_uri = engine
        .ensure_mod_list("did:plc:protected-owner")
        .await
        .unwrap();

    // Populate mock bounced user
    let violator_did = "did:plc:toxic-violator-999";
    let list_item_uri = format!("{list_uri}/item/item123");
    let bounce_entry = BouncedUser {
        subject_did: violator_did.to_string(),
        protected_did: "did:plc:protected-owner".to_string(),
        listitem_uri: list_item_uri.clone(),
        listitem_rkey: "item123".to_string(),
        listitem_cid: "bafytestcid".to_string(),
        category: "HateSpeech".to_string(),
        confidence: 0.95,
        reason: "Targeted harassment".to_string(),
        post_uri: "at://did:plc:toxic-violator-999/app.bsky.feed.post/post123".to_string(),
        post_text: "You are terrible".to_string(),
        bounced_at: 1_720_000_000_000_000,
    };
    cache.record_bounce(&bounce_entry).unwrap();
    let owner_token = create_test_session(&engine, "did:plc:protected-owner");

    // 0. Unauthenticated GET /api/bounces returns 401 Unauthorized
    let unauth_bounces_req = Request::builder()
        .uri("/api/bounces")
        .body(Body::empty())
        .unwrap();
    let unauth_bounces_resp = app.clone().oneshot(unauth_bounces_req).await.unwrap();
    assert_eq!(unauth_bounces_resp.status(), StatusCode::UNAUTHORIZED);

    // 0b. Unauthenticated POST /api/pardon returns 401 Unauthorized
    let unauth_pardon_req = Request::builder()
        .method("POST")
        .uri("/api/pardon")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "subject_did": violator_did })).unwrap(),
        ))
        .unwrap();
    let unauth_pardon_resp = app.clone().oneshot(unauth_pardon_req).await.unwrap();
    assert_eq!(unauth_pardon_resp.status(), StatusCode::UNAUTHORIZED);

    // 0c. Cross-tenant pardon attempt: Mallory cannot pardon user from protected-owner's list
    let mallory_token = create_test_session(&engine, "did:plc:mallory");
    let mallory_pardon_req = Request::builder()
        .method("POST")
        .uri("/api/pardon")
        .header("cookie", format!("skybouncer_session={mallory_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "subject_did": violator_did,
                "protected_did": "did:plc:protected-owner"
            }))
            .unwrap(),
        ))
        .unwrap();
    let mallory_pardon_resp = app.clone().oneshot(mallory_pardon_req).await.unwrap();
    assert_eq!(mallory_pardon_resp.status(), StatusCode::FORBIDDEN);

    // 1. GET /api/bounces returns the recorded bounce
    let bounces_req = Request::builder()
        .uri("/api/bounces?limit=10")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .body(Body::empty())
        .unwrap();
    let bounces_resp = app.clone().oneshot(bounces_req).await.unwrap();
    assert_eq!(bounces_resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(bounces_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let bounces: Vec<BouncedUser> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bounces.len(), 1);
    assert_eq!(bounces[0].subject_did, violator_did);
    assert_eq!(bounces[0].reason, "Targeted harassment");

    // 2. POST /api/pardon pardons the violator
    let pardon_payload = json!({ "subject_did": violator_did });
    let pardon_req = Request::builder()
        .method("POST")
        .uri("/api/pardon")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&pardon_payload).unwrap()))
        .unwrap();
    let pardon_resp = app.clone().oneshot(pardon_req).await.unwrap();
    assert_eq!(pardon_resp.status(), StatusCode::OK);
    let pardon_bytes = axum::body::to_bytes(pardon_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let pardon_result: PardonResponse = serde_json::from_slice(&pardon_bytes).unwrap();
    assert!(pardon_result.pardoned);
    assert_eq!(pardon_result.subject_did, violator_did);

    // Verify PDS deleteRecord was called
    let deleted = pds.deleted_records.lock().clone();
    assert_eq!(deleted.len(), 1);

    // 3. Subsequent pardon returns pardoned: false (already removed)
    let re_pardon_req = Request::builder()
        .method("POST")
        .uri("/api/pardon")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&pardon_payload).unwrap()))
        .unwrap();
    let re_pardon_resp = app.clone().oneshot(re_pardon_req).await.unwrap();
    assert_eq!(re_pardon_resp.status(), StatusCode::OK);
    let re_bytes = axum::body::to_bytes(re_pardon_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let re_result: PardonResponse = serde_json::from_slice(&re_bytes).unwrap();
    assert!(!re_result.pardoned);

    // 4. GET /api/bounces is now empty
    let empty_req = Request::builder()
        .uri("/api/bounces")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .body(Body::empty())
        .unwrap();
    let empty_resp = app.oneshot(empty_req).await.unwrap();
    let empty_bytes = axum::body::to_bytes(empty_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let empty_bounces: Vec<BouncedUser> = serde_json::from_slice(&empty_bytes).unwrap();
    assert!(empty_bounces.is_empty());
}

// =============================================================================
// Dry-Run Simulator API Tests
// =============================================================================

#[tokio::test]
async fn test_api_simulate_unauthenticated_rejected() {
    let (_engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;

    let payload = json!({
        "text": "FREE AIRDROP LIVE NOW!",
        "author_did": "did:plc:spammer123"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_api_simulate_heuristic_match() {
    let (engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;
    let alice_token = create_test_session(&engine, "did:plc:alice");

    let payload = json!({
        "text": "FREE AIRDROP LIVE NOW! Connect wallet to claim free tokens immediately!",
        "author_did": "did:plc:spammer123"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
        .header("cookie", format!("skybouncer_session={alice_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: SimulateResponse = serde_json::from_slice(&bytes).unwrap();

    assert!(result.violates);
    assert_eq!(result.evaluator, "heuristic_prefilter");
    assert!(result.meets_threshold);
    assert_eq!(result.category.as_deref(), Some("crypto_spam"));
}

#[tokio::test]
async fn test_api_simulate_heuristic_disabled_by_default() {
    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block crypto scams", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));
    let classifier = Arc::new(skybouncer::classifier::MockClassifier::new(
        Verdict::permitted("Passed by primary classifier because heuristic is disabled"),
    ));

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());
    // Default config has enable_heuristic_prefilter = false
    let config = SkybouncerConfig::new(protected_dids, rubric);
    assert!(!config.enable_heuristic_prefilter);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    ));

    let metadata = OAuthClientMetadata::new(
        "http://127.0.0.1:3000/oauth/client-metadata.json",
        "http://127.0.0.1:3000/oauth/callback",
    )
    .with_client_name("Skybouncer Test Dashboard");
    let app = create_web_router(Arc::clone(&engine), None, metadata);
    let alice_token = create_test_session(&engine, "did:plc:alice");

    let payload = json!({
        "text": "FREE AIRDROP LIVE NOW! Connect wallet to claim free tokens immediately!",
        "author_did": "did:plc:spammer123"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
        .header("cookie", format!("skybouncer_session={alice_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: SimulateResponse = serde_json::from_slice(&bytes).unwrap();

    // Since heuristic pre-filter is disabled by default, the request routes to the primary classifier
    assert!(!result.violates);
    assert_eq!(result.evaluator, "primary_classifier");
}

#[tokio::test]
async fn test_api_simulate_benign_text() {
    let (engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;
    let alice_token = create_test_session(&engine, "did:plc:alice");

    let payload = json!({
        "text": "Hello! Really enjoyed reading your recent technical architecture notes.",
        "author_did": "did:plc:friendly-peer"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
        .header("cookie", format!("skybouncer_session={alice_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: SimulateResponse = serde_json::from_slice(&bytes).unwrap();

    assert!(!result.violates);
    assert_eq!(result.evaluator, "primary_classifier");
    assert!(!result.meets_threshold);
}

#[tokio::test]
async fn test_api_simulate_validation_error() {
    let (engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;
    let alice_token = create_test_session(&engine, "did:plc:alice");

    let payload = json!({ "text": "   " });
    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
        .header("cookie", format!("skybouncer_session={alice_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_api_simulate_tiered_inspection_escalation() {
    use skybouncer::classifier::{CertaintyConfig, MockClassifier, TieredClassifier};

    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block toxicity", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client("did:plc:alice"));

    // Primary returns borderline confidence 0.65 (in uncertainty band 0.40..0.85)
    let primary = Arc::new(MockClassifier::new(Verdict::permitted_with_confidence(
        "Borderline question with critical phrasing",
        0.65,
    )));
    // Fallback returns decisive permitted 0.95
    let fallback = Arc::new(MockClassifier::new(Verdict::permitted_with_confidence(
        "Clarifying question, no harassment",
        0.95,
    )));

    let certainty = CertaintyConfig::new(0.40, 0.85, true);
    let tiered = Arc::new(TieredClassifier::new(primary, fallback, certainty));

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:alice".to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        tiered,
        modlist_manager,
        pds_client,
    ));
    let metadata = OAuthClientMetadata::new(
        "http://127.0.0.1:3000/oauth/client-metadata.json",
        "http://127.0.0.1:3000/oauth/callback",
    );
    let app = create_web_router(Arc::clone(&engine), None, metadata);

    let payload = json!({
        "text": "Can you explain why you said that earlier? Seems contradictory.",
        "author_did": "did:plc:questioner"
    });
    let alice_token = create_test_session(&engine, "did:plc:alice");

    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
        .header("cookie", format!("skybouncer_session={alice_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: SimulateResponse = serde_json::from_slice(&bytes).unwrap();

    assert!(!result.violates);
    assert_eq!(result.evaluator, "fallback_uncertainty_classifier");
    assert_eq!(result.confidence, 0.95);

    // Verify Tier 1 breakdown box
    let tier1 = result.tier1.expect("tier1 details present");
    assert_eq!(tier1.status, "escalated");
    assert_eq!(tier1.confidence, 0.65);
    assert!(tier1.reason.contains("Borderline question"));

    // Verify Tier 2 breakdown box
    let tier2 = result.tier2.expect("tier2 details present");
    assert_eq!(tier2.status, "resolved");
    assert_eq!(tier2.confidence, 0.95);
    assert!(tier2.reason.contains("Clarifying question"));

    // Verify simulation isolation: engine stats remained 0
    let status_req = Request::builder()
        .uri("/api/status")
        .body(Body::empty())
        .unwrap();
    let status_resp = app.oneshot(status_req).await.unwrap();
    let status_bytes = axum::body::to_bytes(status_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let status: StatusResponse = serde_json::from_slice(&status_bytes).unwrap();
    assert_eq!(status.stats.model_evaluations, 0);
    assert_eq!(status.stats.tier1_evaluations, 0);
    assert_eq!(status.stats.tier2_evaluations, 0);
}

// =============================================================================
// ATProto OAuth 2.0 PKCE Endpoint Tests
// =============================================================================

#[tokio::test]
async fn test_oauth_client_metadata_endpoint() {
    let (_engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;

    let req = Request::builder()
        .uri("/oauth/client-metadata.json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let meta: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        meta["client_id"],
        "http://127.0.0.1:3000/oauth/client-metadata.json"
    );
    assert_eq!(
        meta["redirect_uris"][0],
        "http://127.0.0.1:3000/oauth/callback"
    );
    assert_eq!(meta["client_name"], "Skybouncer Test Dashboard");
}

#[tokio::test]
async fn test_oauth_login_and_callback_error_handling() {
    let (_engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;

    // Missing handle query param
    let login_req = Request::builder()
        .uri("/oauth/login")
        .body(Body::empty())
        .unwrap();
    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(login_resp.status(), StatusCode::BAD_REQUEST);

    // Empty handle query param
    let empty_handle_req = Request::builder()
        .uri("/oauth/login?handle=")
        .body(Body::empty())
        .unwrap();
    let empty_handle_resp = app.clone().oneshot(empty_handle_req).await.unwrap();
    assert_eq!(empty_handle_resp.status(), StatusCode::BAD_REQUEST);

    // Callback with missing code / state query params
    let callback_req = Request::builder()
        .uri("/oauth/callback")
        .body(Body::empty())
        .unwrap();
    let callback_resp = app.oneshot(callback_req).await.unwrap();
    assert_eq!(callback_resp.status(), StatusCode::BAD_REQUEST);
}

// =============================================================================
// Live HTTP Web Server Lifecycle & Graceful Shutdown Test
// =============================================================================

#[tokio::test]
async fn test_live_web_server_lifecycle_and_graceful_shutdown() {
    // Find an available random port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ephemeral_port = listener.local_addr().unwrap().port();
    drop(listener); // release so run_web_server can bind it

    let (engine, _cache, _pds, _app) = setup_test_web_environment("did:plc:live-test").await;
    let web_config = WebServerConfig::new("127.0.0.1", ephemeral_port);
    let cancel = CancellationToken::new();

    let server_handle = {
        let engine = Arc::clone(&engine);
        let cancel = cancel.clone();
        tokio::spawn(async move { run_web_server(web_config, engine, cancel).await })
    };

    // Wait briefly for server to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    let token = engine
        .tenant_registry()
        .create_web_session("did:plc:live-test", Duration::from_secs(3600))
        .unwrap();

    // Issue real HTTP request to the running server
    let client = reqwest::Client::new();
    let status_url = format!("http://127.0.0.1:{ephemeral_port}/api/status");
    let resp = client
        .get(&status_url)
        .header("cookie", format!("skybouncer_session={token}"))
        .send()
        .await;
    assert!(resp.is_ok(), "Live HTTP request to web server succeeded");
    let resp = resp.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let status_body: StatusResponse = resp.json().await.unwrap();
    assert_eq!(status_body.protected_dids, vec!["did:plc:live-test"]);

    // Trigger graceful shutdown
    cancel.cancel();

    // Verify task terminates cleanly without panicking
    let exit_result = tokio::time::timeout(Duration::from_secs(3), server_handle).await;
    assert!(exit_result.is_ok(), "Server shutdown within timeout");
    let inner_res = exit_result.unwrap().unwrap();
    assert!(inner_res.is_ok(), "Server returned clean Ok(())");
}

// =============================================================================
// Auth Session & Admin Fleet Endpoints Integration Tests
// =============================================================================

#[tokio::test]
async fn test_api_session_and_admin_endpoints() {
    let (engine, _cache, _pds, app) = setup_test_web_environment("did:plc:admin123").await;

    let test_tenant =
        skybouncer::tenant::Tenant::new("did:plc:tenant456").with_handle("tenant.bsky.social");
    engine
        .tenant_registry()
        .register_or_update(&test_tenant)
        .expect("enroll tenant");

    let tenant_token = create_test_session(&engine, "did:plc:tenant456");
    let admin_token = create_test_session(&engine, "did:plc:admin123");

    // 1. Unauthenticated /api/me
    let req = Request::builder()
        .uri("/api/me")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let me: skybouncer::web::UserSessionResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!me.authenticated);
    assert_eq!(me.did, None);
    assert!(!me.is_admin);

    // 1b. Spoofed ?did= query param or x-skybouncer-did header without session is ignored
    let req = Request::builder()
        .uri("/api/me?did=did:plc:tenant456")
        .header("x-skybouncer-did", "did:plc:tenant456")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let me: skybouncer::web::UserSessionResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!me.authenticated);

    // 2. Authenticated via session cookie for enrolled tenant
    let req = Request::builder()
        .uri("/api/me")
        .header("cookie", format!("skybouncer_session={tenant_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let me: skybouncer::web::UserSessionResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(me.authenticated);
    assert_eq!(me.did.as_deref(), Some("did:plc:tenant456"));
    assert_eq!(me.handle.as_deref(), Some("tenant.bsky.social"));
    assert!(!me.is_admin);
    assert!(me.is_active);
    assert_eq!(me.monitored_users_count, None);

    // 3. Authenticated via session Bearer header for admin DID
    let req = Request::builder()
        .uri("/api/me")
        .header("authorization", format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let me: skybouncer::web::UserSessionResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(me.authenticated);
    assert_eq!(me.did.as_deref(), Some("did:plc:admin123"));
    assert!(me.is_admin);
    assert!(me.is_active);
    assert_eq!(me.monitored_users_count, Some(1));

    // 4. Non-admin accessing /api/admin/tenants -> 403 Forbidden
    let req = Request::builder()
        .uri("/api/admin/tenants")
        .header("cookie", format!("skybouncer_session={tenant_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4b. Anonymous accessing /api/admin/tenants -> 401 Unauthorized
    let req = Request::builder()
        .uri("/api/admin/tenants")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 5. Admin accessing /api/admin/tenants -> 200 OK
    let req = Request::builder()
        .uri("/api/admin/tenants")
        .header("cookie", format!("skybouncer_session={admin_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let fleet: skybouncer::web::AdminTenantsResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(fleet.total, 1);
    assert_eq!(fleet.active_count, 1);
    assert_eq!(fleet.paused_count, 0);
    assert_eq!(fleet.monitored_count, 1);
    assert_eq!(fleet.tenants[0].did, "did:plc:tenant456");

    // 5c. Non-admin accessing /api/admin/evaluations -> 403 Forbidden
    let req_non_admin_evals = Request::builder()
        .uri("/api/admin/evaluations")
        .header("cookie", format!("skybouncer_session={tenant_token}"))
        .body(Body::empty())
        .unwrap();
    let resp_non_admin_evals = app.clone().oneshot(req_non_admin_evals).await.unwrap();
    assert_eq!(resp_non_admin_evals.status(), StatusCode::FORBIDDEN);

    // 5d. Admin accessing /api/admin/evaluations -> 200 OK
    let req_admin_evals = Request::builder()
        .uri("/api/admin/evaluations")
        .header("cookie", format!("skybouncer_session={admin_token}"))
        .body(Body::empty())
        .unwrap();
    let resp_admin_evals = app.clone().oneshot(req_admin_evals).await.unwrap();
    assert_eq!(resp_admin_evals.status(), StatusCode::OK);
    let evals_bytes = axum::body::to_bytes(resp_admin_evals.into_body(), usize::MAX)
        .await
        .unwrap();
    let evals_resp: skybouncer::web::AdminEvaluationsResponse =
        serde_json::from_slice(&evals_bytes).unwrap();
    assert_eq!(evals_resp.total, 0);

    // 5e. Run a simulation and verify it is recorded in /api/admin/evaluations
    let sim_payload = json!({
        "text": "Testing simulation audit log integration",
        "author_did": "did:plc:sim-tester",
        "target_did": "did:plc:admin123"
    });
    let sim_req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
        .header("cookie", format!("skybouncer_session={admin_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&sim_payload).unwrap()))
        .unwrap();
    let sim_resp = app.clone().oneshot(sim_req).await.unwrap();
    assert_eq!(sim_resp.status(), StatusCode::OK);

    let req_admin_evals_after = Request::builder()
        .uri("/api/admin/evaluations")
        .header("cookie", format!("skybouncer_session={admin_token}"))
        .body(Body::empty())
        .unwrap();
    let resp_admin_evals_after = app.clone().oneshot(req_admin_evals_after).await.unwrap();
    assert_eq!(resp_admin_evals_after.status(), StatusCode::OK);
    let evals_after_bytes = axum::body::to_bytes(resp_admin_evals_after.into_body(), usize::MAX)
        .await
        .unwrap();
    let evals_after: skybouncer::web::AdminEvaluationsResponse =
        serde_json::from_slice(&evals_after_bytes).unwrap();
    assert_eq!(evals_after.total, 1);
    assert_eq!(evals_after.evaluations[0].source, "simulation");
    assert_eq!(evals_after.evaluations[0].author_did, "did:plc:sim-tester");
    assert_eq!(evals_after.evaluations[0].target_did, "did:plc:admin123");

    // 5f. Verify /api/status telemetry reports monitored_users_count for admin, but hides it for unauthenticated
    let status_req_admin = Request::builder()
        .uri("/api/status")
        .header("cookie", format!("skybouncer_session={admin_token}"))
        .body(Body::empty())
        .unwrap();
    let status_resp_admin = app.clone().oneshot(status_req_admin).await.unwrap();
    assert_eq!(status_resp_admin.status(), StatusCode::OK);
    let status_admin_bytes = axum::body::to_bytes(status_resp_admin.into_body(), usize::MAX)
        .await
        .unwrap();
    let status_admin: skybouncer::web::StatusResponse =
        serde_json::from_slice(&status_admin_bytes).unwrap();
    assert_eq!(status_admin.monitored_users_count, Some(1));

    let status_req_unauth = Request::builder()
        .uri("/api/status")
        .body(Body::empty())
        .unwrap();
    let status_resp_unauth = app.clone().oneshot(status_req_unauth).await.unwrap();
    assert_eq!(status_resp_unauth.status(), StatusCode::OK);
    let status_unauth_bytes = axum::body::to_bytes(status_resp_unauth.into_body(), usize::MAX)
        .await
        .unwrap();
    let status_unauth: skybouncer::web::StatusResponse =
        serde_json::from_slice(&status_unauth_bytes).unwrap();
    assert_eq!(status_unauth.monitored_users_count, None);

    // 6. Admin toggling tenant defense pause
    let toggle_req = Request::builder()
        .method("POST")
        .uri("/api/tenant/toggle")
        .header("cookie", format!("skybouncer_session={admin_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "did": "did:plc:tenant456",
                "is_active": false
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(toggle_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let toggle: skybouncer::web::ToggleTenantResponse =
        serde_json::from_slice(&body_bytes).unwrap();
    assert!(toggle.success);
    assert!(!toggle.is_active);

    // 7. Verify /api/me for tenant now shows is_active == false
    let req = Request::builder()
        .uri("/api/me")
        .header("cookie", format!("skybouncer_session={tenant_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let me: skybouncer::web::UserSessionResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!me.is_active);

    // 8. Logout endpoint clears skybouncer_session
    let logout_req = Request::builder()
        .method("POST")
        .uri("/api/auth/logout")
        .header("cookie", format!("skybouncer_session={tenant_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(logout_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie_hdr = resp.headers().get("set-cookie");
    assert!(cookie_hdr.is_some());
    let cookie_str = cookie_hdr.unwrap().to_str().unwrap();
    assert!(cookie_str.contains("skybouncer_session="));
    assert!(cookie_str.contains("Max-Age=0"));
    assert!(cookie_str.contains("HttpOnly"));

    // Verify session token is deleted from SQLite
    assert!(engine
        .tenant_registry()
        .validate_web_session(&tenant_token)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_api_tenant_isolated_rules_and_dynamic_handle_resolution() {
    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let enricher = Arc::new(skybouncer::enricher::MockContextEnricher::new());

    // Register a handle in mock enricher
    enricher.set_handle("alice.custom.domain", "did:plc:tenant-dynamic");

    let rubric = RuleRubric::new("Default global rubric: block spam", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client("did:plc:admin"));

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:admin".to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric).with_admin_did("did:plc:admin");

    let engine = Arc::new(
        SkybouncerEngine::builder(config)
            .with_cache(cache.clone())
            .with_modlist_manager(modlist)
            .with_pds_client(pds_client)
            .with_enricher(enricher)
            .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
                Verdict::permitted("ok"),
            )))
            .build()
            .expect("engine build"),
    );

    let metadata = OAuthClientMetadata::new(
        "http://127.0.0.1:3000/oauth/client-metadata.json",
        "http://127.0.0.1:3000/oauth/callback",
    );
    let app = create_web_router(Arc::clone(&engine), None, metadata);

    // 1. Enroll tenant WITHOUT handle
    let tenant = skybouncer::tenant::Tenant::new("did:plc:tenant-dynamic");
    engine
        .tenant_registry()
        .register_or_update(&tenant)
        .unwrap();

    let dynamic_token = create_test_session(&engine, "did:plc:tenant-dynamic");
    let admin_token = create_test_session(&engine, "did:plc:admin");

    // 2. Call /api/me with session cookie -> handle should resolve dynamically to alice.custom.domain!
    let req = Request::builder()
        .uri("/api/me")
        .header("cookie", format!("skybouncer_session={dynamic_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let me: skybouncer::web::UserSessionResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(me.authenticated);
    assert_eq!(me.handle.as_deref(), Some("alice.custom.domain"));

    // 3. Verify handle was cached into SQLite
    let cached_tenant = engine
        .tenant_registry()
        .get("did:plc:tenant-dynamic")
        .unwrap()
        .unwrap();
    assert_eq!(cached_tenant.handle.as_deref(), Some("alice.custom.domain"));

    // 4. Update rules for this tenant via POST /api/rules (authenticated)
    let custom_payload = json!({
        "prompt": "Custom tenant rubric: block aggressive political baiting",
        "sensitivity": "Low"
    });
    let post_req = Request::builder()
        .method("POST")
        .uri("/api/rules")
        .header("cookie", format!("skybouncer_session={dynamic_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&custom_payload).unwrap()))
        .unwrap();
    let post_resp = app.clone().oneshot(post_req).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_bytes = axum::body::to_bytes(post_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let updated: RulesResponse = serde_json::from_slice(&post_bytes).unwrap();
    assert_eq!(updated.sensitivity, Sensitivity::Low);
    assert_eq!(
        updated.prompt,
        "Custom tenant rubric: block aggressive political baiting"
    );

    // 5. Unauthenticated GET /api/rules returns 401 Unauthorized
    let unauth_req = Request::builder()
        .uri("/api/rules")
        .body(Body::empty())
        .unwrap();
    let unauth_resp = app.clone().oneshot(unauth_req).await.unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 5b. Authenticated user Bob attempting to view Alice's rules returns 403 Forbidden
    let bob = skybouncer::tenant::Tenant::new("did:plc:bob");
    engine.tenant_registry().register_or_update(&bob).unwrap();
    let bob_token = create_test_session(&engine, "did:plc:bob");
    let snoop_req = Request::builder()
        .uri("/api/rules?did=did:plc:tenant-dynamic")
        .header("cookie", format!("skybouncer_session={bob_token}"))
        .body(Body::empty())
        .unwrap();
    let snoop_resp = app.clone().oneshot(snoop_req).await.unwrap();
    assert_eq!(snoop_resp.status(), StatusCode::FORBIDDEN);

    // 6. Tenant GET /api/rules returns their own custom rubric
    let tenant_req = Request::builder()
        .uri("/api/rules")
        .header("cookie", format!("skybouncer_session={dynamic_token}"))
        .body(Body::empty())
        .unwrap();
    let tenant_resp = app.clone().oneshot(tenant_req).await.unwrap();
    assert_eq!(tenant_resp.status(), StatusCode::OK);
    let tenant_bytes = axum::body::to_bytes(tenant_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let tenant_rules: RulesResponse = serde_json::from_slice(&tenant_bytes).unwrap();
    assert_eq!(tenant_rules.sensitivity, Sensitivity::Low);
    assert_eq!(
        tenant_rules.prompt,
        "Custom tenant rubric: block aggressive political baiting"
    );

    // 6b. Admin inspecting tenant's rubric via query param returns 200 OK
    let admin_req = Request::builder()
        .uri("/api/rules?did=did:plc:tenant-dynamic")
        .header("cookie", format!("skybouncer_session={admin_token}"))
        .body(Body::empty())
        .unwrap();
    let admin_resp = app.clone().oneshot(admin_req).await.unwrap();
    assert_eq!(admin_resp.status(), StatusCode::OK);

    // 7. GET /api/me propagates custom rubric in session response
    let me_req = Request::builder()
        .uri("/api/me")
        .header("cookie", format!("skybouncer_session={dynamic_token}"))
        .body(Body::empty())
        .unwrap();
    let me_resp = app.oneshot(me_req).await.unwrap();
    let me_bytes = axum::body::to_bytes(me_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let me_final: skybouncer::web::UserSessionResponse = serde_json::from_slice(&me_bytes).unwrap();
    assert_eq!(
        me_final.rubric.as_ref().map(|r| r.prompt.as_str()),
        Some("Custom tenant rubric: block aggressive political baiting")
    );
    assert_eq!(
        me_final.rubric.as_ref().map(|r| r.sensitivity),
        Some(Sensitivity::Low)
    );
}

// =============================================================================
// SSRF Prevention Integration Tests
// =============================================================================

#[tokio::test]
async fn test_simulate_ssrf_prevention() {
    let (engine, _cache, _pds, app) = setup_test_web_environment("did:plc:admin").await;
    let admin_token = create_test_session(&engine, "did:plc:admin");

    let malicious_urls = vec![
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/internal",
        "http://localhost:3000/admin",
        "http://10.0.0.1/secrets",
        "http://192.168.1.1/router",
        "file:///etc/passwd",
        "ftp://127.0.0.1/test",
    ];

    for malicious_url in malicious_urls {
        let payload = json!({
            "text": "Check this image",
            "author_did": "did:plc:attacker",
            "image_url": malicious_url
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/simulate")
            .header("cookie", format!("skybouncer_session={admin_token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "SSRF URL '{malicious_url}' must be rejected with 400 Bad Request"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&bytes);
        assert!(
            body_str.contains("restricted")
                || body_str.contains("scheme")
                || body_str.contains("Invalid image URL")
                || body_str.contains("host"),
            "Error response should describe restriction for {malicious_url}: {body_str}"
        );
    }
}

#[tokio::test]
async fn test_web_allowlist_endpoints_and_pardon_immunization() {
    let protected_did = "did:plc:protected-owner";
    let (engine, cache, pds, app) = setup_test_web_environment(protected_did).await;
    let owner_token = create_test_session(&engine, protected_did);

    // 1. Initial allowlist is empty
    let list_req = Request::builder()
        .uri("/api/allowlist")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .body(Body::empty())
        .unwrap();
    let list_resp = app.clone().oneshot(list_req).await.unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(list_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let entries: Vec<AllowlistEntry> = serde_json::from_slice(&bytes).unwrap();
    assert!(entries.is_empty());

    // 2. Add an account to the allowlist via POST /api/allowlist
    let add_payload = json!({
        "subject": "did:plc:friend1",
        "reason": "Personal friend"
    });
    let add_req = Request::builder()
        .method("POST")
        .uri("/api/allowlist")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&add_payload).unwrap()))
        .unwrap();
    let add_resp = app.clone().oneshot(add_req).await.unwrap();
    assert_eq!(add_resp.status(), StatusCode::OK);
    let add_bytes = axum::body::to_bytes(add_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let add_res: AddAllowlistResponse = serde_json::from_slice(&add_bytes).unwrap();
    assert_eq!(add_res.subject_did, "did:plc:friend1");
    assert!(engine.is_allowlisted(protected_did, "did:plc:friend1"));

    // 3. GET /api/allowlist now returns the added entry
    let list_req2 = Request::builder()
        .uri("/api/allowlist")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .body(Body::empty())
        .unwrap();
    let list_resp2 = app.clone().oneshot(list_req2).await.unwrap();
    assert_eq!(list_resp2.status(), StatusCode::OK);
    let bytes2 = axum::body::to_bytes(list_resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let entries2: Vec<AllowlistEntry> = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(entries2.len(), 1);
    assert_eq!(entries2[0].subject_did, "did:plc:friend1");
    assert_eq!(entries2[0].reason.as_deref(), Some("Personal friend"));

    // 4. Cross-tenant check: Mallory cannot mutate protected-owner's allowlist
    let mallory_token = create_test_session(&engine, "did:plc:mallory");
    let cross_del_req = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/api/allowlist/did:plc:friend1?user_did={protected_did}"
        ))
        .header("cookie", format!("skybouncer_session={mallory_token}"))
        .body(Body::empty())
        .unwrap();
    let cross_del_resp = app.clone().oneshot(cross_del_req).await.unwrap();
    assert_eq!(cross_del_resp.status(), StatusCode::FORBIDDEN);

    // 5. DELETE /api/allowlist/:did successfully removes entry
    let del_req = Request::builder()
        .method("DELETE")
        .uri("/api/allowlist/did:plc:friend1")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .body(Body::empty())
        .unwrap();
    let del_resp = app.clone().oneshot(del_req).await.unwrap();
    assert_eq!(del_resp.status(), StatusCode::OK);
    let del_bytes = axum::body::to_bytes(del_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let del_res: RemoveAllowlistResponse = serde_json::from_slice(&del_bytes).unwrap();
    assert!(del_res.removed);
    assert!(!engine.is_allowlisted(protected_did, "did:plc:friend1"));

    // 6. Record a bounced violator in cache
    let violator_did = "did:plc:repeat_offender";
    cache
        .record_bounce(&BouncedUser {
            subject_did: violator_did.to_string(),
            protected_did: protected_did.to_string(),
            listitem_uri: format!("at://{protected_did}/app.bsky.graph.listitem/item999"),
            listitem_rkey: "item999".to_string(),
            listitem_cid: "bafyitem999".to_string(),
            category: "harassment".to_string(),
            confidence: 0.95,
            reason: "Targeted insult".to_string(),
            post_uri: format!("at://{violator_did}/app.bsky.feed.post/post999"),
            post_text: "Insulting text".to_string(),
            bounced_at: 1_700_000_000,
        })
        .unwrap();

    // 7. POST /api/pardon with allowlist: true immunizes violator
    let pardon_payload = json!({
        "subject_did": violator_did,
        "allowlist": true,
        "reason": "Pardoned and granted immunity"
    });
    let pardon_req = Request::builder()
        .method("POST")
        .uri("/api/pardon")
        .header("cookie", format!("skybouncer_session={owner_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&pardon_payload).unwrap()))
        .unwrap();
    let pardon_resp = app.clone().oneshot(pardon_req).await.unwrap();
    assert_eq!(pardon_resp.status(), StatusCode::OK);
    let p_bytes = axum::body::to_bytes(pardon_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let p_res: PardonResponse = serde_json::from_slice(&p_bytes).unwrap();
    assert!(p_res.pardoned);
    assert!(p_res.allowlisted);
    assert!(p_res.message.contains("immunized on the allowlist"));

    // Verify PDS deleteRecord was executed
    assert_eq!(pds.deleted_records.lock().len(), 1);
    // Verify removed from bounce cache
    assert!(!cache.is_bounced_for(protected_did, violator_did).unwrap());
    // Verify present on allowlist
    assert!(engine.is_allowlisted(protected_did, violator_did));
}
