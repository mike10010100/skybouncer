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
use skybouncer::modlist::{BouncedUser, DeduplicationCache, ModListManager};
use skybouncer::web::{
    create_web_router, run_web_server, PardonResponse, RulesResponse, SimulateResponse,
    StatusResponse, WebServerConfig,
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
        Verdict::Permitted {
            reason: "Default test verdict: benign interaction".to_string(),
        },
    ));

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected_did.to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric);

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

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/status")
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

    // 1. GET /api/rules returns initial rubric
    let get_req = Request::builder()
        .uri("/api/rules")
        .body(Body::empty())
        .unwrap();
    let get_resp = app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let initial_rules: RulesResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(initial_rules.sensitivity, Sensitivity::Medium);

    // 2. POST /api/rules updates rubric to High sensitivity
    let update_payload = json!({
        "prompt": "Strict anti-spam policy: drop all unsolicited promotions",
        "sensitivity": "High"
    });
    let post_req = Request::builder()
        .method("POST")
        .uri("/api/rules")
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

    // 3. Verify underlying engine reflects update
    let active_rubric = engine.rubric();
    assert_eq!(active_rubric.sensitivity, Sensitivity::High);
    assert_eq!(
        active_rubric.prompt,
        "Strict anti-spam policy: drop all unsolicited promotions"
    );

    // 4. Verify bad request on empty prompt
    let invalid_payload = json!({
        "prompt": "   ",
        "sensitivity": "Low"
    });
    let bad_req = Request::builder()
        .method("POST")
        .uri("/api/rules")
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
        listitem_uri: list_item_uri.clone(),
        listitem_rkey: "item123".to_string(),
        listitem_cid: "bafytestcid".to_string(),
        category: "HateSpeech".to_string(),
        confidence: 0.95,
        reason: "Targeted harassment".to_string(),
        post_uri: "at://did:plc:toxic-violator-999/app.bsky.feed.post/post123".to_string(),
        bounced_at: 1_720_000_000_000_000,
    };
    cache.record_bounce(&bounce_entry).unwrap();

    // 1. GET /api/bounces returns the recorded bounce
    let bounces_req = Request::builder()
        .uri("/api/bounces?limit=10")
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
async fn test_api_simulate_heuristic_match() {
    let (_engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;

    let payload = json!({
        "text": "FREE AIRDROP LIVE NOW! Connect wallet to claim free tokens immediately!",
        "author_did": "did:plc:spammer123"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
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
async fn test_api_simulate_benign_text() {
    let (_engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;

    let payload = json!({
        "text": "Hello! Really enjoyed reading your recent technical architecture notes.",
        "author_did": "did:plc:friendly-peer"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
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
    let (_engine, _cache, _pds, app) = setup_test_web_environment("did:plc:alice").await;

    let payload = json!({ "text": "   " });
    let req = Request::builder()
        .method("POST")
        .uri("/api/simulate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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

    // Issue real HTTP request to the running server
    let client = reqwest::Client::new();
    let status_url = format!("http://127.0.0.1:{ephemeral_port}/api/status");
    let resp = client.get(&status_url).send().await;
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
