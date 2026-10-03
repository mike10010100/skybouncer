//! Comprehensive Multi-Tenant Integration Tests for Milestone 6.
//!
//! Validates:
//! - Multi-tenant isolation and per-tenant rubric resolution.
//! - Dynamic tenant enrollment and activation toggles (`pause` / `resume`).
//! - Conversational onboarding bot flow for unenrolled vs enrolled accounts.
//! - Web onboarding `/auth` redirection.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use tower::ServiceExt;

use skyauth::client::OAuthClientMetadata;
use skybouncer::bot::BotCommandHandler;
use skybouncer::classifier::{RuleRubric, Sensitivity, Verdict};
use skybouncer::engine::{InteractionOutcome, SkybouncerConfig, SkybouncerEngine};
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};
use skybouncer::tenant::Tenant;
use skybouncer::web::create_web_router;

async fn setup_multi_tenant_engine() -> (
    Arc<SkybouncerEngine>,
    Arc<DeduplicationCache>,
    MockPdsServer,
) {
    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let default_rubric = RuleRubric::new(
        "Block obvious crypto spam and phishing",
        Sensitivity::Medium,
    );
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(default_rubric.clone()),
    );
    let pds_client = Arc::new(pds.pds_client("did:plc:admin-fallback"));
    let classifier = Arc::new(skybouncer::classifier::MockClassifier::new(
        Verdict::permitted("Default permitted"),
    ));

    let config = SkybouncerConfig::new(HashSet::<String>::new(), default_rubric)
        .with_enable_heuristic_prefilter(true);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    ));

    (engine, cache, pds)
}

#[tokio::test]
async fn test_multi_tenant_enrollment_and_isolation() {
    let (engine, _, _) = setup_multi_tenant_engine().await;

    let alice_did = "did:plc:alice-tenant-1";
    let bob_did = "did:plc:bob-tenant-2";

    // 1. Initially neither is enrolled
    assert!(!engine.is_enrolled(alice_did));
    assert!(!engine.is_enrolled(bob_did));
    assert!(!engine.is_protected(alice_did));
    assert!(!engine.is_protected(bob_did));

    // 2. Enroll Alice with High sensitivity custom rubric
    let alice_rubric = RuleRubric::new("Block all financial advice and NFTs", Sensitivity::High);
    let alice = Tenant::new(alice_did)
        .with_handle("alice.bsky.social")
        .with_rubric(alice_rubric.clone());
    engine.enroll_tenant(alice).expect("enroll alice");

    assert!(engine.is_enrolled(alice_did));
    assert!(engine.is_protected(alice_did));
    assert_eq!(engine.rubric_for(alice_did).prompt, alice_rubric.prompt);
    assert_eq!(engine.rubric_for(alice_did).sensitivity, Sensitivity::High);

    // 3. Enroll Bob with Low sensitivity custom rubric
    let bob_rubric = RuleRubric::new("Block extreme hate speech only", Sensitivity::Low);
    let bob = Tenant::new(bob_did)
        .with_handle("bob.bsky.social")
        .with_rubric(bob_rubric.clone());
    engine.enroll_tenant(bob).expect("enroll bob");

    assert!(engine.is_enrolled(bob_did));
    assert!(engine.is_protected(bob_did));
    assert_eq!(engine.rubric_for(bob_did).prompt, bob_rubric.prompt);
    assert_eq!(engine.rubric_for(bob_did).sensitivity, Sensitivity::Low);

    // 4. Verify Alice's rubric remains isolated and unchanged
    assert_eq!(engine.rubric_for(alice_did).prompt, alice_rubric.prompt);
    assert_eq!(engine.rubric_for(alice_did).sensitivity, Sensitivity::High);

    // 5. Unenrolled third user falls back to engine default rubric
    let stranger_did = "did:plc:stranger-3";
    assert!(!engine.is_enrolled(stranger_did));
    assert_eq!(
        engine.rubric_for(stranger_did).prompt,
        engine.rubric().prompt
    );
}

#[tokio::test]
async fn test_multi_tenant_pause_and_resume_isolation() {
    let (engine, _, _) = setup_multi_tenant_engine().await;

    let alice_did = "did:plc:alice-tenant-pause";
    let bob_did = "did:plc:bob-tenant-pause";

    let alice = Tenant::new(alice_did).with_handle("alice.bsky.social");
    let bob = Tenant::new(bob_did).with_handle("bob.bsky.social");
    engine.enroll_tenant(alice).expect("enroll alice");
    engine.enroll_tenant(bob).expect("enroll bob");

    // Both active initially
    assert!(!engine.is_tenant_paused(alice_did));
    assert!(!engine.is_tenant_paused(bob_did));

    // Pause only Alice
    engine
        .tenant_registry()
        .set_active(alice_did, false)
        .expect("pause alice");

    assert!(engine.is_tenant_paused(alice_did));
    assert!(!engine.is_tenant_paused(bob_did));

    // Commit targeting Alice is bypassed with Paused outcome
    let alice_commit = make_reply_commit(
        "did:plc:spammer1",
        alice_did,
        "post_alice",
        "parent_alice",
        "Hello Alice free crypto scam",
    );
    let res_alice = engine.process_commit(&alice_commit).await.expect("process");
    let outcomes_alice = res_alice.into_outcomes();
    assert_eq!(outcomes_alice.len(), 1);
    assert!(matches!(
        outcomes_alice[0],
        InteractionOutcome::Paused { .. }
    ));

    // Commit targeting Bob is evaluated and processed normally
    let bob_commit = make_reply_commit(
        "did:plc:spammer2",
        bob_did,
        "post_bob",
        "parent_bob",
        "Hello Bob free crypto scam",
    );
    let res_bob = engine.process_commit(&bob_commit).await.expect("process");
    let outcomes_bob = res_bob.into_outcomes();
    assert_eq!(outcomes_bob.len(), 1);
    assert!(!matches!(
        outcomes_bob[0],
        InteractionOutcome::Paused { .. }
    ));

    // Resume Alice
    engine
        .tenant_registry()
        .set_active(alice_did, true)
        .expect("resume alice");
    assert!(!engine.is_tenant_paused(alice_did));

    let res_alice_resumed = engine.process_commit(&alice_commit).await.expect("process");
    let outcomes_resumed = res_alice_resumed.into_outcomes();
    assert_eq!(outcomes_resumed.len(), 1);
    assert!(!matches!(
        outcomes_resumed[0],
        InteractionOutcome::Paused { .. }
    ));
}

#[tokio::test]
async fn test_conversational_onboarding_bot_flow() {
    let (engine, _, _) = setup_multi_tenant_engine().await;
    let bot_handler = BotCommandHandler::new(Arc::clone(&engine), "did:plc:skybouncer-bot")
        .with_public_url("https://skybouncer.mike10010100.com");

    let unenrolled_did = "did:plc:new-user-unenrolled";

    // 1. Unenrolled user sends greeting -> receives conversational onboarding message with 1-click link
    let reply_hi = bot_handler
        .handle_command(unenrolled_did, "hello")
        .await
        .expect("handle hello");
    assert!(reply_hi.contains("Welcome to **Skybouncer**"));
    assert!(reply_hi.contains("https://skybouncer.mike10010100.com/auth"));

    let reply_start = bot_handler
        .handle_command(unenrolled_did, "start")
        .await
        .expect("handle start");
    assert!(reply_start.contains("Welcome to **Skybouncer**"));
    assert!(reply_start.contains("https://skybouncer.mike10010100.com/auth"));

    // 2. Unenrolled user sends help -> shows commands including auth/start
    let reply_help = bot_handler
        .handle_command(unenrolled_did, "help")
        .await
        .expect("handle help");
    assert!(reply_help.contains("Skybouncer Bot Commands:"));
    assert!(reply_help.contains("https://skybouncer.mike10010100.com/auth"));

    // 3. Enroll user
    let user_tenant = Tenant::new(unenrolled_did)
        .with_handle("newuser.bsky.social")
        .with_rubric(RuleRubric::new("Block crypto bots", Sensitivity::Medium));
    engine.enroll_tenant(user_tenant).expect("enroll");

    // 4. Enrolled user runs management commands
    let reply_rules = bot_handler
        .handle_command(unenrolled_did, "rules")
        .await
        .expect("handle rules");
    assert!(reply_rules.contains("Current Moderation Rubric:"));
    assert!(reply_rules.contains("Block crypto bots"));

    let reply_pause = bot_handler
        .handle_command(unenrolled_did, "pause")
        .await
        .expect("handle pause");
    assert!(reply_pause.contains("Skybouncer has been **paused**"));
    assert!(engine.is_tenant_paused(unenrolled_did));

    let reply_resume = bot_handler
        .handle_command(unenrolled_did, "resume")
        .await
        .expect("handle resume");
    assert!(reply_resume.contains("Skybouncer has been **resumed**"));
    assert!(!engine.is_tenant_paused(unenrolled_did));
}

#[tokio::test]
async fn test_web_auth_redirect_endpoint() {
    let (engine, _, _) = setup_multi_tenant_engine().await;
    let metadata = OAuthClientMetadata::new(
        "https://skybouncer.mike10010100.com/oauth/client-metadata.json",
        "https://skybouncer.mike10010100.com/oauth/callback",
    );
    let app = create_web_router(engine, None, metadata);

    // 1. GET /auth without handle redirects to /?auth=login
    let req_no_handle = Request::builder()
        .uri("/auth")
        .method("GET")
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req_no_handle).await.expect("execute");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/?auth=login")
    );

    // 2. GET /auth?handle=carol.bsky.social redirects to /oauth/login?handle=carol.bsky.social
    let req_with_handle = Request::builder()
        .uri("/auth?handle=carol.bsky.social")
        .method("GET")
        .body(Body::empty())
        .expect("build request");
    let resp_handle = app.oneshot(req_with_handle).await.expect("execute");
    assert_eq!(resp_handle.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp_handle
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/oauth/login?handle=carol.bsky.social")
    );
}
