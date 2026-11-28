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
use skybouncer::modlist::{BouncedUser, DeduplicationCache, ModListManager};
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

    let engine = Arc::new(
        SkybouncerEngine::new(
            config,
            follow_graph,
            gate,
            classifier,
            modlist_manager,
            pds_client,
        )
        .expect("multi-tenant test engine should initialize"),
    );

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

#[tokio::test]
async fn test_temporary_ttl_timeout_pruning_in_engine() {
    let (engine, cache, pds) = setup_multi_tenant_engine().await;
    let metadata = OAuthClientMetadata::new(
        "http://127.0.0.1:3000/oauth/client-metadata.json",
        "http://127.0.0.1:3000/oauth/callback",
    );
    let oauth_client = Arc::new(
        skyauth::client::AtprotoOAuthClient::builder()
            .client_metadata(metadata)
            .allow_insecure_localhost(true)
            .build()
            .expect("oauth client"),
    );
    engine.set_oauth_client(oauth_client);
    let now_us = 1_720_000_000_000_000;

    // Enroll a tenant with an OAuthSession pointing at the mock PDS
    let tenant_did = "did:plc:alice_tenant";
    let session = skyauth::session::OAuthSession::new(
        tenant_did,
        "at-test-access-token",
        Some("rt-test-refresh-token".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        skyauth::dpop::DPoPKey::generate(),
        Some(pds.uri()),
        Some(pds.uri()),
        Some(format!("{}/oauth/token", pds.uri())),
    )
    .expect("session");
    let tenant = Tenant::new(tenant_did)
        .with_handle("alice.bsky.social")
        .with_session(session);
    engine.enroll_tenant(tenant).expect("enroll");

    // Populate an expired temporary bounce
    let expired_user = BouncedUser {
        subject_did: "did:plc:timed_out_spammer".to_string(),
        protected_did: tenant_did.to_string(),
        listitem_uri: format!("at://{tenant_did}/app.bsky.graph.listitem/item_expired"),
        listitem_rkey: "item_expired".to_string(),
        listitem_cid: "bafyitemexpired".to_string(),
        category: "crypto_spam".to_string(),
        confidence: 0.96,
        reason: "24h cooldown".to_string(),
        post_uri: "at://did:plc:timed_out_spammer/app.bsky.feed.post/1".to_string(),
        post_text: "Crypto spam".to_string(),
        reply_to_uri: None,
        bounced_at: now_us - 100_000_000,
        expires_at: Some(now_us - 10_000_000), // Expired
    };
    cache.record_bounce(&expired_user).expect("record bounce");
    assert!(cache
        .is_bounced_for(tenant_did, "did:plc:timed_out_spammer")
        .unwrap());

    // Run engine pruning
    let pruned = engine.prune_expired_bounces().await.expect("prune");
    assert_eq!(pruned, 1);

    // Verify violator is no longer recorded as bounced for this tenant
    assert!(!cache
        .is_bounced_for(tenant_did, "did:plc:timed_out_spammer")
        .unwrap());
    assert_eq!(cache.count_bounced().expect("count"), 0);
}

#[tokio::test]
async fn test_is_single_tenant_matrix_and_401_expired_token_refresh_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // 1. admin_did + 1 enrolled tenant => is_single_tenant() == false!
    let pds1 = MockPdsServer::start().await;
    let rubric = RuleRubric::new("Default", Sensitivity::Medium);
    let mut cfg1 =
        SkybouncerConfig::new(["did:plc:admin"], rubric.clone()).with_admin_did("did:plc:admin");
    cfg1.protected_dids.insert("did:plc:tenant1".to_string());
    let eng_admin_plus_1 = SkybouncerEngine::builder(cfg1)
        .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
            Verdict::permitted("ok"),
        )))
        .with_pds_client(Arc::new(pds1.pds_client("did:plc:admin")))
        .build()
        .unwrap();
    eng_admin_plus_1
        .enroll_tenant(Tenant::new("did:plc:tenant1"))
        .unwrap();
    assert!(!eng_admin_plus_1.is_single_tenant());

    // 2. 1 static protected DID + 1 different enrolled tenant => is_single_tenant() == false!
    let mut static_set = HashSet::new();
    static_set.insert("did:plc:static_owner".to_string());
    let eng_diff = SkybouncerEngine::builder(SkybouncerConfig::new(static_set, rubric.clone()))
        .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
            Verdict::permitted("ok"),
        )))
        .with_pds_client(Arc::new(pds1.pds_client("did:plc:static_owner")))
        .build()
        .unwrap();
    eng_diff
        .enroll_tenant(Tenant::new("did:plc:different_tenant"))
        .unwrap();
    assert!(!eng_diff.is_single_tenant());

    // 3. Matching 1 static + 1 enrolled same DID => is_single_tenant() == true!
    let mut same_set = HashSet::new();
    same_set.insert("did:plc:solo".to_string());
    let eng_solo = SkybouncerEngine::builder(SkybouncerConfig::new(same_set, rubric.clone()))
        .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
            Verdict::permitted("ok"),
        )))
        .with_pds_client(Arc::new(pds1.pds_client("did:plc:solo")))
        .build()
        .unwrap();
    eng_solo.enroll_tenant(Tenant::new("did:plc:solo")).unwrap();
    assert!(eng_solo.is_single_tenant());

    // 3b. admin_did != sole_protected OR admin_did != sole_tenant => is_single_tenant() == false!
    let eng_mismatch_admin = SkybouncerEngine::builder(
        SkybouncerConfig::new(["did:plc:other_user"], rubric.clone())
            .with_admin_did("did:plc:admin"),
    )
    .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
        Verdict::permitted("ok"),
    )))
    .with_pds_client(Arc::new(pds1.pds_client("did:plc:admin")))
    .build()
    .unwrap();
    assert!(!eng_mismatch_admin.is_single_tenant());

    let eng_admin_with_other_tenant = SkybouncerEngine::builder(
        SkybouncerConfig::new(HashSet::<String>::new(), rubric.clone())
            .with_admin_did("did:plc:admin"),
    )
    .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
        Verdict::permitted("ok"),
    )))
    .with_pds_client(Arc::new(pds1.pds_client("did:plc:admin")))
    .build()
    .unwrap();
    eng_admin_with_other_tenant
        .enroll_tenant(Tenant::new("did:plc:other_tenant"))
        .unwrap();
    assert!(!eng_admin_with_other_tenant.is_single_tenant());

    // 4. 401 ExpiredToken single refresh + retry succeeds end-to-end via publish_sovereign_config!
    let server = MockServer::start().await;
    let alice = "did:plc:alice_401_retry";
    let metadata = OAuthClientMetadata::new(
        "http://127.0.0.1:3000/oauth/client-metadata.json",
        "http://127.0.0.1:3000/oauth/callback",
    );
    let oauth_client = Arc::new(
        skyauth::client::AtprotoOAuthClient::builder()
            .client_metadata(metadata)
            .allow_insecure_localhost(true)
            .build()
            .expect("oauth client"),
    );

    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let refresh_calls_ref = Arc::clone(&refresh_calls);
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(move |_: &wiremock::Request| {
            let n = refresh_calls_ref.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .insert_header("dpop-nonce", "nonce-refreshed")
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "access_token": format!("at-refreshed-{n}"),
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "rt-refreshed",
                    "scope": "atproto",
                    "sub": alice
                }))
        })
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "RecordNotFound",
            "message": "Could not locate record"
        })))
        .mount(&server)
        .await;

    let put_calls = Arc::new(AtomicUsize::new(0));
    let put_calls_ref = Arc::clone(&put_calls);
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.repo.putRecord"))
        .respond_with(move |_: &wiremock::Request| {
            let n = put_calls_ref.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "error": "ExpiredToken",
                    "message": "Token has expired"
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uri": format!("at://{alice}/social.skybouncer.config/self"),
                    "cid": "bafyafterrefresh"
                }))
            }
        })
        .mount(&server)
        .await;

    let engine = SkybouncerEngine::builder(SkybouncerConfig::new([alice], rubric))
        .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
            Verdict::permitted("ok"),
        )))
        .with_oauth_client(oauth_client)
        .with_pds_client(Arc::new(
            skybase::repo::PdsRepoClient::from_credentials(server.uri(), alice, "unused")
                .unwrap()
                .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true)),
        ))
        .build()
        .unwrap();

    let session = skyauth::session::OAuthSession::new(
        alice,
        "at-expired-initial",
        Some("rt-initial".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        skyauth::dpop::DPoPKey::generate(),
        Some(server.uri()),
        Some(server.uri()),
        Some(format!("{}/oauth/token", server.uri())),
    )
    .unwrap();
    engine
        .enroll_tenant(Tenant::new(alice).with_session(session))
        .unwrap();

    let published = engine
        .publish_sovereign_config(alice)
        .await
        .expect("401 ExpiredToken must trigger single refresh and retry cleanly");
    assert!(published.contains("social.skybouncer.config/self"));
    assert!(refresh_calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(put_calls.load(Ordering::SeqCst), 2);

    // 5. Persistent 401 when refresh returns invalid_grant marks reauth_required and surfaces error.
    let srv_fail = MockServer::start().await;
    let bob = "did:plc:bob_401_reauth";
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Refresh token expired"
        })))
        .mount(&srv_fail)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "InvalidToken",
            "message": "Token revoked"
        })))
        .mount(&srv_fail)
        .await;

    let oc2 = Arc::new(
        skyauth::client::AtprotoOAuthClient::builder()
            .client_metadata(OAuthClientMetadata::new(
                "http://127.0.0.1:3000/oauth/client-metadata.json",
                "http://127.0.0.1:3000/oauth/callback",
            ))
            .allow_insecure_localhost(true)
            .build()
            .unwrap(),
    );
    let eng_fail = SkybouncerEngine::builder(SkybouncerConfig::new([bob], RuleRubric::default()))
        .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
            Verdict::permitted("ok"),
        )))
        .with_oauth_client(oc2)
        .with_pds_client(Arc::new(
            skybase::repo::PdsRepoClient::from_credentials(srv_fail.uri(), bob, "unused")
                .unwrap()
                .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true)),
        ))
        .build()
        .unwrap();
    let bob_session = skyauth::session::OAuthSession::new(
        bob,
        "at-revoked",
        Some("rt-revoked".to_string()),
        "DPoP",
        Some("atproto".to_string()),
        Some(3600),
        skyauth::dpop::DPoPKey::generate(),
        Some(srv_fail.uri()),
        Some(srv_fail.uri()),
        Some(format!("{}/oauth/token", srv_fail.uri())),
    )
    .unwrap();
    eng_fail
        .enroll_tenant(Tenant::new(bob).with_session(bob_session))
        .unwrap();
    assert!(eng_fail.publish_sovereign_config(bob).await.is_err());
    assert!(eng_fail.tenant_registry().is_reauth_required(bob).unwrap());
    assert!(eng_fail.is_tenant_paused(bob));
}
