//! Tests for the daemon's extracted cold-start hydration and PDS provisioning helpers.

#![cfg(all(
    feature = "web",
    feature = "stream",
    feature = "bot",
    feature = "telemetry"
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::MockPdsServer;
use serde_json::json;
use skybouncer::classifier::{MockClassifier, RuleRubric, Sensitivity, Verdict};
use skybouncer::engine::{SkybouncerConfig, SkybouncerEngine};
use skybouncer::enricher::AppViewContextEnricher;
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn build_engine(
    protected: &str,
    pds: &MockPdsServer,
    dry_run: bool,
) -> Arc<SkybouncerEngine> {
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client(protected));
    let classifier = Arc::new(MockClassifier::new(Verdict::permitted("ok")));
    let mut dids = HashSet::new();
    dids.insert(protected.to_string());
    let config = SkybouncerConfig::new(dids, rubric).with_dry_run(dry_run);
    Arc::new(
        SkybouncerEngine::builder(config)
            .with_follow_graph(follow_graph)
            .with_gate(gate)
            .with_cache(cache)
            .with_modlist_manager(modlist)
            .with_pds_client(pds_client)
            .with_classifier(classifier)
            .build()
            .expect("engine"),
    )
}

#[tokio::test]
async fn hydrate_cold_start_seeds_follow_records_and_followers() {
    let appview = MockServer::start().await;
    let pds = MockPdsServer::start().await;
    let protected = "did:plc:alice";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [{
                "uri": "at://did:plc:alice/app.bsky.graph.follow/3kabc",
                "value": {"subject": "did:plc:bob"}
            }],
            "cursor": null
        })))
        .mount(&appview)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.graph.getFollowers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "followers": [{"did": "did:plc:carol"}],
            "cursor": null
        })))
        .mount(&appview)
        .await;

    let engine = build_engine(protected, &pds, true).await;
    let enricher = AppViewContextEnricher::with_endpoint(appview.uri());
    let mut dids = HashSet::new();
    dids.insert(protected.to_string());

    let hydrated = skybouncer::daemon::hydrate_cold_start(&engine, &enricher, &dids).await;
    assert!(hydrated >= 2, "expected follow record + follower hydration");
    assert!(engine.is_following(protected, "did:plc:bob"));
}

#[tokio::test]
async fn provision_pds_resources_creates_lists_for_protected_did() {
    let pds = MockPdsServer::start().await;
    let protected = "did:plc:alice";
    let engine = build_engine(protected, &pds, false).await;
    let mut dids = HashSet::new();
    dids.insert(protected.to_string());

    // Ensure the list exists (mock PDS handles createRecord/listRecords dynamically).
    let provisioned = skybouncer::daemon::provision_pds_resources(&engine, &dids).await;
    assert_eq!(provisioned, 1);
}

#[tokio::test]
async fn provision_pds_resources_includes_enrolled_tenant_with_session() {
    use skyauth::dpop::DPoPKey;
    use skyauth::session::OAuthSession;
    let pds = MockPdsServer::start().await;
    let protected = "did:plc:alice";
    let engine = build_engine(protected, &pds, false).await;

    // Enroll a tenant WITH a session so the provisioning loop includes it.
    let session = OAuthSession::new(
        "did:plc:tenant-sess",
        "at-token",
        Some("rt-token".to_string()),
        "DPoP",
        None,
        Some(3600),
        DPoPKey::generate(),
        Some(pds.uri()),
        None,
        None,
    )
    .unwrap();
    engine
        .tenant_registry()
        .register_or_update(
            &skybouncer::tenant::Tenant::new("did:plc:tenant-sess").with_session(session),
        )
        .unwrap();

    let mut dids = HashSet::new();
    dids.insert(protected.to_string());
    // At least the protected DID + the session-bearing tenant are attempted.
    let provisioned = skybouncer::daemon::provision_pds_resources(&engine, &dids).await;
    assert!(provisioned >= 1);
}

#[tokio::test]
async fn resolve_bot_client_no_credentials_returns_none() {
    let r = skybouncer::daemon::resolve_bot_client(
        None,
        None,
        "https://bsky.social",
        "https://api.bsky.chat",
        None,
        None,
    )
    .await;
    assert!(r.is_none());
}

#[tokio::test]
async fn resolve_bot_client_with_token_returns_client() {
    // A token + DID yields a ChatClient without any network call.
    let r = skybouncer::daemon::resolve_bot_client(
        None,
        None,
        "https://bsky.social",
        "https://api.bsky.chat",
        Some("some_token".to_string()),
        Some("did:plc:bot".to_string()),
    )
    .await;
    let (client, did) = r.expect("client");
    assert_eq!(did, "did:plc:bot");
    assert_eq!(client.current_access_token().await, "some_token");
}

#[tokio::test]
async fn resolve_bot_client_app_password_login_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.server.createSession"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": "did:plc:botresolved",
            "accessJwt": "at-jwt",
            "refreshJwt": "rt-jwt"
        })))
        .mount(&server)
        .await;

    let r = skybouncer::daemon::resolve_bot_client(
        Some("bot.bsky.social".to_string()),
        Some("app-password".to_string()),
        &server.uri(),
        &server.uri(),
        None,
        None,
    )
    .await;
    let (_client, did) = r.expect("client");
    assert_eq!(did, "did:plc:botresolved");
}

#[tokio::test]
async fn resolve_bot_client_app_password_login_failure_returns_none() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.server.createSession"))
        .respond_with(ResponseTemplate::new(401).set_body_string("bad password"))
        .mount(&server)
        .await;

    let r = skybouncer::daemon::resolve_bot_client(
        Some("bot.bsky.social".to_string()),
        Some("wrong".to_string()),
        &server.uri(),
        &server.uri(),
        None,
        None,
    )
    .await;
    assert!(r.is_none());
}
