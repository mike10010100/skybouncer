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
async fn resolve_bot_client_discovers_did_doc_pds_for_default_chat_endpoint_and_dispatches_bounce_dm(
) {
    let entryway = MockServer::start().await;
    let shard_pds = MockServer::start().await;

    // Entryway handles createSession and returns didDoc pointing #atproto_pds at shard_pds,
    // while rejecting chat XRPCs with 501 if misrouted.
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.getConvoForMembers"))
        .respond_with(ResponseTemplate::new(501).set_body_string("MethodNotImplemented"))
        .expect(0)
        .mount(&entryway)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.server.createSession"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": "did:plc:pl7wa2phjeo4zp4zxmewnsis",
            "handle": "skybouncer.bsky.social",
            "accessJwt": "at-jwt-token",
            "refreshJwt": "rt-jwt-token",
            "didDoc": {
                "id": "did:plc:pl7wa2phjeo4zp4zxmewnsis",
                "alsoKnownAs": ["at://skybouncer.bsky.social"],
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": shard_pds.uri()
                }]
            }
        })))
        .expect(1)
        .mount(&entryway)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.getConvoForMembers"))
        .respond_with(|req: &wiremock::Request| {
            let proxy = req
                .headers
                .get("atproto-proxy")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(proxy, "did:web:api.bsky.chat#bsky_chat");
            ResponseTemplate::new(200).set_body_json(json!({
                "convo": {
                    "id": "convo-dm-1",
                    "rev": "1",
                    "members": [{"did": "did:plc:alice"}],
                    "muted": false,
                    "unreadCount": 0
                }
            }))
        })
        .expect(1)
        .mount(&shard_pds)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(|req: &wiremock::Request| {
            let proxy = req
                .headers
                .get("atproto-proxy")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(proxy, "did:web:api.bsky.chat#bsky_chat");
            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg-alert-1",
                "rev": "2",
                "text": "ok",
                "sender": {"did": "did:plc:pl7wa2phjeo4zp4zxmewnsis"},
                "sentAt": "2026-11-11T17:00:00Z"
            }))
        })
        .expect(1)
        .mount(&shard_pds)
        .await;

    let (client, did) = skybouncer::daemon::resolve_bot_client(
        Some("skybouncer.bsky.social".to_string()),
        Some("app-password".to_string()),
        &entryway.uri(),
        skybouncer::DEFAULT_CHAT_ENDPOINT,
        None,
        None,
    )
    .await
    .expect("bot client should resolve via didDoc PDS");
    assert_eq!(did, "did:plc:pl7wa2phjeo4zp4zxmewnsis");
    assert_eq!(client.base_url().await, shard_pds.uri());

    let (tx, rx) = tokio::sync::broadcast::channel(8);
    let cancel = tokio_util::sync::CancellationToken::new();
    let _ = tx.send(skybouncer::BounceNotification {
        target_did: "did:plc:alice".to_string(),
        violator_did: "did:plc:spammer".to_string(),
        violator_handle: Some("spammer.bsky.social".to_string()),
        category: skybouncer::ViolationCategory::Harassment,
        confidence: 0.99,
        reason: "Targeted personal insult".to_string(),
        post_uri: "at://did:plc:spammer/app.bsky.feed.post/3n22gtcw4qk24".to_string(),
        reply_to_uri: None,
        post_snippet: "insult".to_string(),
        bounce_duration: skybouncer::BounceDuration::Cooldown24h,
    });
    drop(tx);

    skybouncer::run_bounce_alert_dispatcher(client, rx, cancel)
        .await
        .expect("bounce alert dispatcher must deliver DM via shard_pds proxy");
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

#[tokio::test]
async fn hydrate_cold_start_falls_back_to_follows_and_skips_empty() {
    let appview = MockServer::start().await;
    let pds = MockPdsServer::start().await;
    let protected = "did:plc:alice";

    // No listRecords -> empty, forcing the getFollows fallback.
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [],
            "cursor": null
        })))
        .mount(&appview)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.graph.getFollows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "follows": [{"did": "did:plc:followed-via-fallback"}],
            "cursor": null
        })))
        .mount(&appview)
        .await;
    // Empty followers -> skip branch.
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.graph.getFollowers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "followers": [],
            "cursor": null
        })))
        .mount(&appview)
        .await;

    let engine = build_engine(protected, &pds, true).await;
    let enricher = AppViewContextEnricher::with_endpoint(appview.uri());
    let mut dids = HashSet::new();
    dids.insert(protected.to_string());

    let hydrated = skybouncer::daemon::hydrate_cold_start(&engine, &enricher, &dids).await;
    assert_eq!(hydrated, 1, "only the fallback follow is hydrated");
    assert!(engine.is_following(protected, "did:plc:followed-via-fallback"));
}

static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvVarGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl EnvVarGuard {
    fn new(keys: &[&'static str]) -> Self {
        let saved = keys.iter().map(|&k| (k, std::env::var_os(k))).collect();
        Self { saved }
    }

    fn set(&self, key: &str, val: &str) {
        std::env::set_var(key, val);
    }

    fn remove(&self, key: &str) {
        std::env::remove_var(key);
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (k, orig) in &self.saved {
            match orig {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }
}

#[test]
fn bot_env_settings_ignores_pds_access_token_and_reads_chat_poll_interval() {
    let _lock = ENV_TEST_LOCK.lock().unwrap();
    let guard = EnvVarGuard::new(&[
        "PDS_ACCESS_TOKEN",
        "CHAT_ACCESS_TOKEN",
        "BOT_DID",
        "PROTECTED_DIDS",
        "CHAT_POLL_INTERVAL_SECS",
        "SKYBOUNCER_CHAT_POLL_INTERVAL_SECS",
        "BOT_HANDLE",
        "BOT_IDENTIFIER",
        "BOT_APP_PASSWORD",
        "BLUESKY_APP_PASSWORD",
    ]);

    guard.set("PDS_ACCESS_TOKEN", "should-not-become-chat-token");
    guard.set("PROTECTED_DIDS", "did:plc:protectedaaaaaaaaaaaaaaa");
    guard.remove("CHAT_ACCESS_TOKEN");
    guard.remove("BOT_DID");
    guard.remove("BOT_HANDLE");
    guard.remove("BOT_IDENTIFIER");
    guard.remove("BOT_APP_PASSWORD");
    guard.remove("BLUESKY_APP_PASSWORD");
    guard.set("CHAT_POLL_INTERVAL_SECS", "17");
    guard.remove("SKYBOUNCER_CHAT_POLL_INTERVAL_SECS");

    let s = skybouncer::daemon::BotEnvSettings::from_env();
    assert_eq!(s.chat_token, None, "must never inherit PDS_ACCESS_TOKEN");
    assert_eq!(s.bot_did, None, "must never inherit protected_dids");
    assert_eq!(s.poll_interval, std::time::Duration::from_secs(17));

    // SKYBOUNCER_CHAT_POLL_INTERVAL_SECS fallback + minimum 1s clamp
    guard.remove("CHAT_POLL_INTERVAL_SECS");
    guard.set("SKYBOUNCER_CHAT_POLL_INTERVAL_SECS", "9");
    let s2 = skybouncer::daemon::BotEnvSettings::from_env();
    assert_eq!(s2.poll_interval, std::time::Duration::from_secs(9));

    guard.set("CHAT_POLL_INTERVAL_SECS", "0");
    let s3 = skybouncer::daemon::BotEnvSettings::from_env();
    assert_eq!(s3.poll_interval, std::time::Duration::from_secs(1));
}

#[test]
fn config_env_wiring_reads_newly_wired_variables() {
    let _lock = ENV_TEST_LOCK.lock().unwrap();
    let guard = EnvVarGuard::new(&[
        "SENSITIVITY",
        "SKYBOUNCER_SENSITIVITY",
        "EVAL_CACHE_TTL_SECS",
        "SKYBOUNCER_EVAL_CACHE_TTL_SECS",
        "EVALUATION_CACHE_TTL_HOURS",
        "SKYBOUNCER_EVALUATION_CACHE_TTL_HOURS",
        "LIST_NAME",
        "SKYBOUNCER_LIST_NAME",
        "LIST_DESCRIPTION",
        "SKYBOUNCER_LIST_DESCRIPTION",
        "RATE_LIMIT_PER_HOUR",
        "SKYBOUNCER_RATE_LIMIT_EVALS_PER_HOUR",
    ]);

    guard.set("SENSITIVITY", "high");
    guard.remove("SKYBOUNCER_SENSITIVITY");
    guard.remove("EVAL_CACHE_TTL_SECS");
    guard.remove("SKYBOUNCER_EVAL_CACHE_TTL_SECS");
    guard.set("EVALUATION_CACHE_TTL_HOURS", "48");
    guard.set("LIST_NAME", "Custom Shield");
    guard.set("LIST_DESCRIPTION", "Custom moderation list description");
    guard.remove("SKYBOUNCER_RATE_LIMIT_EVALS_PER_HOUR");
    guard.set("RATE_LIMIT_PER_HOUR", "250");

    let cfg = SkybouncerConfig::from_env().expect("config from env");
    assert_eq!(cfg.rubric.sensitivity, Sensitivity::High);
    assert_eq!(
        cfg.evaluation_ttl,
        std::time::Duration::from_secs(48 * 3600)
    );
    assert_eq!(cfg.list_name, "Custom Shield");
    assert_eq!(
        cfg.list_description.as_deref(),
        Some("Custom moderation list description")
    );
    assert_eq!(cfg.rate_limiter_config.max_evaluations, 250);

    // SKYBOUNCER_EVAL_CACHE_TTL_SECS takes precedence over EVALUATION_CACHE_TTL_HOURS
    guard.set("SKYBOUNCER_EVAL_CACHE_TTL_SECS", "120");
    guard.set("SKYBOUNCER_RATE_LIMIT_EVALS_PER_HOUR", "99");
    let cfg2 = SkybouncerConfig::from_env().expect("config2 from env");
    assert_eq!(cfg2.evaluation_ttl, std::time::Duration::from_secs(120));
    assert_eq!(cfg2.rate_limiter_config.max_evaluations, 99);
}
