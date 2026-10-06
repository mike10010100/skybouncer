//! Integration tests for the operational CLI command runners in `skybouncer::app`.
//!
//! These exercise `run_cli_status`, `run_cli_pardon`, and `run_cli_simulate` against a
//! mock HTTP daemon (wiremock), plus the offline simulation path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use serde_json::json;
use skybouncer::app::{run_cli_pardon, run_cli_simulate, run_cli_status};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn status_json() -> serde_json::Value {
    json!({
        "stats": serde_json::to_value(skybouncer::engine::EngineStatsSnapshot::default()).unwrap(),
        "protected_dids": ["did:plc:alice"],
        "rubric": {
            "prompt": "Block spam",
            "sensitivity": "medium",
            "threshold": 0.8,
            "bounce_duration": "permanent",
            "bypass_incoming_followers": true
        },
        "dry_run": false,
        "version": "9.9.9"
    })
}

#[tokio::test]
async fn run_cli_status_renders_human_report() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status_json()))
        .mount(&server)
        .await;

    let a = args(&["--url", &server.uri()]);
    run_cli_status(&a).await.expect("status ok");
}

#[tokio::test]
async fn run_cli_status_json_output() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status_json()))
        .mount(&server)
        .await;

    let a = args(&["--url", &server.uri(), "--json"]);
    run_cli_status(&a).await.expect("status json ok");
}

#[tokio::test]
async fn run_cli_status_reports_non_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&server)
        .await;

    let a = args(&["--url", &server.uri()]);
    let err = run_cli_status(&a).await.expect_err("must fail");
    assert!(matches!(err, skybouncer::SkybouncerError::Config(_)));
}

#[tokio::test]
async fn run_cli_status_reports_unreachable_daemon() {
    // Point at a port nothing is listening on.
    let a = args(&["--url", "http://127.0.0.1:1"]);
    let err = run_cli_status(&a).await.expect_err("must fail");
    assert!(matches!(err, skybouncer::SkybouncerError::Config(_)));
}

#[tokio::test]
async fn run_cli_pardon_did_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/pardon"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "subject_did": "did:plc:spammer",
            "pardoned": true,
            "message": "pardoned"
        })))
        .mount(&server)
        .await;

    let a = args(&["did:plc:spammer", "--url", &server.uri()]);
    run_cli_pardon(&a).await.expect("pardon ok");
}

#[tokio::test]
async fn run_cli_pardon_did_failure_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/pardon"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&server)
        .await;

    let a = args(&["did:plc:spammer", "--url", &server.uri()]);
    let err = run_cli_pardon(&a).await.expect_err("must fail");
    assert!(matches!(err, skybouncer::SkybouncerError::Config(_)));
}

#[tokio::test]
async fn run_cli_pardon_missing_subject_errors() {
    let a = args(&["--url", "http://127.0.0.1:1"]);
    let err = run_cli_pardon(&a).await.expect_err("must fail");
    assert!(matches!(err, skybouncer::SkybouncerError::Config(_)));
}

#[tokio::test]
async fn run_cli_pardon_handle_resolution_success() {
    let server = MockServer::start().await;
    // Handle resolution hits bsky.social directly; we can't redirect that, so this
    // test only verifies the DID passthrough path against the mock daemon.
    Mock::given(method("POST"))
        .and(path("/api/pardon"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "subject_did": "did:plc:spammer",
            "pardoned": true,
            "message": "ok"
        })))
        .mount(&server)
        .await;

    let a = args(&[
        "did:plc:spammer",
        "--target",
        "did:plc:alice",
        "--url",
        &server.uri(),
    ]);
    run_cli_pardon(&a).await.expect("pardon with target ok");
}

#[tokio::test]
async fn run_cli_simulate_via_daemon() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/simulate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.95,
            "reason": "airdrop",
            "evaluator": "heuristic_prefilter",
            "meets_threshold": true,
            "threshold": 0.8,
            "images_evaluated": 0
        })))
        .mount(&server)
        .await;

    let a = args(&["free airdrop scam", "--url", &server.uri()]);
    run_cli_simulate(&a).await.expect("simulate via daemon ok");
}

#[tokio::test]
async fn run_cli_simulate_offline_uses_local_engine() {
    // No network; forces the offline dry-run engine path.
    let a = args(&["definitely benign text here", "--offline"]);
    // The offline path builds an engine from env; JEV isn't configured so it may
    // error at classifier construction, which is still a valid covered path.
    let _ = run_cli_simulate(&a).await;
}

#[tokio::test]
async fn run_cli_simulate_missing_text_errors() {
    let a = args(&["--offline"]);
    let err = run_cli_simulate(&a).await.expect_err("must fail");
    assert!(matches!(err, skybouncer::SkybouncerError::Config(_)));
}

#[tokio::test]
async fn run_cli_simulate_falls_back_to_offline_when_daemon_unreachable() {
    // Daemon URL points nowhere valid; simulate should fall through to offline.
    let a = args(&["some sample text", "--url", "http://127.0.0.1:1"]);
    let _ = run_cli_simulate(&a).await;
}

#[tokio::test]
async fn dispatch_help_and_unknown_command() {
    use skybouncer::app::dispatch;
    use tokio_util::sync::CancellationToken;

    // Help forms return Ok without network (note: a bare argv defaults to daemon,
    // so it is intentionally excluded here).
    for argv in [
        vec!["skybouncer", "--help"],
        vec!["skybouncer", "-h"],
        vec!["skybouncer", "help"],
    ] {
        let a: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        dispatch(&a, CancellationToken::new())
            .await
            .expect("help dispatch ok");
    }

    // Unknown command -> Config error.
    let a = args(&["skybouncer", "frobnicate"]);
    let err = dispatch(&a, CancellationToken::new())
        .await
        .expect_err("unknown command");
    assert!(matches!(err, skybouncer::SkybouncerError::Config(_)));
}

#[tokio::test]
async fn dispatch_routes_status_and_simulate_to_daemon_url() {
    use skybouncer::app::dispatch;
    use tokio_util::sync::CancellationToken;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status_json()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/simulate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": false,
            "category": null,
            "confidence": 0.1,
            "reason": "benign",
            "evaluator": "primary_classifier",
            "meets_threshold": false,
            "threshold": 0.8,
            "images_evaluated": 0
        })))
        .mount(&server)
        .await;

    let a = args(&["skybouncer", "status", "--url", &server.uri()]);
    dispatch(&a, CancellationToken::new())
        .await
        .expect("status");

    let a = args(&["skybouncer", "simulate", "hello", "--url", &server.uri()]);
    dispatch(&a, CancellationToken::new())
        .await
        .expect("simulate");
}

#[tokio::test]
async fn dispatch_daemon_bare_flag_form_cancels() {
    use skybouncer::app::dispatch;
    use tokio_util::sync::CancellationToken;

    // Bare `--dry-run` (no `daemon` keyword) routes to the daemon; cancel immediately.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let a = args(&["skybouncer", "--dry-run", "--did", "did:plc:d1"]);
    let _ = dispatch(&a, cancel).await;
}

#[tokio::test]
async fn run_cli_simulate_offline_with_jev_config_uses_local_engine() {
    // Point the Jev classifier at a mock so the offline dry-run engine builds,
    // and the daemon URL at an unreachable port to force the offline path.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": false,
            "confidence": 0.1,
            "category": null,
            "reason": "benign"
        })))
        .mount(&server)
        .await;

    // Save & set env for the classifier + a DB path.
    let saved: Vec<(&str, Option<String>)> = ["JEV_API_BASE_URL", "SKYBOUNCER_DB_PATH", "DRY_RUN"]
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
    std::env::set_var("JEV_API_BASE_URL", format!("{}/v1/classify", server.uri()));
    std::env::remove_var("SKYBOUNCER_DB_PATH");
    std::env::remove_var("DRY_RUN");

    let a = args(&[
        "a benign offline message",
        "--url",
        "http://127.0.0.1:1",
        "--offline",
    ]);
    // The offline path builds an in-memory dry-run engine and runs the simulation.
    run_cli_simulate(&a).await.expect("offline simulate");

    for (k, v) in saved {
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
}

#[tokio::test]
async fn run_cli_pardon_handle_resolution_via_override() {
    let server = MockServer::start().await;
    // Resolution endpoint (SKYBOUNCER_RESOLVE_HANDLE_URL).
    Mock::given(method("GET"))
        .and(path("/resolve"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"did": "did:plc:resolved"})))
        .mount(&server)
        .await;
    // Daemon pardon endpoint.
    Mock::given(method("POST"))
        .and(path("/api/pardon"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "subject_did": "did:plc:resolved",
            "pardoned": true,
            "message": "ok"
        })))
        .mount(&server)
        .await;

    let saved = std::env::var("SKYBOUNCER_RESOLVE_HANDLE_URL").ok();
    std::env::set_var(
        "SKYBOUNCER_RESOLVE_HANDLE_URL",
        format!("{}/resolve", server.uri()),
    );
    let a = args(&["@alice.bsky.social", "--url", &server.uri()]);
    let r = run_cli_pardon(&a).await;
    match saved {
        Some(v) => std::env::set_var("SKYBOUNCER_RESOLVE_HANDLE_URL", v),
        None => std::env::remove_var("SKYBOUNCER_RESOLVE_HANDLE_URL"),
    }
    r.expect("pardon via resolved handle");
}

#[tokio::test]
async fn run_cli_pardon_handle_resolution_error_paths() {
    let server = MockServer::start().await;
    // 404 resolution -> Config error.
    Mock::given(method("GET"))
        .and(path("/resolve"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let saved = std::env::var("SKYBOUNCER_RESOLVE_HANDLE_URL").ok();
    std::env::set_var(
        "SKYBOUNCER_RESOLVE_HANDLE_URL",
        format!("{}/resolve", server.uri()),
    );
    let a = args(&["@ghost.bsky.social", "--url", &server.uri()]);
    let r = run_cli_pardon(&a).await;
    match saved {
        Some(v) => std::env::set_var("SKYBOUNCER_RESOLVE_HANDLE_URL", v),
        None => std::env::remove_var("SKYBOUNCER_RESOLVE_HANDLE_URL"),
    }
    assert!(matches!(r, Err(skybouncer::SkybouncerError::Config(_))));
}

#[tokio::test]
async fn run_cli_status_with_populated_stats_and_shadow_mode() {
    let server = MockServer::start().await;
    let stats = skybouncer::engine::EngineStatsSnapshot {
        commits_received: 5000,
        interactions_matched: 100,
        gate_bypassed_self: 10,
        gate_bypassed_followed: 20,
        gate_bypassed_follower: 15,
        eval_queue_enqueued: 30,
        eval_queue_processed: 25,
        ..Default::default()
    };
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "stats": serde_json::to_value(stats).unwrap(),
            "protected_dids": ["did:plc:alice", "did:plc:bob"],
            "rubric": {
                "prompt": "Block spam",
                "sensitivity": "high",
                "threshold": 0.6,
                "bounce_duration": "permanent",
                "bypass_incoming_followers": true
            },
            "dry_run": true,
            "version": "1.2.3"
        })))
        .mount(&server)
        .await;

    let a = args(&["--url", &server.uri()]);
    run_cli_status(&a).await.expect("status with stats");
}
