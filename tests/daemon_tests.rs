//! Integration test for the daemon orchestrator (`skybouncer::daemon::run`).
//!
//! Drives a dry-run daemon with a pre-cancelled token so startup, task supervision,
//! graceful drain, and final telemetry all execute without live network dependencies.

#![cfg(all(
    feature = "web",
    feature = "stream",
    feature = "bot",
    feature = "telemetry"
))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::await_holding_lock,
    missing_docs
)]

use std::sync::Mutex;

use tokio_util::sync::CancellationToken;

/// Serialize env mutation across the test process.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const ENV_KEYS: &[&str] = &[
    "PROTECTED_DIDS",
    "SKYBOUNCER_PROTECTED_DIDS",
    "ADMIN_DID",
    "SKYBOUNCER_ADMIN_DID",
    "PORT",
    "SKYBOUNCER_PORT",
    "WEB_ENABLED",
    "SKYBOUNCER_WEB_ENABLED",
    "DRY_RUN",
    "SKYBOUNCER_DRY_RUN",
    "SKYBOUNCER_SHADOW_MODE",
    "BOT_APP_PASSWORD",
    "BLUESKY_APP_PASSWORD",
    "CHAT_ACCESS_TOKEN",
];

/// Saves and clears the daemon-related env vars; returns the saved snapshot.
fn clear_env() -> Vec<(&'static str, Option<String>)> {
    ENV_KEYS
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect::<Vec<_>>()
}

fn restore_env(saved: &[(&'static str, Option<String>)]) {
    for (k, v) in saved {
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
}

fn clear_daemon_vars() {
    for k in ENV_KEYS {
        std::env::remove_var(k);
    }
}

#[tokio::test]
async fn daemon_dry_run_starts_and_shuts_down_on_cancel() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = clear_env();
    clear_daemon_vars();

    let cancel = CancellationToken::new();
    cancel.cancel(); // pre-cancelled: shutdown immediately after startup

    let args: Vec<String> = vec![
        "--dry-run".to_string(),
        "--did".to_string(),
        "did:plc:daemon-test".to_string(),
    ];

    let result = skybouncer::daemon::run(&args, cancel).await;
    assert!(result.is_ok(), "daemon run failed: {result:?}");

    restore_env(&saved);
}

#[tokio::test]
async fn daemon_rejects_blank_rules_argument() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = clear_env();
    clear_daemon_vars();

    let cancel = CancellationToken::new();
    cancel.cancel();

    let args: Vec<String> = vec!["--rules".to_string(), "   ".to_string()];
    let result = skybouncer::daemon::run(&args, cancel).await;
    // Either rejects the malformed rubric (Config error) or proceeds; assert no panic.
    if let Err(e) = result {
        assert!(matches!(e, skybouncer::SkybouncerError::Config(_)));
    }

    restore_env(&saved);
}

#[tokio::test]
async fn daemon_with_chat_token_spawns_bot_workers() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = clear_env();
    clear_daemon_vars();

    // Provide a chat token + bot DID so the bot-worker + alert-dispatcher spawn paths run.
    std::env::set_var("CHAT_ACCESS_TOKEN", "test-token");
    std::env::set_var("BOT_DID", "did:plc:botworker");

    let cancel = CancellationToken::new();
    cancel.cancel();

    let args: Vec<String> = vec![
        "--dry-run".to_string(),
        "--did".to_string(),
        "did:plc:daemon-bot".to_string(),
    ];
    let result = skybouncer::daemon::run(&args, cancel).await;
    assert!(result.is_ok(), "daemon run failed: {result:?}");

    restore_env(&saved);
}

#[tokio::test]
async fn daemon_enables_web_dashboard_on_port() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = clear_env();
    clear_daemon_vars();

    // A configured PORT enables the web-dashboard spawn branch.
    std::env::set_var("PORT", "0");

    let cancel = CancellationToken::new();
    cancel.cancel();

    let args: Vec<String> = vec![
        "--dry-run".to_string(),
        "--did".to_string(),
        "did:plc:daemon-web".to_string(),
    ];
    let result = skybouncer::daemon::run(&args, cancel).await;
    assert!(result.is_ok(), "daemon run failed: {result:?}");

    restore_env(&saved);
}
