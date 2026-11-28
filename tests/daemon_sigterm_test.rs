//! Isolated integration test verifying Unix `SIGTERM` shutdown, JoinSet drain,
//! and clean `PRAGMA wal_checkpoint(TRUNCATE)` in `skybouncer::daemon::run`.

#![cfg(all(
    unix,
    feature = "web",
    feature = "stream",
    feature = "bot",
    feature = "telemetry"
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_pr3_daemon_run_handles_sigterm_and_truncates_wal() {
    let base_dir = std::env::temp_dir().join(format!("skybouncer_sigterm_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base_dir);
    std::fs::create_dir_all(&base_dir).unwrap();
    let db_path = base_dir.join("skybouncer.db");
    let wal_path = base_dir.join("skybouncer.db-wal");

    // Isolate environment for daemon::run (isolated single-test binary).
    std::env::set_var("SKYBOUNCER_DB_PATH", &db_path);
    std::env::set_var("SKYBOUNCER_SHADOW_MODE", "true");
    std::env::set_var("WEB_ENABLED", "false");
    std::env::remove_var("PORT");
    std::env::remove_var("SKYBOUNCER_PORT");
    std::env::remove_var("PROTECTED_DIDS");
    std::env::remove_var("SKYBOUNCER_PROTECTED_DIDS");
    std::env::remove_var("ADMIN_DID");
    std::env::remove_var("BOT_APP_PASSWORD");
    std::env::remove_var("PDS_ACCESS_TOKEN");
    std::env::remove_var("CHAT_ACCESS_TOKEN");
    std::env::set_var("JETSTREAM_ENDPOINT", "ws://127.0.0.1:9/subscribe");
    std::env::set_var("APPVIEW_ENDPOINT", "http://127.0.0.1:9");

    let cancel = CancellationToken::new();
    let daemon_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        skybouncer::daemon::run(&["--dry-run".to_string()], daemon_cancel).await
    });

    // Give daemon::run enough time to register its SIGTERM signal handler and enter select!
    tokio::time::sleep(Duration::from_millis(350)).await;

    let pid = std::process::id().to_string();
    let status = std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("spawn kill -TERM");
    assert!(status.success(), "kill -TERM must succeed");

    let daemon_res = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("daemon::run should exit promptly after SIGTERM")
        .expect("daemon task join");
    assert!(daemon_res.is_ok(), "daemon::run error: {daemon_res:?}");

    // On clean exit, PRAGMA wal_checkpoint(TRUNCATE) should leave zero WAL bytes (or no -wal).
    let wal_len = wal_path.metadata().map(|m| m.len()).unwrap_or(0);
    assert_eq!(wal_len, 0, "WAL must be truncated cleanly on daemon exit");

    let _ = std::fs::remove_dir_all(&base_dir);
}
