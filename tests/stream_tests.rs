//! Integration tests for the Jetstream streamer (`run_jetstream_streamer`).
//!
//! Exercises the S5-refactored forward loop, cursor handling, reconnect, and graceful
//! cancellation against skybase's hermetic `MockJetstreamServer`.
#![cfg(feature = "stream")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::time::Duration;

use skybase::ingest::events::JetstreamCommit;
use skybase::ingest::MockJetstreamServer;
use skybouncer::stream::{run_jetstream_streamer, StreamConfig};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

async fn wait_for_connection(server: &MockJetstreamServer) {
    for _ in 0..100 {
        if server.active_connections() > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("streamer never connected to the mock server");
}

#[tokio::test]
async fn streamer_forwards_parsed_commits_to_channel() {
    let server = MockJetstreamServer::start().await.expect("mock server");
    let (tx, mut rx) = mpsc::channel::<JetstreamCommit>(16);

    let cancel = CancellationToken::new();
    let config = StreamConfig::new(server.ws_url());
    let handle = {
        let cancel = cancel.clone();
        tokio::spawn(async move { run_jetstream_streamer(config, tx, cancel).await })
    };

    // The mock only broadcasts to connected subscribers, so connect first.
    wait_for_connection(&server).await;
    server
        .emit_commit_payload(
            "did:plc:alice",
            1_700_000_000_000_000,
            "app.bsky.feed.post",
            "3kabc",
            "create",
            Some("bafycid"),
            Some(serde_json::json!({"text": "hello"})),
        )
        .expect("emit");

    let commit = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("did not receive a commit in time")
        .expect("channel closed");
    assert_eq!(commit.did, "did:plc:alice");
    assert_eq!(commit.collection.as_str(), "app.bsky.feed.post");
    assert_eq!(commit.rkey, "3kabc");

    cancel.cancel();
    let res = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("streamer did not stop after cancellation")
        .expect("join");
    assert!(res.is_ok(), "streamer returned error: {res:?}");
}

#[tokio::test]
async fn streamer_stops_cleanly_on_cancel_before_any_traffic() {
    let server = MockJetstreamServer::start().await.expect("mock server");
    let (tx, _rx) = mpsc::channel::<JetstreamCommit>(16);

    let cancel = CancellationToken::new();
    let config = StreamConfig::new(server.ws_url());
    let handle = {
        let cancel = cancel.clone();
        tokio::spawn(async move { run_jetstream_streamer(config, tx, cancel).await })
    };

    wait_for_connection(&server).await;
    cancel.cancel();

    let res = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("streamer did not stop")
        .expect("join");
    assert!(res.is_ok());
}

#[tokio::test]
async fn streamer_stops_when_receiver_drops() {
    let server = MockJetstreamServer::start().await.expect("mock server");
    let (tx, rx) = mpsc::channel::<JetstreamCommit>(16);
    drop(rx); // receiver gone

    let cancel = CancellationToken::new();
    let config = StreamConfig::new(server.ws_url());
    let handle = {
        let cancel = cancel.clone();
        tokio::spawn(async move { run_jetstream_streamer(config, tx, cancel).await })
    };

    wait_for_connection(&server).await;
    server
        .emit_commit_payload(
            "did:plc:alice",
            1_700_000_000_000_000,
            "app.bsky.feed.post",
            "3kabc",
            "create",
            None,
            None,
        )
        .expect("emit");

    // Sending on a closed channel must terminate the streamer cleanly.
    let res = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("streamer did not stop after receiver dropped")
        .expect("join");
    assert!(res.is_ok());
}

#[tokio::test]
async fn streamer_reconnects_after_disconnect_and_still_forwards() {
    let server = MockJetstreamServer::start().await.expect("mock server");
    let (tx, mut rx) = mpsc::channel::<JetstreamCommit>(16);

    let cancel = CancellationToken::new();
    let config = StreamConfig::new(server.ws_url());
    let handle = {
        let cancel = cancel.clone();
        tokio::spawn(async move { run_jetstream_streamer(config, tx, cancel).await })
    };

    wait_for_connection(&server).await;
    let first_gen = server.total_connections();

    // Abort the connection to force the reconnect/backoff path.
    server.disconnect_all().expect("disconnect");

    // The streamer should reconnect (new connection observed within the backoff window).
    let mut reconnected = false;
    for _ in 0..200 {
        if server.total_connections() > first_gen {
            reconnected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(reconnected, "streamer did not reconnect after disconnect");

    // A commit emitted after reconnect must still flow through.
    server
        .emit_commit_payload(
            "did:plc:bob",
            1_700_000_000_100_000,
            "app.bsky.feed.post",
            "3kreconnect",
            "create",
            None,
            None,
        )
        .expect("emit");

    let commit = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("no commit after reconnect")
        .expect("channel closed");
    assert_eq!(commit.did, "did:plc:bob");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

#[tokio::test]
async fn streamer_ignores_non_commit_frames() {
    let server = MockJetstreamServer::start().await.expect("mock server");
    let (tx, mut rx) = mpsc::channel::<JetstreamCommit>(16);

    let cancel = CancellationToken::new();
    let config = StreamConfig::new(server.ws_url());
    let handle = {
        let cancel = cancel.clone();
        tokio::spawn(async move { run_jetstream_streamer(config, tx, cancel).await })
    };

    wait_for_connection(&server).await;
    // Heartbeat frames parse as non-commit events and must be dropped.
    server
        .emit_heartbeat(1_700_000_000_000_000)
        .expect("heartbeat");

    // Follow with a real commit so we can deterministically observe ordering.
    server
        .emit_commit_payload(
            "did:plc:carol",
            1_700_000_000_200_000,
            "app.bsky.feed.post",
            "3kreal",
            "create",
            None,
            None,
        )
        .expect("emit");

    let commit = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("no commit")
        .expect("closed");
    // The first received item must be the commit, not the heartbeat.
    assert_eq!(commit.did, "did:plc:carol");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}
