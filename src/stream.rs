//! Jetstream WebSocket streaming client for live firehose ingestion.
//!
//! Connects to public ATProto Jetstream firehose endpoints, subscribes to post, follow,
//! and sovereign configuration collections, handles automatic reconnection with exponential backoff,
//! and dispatches parsed [`JetstreamCommit`] frames to the [`crate::engine::SkybouncerEngine`].

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use skybase::ingest::backoff::BackoffManager;
use skybase::ingest::events::{parse_jetstream_frame, JetstreamCommit, JetstreamEvent};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::SkybouncerError;
use crate::modlist::SOVEREIGN_CONFIG_COLLECTION;

/// Default public Jetstream endpoint.
pub const DEFAULT_JETSTREAM_ENDPOINT: &str = "wss://jetstream2.us-east.bsky.network/subscribe";

/// Initial backoff delay on connection failure (500ms).
pub const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// Maximum backoff delay cap on repeated failures (30s).
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Configuration for the Jetstream stream listener.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// WebSocket endpoint URL.
    pub endpoint: String,
    /// Collections to subscribe to at the edge.
    pub collections: Vec<String>,
    /// Initial cursor timestamp in microseconds (`time_us`), if replaying from a point in time.
    pub cursor: Option<u64>,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_JETSTREAM_ENDPOINT.to_string(),
            collections: vec![
                "app.bsky.feed.post".to_string(),
                "app.bsky.graph.follow".to_string(),
                SOVEREIGN_CONFIG_COLLECTION.to_string(),
                "app.bsky.graph.list".to_string(),
            ],
            cursor: None,
        }
    }
}

impl StreamConfig {
    /// Creates a new streaming configuration with default collections.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Self::default()
        }
    }

    /// Appends a target collection NSID to subscribe to.
    #[must_use]
    pub fn with_collection(mut self, collection: impl Into<String>) -> Self {
        self.collections.push(collection.into());
        self
    }

    /// Sets the replay cursor timestamp in microseconds.
    #[must_use]
    pub fn with_cursor(mut self, cursor: u64) -> Self {
        self.cursor = if cursor > 0 { Some(cursor) } else { None };
        self
    }

    /// Constructs the full WebSocket subscription URL with query parameters.
    #[must_use]
    pub fn build_url(&self) -> String {
        skybase::ingest::build_subscription_url_full(
            &self.endpoint,
            &self.collections,
            &[],
            self.cursor.filter(|c| *c > 0),
        )
    }
}

/// Connects to Jetstream and forwards parsed commits to `tx` until `cancel` is triggered.
///
/// Automatically reconnects with exponential backoff on connection drops and restores
/// last seen cursor to prevent dropped events during reconnects.
///
/// # Errors
/// Returns [`SkybouncerError`] if unrecoverable stream configuration errors occur.
pub async fn run_jetstream_streamer(
    config: StreamConfig,
    tx: mpsc::Sender<JetstreamCommit>,
    cancel: CancellationToken,
) -> Result<(), SkybouncerError> {
    let mut backoff = BackoffManager::new(INITIAL_BACKOFF, MAX_BACKOFF);
    let mut current_cursor: Option<u64> = config.cursor;

    while !cancel.is_cancelled() {
        let mut active_config = config.clone();
        if let Some(cursor) = current_cursor {
            // Rewind 5s (5,000,000 µs) on reconnect to prevent missed events across network drops
            active_config.cursor = Some(cursor.saturating_sub(5_000_000));
        }
        let url = active_config.build_url();
        info!(endpoint = %url, cursor = ?active_config.cursor, "Connecting to Jetstream firehose");

        match connect_async(&url).await {
            Ok((ws_stream, response)) => {
                debug!(status = %response.status(), "WebSocket connection established");

                let (mut write_half, mut read_half) = ws_stream.split();

                loop {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {
                            info!("Streamer received cancellation signal; closing connection");
                            let _ = write_half.send(Message::Close(None)).await;
                            return Ok(());
                        }
                        msg_opt = read_half.next() => {
                            match msg_opt {
                                Some(Ok(Message::Text(text))) => {
                                    if let Some(JetstreamEvent::Commit(commit)) =
                                        parse_jetstream_frame(&text)
                                    {
                                        current_cursor = Some(commit.time_us);
                                        backoff.reset();
                                        if tx.send(commit).await.is_err() {
                                            debug!("Commit receiver dropped; stopping streamer");
                                            return Ok(());
                                        }
                                    }
                                }
                                Some(Ok(Message::Binary(bytes))) => {
                                    if let Ok(text) = std::str::from_utf8(&bytes) {
                                        if let Some(JetstreamEvent::Commit(commit)) =
                                            parse_jetstream_frame(text)
                                        {
                                            current_cursor = Some(commit.time_us);
                                            backoff.reset();
                                            if tx.send(commit).await.is_err() {
                                                debug!("Commit receiver dropped; stopping streamer");
                                                return Ok(());
                                            }
                                        }
                                    }
                                }

                                Some(Ok(Message::Ping(payload))) => {
                                    let _ = write_half.send(Message::Pong(payload)).await;
                                }
                                Some(Ok(Message::Pong(_))) => {}
                                Some(Ok(Message::Close(frame))) => {
                                    warn!(frame = ?frame, "Jetstream server sent close frame; reconnecting");
                                    break;
                                }
                                Some(Ok(Message::Frame(_))) => {}
                                Some(Err(e)) => {
                                    warn!(error = %e, "WebSocket read error; reconnecting");
                                    break;
                                }
                                None => {
                                    warn!("Jetstream stream ended unexpectedly; reconnecting");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to connect to Jetstream");
            }
        }

        // Backoff delay before attempting reconnect (exponential with jitter)
        let delay = backoff.next_backoff();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                return Ok(());
            }
            _ = tokio::time::sleep(delay) => {}
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_collections_and_no_cursor() {
        let cfg = StreamConfig::default();
        assert_eq!(cfg.endpoint, DEFAULT_JETSTREAM_ENDPOINT);
        assert_eq!(cfg.cursor, None);
        assert!(cfg.collections.contains(&"app.bsky.feed.post".to_string()));
        assert!(cfg
            .collections
            .contains(&"app.bsky.graph.follow".to_string()));
        assert!(cfg.collections.contains(&"app.bsky.graph.list".to_string()));
        assert!(cfg
            .collections
            .contains(&SOVEREIGN_CONFIG_COLLECTION.to_string()));
    }

    #[test]
    fn with_collection_appends() {
        let cfg =
            StreamConfig::new("wss://example.test/subscribe").with_collection("com.example.custom");
        assert!(cfg.collections.contains(&"com.example.custom".to_string()));
    }

    #[test]
    fn with_cursor_zero_clears_cursor() {
        assert_eq!(StreamConfig::default().with_cursor(0).cursor, None);
        assert_eq!(StreamConfig::default().with_cursor(123).cursor, Some(123));
    }

    #[test]
    fn build_url_includes_all_wanted_collections() {
        let cfg = StreamConfig::new("wss://example.test/subscribe");
        let url = cfg.build_url();
        assert!(
            url.starts_with("wss://example.test/subscribe?"),
            "url={url}"
        );
        for col in &cfg.collections {
            assert!(
                url.contains(&format!("wantedCollections={col}")),
                "url={url}"
            );
        }
        // No cursor means no cursor param.
        assert!(!url.contains("cursor="), "url={url}");
    }

    #[test]
    fn build_url_includes_cursor_when_set() {
        let url = StreamConfig::new("wss://example.test/subscribe")
            .with_cursor(1_700_000_000_000_000)
            .build_url();
        assert!(
            url.contains("cursor=1700000000000000"),
            "cursor must be appended, url={url}"
        );
    }

    #[test]
    fn build_url_prefers_existing_query_separator() {
        let url = StreamConfig::new("wss://example.test/subscribe?foo=bar")
            .with_collection("app.bsky.feed.post")
            .build_url();
        // Existing query string is preserved and joined with '&'.
        assert!(url.contains("foo=bar"), "url={url}");
        assert!(
            url.contains("wantedCollections=app.bsky.feed.post"),
            "url={url}"
        );
    }
}
