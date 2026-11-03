//! Jetstream WebSocket streaming client for live firehose ingestion.
//!
//! Connects to public ATProto Jetstream firehose endpoints, subscribes to post, follow,
//! and sovereign configuration collections, handles automatic reconnection with exponential backoff,
//! and dispatches parsed [`JetstreamCommit`] frames to the [`crate::engine::SkybouncerEngine`].

use std::time::Duration;

use skybase::ingest::events::JetstreamCommit;
pub use skybase::ingest::streamer::{
    resolve_resume_cursor, CURSOR_REWIND_OVERLAP_US, DEFAULT_JETSTREAM_ENDPOINT,
    DEFAULT_READ_TIMEOUT, INITIAL_BACKOFF, MAX_BACKOFF, MAX_JETSTREAM_REPLAY_WINDOW_US,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::SkybouncerError;
use crate::modlist::SOVEREIGN_CONFIG_COLLECTION;

/// Configuration for the Jetstream stream listener.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// WebSocket endpoint URL.
    pub endpoint: String,
    /// Collections to subscribe to at the edge.
    pub collections: Vec<String>,
    /// Initial cursor timestamp in microseconds (`time_us`), if replaying from a point in time.
    pub cursor: Option<u64>,
    /// Maximum idle duration between WebSocket frames before forcing a reconnect.
    pub read_timeout: Duration,
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
            read_timeout: DEFAULT_READ_TIMEOUT,
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

    /// Sets the idle read timeout before reconnecting on a silent WebSocket stall.
    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout.max(Duration::from_millis(50));
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

    /// Converts this `skybouncer` [`StreamConfig`] into a [`skybase::ingest::streamer::StreamConfig`].
    #[must_use]
    pub fn to_skybase_config(&self) -> skybase::ingest::streamer::StreamConfig {
        let mut cfg = skybase::ingest::streamer::StreamConfig::new(&self.endpoint)
            .with_collections(self.collections.clone())
            .with_read_timeout(self.read_timeout);
        if let Some(c) = self.cursor {
            cfg = cfg.with_cursor(c);
        }
        cfg
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
    skybase::ingest::streamer::run_jetstream_streamer(config.to_skybase_config(), tx, cancel)
        .await
        .map_err(SkybouncerError::from)
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

    #[test]
    fn resolve_resume_cursor_rewinds_and_clamps_to_retention_window() {
        let now_us = 1_800_000_000_000_000_u64;
        assert_eq!(resolve_resume_cursor(0, now_us), None);

        // Recent cursor (10 minutes ago) rewinds by 5s
        let recent = now_us - 600_000_000;
        assert_eq!(
            resolve_resume_cursor(recent, now_us),
            Some(recent - CURSOR_REWIND_OVERLAP_US)
        );

        // Stale cursor (10 days ago) clamps to 72h before now_us
        let stale = now_us - (10 * 24 * 3600 * 1_000_000);
        assert_eq!(
            resolve_resume_cursor(stale, now_us),
            Some(now_us - MAX_JETSTREAM_REPLAY_WINDOW_US)
        );
    }
}
