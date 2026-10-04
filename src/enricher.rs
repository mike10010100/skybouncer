//! Context enricher querying author profile metadata and parent post conversation threads.
//!
//! Provides deeper conversational nuance (parent post context, author account age, bio)
//! to the downstream classifier engine, helping detect bad-faith sea-lioning and harassment.

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::matcher::Interaction;

/// Default public Bluesky AppView endpoint for read-only XRPC resolution.
pub const DEFAULT_APPVIEW_ENDPOINT: &str = "https://public.api.bsky.app";

/// Default public Bluesky CDN endpoint for image thumbnail retrieval.
pub const DEFAULT_CDN_ENDPOINT: &str = "https://cdn.bsky.app";

/// Default timeout in milliseconds for AppView profile and post enrichment queries.
pub const DEFAULT_ENRICHER_TIMEOUT_MS: u64 = 1500;

/// Profile metadata describing the author of an interaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct AuthorContext {
    /// Author Bluesky handle (e.g. `"alice.bsky.social"`).
    pub handle: Option<String>,
    /// User-defined display name.
    pub display_name: Option<String>,
    /// Profile description / bio text.
    pub description: Option<String>,
    /// Count of accounts following this author.
    pub followers_count: Option<u64>,
    /// Count of accounts followed by this author.
    pub follows_count: Option<u64>,
    /// Account registration timestamp in ISO 8601 format.
    pub created_at: Option<String>,
}

/// Context metadata describing the parent post in a conversation thread.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ParentPostContext {
    /// Author DID of the parent post.
    pub author_did: String,
    /// Text content of the parent post being replied to.
    pub text: String,
    /// Content identifier (CID) of the parent post record.
    pub cid: Option<String>,
}

/// Consolidated conversational, author, and visual context supplied to classifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct EnrichedContext {
    /// Resolved author profile details.
    pub author: Option<AuthorContext>,
    /// Resolved parent post content and author.
    pub parent_post: Option<ParentPostContext>,
    /// Base64-encoded image payloads fetched from CDN for attached images.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images_base64: Vec<String>,
}

impl EnrichedContext {
    /// Creates an empty context with no author or parent post details.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` if neither author, parent post, nor image context was resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.author.is_none() && self.parent_post.is_none() && self.images_base64.is_empty()
    }

    /// Formats the enriched context into a concise string block for classifier prompt injection.
    #[must_use]
    pub fn format_for_classifier(&self) -> String {
        let mut sections = Vec::new();

        if let Some(ref author) = self.author {
            let mut author_desc = Vec::new();
            if let Some(ref handle) = author.handle {
                author_desc.push(format!("handle: @{handle}"));
            }
            if let Some(ref name) = author.display_name {
                author_desc.push(format!("name: \"{name}\""));
            }
            if let Some(ref bio) = author.description {
                let bio_snippet: String = bio.chars().take(250).collect();
                author_desc.push(format!("bio: \"{bio_snippet}\""));
            }
            if let Some(followers) = author.followers_count {
                author_desc.push(format!("followers: {followers}"));
            }
            if !author_desc.is_empty() {
                sections.push(format!("Author Profile [{}]", author_desc.join(", ")));
            }
        }

        if let Some(ref parent) = self.parent_post {
            let text_snippet: String = parent.text.chars().take(200).collect();
            sections.push(format!(
                "In Reply To (by {}): \"{}\"",
                parent.author_did, text_snippet
            ));
        }

        if !self.images_base64.is_empty() {
            sections.push(format!(
                "Image Attachments [{} image(s) attached and decoded for visual inspection]",
                self.images_base64.len()
            ));
        }

        sections.join("\n")
    }
}

/// Asynchronous trait for enriching interaction candidates before classification.
#[async_trait]
pub trait ContextEnricher: Send + Sync {
    /// Enriches an interaction with author metadata and parent post context.
    ///
    /// Must never fail or block the pipeline; failures should degrade gracefully to [`EnrichedContext::empty`].
    async fn enrich(&self, interaction: &Interaction) -> EnrichedContext;

    /// Resolves an ATProto handle to a DID via XRPC `com.atproto.identity.resolveHandle`.
    ///
    /// Returns `None` if the handle cannot be resolved or if the enricher does not support resolution.
    async fn resolve_handle(&self, _handle: &str) -> Option<String> {
        None
    }

    /// Resolves an ATProto DID to a handle via profile lookup or directory resolution.
    ///
    /// Returns `None` if the DID cannot be resolved or if the enricher does not support resolution.
    async fn resolve_did(&self, _did: &str) -> Option<String> {
        None
    }

    /// Fetches a base64-encoded image thumbnail for an author and image CID.
    ///
    /// Returns `None` if the image cannot be retrieved or decoded.
    async fn fetch_image_base64(&self, _author_did: &str, _cid: &str) -> Option<String> {
        None
    }
}

/// Zero-cost no-op enricher returning empty context immediately.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopContextEnricher;

#[async_trait]
impl ContextEnricher for NoopContextEnricher {
    async fn enrich(&self, _interaction: &Interaction) -> EnrichedContext {
        EnrichedContext::empty()
    }
}

/// Mock context enricher for deterministic hermetic testing.
#[derive(Debug, Default, Clone)]
pub struct MockContextEnricher {
    authors: Arc<RwLock<HashMap<String, AuthorContext>>>,
    parent_posts: Arc<RwLock<HashMap<String, ParentPostContext>>>,
    handles: Arc<RwLock<HashMap<String, String>>>,
    images: Arc<RwLock<HashMap<(String, String), String>>>,
}

impl MockContextEnricher {
    /// Creates a new empty [`MockContextEnricher`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Injects author profile metadata for a given DID.
    pub fn set_author(&self, did: impl Into<String>, author: AuthorContext) {
        self.authors.write().insert(did.into(), author);
    }

    /// Injects parent post context for a given AT-URI.
    pub fn set_parent_post(&self, uri: impl Into<String>, parent: ParentPostContext) {
        self.parent_posts.write().insert(uri.into(), parent);
    }

    /// Registers a mock handle-to-DID resolution mapping.
    pub fn set_handle(&self, handle: impl Into<String>, did: impl Into<String>) {
        let clean = handle.into().trim().trim_start_matches('@').to_string();
        self.handles.write().insert(clean, did.into());
    }

    /// Injects a base64-encoded image payload for a given author DID and image CID.
    pub fn set_image_base64(
        &self,
        author_did: impl Into<String>,
        cid: impl Into<String>,
        base64: impl Into<String>,
    ) {
        self.images
            .write()
            .insert((author_did.into(), cid.into()), base64.into());
    }
}

#[async_trait]
impl ContextEnricher for MockContextEnricher {
    async fn enrich(&self, interaction: &Interaction) -> EnrichedContext {
        let author = self.authors.read().get(&interaction.author_did).cloned();
        let parent_post = interaction
            .parent_uri
            .as_ref()
            .and_then(|uri| self.parent_posts.read().get(uri).cloned());

        let mut images_base64 = Vec::new();
        {
            let guard = self.images.read();
            for cid in &interaction.image_cids {
                if let Some(b64) = guard.get(&(interaction.author_did.clone(), cid.clone())) {
                    images_base64.push(b64.clone());
                }
            }
        }

        EnrichedContext {
            author,
            parent_post,
            images_base64,
        }
    }

    async fn resolve_handle(&self, handle: &str) -> Option<String> {
        let clean = handle.trim().trim_start_matches('@');
        if clean.starts_with("did:") {
            return Some(clean.to_string());
        }
        self.handles.read().get(clean).cloned()
    }

    async fn resolve_did(&self, did: &str) -> Option<String> {
        let clean = did.trim();
        if let Some(author) = self.authors.read().get(clean) {
            if let Some(ref h) = author.handle {
                let trimmed = h.trim().trim_start_matches('@').to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
        for (h, d) in self.handles.read().iter() {
            if d == clean {
                return Some(h.clone());
            }
        }
        None
    }

    async fn fetch_image_base64(&self, author_did: &str, cid: &str) -> Option<String> {
        self.images
            .read()
            .get(&(author_did.to_string(), cid.to_string()))
            .cloned()
    }
}

/// AppView HTTP client resolving author profiles and parent posts via public XRPC endpoints.
#[derive(Debug, Clone)]
pub struct AppViewContextEnricher {
    appview_url: String,
    cdn_url: String,
    http_client: reqwest::Client,
}

impl AppViewContextEnricher {
    /// Creates a new [`AppViewContextEnricher`] targeting the default public AppView and CDN.
    #[must_use]
    pub fn new() -> Self {
        Self::with_endpoints(DEFAULT_APPVIEW_ENDPOINT, DEFAULT_CDN_ENDPOINT)
    }

    /// Creates a new [`AppViewContextEnricher`] with a custom AppView endpoint and default CDN.
    #[must_use]
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self::with_endpoints(endpoint, DEFAULT_CDN_ENDPOINT)
    }

    /// Creates a new [`AppViewContextEnricher`] with custom AppView and CDN endpoints.
    #[must_use]
    pub fn with_endpoints(
        appview_endpoint: impl Into<String>,
        cdn_endpoint: impl Into<String>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_millis(DEFAULT_ENRICHER_TIMEOUT_MS))
            .build()
            .unwrap_or_default();

        Self {
            appview_url: appview_endpoint.into().trim_end_matches('/').to_string(),
            cdn_url: cdn_endpoint.into().trim_end_matches('/').to_string(),
            http_client: client,
        }
    }

    /// Fetches author profile metadata from the AppView.
    async fn fetch_author_profile(&self, did: &str) -> Option<AuthorContext> {
        let url = format!(
            "{}/xrpc/app.bsky.actor.getProfile?actor={did}",
            self.appview_url
        );
        let resp = self.http_client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }

        #[derive(Deserialize)]
        struct RawProfile {
            handle: Option<String>,
            #[serde(rename = "displayName")]
            display_name: Option<String>,
            description: Option<String>,
            #[serde(rename = "followersCount")]
            followers_count: Option<u64>,
            #[serde(rename = "followsCount")]
            follows_count: Option<u64>,
            #[serde(rename = "createdAt")]
            created_at: Option<String>,
        }

        let raw: RawProfile = resp.json().await.ok()?;
        Some(AuthorContext {
            handle: raw.handle,
            display_name: raw.display_name,
            description: raw.description,
            followers_count: raw.followers_count,
            follows_count: raw.follows_count,
            created_at: raw.created_at,
        })
    }

    /// Fetches parent post text content from the AppView.
    async fn fetch_parent_post(&self, uri: &str) -> Option<ParentPostContext> {
        let url = format!(
            "{}/xrpc/app.bsky.feed.getPosts?uris={uri}",
            self.appview_url
        );
        let resp = self.http_client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }

        #[derive(Deserialize)]
        struct RawRecord {
            text: Option<String>,
        }

        #[derive(Deserialize)]
        struct RawAuthor {
            did: String,
        }

        #[derive(Deserialize)]
        struct RawPostView {
            author: RawAuthor,
            record: serde_json::Value,
            cid: Option<String>,
        }

        #[derive(Deserialize)]
        struct RawPostsResponse {
            posts: Vec<RawPostView>,
        }

        let raw: RawPostsResponse = resp.json().await.ok()?;
        let first = raw.posts.into_iter().next()?;
        let text = serde_json::from_value::<RawRecord>(first.record)
            .ok()
            .and_then(|r| r.text)
            .unwrap_or_default();

        Some(ParentPostContext {
            author_did: first.author.did,
            text,
            cid: first.cid,
        })
    }

    /// Fetches initial followed DIDs for an actor from the public AppView (XRPC `app.bsky.graph.getFollows`).
    ///
    /// Used for zero-credential cold-start hydration of the local follow graph.
    pub async fn fetch_follows(&self, actor: &str, limit: u8) -> Vec<String> {
        let url = format!(
            "{}/xrpc/app.bsky.graph.getFollows?actor={actor}&limit={limit}",
            self.appview_url
        );
        let resp = match self.http_client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => return Vec::new(),
        };

        #[derive(Deserialize)]
        struct FollowProfile {
            did: String,
        }

        #[derive(Deserialize)]
        struct GetFollowsResponse {
            follows: Vec<FollowProfile>,
        }

        match resp.json::<GetFollowsResponse>().await {
            Ok(body) => body.follows.into_iter().map(|f| f.did).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Resolves an ATProto handle to a DID via XRPC `com.atproto.identity.resolveHandle`.
    pub async fn resolve_handle(&self, handle: &str) -> Option<String> {
        let clean = handle.trim().trim_start_matches('@');
        if clean.starts_with("did:") {
            return Some(clean.to_string());
        }

        let url = format!(
            "{}/xrpc/com.atproto.identity.resolveHandle?handle={clean}",
            self.appview_url
        );
        let resp = self.http_client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }

        #[derive(Deserialize)]
        struct ResolveHandleResponse {
            did: String,
        }

        resp.json::<ResolveHandleResponse>()
            .await
            .ok()
            .map(|r| r.did)
    }

    /// Fetches an image thumbnail from the Bluesky CDN and encodes it as base64.
    pub async fn fetch_image_base64(&self, author_did: &str, cid: &str) -> Option<String> {
        let url = format!(
            "{}/img/feed_thumbnail/plain/{author_did}/{cid}@jpeg",
            self.cdn_url
        );
        let resp = self.http_client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }

        let bytes = resp.bytes().await.ok()?;
        if bytes.len() > 2 * 1024 * 1024 {
            return None;
        }

        use base64::Engine;
        Some(base64::engine::general_purpose::STANDARD.encode(&bytes))
    }

    /// Fetches base64-encoded thumbnails for a set of image CIDs from the Bluesky CDN.
    pub async fn fetch_images_base64(&self, author_did: &str, cids: &[String]) -> Vec<String> {
        let mut results = Vec::with_capacity(cids.len().min(4));
        for cid in cids.iter().take(4) {
            if let Some(b64) = self.fetch_image_base64(author_did, cid).await {
                results.push(b64);
            }
        }
        results
    }

    /// Resolves an ATProto DID to a handle via profile lookup or PLC directory fallback.
    pub async fn resolve_did(&self, did: &str) -> Option<String> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }

        // 1. Try AppView actor profile
        if let Some(profile) = self.fetch_author_profile(clean).await {
            if let Some(h) = profile.handle {
                let trimmed = h.trim().trim_start_matches('@').to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }

        // 2. Fallback to PLC directory if did:plc:...
        if clean.starts_with("did:plc:") {
            let plc_url = format!("https://plc.directory/{clean}");
            if let Ok(resp) = self.http_client.get(&plc_url).send().await {
                if resp.status().is_success() {
                    #[derive(Deserialize)]
                    struct PlcDoc {
                        #[serde(rename = "alsoKnownAs", default)]
                        also_known_as: Vec<String>,
                    }
                    if let Ok(doc) = resp.json::<PlcDoc>().await {
                        for alias in doc.also_known_as {
                            if let Some(handle) = alias.strip_prefix("at://") {
                                let trimmed = handle.trim().trim_start_matches('@').to_string();
                                if !trimmed.is_empty() {
                                    return Some(trimmed);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

impl Default for AppViewContextEnricher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ContextEnricher for AppViewContextEnricher {
    async fn enrich(&self, interaction: &Interaction) -> EnrichedContext {
        let author_fut = self.fetch_author_profile(&interaction.author_did);
        let parent_fut = async {
            if let Some(ref uri) = interaction.parent_uri {
                self.fetch_parent_post(uri).await
            } else {
                None
            }
        };
        let images_fut = async {
            if interaction.has_images() {
                self.fetch_images_base64(&interaction.author_did, &interaction.image_cids)
                    .await
            } else {
                Vec::new()
            }
        };

        let (author, parent_post, images_base64) = tokio::join!(author_fut, parent_fut, images_fut);

        EnrichedContext {
            author,
            parent_post,
            images_base64,
        }
    }

    async fn resolve_handle(&self, handle: &str) -> Option<String> {
        self.resolve_handle(handle).await
    }

    async fn resolve_did(&self, did: &str) -> Option<String> {
        self.resolve_did(did).await
    }

    async fn fetch_image_base64(&self, author_did: &str, cid: &str) -> Option<String> {
        self.fetch_image_base64(author_did, cid).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_context_enricher_with_images() {
        let enricher = MockContextEnricher::new();
        enricher.set_image_base64("did:plc:author1", "bafkimage1", "aGVsbG8gd29ybGQ=");
        enricher.set_image_base64("did:plc:author1", "bafkimage2", "c2Vjb25kIGltYWdl");

        let mut interaction = Interaction::mock_test_candidate(
            "did:plc:author1",
            "did:plc:target1",
            "Check this image",
        );
        interaction.image_cids = vec!["bafkimage1".to_string(), "bafkimage2".to_string()];
        interaction.image_alts = vec!["Alt 1".to_string(), "Alt 2".to_string()];

        let enriched = enricher.enrich(&interaction).await;
        assert_eq!(enriched.images_base64.len(), 2);
        assert_eq!(enriched.images_base64[0], "aGVsbG8gd29ybGQ=");
        assert_eq!(enriched.images_base64[1], "c2Vjb25kIGltYWdl");

        let formatted = enriched.format_for_classifier();
        assert!(formatted
            .contains("Image Attachments [2 image(s) attached and decoded for visual inspection]"));
    }

    #[tokio::test]
    async fn test_mock_context_enricher_fetch_image_base64() {
        let enricher = MockContextEnricher::new();
        enricher.set_image_base64("did:plc:author1", "bafkimage1", "aGVsbG8=");

        let fetched = enricher
            .fetch_image_base64("did:plc:author1", "bafkimage1")
            .await;
        assert_eq!(fetched, Some("aGVsbG8=".to_string()));

        let missing = enricher
            .fetch_image_base64("did:plc:author1", "bafkimage_unknown")
            .await;
        assert_eq!(missing, None);
    }

    #[tokio::test]
    async fn test_mock_context_enricher_resolve_did() {
        let enricher = MockContextEnricher::new();
        enricher.set_handle("alice.bsky.social", "did:plc:alice123");

        let resolved = enricher.resolve_did("did:plc:alice123").await;
        assert_eq!(resolved, Some("alice.bsky.social".to_string()));

        let unknown = enricher.resolve_did("did:plc:unknown").await;
        assert_eq!(unknown, None);
    }
}
