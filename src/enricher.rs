//! Context enricher querying author profile metadata and parent post conversation threads.
//!
//! Provides deeper conversational nuance (parent post context, author account age, bio)
//! to the downstream classifier engine, helping detect bad-faith sea-lioning and harassment.

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::matcher::Interaction;

/// Default public Bluesky AppView endpoint for read-only XRPC resolution.
pub const DEFAULT_APPVIEW_ENDPOINT: &str = "https://public.api.bsky.app";

/// Default public Bluesky CDN endpoint for image thumbnail retrieval.
pub const DEFAULT_CDN_ENDPOINT: &str = "https://cdn.bsky.app";

/// Default timeout in milliseconds for AppView profile and post enrichment queries.
pub const DEFAULT_ENRICHER_TIMEOUT_MS: u64 = 1500;

/// Maximum number of ancestor posts rendered into a classifier prompt.
pub const MAX_RENDERED_THREAD_ANCESTORS: usize = 8;

/// Per-post character cap applied to each rendered thread ancestor.
pub const THREAD_ANCESTOR_CHAR_CAP: usize = 300;

/// A single ancestor post resolved from the conversation thread above the candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ThreadPost {
    /// DID of the ancestor post author.
    pub author_did: String,
    /// Plaintext content of the ancestor post.
    pub text: String,
}

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
    /// Ordered ancestor posts from oldest (thread root) to newest (immediate parent).
    ///
    /// Populated only when thread-context enrichment is enabled; empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thread_ancestors: Vec<ThreadPost>,
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

    /// Returns `true` if no author, parent post, thread ancestor, or image context was resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.author.is_none()
            && self.parent_post.is_none()
            && self.thread_ancestors.is_empty()
            && self.images_base64.is_empty()
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

        if self.thread_ancestors.is_empty() {
            if let Some(ref parent) = self.parent_post {
                let text_snippet: String = parent.text.chars().take(200).collect();
                sections.push(format!(
                    "In Reply To (by {}): \"{}\"",
                    parent.author_did, text_snippet
                ));
            }
        } else {
            let start = self
                .thread_ancestors
                .len()
                .saturating_sub(MAX_RENDERED_THREAD_ANCESTORS);
            let mut rendered = Vec::new();
            for (offset, ancestor) in self.thread_ancestors[start..].iter().enumerate() {
                let depth = start + offset + 1;
                let snippet: String = ancestor
                    .text
                    .chars()
                    .take(THREAD_ANCESTOR_CHAR_CAP)
                    .collect();
                rendered.push(format!(
                    "[{depth}] {}: \"{}\"",
                    ancestor.author_did, snippet
                ));
            }
            sections.push(format!(
                "Conversation Thread (oldest → newest):\n{}",
                rendered.join("\n")
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
        let clean = crate::util::normalize_handle(&handle.into()).to_string();
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
            thread_ancestors: Vec::new(),
            images_base64,
        }
    }

    async fn resolve_handle(&self, handle: &str) -> Option<String> {
        let clean = crate::util::normalize_handle(handle);
        if clean.starts_with("did:") {
            return Some(clean.to_string());
        }
        self.handles.read().get(clean).cloned()
    }

    async fn resolve_did(&self, did: &str) -> Option<String> {
        let clean = did.trim();
        if let Some(author) = self.authors.read().get(clean) {
            if let Some(ref h) = author.handle {
                let trimmed = crate::util::normalize_handle(h).to_string();
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
///
/// Delegates all XRPC reads and cursor pagination to [`skybase::appview::AppViewClient`];
/// this type layers skybouncer's interaction-level enrichment (parallel author/parent/image
/// fetch) and PLC-directory fallback on top.
#[derive(Debug, Clone)]
pub struct AppViewContextEnricher {
    client: skybase::appview::AppViewClient,
    thread_context: bool,
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

    /// Creates an enricher using the AppView endpoint from `APPVIEW_ENDPOINT` /
    /// `SKYBOUNCER_APPVIEW_ENDPOINT`, falling back to [`DEFAULT_APPVIEW_ENDPOINT`].
    #[must_use]
    pub fn from_env() -> Self {
        let endpoint = crate::env::var_or(
            &["APPVIEW_ENDPOINT", "SKYBOUNCER_APPVIEW_ENDPOINT"],
            DEFAULT_APPVIEW_ENDPOINT,
        );
        Self::with_endpoint(endpoint)
    }

    /// Creates a new [`AppViewContextEnricher`] with custom AppView and CDN endpoints.
    #[must_use]
    pub fn with_endpoints(
        appview_endpoint: impl Into<String>,
        cdn_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            client: skybase::appview::AppViewClient::with_endpoints(appview_endpoint, cdn_endpoint),
            thread_context: false,
        }
    }

    /// Enables or disables full conversation-thread ancestor resolution during [`ContextEnricher::enrich`].
    ///
    /// When enabled, [`ContextEnricher::enrich`] additionally walks the ancestor chain via
    /// `app.bsky.feed.getPostThread`, attaching oldest-first [`EnrichedContext::thread_ancestors`]
    /// so classifiers can reason over multi-post conversation context. Disabled by default to
    /// preserve the sub-10ms enrichment budget.
    #[must_use]
    pub fn with_thread_context(mut self, enabled: bool) -> Self {
        self.thread_context = enabled;
        self
    }

    /// Returns whether conversation-thread ancestor resolution is enabled.
    #[must_use]
    pub fn thread_context_enabled(&self) -> bool {
        self.thread_context
    }

    /// Returns the configured AppView base URL.
    #[must_use]
    pub fn appview_url(&self) -> &str {
        self.client.appview_url()
    }

    /// Returns the configured CDN base URL.
    #[must_use]
    pub fn cdn_url(&self) -> &str {
        self.client.cdn_url()
    }

    /// Fetches author profile metadata from the AppView.
    async fn fetch_author_profile(&self, did: &str) -> Option<AuthorContext> {
        let profile = self.client.fetch_profile(did).await?;
        Some(AuthorContext {
            handle: profile.handle,
            display_name: profile.display_name,
            description: profile.description,
            followers_count: profile.followers_count,
            follows_count: profile.follows_count,
            created_at: profile.created_at,
        })
    }

    /// Fetches parent post text content from the AppView.
    async fn fetch_parent_post(&self, uri: &str) -> Option<ParentPostContext> {
        let post = self.client.fetch_post(uri).await?;
        Some(ParentPostContext {
            author_did: post.author_did,
            text: post.text,
            cid: post.cid,
        })
    }

    /// Resolves the full ancestor chain above `uri` via `app.bsky.feed.getPostThread`
    /// with `depth = 0`, returning posts ordered oldest (thread root) to newest
    /// (immediate parent). Caps the chain at [`MAX_RENDERED_THREAD_ANCESTORS`].
    ///
    /// Returns an empty vector on any AppView failure.
    pub async fn fetch_thread_ancestors(&self, uri: &str) -> Vec<ThreadPost> {
        #[derive(Deserialize)]
        struct RawAuthor {
            did: String,
        }
        #[derive(Deserialize)]
        struct RawRecord {
            #[serde(default)]
            text: String,
        }
        #[derive(Deserialize)]
        struct RawPost {
            author: RawAuthor,
            record: RawRecord,
        }
        #[derive(Deserialize)]
        struct RawThreadNode {
            #[serde(default)]
            parent: Option<Box<RawThreadNode>>,
            post: Option<RawPost>,
        }
        #[derive(Deserialize)]
        struct RawThreadResponse {
            thread: RawThreadNode,
        }

        let resp = self
            .client
            .get::<RawThreadResponse>("app.bsky.feed.getPostThread", &[("uri", uri.to_string())])
            .await;

        let thread = match resp {
            Ok(r) => r.thread,
            Err(_) => return Vec::new(),
        };

        let mut chain = Vec::new();
        let mut cursor = thread.parent;
        while let Some(node) = cursor {
            if let Some(post) = node.post {
                chain.push(ThreadPost {
                    author_did: post.author.did,
                    text: post.record.text,
                });
            }
            cursor = node.parent;
        }
        // Walk yields newest-first; reverse to oldest-first.
        chain.reverse();
        let start = chain.len().saturating_sub(MAX_RENDERED_THREAD_ANCESTORS);
        chain.split_off(start)
    }

    /// Fetches initial followed DIDs for an actor from the public AppView (XRPC `app.bsky.graph.getFollows`).
    ///
    /// Used for zero-credential cold-start hydration of the local follow graph.
    pub async fn fetch_follows(&self, actor: &str, limit: u8) -> Vec<String> {
        self.client.fetch_follows(actor, limit).await
    }

    /// Fetches initial incoming follower DIDs for an actor from the public AppView (XRPC `app.bsky.graph.getFollowers`).
    ///
    /// Used for zero-credential cold-start hydration of the local incoming follower graph.
    pub async fn fetch_followers(&self, actor: &str, limit: u8) -> Vec<String> {
        self.client.fetch_followers(actor, limit).await
    }

    /// Fetches follow records `(rkey, followed_did)` for an actor via `com.atproto.repo.listRecords`.
    ///
    /// Used for cold-start hydration of the local follow graph with real repository rkeys,
    /// enabling real-time unfollow reconciliation when `CommitOperation::Delete` arrives.
    pub async fn fetch_follow_records(&self, actor: &str, limit: u8) -> Vec<(String, String)> {
        self.client.fetch_follow_records(actor, limit).await
    }

    /// Resolves an ATProto handle to a DID via XRPC `com.atproto.identity.resolveHandle`.
    pub async fn resolve_handle(&self, handle: &str) -> Option<String> {
        self.client.resolve_handle(handle).await
    }

    /// Fetches an image thumbnail from the Bluesky CDN and encodes it as base64.
    pub async fn fetch_image_base64(&self, author_did: &str, cid: &str) -> Option<String> {
        let clean_did: String = author_did
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ':' || *c == '.' || *c == '-' || *c == '_')
            .collect();
        let clean_cid: String = cid
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .collect();
        if clean_did.is_empty() || clean_cid.is_empty() {
            return None;
        }

        let url = self.client.thumbnail_url(&clean_did, &clean_cid);
        let resp = self.client.http_client().get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }

        use futures_util::StreamExt;
        let mut stream = resp.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res.ok()?;
            if bytes.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
                return None;
            }
            bytes.extend_from_slice(&chunk);
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
                let trimmed = crate::util::normalize_handle(&h).to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }

        // 2. Fallback to PLC directory if did:plc:...
        if clean.starts_with("did:plc:") {
            let clean_plc: String = clean
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ':')
                .collect();
            let plc_url = format!("https://plc.directory/{clean_plc}");
            if let Ok(resp) = self.client.http_client().get(&plc_url).send().await {
                if resp.status().is_success() {
                    #[derive(Deserialize)]
                    struct PlcDoc {
                        #[serde(rename = "alsoKnownAs", default)]
                        also_known_as: Vec<String>,
                    }
                    if let Ok(doc) = resp.json::<PlcDoc>().await {
                        for alias in doc.also_known_as {
                            if let Some(handle) = alias.strip_prefix("at://") {
                                let trimmed = crate::util::normalize_handle(handle).to_string();
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
        let thread_fut = async {
            match (self.thread_context, interaction.parent_uri.as_ref()) {
                (true, Some(uri)) => self.fetch_thread_ancestors(uri).await,
                _ => Vec::new(),
            }
        };

        let (author, parent_post, images_base64, thread_ancestors) =
            tokio::join!(author_fut, parent_fut, images_fut, thread_fut);

        EnrichedContext {
            author,
            parent_post,
            thread_ancestors,
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
