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

/// Default timeout in milliseconds for AppView profile and post enrichment queries.
pub const DEFAULT_ENRICHER_TIMEOUT_MS: u64 = 600;

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

/// Consolidated conversational and author context supplied to classifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct EnrichedContext {
    /// Resolved author profile details.
    pub author: Option<AuthorContext>,
    /// Resolved parent post content and author.
    pub parent_post: Option<ParentPostContext>,
}

impl EnrichedContext {
    /// Creates an empty context with no author or parent post details.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` if neither author nor parent post context was resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.author.is_none() && self.parent_post.is_none()
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
                let bio_snippet: String = bio.chars().take(120).collect();
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
}

#[async_trait]
impl ContextEnricher for MockContextEnricher {
    async fn enrich(&self, interaction: &Interaction) -> EnrichedContext {
        let author = self.authors.read().get(&interaction.author_did).cloned();
        let parent_post = interaction
            .parent_uri
            .as_ref()
            .and_then(|uri| self.parent_posts.read().get(uri).cloned());

        EnrichedContext {
            author,
            parent_post,
        }
    }

    async fn resolve_handle(&self, handle: &str) -> Option<String> {
        let clean = handle.trim().trim_start_matches('@');
        if clean.starts_with("did:") {
            return Some(clean.to_string());
        }
        self.handles.read().get(clean).cloned()
    }
}

/// AppView HTTP client resolving author profiles and parent posts via public XRPC endpoints.
#[derive(Debug, Clone)]
pub struct AppViewContextEnricher {
    appview_url: String,
    http_client: reqwest::Client,
}

impl AppViewContextEnricher {
    /// Creates a new [`AppViewContextEnricher`] targeting the default public AppView.
    #[must_use]
    pub fn new() -> Self {
        Self::with_endpoint(DEFAULT_APPVIEW_ENDPOINT)
    }

    /// Creates a new [`AppViewContextEnricher`] with a custom AppView endpoint.
    #[must_use]
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_millis(DEFAULT_ENRICHER_TIMEOUT_MS))
            .build()
            .unwrap_or_default();

        Self {
            appview_url: endpoint.into().trim_end_matches('/').to_string(),
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

        let (author, parent_post) = tokio::join!(author_fut, parent_fut);

        EnrichedContext {
            author,
            parent_post,
        }
    }

    async fn resolve_handle(&self, handle: &str) -> Option<String> {
        self.resolve_handle(handle).await
    }
}
