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

/// Maximum number of attached post images fetched and inspected per interaction.
///
/// Matches the ATProto `app.bsky.embed.gallery` lexicon protocol ceiling (`maxLength: 20`),
/// accommodating both legacy 4-image embeds (`app.bsky.embed.images`) and multi-image
/// gallery posts (10-item UI limit, 20-item protocol max).
pub const MAX_POST_IMAGES: usize = 20;

/// Maximum number of protected target profiles cached in memory by [`AppViewContextEnricher`].
const MAX_TARGET_PROFILE_CACHE_ENTRIES: usize = 1024;

/// Maximum number of additional `getPostThread` hops performed when a conversation thread
/// crosses a `blockedPost` boundary (e.g. a previously bounced troll higher up in the thread).
const MAX_BLOCKED_THREAD_HOPS: usize = 3;

/// A single ancestor post resolved from the conversation thread above the candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ThreadPost {
    /// DID of the ancestor post author.
    pub author_did: String,
    /// Plaintext content of the ancestor post.
    pub text: String,
}

/// Embedded quoted post attached to a thread ancestor post.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct QuotedAncestor {
    /// DID of the quoted post's author.
    pub author_did: String,
    /// Normalized Bluesky handle of the quoted post's author, when present in the AppView record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_handle: Option<String>,
    /// Plaintext content of the quoted post.
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
    /// Resolved protected target user profile details (handle, display name, bio).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<AuthorContext>,
    /// Resolved parent post content and author.
    pub parent_post: Option<ParentPostContext>,
    /// Resolved quoted post content and author when the candidate embeds a quote (`app.bsky.embed.record`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_post: Option<ParentPostContext>,
    /// Ordered ancestor posts from oldest (thread root) to newest (immediate parent).
    ///
    /// Populated only when thread-context enrichment is enabled; empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thread_ancestors: Vec<ThreadPost>,
    /// Optional quoted post embeds corresponding by index to `thread_ancestors`.
    ///
    /// Empty when no thread ancestor embeds a readable quote post (including during
    /// mock enrichment or simple fixtures).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thread_ancestor_quotes: Vec<Option<QuotedAncestor>>,
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

    /// Returns `true` if no author, target, parent post, quoted post, thread ancestor, or image context was resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.author.is_none()
            && self.target.is_none()
            && self.parent_post.is_none()
            && self.quoted_post.is_none()
            && self.thread_ancestors.is_empty()
            && self.thread_ancestor_quotes.iter().all(Option::is_none)
            && self.images_base64.is_empty()
    }

    /// Formats the enriched context into a concise string block for classifier prompt injection.
    #[must_use]
    pub fn format_for_classifier(&self) -> String {
        self.format_internal(None)
    }

    /// Formats the enriched context with explicit speaker role labels (`Author`, `Target`,
    /// or `OtherUser`) on parent, quoted, and thread ancestor posts so downstream models can
    /// disambiguate multi-party conversations without matching opaque DIDs.
    #[must_use]
    pub fn format_for_interaction(&self, author_did: &str, target_did: &str) -> String {
        self.format_internal(Some((author_did, target_did)))
    }

    fn format_internal(&self, roles: Option<(&str, &str)>) -> String {
        let format_actor = |did: &str| match roles {
            Some((_, target_did)) if did == target_did => format!("Target ({did})"),
            Some((author_did, _)) if did == author_did => format!("Author ({did})"),
            Some(_) => format!("OtherUser ({did})"),
            None => did.to_string(),
        };

        let mut sections = Vec::new();

        if let Some(ref target) = self.target {
            let mut target_desc = Vec::new();
            if let Some(ref handle) = target.handle {
                target_desc.push(format!("handle: @{handle}"));
            }
            if let Some(ref name) = target.display_name {
                target_desc.push(format!("name: \"{name}\""));
            }
            if let Some(ref bio) = target.description {
                let bio_snippet: String = bio.chars().take(160).collect();
                if !bio_snippet.trim().is_empty() {
                    target_desc.push(format!("bio: \"{bio_snippet}\""));
                }
            }
            if !target_desc.is_empty() {
                sections.push(format!(
                    "Target Profile (protected user) [{}]",
                    target_desc.join(", ")
                ));
            }
        }

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
                    format_actor(&parent.author_did),
                    text_snippet
                ));
            }
        } else {
            let start = self
                .thread_ancestors
                .len()
                .saturating_sub(MAX_RENDERED_THREAD_ANCESTORS);
            let slice = &self.thread_ancestors[start..];
            let last_idx = slice.len().saturating_sub(1);
            let mut rendered = Vec::new();
            for (offset, ancestor) in slice.iter().enumerate() {
                let depth = start + offset + 1;
                let snippet: String = ancestor
                    .text
                    .chars()
                    .take(THREAD_ANCESTOR_CHAR_CAP)
                    .collect();
                let is_immediate_parent = roles.is_some()
                    && offset == last_idx
                    && self
                        .parent_post
                        .as_ref()
                        .is_none_or(|p| p.author_did == ancestor.author_did);
                let quote_suffix = match roles {
                    Some((author_did, target_did)) => self
                        .thread_ancestor_quotes
                        .get(start + offset)
                        .and_then(Option::as_ref)
                        .map(|q| {
                            let q_snippet: String = q.text.chars().take(160).collect();
                            let role = if q.author_did == target_did {
                                "Target"
                            } else if q.author_did == author_did {
                                "Author"
                            } else {
                                "OtherUser"
                            };
                            let actor = match q.author_handle.as_deref() {
                                Some(h) if !h.trim().is_empty() => format!(
                                    "{role} @{} ({})",
                                    crate::util::normalize_handle(h),
                                    q.author_did
                                ),
                                _ => format!("{role} ({})", q.author_did),
                            };
                            format!(" [quoting {actor}: \"{q_snippet}\"]")
                        })
                        .unwrap_or_default(),
                    None => String::new(),
                };
                if is_immediate_parent {
                    rendered.push(format!(
                        "[{depth}] {}: \"{}\"{quote_suffix} [IMMEDIATE PARENT — Author is replying to this post]",
                        format_actor(&ancestor.author_did),
                        snippet
                    ));
                } else {
                    rendered.push(format!(
                        "[{depth}] {}: \"{}\"{quote_suffix}",
                        format_actor(&ancestor.author_did),
                        snippet
                    ));
                }
            }
            sections.push(format!(
                "Conversation Thread (oldest → newest):\n{}",
                rendered.join("\n")
            ));
            if roles.is_some() {
                if let Some(ref parent) = self.parent_post {
                    if slice
                        .last()
                        .is_none_or(|last| last.author_did != parent.author_did)
                    {
                        let text_snippet: String = parent.text.chars().take(200).collect();
                        sections.push(format!(
                            "In Reply To (by {}): \"{}\"",
                            format_actor(&parent.author_did),
                            text_snippet
                        ));
                    }
                }
            }
        }

        if let Some(ref quoted) = self.quoted_post {
            let text_snippet: String = quoted.text.chars().take(300).collect();
            sections.push(format!(
                "Quoted Post (by {}): \"{}\"",
                format_actor(&quoted.author_did),
                text_snippet
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

    /// Queries the live follow relationship between `target_did` and `candidate_did` via
    /// `app.bsky.graph.getRelationships`, returning `(target_follows_candidate, candidate_follows_target)`.
    ///
    /// Used as a lazy fallback before invoking the AI classifier so followers missed by
    /// cold-start cursor pagination caps are discovered, cached in [`crate::matcher::FollowGraph`],
    /// and bypassed at zero model cost. Defaults to `(false, false)`.
    async fn check_relationship(&self, _target_did: &str, _candidate_did: &str) -> (bool, bool) {
        (false, false)
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

/// Mapping of `(target_did, candidate_did)` pairs to `(target_follows_candidate, candidate_follows_target)`.
type RelationshipMap = HashMap<(String, String), (bool, bool)>;

/// Mock context enricher for deterministic hermetic testing.
#[derive(Debug, Default, Clone)]
pub struct MockContextEnricher {
    authors: Arc<RwLock<HashMap<String, AuthorContext>>>,
    targets: Arc<RwLock<HashMap<String, AuthorContext>>>,
    parent_posts: Arc<RwLock<HashMap<String, ParentPostContext>>>,
    quoted_posts: Arc<RwLock<HashMap<String, ParentPostContext>>>,
    handles: Arc<RwLock<HashMap<String, String>>>,
    images: Arc<RwLock<HashMap<(String, String), String>>>,
    relationships: Arc<RwLock<RelationshipMap>>,
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

    /// Injects protected target profile metadata for a given DID.
    pub fn set_target(&self, did: impl Into<String>, target: AuthorContext) {
        self.targets.write().insert(did.into(), target);
    }

    /// Injects parent post context for a given AT-URI.
    pub fn set_parent_post(&self, uri: impl Into<String>, parent: ParentPostContext) {
        self.parent_posts.write().insert(uri.into(), parent);
    }

    /// Injects quoted post context for a given AT-URI.
    pub fn set_quoted_post(&self, uri: impl Into<String>, quoted: ParentPostContext) {
        self.quoted_posts.write().insert(uri.into(), quoted);
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

    /// Injects a mock `(target_follows_candidate, candidate_follows_target)` relationship
    /// for `(target_did, candidate_did)`.
    pub fn set_relationship(
        &self,
        target_did: impl Into<String>,
        candidate_did: impl Into<String>,
        target_follows_candidate: bool,
        candidate_follows_target: bool,
    ) {
        self.relationships.write().insert(
            (target_did.into(), candidate_did.into()),
            (target_follows_candidate, candidate_follows_target),
        );
    }
}

#[async_trait]
impl ContextEnricher for MockContextEnricher {
    async fn enrich(&self, interaction: &Interaction) -> EnrichedContext {
        let author = self.authors.read().get(&interaction.author_did).cloned();
        let target = self.targets.read().get(&interaction.target_did).cloned();
        let parent_post = interaction
            .parent_uri
            .as_ref()
            .and_then(|uri| self.parent_posts.read().get(uri).cloned());
        let quoted_post = interaction.quote_uri.as_ref().and_then(|uri| {
            self.quoted_posts
                .read()
                .get(uri)
                .cloned()
                .or_else(|| self.parent_posts.read().get(uri).cloned())
        });

        let mut images_base64 = Vec::new();
        {
            let guard = self.images.read();
            for cid in interaction.image_cids.iter().take(MAX_POST_IMAGES) {
                if let Some(b64) = guard.get(&(interaction.author_did.clone(), cid.clone())) {
                    images_base64.push(b64.clone());
                }
            }
        }

        EnrichedContext {
            author,
            target,
            parent_post,
            quoted_post,
            thread_ancestors: Vec::new(),
            thread_ancestor_quotes: Vec::new(),
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

    async fn check_relationship(&self, target_did: &str, candidate_did: &str) -> (bool, bool) {
        self.relationships
            .read()
            .get(&(target_did.to_string(), candidate_did.to_string()))
            .copied()
            .unwrap_or((false, false))
    }
}

/// AppView HTTP client resolving author profiles and parent posts via public XRPC endpoints.
///
/// Delegates all XRPC reads and cursor pagination to [`skybase::appview::AppViewClient`];
/// this type layers skybouncer's interaction-level enrichment (parallel author/target/parent/quote/image
/// fetch, cached target profiles, and thread ancestor resolution) and PLC-directory fallback on top.
#[derive(Debug, Clone)]
pub struct AppViewContextEnricher {
    client: skybase::appview::AppViewClient,
    thread_context: bool,
    target_cache: Arc<RwLock<HashMap<String, AuthorContext>>>,
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
    /// `SKYBOUNCER_APPVIEW_ENDPOINT` (falling back to [`DEFAULT_APPVIEW_ENDPOINT`]) and
    /// enabling full conversation-thread ancestor resolution by default (controlled via
    /// `THREAD_CONTEXT` / `SKYBOUNCER_THREAD_CONTEXT`).
    #[must_use]
    pub fn from_env() -> Self {
        let endpoint = crate::env::var_or(
            &["APPVIEW_ENDPOINT", "SKYBOUNCER_APPVIEW_ENDPOINT"],
            DEFAULT_APPVIEW_ENDPOINT,
        );
        let thread_context =
            crate::env::bool_or(&["THREAD_CONTEXT", "SKYBOUNCER_THREAD_CONTEXT"], true);
        Self::with_endpoint(endpoint).with_thread_context(thread_context)
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
            target_cache: Arc::new(RwLock::new(HashMap::new())),
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

    /// Fetches and caches protected target profile metadata from the AppView.
    ///
    /// Verifies that the returned profile DID matches `did` so unparameterized test mocks
    /// returning another actor's profile do not misattribute identity.
    async fn fetch_target_profile(&self, did: &str) -> Option<AuthorContext> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }
        {
            if let Some(cached) = self.target_cache.read().get(clean).cloned() {
                return Some(cached);
            }
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RawTargetProfile {
            #[serde(default)]
            did: Option<String>,
            #[serde(default)]
            handle: Option<String>,
            #[serde(default)]
            display_name: Option<String>,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            followers_count: Option<u64>,
            #[serde(default)]
            follows_count: Option<u64>,
            #[serde(default)]
            created_at: Option<String>,
        }

        let resp = self
            .client
            .get::<RawTargetProfile>("app.bsky.actor.getProfile", &[("actor", clean.to_string())])
            .await
            .ok()?;

        if resp.did.as_deref() != Some(clean) {
            return None;
        }

        let ctx = AuthorContext {
            handle: resp.handle,
            display_name: resp.display_name,
            description: resp.description,
            followers_count: resp.followers_count,
            follows_count: resp.follows_count,
            created_at: resp.created_at,
        };
        if ctx.handle.is_none() && ctx.display_name.is_none() {
            return None;
        }

        {
            let mut cache = self.target_cache.write();
            if cache.len() >= MAX_TARGET_PROFILE_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(clean.to_string(), ctx.clone());
        }
        Some(ctx)
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

    /// Extracts an embedded quote-post summary from a `getPostThread` post `embed` object.
    fn extract_ancestor_quote(embed: &serde_json::Value) -> Option<QuotedAncestor> {
        let embed_type = embed.get("$type").and_then(|v| v.as_str())?;
        let record = match embed_type {
            "app.bsky.embed.record#view" => embed.get("record")?,
            "app.bsky.embed.recordWithMedia#view" => embed.get("record")?.get("record")?,
            _ => return None,
        };
        if let Some(rec_type) = record.get("$type").and_then(|v| v.as_str()) {
            if rec_type != "app.bsky.embed.record#viewRecord" {
                return None;
            }
        }
        let author = record.get("author")?;
        let author_did = author
            .get("did")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())?
            .to_string();
        let author_handle = author
            .get("handle")
            .and_then(|v| v.as_str())
            .map(crate::util::normalize_handle)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let text = record
            .get("value")
            .and_then(|v| v.get("text"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Some(QuotedAncestor {
            author_did,
            author_handle,
            text,
        })
    }

    /// Resolves the full ancestor chain above `uri` via `app.bsky.feed.getPostThread`
    /// with `depth = 0`, returning posts ordered oldest (thread root) to newest
    /// (immediate parent). Caps the chain at [`MAX_RENDERED_THREAD_ANCESTORS`].
    ///
    /// Returns an empty vector on any AppView failure.
    pub async fn fetch_thread_ancestors(&self, uri: &str) -> Vec<ThreadPost> {
        self.fetch_thread_chain_with_quotes(uri, false, "", "")
            .await
            .0
    }

    /// Resolves the conversation thread anchored at `parent_uri`, including `parent_uri`
    /// itself as the newest ancestor (along with any embedded quoted posts) when `getPostThread`
    /// returns the parent post as the focal `thread.post` node (standard AppView behavior
    /// when querying by `parent_uri`).
    async fn fetch_thread_from_parent(
        &self,
        parent_uri: &str,
        candidate_author_did: &str,
        candidate_text: &str,
    ) -> (Vec<ThreadPost>, Vec<Option<QuotedAncestor>>) {
        self.fetch_thread_chain_with_quotes(parent_uri, true, candidate_author_did, candidate_text)
            .await
    }

    async fn fetch_thread_chain_with_quotes(
        &self,
        uri: &str,
        include_focal_when_parent: bool,
        candidate_author_did: &str,
        candidate_text: &str,
    ) -> (Vec<ThreadPost>, Vec<Option<QuotedAncestor>>) {
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
            #[serde(default)]
            uri: Option<String>,
            author: RawAuthor,
            record: RawRecord,
            #[serde(default)]
            embed: Option<serde_json::Value>,
        }
        #[derive(Deserialize)]
        struct RawThreadNode {
            #[serde(default)]
            uri: Option<String>,
            #[serde(default)]
            blocked: bool,
            #[serde(default)]
            parent: Option<Box<RawThreadNode>>,
            post: Option<RawPost>,
        }
        #[derive(Deserialize)]
        struct RawThreadResponse {
            thread: RawThreadNode,
        }

        let mut chain = Vec::new();
        let mut quotes = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut current_uri = Some(uri.to_string());
        let mut is_first_hop = true;
        let mut hops = 0usize;

        while let Some(query_uri) = current_uri.take() {
            if !visited.insert(query_uri.clone()) {
                break;
            }
            let resp = self
                .client
                .get::<RawThreadResponse>(
                    "app.bsky.feed.getPostThread",
                    &[("uri", query_uri.clone())],
                )
                .await;

            let Ok(r) = resp else {
                break;
            };
            let thread = r.thread;

            let include_focal = if is_first_hop {
                include_focal_when_parent
            } else {
                true
            };
            is_first_hop = false;

            if include_focal {
                if let Some(focal) = thread.post {
                    let is_ancestor = if hops > 0 {
                        true
                    } else {
                        match focal.uri.as_deref() {
                            Some(focal_uri) => focal_uri == query_uri,
                            None => {
                                !(focal.author.did == candidate_author_did
                                    && focal.record.text == candidate_text)
                            }
                        }
                    };
                    if is_ancestor {
                        quotes.push(focal.embed.as_ref().and_then(Self::extract_ancestor_quote));
                        chain.push(ThreadPost {
                            author_did: focal.author.did,
                            text: focal.record.text,
                        });
                    }
                }
            }

            let mut cursor = thread.parent;
            while let Some(node) = cursor {
                if let Some(post) = node.post {
                    quotes.push(post.embed.as_ref().and_then(Self::extract_ancestor_quote));
                    chain.push(ThreadPost {
                        author_did: post.author.did,
                        text: post.record.text,
                    });
                    cursor = node.parent;
                } else if node.blocked
                    && hops < MAX_BLOCKED_THREAD_HOPS
                    && chain.len() < MAX_RENDERED_THREAD_ANCESTORS
                {
                    if let Some(blocked_uri) = node.uri.filter(|u| !u.is_empty()) {
                        current_uri = Some(blocked_uri);
                        hops += 1;
                    }
                    break;
                } else {
                    cursor = node.parent;
                }
            }

            if chain.len() >= MAX_RENDERED_THREAD_ANCESTORS {
                break;
            }
        }

        // Walk yields newest-first; reverse to oldest-first.
        chain.reverse();
        quotes.reverse();
        let start = chain.len().saturating_sub(MAX_RENDERED_THREAD_ANCESTORS);
        let ancestors = chain.split_off(start);
        let mut trimmed_quotes = quotes.split_off(start);
        if trimmed_quotes.iter().all(Option::is_none) {
            trimmed_quotes.clear();
        }
        (ancestors, trimmed_quotes)
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

    /// Queries `app.bsky.graph.getRelationships` on the public AppView to check whether
    /// `target_did` follows `candidate_did` (`following`) or `candidate_did` follows
    /// `target_did` (`followedBy`).
    ///
    /// Degrades gracefully to `(false, false)` on network or decode failure.
    pub async fn fetch_relationship(&self, target_did: &str, candidate_did: &str) -> (bool, bool) {
        #[derive(Deserialize)]
        struct RelationshipItem {
            #[serde(default)]
            following: Option<String>,
            #[serde(default, rename = "followedBy")]
            followed_by: Option<String>,
        }
        #[derive(Deserialize)]
        struct RelationshipsResponse {
            #[serde(default)]
            relationships: Vec<RelationshipItem>,
        }

        let Ok(resp) = self
            .client
            .get::<RelationshipsResponse>(
                "app.bsky.graph.getRelationships",
                &[
                    ("actor", target_did.to_string()),
                    ("others", candidate_did.to_string()),
                ],
            )
            .await
        else {
            return (false, false);
        };

        let Some(rel) = resp.relationships.into_iter().next() else {
            return (false, false);
        };

        let is_following = rel.following.as_deref().is_some_and(|s| !s.is_empty());
        let is_followed_by = rel.followed_by.as_deref().is_some_and(|s| !s.is_empty());
        (is_following, is_followed_by)
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
    ///
    /// Caps retrieval at [`MAX_POST_IMAGES`] (20) to match the ATProto `app.bsky.embed.gallery`
    /// lexicon maximum.
    pub async fn fetch_images_base64(&self, author_did: &str, cids: &[String]) -> Vec<String> {
        let mut results = Vec::with_capacity(cids.len().min(MAX_POST_IMAGES));
        for cid in cids.iter().take(MAX_POST_IMAGES) {
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

        // 2. Fallback to DID document resolution via skyauth::identity::IdentityResolver
        let resolver =
            skyauth::identity::IdentityResolver::new(skyauth::ssrf::SsrfFilter::default());
        if let Ok(doc) = resolver.resolve_did(clean).await {
            if let Some(handle) = doc.extract_primary_handle() {
                let trimmed = crate::util::normalize_handle(&handle).to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
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
        let target_fut = self.fetch_target_profile(&interaction.target_did);
        let parent_fut = async {
            if let Some(ref uri) = interaction.parent_uri {
                self.fetch_parent_post(uri).await
            } else {
                None
            }
        };
        let quoted_fut = async {
            if let Some(ref uri) = interaction.quote_uri {
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
                (true, Some(uri)) => {
                    self.fetch_thread_from_parent(uri, &interaction.author_did, &interaction.text)
                        .await
                }
                _ => (Vec::new(), Vec::new()),
            }
        };

        let (
            author,
            target,
            parent_post,
            quoted_post,
            images_base64,
            (thread_ancestors, thread_ancestor_quotes),
        ) = tokio::join!(author_fut, target_fut, parent_fut, quoted_fut, images_fut, thread_fut);

        EnrichedContext {
            author,
            target,
            parent_post,
            quoted_post,
            thread_ancestors,
            thread_ancestor_quotes,
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

    async fn check_relationship(&self, target_did: &str, candidate_did: &str) -> (bool, bool) {
        self.fetch_relationship(target_did, candidate_did).await
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

    #[tokio::test]
    async fn test_mock_context_enricher_supports_up_to_max_post_images() {
        let enricher = MockContextEnricher::new();
        let mut cids = Vec::new();
        for idx in 0..25 {
            let cid = format!("bafkimg{idx}");
            enricher.set_image_base64("did:plc:author1", &cid, format!("b64_{idx}"));
            cids.push(cid);
        }

        let mut interaction = Interaction::mock_test_candidate(
            "did:plc:author1",
            "did:plc:target1",
            "Gallery post with >4 images",
        );
        interaction.image_cids = cids;

        let enriched = enricher.enrich(&interaction).await;
        assert_eq!(enriched.images_base64.len(), MAX_POST_IMAGES);
        assert_eq!(enriched.images_base64[0], "b64_0");
        assert_eq!(enriched.images_base64[MAX_POST_IMAGES - 1], "b64_19");
    }

    #[tokio::test]
    async fn test_appview_fetch_relationship_and_noop() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let noop = NoopContextEnricher;
        assert_eq!(
            noop.check_relationship("did:plc:a", "did:plc:b").await,
            (false, false)
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.graph.getRelationships"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "actor": "did:plc:alice",
                "relationships": [
                    {
                        "did": "did:plc:pelasgus",
                        "followedBy": "at://did:plc:pelasgus/app.bsky.graph.follow/3mxuft7ygur2n"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let enricher = AppViewContextEnricher::with_endpoint(server.uri());
        let (following, followed_by) = enricher
            .check_relationship("did:plc:alice", "did:plc:pelasgus")
            .await;
        assert!(!following);
        assert!(followed_by);
    }
}
