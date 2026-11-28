//! Live AppView HTTP and CDN context enricher implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt;
use parking_lot::RwLock;
use serde::Deserialize;

use crate::enricher::fundraiser::{
    extract_fundraiser_urls_from_text, extract_urls_from_embed_obj, extract_urls_from_record_obj,
    push_unique_fundraiser_url,
};
use crate::enricher::timing::{
    compute_reply_timing_signals, parse_iso8601_utc_secs, TID_TIMESTAMP_MIN_US,
};
use crate::enricher::{
    collect_non_empty_alts, AuthorActivitySignals, AuthorContext, ContextEnricher, ContextImageRef,
    EnrichedContext, ParentPostContext, PostEmbedSummary, QuotedAncestor, ThreadPost,
    AUTHOR_FEED_RECENT_LIMIT, AUTHOR_FEED_TOP_LIMIT, DEFAULT_APPVIEW_ENDPOINT,
    DEFAULT_CDN_ENDPOINT, MAX_CONTEXT_IMAGES, MAX_DISPLAY_NAME_CHARS, MAX_OTHER_REPLY_SNIPPETS,
    MAX_POST_IMAGES, MAX_RENDERED_THREAD_ANCESTORS, REPLY_BLAST_WINDOW_SECS,
};
use crate::matcher::Interaction;

/// Maximum number of protected target profiles cached in memory by [`AppViewContextEnricher`].
const MAX_TARGET_PROFILE_CACHE_ENTRIES: usize = 1024;

/// Time-to-live for cached protected target profiles (20 minutes).
pub(crate) const TARGET_PROFILE_CACHE_TTL: Duration = Duration::from_secs(20 * 60);

/// Maximum number of additional `getPostThread` hops performed when a conversation thread
/// crosses a `blockedPost` boundary (e.g. a previously bounced troll higher up in the thread).
const MAX_BLOCKED_THREAD_HOPS: usize = 3;

/// Per-image CDN download size limit (2 MiB).
const MAX_CDN_IMAGE_BYTES: usize = 2 * 1024 * 1024;

/// Aggregate CDN download byte budget across all images in a single post (6 MiB).
pub(crate) const MAX_CDN_BATCH_IMAGE_BYTES: usize = 6 * 1024 * 1024;

/// Maximum concurrent CDN image downloads per post.
const CDN_IMAGE_CONCURRENCY: usize = 4;

#[derive(Debug, Default)]
struct ExtractedMedia {
    image_count: usize,
    image_alts: Vec<String>,
    external_title: Option<String>,
    external_description: Option<String>,
    image_refs: Vec<ContextImageRef>,
}

#[derive(Debug, Default)]
struct ThreadFetchResult {
    ancestors: Vec<ThreadPost>,
    quotes: Vec<Option<QuotedAncestor>>,
    embeds: Vec<Option<PostEmbedSummary>>,
    context_image_refs: Vec<ContextImageRef>,
    focal_post: Option<ParentPostContext>,
}

struct BudgetGuard {
    used: Arc<AtomicUsize>,
    reserved: usize,
}

impl BudgetGuard {
    fn new(used: Arc<AtomicUsize>) -> Self {
        Self { used, reserved: 0 }
    }

    fn try_reserve(&mut self, amount: usize, max_total: usize) -> bool {
        loop {
            let cur = self.used.load(Ordering::SeqCst);
            let Some(next) = cur.checked_add(amount).filter(|&n| n <= max_total) else {
                return false;
            };
            if self
                .used
                .compare_exchange_weak(cur, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.reserved = self.reserved.saturating_add(amount);
                return true;
            }
        }
    }

    fn commit(mut self) {
        self.reserved = 0;
    }
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        if self.reserved > 0 {
            self.used.fetch_sub(self.reserved, Ordering::SeqCst);
        }
    }
}

/// Validates an author DID before interpolating it into a Bluesky CDN path.
///
/// Rejects path traversal (`..`, `.` segments), `/`, `\`, `?`, `#`, `%`, whitespace,
/// control characters, and non-ASCII bytes.
pub(crate) fn is_valid_cdn_did(did: &str) -> bool {
    if !did.is_ascii() || !did.starts_with("did:") || did.contains("..") {
        return false;
    }
    if did.bytes().any(|b| {
        b.is_ascii_control()
            || b.is_ascii_whitespace()
            || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'%')
    }) {
        return false;
    }
    let mut segments = did.split(':');
    let Some("did") = segments.next() else {
        return false;
    };
    let Some(method) = segments.next() else {
        return false;
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return false;
    }
    let rest: Vec<&str> = segments.collect();
    !rest.is_empty()
        && rest
            .iter()
            .all(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
}

/// Validates an image blob CID before interpolating it into a Bluesky CDN path.
///
/// Requires non-empty ASCII alphanumeric / `-` / `_` characters only (rejecting `.`, `..`, `/`, `%`, etc.).
pub(crate) fn is_valid_cdn_cid(cid: &str) -> bool {
    !cid.is_empty()
        && cid.len() <= 256
        && cid.is_ascii()
        && cid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Validates that downloaded bytes match JPEG, PNG, GIF, or WebP magic-byte signatures.
pub(crate) fn is_valid_image_magic_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        || bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
        || bytes.starts_with(b"GIF87a")
        || bytes.starts_with(b"GIF89a")
        || (bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
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
    author_feed_context: bool,
    target_cache: Arc<RwLock<HashMap<String, (AuthorContext, Instant)>>>,
    identity_resolver: skyauth::identity::IdentityResolver,
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
    /// enabling full conversation-thread ancestor and author-feed signal resolution by default
    /// (controlled via `THREAD_CONTEXT` / `SKYBOUNCER_THREAD_CONTEXT` and
    /// `AUTHOR_FEED_CONTEXT` / `SKYBOUNCER_AUTHOR_FEED_CONTEXT`).
    #[must_use]
    pub fn from_env() -> Self {
        let endpoint = crate::env::var_or(
            &["APPVIEW_ENDPOINT", "SKYBOUNCER_APPVIEW_ENDPOINT"],
            DEFAULT_APPVIEW_ENDPOINT,
        );
        let thread_context =
            crate::env::bool_or(&["THREAD_CONTEXT", "SKYBOUNCER_THREAD_CONTEXT"], true);
        let author_feed_context = crate::env::bool_or(
            &["AUTHOR_FEED_CONTEXT", "SKYBOUNCER_AUTHOR_FEED_CONTEXT"],
            true,
        );
        Self::with_endpoint(endpoint)
            .with_thread_context(thread_context)
            .with_author_feed_context(author_feed_context)
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
            author_feed_context: false,
            target_cache: Arc::new(RwLock::new(HashMap::new())),
            identity_resolver: skyauth::identity::IdentityResolver::new(
                skyauth::ssrf::SsrfFilter::default(),
            ),
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

    /// Enables or disables bounded `app.bsky.feed.getAuthorFeed` behavioral signal extraction
    /// (fundraiser funnels, stranger reply blasts, repeated templates) during [`ContextEnricher::enrich`].
    #[must_use]
    pub fn with_author_feed_context(mut self, enabled: bool) -> Self {
        self.author_feed_context = enabled;
        self
    }

    /// Returns whether `getAuthorFeed` behavioral signal enrichment is enabled.
    #[must_use]
    pub fn author_feed_context_enabled(&self) -> bool {
        self.author_feed_context
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

    /// Backdates a cached `target_cache` entry timestamp (test helper).
    #[cfg(test)]
    pub(crate) fn set_target_cache_age_for_test(&self, did: &str, age: Duration) {
        if let Some((_, cached_at)) = self.target_cache.write().get_mut(did) {
            *cached_at = Instant::now() - age;
        }
    }

    /// Fetches author profile metadata from the AppView.
    async fn fetch_author_profile(&self, did: &str) -> Option<AuthorContext> {
        let profile = self.client.fetch_profile(did).await?;
        Some(AuthorContext {
            handle: profile.handle,
            display_name: profile
                .display_name
                .map(|s| s.chars().take(MAX_DISPLAY_NAME_CHARS).collect()),
            description: profile.description,
            followers_count: profile.followers_count,
            follows_count: profile.follows_count,
            created_at: profile.created_at,
        })
    }

    /// Fetches and caches protected target profile metadata from the AppView (20-minute TTL).
    ///
    /// Verifies that the returned profile DID matches `did` so unparameterized test mocks
    /// returning another actor's profile do not misattribute identity.
    async fn fetch_target_profile(&self, did: &str) -> Option<AuthorContext> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }
        let now = Instant::now();
        {
            if let Some((cached, cached_at)) = self.target_cache.read().get(clean) {
                if now.saturating_duration_since(*cached_at) < TARGET_PROFILE_CACHE_TTL {
                    return Some(cached.clone());
                }
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
            display_name: resp
                .display_name
                .map(|s| s.chars().take(MAX_DISPLAY_NAME_CHARS).collect()),
            description: resp.description,
            followers_count: resp.followers_count,
            follows_count: resp.follows_count,
            created_at: resp.created_at,
        };
        if ctx.handle.is_none() && ctx.display_name.is_none() {
            return None;
        }

        {
            let insert_now = Instant::now();
            let mut cache = self.target_cache.write();
            if cache.len() >= MAX_TARGET_PROFILE_CACHE_ENTRIES && !cache.contains_key(clean) {
                cache.retain(|_, (_, ts)| {
                    insert_now.saturating_duration_since(*ts) < TARGET_PROFILE_CACHE_TTL
                });
                if cache.len() >= MAX_TARGET_PROFILE_CACHE_ENTRIES {
                    cache.clear();
                }
            }
            cache.insert(clean.to_string(), (ctx.clone(), insert_now));
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

    /// Extracts the `app.bsky.embed.record#viewRecord` payload from a post `embed` view object.
    fn extract_view_record(embed: &serde_json::Value) -> Option<&serde_json::Value> {
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
        Some(record)
    }

    /// Extracts an embedded quote-post summary from a `getPostThread` post `embed` object.
    fn extract_ancestor_quote(embed: &serde_json::Value) -> Option<QuotedAncestor> {
        let record = Self::extract_view_record(embed)?;
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

    fn trimmed_non_empty(val: Option<&str>) -> Option<String> {
        val.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    fn parse_cdn_plain_ref(url: &str) -> Option<ContextImageRef> {
        let (_, rest) = url.split_once("/plain/")?;
        let (did_raw, cid_part) = rest.split_once('/')?;
        let did = did_raw.trim();
        if !is_valid_cdn_did(did) {
            return None;
        }
        let cid = cid_part.split(['@', '?', '#', '/']).next()?.trim();
        if !is_valid_cdn_cid(cid) {
            return None;
        }
        Some(ContextImageRef {
            author_did: did.to_string(),
            cid: cid.to_string(),
        })
    }

    fn extract_media_node(author_did: &str, embed: &serde_json::Value) -> ExtractedMedia {
        let embed_type = embed.get("$type").and_then(|v| v.as_str()).unwrap_or("");
        let media = match embed_type {
            "app.bsky.embed.recordWithMedia" | "app.bsky.embed.recordWithMedia#view" => {
                let Some(m) = embed.get("media") else {
                    return ExtractedMedia::default();
                };
                m
            }
            _ => embed,
        };
        let media_type = media.get("$type").and_then(|v| v.as_str()).unwrap_or("");
        let mut out = ExtractedMedia::default();

        let extract_items = |arr: &[serde_json::Value],
                             out: &mut ExtractedMedia,
                             blob_key: &str| {
            for item in arr {
                out.image_count += 1;
                if let Some(alt) = Self::trimmed_non_empty(item.get("alt").and_then(|v| v.as_str()))
                {
                    out.image_alts.push(alt);
                }
                let raw_cid = item
                    .get(blob_key)
                    .or_else(|| item.get("image"))
                    .and_then(|img| img.get("ref"))
                    .and_then(|r| r.get("$link"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| Self::trimmed_non_empty(Some(s)));
                if let Some(cid) = raw_cid {
                    if is_valid_cdn_did(author_did) && is_valid_cdn_cid(&cid) {
                        out.image_refs.push(ContextImageRef {
                            author_did: author_did.to_string(),
                            cid,
                        });
                    }
                } else {
                    let cdn_ref = item
                        .get("thumb")
                        .and_then(|v| v.as_str())
                        .and_then(Self::parse_cdn_plain_ref)
                        .or_else(|| {
                            item.get("fullsize")
                                .and_then(|v| v.as_str())
                                .and_then(Self::parse_cdn_plain_ref)
                        });
                    if let Some(cref) = cdn_ref {
                        out.image_refs.push(cref);
                    }
                }
            }
        };

        if matches!(
            media_type,
            "app.bsky.embed.images" | "app.bsky.embed.images#view"
        ) || (media_type.is_empty() && media.get("images").is_some())
        {
            if let Some(arr) = media.get("images").and_then(|v| v.as_array()) {
                extract_items(arr, &mut out, "image");
            }
        } else if matches!(
            media_type,
            "app.bsky.embed.gallery" | "app.bsky.embed.gallery#view"
        ) || (media_type.is_empty() && media.get("items").is_some())
        {
            if let Some(arr) = media.get("items").and_then(|v| v.as_array()) {
                extract_items(arr, &mut out, "item");
            }
        } else if matches!(
            media_type,
            "app.bsky.embed.external" | "app.bsky.embed.external#view"
        ) || (media_type.is_empty() && media.get("external").is_some())
        {
            if let Some(ext) = media.get("external") {
                out.external_title =
                    Self::trimmed_non_empty(ext.get("title").and_then(|v| v.as_str()));
                out.external_description =
                    Self::trimmed_non_empty(ext.get("description").and_then(|v| v.as_str()));
            }
        }

        out
    }

    fn merge_raw_and_views(
        author_did: &str,
        raw_embed: Option<&serde_json::Value>,
        view_embeds: &[&serde_json::Value],
    ) -> ExtractedMedia {
        let raw = raw_embed
            .map(|e| Self::extract_media_node(author_did, e))
            .unwrap_or_default();
        let mut combined_view = ExtractedMedia::default();
        for v in view_embeds {
            let extracted = Self::extract_media_node(author_did, v);
            if extracted.image_count > combined_view.image_count {
                combined_view.image_count = extracted.image_count;
                if !extracted.image_alts.is_empty() {
                    combined_view.image_alts = extracted.image_alts;
                }
                if !extracted.image_refs.is_empty() {
                    combined_view.image_refs = extracted.image_refs;
                }
            } else {
                if combined_view.image_alts.is_empty() && !extracted.image_alts.is_empty() {
                    combined_view.image_alts = extracted.image_alts;
                }
                if combined_view.image_refs.is_empty() && !extracted.image_refs.is_empty() {
                    combined_view.image_refs = extracted.image_refs;
                }
            }
            if combined_view.external_title.is_none() {
                combined_view.external_title = extracted.external_title;
            }
            if combined_view.external_description.is_none() {
                combined_view.external_description = extracted.external_description;
            }
        }

        ExtractedMedia {
            image_count: raw.image_count.max(combined_view.image_count),
            image_alts: if !raw.image_alts.is_empty() {
                raw.image_alts
            } else {
                combined_view.image_alts
            },
            external_title: combined_view.external_title.or(raw.external_title),
            external_description: combined_view
                .external_description
                .or(raw.external_description),
            image_refs: if !raw.image_refs.is_empty() {
                raw.image_refs
            } else {
                combined_view.image_refs
            },
        }
    }

    fn extract_post_embed_and_refs(
        author_did: &str,
        raw_embed: Option<&serde_json::Value>,
        view_embed: Option<&serde_json::Value>,
    ) -> (Option<PostEmbedSummary>, Vec<ContextImageRef>) {
        let view_slice: Vec<&serde_json::Value> = view_embed.into_iter().collect();
        let own = Self::merge_raw_and_views(author_did, raw_embed, &view_slice);

        let quoted = if let Some(view_rec) = view_embed.and_then(Self::extract_view_record) {
            let quoted_author = view_rec
                .get("author")
                .and_then(|a| a.get("did"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let q_raw = view_rec.get("value").and_then(|v| v.get("embed"));
            let q_views: Vec<&serde_json::Value> = view_rec
                .get("embeds")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().collect())
                .unwrap_or_default();
            Self::merge_raw_and_views(quoted_author, q_raw, &q_views)
        } else {
            ExtractedMedia::default()
        };

        let summary = PostEmbedSummary {
            image_count: own.image_count,
            image_alts: own.image_alts,
            external_title: own.external_title,
            external_description: own.external_description,
            quoted_image_count: quoted.image_count,
            quoted_image_alts: quoted.image_alts,
            quoted_external_title: quoted.external_title,
            quoted_external_description: quoted.external_description,
        };

        let mut refs = Vec::new();
        for r in own.image_refs.into_iter().chain(quoted.image_refs) {
            if !refs.contains(&r) {
                refs.push(r);
                if refs.len() >= MAX_CONTEXT_IMAGES {
                    break;
                }
            }
        }

        ((!summary.is_empty()).then_some(summary), refs)
    }

    /// Resolves the full ancestor chain above `uri` via `app.bsky.feed.getPostThread`
    /// with `depth = 0` and `parentHeight = 12`, returning posts ordered oldest (thread root)
    /// to newest (immediate parent). Caps the chain at [`MAX_RENDERED_THREAD_ANCESTORS`].
    ///
    /// Returns an empty vector on any AppView failure.
    pub async fn fetch_thread_ancestors(&self, uri: &str) -> Vec<ThreadPost> {
        self.fetch_thread_chain_with_quotes(uri, false, "", "")
            .await
            .ancestors
    }

    /// Resolves the conversation thread anchored at `parent_uri`, including `parent_uri`
    /// itself as the newest ancestor (along with its `cid`, embedded quoted posts, and embed
    /// metadata) when `getPostThread` returns the parent post as the focal `thread.post` node.
    async fn fetch_thread_from_parent(
        &self,
        parent_uri: &str,
        candidate_author_did: &str,
        candidate_text: &str,
    ) -> ThreadFetchResult {
        self.fetch_thread_chain_with_quotes(parent_uri, true, candidate_author_did, candidate_text)
            .await
    }

    async fn fetch_thread_chain_with_quotes(
        &self,
        uri: &str,
        include_focal_when_parent: bool,
        candidate_author_did: &str,
        candidate_text: &str,
    ) -> ThreadFetchResult {
        #[derive(Deserialize)]
        struct RawAuthor {
            did: String,
        }
        #[derive(Deserialize)]
        struct RawRecord {
            #[serde(default)]
            text: String,
            #[serde(default)]
            embed: Option<serde_json::Value>,
        }
        #[derive(Deserialize)]
        struct RawPost {
            #[serde(default)]
            uri: Option<String>,
            #[serde(default)]
            cid: Option<String>,
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
        let mut embeds = Vec::new();
        let mut post_image_refs: Vec<Vec<ContextImageRef>> = Vec::new();
        let mut focal_post: Option<ParentPostContext> = None;
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
                    &[
                        ("uri", query_uri.clone()),
                        ("depth", "0".to_string()),
                        ("parentHeight", "12".to_string()),
                    ],
                )
                .await;

            let Ok(r) = resp else {
                break;
            };
            let thread = r.thread;

            let first_hop = is_first_hop;
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
                        if first_hop && focal_post.is_none() {
                            focal_post = Some(ParentPostContext {
                                author_did: focal.author.did.clone(),
                                text: focal.record.text.clone(),
                                cid: focal.cid.clone(),
                            });
                        }
                        let quote = focal.embed.as_ref().and_then(Self::extract_ancestor_quote);
                        let (embed_summary, refs) = Self::extract_post_embed_and_refs(
                            &focal.author.did,
                            focal.record.embed.as_ref(),
                            focal.embed.as_ref(),
                        );
                        quotes.push(quote);
                        embeds.push(embed_summary);
                        post_image_refs.push(refs);
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
                    let quote = post.embed.as_ref().and_then(Self::extract_ancestor_quote);
                    let (embed_summary, refs) = Self::extract_post_embed_and_refs(
                        &post.author.did,
                        post.record.embed.as_ref(),
                        post.embed.as_ref(),
                    );
                    quotes.push(quote);
                    embeds.push(embed_summary);
                    post_image_refs.push(refs);
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
        embeds.reverse();
        post_image_refs.reverse();
        let start = chain.len().saturating_sub(MAX_RENDERED_THREAD_ANCESTORS);
        let ancestors = chain.split_off(start);
        let mut trimmed_quotes = quotes.split_off(start);
        if trimmed_quotes.iter().all(Option::is_none) {
            trimmed_quotes.clear();
        }
        let mut trimmed_embeds = embeds.split_off(start);
        if trimmed_embeds.iter().all(Option::is_none) {
            trimmed_embeds.clear();
        }
        let context_image_refs = post_image_refs.pop().unwrap_or_default();
        ThreadFetchResult {
            ancestors,
            quotes: trimmed_quotes,
            embeds: trimmed_embeds,
            context_image_refs,
            focal_post,
        }
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

    async fn fetch_image_bytes(
        &self,
        author_did: &str,
        cid: &str,
        batch_used: Option<Arc<AtomicUsize>>,
    ) -> Option<Vec<u8>> {
        if !is_valid_cdn_did(author_did) || !is_valid_cdn_cid(cid) {
            return None;
        }

        let url = self.client.thumbnail_url(author_did, cid);
        let resp = self.client.http_client().get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }

        if let Some(ct_header) = resp.headers().get(reqwest::header::CONTENT_TYPE) {
            let ct = ct_header.to_str().ok()?;
            let media_type = ct.split(';').next().unwrap_or("").trim();
            if media_type.len() < 6 || !media_type[..6].eq_ignore_ascii_case("image/") {
                return None;
            }
        }

        let mut budget_guard = batch_used.map(BudgetGuard::new);
        let mut stream = resp.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res.ok()?;
            if bytes.len().saturating_add(chunk.len()) > MAX_CDN_IMAGE_BYTES {
                return None;
            }
            if let Some(ref mut guard) = budget_guard {
                if !guard.try_reserve(chunk.len(), MAX_CDN_BATCH_IMAGE_BYTES) {
                    return None;
                }
            }
            bytes.extend_from_slice(&chunk);
        }

        if !is_valid_image_magic_bytes(&bytes) {
            return None;
        }

        if let Some(guard) = budget_guard {
            guard.commit();
        }
        Some(bytes)
    }

    /// Fetches an image thumbnail from the Bluesky CDN and encodes it as base64.
    ///
    /// Enforces strict ASCII `did:`/`cid` path validation, `Content-Type: image/*` when present,
    /// a 2 MiB per-image cap, and JPEG/PNG/GIF/WebP magic-byte validation.
    pub async fn fetch_image_base64(&self, author_did: &str, cid: &str) -> Option<String> {
        let bytes = self.fetch_image_bytes(author_did, cid, None).await?;
        use base64::Engine;
        Some(base64::engine::general_purpose::STANDARD.encode(&bytes))
    }

    /// Fetches base64-encoded thumbnails concurrently (up to 4 in flight) for a set of image CIDs
    /// from the Bluesky CDN, enforcing [`MAX_POST_IMAGES`] (20) and an aggregate 6 MiB raw byte cap.
    pub async fn fetch_images_base64(&self, author_did: &str, cids: &[String]) -> Vec<String> {
        if !is_valid_cdn_did(author_did) {
            return Vec::new();
        }
        let batch_used = Arc::new(AtomicUsize::new(0));
        let items: Vec<(usize, String)> = cids
            .iter()
            .take(MAX_POST_IMAGES)
            .enumerate()
            .map(|(idx, cid)| (idx, cid.clone()))
            .collect();
        let mut indexed_bytes: Vec<(usize, Vec<u8>)> = futures_util::stream::iter(items)
            .map(|(idx, cid)| {
                let budget = Arc::clone(&batch_used);
                async move {
                    self.fetch_image_bytes(author_did, &cid, Some(budget))
                        .await
                        .map(|bytes| (idx, bytes))
                }
            })
            .buffer_unordered(CDN_IMAGE_CONCURRENCY)
            .filter_map(|opt| async move { opt })
            .collect()
            .await;

        indexed_bytes.sort_by_key(|(idx, _)| *idx);

        use base64::Engine;
        let mut total_bytes = 0usize;
        let mut results = Vec::with_capacity(indexed_bytes.len());
        for (_, bytes) in indexed_bytes {
            if total_bytes.saturating_add(bytes.len()) > MAX_CDN_BATCH_IMAGE_BYTES {
                break;
            }
            total_bytes = total_bytes.saturating_add(bytes.len());
            results.push(base64::engine::general_purpose::STANDARD.encode(&bytes));
        }
        results
    }

    /// Resolves an ATProto DID to a handle via profile lookup or bidirectionally verified PLC directory fallback.
    pub async fn resolve_did(&self, did: &str) -> Option<String> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }

        // 1. Try AppView actor profile (AppView validates handle ownership, marking invalid as "handle.invalid")
        if let Some(profile) = self.fetch_author_profile(clean).await {
            if let Some(h) = profile.handle {
                let trimmed = crate::util::normalize_handle(&h).to_ascii_lowercase();
                if !trimmed.is_empty() && trimmed != "handle.invalid" {
                    return Some(trimmed);
                }
            }
        }

        // 2. Fallback to DID document resolution via reusable IdentityResolver,
        //    requiring bidirectional handle -> DID verification before trusting `alsoKnownAs`.
        if let Ok(doc) = self.identity_resolver.resolve_did(clean).await {
            if let Some(handle) = doc.extract_primary_handle() {
                let trimmed = crate::util::normalize_handle(&handle).to_ascii_lowercase();
                if !trimmed.is_empty()
                    && trimmed != "handle.invalid"
                    && self.resolve_handle(&trimmed).await.as_deref() == Some(clean)
                {
                    return Some(trimmed);
                }
            }
        }

        None
    }

    /// Fetches batched engagement metadata for up to 25 AT-URIs per AppView `getPosts` request.
    pub async fn fetch_post_engagements(
        &self,
        uris: &[String],
    ) -> Vec<crate::dogpile::PostEngagementSnapshot> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RawAuthor {
            did: String,
            #[serde(default)]
            handle: Option<String>,
        }
        #[derive(Deserialize)]
        struct RawRecord {
            #[serde(default)]
            text: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RawPostView {
            uri: String,
            author: RawAuthor,
            #[serde(default)]
            record: serde_json::Value,
            #[serde(default)]
            reply_count: Option<u64>,
            #[serde(default)]
            repost_count: Option<u64>,
            #[serde(default)]
            like_count: Option<u64>,
            #[serde(default)]
            quote_count: Option<u64>,
        }
        #[derive(Deserialize)]
        struct RawPostsResp {
            #[serde(default)]
            posts: Vec<RawPostView>,
        }

        let mut results = Vec::new();
        let clean_uris: Vec<&str> = uris
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|s| s.starts_with("at://"))
            .collect();

        for chunk in clean_uris.chunks(25) {
            let query: Vec<(&str, String)> =
                chunk.iter().map(|u| ("uris", (*u).to_string())).collect();
            let Ok(resp) = self
                .client
                .get::<RawPostsResp>("app.bsky.feed.getPosts", &query)
                .await
            else {
                continue;
            };
            for p in resp.posts {
                let text = serde_json::from_value::<RawRecord>(p.record)
                    .ok()
                    .and_then(|r| r.text)
                    .unwrap_or_default();
                let author_handle = p
                    .author
                    .handle
                    .as_deref()
                    .map(crate::util::normalize_handle)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                results.push(crate::dogpile::PostEngagementSnapshot {
                    uri: p.uri,
                    author_did: p.author.did,
                    author_handle,
                    author_followers: None,
                    text,
                    reply_count: p.reply_count.unwrap_or(0),
                    repost_count: p.repost_count.unwrap_or(0),
                    like_count: p.like_count.unwrap_or(0),
                    quote_count: p.quote_count.unwrap_or(0),
                });
            }
        }
        results
    }

    /// Resolves an actor's follower count (`followersCount`), using non-expired cached target profiles first.
    pub async fn fetch_actor_followers_count(&self, did: &str) -> Option<u64> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }
        let now = Instant::now();
        if let Some((ctx, cached_at)) = self.target_cache.read().get(clean) {
            if now.saturating_duration_since(*cached_at) < TARGET_PROFILE_CACHE_TTL {
                if let Some(followers) = ctx.followers_count {
                    return Some(followers);
                }
            }
        }
        self.fetch_author_profile(clean)
            .await
            .and_then(|a| a.followers_count)
    }

    fn extract_fundraiser_urls_from_feed_item(item: &serde_json::Value) -> Vec<String> {
        let mut urls = Vec::new();
        let Some(post) = item.get("post") else {
            return urls;
        };
        if let Some(rec) = post.get("record") {
            extract_urls_from_record_obj(rec, &mut urls);
            if let Some(emb) = rec.get("embed") {
                extract_urls_from_embed_obj(emb, &mut urls);
            }
        }
        if let Some(emb) = post.get("embed") {
            extract_urls_from_embed_obj(emb, &mut urls);
            if let Some(view_rec) = Self::extract_view_record(emb) {
                if let Some(qval) = view_rec.get("value") {
                    extract_urls_from_record_obj(qval, &mut urls);
                    if let Some(qemb) = qval.get("embed") {
                        extract_urls_from_embed_obj(qemb, &mut urls);
                    }
                }
                if let Some(qembeds) = view_rec.get("embeds").and_then(|v| v.as_array()) {
                    for qemb in qembeds {
                        extract_urls_from_embed_obj(qemb, &mut urls);
                    }
                }
            }
        }
        urls
    }

    async fn fetch_author_feed(
        &self,
        actor: &str,
        filter: &str,
        limit: u8,
    ) -> Vec<serde_json::Value> {
        #[derive(Deserialize)]
        struct RawFeedResp {
            #[serde(default)]
            feed: Vec<serde_json::Value>,
        }
        self.client
            .get::<RawFeedResp>(
                "app.bsky.feed.getAuthorFeed",
                &[
                    ("actor", actor.to_string()),
                    ("filter", filter.to_string()),
                    ("limit", limit.to_string()),
                ],
            )
            .await
            .map_or_else(|_| Vec::new(), |r| r.feed)
    }

    async fn fetch_author_feed_signals(&self, interaction: &Interaction) -> AuthorActivitySignals {
        let mut signals = AuthorActivitySignals::default();
        if !self.author_feed_context || !interaction.author_did.starts_with("did:") {
            return signals;
        }
        let (top_feed, recent_feed) = tokio::join!(
            self.fetch_author_feed(
                &interaction.author_did,
                "posts_no_replies",
                AUTHOR_FEED_TOP_LIMIT
            ),
            self.fetch_author_feed(
                &interaction.author_did,
                "posts_with_replies",
                AUTHOR_FEED_RECENT_LIMIT
            ),
        );

        for item in &top_feed {
            let item_urls = Self::extract_fundraiser_urls_from_feed_item(item);
            if !item_urls.is_empty() {
                signals.profile_fundraiser_item_count += 1;
                for u in item_urls {
                    push_unique_fundraiser_url(&mut signals.profile_fundraiser_urls, &u);
                }
            }
        }

        struct ParsedReplyItem {
            target_did: String,
            ts_secs: Option<u64>,
            text: String,
            post_uri: String,
        }

        let mut parsed_replies = Vec::new();
        let mut template_counts: HashMap<String, usize> = HashMap::new();
        let mut max_ts_secs = if interaction.created_at_us >= TID_TIMESTAMP_MIN_US {
            interaction.created_at_us / 1_000_000
        } else {
            0
        };

        for item in &recent_feed {
            if item.get("reason").is_some_and(|v| !v.is_null()) {
                continue;
            }
            let Some(post) = item.get("post") else {
                continue;
            };
            if let Some(adid) = post
                .get("author")
                .and_then(|a| a.get("did"))
                .and_then(|v| v.as_str())
            {
                if adid != interaction.author_did {
                    continue;
                }
            }
            let Some(rec) = post.get("record") else {
                continue;
            };
            let Some(reply) = rec.get("reply").filter(|v| v.is_object()) else {
                continue;
            };
            let Some(parent_uri) = reply
                .get("parent")
                .and_then(|p| p.get("uri"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Some(target_did) = crate::matcher::extract_did_from_at_uri(parent_uri) else {
                continue;
            };
            // Exclude self-replies before counting repeated reply templates or bursts.
            if target_did == interaction.author_did {
                continue;
            }
            let text = rec
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if !text.is_empty() {
                let norm = text
                    .replace(['’', '‘'], "'")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_lowercase();
                *template_counts.entry(norm).or_insert(0) += 1;
            }
            let ts_secs = post
                .get("indexedAt")
                .and_then(|v| v.as_str())
                .and_then(parse_iso8601_utc_secs)
                .or_else(|| {
                    rec.get("createdAt")
                        .and_then(|v| v.as_str())
                        .and_then(parse_iso8601_utc_secs)
                });
            if let Some(ts) = ts_secs {
                max_ts_secs = max_ts_secs.max(ts);
            }
            let post_uri = post
                .get("uri")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            parsed_replies.push(ParsedReplyItem {
                target_did: target_did.to_string(),
                ts_secs,
                text,
                post_uri,
            });
        }

        signals.repeated_reply_template_count = template_counts
            .into_values()
            .filter(|&c| c >= 2)
            .max()
            .unwrap_or(0);

        let mut distinct_targets = std::collections::HashSet::new();
        for r in &parsed_replies {
            let in_window = r
                .ts_secs
                .is_some_and(|ts| max_ts_secs.saturating_sub(ts) <= REPLY_BLAST_WINDOW_SECS);
            if in_window {
                signals.recent_reply_burst_count += 1;
                distinct_targets.insert(r.target_did.as_str());
            }
            if r.post_uri != interaction.post_uri
                && r.target_did != interaction.target_did
                && !r.text.is_empty()
                && signals.recent_other_reply_snippets.len() < MAX_OTHER_REPLY_SNIPPETS
            {
                let snippet: String = r.text.chars().take(100).collect();
                if !signals.recent_other_reply_snippets.contains(&snippet) {
                    signals.recent_other_reply_snippets.push(snippet);
                }
            }
        }
        signals.recent_distinct_reply_targets = distinct_targets.len();
        signals
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
        let use_thread_for_parent = self.thread_context && interaction.parent_uri.is_some();
        let use_thread_for_standalone_quote = self.thread_context
            && interaction.parent_uri.is_none()
            && interaction.quote_uri.is_some();

        let author_fut = self.fetch_author_profile(&interaction.author_did);
        let target_fut = self.fetch_target_profile(&interaction.target_did);
        let parent_fut = async {
            if use_thread_for_parent {
                None
            } else if let Some(ref uri) = interaction.parent_uri {
                self.fetch_parent_post(uri).await
            } else {
                None
            }
        };
        let quoted_fut = async {
            if use_thread_for_standalone_quote {
                None
            } else if let Some(ref uri) = interaction.quote_uri {
                if use_thread_for_parent && interaction.parent_uri.as_deref() == Some(uri.as_str())
                {
                    None
                } else {
                    self.fetch_parent_post(uri).await
                }
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
            match (
                self.thread_context,
                interaction.parent_uri.as_deref(),
                interaction.quote_uri.as_deref(),
            ) {
                (true, Some(uri), _) => {
                    self.fetch_thread_from_parent(uri, &interaction.author_did, &interaction.text)
                        .await
                }
                (true, None, Some(quote_uri)) => {
                    let result = self
                        .fetch_thread_from_parent(
                            quote_uri,
                            &interaction.author_did,
                            &interaction.text,
                        )
                        .await;
                    let focal_post = result.focal_post.clone();
                    if result.ancestors.len() > 1
                        || !result.quotes.is_empty()
                        || !result.embeds.is_empty()
                        || !result.context_image_refs.is_empty()
                    {
                        result
                    } else {
                        ThreadFetchResult {
                            focal_post,
                            ..ThreadFetchResult::default()
                        }
                    }
                }
                _ => ThreadFetchResult::default(),
            }
        };

        let author_signals_fut = self.fetch_author_feed_signals(interaction);

        let (
            author,
            target,
            mut parent_post,
            mut quoted_post,
            images_base64,
            thread_res,
            mut author_signals,
        ) = tokio::join!(
            author_fut,
            target_fut,
            parent_fut,
            quoted_fut,
            images_fut,
            thread_fut,
            author_signals_fut
        );

        let derived_focal = thread_res.focal_post.or_else(|| {
            thread_res.ancestors.last().map(|a| ParentPostContext {
                author_did: a.author_did.clone(),
                text: a.text.clone(),
                cid: None,
            })
        });

        if use_thread_for_parent {
            parent_post = derived_focal;
            if quoted_post.is_none()
                && interaction.quote_uri.is_some()
                && interaction.quote_uri == interaction.parent_uri
            {
                quoted_post = parent_post.clone();
            }
        } else if use_thread_for_standalone_quote {
            quoted_post = derived_focal;
        }

        let (reply_latency_ms, forged_tid) = compute_reply_timing_signals(interaction);
        author_signals.reply_latency_ms = reply_latency_ms;
        author_signals.forged_tid = forged_tid;
        if let Some(desc) = author.as_ref().and_then(|a| a.description.as_deref()) {
            for u in extract_fundraiser_urls_from_text(desc) {
                push_unique_fundraiser_url(&mut author_signals.profile_fundraiser_urls, &u);
            }
        }
        if !author_signals.has_suspicious_bot_signals()
            && author_signals.profile_fundraiser_urls.is_empty()
        {
            author_signals.recent_other_reply_snippets.clear();
        }
        let author_signals = (!author_signals.is_empty()).then_some(author_signals);

        EnrichedContext {
            author,
            target,
            parent_post,
            quoted_post,
            thread_ancestors: thread_res.ancestors,
            thread_ancestor_quotes: thread_res.quotes,
            thread_ancestor_embeds: thread_res.embeds,
            images_base64,
            image_alts: collect_non_empty_alts(&interaction.image_alts),
            context_image_refs: thread_res.context_image_refs,
            context_images_base64: Vec::new(),
            author_signals,
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

    async fn fetch_post_engagements(
        &self,
        uris: &[String],
    ) -> Vec<crate::dogpile::PostEngagementSnapshot> {
        self.fetch_post_engagements(uris).await
    }

    async fn fetch_actor_followers_count(&self, did: &str) -> Option<u64> {
        self.fetch_actor_followers_count(did).await
    }
}
