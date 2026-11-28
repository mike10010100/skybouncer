//! Context enricher querying author profile metadata and parent post conversation threads.
//!
//! Provides deeper conversational nuance (parent post context, author account age, bio)
//! to the downstream classifier engine, helping detect bad-faith sea-lioning and harassment.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::matcher::Interaction;

mod appview;
mod fundraiser;
mod mock;
mod timing;

pub use appview::AppViewContextEnricher;
pub use fundraiser::extract_fundraiser_urls_from_text;
pub use mock::MockContextEnricher;
pub use timing::{
    compute_reply_timing_signals, decode_tid_timestamp_us, extract_rkey_from_at_uri,
    parse_iso8601_utc_secs,
};

#[cfg(test)]
pub(crate) use appview::{is_valid_cdn_cid, is_valid_cdn_did, is_valid_image_magic_bytes};

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

/// Maximum number of parent or quoted context image thumbnails lazily fetched on System-2
/// escalation for visual disambiguation.
pub const MAX_CONTEXT_IMAGES: usize = 2;

/// Maximum character length enforced on untrusted actor display names in classifier prompts.
pub const MAX_DISPLAY_NAME_CHARS: usize = 80;

/// Reply-latency threshold in milliseconds below which a non-followed stranger reply
/// is treated as a sub-human automated firehose snipe.
pub const FAST_REPLY_LATENCY_MS: u64 = 2_500;

/// Maximum clock drift in seconds allowed between an ATProto TID `rkey` timestamp and
/// a commit timestamp before flagging the post as having a forged/backdated TID.
pub const FORGED_TID_DRIFT_SECS: u64 = 3_600;

/// Number of top non-reply items fetched from `app.bsky.feed.getAuthorFeed` (`posts_no_replies`)
/// to inspect pinned/reposted fundraiser funnels.
pub const AUTHOR_FEED_TOP_LIMIT: u8 = 5;

/// Number of recent items fetched from `app.bsky.feed.getAuthorFeed` (`posts_with_replies`)
/// to detect cross-thread stranger reply blasts and repeated plea templates.
pub const AUTHOR_FEED_RECENT_LIMIT: u8 = 10;

/// Rolling time window in seconds for counting cross-thread reply-blast bursts.
pub const REPLY_BLAST_WINDOW_SECS: u64 = 600;

/// Minimum distinct stranger targets replied to within [`REPLY_BLAST_WINDOW_SECS`] to
/// flag an automated cross-thread reply blast.
pub const REPLY_BLAST_MIN_DISTINCT_TARGETS: usize = 4;

/// Maximum normalized fundraiser/payment URLs retained in [`AuthorActivitySignals`].
pub const MAX_PROFILE_FUNDRAISER_URLS: usize = 3;

/// Maximum recent non-self reply snippets to other users retained in [`AuthorActivitySignals`].
pub const MAX_OTHER_REPLY_SNIPPETS: usize = 3;

/// Neutralizes prompt-injection boundary tags (`<untrusted_input`, `</untrusted_input`,
/// `<candidate_content`, `</candidate_content`, case-insensitive) by replacing `<` with `[`.
#[must_use]
pub(crate) fn strip_boundary_tags(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    let mut out = String::with_capacity(raw.len());
    let mut last = 0usize;
    let bytes = lower.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'/' {
                j += 1;
            }
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let tail = &lower[j..];
            if tail.starts_with("untrusted_input") || tail.starts_with("candidate_content") {
                out.push_str(&raw[last..i]);
                out.push('[');
                last = i + 1;
            }
        }
        i += 1;
    }
    out.push_str(&raw[last..]);
    out
}

/// Normalizes control characters/newlines, escapes double quotes, neutralizes prompt boundary tags,
/// and truncates an untrusted metadata field to `max_chars` Unicode scalar values.
#[must_use]
pub(crate) fn sanitize_untrusted_field(raw: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let normalized: String = raw
        .trim()
        .chars()
        .take(max_chars.saturating_mul(4).max(1024))
        .map(|ch| {
            if ch.is_control() {
                ' '
            } else if ch == '"' {
                '\''
            } else {
                ch
            }
        })
        .collect();
    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    let stripped = strip_boundary_tags(&collapsed);
    stripped.chars().take(max_chars).collect()
}

pub(super) fn collect_non_empty_alts(alts: &[String]) -> Vec<String> {
    alts.iter()
        .take(MAX_POST_IMAGES)
        .filter_map(|alt| {
            let trimmed = alt.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect()
}

/// Temporal, feed-funnel, and cross-thread behavioral signals derived for a candidate author.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct AuthorActivitySignals {
    /// Elapsed milliseconds between parent post TID creation and the candidate reply commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_latency_ms: Option<u64>,
    /// Whether the candidate post's TID `rkey` diverges more than [`FORGED_TID_DRIFT_SECS`] from commit time.
    #[serde(default)]
    pub forged_tid: bool,
    /// Normalized donation, crowdfunding, or payment URLs found in the author's bio, top posts, or 1-hop repost quotes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_fundraiser_urls: Vec<String>,
    /// Number of top author-feed items (pinned posts / reposts) carrying fundraiser URLs.
    #[serde(default)]
    pub profile_fundraiser_item_count: usize,
    /// Number of distinct external account DIDs replied to within [`REPLY_BLAST_WINDOW_SECS`].
    #[serde(default)]
    pub recent_distinct_reply_targets: usize,
    /// Total non-self replies posted within [`REPLY_BLAST_WINDOW_SECS`].
    #[serde(default)]
    pub recent_reply_burst_count: usize,
    /// Highest repetition count among identical normalized reply bodies across recent replies.
    #[serde(default)]
    pub repeated_reply_template_count: usize,
    /// Up to [`MAX_OTHER_REPLY_SNIPPETS`] distinct recent reply snippets sent to other users.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_other_reply_snippets: Vec<String>,
}

impl AuthorActivitySignals {
    /// Returns `true` when the reply was posted within [`FAST_REPLY_LATENCY_MS`] of its parent post.
    #[must_use]
    pub fn is_fast_snipe(&self) -> bool {
        self.reply_latency_ms
            .is_some_and(|ms| ms <= FAST_REPLY_LATENCY_MS)
    }

    /// Returns `true` when the author replied to at least [`REPLY_BLAST_MIN_DISTINCT_TARGETS`]
    /// distinct external accounts within [`REPLY_BLAST_WINDOW_SECS`].
    #[must_use]
    pub fn is_reply_blast(&self) -> bool {
        self.recent_distinct_reply_targets >= REPLY_BLAST_MIN_DISTINCT_TARGETS
    }

    /// Returns `true` when temporal, repetition, or combined funnel+burst signals indicate
    /// an automated reply-bait bot warranting System-2 contextual verification.
    ///
    /// Note: merely having fundraiser URLs on a profile/repost without sniping, forged TIDs,
    /// repeated templates, or multi-target reply bursts does **not** return `true`.
    #[must_use]
    pub fn has_suspicious_bot_signals(&self) -> bool {
        self.is_fast_snipe()
            || self.forged_tid
            || self.is_reply_blast()
            || self.repeated_reply_template_count >= 2
            || (!self.profile_fundraiser_urls.is_empty() && self.recent_distinct_reply_targets >= 2)
    }

    /// Returns `true` when no actionable timing, funnel, burst, or snippet signals are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.is_fast_snipe()
            && !self.forged_tid
            && self.profile_fundraiser_urls.is_empty()
            && !self.is_reply_blast()
            && self.repeated_reply_template_count < 2
            && self.recent_other_reply_snippets.is_empty()
    }

    /// Formats triggered behavioral signals as a single-line summary for classifier prompts.
    #[must_use]
    pub fn format_summary(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.is_fast_snipe() {
            if let Some(ms) = self.reply_latency_ms {
                parts.push(format!("sub-human reply latency: {ms}ms"));
            }
        }
        if self.forged_tid {
            parts.push("forged/backdated post TID rkey".to_string());
        }
        if !self.profile_fundraiser_urls.is_empty() {
            let urls: Vec<String> = self
                .profile_fundraiser_urls
                .iter()
                .map(|u| sanitize_untrusted_field(u, 200))
                .collect();
            parts.push(format!(
                "profile/repost fundraiser funnel ({} item(s)): {}",
                self.profile_fundraiser_item_count.max(1),
                urls.join(", ")
            ));
        }
        if self.is_reply_blast() {
            parts.push(format!(
                "rapid cross-thread reply blast: {} replies to {} distinct strangers within {}m",
                self.recent_reply_burst_count
                    .max(self.recent_distinct_reply_targets),
                self.recent_distinct_reply_targets,
                REPLY_BLAST_WINDOW_SECS / 60
            ));
        } else if !self.profile_fundraiser_urls.is_empty()
            && self.recent_distinct_reply_targets >= 2
        {
            parts.push(format!(
                "recent stranger replies: {} replies to {} distinct accounts within {}m",
                self.recent_reply_burst_count
                    .max(self.recent_distinct_reply_targets),
                self.recent_distinct_reply_targets,
                REPLY_BLAST_WINDOW_SECS / 60
            ));
        }
        if self.repeated_reply_template_count >= 2 {
            parts.push(format!(
                "repeated identical reply template x{}",
                self.repeated_reply_template_count
            ));
        }
        if !self.recent_other_reply_snippets.is_empty()
            && (self.has_suspicious_bot_signals() || !self.profile_fundraiser_urls.is_empty())
        {
            let quoted: Vec<String> = self
                .recent_other_reply_snippets
                .iter()
                .take(MAX_OTHER_REPLY_SNIPPETS)
                .map(|s| format!("\"{}\"", sanitize_untrusted_field(s, 200)))
                .collect();
            parts.push(format!("recent replies to others: {}", quoted.join("; ")));
        }
        (!parts.is_empty()).then(|| format!("Author Activity Signals [{}]", parts.join("; ")))
    }
}

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

/// Reference to a parent or quoted post's CDN image thumbnail eligible for lazy System-2
/// visual context inspection when Tier-1 escalates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ContextImageRef {
    /// DID of the post author hosting the blob (CDN path owner).
    pub author_did: String,
    /// Blob CID of the attached image.
    pub cid: String,
}

/// Non-text embed metadata (link cards, image alt text, media counts) extracted from a post
/// and its embedded quote record without extra network calls.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct PostEmbedSummary {
    /// Number of images attached directly to the post.
    #[serde(default)]
    pub image_count: usize,
    /// Non-empty alt-text strings on images attached directly to the post.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_alts: Vec<String>,
    /// External link-card title attached directly to the post.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_title: Option<String>,
    /// External link-card description attached directly to the post.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_description: Option<String>,
    /// Number of images attached to the post's embedded quoted post.
    #[serde(default)]
    pub quoted_image_count: usize,
    /// Non-empty alt-text strings on images inside the embedded quoted post.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quoted_image_alts: Vec<String>,
    /// External link-card title inside the embedded quoted post.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_external_title: Option<String>,
    /// External link-card description inside the embedded quoted post.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_external_description: Option<String>,
}

impl PostEmbedSummary {
    /// Returns `true` when neither the post nor its embedded quote carries link-card or image metadata.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.image_count == 0
            && self.image_alts.is_empty()
            && self.external_title.is_none()
            && self.external_description.is_none()
            && self.quoted_image_count == 0
            && self.quoted_image_alts.is_empty()
            && self.quoted_external_title.is_none()
            && self.quoted_external_description.is_none()
    }

    fn format_link_card(label: &str, title: Option<&str>, description: Option<&str>) -> String {
        let t = title
            .map(|s| sanitize_untrusted_field(s, 140))
            .filter(|s| !s.is_empty());
        let d = description
            .map(|s| sanitize_untrusted_field(s, 160))
            .filter(|s| !s.is_empty());
        match (t, d) {
            (Some(title), Some(desc)) => format!(" [{label}: \"{title}\" — \"{desc}\"]"),
            (Some(only), None) | (None, Some(only)) => format!(" [{label}: \"{only}\"]"),
            (None, None) => String::new(),
        }
    }

    fn format_image_summary(
        count: usize,
        alts: &[String],
        empty_tag: &str,
        alt_prefix: &str,
    ) -> String {
        if count == 0 {
            return String::new();
        }
        let capped_alts: Vec<String> = alts
            .iter()
            .map(|s| sanitize_untrusted_field(s, 160))
            .filter(|s| !s.is_empty())
            .collect();
        if capped_alts.is_empty() {
            format!(" [{empty_tag} (no alt text)]")
        } else {
            format!(
                " [{alt_prefix} {count} image(s); alt: \"{}\"]",
                capped_alts.join("; ")
            )
        }
    }

    /// Formats link-card and image metadata belonging directly to the ancestor post.
    #[must_use]
    pub(crate) fn format_post_media(&self) -> String {
        let card = Self::format_link_card(
            "link card",
            self.external_title.as_deref(),
            self.external_description.as_deref(),
        );
        let imgs = Self::format_image_summary(
            self.image_count,
            &self.image_alts,
            &format!("attached {} image(s)", self.image_count),
            "attached",
        );
        format!("{card}{imgs}")
    }

    /// Formats link-card and image metadata belonging to the ancestor post's embedded quote.
    #[must_use]
    pub(crate) fn format_quoted_media(&self) -> String {
        let card = Self::format_link_card(
            "quoted post link card",
            self.quoted_external_title.as_deref(),
            self.quoted_external_description.as_deref(),
        );
        let imgs = Self::format_image_summary(
            self.quoted_image_count,
            &self.quoted_image_alts,
            &format!(
                "quoted post has {} attached image(s)",
                self.quoted_image_count
            ),
            "quoted post attached",
        );
        format!("{card}{imgs}")
    }
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
    /// Non-empty alt-text captions attached to the candidate post's images.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_alts: Vec<String>,
    /// Optional non-text embed summaries corresponding by index to `thread_ancestors`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thread_ancestor_embeds: Vec<Option<PostEmbedSummary>>,
    /// Deduplicated CDN image references from the focal parent/quoted post for lazy System-2 inspection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_image_refs: Vec<ContextImageRef>,
    /// Base64-encoded parent/quoted context thumbnails hydrated only on System-2 escalation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_images_base64: Vec<String>,
    /// Temporal, feed-funnel, and cross-thread behavioral signals derived for the candidate author.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_signals: Option<AuthorActivitySignals>,
}

impl EnrichedContext {
    /// Creates an empty context with no author or parent post details.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` if no author, target, parent post, quoted post, thread ancestor, image, or author activity context was resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.author.is_none()
            && self.target.is_none()
            && self.parent_post.is_none()
            && self.quoted_post.is_none()
            && self.thread_ancestors.is_empty()
            && self.thread_ancestor_quotes.iter().all(Option::is_none)
            && self.thread_ancestor_embeds.iter().all(Option::is_none)
            && self.images_base64.is_empty()
            && self.image_alts.iter().all(|a| a.trim().is_empty())
            && self.context_image_refs.is_empty()
            && self.context_images_base64.is_empty()
            && self
                .author_signals
                .as_ref()
                .is_none_or(AuthorActivitySignals::is_empty)
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
                let clean_h = sanitize_untrusted_field(crate::util::normalize_handle(handle), 120);
                if !clean_h.is_empty() {
                    target_desc.push(format!("handle: @{clean_h}"));
                }
            }
            if let Some(ref name) = target.display_name {
                let clean_n = sanitize_untrusted_field(name, MAX_DISPLAY_NAME_CHARS);
                if !clean_n.is_empty() {
                    target_desc.push(format!("name: \"{clean_n}\""));
                }
            }
            if let Some(ref bio) = target.description {
                let bio_snippet = sanitize_untrusted_field(bio, 160);
                if !bio_snippet.is_empty() {
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
                let clean_h = sanitize_untrusted_field(crate::util::normalize_handle(handle), 120);
                if !clean_h.is_empty() {
                    author_desc.push(format!("handle: @{clean_h}"));
                }
            }
            if let Some(ref name) = author.display_name {
                let clean_n = sanitize_untrusted_field(name, MAX_DISPLAY_NAME_CHARS);
                if !clean_n.is_empty() {
                    author_desc.push(format!("name: \"{clean_n}\""));
                }
            }
            if let Some(ref bio) = author.description {
                let bio_snippet = sanitize_untrusted_field(bio, 250);
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
                let text_snippet = sanitize_untrusted_field(&parent.text, 200);
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
            let is_standalone_quote = self.parent_post.is_none() && self.quoted_post.is_some();
            let mut rendered = Vec::new();
            for (offset, ancestor) in slice.iter().enumerate() {
                let depth = start + offset + 1;
                let snippet = sanitize_untrusted_field(&ancestor.text, THREAD_ANCESTOR_CHAR_CAP);
                let is_immediate_parent = roles.is_some()
                    && !is_standalone_quote
                    && offset == last_idx
                    && self
                        .parent_post
                        .as_ref()
                        .is_none_or(|p| p.author_did == ancestor.author_did);
                let is_focal_quoted_post = roles.is_some()
                    && is_standalone_quote
                    && offset == last_idx
                    && self
                        .quoted_post
                        .as_ref()
                        .is_some_and(|q| q.author_did == ancestor.author_did);
                let quote_suffix = match roles {
                    Some((author_did, target_did)) => self
                        .thread_ancestor_quotes
                        .get(start + offset)
                        .and_then(Option::as_ref)
                        .map(|q| {
                            let q_snippet = sanitize_untrusted_field(&q.text, 160);
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
                                    sanitize_untrusted_field(crate::util::normalize_handle(h), 120),
                                    q.author_did
                                ),
                                _ => format!("{role} ({})", q.author_did),
                            };
                            format!(" [quoting {actor}: \"{q_snippet}\"]")
                        })
                        .unwrap_or_default(),
                    None => String::new(),
                };
                let embed_suffix = if roles.is_some() {
                    self.thread_ancestor_embeds
                        .get(start + offset)
                        .and_then(Option::as_ref)
                        .map(|s| format!("{}{}", s.format_post_media(), s.format_quoted_media()))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                if is_immediate_parent {
                    rendered.push(format!(
                        "[{depth}] {}: \"{}\"{quote_suffix}{embed_suffix} [IMMEDIATE PARENT — Author is replying to this post]",
                        format_actor(&ancestor.author_did),
                        snippet
                    ));
                } else if is_focal_quoted_post {
                    rendered.push(format!(
                        "[{depth}] {}: \"{}\"{quote_suffix}{embed_suffix} [QUOTED POST — Author is quote-posting this post]",
                        format_actor(&ancestor.author_did),
                        snippet
                    ));
                } else {
                    rendered.push(format!(
                        "[{depth}] {}: \"{}\"{quote_suffix}{embed_suffix}",
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
                        let text_snippet = sanitize_untrusted_field(&parent.text, 200);
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
            let text_snippet = sanitize_untrusted_field(&quoted.text, 300);
            sections.push(format!(
                "Quoted Post (by {}): \"{}\"",
                format_actor(&quoted.author_did),
                text_snippet
            ));
        }

        if roles.is_some() {
            let formatted_alts: Vec<String> = self
                .image_alts
                .iter()
                .enumerate()
                .filter_map(|(idx, alt)| {
                    let cap = sanitize_untrusted_field(alt, 200);
                    if cap.is_empty() {
                        None
                    } else {
                        Some(format!("[{}] \"{}\"", idx + 1, cap))
                    }
                })
                .collect();
            if !formatted_alts.is_empty() {
                sections.push(format!(
                    "Candidate Image Alt Text: {}",
                    formatted_alts.join("; ")
                ));
            }
        }

        if !self.images_base64.is_empty() {
            sections.push(format!(
                "Image Attachments [{} image(s) attached and decoded for visual inspection]",
                self.images_base64.len()
            ));
        }

        if roles.is_some() && !self.context_images_base64.is_empty() {
            sections.push(format!(
                "Context Thread Images [{} thumbnail(s) from the parent/quoted post decoded for visual context — NOT uploaded by Author]",
                self.context_images_base64.len()
            ));
        }

        if roles.is_some() {
            if let Some(summary) = self
                .author_signals
                .as_ref()
                .and_then(AuthorActivitySignals::format_summary)
            {
                sections.push(summary);
            }
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

    /// Fetches batched engagement metadata (likes, reposts, replies, quotes, text) for up to
    /// 25 post AT-URIs per chunk via `app.bsky.feed.getPosts`.
    async fn fetch_post_engagements(
        &self,
        _uris: &[String],
    ) -> Vec<crate::dogpile::PostEngagementSnapshot> {
        Vec::new()
    }

    /// Resolves an actor's follower count (`followersCount`) via `app.bsky.actor.getProfile`
    /// or cached target profile metadata.
    async fn fetch_actor_followers_count(&self, _did: &str) -> Option<u64> {
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

    #[test]
    fn test_cdn_validators_and_magic_bytes() {
        assert!(is_valid_cdn_did("did:plc:bob123"));
        assert!(is_valid_cdn_did("did:web:example.com"));
        assert!(!is_valid_cdn_did("did:plc:.."));
        assert!(!is_valid_cdn_did("did:plc:."));
        assert!(!is_valid_cdn_did("did:plc:a/b"));
        assert!(!is_valid_cdn_did("did:plc:a%2fb"));
        assert!(!is_valid_cdn_did("did:plc:café"));
        assert!(!is_valid_cdn_did("alice.bsky.social"));

        assert!(is_valid_cdn_cid("bafkreibob123"));
        assert!(is_valid_cdn_cid("bafk_img-1"));
        assert!(!is_valid_cdn_cid(""));
        assert!(!is_valid_cdn_cid("."));
        assert!(!is_valid_cdn_cid(".."));
        assert!(!is_valid_cdn_cid("bafy.img"));
        assert!(!is_valid_cdn_cid("bafy/img"));
        assert!(!is_valid_cdn_cid("bafy%20img"));
        assert!(!is_valid_cdn_cid("café"));

        assert!(is_valid_image_magic_bytes(&[0xFF, 0xD8, 0xFF, 0xE0]));
        assert!(is_valid_image_magic_bytes(&[
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A
        ]));
        assert!(is_valid_image_magic_bytes(b"GIF87a..."));
        assert!(is_valid_image_magic_bytes(b"GIF89a..."));
        assert!(is_valid_image_magic_bytes(b"RIFF\x00\x00\x00\x00WEBP"));
        assert!(!is_valid_image_magic_bytes(b"<html>nope</html>"));
        assert!(!is_valid_image_magic_bytes(b"PNGDATA"));
        assert!(!is_valid_image_magic_bytes(b"IMG"));
    }

    #[tokio::test]
    async fn test_target_cache_20m_ttl_hits_and_expires() {
        use std::time::Duration;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let target_did = "did:plc:targetcache20m";
        let author_did = "did:plc:authorcache20m";

        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfile"))
            .and(query_param("actor", author_did))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "did": author_did,
                "handle": "author.bsky.social"
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/xrpc/app.bsky.actor.getProfile"))
            .and(query_param("actor", target_did))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "did": target_did,
                "handle": "target.bsky.social",
                "displayName": "Protected Target"
            })))
            .expect(2)
            .mount(&server)
            .await;

        let enricher = AppViewContextEnricher::with_endpoint(server.uri());
        let inter = Interaction::mock_test_candidate(author_did, target_did, "hi");

        // 1. Cold miss -> 1 HTTP call
        let ctx1 = enricher.enrich(&inter).await;
        assert_eq!(
            ctx1.target.as_ref().and_then(|t| t.handle.as_deref()),
            Some("target.bsky.social")
        );

        // 2. Warm within 20 minutes -> cached (0 extra HTTP calls)
        enricher.set_target_cache_age_for_test(target_did, Duration::from_secs(19 * 60));
        let ctx2 = enricher.enrich(&inter).await;
        assert!(ctx2.target.is_some());

        // 3. Past 20-minute TTL -> expires and triggers 2nd HTTP call
        enricher.set_target_cache_age_for_test(target_did, Duration::from_secs(21 * 60));
        let ctx3 = enricher.enrich(&inter).await;
        assert!(ctx3.target.is_some());
    }
}
