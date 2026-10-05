//! Interaction candidate models extracted from ATProto Jetstream firehose commits.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Type of interaction targeting a protected user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionType {
    /// Direct reply to a protected post (`record.reply.parent.uri`).
    DirectReply,
    /// Reply within a thread initiated by a protected user (`record.reply.root.uri`).
    ThreadReply,
    /// Explicit mention within post text facets (`app.bsky.richtext.facet#mention`).
    Mention,
    /// Quote post embedding a protected user's post (`app.bsky.embed.record`).
    Quote,
}

impl InteractionType {
    /// Returns the static string representation of this interaction type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DirectReply => "direct_reply",
            Self::ThreadReply => "thread_reply",
            Self::Mention => "mention",
            Self::Quote => "quote",
        }
    }
}

impl fmt::Display for InteractionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Normalized candidate interaction targeting a protected user, extracted from Jetstream.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Interaction {
    /// Canonical AT-URI of the candidate post (`at://{author_did}/app.bsky.feed.post/{rkey}`).
    pub post_uri: String,
    /// CID of the post, if available.
    pub post_cid: Option<String>,
    /// Decentralized identifier (DID) of the post author.
    pub author_did: String,
    /// Protected user DID targeted by this interaction.
    pub target_did: String,
    /// Plaintext content of the post.
    pub text: String,
    /// Classification of the interaction vector (reply, mention, quote).
    pub interaction_type: InteractionType,
    /// Parent post AT-URI, if this interaction is a direct reply.
    pub parent_uri: Option<String>,
    /// Root post AT-URI, if this interaction is a thread reply.
    pub root_uri: Option<String>,
    /// Event timestamp in monotonic microseconds since Unix epoch.
    pub created_at_us: u64,
    /// CIDs of attached images (e.g. in `app.bsky.embed.images`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_cids: Vec<String>,
    /// Alt text descriptions of attached images.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_alts: Vec<String>,
    /// Optional enriched author profile and parent post context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enriched_context: Option<crate::enricher::EnrichedContext>,
    /// Optional tenant-specific moderation rubric governing this interaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rubric: Option<crate::classifier::RuleRubric>,
}

impl Interaction {
    /// Creates a new candidate [`Interaction`].
    #[must_use]
    pub fn new(
        author_did: impl Into<String>,
        target_did: impl Into<String>,
        interaction_type: InteractionType,
        post_uri: impl Into<String>,
        post_cid: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            post_uri: post_uri.into(),
            post_cid: Some(post_cid.into()),
            author_did: author_did.into(),
            target_did: target_did.into(),
            text: text.into(),
            interaction_type,
            parent_uri: None,
            root_uri: None,
            created_at_us: 1_700_000_000_000_000,
            image_cids: Vec::new(),
            image_alts: Vec::new(),
            enriched_context: None,
            rubric: None,
        }
    }

    /// Sets the parent post AT-URI.
    #[must_use]
    pub fn with_parent_uri(mut self, uri: impl Into<String>) -> Self {
        self.parent_uri = Some(uri.into());
        self
    }

    /// Sets the root post AT-URI.
    #[must_use]
    pub fn with_root_uri(mut self, uri: impl Into<String>) -> Self {
        self.root_uri = Some(uri.into());
        self
    }

    /// Returns `true` if the candidate post contains attached images.
    #[must_use]
    pub fn has_images(&self) -> bool {
        !self.image_cids.is_empty()
    }

    /// Sets the attached image CIDs and alt texts.
    #[must_use]
    pub fn with_images(mut self, cids: Vec<String>, alts: Vec<String>) -> Self {
        self.image_cids = cids;
        self.image_alts = alts;
        self
    }

    /// Returns `true` if the interaction is an author interacting with themselves.
    #[must_use]
    pub fn is_self_interaction(&self) -> bool {
        self.author_did == self.target_did
    }

    /// Attaches enriched context to this interaction.
    #[must_use]
    pub fn with_enriched_context(mut self, ctx: crate::enricher::EnrichedContext) -> Self {
        self.enriched_context = Some(ctx);
        self
    }

    /// Attaches an optional tenant-specific rule rubric.
    #[must_use]
    pub fn with_rubric(mut self, rubric: crate::classifier::RuleRubric) -> Self {
        self.rubric = Some(rubric);
        self
    }

    /// Helper for creating synthetic interactions in tests.
    #[must_use]
    pub fn mock_test_candidate(author_did: &str, target_did: &str, text: &str) -> Self {
        Self {
            post_uri: format!("at://{author_did}/app.bsky.feed.post/3mockrkey123"),
            post_cid: Some("bafyreitestmockcid123".to_string()),
            author_did: author_did.to_string(),
            target_did: target_did.to_string(),
            text: text.to_string(),
            interaction_type: InteractionType::DirectReply,
            parent_uri: Some(format!(
                "at://{target_did}/app.bsky.feed.post/3parentrkey123"
            )),
            root_uri: Some(format!("at://{target_did}/app.bsky.feed.post/3rootrkey123")),
            created_at_us: 1_700_000_000_000_000,
            image_cids: Vec::new(),
            image_alts: Vec::new(),
            enriched_context: None,
            rubric: None,
        }
    }
}

/// Extracts the DID portion from an AT-URI (`at://{did}/{collection}/{rkey}`).
///
/// Returns `None` if the URI does not start with `at://` or lacks a valid repository DID authority.
#[must_use]
pub fn extract_did_from_at_uri(uri: &str) -> Option<&str> {
    let stripped = uri.strip_prefix("at://")?;
    let did = stripped.split('/').next()?;
    if did.starts_with("did:") {
        Some(did)
    } else {
        None
    }
}

/// Extracts the authority DID from an AT-URI if and only if the collection matches `expected_collection`.
///
/// Returns `None` if the URI is malformed, lacks a `did:` authority, has a non-matching
/// collection name, or has an empty record key.
///
/// # Examples
/// ```
/// use skybouncer::matcher::extract_did_for_collection;
///
/// assert_eq!(
///     extract_did_for_collection("at://did:plc:123/app.bsky.feed.post/456", "app.bsky.feed.post"),
///     Some("did:plc:123")
/// );
/// assert_eq!(
///     extract_did_for_collection("at://did:plc:123/app.bsky.graph.list/456", "app.bsky.feed.post"),
///     None
/// );
/// ```
#[must_use]
pub fn extract_did_for_collection<'a>(uri: &'a str, expected_collection: &str) -> Option<&'a str> {
    let stripped = uri.strip_prefix("at://")?;
    let mut parts = stripped.split('/');
    let did = parts.next()?;
    if !did.starts_with("did:") {
        return None;
    }
    let collection = parts.next()?;
    if collection != expected_collection {
        return None;
    }
    let rkey = parts.next()?;
    if rkey.is_empty() {
        return None;
    }
    Some(did)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_did_from_at_uri_valid() {
        assert_eq!(
            extract_did_from_at_uri("at://did:plc:abc123def456/app.bsky.feed.post/3la7xyz"),
            Some("did:plc:abc123def456")
        );
        assert_eq!(
            extract_did_from_at_uri("at://did:web:example.com/app.bsky.feed.post/123"),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn test_extract_did_from_at_uri_invalid() {
        assert_eq!(
            extract_did_from_at_uri("https://bsky.app/profile/alice"),
            None
        );
        assert_eq!(
            extract_did_from_at_uri("at://alice.bsky.social/app.bsky.feed.post/1"),
            None
        );
        assert_eq!(extract_did_from_at_uri("at://"), None);
    }

    #[test]
    fn test_extract_did_for_collection_matching() {
        assert_eq!(
            extract_did_for_collection(
                "at://did:plc:alice123/app.bsky.feed.post/post456",
                "app.bsky.feed.post"
            ),
            Some("did:plc:alice123")
        );
    }

    #[test]
    fn test_extract_did_for_collection_mismatch_or_malformed() {
        // Mismatched collection
        assert_eq!(
            extract_did_for_collection(
                "at://did:plc:alice123/app.bsky.graph.list/list456",
                "app.bsky.feed.post"
            ),
            None
        );
        // Missing rkey
        assert_eq!(
            extract_did_for_collection(
                "at://did:plc:alice123/app.bsky.feed.post/",
                "app.bsky.feed.post"
            ),
            None
        );
        // Non-did authority
        assert_eq!(
            extract_did_for_collection(
                "at://alice.bsky.social/app.bsky.feed.post/123",
                "app.bsky.feed.post"
            ),
            None
        );
        // Non-at URI
        assert_eq!(
            extract_did_for_collection(
                "https://bsky.app/profile/did:plc:alice123/post/456",
                "app.bsky.feed.post"
            ),
            None
        );
    }
}
