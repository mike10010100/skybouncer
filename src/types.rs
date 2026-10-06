//! Strongly-typed ATProto Lexicon data models for `skybouncer`.
//!
//! Provides clean, lightweight Serde representations of ATProto records matching
//! official lexicon schemas (`app.bsky.feed.post`, `app.bsky.richtext.facet`,
//! `app.bsky.embed.record`, `app.bsky.embed.recordWithMedia`, `app.bsky.graph.follow`,
//! `app.bsky.graph.list`, and `app.bsky.graph.listitem`).

use serde::{Deserialize, Serialize};

/// Returns `true`, used as the serde default for opt-out moderation bypass flags.
pub(crate) fn default_true() -> bool {
    true
}

/// Returns whether the flag is `true`, used to omit the default value during serialization.
pub(crate) fn is_true(value: &bool) -> bool {
    *value
}

/// Strong reference to an ATProto repository record (`com.atproto.repo.strongRef`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StrongRef {
    /// Canonical AT-URI (`at://{did}/{collection}/{rkey}`).
    pub uri: String,
    /// Content identifier (CID) hash string.
    pub cid: String,
}

impl StrongRef {
    /// Creates a new [`StrongRef`].
    #[must_use]
    pub fn new(uri: impl Into<String>, cid: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            cid: cid.into(),
        }
    }

    /// Extracts the authority DID from the record's AT-URI without allocating.
    #[must_use]
    pub fn did(&self) -> Option<&str> {
        crate::matcher::extract_did_from_at_uri(&self.uri)
    }
}

/// Reply references connecting a post to its thread root and immediate parent (`app.bsky.feed.post#replyRef`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplyRef {
    /// Reference to the thread root post.
    pub root: StrongRef,
    /// Reference to the immediate parent post being replied to.
    pub parent: StrongRef,
}

impl ReplyRef {
    /// Creates a new [`ReplyRef`].
    #[must_use]
    pub fn new(root: StrongRef, parent: StrongRef) -> Self {
        Self { root, parent }
    }

    /// Extracts the author DID of the immediate parent post.
    #[must_use]
    pub fn parent_did(&self) -> Option<&str> {
        self.parent.did()
    }

    /// Extracts the author DID of the thread root post.
    #[must_use]
    pub fn root_did(&self) -> Option<&str> {
        self.root.did()
    }
}

// Re-exported rich text lexicon types and link-facet extraction from `skybase`.
pub use skybase::lexicon::{extract_link_facets, ByteSlice, Facet, FacetFeature, FacetIndex};

/// Quoted record embed reference (`app.bsky.embed.record`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordEmbed {
    /// Optional lexicon type discriminator.
    #[serde(rename = "$type", default)]
    pub record_type: Option<String>,
    /// Quoted record reference.
    pub record: StrongRef,
}

impl RecordEmbed {
    /// Creates a new [`RecordEmbed`].
    #[must_use]
    pub fn new(record: StrongRef) -> Self {
        Self {
            record_type: Some("app.bsky.embed.record".to_string()),
            record,
        }
    }
}

/// Quoted record combined with media attachments (`app.bsky.embed.recordWithMedia`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordWithMediaEmbed {
    /// Optional lexicon type discriminator.
    #[serde(rename = "$type", default)]
    pub record_type: Option<String>,
    /// Quoted record embed container.
    pub record: RecordEmbed,
    /// Media attachments (images, video, external).
    #[serde(default)]
    pub media: Option<serde_json::Value>,
}

impl RecordWithMediaEmbed {
    /// Creates a new [`RecordWithMediaEmbed`].
    #[must_use]
    pub fn new(record: RecordEmbed, media: Option<serde_json::Value>) -> Self {
        Self {
            record_type: Some("app.bsky.embed.recordWithMedia".to_string()),
            record,
            media,
        }
    }
}

/// Embedded content union on a post record (`app.bsky.feed.post#embed`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum Embed {
    /// Quoted record embed (`app.bsky.embed.record`).
    #[serde(rename = "app.bsky.embed.record")]
    Record(RecordEmbed),
    /// Quoted record embed combined with media (`app.bsky.embed.recordWithMedia`).
    #[serde(rename = "app.bsky.embed.recordWithMedia")]
    RecordWithMedia(Box<RecordWithMediaEmbed>),
    /// Image attachments (`app.bsky.embed.images`).
    #[serde(rename = "app.bsky.embed.images")]
    Images(serde_json::Value),
    /// External card embed (`app.bsky.embed.external`).
    #[serde(rename = "app.bsky.embed.external")]
    External(serde_json::Value),
    /// Video embed (`app.bsky.embed.video`).
    #[serde(rename = "app.bsky.embed.video")]
    Video(serde_json::Value),
    /// Unrecognized or future embed type.
    #[serde(other)]
    Unknown,
}

impl Embed {
    /// Returns the quoted record AT-URI if this embed is a quote (`Record` or `RecordWithMedia`).
    #[must_use]
    pub fn quote_uri(&self) -> Option<&str> {
        match self {
            Self::Record(r) => Some(r.record.uri.as_str()),
            Self::RecordWithMedia(rwm) => Some(rwm.record.record.uri.as_str()),
            _ => None,
        }
    }

    /// Returns the quoted record CID if this embed is a quote (`Record` or `RecordWithMedia`).
    #[must_use]
    pub fn quote_cid(&self) -> Option<&str> {
        match self {
            Self::Record(r) => Some(r.record.cid.as_str()),
            Self::RecordWithMedia(rwm) => Some(rwm.record.record.cid.as_str()),
            _ => None,
        }
    }

    /// Returns `true` if this embed contains a quoted record.
    #[must_use]
    pub fn is_quote(&self) -> bool {
        matches!(self, Self::Record(_) | Self::RecordWithMedia(_))
    }

    /// Extracts all attached image CIDs and optional alt texts from this embed.
    ///
    /// Supports both direct image embeds (`app.bsky.embed.images`) and composite
    /// quote-with-media embeds (`app.bsky.embed.recordWithMedia`).
    #[must_use]
    pub fn extract_images(&self) -> Vec<(String, String)> {
        match self {
            Self::Images(val) => Self::extract_images_from_value(val),
            Self::RecordWithMedia(rwm) => {
                if let Some(ref media) = rwm.media {
                    Self::extract_images_from_value(media)
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    /// Internal helper extracting `(cid, alt)` pairs from an arbitrary JSON value.
    fn extract_images_from_value(val: &serde_json::Value) -> Vec<(String, String)> {
        let mut results = Vec::new();
        let images_array = if let Some(arr) = val.get("images").and_then(|v| v.as_array()) {
            arr
        } else if let Some(arr) = val.as_array() {
            arr
        } else {
            return results;
        };

        for item in images_array {
            let alt = item
                .get("alt")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let cid = item
                .get("image")
                .and_then(|img| {
                    img.get("ref")
                        .and_then(|r| r.get("$link"))
                        .and_then(|l| l.as_str())
                        .or_else(|| img.get("cid").and_then(|c| c.as_str()))
                })
                .or_else(|| item.get("cid").and_then(|c| c.as_str()));

            if let Some(c) = cid {
                if !c.is_empty() {
                    results.push((c.to_string(), alt));
                }
            }
        }

        results
    }
}

/// ATProto post record model (`app.bsky.feed.post`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostRecord {
    /// Optional lexicon type discriminator.
    #[serde(rename = "$type", default)]
    pub record_type: Option<String>,
    /// Text body of the post.
    #[serde(default)]
    pub text: String,
    /// Optional reply references.
    #[serde(default)]
    pub reply: Option<ReplyRef>,
    /// Optional rich text facet annotations.
    #[serde(default)]
    pub facets: Option<Vec<Facet>>,
    /// Optional embedded media or quote post.
    #[serde(default)]
    pub embed: Option<Embed>,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: String,
    /// Optional language tags.
    #[serde(default)]
    pub langs: Option<Vec<String>>,
    /// Optional post hashtags or category tags.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

impl PostRecord {
    /// Creates a minimal [`PostRecord`] with text and creation timestamp.
    #[must_use]
    pub fn new(text: impl Into<String>, created_at: impl Into<String>) -> Self {
        Self {
            record_type: Some("app.bsky.feed.post".to_string()),
            text: text.into(),
            reply: None,
            facets: None,
            embed: None,
            created_at: created_at.into(),
            langs: None,
            tags: None,
        }
    }

    /// Sets the reply reference.
    #[must_use]
    pub fn with_reply(mut self, reply: ReplyRef) -> Self {
        self.reply = Some(reply);
        self
    }

    /// Sets rich text facets.
    #[must_use]
    pub fn with_facets(mut self, facets: Vec<Facet>) -> Self {
        self.facets = Some(facets);
        self
    }

    /// Sets an embedded item.
    #[must_use]
    pub fn with_embed(mut self, embed: Embed) -> Self {
        self.embed = Some(embed);
        self
    }

    /// Returns an iterator over all distinct DIDs mentioned in this post's facets.
    pub fn mentioned_dids(&self) -> impl Iterator<Item = &str> {
        self.facets
            .as_deref()
            .into_iter()
            .flatten()
            .flat_map(Facet::mentioned_dids)
    }

    /// Returns the quoted post AT-URI if present.
    #[must_use]
    pub fn quote_uri(&self) -> Option<&str> {
        self.embed.as_ref().and_then(Embed::quote_uri)
    }
}

/// ATProto graph follow record model (`app.bsky.graph.follow`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FollowRecord {
    /// Optional lexicon type discriminator.
    #[serde(rename = "$type", default)]
    pub record_type: Option<String>,
    /// Decentralized identifier (DID) of the account being followed.
    pub subject: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

impl FollowRecord {
    /// Creates a new [`FollowRecord`].
    #[must_use]
    pub fn new(subject: impl Into<String>, created_at: impl Into<String>) -> Self {
        Self {
            record_type: Some("app.bsky.graph.follow".to_string()),
            subject: subject.into(),
            created_at: created_at.into(),
        }
    }
}

/// ATProto moderation list record model (`app.bsky.graph.list`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModListRecord {
    /// Optional lexicon type discriminator.
    #[serde(rename = "$type", default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    /// List purpose identifier (`app.bsky.graph.defs#modlist`).
    pub purpose: String,
    /// Human-readable list title.
    pub name: String,
    /// Optional human-readable list description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional rich text facets for description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description_facets: Option<Vec<Facet>>,
    /// Optional avatar blob reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<serde_json::Value>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

impl ModListRecord {
    /// Creates a new moderation list record with default purpose `app.bsky.graph.defs#modlist`.
    #[must_use]
    pub fn new_modlist(
        name: impl Into<String>,
        description: Option<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            record_type: Some("app.bsky.graph.list".to_string()),
            purpose: "app.bsky.graph.defs#modlist".to_string(),
            name: name.into(),
            description,
            description_facets: None,
            avatar: None,
            created_at: created_at.into(),
        }
    }

    /// Creates a new generic list record with specified purpose.
    #[must_use]
    pub fn new(
        purpose: impl Into<String>,
        name: impl Into<String>,
        description: Option<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            record_type: Some("app.bsky.graph.list".to_string()),
            purpose: purpose.into(),
            name: name.into(),
            description,
            description_facets: None,
            avatar: None,
            created_at: created_at.into(),
        }
    }

    /// Checks whether this list record has the moderation list purpose.
    #[must_use]
    pub fn is_modlist(&self) -> bool {
        self.purpose == "app.bsky.graph.defs#modlist"
    }
}

/// ATProto list item record model (`app.bsky.graph.listitem`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListItemRecord {
    /// Optional lexicon type discriminator.
    #[serde(rename = "$type", default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    /// Decentralized identifier (DID) of the account added to the list.
    pub subject: String,
    /// Canonical AT-URI of the parent moderation list (`at://{did}/app.bsky.graph.list/{rkey}`).
    pub list: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

impl ListItemRecord {
    /// Creates a new [`ListItemRecord`].
    #[must_use]
    pub fn new(
        subject: impl Into<String>,
        list: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            record_type: Some("app.bsky.graph.listitem".to_string()),
            subject: subject.into(),
            list: list.into(),
            created_at: created_at.into(),
        }
    }
}

/// ATProto list block record model (`app.bsky.graph.listblock`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListBlockRecord {
    /// Optional lexicon type discriminator.
    #[serde(rename = "$type", default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    /// Canonical AT-URI of the moderation list being blocked (`at://{did}/app.bsky.graph.list/{rkey}`).
    pub subject: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

impl ListBlockRecord {
    /// Creates a new [`ListBlockRecord`] targeting a moderation list AT-URI.
    #[must_use]
    pub fn new(subject: impl Into<String>, created_at: impl Into<String>) -> Self {
        Self {
            record_type: Some("app.bsky.graph.listblock".to_string()),
            subject: subject.into(),
            created_at: created_at.into(),
        }
    }
}

/// A record item returned by `com.atproto.repo.listRecords`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoRecordItem<T = serde_json::Value> {
    /// Canonical AT-URI of the committed record.
    pub uri: String,
    /// Content identifier (CID) hash string.
    pub cid: String,
    /// The deserialized record value payload.
    pub value: T,
}

/// The response payload from `com.atproto.repo.listRecords`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListRecordsResponse<T = serde_json::Value> {
    /// Array of committed records in the target collection.
    pub records: Vec<RepoRecordItem<T>>,
    /// Optional pagination cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Formats a [`std::time::SystemTime`] as an ISO-8601 (RFC 3339) UTC timestamp string.
#[must_use]
pub fn format_system_time_iso8601(time: std::time::SystemTime) -> String {
    let dur = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO);
    let total_secs = dur.as_secs();
    let millis = dur.subsec_millis();

    let days = (total_secs / 86400) as i64;
    let day_secs = (total_secs % 86400) as u32;

    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let second = day_secs % 60;

    // Euclidean affine civil calendar algorithm (Howard Hinnant)
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Convenience function returning the current UTC time as an ISO-8601 string.
#[must_use]
pub fn now_iso8601() -> String {
    format_system_time_iso8601(std::time::SystemTime::now())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_format_system_time_epoch() {
        let formatted = format_system_time_iso8601(UNIX_EPOCH);
        assert_eq!(formatted, "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn test_format_system_time_known_date() {
        // 2026-10-02T02:00:00.500Z -> days = 20728, seconds = 7200, ms = 500
        let time = UNIX_EPOCH + Duration::from_millis(1_790_906_400_500);
        let formatted = format_system_time_iso8601(time);
        assert_eq!(formatted, "2026-10-02T02:00:00.500Z");
    }

    #[test]
    fn test_now_iso8601_non_empty() {
        let now = now_iso8601();
        assert!(now.ends_with('Z'));
        assert!(now.contains('T'));
    }

    #[test]
    fn test_mod_list_record_serde_roundtrip() {
        let record = ModListRecord::new_modlist(
            "Test Mod List",
            Some("Description".to_string()),
            "2026-10-02T00:00:00.000Z",
        );
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"purpose\":\"app.bsky.graph.defs#modlist\""));
        assert!(json.contains("\"name\":\"Test Mod List\""));

        let deserialized: ModListRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
        assert!(deserialized.is_modlist());
    }

    #[test]
    fn test_list_item_record_serde_roundtrip() {
        let record = ListItemRecord::new(
            "did:plc:badactor",
            "at://did:plc:alice/app.bsky.graph.list/123",
            "2026-10-02T00:00:00.000Z",
        );
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"subject\":\"did:plc:badactor\""));

        let deserialized: ListItemRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_embed_extract_images_direct() {
        let json = serde_json::json!({
            "$type": "app.bsky.embed.images",
            "images": [
                {
                    "alt": "A test visual",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": "bafkreicid12345" },
                        "mimeType": "image/jpeg",
                        "size": 1234
                    }
                },
                {
                    "alt": "Second visual",
                    "image": {
                        "cid": "bafkreicid67890"
                    }
                }
            ]
        });

        let embed: Embed = serde_json::from_value(json).unwrap();
        let images = embed.extract_images();
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].0, "bafkreicid12345");
        assert_eq!(images[0].1, "A test visual");
        assert_eq!(images[1].0, "bafkreicid67890");
        assert_eq!(images[1].1, "Second visual");
    }

    #[test]
    fn test_embed_extract_images_record_with_media() {
        let json = serde_json::json!({
            "$type": "app.bsky.embed.recordWithMedia",
            "record": {
                "record": {
                    "uri": "at://did:plc:alice/app.bsky.feed.post/123",
                    "cid": "bafyquoted"
                }
            },
            "media": {
                "$type": "app.bsky.embed.images",
                "images": [
                    {
                        "alt": "Embedded image",
                        "image": {
                            "ref": { "$link": "bafkmediaimage1" }
                        }
                    }
                ]
            }
        });

        let embed: Embed = serde_json::from_value(json).unwrap();
        let images = embed.extract_images();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].0, "bafkmediaimage1");
        assert_eq!(images[0].1, "Embedded image");
        assert!(embed.is_quote());
        assert_eq!(
            embed.quote_uri(),
            Some("at://did:plc:alice/app.bsky.feed.post/123")
        );
    }
}
