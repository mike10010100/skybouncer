//! Target matching engine inspecting ATProto Jetstream commits for candidate interactions.

use std::collections::HashSet;

use skybase::ingest::{CommitOperation, JetstreamCommit};

use crate::matcher::interaction::{extract_did_for_collection, Interaction, InteractionType};
use crate::types::{FacetFeature, PostRecord};

/// ATProto post collection NSID.
const POST_COLLECTION: &str = "app.bsky.feed.post";

/// Zero-allocation `&serde_json::Value` check across all 4 interaction target vectors before
/// cloning or deserializing a full [`PostRecord`].
fn uri_targets_protected(uri: &str, protected_dids: &HashSet<String>) -> bool {
    extract_did_for_collection(uri, POST_COLLECTION).is_some_and(|did| protected_dids.contains(did))
}

fn record_targets_protected_did(
    record_val: &serde_json::Value,
    protected_dids: &HashSet<String>,
) -> bool {
    if let Some(reply) = record_val.get("reply") {
        if reply
            .get("parent")
            .and_then(|p| p.get("uri"))
            .and_then(|u| u.as_str())
            .is_some_and(|uri| uri_targets_protected(uri, protected_dids))
        {
            return true;
        }
        if reply
            .get("root")
            .and_then(|r| r.get("uri"))
            .and_then(|u| u.as_str())
            .is_some_and(|uri| uri_targets_protected(uri, protected_dids))
        {
            return true;
        }
    }

    if let Some(facets) = record_val.get("facets").and_then(|f| f.as_array()) {
        for facet in facets {
            if let Some(features) = facet.get("features").and_then(|f| f.as_array()) {
                for feat in features {
                    if feat.get("$type").and_then(|t| t.as_str())
                        == Some("app.bsky.richtext.facet#mention")
                        && feat
                            .get("did")
                            .and_then(|d| d.as_str())
                            .is_some_and(|did| protected_dids.contains(did))
                    {
                        return true;
                    }
                }
            }
        }
    }

    if let Some(embed) = record_val.get("embed") {
        if let Some(embed_type) = embed.get("$type").and_then(|t| t.as_str()) {
            let quote_uri = match embed_type {
                "app.bsky.embed.record" => embed
                    .get("record")
                    .and_then(|r| r.get("uri"))
                    .and_then(|u| u.as_str()),
                "app.bsky.embed.recordWithMedia" => embed
                    .get("record")
                    .and_then(|r| r.get("record"))
                    .and_then(|r| r.get("uri"))
                    .and_then(|u| u.as_str()),
                _ => None,
            };
            if quote_uri.is_some_and(|uri| uri_targets_protected(uri, protected_dids)) {
                return true;
            }
        }
    }

    false
}

/// Target matching engine detecting incoming interactions directed at protected users.
#[derive(Debug, Default, Clone, Copy)]
pub struct TargetMatcher;

impl TargetMatcher {
    /// Creates a new [`TargetMatcher`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluates a Jetstream commit against a set of protected DIDs.
    ///
    /// Returns `Some(Interaction)` if the commit represents an incoming post that
    /// targets one of the `protected_dids` via direct reply, thread reply,
    /// mention, or quote post.
    ///
    /// Returns `None` if:
    /// - The commit is not for collection `app.bsky.feed.post`
    /// - The commit operation is not [`CommitOperation::Create`]
    /// - The commit has no record payload or cannot be parsed as a post
    /// - The post does not target any protected DID
    #[must_use]
    pub fn match_interaction(
        commit: &JetstreamCommit,
        protected_dids: &HashSet<String>,
    ) -> Option<Interaction> {
        Self::match_all_interactions(commit, protected_dids)
            .into_iter()
            .next()
    }

    /// Evaluates a Jetstream commit and returns all distinct interactions targeting protected DIDs.
    ///
    /// This supports posts that target multiple protected users simultaneously (e.g. mentioning
    /// two protected accounts).
    #[must_use]
    pub fn match_all_interactions(
        commit: &JetstreamCommit,
        protected_dids: &HashSet<String>,
    ) -> Vec<Interaction> {
        if protected_dids.is_empty() {
            return Vec::new();
        }

        if commit.collection != POST_COLLECTION || commit.operation != CommitOperation::Create {
            return Vec::new();
        }

        let Some(ref record_val) = commit.record else {
            return Vec::new();
        };

        // Fast-path bypass: if record has neither reply, facets, nor embed targeting a protected
        // DID, skip cloning and deserializing `PostRecord` altogether.
        if (record_val.get("reply").is_none()
            && record_val.get("facets").is_none()
            && record_val.get("embed").is_none())
            || !record_targets_protected_did(record_val, protected_dids)
        {
            return Vec::new();
        }

        // Deserialize strongly-typed PostRecord
        let post: PostRecord = match serde_json::from_value(record_val.clone()) {
            Ok(p) => p,
            Err(err) => {
                tracing::debug!(
                    uri = %commit.uri(),
                    error = %err,
                    "Failed to deserialize post record in TargetMatcher"
                );
                return Vec::new();
            }
        };

        let mut matches = Vec::new();
        let mut seen_targets = HashSet::new();

        // Extract attached image CIDs and alt texts once for this post, supporting both
        // legacy `app.bsky.embed.images` and multi-image `app.bsky.embed.gallery` embeds.
        let (image_cids, image_alts) = extract_post_images(&post, record_val);
        let post_quote_uri = post
            .embed
            .as_ref()
            .and_then(|e| e.quote_uri())
            .map(str::to_owned);

        // Vector 1: Direct Reply (parent.uri)
        if let Some(ref reply) = post.reply {
            if let Some(parent_did) = extract_did_for_collection(&reply.parent.uri, POST_COLLECTION)
            {
                if protected_dids.contains(parent_did) {
                    seen_targets.insert(parent_did.to_string());
                    matches.push(Interaction {
                        post_uri: commit.uri(),
                        post_cid: commit.cid.clone(),
                        author_did: commit.did.clone(),
                        target_did: parent_did.to_string(),
                        text: post.text.clone(),
                        interaction_type: InteractionType::DirectReply,
                        parent_uri: Some(reply.parent.uri.clone()),
                        root_uri: Some(reply.root.uri.clone()),
                        quote_uri: post_quote_uri.clone(),
                        created_at_us: commit.time_us,
                        image_cids: image_cids.clone(),
                        image_alts: image_alts.clone(),
                        enriched_context: None,
                        rubric: None,
                    });
                }
            }

            // Vector 2: Thread Root Reply (root.uri, when root != parent or parent was not protected)
            if let Some(root_did) = extract_did_for_collection(&reply.root.uri, POST_COLLECTION) {
                if protected_dids.contains(root_did) && !seen_targets.contains(root_did) {
                    seen_targets.insert(root_did.to_string());
                    matches.push(Interaction {
                        post_uri: commit.uri(),
                        post_cid: commit.cid.clone(),
                        author_did: commit.did.clone(),
                        target_did: root_did.to_string(),
                        text: post.text.clone(),
                        interaction_type: InteractionType::ThreadReply,
                        parent_uri: Some(reply.parent.uri.clone()),
                        root_uri: Some(reply.root.uri.clone()),
                        quote_uri: post_quote_uri.clone(),
                        created_at_us: commit.time_us,
                        image_cids: image_cids.clone(),
                        image_alts: image_alts.clone(),
                        enriched_context: None,
                        rubric: None,
                    });
                }
            }
        }

        // Vector 3: Mentions (facets)
        if let Some(ref facets) = post.facets {
            for facet in facets {
                for feature in &facet.features {
                    if let FacetFeature::Mention { ref did } = feature {
                        if protected_dids.contains(did) && !seen_targets.contains(did) {
                            seen_targets.insert(did.clone());
                            matches.push(Interaction {
                                post_uri: commit.uri(),
                                post_cid: commit.cid.clone(),
                                author_did: commit.did.clone(),
                                target_did: did.clone(),
                                text: post.text.clone(),
                                interaction_type: InteractionType::Mention,
                                parent_uri: post.reply.as_ref().map(|r| r.parent.uri.clone()),
                                root_uri: post.reply.as_ref().map(|r| r.root.uri.clone()),
                                quote_uri: post_quote_uri.clone(),
                                created_at_us: commit.time_us,
                                image_cids: image_cids.clone(),
                                image_alts: image_alts.clone(),
                                enriched_context: None,
                                rubric: None,
                            });
                        }
                    }
                }
            }
        }

        // Vector 4: Quotes (embed.record or embed.recordWithMedia)
        if let Some(ref quote_uri) = post_quote_uri {
            if let Some(quoted_did) = extract_did_for_collection(quote_uri, POST_COLLECTION) {
                if protected_dids.contains(quoted_did) && !seen_targets.contains(quoted_did) {
                    seen_targets.insert(quoted_did.to_string());
                    matches.push(Interaction {
                        post_uri: commit.uri(),
                        post_cid: commit.cid.clone(),
                        author_did: commit.did.clone(),
                        target_did: quoted_did.to_string(),
                        text: post.text.clone(),
                        interaction_type: InteractionType::Quote,
                        parent_uri: post.reply.as_ref().map(|r| r.parent.uri.clone()),
                        root_uri: post.reply.as_ref().map(|r| r.root.uri.clone()),
                        quote_uri: Some(quote_uri.clone()),
                        created_at_us: commit.time_us,
                        image_cids: image_cids.clone(),
                        image_alts: image_alts.clone(),
                        enriched_context: None,
                        rubric: None,
                    });
                }
            }
        }

        matches
    }
}

/// Extracts image CIDs and alt texts from a post record, supporting both legacy
/// `app.bsky.embed.images` (via [`crate::types::Embed::extract_images`]) and
/// multi-image `app.bsky.embed.gallery` embeds (`items` array up to [`crate::enricher::MAX_POST_IMAGES`]).
fn extract_post_images(
    post: &PostRecord,
    record_val: &serde_json::Value,
) -> (Vec<String>, Vec<String>) {
    let mut pairs = post
        .embed
        .as_ref()
        .map(crate::types::Embed::extract_images)
        .unwrap_or_default();

    if pairs.is_empty() {
        if let Some(embed_val) = record_val.get("embed") {
            pairs = extract_gallery_items(embed_val);
            if pairs.is_empty() {
                if let Some(media_val) = embed_val.get("media") {
                    pairs = extract_gallery_items(media_val);
                }
            }
        }
    }

    let cap = pairs.len().min(crate::enricher::MAX_POST_IMAGES);
    let mut cids = Vec::with_capacity(cap);
    let mut alts = Vec::with_capacity(cap);
    for (c, a) in pairs.into_iter().take(crate::enricher::MAX_POST_IMAGES) {
        cids.push(c);
        alts.push(a);
    }
    (cids, alts)
}

/// Extracts `(cid, alt)` pairs from an `app.bsky.embed.gallery` (or `images`) JSON object.
fn extract_gallery_items(val: &serde_json::Value) -> Vec<(String, String)> {
    crate::types::Embed::extract_gallery_items(val)
}
