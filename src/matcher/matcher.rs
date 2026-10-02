//! Target matching engine inspecting ATProto Jetstream commits for candidate interactions.

use std::collections::HashSet;

use skybase::ingest::{CommitOperation, JetstreamCommit};

use crate::matcher::interaction::{extract_did_for_collection, Interaction, InteractionType};
use crate::types::{FacetFeature, PostRecord};

/// ATProto post collection NSID.
const POST_COLLECTION: &str = "app.bsky.feed.post";

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

        // Fast-path bypass: if record has neither reply, facets, nor embed, it cannot target any user.
        if record_val.get("reply").is_none()
            && record_val.get("facets").is_none()
            && record_val.get("embed").is_none()
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
                        created_at_us: commit.time_us,
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
                        created_at_us: commit.time_us,
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
                                created_at_us: commit.time_us,
                            });
                        }
                    }
                }
            }
        }

        // Vector 4: Quotes (embed.record or embed.recordWithMedia)
        if let Some(ref embed) = post.embed {
            if let Some(quote_uri) = embed.quote_uri() {
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
                            created_at_us: commit.time_us,
                        });
                    }
                }
            }
        }

        matches
    }
}
