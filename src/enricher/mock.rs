//! Deterministic mock context enricher for hermetic testing.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::enricher::{
    collect_non_empty_alts, compute_reply_timing_signals, extract_fundraiser_urls_from_text,
    AuthorActivitySignals, AuthorContext, ContextEnricher, ContextImageRef, EnrichedContext,
    ParentPostContext, MAX_CONTEXT_IMAGES, MAX_POST_IMAGES,
};
use crate::matcher::Interaction;

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
    context_image_refs: Arc<RwLock<HashMap<String, Vec<ContextImageRef>>>>,
    relationships: Arc<RwLock<RelationshipMap>>,
    post_engagements: Arc<RwLock<HashMap<String, crate::dogpile::PostEngagementSnapshot>>>,
    author_signals: Arc<RwLock<HashMap<String, AuthorActivitySignals>>>,
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

    /// Injects context image references for a parent or quoted post AT-URI.
    pub fn set_context_image_refs(&self, uri: impl Into<String>, refs: Vec<ContextImageRef>) {
        self.context_image_refs.write().insert(uri.into(), refs);
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

    /// Injects a mock [`crate::dogpile::PostEngagementSnapshot`] keyed by its AT-URI.
    pub fn set_post_engagement(&self, snapshot: crate::dogpile::PostEngagementSnapshot) {
        self.post_engagements
            .write()
            .insert(snapshot.uri.clone(), snapshot);
    }

    /// Injects mock [`AuthorActivitySignals`] for a candidate author DID.
    pub fn set_author_signals(&self, did: impl Into<String>, signals: AuthorActivitySignals) {
        self.author_signals.write().insert(did.into(), signals);
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
        let image_alts = collect_non_empty_alts(&interaction.image_alts);
        let context_image_refs = interaction
            .parent_uri
            .as_deref()
            .or(interaction.quote_uri.as_deref())
            .and_then(|uri| self.context_image_refs.read().get(uri).cloned())
            .map(|refs| refs.into_iter().take(MAX_CONTEXT_IMAGES).collect())
            .unwrap_or_default();

        let author_signals = self
            .author_signals
            .read()
            .get(&interaction.author_did)
            .cloned()
            .or_else(|| {
                let (reply_latency_ms, forged_tid) = compute_reply_timing_signals(interaction);
                let mut sig = AuthorActivitySignals {
                    reply_latency_ms,
                    forged_tid,
                    ..Default::default()
                };
                if let Some(ref auth) = author {
                    if let Some(ref desc) = auth.description {
                        sig.profile_fundraiser_urls = extract_fundraiser_urls_from_text(desc);
                    }
                }
                (!sig.is_empty()).then_some(sig)
            });

        EnrichedContext {
            author,
            target,
            parent_post,
            quoted_post,
            thread_ancestors: Vec::new(),
            thread_ancestor_quotes: Vec::new(),
            thread_ancestor_embeds: Vec::new(),
            images_base64,
            image_alts,
            context_image_refs,
            context_images_base64: Vec::new(),
            author_signals,
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

    async fn fetch_post_engagements(
        &self,
        uris: &[String],
    ) -> Vec<crate::dogpile::PostEngagementSnapshot> {
        let guard = self.post_engagements.read();
        uris.iter().filter_map(|u| guard.get(u).cloned()).collect()
    }

    async fn fetch_actor_followers_count(&self, did: &str) -> Option<u64> {
        self.authors
            .read()
            .get(did)
            .and_then(|a| a.followers_count)
            .or_else(|| self.targets.read().get(did).and_then(|t| t.followers_count))
    }
}
