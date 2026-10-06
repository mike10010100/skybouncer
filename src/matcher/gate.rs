//! Non-Followed Direct Interaction Gate.
//!
//! Enforces the sub-microsecond ($<1\mu s$), zero-cost ($0 network/DB calls) filter
//! dropping self-interactions and interactions from followed accounts before any
//! classifier is invoked.

use crate::matcher::follow_graph::FollowGraph;
use crate::matcher::interaction::Interaction;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Detailed reason why an incoming interaction bypassed moderation evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassReason {
    /// Interaction is authored by the protected user themselves (self-reply, thread continuation, self-quote).
    SelfInteraction,
    /// Author is actively followed by the protected user.
    FollowedAuthor,
    /// Author follows the protected user (incoming follower).
    FollowerAuthor,
    /// Author is explicitly on the protected user's moderation allowlist.
    AllowlistedAuthor,
}

impl BypassReason {
    /// Returns the static string representation of this bypass reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SelfInteraction => "self_interaction",
            Self::FollowedAuthor => "followed_author",
            Self::FollowerAuthor => "follower_author",
            Self::AllowlistedAuthor => "allowlisted_author",
        }
    }
}

/// Result of evaluating an incoming interaction through the Non-Followed Gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Interaction passed the gate and is a candidate for classifier evaluation.
    Candidate(Interaction),
    /// Interaction bypassed evaluation at zero cost without calling any classifier.
    Bypassed {
        /// Reason the interaction was bypassed.
        reason: BypassReason,
        /// The bypassed interaction.
        interaction: Interaction,
    },
}

impl GateDecision {
    /// Returns `true` if the interaction passed the gate as a candidate.
    #[must_use]
    pub fn is_candidate(&self) -> bool {
        matches!(self, Self::Candidate(_))
    }

    /// Returns `true` if the interaction was bypassed.
    #[must_use]
    pub fn is_bypassed(&self) -> bool {
        matches!(self, Self::Bypassed { .. })
    }

    /// Unwraps the decision into an `Option<Interaction>`, returning `Some` only if candidate.
    #[must_use]
    pub fn into_candidate(self) -> Option<Interaction> {
        match self {
            Self::Candidate(interaction) => Some(interaction),
            Self::Bypassed { .. } => None,
        }
    }

    /// Returns a reference to the candidate interaction if not bypassed.
    #[must_use]
    pub fn candidate(&self) -> Option<&Interaction> {
        match self {
            Self::Candidate(ref interaction) => Some(interaction),
            Self::Bypassed { .. } => None,
        }
    }

    /// Returns the bypass reason if the interaction was bypassed.
    #[must_use]
    pub fn bypass_reason(&self) -> Option<BypassReason> {
        match self {
            Self::Bypassed { reason, .. } => Some(*reason),
            Self::Candidate(_) => None,
        }
    }
}

/// Cost Control Gate evaluating incoming interactions against protected follow graphs and allowlists.
#[derive(Debug, Clone)]
pub struct NonFollowedGate {
    follow_graph: Arc<FollowGraph>,
    allowlist: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    bypass_flags: Arc<RwLock<HashMap<String, bool>>>,
}

impl NonFollowedGate {
    /// Creates a new `NonFollowedGate` bound to the given shared [`FollowGraph`] and an empty allowlist.
    #[must_use]
    pub fn new(follow_graph: Arc<FollowGraph>) -> Self {
        Self {
            follow_graph,
            allowlist: Arc::new(RwLock::new(HashMap::new())),
            bypass_flags: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a new `NonFollowedGate` bound to the given shared [`FollowGraph`] and allowlist cache.
    #[must_use]
    pub fn new_with_allowlist(
        follow_graph: Arc<FollowGraph>,
        allowlist: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    ) -> Self {
        Self {
            follow_graph,
            allowlist,
            bypass_flags: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns a reference to the underlying follow graph.
    #[must_use]
    pub fn follow_graph(&self) -> &FollowGraph {
        &self.follow_graph
    }

    /// Returns a reference to the underlying allowlist mapping.
    #[must_use]
    pub fn allowlist(&self) -> &Arc<RwLock<HashMap<String, HashSet<String>>>> {
        &self.allowlist
    }

    /// Returns a reference to the per-user incoming-follower bypass flags.
    #[must_use]
    pub fn bypass_flags(&self) -> &Arc<RwLock<HashMap<String, bool>>> {
        &self.bypass_flags
    }

    /// Sets whether incoming followers bypass moderation for a protected user.
    ///
    /// This is an in-memory mirror of the per-user sovereign rubric flag, keeping the
    /// gate lookup at `<1µs` without a per-interaction SQLite query.
    pub fn set_bypass_incoming_followers(&self, protected_did: impl Into<String>, bypass: bool) {
        self.bypass_flags
            .write()
            .insert(protected_did.into(), bypass);
    }

    /// Returns whether incoming followers bypass moderation for a protected user.
    ///
    /// Defaults to `true` when the protected user has no explicit override.
    #[must_use]
    pub fn bypass_incoming_followers(&self, protected_did: &str) -> bool {
        self.bypass_flags
            .read()
            .get(protected_did)
            .copied()
            .unwrap_or(true)
    }

    /// Checks whether an author is in the protected user's allowlist in $<1\mu s$ memory access.
    #[must_use]
    pub fn is_allowlisted(&self, protected_did: &str, author_did: &str) -> bool {
        self.allowlist
            .read()
            .get(protected_did)
            .is_some_and(|set| set.contains(author_did))
    }

    /// Adds an author to the in-memory allowlist for a protected user.
    pub fn add_to_allowlist(
        &self,
        protected_did: impl Into<String>,
        author_did: impl Into<String>,
    ) {
        self.allowlist
            .write()
            .entry(protected_did.into())
            .or_default()
            .insert(author_did.into());
    }

    /// Removes an author from the in-memory allowlist for a protected user.
    pub fn remove_from_allowlist(&self, protected_did: &str, author_did: &str) -> bool {
        self.allowlist
            .write()
            .get_mut(protected_did)
            .is_some_and(|set| set.remove(author_did))
    }

    /// Evaluates an interaction against the follow graph and allowlist.
    ///
    /// # Performance Guarantee
    /// Executes in $<1\mu s$ (typically 50–90ns) with zero network calls, zero heap allocations,
    /// and zero production panics.
    #[must_use]
    pub fn evaluate(&self, interaction: Interaction) -> GateDecision {
        // Stage 1: Fast-exit self-interaction check (~15ns, $0 cost)
        if interaction.is_self_interaction() {
            return GateDecision::Bypassed {
                reason: BypassReason::SelfInteraction,
                interaction,
            };
        }

        // Stage 2: FollowGraph lookup (~65ns, $0 cost)
        // target_did is the protected user; author_did is the candidate author being checked
        if self
            .follow_graph
            .is_following(&interaction.target_did, &interaction.author_did)
        {
            return GateDecision::Bypassed {
                reason: BypassReason::FollowedAuthor,
                interaction,
            };
        }

        // Stage 2.5: Incoming follower lookup (~65ns, $0 cost), gated by per-user opt-out
        if self.bypass_incoming_followers(&interaction.target_did)
            && self
                .follow_graph
                .is_followed_by(&interaction.target_did, &interaction.author_did)
        {
            return GateDecision::Bypassed {
                reason: BypassReason::FollowerAuthor,
                interaction,
            };
        }

        // Stage 3: Allowlist lookup (~60ns, $0 cost)
        if self.is_allowlisted(&interaction.target_did, &interaction.author_did) {
            return GateDecision::Bypassed {
                reason: BypassReason::AllowlistedAuthor,
                interaction,
            };
        }

        // Stage 4: Author is not followed, not allowlisted, and not self -> forward to classifier
        GateDecision::Candidate(interaction)
    }

    /// Convenience functional filter returning `Some(Interaction)` if candidate, or `None` if dropped.
    #[must_use]
    pub fn filter(&self, interaction: Interaction) -> Option<Interaction> {
        self.evaluate(interaction).into_candidate()
    }

    /// Static stateless evaluation checking an interaction against any [`FollowGraph`] reference.
    #[must_use]
    pub fn check_interaction(interaction: Interaction, follow_graph: &FollowGraph) -> GateDecision {
        // Stage 1: Fast-exit self-interaction check (~15ns, $0 cost)
        if interaction.is_self_interaction() {
            return GateDecision::Bypassed {
                reason: BypassReason::SelfInteraction,
                interaction,
            };
        }

        // Stage 2: FollowGraph lookup (~65ns, $0 cost)
        // target_did is the protected user; author_did is the candidate author being checked
        if follow_graph.is_following(&interaction.target_did, &interaction.author_did) {
            return GateDecision::Bypassed {
                reason: BypassReason::FollowedAuthor,
                interaction,
            };
        }

        // Stage 2.5: Incoming follower lookup (~65ns, $0 cost); defaults to enabled.
        if follow_graph.is_followed_by(&interaction.target_did, &interaction.author_did) {
            return GateDecision::Bypassed {
                reason: BypassReason::FollowerAuthor,
                interaction,
            };
        }

        // Stage 3: Author is not followed and not self -> forward to classifier
        GateDecision::Candidate(interaction)
    }

    /// Static evaluation checking an interaction against a [`FollowGraph`] and an allowlist map.
    #[must_use]
    pub fn check_interaction_with_allowlist(
        interaction: Interaction,
        follow_graph: &FollowGraph,
        allowlist: &HashMap<String, HashSet<String>>,
    ) -> GateDecision {
        if interaction.is_self_interaction() {
            return GateDecision::Bypassed {
                reason: BypassReason::SelfInteraction,
                interaction,
            };
        }

        if follow_graph.is_following(&interaction.target_did, &interaction.author_did) {
            return GateDecision::Bypassed {
                reason: BypassReason::FollowedAuthor,
                interaction,
            };
        }

        if follow_graph.is_followed_by(&interaction.target_did, &interaction.author_did) {
            return GateDecision::Bypassed {
                reason: BypassReason::FollowerAuthor,
                interaction,
            };
        }

        if allowlist
            .get(&interaction.target_did)
            .is_some_and(|set| set.contains(&interaction.author_did))
        {
            return GateDecision::Bypassed {
                reason: BypassReason::AllowlistedAuthor,
                interaction,
            };
        }

        GateDecision::Candidate(interaction)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::matcher::interaction::InteractionType;

    #[test]
    fn test_gate_allowlist_bypass() {
        let follow_graph = Arc::new(FollowGraph::new());
        let gate = NonFollowedGate::new(follow_graph);

        let protected_did = "did:plc:protected";
        let allowlisted_author = "did:plc:friend";
        let unknown_author = "did:plc:unknown";

        gate.add_to_allowlist(protected_did, allowlisted_author);
        assert!(gate.is_allowlisted(protected_did, allowlisted_author));
        assert!(!gate.is_allowlisted(protected_did, unknown_author));

        let allowlisted_interaction = Interaction::new(
            allowlisted_author,
            protected_did,
            InteractionType::DirectReply,
            "at://did:plc:friend/app.bsky.feed.post/123",
            "bafytest",
            "Hello friend!",
        );

        let decision = gate.evaluate(allowlisted_interaction);
        assert_eq!(
            decision.bypass_reason(),
            Some(BypassReason::AllowlistedAuthor)
        );
        assert_eq!(
            BypassReason::AllowlistedAuthor.as_str(),
            "allowlisted_author"
        );

        let unknown_interaction = Interaction::new(
            unknown_author,
            protected_did,
            InteractionType::DirectReply,
            "at://did:plc:unknown/app.bsky.feed.post/456",
            "bafytest2",
            "Who are you?",
        );

        let decision2 = gate.evaluate(unknown_interaction);
        assert!(decision2.is_candidate());

        // Remove from allowlist
        assert!(gate.remove_from_allowlist(protected_did, allowlisted_author));
        assert!(!gate.is_allowlisted(protected_did, allowlisted_author));
    }

    #[test]
    fn test_gate_incoming_follower_bypass() {
        let follow_graph = Arc::new(FollowGraph::new());
        let protected = "did:plc:protected";
        let follower = "did:plc:follower";

        // Follower follows the protected user (incoming), but protected does not follow back.
        follow_graph.add_follower(protected, follower, "rk_in");

        let interaction = Interaction::new(
            follower,
            protected,
            InteractionType::DirectReply,
            "at://did:plc:follower/app.bsky.feed.post/123",
            "bafytest",
            "hey there",
        );

        let gate = NonFollowedGate::new(Arc::clone(&follow_graph));
        let decision = gate.evaluate(interaction.clone());
        assert_eq!(decision.bypass_reason(), Some(BypassReason::FollowerAuthor));
        assert_eq!(BypassReason::FollowerAuthor.as_str(), "follower_author");

        // Opting out disables the incoming-follower bypass.
        gate.set_bypass_incoming_followers(protected, false);
        assert!(!gate.bypass_incoming_followers(protected));
        assert!(gate.evaluate(interaction).is_candidate());

        // Default for unknown users is enabled.
        assert!(gate.bypass_incoming_followers("did:plc:someone_else"));
    }

    #[test]
    fn test_follow_graph_incoming_add_remove() {
        let graph = FollowGraph::new();
        let protected = "did:plc:alice";
        let follower = "did:plc:bob";

        assert!(!graph.is_followed_by(protected, follower));
        graph.add_follower(protected, follower, "rk1");
        assert!(graph.is_followed_by(protected, follower));
        assert_eq!(graph.follower_count(protected), 1);
        // Incoming follow must not be visible as an outgoing follow.
        assert!(!graph.is_following(protected, follower));

        let removed = graph.remove_follower_by_rkey(follower, "rk1");
        assert_eq!(removed.as_deref(), Some(protected));
        assert!(!graph.is_followed_by(protected, follower));
        assert_eq!(graph.follower_count(protected), 0);
    }

    #[test]
    fn test_follow_graph_hydrate_followers_and_clear() {
        let graph = FollowGraph::new();
        let protected = "did:plc:alice";
        let count = graph.hydrate_followers(protected, ["did:plc:a", "did:plc:b"]);
        assert_eq!(count, 2);
        assert!(graph.is_followed_by(protected, "did:plc:a"));
        assert!(graph.is_followed_by(protected, "did:plc:b"));
        graph.clear();
        assert!(!graph.is_followed_by(protected, "did:plc:a"));
    }

    fn candidate() -> Interaction {
        Interaction::mock_test_candidate("did:plc:author", "did:plc:target", "hi")
    }

    #[test]
    fn gate_decision_accessors() {
        let decision = GateDecision::Candidate(candidate());
        assert!(decision.is_candidate());
        assert!(decision.candidate().is_some());
        assert!(decision.bypass_reason().is_none());
        assert!(decision.clone().into_candidate().is_some());

        let bypassed = GateDecision::Bypassed {
            reason: BypassReason::SelfInteraction,
            interaction: candidate(),
        };
        assert!(!bypassed.is_candidate());
        assert!(bypassed.candidate().is_none());
        assert_eq!(
            bypassed.bypass_reason(),
            Some(BypassReason::SelfInteraction)
        );
        assert!(bypassed.into_candidate().is_none());
    }

    #[test]
    fn gate_allowlist_accessors_and_flags() {
        let graph = Arc::new(FollowGraph::new());
        let gate = NonFollowedGate::new(Arc::clone(&graph));
        assert!(gate.follow_graph().is_empty());
        assert!(!gate.is_allowlisted("did:plc:t", "did:plc:a"));

        gate.add_to_allowlist("did:plc:t", "did:plc:a");
        assert!(gate.is_allowlisted("did:plc:t", "did:plc:a"));
        assert!(gate.allowlist().read().contains_key("did:plc:t"));
        assert!(gate.remove_from_allowlist("did:plc:t", "did:plc:a"));
        assert!(!gate.remove_from_allowlist("did:plc:t", "did:plc:missing"));

        // Bypass flag defaults true and can be overridden.
        assert!(gate.bypass_incoming_followers("did:plc:t"));
        gate.set_bypass_incoming_followers("did:plc:t", false);
        assert!(!gate.bypass_incoming_followers("did:plc:t"));
        assert!(gate.bypass_flags().read().contains_key("did:plc:t"));
    }

    #[test]
    fn gate_new_with_shared_allowlist_observes_preloaded_entries() {
        let graph = Arc::new(FollowGraph::new());
        let mut map = HashMap::new();
        map.insert(
            "did:plc:t".to_string(),
            std::iter::once("did:plc:preloaded".to_string()).collect(),
        );
        let allowlist = Arc::new(RwLock::new(map));
        let gate = NonFollowedGate::new_with_allowlist(Arc::clone(&graph), Arc::clone(&allowlist));
        assert!(gate.is_allowlisted("did:plc:t", "did:plc:preloaded"));

        // evaluate() bypasses the preloaded author via allowlist.
        let mut i = candidate();
        i.target_did = "did:plc:t".to_string();
        i.author_did = "did:plc:preloaded".to_string();
        let decision = gate.evaluate(i);
        assert_eq!(
            decision.bypass_reason(),
            Some(BypassReason::AllowlistedAuthor)
        );
    }

    #[test]
    fn gate_filter_returns_option() {
        let graph = Arc::new(FollowGraph::new());
        let gate = NonFollowedGate::new(graph);
        assert!(gate.filter(candidate()).is_some());
    }

    #[test]
    fn static_check_interaction_variants() {
        let graph = FollowGraph::new();
        // Self interaction bypassed.
        let mut self_i = candidate();
        self_i.target_did = self_i.author_did.clone();
        assert_eq!(
            NonFollowedGate::check_interaction(self_i, &graph).bypass_reason(),
            Some(BypassReason::SelfInteraction)
        );

        // Followed author bypassed.
        graph.add_follow("did:plc:target", "rk", "did:plc:author");
        assert_eq!(
            NonFollowedGate::check_interaction(candidate(), &graph).bypass_reason(),
            Some(BypassReason::FollowedAuthor)
        );

        // Incoming follower bypassed (on a fresh graph).
        let graph2 = FollowGraph::new();
        graph2.add_follower("did:plc:target", "did:plc:author", "rk");
        assert_eq!(
            NonFollowedGate::check_interaction(candidate(), &graph2).bypass_reason(),
            Some(BypassReason::FollowerAuthor)
        );

        // Plain candidate.
        let graph3 = FollowGraph::new();
        assert!(NonFollowedGate::check_interaction(candidate(), &graph3).is_candidate());
    }

    #[test]
    fn static_check_interaction_with_allowlist_covers_all_stages() {
        let graph = FollowGraph::new();
        let allowlist = HashMap::new();
        assert!(
            NonFollowedGate::check_interaction_with_allowlist(candidate(), &graph, &allowlist)
                .is_candidate()
        );

        let mut allow = HashMap::new();
        allow.insert(
            "did:plc:target".to_string(),
            std::iter::once("did:plc:author".to_string()).collect(),
        );
        assert_eq!(
            NonFollowedGate::check_interaction_with_allowlist(candidate(), &graph, &allow)
                .bypass_reason(),
            Some(BypassReason::AllowlistedAuthor)
        );
    }
}
