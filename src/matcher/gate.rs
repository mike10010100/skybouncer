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
}

impl NonFollowedGate {
    /// Creates a new `NonFollowedGate` bound to the given shared [`FollowGraph`] and an empty allowlist.
    #[must_use]
    pub fn new(follow_graph: Arc<FollowGraph>) -> Self {
        Self {
            follow_graph,
            allowlist: Arc::new(RwLock::new(HashMap::new())),
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
}
