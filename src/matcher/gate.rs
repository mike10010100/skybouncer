//! Non-Followed Direct Interaction Gate.
//!
//! Enforces the sub-microsecond ($<1\mu s$), zero-cost ($0 network/DB calls) filter
//! dropping self-interactions and interactions from followed accounts before any
//! classifier is invoked.

use crate::matcher::follow_graph::FollowGraph;
use crate::matcher::interaction::Interaction;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Detailed reason why an incoming interaction bypassed moderation evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassReason {
    /// Interaction is authored by the protected user themselves (self-reply, thread continuation, self-quote).
    SelfInteraction,
    /// Author is actively followed by the protected user.
    FollowedAuthor,
}

impl BypassReason {
    /// Returns the static string representation of this bypass reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SelfInteraction => "self_interaction",
            Self::FollowedAuthor => "followed_author",
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

/// Cost Control Gate evaluating incoming interactions against protected follow graphs.
#[derive(Debug, Clone)]
pub struct NonFollowedGate {
    follow_graph: Arc<FollowGraph>,
}

impl NonFollowedGate {
    /// Creates a new `NonFollowedGate` bound to the given shared [`FollowGraph`].
    #[must_use]
    pub fn new(follow_graph: Arc<FollowGraph>) -> Self {
        Self { follow_graph }
    }

    /// Returns a reference to the underlying follow graph.
    #[must_use]
    pub fn follow_graph(&self) -> &FollowGraph {
        &self.follow_graph
    }

    /// Evaluates an interaction against the follow graph.
    ///
    /// # Performance Guarantee
    /// Executes in $<1\mu s$ (typically 50–90ns) with zero network calls, zero heap allocations,
    /// and zero production panics.
    #[must_use]
    pub fn evaluate(&self, interaction: Interaction) -> GateDecision {
        Self::check_interaction(interaction, &self.follow_graph)
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
}
