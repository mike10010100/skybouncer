//! Target matching, interaction extraction, and non-followed bypass gate.

pub mod follow_graph;
pub mod gate;
pub mod interaction;
pub mod target;

pub use follow_graph::{FollowGraph, FollowSyncEvent};
pub use gate::{BypassReason, GateDecision, NonFollowedGate};
pub use interaction::{
    extract_did_for_collection, extract_did_from_at_uri, Interaction, InteractionType,
};
pub use target::TargetMatcher;
