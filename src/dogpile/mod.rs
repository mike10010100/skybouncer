//! Real-time dogpile, brigade, and quote-cascade detection primitives.
//!
//! Designed as a pure, feature-independent subsystem so the cascade math,
//! sliding-window surge tracker, batch stance verification, and ATProto interaction
//! gate helpers can later be extracted cleanly into a shared crate for network-wide
//! radar (`skydoppler`).

pub mod gates;
pub mod math;
pub mod stance;
pub mod tracker;
pub mod types;

pub use gates::{
    apply_postgate_detach, apply_threadgate, parse_owned_post_uri, remove_threadgate,
    PostgateRecord, ThreadgatePolicy, ThreadgateRecord, MAX_DETACHED_EMBEDDING_URIS,
};
pub use math::{
    canonical_focal_post_uri, compute_burst_acceleration, compute_composite_score,
    compute_direct_ratio, compute_dunk_ratio, compute_power_asymmetry, compute_structural_score,
    severity_from_score,
};
pub use stance::{
    LlmStormStanceClassifier, MockStormStanceClassifier, NoopStormStanceClassifier,
    StormStanceClassifier, StormStanceInput,
};
pub use tracker::DogpileTracker;
pub use types::{
    CatalystInfo, DigestBounceSummary, DogpileConfig, PostEngagementSnapshot, SampleReply,
    StormDigestNotification, StormEvent, StormMetrics, StormNotification, StormSeverity,
    StormStanceVerdict, StormStatus, SurgeCandidate,
};
