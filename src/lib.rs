//! # Skybouncer
//!
//! Sovereign, rule-driven automated moderation and bouncer service for the AT Protocol (ATProto) and Bluesky.
//!
//! `skybouncer` continuously monitors incoming interactions (mentions, replies, quotes) targeting protected users,
//! evaluates candidate interactions against user-defined rule rubrics via low-latency System-1 classifiers (Jev),
//! and automatically mutates ATProto Moderation Lists (`app.bsky.graph.listitem`) to shield users from harassment,
//! bad-faith sea-lioning, and crypto spam.

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    missing_docs,
    rust_2018_idioms
)]

pub mod classifier;
pub mod engine;
pub mod error;
pub mod matcher;
pub mod modlist;
pub mod stream;
pub mod types;

pub use stream::{run_jetstream_streamer, StreamConfig, DEFAULT_JETSTREAM_ENDPOINT};

pub use classifier::{
    Classifier, HeuristicClassifier, HeuristicRule, JevClassifier, JevConfig, MockClassifier,
    RuleRubric, Sensitivity, Verdict, ViolationCategory,
};
pub use engine::{
    EngineStats, EngineStatsSnapshot, InteractionOutcome, ProcessCommitResult, ProcessOutcome,
    SkybouncerConfig, SkybouncerEngine, SkybouncerEngineBuilder, DEFAULT_ENGINE_CHANNEL_CAPACITY,
    DEFAULT_EVALUATION_CACHE_TTL, DEFAULT_MAINTENANCE_INTERVAL, DEFAULT_SHUTDOWN_TIMEOUT,
};
pub use error::SkybouncerError;
pub use matcher::{
    extract_did_for_collection, extract_did_from_at_uri, BypassReason, FollowGraph,
    FollowSyncEvent, GateDecision, Interaction, InteractionType, NonFollowedGate, TargetMatcher,
};
pub use modlist::{
    BouncedUser, DeduplicationCache, ModListConfig, ModListManager, DEFAULT_MOD_LIST_DESCRIPTION,
    DEFAULT_MOD_LIST_NAME,
};
pub use types::{
    format_system_time_iso8601, now_iso8601, ByteSlice, Embed, Facet, FacetFeature, FollowRecord,
    ListItemRecord, ListRecordsResponse, ModListRecord, PostRecord, RecordEmbed,
    RecordWithMediaEmbed, ReplyRef, RepoRecordItem, StrongRef,
};
