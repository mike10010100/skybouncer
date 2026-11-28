//! Sovereign ATProto moderation list management, PDS mutations, and SQLite deduplication.
//!
//! Coordinates cache-first moderation list provisioning, violator bouncing via
//! `app.bsky.graph.listitem` records, and pardoning via `deleteRecord`.

pub mod cache;
pub mod manager;
pub mod sovereign_config;

pub use cache::{
    AllowlistEntry, ArchivedBounce, BouncedUser, DeduplicationCache, EvaluationLogContext,
    ModListConfig,
};
pub use manager::{
    BounceOutcome, BounceRequest, ManualBounceOutcome, ModListManager,
    DEFAULT_MOD_LIST_DESCRIPTION, DEFAULT_MOD_LIST_NAME,
};
pub use sovereign_config::{
    extract_rubric_from_list_description, fetch_sovereign_config, fetch_sovereign_config_record,
    fetch_sovereign_config_with_cid, format_list_description_with_rubric, publish_sovereign_config,
    publish_sovereign_config_with_options, SovereignConfigRecord, SOVEREIGN_CONFIG_COLLECTION,
    SOVEREIGN_CONFIG_RKEY,
};
