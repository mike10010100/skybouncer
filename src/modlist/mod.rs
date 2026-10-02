//! Sovereign ATProto moderation list management, PDS mutations, and SQLite deduplication.
//!
//! Coordinates cache-first moderation list provisioning, violator bouncing via
//! `app.bsky.graph.listitem` records, and pardoning via `deleteRecord`.

pub mod cache;
pub mod manager;

pub use cache::{BouncedUser, DeduplicationCache, ModListConfig};
pub use manager::{ModListManager, DEFAULT_MOD_LIST_DESCRIPTION, DEFAULT_MOD_LIST_NAME};
