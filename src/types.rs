//! ATProto Lexicon data models for `skybouncer`.
//!
//! The record and rich-text models now live in [`skybase::lexicon`]; this module
//! re-exports them for crate-internal and public use, and retains the
//! skybouncer-specific serde helpers.

pub use skybase::lexicon::{
    extract_link_facets, format_system_time_iso8601, now_iso8601, ByteSlice, Embed, Facet,
    FacetFeature, FacetIndex, FollowRecord, ListBlockRecord, ListItemRecord, ListRecordsResponse,
    ModListRecord, PostRecord, RecordEmbed, RecordWithMediaEmbed, ReplyRef, RepoRecordItem,
    StrongRef,
};

/// Returns `true`, used as the serde default for opt-out moderation bypass flags.
pub(crate) fn default_true() -> bool {
    true
}

/// Returns whether the flag is `true`, used to omit the default value during serialization.
pub(crate) fn is_true(value: &bool) -> bool {
    *value
}
