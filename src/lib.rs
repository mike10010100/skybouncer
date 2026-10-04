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

pub mod bot;
pub mod classifier;
pub mod crypto;
pub mod engine;
pub mod enricher;
pub mod error;
pub mod limiter;
pub mod matcher;
pub mod modlist;
pub mod stream;
pub mod tenant;
pub mod types;
pub mod web;

pub use crypto::SessionCipher;
pub use tenant::{Tenant, TenantRegistry};

pub use bot::{
    format_bounce_alert, run_bot_poller, run_bounce_alert_dispatcher, AcceptConvoRequest,
    AcceptConvoResponse, BotCommandHandler, ChatClient, ConvoMember, ConvoView,
    GetMessagesResponse, ListConvoRequestsResponse, ListConvosResponse, MessageSender, MessageView,
    SendMessagePayload, SendMessageRequest, UpdateReadRequest, DEFAULT_BOT_POLL_INTERVAL,
    DEFAULT_CHAT_ENDPOINT,
};
pub use enricher::{
    AppViewContextEnricher, AuthorContext, ContextEnricher, EnrichedContext, MockContextEnricher,
    NoopContextEnricher, ParentPostContext, DEFAULT_APPVIEW_ENDPOINT, DEFAULT_ENRICHER_TIMEOUT_MS,
};
pub use limiter::{
    EvaluationRateLimiter, RateLimiterConfig, DEFAULT_MAX_EVALUATIONS_PER_WINDOW,
    DEFAULT_RATE_LIMIT_WINDOW,
};
pub use stream::{run_jetstream_streamer, StreamConfig, DEFAULT_JETSTREAM_ENDPOINT};
pub use web::{
    create_web_router, run_web_server, AddAllowlistRequest, AddAllowlistResponse, AllowlistQuery,
    ApiState, BouncesQuery, LoginQuery, OAuthState, PardonRequest, PardonResponse,
    RemoveAllowlistResponse, RulesResponse, SimulateRequest, SimulateResponse, StatusResponse,
    UpdateRulesRequest, WebServerConfig, DEFAULT_WEB_HOST, DEFAULT_WEB_PORT,
};

pub use classifier::{
    Classifier, HeuristicClassifier, HeuristicRule, JevClassifier, JevConfig, MockClassifier,
    RuleRubric, Sensitivity, Verdict, ViolationCategory,
};
pub use engine::{
    BounceNotification, EngineStats, EngineStatsSnapshot, InteractionOutcome, ProcessCommitResult,
    ProcessOutcome, SkybouncerConfig, SkybouncerEngine, SkybouncerEngineBuilder,
    SovereignConfigSyncEvent, DEFAULT_ENGINE_CHANNEL_CAPACITY, DEFAULT_EVALUATION_CACHE_TTL,
    DEFAULT_EVALUATION_CONCURRENCY, DEFAULT_EVALUATION_QUEUE_CAPACITY,
    DEFAULT_MAINTENANCE_INTERVAL, DEFAULT_SHUTDOWN_TIMEOUT,
};
pub use error::SkybouncerError;
pub use matcher::{
    extract_did_for_collection, extract_did_from_at_uri, BypassReason, FollowGraph,
    FollowSyncEvent, GateDecision, Interaction, InteractionType, NonFollowedGate, TargetMatcher,
};
pub use modlist::{
    extract_rubric_from_list_description, fetch_sovereign_config,
    format_list_description_with_rubric, publish_sovereign_config, AllowlistEntry, BouncedUser,
    DeduplicationCache, ModListConfig, ModListManager, SovereignConfigRecord,
    DEFAULT_MOD_LIST_DESCRIPTION, DEFAULT_MOD_LIST_NAME, SOVEREIGN_CONFIG_COLLECTION,
    SOVEREIGN_CONFIG_RKEY,
};
pub use types::{
    format_system_time_iso8601, now_iso8601, ByteSlice, Embed, Facet, FacetFeature, FollowRecord,
    ListItemRecord, ListRecordsResponse, ModListRecord, PostRecord, RecordEmbed,
    RecordWithMediaEmbed, ReplyRef, RepoRecordItem, StrongRef,
};
