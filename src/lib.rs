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

#[cfg(feature = "web")]
pub mod app;
#[cfg(feature = "bot")]
pub mod bot;
pub mod classifier;
pub mod cli;
pub mod crypto;
#[cfg(all(
    feature = "web",
    feature = "stream",
    feature = "bot",
    feature = "telemetry"
))]
pub mod daemon;
pub mod dogpile;
pub mod engine;
pub mod enricher;
pub mod env;
pub mod error;
pub mod limiter;
pub mod matcher;
pub mod modlist;
#[cfg(feature = "stream")]
pub mod stream;
pub mod tenant;
pub mod time;
pub mod types;
pub mod util;
#[cfg(feature = "web")]
pub mod web;

pub use crypto::SessionCipher;
pub use tenant::{
    Tenant, TenantRegistry, DEFAULT_HANDLE_TTL, DEFAULT_REAUTH_REMINDER_INTERVAL,
    MAX_REAUTH_NOTIFICATIONS,
};

#[cfg(feature = "bot")]
pub use bot::{
    account_label, account_label_with_url, bsky_post_or_web_url, bsky_post_url,
    bsky_post_url_from_at_uri, bsky_profile_url, command_target, extract_link_facets,
    format_bounce_alert, format_reauth_alert, format_reauth_alert_with_count, format_storm_alert,
    format_storm_digest, run_bot_poller, run_bounce_alert_dispatcher, run_reauth_alert_dispatcher,
    run_storm_alert_dispatcher, run_storm_digest_dispatcher, AcceptConvoRequest,
    AcceptConvoResponse, BotCommandHandler, ChatClient, ConvoMember, ConvoView, FacetIndex,
    GetMessagesResponse, ListConvoRequestsResponse, ListConvosResponse, MessageSender, MessageView,
    SendMessagePayload, SendMessageRequest, UpdateReadRequest, BSKY_WEB_ORIGIN,
    DEFAULT_BOT_POLL_INTERVAL, DEFAULT_CHAT_ENDPOINT,
};
pub use enricher::{
    compute_reply_timing_signals, decode_tid_timestamp_us, extract_fundraiser_urls_from_text,
    extract_rkey_from_at_uri, parse_iso8601_utc_secs, AppViewContextEnricher,
    AuthorActivitySignals, AuthorContext, ContextEnricher, ContextImageRef, EnrichedContext,
    MockContextEnricher, NoopContextEnricher, ParentPostContext, PostEmbedSummary, QuotedAncestor,
    ThreadPost, AUTHOR_FEED_RECENT_LIMIT, AUTHOR_FEED_TOP_LIMIT, DEFAULT_APPVIEW_ENDPOINT,
    DEFAULT_ENRICHER_TIMEOUT_MS, FAST_REPLY_LATENCY_MS, FORGED_TID_DRIFT_SECS, MAX_CONTEXT_IMAGES,
    MAX_OTHER_REPLY_SNIPPETS, MAX_POST_IMAGES, MAX_PROFILE_FUNDRAISER_URLS,
    MAX_RENDERED_THREAD_ANCESTORS, REPLY_BLAST_MIN_DISTINCT_TARGETS, REPLY_BLAST_WINDOW_SECS,
    THREAD_ANCESTOR_CHAR_CAP,
};
pub use limiter::{
    EvaluationRateLimiter, RateLimiterConfig, DEFAULT_MAX_EVALUATIONS_PER_WINDOW,
    DEFAULT_RATE_LIMIT_WINDOW,
};
#[cfg(feature = "stream")]
pub use stream::{run_jetstream_streamer, StreamConfig, DEFAULT_JETSTREAM_ENDPOINT};
#[cfg(feature = "web")]
pub use web::{
    create_web_router, get_prometheus_metrics, run_web_server, AddAllowlistRequest,
    AddAllowlistResponse, AllowlistQuery, ApiState, BouncedUserWithHandle, BouncesQuery,
    DetachQuotesRequest, DismissStormRequest, DismissStormResponse, EvaluationsQuery,
    EvaluationsResponse, GuestRateLimitDecision, GuestSandboxLimiter, GuestSimulateRequest,
    GuestSimulateResponse, LockThreadRequest, LoginQuery, OAuthState, PardonRequest,
    PardonResponse, RemoveAllowlistResponse, ResolveQuery, ResolveResponse, RulesResponse,
    ShieldActionResponse, SimulateRequest, SimulateResponse, StatusResponse, StormModeRequest,
    StormModeResponse, StormsQuery, StormsResponse, UnlockThreadRequest, UpdateRulesRequest,
    UpgradeBounceRequest, UpgradeBounceResponse, WebServerConfig, DEFAULT_WEB_HOST,
    DEFAULT_WEB_PORT,
};

pub use classifier::{
    BounceDuration, Classifier, DynamicModelPolicy, DynamicPrimaryClassifier, DynamicPrimaryStats,
    DynamicPrimaryStatsSnapshot, HeuristicClassifier, HeuristicRule, JevClassifier, JevConfig,
    MockClassifier, OllamaChatOptions, RuleRubric, Sensitivity, Verdict, ViolationCategory,
    DEFAULT_MULTIMODAL_PRIMARY_MODEL, DEFAULT_OLLAMA_NUM_CTX, DEFAULT_TEXT_ONLY_PRIMARY_MODEL,
};
pub use dogpile::{
    apply_postgate_detach, apply_threadgate, canonical_focal_post_uri, compute_burst_acceleration,
    compute_composite_score, compute_direct_ratio, compute_dunk_ratio, compute_power_asymmetry,
    compute_structural_score, parse_owned_post_uri, remove_threadgate, severity_from_score,
    CatalystInfo, DigestBounceSummary, DogpileConfig, DogpileTracker, LlmStormStanceClassifier,
    MockStormStanceClassifier, NoopStormStanceClassifier, PostEngagementSnapshot, PostgateRecord,
    SampleReply, StormDigestNotification, StormEvent, StormMetrics, StormNotification,
    StormSeverity, StormStanceClassifier, StormStanceInput, StormStanceVerdict, StormStatus,
    SurgeCandidate, ThreadgatePolicy, ThreadgateRecord, MAX_DETACHED_EMBEDDING_URIS,
};
pub use engine::{
    simulate::{SimulateTierStage, SimulationInputs, SimulationResult},
    BounceNotification, EngineStats, EngineStatsSnapshot, InteractionOutcome, ProcessCommitResult,
    ProcessOutcome, ReauthNotification, SkybouncerConfig, SkybouncerEngine,
    SkybouncerEngineBuilder, SovereignConfigSyncEvent, DEFAULT_ENGINE_CHANNEL_CAPACITY,
    DEFAULT_EVALUATION_CACHE_TTL, DEFAULT_EVALUATION_CONCURRENCY,
    DEFAULT_EVALUATION_QUEUE_CAPACITY, DEFAULT_MAINTENANCE_INTERVAL, DEFAULT_SHUTDOWN_TIMEOUT,
};
pub use error::SkybouncerError;
pub use matcher::{
    extract_did_for_collection, extract_did_from_at_uri, BypassReason, FollowGraph,
    FollowSyncEvent, GateDecision, Interaction, InteractionType, NonFollowedGate, TargetMatcher,
};
pub use modlist::{
    extract_rubric_from_list_description, fetch_sovereign_config,
    format_list_description_with_rubric, publish_sovereign_config, AllowlistEntry, ArchivedBounce,
    BounceRequest, BouncedUser, DeduplicationCache, ManualBounceOutcome, ModListConfig,
    ModListManager, SovereignConfigRecord, DEFAULT_MOD_LIST_DESCRIPTION, DEFAULT_MOD_LIST_NAME,
    SOVEREIGN_CONFIG_COLLECTION, SOVEREIGN_CONFIG_RKEY,
};
pub use types::{
    format_system_time_iso8601, now_iso8601, ByteSlice, Embed, Facet, FacetFeature, FollowRecord,
    ListItemRecord, ListRecordsResponse, ModListRecord, PostRecord, RecordEmbed,
    RecordWithMediaEmbed, ReplyRef, RepoRecordItem, StrongRef,
};
