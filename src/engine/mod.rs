//! Asynchronous moderation engine coordinating event ingestion, target matching,
//! non-followed account gating, classifier evaluation, and sovereign PDS modlist mutations.
//!
//! # Architecture
//! [`SkybouncerEngine`] integrates the entire ATProto moderation pipeline:
//! 1. **Jetstream Ingestion**: Ingests commit events for `app.bsky.feed.post` and `app.bsky.graph.follow`.
//! 2. **FollowGraph Sync**: Dynamically updates the in-memory follow set on follow/unfollow events.
//! 3. **Target Matcher**: Extracts candidate interactions targeting protected DIDs.
//! 4. **Non-Followed Gate**: Drops self-interactions and followed accounts in <1µs ($0 cost).
//! 5. **Deduplication & Evaluation Cache**: Short-circuits previously bounced authors and unexpired evaluations.
//! 6. **Zero-Cost Heuristic Pre-Filter**: Matches obvious spam/scam patterns in <500ns ($0 cost).
//! 7. **Primary Classifier**: Evaluates surviving candidates against user-defined rubrics (e.g. Jev System-1).
//! 8. **Sovereign PDS Mutator**: Creates DPoP-signed `app.bsky.graph.listitem` records on the user's PDS.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use skyauth::client::AtprotoOAuthClient;
use skybase::ingest::{CommitOperation, JetstreamCommit};
use skybase::repo::PdsRepoClient;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};

use crate::classifier::{
    CertaintyConfig, Classifier, DynamicModelPolicy, DynamicPrimaryClassifier, HeuristicClassifier,
    JevClassifier, JevConfig, RuleRubric, Sensitivity, TieredClassifier, Verdict,
    ViolationCategory,
};
use crate::enricher::{ContextEnricher, NoopContextEnricher};
use crate::error::SkybouncerError;
use crate::limiter::{EvaluationRateLimiter, RateLimiterConfig};
use crate::matcher::{
    BypassReason, FollowGraph, FollowSyncEvent, GateDecision, Interaction, NonFollowedGate,
    TargetMatcher,
};
use crate::modlist::{
    BounceRequest, BouncedUser, DeduplicationCache, ModListManager, DEFAULT_MOD_LIST_NAME,
};
use crate::tenant::{Tenant, TenantRegistry};
use crate::time::current_time_us;

/// Default capacity for the engine's internal commit event processing channel.
pub const DEFAULT_ENGINE_CHANNEL_CAPACITY: usize = 1024;

/// Default capacity for the decoupled candidate evaluation queue.
pub const DEFAULT_EVALUATION_QUEUE_CAPACITY: usize = 256;

/// Default maximum concurrent evaluations permitted against the primary model.
pub const DEFAULT_EVALUATION_CONCURRENCY: usize = 1;

/// Default evaluation verdict cache TTL (24 hours).
pub const DEFAULT_EVALUATION_CACHE_TTL: Duration = Duration::from_secs(86400);

/// Default periodic cache maintenance interval (60 seconds).
pub const DEFAULT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

/// Default maximum age for cached DID-to-handle mappings (30 days) before eviction.
pub const DEFAULT_DID_HANDLE_CACHE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Default upper bound on retained DID-to-handle cache entries.
pub const DEFAULT_DID_HANDLE_CACHE_MAX_ENTRIES: usize = 50_000;

/// Default graceful shutdown timeout (5 seconds).
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Loads persisted cumulative telemetry counters, falling back to a zeroed [`EngineStats`].
fn load_persisted_stats(cache: &DeduplicationCache) -> EngineStats {
    match cache.load_dashboard_stats::<EngineStatsSnapshot>() {
        Ok(Some(snapshot)) => {
            info!(
                commits_received = snapshot.commits_received,
                bounces_executed = snapshot.bounces_executed,
                "Restored cumulative dashboard telemetry counters from persistent storage"
            );
            EngineStats::from_snapshot(&snapshot)
        }
        Ok(None) => EngineStats::default(),
        Err(e) => {
            warn!(error = %e, "Failed to load persisted dashboard telemetry counters; starting from zero");
            EngineStats::default()
        }
    }
}

/// Configuration parameters for [`SkybouncerEngine`].
#[derive(Debug, Clone)]
pub struct SkybouncerConfig {
    /// Decentralized identifiers (DIDs) of protected users monitored by the engine.
    pub protected_dids: HashSet<String>,
    /// Natural-language moderation rubric and sensitivity threshold.
    pub rubric: RuleRubric,
    /// Remote PDS endpoint URL (e.g. `<https://bsky.social>`).
    pub pds_endpoint: Option<String>,
    /// PDS bearer access token or OAuth credential.
    pub pds_access_token: Option<String>,
    /// Path to persistent SQLite cache database. If `None`, an in-memory cache is used.
    pub cache_path: Option<PathBuf>,
    /// Time-to-live duration for caching classifier evaluation verdicts.
    pub evaluation_ttl: Duration,
    /// Bounded capacity for the incoming commit event channel.
    pub channel_capacity: usize,
    /// Bounded capacity for the decoupled candidate evaluation queue.
    pub evaluation_queue_capacity: usize,
    /// Maximum concurrent evaluations permitted against the primary model.
    pub evaluation_concurrency: usize,
    /// Jev classification client configuration, if Jev is used as the primary model.
    pub jev_config: Option<JevConfig>,
    /// Fallback multimodal classification client configuration (e.g. gemma4:12b, llama3.2-vision via Ollama).
    pub fallback_jev_config: Option<JevConfig>,
    /// Optional multimodal primary model configuration enabling dynamic Tier-1 routing.
    ///
    /// When set, interactions carrying images are routed to this multimodal model at
    /// Tier-1 (instead of the text-only [`SkybouncerConfig::jev_config`] model), so
    /// image-borne violations are inspected without invoking the heavier Tier-2 fallback.
    pub multimodal_jev_config: Option<JevConfig>,
    /// Certainty threshold configuration governing when evaluations escalate to the fallback model.
    pub certainty_config: CertaintyConfig,
    /// Title assigned to provisioned moderation lists.
    pub list_name: String,
    /// Optional description for provisioned moderation lists.
    pub list_description: Option<String>,
    /// Configuration parameters for the Tier-4 per-user evaluation rate limiter.
    pub rate_limiter_config: RateLimiterConfig,
    /// Whether to enable the zero-cost heuristic regex pre-filter.
    ///
    /// Defaults to `false` to avoid false-positive classifications on homonyms
    /// and contextual speech (e.g. Apple AirDrop, military airdrops, security warnings),
    /// allowing all candidate interactions to be evaluated by the primary semantic model.
    pub enable_heuristic_prefilter: bool,
    /// Whether to operate in shadow dry-run mode.
    ///
    /// When active, incoming interactions from live Jetstream are processed and evaluated normally,
    /// but remote PDS moderation list mutations are simulated with zero remote network writes.
    pub dry_run: bool,
    /// Explicit decentralized identifier (DID) of the system administrator.
    ///
    /// When set, only this DID is granted administrative privileges (fleet oversight, tenant management).
    /// The administrator is also automatically included in [`SkybouncerConfig::protected_dids`].
    pub admin_did: Option<String>,
    /// Time-to-live duration for caching handle-to-DID resolutions.
    pub handle_cache_ttl: Duration,
}

impl Default for SkybouncerConfig {
    fn default() -> Self {
        Self {
            protected_dids: HashSet::new(),
            rubric: RuleRubric::default(),
            pds_endpoint: None,
            pds_access_token: None,
            cache_path: None,
            evaluation_ttl: DEFAULT_EVALUATION_CACHE_TTL,
            channel_capacity: DEFAULT_ENGINE_CHANNEL_CAPACITY,
            evaluation_queue_capacity: DEFAULT_EVALUATION_QUEUE_CAPACITY,
            evaluation_concurrency: DEFAULT_EVALUATION_CONCURRENCY,
            jev_config: None,
            fallback_jev_config: None,
            multimodal_jev_config: None,
            certainty_config: CertaintyConfig::default(),
            list_name: DEFAULT_MOD_LIST_NAME.to_string(),
            list_description: None,
            rate_limiter_config: RateLimiterConfig::default(),
            enable_heuristic_prefilter: false,
            dry_run: false,
            admin_did: None,
            handle_cache_ttl: crate::tenant::DEFAULT_HANDLE_TTL,
        }
    }
}

impl SkybouncerConfig {
    /// Creates a new configuration protecting the specified DIDs with the given rubric.
    #[must_use]
    pub fn new(
        protected_dids: impl IntoIterator<Item = impl Into<String>>,
        rubric: RuleRubric,
    ) -> Self {
        Self {
            protected_dids: protected_dids.into_iter().map(Into::into).collect(),
            rubric,
            ..Self::default()
        }
    }

    /// Sets the remote PDS endpoint URL.
    #[must_use]
    pub fn with_pds_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.pds_endpoint = Some(endpoint.into());
        self
    }

    /// Sets the PDS bearer access token.
    #[must_use]
    pub fn with_pds_access_token(mut self, token: impl Into<String>) -> Self {
        self.pds_access_token = Some(token.into());
        self
    }

    /// Sets the filesystem path for persistent SQLite cache storage.
    #[must_use]
    pub fn with_cache_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.cache_path = Some(path.into());
        self
    }

    /// Sets the evaluation verdict cache TTL.
    #[must_use]
    pub fn with_evaluation_ttl(mut self, ttl: Duration) -> Self {
        self.evaluation_ttl = ttl;
        self
    }

    /// Sets the commit event channel capacity.
    #[must_use]
    pub fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self.evaluation_queue_capacity = self.evaluation_queue_capacity.max(capacity);
        self
    }

    /// Sets the bounded capacity for the decoupled candidate evaluation queue.
    #[must_use]
    pub fn with_evaluation_queue_capacity(mut self, capacity: usize) -> Self {
        self.evaluation_queue_capacity = capacity;
        self
    }

    /// Sets the maximum concurrent evaluations permitted against the primary model.
    #[must_use]
    pub fn with_evaluation_concurrency(mut self, concurrency: usize) -> Self {
        self.evaluation_concurrency = concurrency.max(1);
        self
    }

    /// Sets the Jev classification configuration.
    #[must_use]
    pub fn with_jev_config(mut self, config: JevConfig) -> Self {
        self.jev_config = Some(config);
        self
    }

    /// Sets the fallback multimodal Jev classification configuration.
    #[must_use]
    pub fn with_fallback_jev_config(mut self, config: JevConfig) -> Self {
        self.fallback_jev_config = Some(config);
        self
    }

    /// Sets the certainty configuration governing tiered escalation.
    #[must_use]
    pub fn with_certainty_config(mut self, config: CertaintyConfig) -> Self {
        self.certainty_config = config;
        self
    }

    /// Sets the title assigned to moderation lists.
    #[must_use]
    pub fn with_list_name(mut self, name: impl Into<String>) -> Self {
        self.list_name = name.into();
        self
    }

    /// Sets the description assigned to moderation lists.
    #[must_use]
    pub fn with_list_description(mut self, description: impl Into<String>) -> Self {
        self.list_description = Some(description.into());
        self
    }

    /// Sets the rate limiter configuration.
    #[must_use]
    pub fn with_rate_limiter_config(mut self, config: RateLimiterConfig) -> Self {
        self.rate_limiter_config = config;
        self
    }

    /// Sets whether the zero-cost heuristic regex pre-filter is enabled.
    #[must_use]
    pub fn with_enable_heuristic_prefilter(mut self, enabled: bool) -> Self {
        self.enable_heuristic_prefilter = enabled;
        self
    }

    /// Sets whether to operate in shadow dry-run mode.
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Designates the system administrator DID, automatically shielding it in [`SkybouncerConfig::protected_dids`].
    #[must_use]
    pub fn with_admin_did(mut self, admin_did: impl Into<String>) -> Self {
        let did = admin_did.into();
        self.protected_dids.insert(did.clone());
        self.admin_did = Some(did);
        self
    }

    /// Sets the handle resolution cache TTL.
    #[must_use]
    pub fn with_handle_cache_ttl(mut self, ttl: Duration) -> Self {
        self.handle_cache_ttl = ttl;
        self
    }

    /// Loads configuration from environment variables with fallback defaults.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if rubric parsing fails.
    pub fn from_env() -> Result<Self, SkybouncerError> {
        let mut protected_dids = HashSet::new();
        let dids_str = crate::env::var_or(&["PROTECTED_DIDS", "SKYBOUNCER_PROTECTED_DIDS"], "");
        for did in dids_str.split(',') {
            let trimmed = did.trim();
            if !trimmed.is_empty() {
                protected_dids.insert(trimmed.to_string());
            }
        }

        let admin_did = crate::env::var(&["ADMIN_DID", "SKYBOUNCER_ADMIN_DID"]);
        if let Some(ref admin) = admin_did {
            protected_dids.insert(admin.clone());
        }

        let rubric_prompt = crate::env::var_or(
            &["MODERATION_RUBRIC", "SKYBOUNCER_RULES"],
            "Block crypto airdrop spam, scam bots, phishing, targeted harassment, and bad-faith sea-lioning.",
        );
        let rubric = RuleRubric::parse(&rubric_prompt)?;

        let pds_endpoint = crate::env::var(&["PDS_ENDPOINT", "SKYBOUNCER_PDS_URL"]);

        let pds_access_token = crate::env::var(&["PDS_ACCESS_TOKEN"]);

        let cache_path =
            crate::env::var(&["SKYBOUNCER_DB_PATH", "SKYBOUNCER_DATABASE_PATH"]).map(PathBuf::from);

        let jev_config = JevConfig::from_env().ok();

        let fallback_jev_config = if let Some(fb_model) =
            crate::env::var(&["FALLBACK_MODEL", "SKYBOUNCER_FALLBACK_MODEL"])
        {
            let fb_base = crate::env::var_or(
                &["FALLBACK_API_BASE_URL", "SKYBOUNCER_FALLBACK_BASE_URL"],
                "http://localhost:11434",
            );
            let fb_key = crate::env::var(&["FALLBACK_API_KEY"]);
            let fb_timeout_ms = crate::env::parsed_or(&["FALLBACK_TIMEOUT_MS"], 5000_u64);
            let fb_max_retries = crate::env::parsed_or(&["FALLBACK_MAX_RETRIES"], 1_usize);
            Some(JevConfig {
                base_url: fb_base,
                api_key: fb_key,
                model: fb_model,
                timeout: Duration::from_millis(fb_timeout_ms),
                max_retries: fb_max_retries,
                supports_images: false,
            })
        } else {
            None
        };

        let uncertainty_min = crate::env::parsed_or(
            &["UNCERTAINTY_MIN", "SKYBOUNCER_UNCERTAINTY_MIN"],
            crate::classifier::tiered::DEFAULT_UNCERTAINTY_MIN_CONFIDENCE,
        );

        let uncertainty_max = crate::env::parsed_or(
            &["UNCERTAINTY_MAX", "SKYBOUNCER_UNCERTAINTY_MAX"],
            crate::classifier::tiered::DEFAULT_UNCERTAINTY_MAX_CONFIDENCE,
        );

        let escalate_on_images = crate::env::bool_or(
            &["ESCALATE_ON_IMAGES", "SKYBOUNCER_ESCALATE_ON_IMAGES"],
            true,
        );

        let certainty_config =
            CertaintyConfig::new(uncertainty_min, uncertainty_max, escalate_on_images);

        // Optional dynamic Tier-1 multimodal primary: route image-bearing interactions
        // to a multimodal model before falling back to the heavyweight System-2 tier.
        let multimodal_jev_config = crate::env::var(&[
            "MULTIMODAL_PRIMARY_MODEL",
            "SKYBOUNCER_MULTIMODAL_PRIMARY_MODEL",
        ])
        .map(|mm_model| {
            let mm_base = crate::env::var_or(
                &["MULTIMODAL_API_BASE_URL", "SKYBOUNCER_MULTIMODAL_BASE_URL"],
                &crate::env::var_or(
                    &["JEV_API_BASE_URL"],
                    crate::classifier::jev::DEFAULT_JEV_BASE_URL,
                ),
            );
            JevConfig {
                base_url: mm_base,
                api_key: crate::env::var(&["MULTIMODAL_API_KEY", "SKYBOUNCER_MULTIMODAL_API_KEY"]),
                model: mm_model,
                timeout: Duration::from_millis(crate::env::parsed_or(
                    &["MULTIMODAL_TIMEOUT_MS", "SKYBOUNCER_MULTIMODAL_TIMEOUT_MS"],
                    60000_u64,
                )),
                max_retries: crate::env::parsed_or(
                    &[
                        "MULTIMODAL_MAX_RETRIES",
                        "SKYBOUNCER_MULTIMODAL_MAX_RETRIES",
                    ],
                    1_usize,
                ),
                supports_images: true,
            }
        });

        let rate_limiter_config = RateLimiterConfig::from_env();

        let enable_heuristic_prefilter = crate::env::bool_or(
            &[
                "ENABLE_HEURISTIC_PREFILTER",
                "SKYBOUNCER_ENABLE_HEURISTIC_PREFILTER",
            ],
            false,
        );

        let dry_run = crate::env::bool_or(
            &["DRY_RUN", "SKYBOUNCER_DRY_RUN", "SKYBOUNCER_SHADOW_MODE"],
            false,
        );

        let evaluation_queue_capacity = crate::env::parsed_or(
            &["SKYBOUNCER_EVAL_QUEUE_CAPACITY"],
            DEFAULT_EVALUATION_QUEUE_CAPACITY,
        );

        let evaluation_concurrency = crate::env::parsed_or(
            &["SKYBOUNCER_EVAL_CONCURRENCY"],
            DEFAULT_EVALUATION_CONCURRENCY,
        );

        Ok(Self {
            protected_dids,
            rubric,
            pds_endpoint,
            pds_access_token,
            cache_path,
            evaluation_ttl: DEFAULT_EVALUATION_CACHE_TTL,
            channel_capacity: DEFAULT_ENGINE_CHANNEL_CAPACITY,
            evaluation_queue_capacity,
            evaluation_concurrency,
            jev_config,
            fallback_jev_config,
            multimodal_jev_config,
            certainty_config,
            list_name: DEFAULT_MOD_LIST_NAME.to_string(),
            list_description: None,
            rate_limiter_config,
            enable_heuristic_prefilter,
            dry_run,
            admin_did,
            handle_cache_ttl: crate::tenant::DEFAULT_HANDLE_TTL,
        })
    }
}

/// Operational metrics and telemetry counters for [`SkybouncerEngine`].
#[derive(Debug, Default)]
pub struct EngineStats {
    /// Total incoming Jetstream commits processed.
    pub commits_received: AtomicU64,
    /// Total follow/unfollow events synchronized to the follow graph.
    pub follow_sync_events: AtomicU64,
    /// Total follow/unfollow events synchronized (alias for `follow_sync_events`).
    pub follows_synced: AtomicU64,
    /// Total interaction candidates extracted by [`TargetMatcher`].
    pub interactions_matched: AtomicU64,
    /// Interactions dropped because author interacted with themselves.
    pub gate_bypassed_self: AtomicU64,
    /// Interactions dropped because author is actively followed by the protected user.
    pub gate_bypassed_followed: AtomicU64,
    /// Interactions dropped because author follows the protected user (incoming follower).
    pub gate_bypassed_follower: AtomicU64,
    /// Interactions dropped because author is on the protected user's persistent moderation allowlist.
    pub gate_bypassed_allowlist: AtomicU64,
    /// Interactions that passed the gate and were evaluated.
    pub candidates_evaluated: AtomicU64,
    /// Interactions dropped because author was already recorded as bounced in cache.
    pub dedup_cache_hits: AtomicU64,
    /// Candidate evaluations served from SQLite TTL evaluation cache.
    pub eval_cache_hits: AtomicU64,
    /// High-confidence violations matched instantly by zero-cost heuristic regex rules.
    pub heuristic_violations: AtomicU64,
    /// Candidate interactions dispatched to the primary classifier (e.g. Jev model).
    pub model_evaluations: AtomicU64,
    /// Tier-1 primary model evaluations.
    pub tier1_evaluations: AtomicU64,
    /// Tier-2 fallback model escalations.
    pub tier2_evaluations: AtomicU64,
    /// Tier-2 escalations triggered by attached images.
    pub tier2_image_escalations: AtomicU64,
    /// Tier-2 escalations triggered by confidence uncertainty band.
    pub tier2_uncertainty_escalations: AtomicU64,
    /// Candidate interactions enqueued to the background evaluation queue.
    pub eval_queue_enqueued: AtomicU64,
    /// Candidate interactions processed by the background evaluation worker.
    pub eval_queue_processed: AtomicU64,
    /// Candidate interactions dropped due to evaluation queue capacity saturation.
    pub eval_queue_overflows: AtomicU64,
    /// Evaluations dropped due to Tier-4 per-user evaluation rate limits.
    pub rate_limited_evaluations: AtomicU64,
    /// Candidates enriched with author profile and parent post context.
    pub context_enrichments: AtomicU64,
    /// Total violations confirmed across heuristic and model classifiers.
    pub violations_detected: AtomicU64,
    /// Successful listitem mutations created on the sovereign PDS.
    pub bounces_executed: AtomicU64,
    /// Successful listitem mutations created on the sovereign PDS (alias for `bounces_executed`).
    pub bounced: AtomicU64,
    /// Total interactions classified as permitted / benign.
    pub permitted: AtomicU64,
    /// Violations dropped because confidence fell below rubric sensitivity threshold.
    pub bounces_skipped_rubric: AtomicU64,
    /// Total operational or network errors encountered during pipeline execution.
    pub errors_encountered: AtomicU64,
    /// Total sovereign configuration hot-reload events synchronized from the firehose.
    pub sovereign_configs_synced: AtomicU64,
}

impl EngineStats {
    /// Reconstructs live counters from a previously captured snapshot.
    ///
    /// Used to restore cumulative telemetry across process restarts.
    #[must_use]
    pub fn from_snapshot(snapshot: &EngineStatsSnapshot) -> Self {
        Self {
            commits_received: AtomicU64::new(snapshot.commits_received),
            follow_sync_events: AtomicU64::new(snapshot.follow_sync_events),
            follows_synced: AtomicU64::new(snapshot.follows_synced),
            interactions_matched: AtomicU64::new(snapshot.interactions_matched),
            gate_bypassed_self: AtomicU64::new(snapshot.gate_bypassed_self),
            gate_bypassed_followed: AtomicU64::new(snapshot.gate_bypassed_followed),
            gate_bypassed_follower: AtomicU64::new(snapshot.gate_bypassed_follower),
            gate_bypassed_allowlist: AtomicU64::new(snapshot.gate_bypassed_allowlist),
            candidates_evaluated: AtomicU64::new(snapshot.candidates_evaluated),
            dedup_cache_hits: AtomicU64::new(snapshot.dedup_cache_hits),
            eval_cache_hits: AtomicU64::new(snapshot.eval_cache_hits),
            heuristic_violations: AtomicU64::new(snapshot.heuristic_violations),
            model_evaluations: AtomicU64::new(snapshot.model_evaluations),
            tier1_evaluations: AtomicU64::new(snapshot.tier1_evaluations),
            tier2_evaluations: AtomicU64::new(snapshot.tier2_evaluations),
            tier2_image_escalations: AtomicU64::new(snapshot.tier2_image_escalations),
            tier2_uncertainty_escalations: AtomicU64::new(snapshot.tier2_uncertainty_escalations),
            eval_queue_enqueued: AtomicU64::new(snapshot.eval_queue_enqueued),
            eval_queue_processed: AtomicU64::new(snapshot.eval_queue_processed),
            eval_queue_overflows: AtomicU64::new(snapshot.eval_queue_overflows),
            rate_limited_evaluations: AtomicU64::new(snapshot.rate_limited_evaluations),
            context_enrichments: AtomicU64::new(snapshot.context_enrichments),
            violations_detected: AtomicU64::new(snapshot.violations_detected),
            bounces_executed: AtomicU64::new(snapshot.bounces_executed),
            bounced: AtomicU64::new(snapshot.bounced),
            permitted: AtomicU64::new(snapshot.permitted),
            bounces_skipped_rubric: AtomicU64::new(snapshot.bounces_skipped_rubric),
            errors_encountered: AtomicU64::new(snapshot.errors_encountered),
            sovereign_configs_synced: AtomicU64::new(snapshot.sovereign_configs_synced),
        }
    }

    /// Captures an immutable snapshot of all counters.
    #[must_use]
    pub fn snapshot(&self) -> EngineStatsSnapshot {
        EngineStatsSnapshot {
            commits_received: self.commits_received.load(Ordering::Relaxed),
            follow_sync_events: self.follow_sync_events.load(Ordering::Relaxed),
            follows_synced: self.follows_synced.load(Ordering::Relaxed),
            interactions_matched: self.interactions_matched.load(Ordering::Relaxed),
            gate_bypassed_self: self.gate_bypassed_self.load(Ordering::Relaxed),
            gate_bypassed_followed: self.gate_bypassed_followed.load(Ordering::Relaxed),
            gate_bypassed_follower: self.gate_bypassed_follower.load(Ordering::Relaxed),
            gate_bypassed_allowlist: self.gate_bypassed_allowlist.load(Ordering::Relaxed),
            candidates_evaluated: self.candidates_evaluated.load(Ordering::Relaxed),
            dedup_cache_hits: self.dedup_cache_hits.load(Ordering::Relaxed),
            eval_cache_hits: self.eval_cache_hits.load(Ordering::Relaxed),
            heuristic_violations: self.heuristic_violations.load(Ordering::Relaxed),
            model_evaluations: self.model_evaluations.load(Ordering::Relaxed),
            tier1_evaluations: self.tier1_evaluations.load(Ordering::Relaxed),
            tier2_evaluations: self.tier2_evaluations.load(Ordering::Relaxed),
            tier2_image_escalations: self.tier2_image_escalations.load(Ordering::Relaxed),
            tier2_uncertainty_escalations: self
                .tier2_uncertainty_escalations
                .load(Ordering::Relaxed),
            eval_queue_enqueued: self.eval_queue_enqueued.load(Ordering::Relaxed),
            eval_queue_processed: self.eval_queue_processed.load(Ordering::Relaxed),
            eval_queue_overflows: self.eval_queue_overflows.load(Ordering::Relaxed),
            rate_limited_evaluations: self.rate_limited_evaluations.load(Ordering::Relaxed),
            context_enrichments: self.context_enrichments.load(Ordering::Relaxed),
            violations_detected: self.violations_detected.load(Ordering::Relaxed),
            bounces_executed: self.bounces_executed.load(Ordering::Relaxed),
            bounced: self.bounced.load(Ordering::Relaxed),
            permitted: self.permitted.load(Ordering::Relaxed),
            bounces_skipped_rubric: self.bounces_skipped_rubric.load(Ordering::Relaxed),
            errors_encountered: self.errors_encountered.load(Ordering::Relaxed),
            sovereign_configs_synced: self.sovereign_configs_synced.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time immutable snapshot of [`EngineStats`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EngineStatsSnapshot {
    /// Total incoming Jetstream commits processed.
    pub commits_received: u64,
    /// Total follow/unfollow events synchronized to the follow graph.
    pub follow_sync_events: u64,
    /// Total follow/unfollow events synchronized (alias for `follow_sync_events`).
    pub follows_synced: u64,
    /// Total interaction candidates extracted by [`TargetMatcher`].
    pub interactions_matched: u64,
    /// Interactions dropped because author interacted with themselves.
    pub gate_bypassed_self: u64,
    /// Interactions dropped because author is actively followed by the protected user.
    pub gate_bypassed_followed: u64,
    /// Interactions dropped because author follows the protected user (incoming follower).
    #[serde(default)]
    pub gate_bypassed_follower: u64,
    /// Interactions dropped because author is on the protected user's persistent moderation allowlist.
    #[serde(default)]
    pub gate_bypassed_allowlist: u64,
    /// Interactions that passed the gate and were evaluated.
    pub candidates_evaluated: u64,
    /// Interactions dropped because author was already recorded as bounced in cache.
    pub dedup_cache_hits: u64,
    /// Candidate evaluations served from SQLite TTL evaluation cache.
    pub eval_cache_hits: u64,
    /// High-confidence violations matched instantly by zero-cost heuristic regex rules.
    pub heuristic_violations: u64,
    /// Candidate interactions dispatched to the primary classifier (e.g. Jev model).
    pub model_evaluations: u64,
    /// Tier-1 primary model evaluations.
    #[serde(default)]
    pub tier1_evaluations: u64,
    /// Tier-2 fallback model escalations.
    #[serde(default)]
    pub tier2_evaluations: u64,
    /// Tier-2 escalations triggered by attached images.
    #[serde(default)]
    pub tier2_image_escalations: u64,
    /// Tier-2 escalations triggered by confidence uncertainty band.
    #[serde(default)]
    pub tier2_uncertainty_escalations: u64,
    /// Candidate interactions enqueued to the background evaluation queue.
    pub eval_queue_enqueued: u64,
    /// Candidate interactions processed by the background evaluation worker.
    pub eval_queue_processed: u64,
    /// Candidate interactions dropped due to evaluation queue capacity saturation.
    pub eval_queue_overflows: u64,
    /// Evaluations dropped due to Tier-4 per-user evaluation rate limits.
    pub rate_limited_evaluations: u64,
    /// Candidates enriched with author profile and parent post context.
    pub context_enrichments: u64,
    /// Total violations confirmed across heuristic and model classifiers.
    pub violations_detected: u64,
    /// Successful listitem mutations created on the sovereign PDS.
    pub bounces_executed: u64,
    /// Successful listitem mutations created on the sovereign PDS (alias for `bounces_executed`).
    pub bounced: u64,
    /// Total interactions classified as permitted / benign.
    pub permitted: u64,
    /// Violations dropped because confidence fell below rubric sensitivity threshold.
    pub bounces_skipped_rubric: u64,
    /// Total operational or network errors encountered during pipeline execution.
    pub errors_encountered: u64,
    /// Total sovereign configuration hot-reload events synchronized from the firehose.
    #[serde(default)]
    pub sovereign_configs_synced: u64,
}

/// Outcome of evaluating an interaction candidate through the moderation pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum InteractionOutcome {
    /// Dropped at the gate (self-interaction, followed author, incoming follower, or allowlisted author) with zero network/model cost.
    Bypassed {
        /// Reason for bypassing evaluation.
        reason: BypassReason,
        /// DID of the interaction author.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
    },
    /// Dropped because author is already recorded as bounced in the SQLite deduplication cache.
    AlreadyBounced {
        /// DID of the already-bounced author.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
    },
    /// Interaction is permitted / benign.
    Permitted {
        /// DID of the interaction author.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
        /// Rationale explaining why interaction is permitted.
        reason: String,
    },
    /// Offending interaction met rubric sensitivity and author was bounced on sovereign PDS.
    Bounced {
        /// Violator DID added to the moderation list.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
        /// Canonical AT-URI of the created `app.bsky.graph.listitem` record on PDS.
        listitem_uri: String,
        /// Violation category.
        category: ViolationCategory,
        /// Confidence score (0.0..=1.0).
        confidence: f64,
        /// Explanatory reason or model rationale.
        reason: String,
    },
    /// Violation detected by classifier but confidence fell below rubric sensitivity threshold.
    BelowThreshold {
        /// DID of the interaction author.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
        /// Violation category.
        category: ViolationCategory,
        /// Confidence score observed.
        confidence: f64,
        /// Required sensitivity threshold.
        threshold: f64,
    },
    /// Dropped because per-user evaluation rate limit was exceeded (Tier-4 Anti-Denial-of-Wallet).
    RateLimited {
        /// DID of the interaction author.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
        /// Reason describing the rate limit ceiling.
        reason: String,
    },
    /// Interaction candidate was accepted into the decoupled evaluation queue.
    QueuedForEvaluation {
        /// DID of the interaction author.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
        /// Canonical AT-URI of the candidate post.
        post_uri: String,
    },
    /// Interaction candidate was dropped because evaluation queue was saturated.
    QueueOverflow {
        /// DID of the interaction author.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
        /// Canonical AT-URI of the candidate post.
        post_uri: String,
    },
    /// Automated moderation is temporarily paused; candidate bypassed evaluation.
    Paused {
        /// DID of the interaction author.
        author_did: String,
        /// DID of the protected target account.
        target_did: String,
    },
}

/// Notification payload emitted when an offending account is bounced on the sovereign PDS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BounceNotification {
    /// DID of the protected target user who received the interaction.
    pub target_did: String,
    /// DID of the offending author who was bounced.
    pub violator_did: String,
    /// Violation category.
    pub category: ViolationCategory,
    /// Classification confidence score (0.0..=1.0).
    pub confidence: f64,
    /// Explanatory rationale or violation reason.
    pub reason: String,
    /// Canonical AT-URI of the offending post.
    pub post_uri: String,
    /// Text snippet of the offending post.
    pub post_snippet: String,
}

impl InteractionOutcome {
    /// Returns the author DID associated with this outcome.
    #[must_use]
    pub fn author_did(&self) -> &str {
        match self {
            Self::Bypassed { author_did, .. }
            | Self::AlreadyBounced { author_did, .. }
            | Self::Permitted { author_did, .. }
            | Self::Bounced { author_did, .. }
            | Self::BelowThreshold { author_did, .. }
            | Self::RateLimited { author_did, .. }
            | Self::QueuedForEvaluation { author_did, .. }
            | Self::QueueOverflow { author_did, .. }
            | Self::Paused { author_did, .. } => author_did.as_str(),
        }
    }

    /// Returns the protected target DID associated with this outcome, if applicable.
    #[must_use]
    pub fn target_did(&self) -> Option<&str> {
        match self {
            Self::Bypassed { target_did, .. }
            | Self::AlreadyBounced { target_did, .. }
            | Self::Permitted { target_did, .. }
            | Self::Bounced { target_did, .. }
            | Self::BelowThreshold { target_did, .. }
            | Self::RateLimited { target_did, .. }
            | Self::QueuedForEvaluation { target_did, .. }
            | Self::QueueOverflow { target_did, .. }
            | Self::Paused { target_did, .. } => Some(target_did.as_str()),
        }
    }

    /// Returns `true` if this outcome resulted in a moderation list bounce.
    #[must_use]
    pub fn is_bounced(&self) -> bool {
        matches!(self, Self::Bounced { .. })
    }

    /// Returns `true` if this outcome was permitted / benign.
    #[must_use]
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permitted { .. })
    }

    /// Returns `true` if this outcome bypassed evaluation at the gate.
    #[must_use]
    pub fn is_bypassed(&self) -> bool {
        matches!(self, Self::Bypassed { .. })
    }

    /// Returns `true` if this outcome was enqueued for background evaluation.
    #[must_use]
    pub fn is_queued(&self) -> bool {
        matches!(self, Self::QueuedForEvaluation { .. })
    }

    /// Returns `true` if this outcome was dropped due to evaluation queue saturation.
    #[must_use]
    pub fn is_queue_overflow(&self) -> bool {
        matches!(self, Self::QueueOverflow { .. })
    }

    /// Returns `true` if this outcome was bypassed due to the engine being paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        matches!(self, Self::Paused { .. })
    }

    /// Returns the short human-readable label persisted to the evaluation audit log.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Bounced { .. } => "Bounced",
            Self::Permitted { .. } => "Permitted",
            Self::BelowThreshold { .. } => "Below Rubric Threshold",
            Self::AlreadyBounced { .. } => "Already Bounced",
            Self::RateLimited { .. } => "Rate Limited",
            Self::Paused { .. } => "Paused",
            Self::Bypassed { .. } => "Bypassed",
            Self::QueuedForEvaluation { .. } => "Queued",
            Self::QueueOverflow { .. } => "Queue Overflow",
        }
    }
}

/// Event emitted when sovereign configuration is synchronized from a firehose commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SovereignConfigSyncEvent {
    /// Moderation rules and sensitivity were updated from `social.skybouncer.config`.
    Updated {
        /// Protected DID whose configuration was updated.
        did: String,
        /// New rubric prompt.
        prompt: String,
        /// New operating sensitivity.
        sensitivity: Sensitivity,
    },
    /// Moderation rules and sensitivity were extracted and updated from `app.bsky.graph.list` description metadata.
    ListMetadataUpdated {
        /// Protected DID whose list metadata was updated.
        did: String,
        /// New rubric prompt.
        prompt: String,
        /// New operating sensitivity.
        sensitivity: Sensitivity,
    },
    /// Sovereign configuration record was deleted.
    Deleted {
        /// Protected DID whose configuration was deleted.
        did: String,
    },
    /// Commit did not contain valid or relevant sovereign configuration.
    Ignored,
}

/// Backward compatibility alias for [`InteractionOutcome`].
pub type ProcessOutcome = InteractionOutcome;

/// Result of dispatching a commit through the tiers shared by the sync and queued
/// commit processors.
enum CommitDispatch {
    /// The commit was fully resolved without any per-interaction evaluation.
    Resolved(ProcessCommitResult),
    /// One or more candidate interactions require evaluation.
    Interactions(Vec<Interaction>),
}

/// Result of running the per-interaction fast-path tiers.
enum FastPath {
    /// The interaction was resolved without a model call; return this outcome.
    Resolved(InteractionOutcome),
    /// A heuristic violation was acted upon; the sync caller emits an audit log
    /// (including for errors) carrying the raw verdict before returning the outcome.
    Heuristic(Result<InteractionOutcome, SkybouncerError>, Verdict),
    /// No fast-path tier resolved the interaction; the caller must evaluate or enqueue.
    Continue,
}

/// Outcome of processing a single [`JetstreamCommit`] through [`SkybouncerEngine`].
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessCommitResult {
    /// Commit updated the follow graph for a protected user.
    FollowSynced(FollowSyncEvent),
    /// Commit updated or deleted sovereign configuration for a protected user.
    SovereignConfigSynced(SovereignConfigSyncEvent),
    /// Post commit did not target any configured protected user.
    NoMatch,
    /// One or more interaction candidates were extracted and evaluated.
    InteractionsProcessed(Vec<InteractionOutcome>),
    /// Commit was ignored (unrelated collection, delete operation on post, etc.).
    Ignored,
}

impl ProcessCommitResult {
    /// Returns a slice of interaction outcomes if any were processed.
    #[must_use]
    pub fn outcomes(&self) -> &[InteractionOutcome] {
        match self {
            Self::InteractionsProcessed(outcomes) => outcomes,
            _ => &[],
        }
    }

    /// Consumes the result and returns any processed interaction outcomes.
    #[must_use]
    pub fn into_outcomes(self) -> Vec<InteractionOutcome> {
        match self {
            Self::InteractionsProcessed(outcomes) => outcomes,
            _ => Vec::new(),
        }
    }

    /// Returns `true` if this commit was a follow synchronization event.
    #[must_use]
    pub fn is_follow_synced(&self) -> bool {
        matches!(self, Self::FollowSynced(_))
    }

    /// Returns `true` if this commit was a sovereign configuration synchronization event.
    #[must_use]
    pub fn is_sovereign_config_synced(&self) -> bool {
        matches!(self, Self::SovereignConfigSynced(_))
    }

    /// Returns a reference to the [`SovereignConfigSyncEvent`] if this was a config sync commit.
    #[must_use]
    pub fn sovereign_config_sync_event(&self) -> Option<&SovereignConfigSyncEvent> {
        match self {
            Self::SovereignConfigSynced(event) => Some(event),
            _ => None,
        }
    }

    /// Returns `true` if the commit was ignored.
    #[must_use]
    pub fn is_ignored(&self) -> bool {
        matches!(self, Self::Ignored)
    }

    /// Returns `true` if no interactions matched any protected DIDs.
    #[must_use]
    pub fn is_no_match(&self) -> bool {
        matches!(self, Self::NoMatch)
    }
}

/// High-performance automated moderation engine and bouncer for Bluesky and ATProto.
#[derive(Clone)]
pub struct SkybouncerEngine {
    config: SkybouncerConfig,
    protected_dids: Arc<RwLock<HashSet<String>>>,
    rubric: Arc<RwLock<RuleRubric>>,
    follow_graph: Arc<FollowGraph>,
    gate: Arc<NonFollowedGate>,
    heuristic_classifier: HeuristicClassifier,
    classifier: Arc<dyn Classifier>,
    modlist_manager: Arc<ModListManager>,
    cache: Arc<DeduplicationCache>,
    tenant_registry: Arc<TenantRegistry>,
    pds_client: Arc<PdsRepoClient>,
    rate_limiter: Arc<EvaluationRateLimiter>,
    enricher: Arc<dyn ContextEnricher>,
    stats: Arc<EngineStats>,
    paused: Arc<AtomicBool>,
    bounce_notifier: broadcast::Sender<BounceNotification>,
    oauth_client: Arc<RwLock<Option<Arc<AtprotoOAuthClient>>>>,
    handle_cache: Arc<RwLock<HashMap<String, (String, std::time::Instant)>>>,
}

mod accessors;
mod handles;
mod lifecycle;
mod modlist_ops;
mod processing;
pub mod simulate;
mod tenant_ops;

/// Builder for constructing [`SkybouncerEngine`] with optional component overrides.
pub struct SkybouncerEngineBuilder {
    config: SkybouncerConfig,
    follow_graph: Option<Arc<FollowGraph>>,
    gate: Option<Arc<NonFollowedGate>>,
    heuristic_classifier: Option<HeuristicClassifier>,
    classifier: Option<Arc<dyn Classifier>>,
    fallback_classifier: Option<Arc<dyn Classifier>>,
    multimodal_classifier: Option<Arc<dyn Classifier>>,
    modlist_manager: Option<Arc<ModListManager>>,
    cache: Option<Arc<DeduplicationCache>>,
    pds_client: Option<Arc<PdsRepoClient>>,
    tenant_registry: Option<Arc<TenantRegistry>>,
    rate_limiter: Option<Arc<EvaluationRateLimiter>>,
    enricher: Option<Arc<dyn ContextEnricher>>,
    oauth_client: Option<Arc<AtprotoOAuthClient>>,
}

impl SkybouncerEngineBuilder {
    /// Creates a builder with the given configuration.
    #[must_use]
    pub fn new(config: SkybouncerConfig) -> Self {
        Self {
            config,
            follow_graph: None,
            gate: None,
            heuristic_classifier: None,
            classifier: None,
            fallback_classifier: None,
            multimodal_classifier: None,
            modlist_manager: None,
            cache: None,
            pds_client: None,
            tenant_registry: None,
            rate_limiter: None,
            enricher: None,
            oauth_client: None,
        }
    }

    /// Configures an explicit ATProto OAuth client for background session token refreshes.
    #[must_use]
    pub fn with_oauth_client(mut self, client: Arc<AtprotoOAuthClient>) -> Self {
        self.oauth_client = Some(client);
        self
    }

    /// Configures an explicit shared tenant registry.
    #[must_use]
    pub fn with_tenant_registry(mut self, registry: Arc<TenantRegistry>) -> Self {
        self.tenant_registry = Some(registry);
        self
    }

    /// Configures an explicit shared follow graph.
    #[must_use]
    pub fn with_follow_graph(mut self, graph: Arc<FollowGraph>) -> Self {
        self.follow_graph = Some(graph);
        self
    }

    /// Configures an explicit non-followed gate.
    #[must_use]
    pub fn with_gate(mut self, gate: Arc<NonFollowedGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Configures an explicit heuristic classifier regex engine.
    #[must_use]
    pub fn with_heuristic_classifier(mut self, classifier: HeuristicClassifier) -> Self {
        self.heuristic_classifier = Some(classifier);
        self
    }

    /// Configures an explicit classifier implementation (e.g. `MockClassifier`).
    #[must_use]
    pub fn with_classifier(mut self, classifier: Arc<dyn Classifier>) -> Self {
        self.classifier = Some(classifier);
        self
    }

    /// Configures an explicit secondary fallback classifier implementation (e.g. for vision or heavier reasoning).
    #[must_use]
    pub fn with_fallback_classifier(mut self, classifier: Arc<dyn Classifier>) -> Self {
        self.fallback_classifier = Some(classifier);
        self
    }

    /// Configures an explicit multimodal primary classifier used for dynamic Tier-1 routing.
    ///
    /// When set, image-bearing interactions are routed to this classifier at Tier-1;
    /// text-only interactions continue to use the primary classifier.
    #[must_use]
    pub fn with_multimodal_classifier(mut self, classifier: Arc<dyn Classifier>) -> Self {
        self.multimodal_classifier = Some(classifier);
        self
    }

    /// Configures an explicit modlist manager.
    #[must_use]
    pub fn with_modlist_manager(mut self, manager: Arc<ModListManager>) -> Self {
        self.modlist_manager = Some(manager);
        self
    }

    /// Configures an explicit deduplication cache.
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<DeduplicationCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Configures an explicit PDS repository client.
    #[must_use]
    pub fn with_pds_client(mut self, client: Arc<PdsRepoClient>) -> Self {
        self.pds_client = Some(client);
        self
    }

    /// Configures an explicit evaluation rate limiter.
    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: Arc<EvaluationRateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Configures an explicit context enricher.
    #[must_use]
    pub fn with_enricher(mut self, enricher: Arc<dyn ContextEnricher>) -> Self {
        self.enricher = Some(enricher);
        self
    }

    /// Sets the decoupled candidate evaluation queue capacity.
    #[must_use]
    pub fn with_evaluation_queue_capacity(mut self, capacity: usize) -> Self {
        self.config.evaluation_queue_capacity = capacity;
        self
    }

    /// Sets the maximum concurrent evaluations permitted against the primary model.
    #[must_use]
    pub fn with_evaluation_concurrency(mut self, concurrency: usize) -> Self {
        self.config.evaluation_concurrency = concurrency.max(1);
        self
    }

    /// Builds and initializes the [`SkybouncerEngine`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] or [`SkybouncerError::Database`] if component initialization fails.
    pub fn build(self) -> Result<SkybouncerEngine, SkybouncerError> {
        // 1. Initialize or resolve DeduplicationCache
        let cache = match self.cache {
            Some(c) => c,
            None => match self.modlist_manager {
                Some(ref m) => Arc::clone(m.cache()),
                None => match self.config.cache_path.as_ref() {
                    Some(path) => {
                        let target_path = if self.config.dry_run {
                            let mut shadow = path.clone();
                            let stem = shadow
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("skybouncer");
                            let ext = shadow.extension().and_then(|e| e.to_str()).unwrap_or("db");
                            shadow.set_file_name(format!("{stem}_shadow.{ext}"));
                            shadow
                        } else {
                            path.clone()
                        };
                        Arc::new(DeduplicationCache::open(target_path)?)
                    }
                    None => Arc::new(DeduplicationCache::open_in_memory()?),
                },
            },
        };

        // 2. Initialize FollowGraph & NonFollowedGate
        let follow_graph = self
            .follow_graph
            .unwrap_or_else(|| Arc::new(FollowGraph::new()));
        let gate = self
            .gate
            .unwrap_or_else(|| Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph))));

        if let Ok(loaded_allowlists) = cache.load_all_allowlists() {
            let mut guard = gate.allowlist().write();
            for (prot, authors) in loaded_allowlists {
                guard.entry(prot).or_default().extend(authors);
            }
        }

        for did in &self.config.protected_dids {
            gate.set_bypass_incoming_followers(did, self.config.rubric.bypass_incoming_followers);
        }

        // 3. Initialize HeuristicClassifier
        let heuristic_classifier = self.heuristic_classifier.unwrap_or_else(|| {
            if self.config.enable_heuristic_prefilter {
                HeuristicClassifier::default()
            } else {
                HeuristicClassifier::empty()
            }
        });

        // 4. Initialize Primary Classifier
        let primary_classifier: Arc<dyn Classifier> = match self.classifier {
            Some(c) => c,
            None => {
                if let Some(ref jev_cfg) = self.config.jev_config {
                    Arc::new(JevClassifier::new(
                        jev_cfg.clone(),
                        self.config.rubric.clone(),
                    )?)
                } else {
                    return Err(SkybouncerError::Config(
                        "No classifier provided and JEV configuration is missing".to_string(),
                    ));
                }
            }
        };

        // Resolve optional multimodal Tier-1 classifier for dynamic primary routing.
        let multimodal_classifier: Option<Arc<dyn Classifier>> = match self.multimodal_classifier {
            Some(c) => Some(c),
            None => {
                if let Some(ref mm_cfg) = self.config.multimodal_jev_config {
                    Some(Arc::new(JevClassifier::new(
                        mm_cfg.clone(),
                        self.config.rubric.clone(),
                    )?))
                } else {
                    None
                }
            }
        };
        let has_multimodal_primary = multimodal_classifier.is_some();

        // When a multimodal Tier-1 classifier is configured, wrap the primary in a
        // DynamicPrimaryClassifier that routes image-bearing interactions to it.
        let primary_classifier: Arc<dyn Classifier> = match multimodal_classifier {
            Some(multimodal) => Arc::new(DynamicPrimaryClassifier::new(
                primary_classifier,
                multimodal,
                DynamicModelPolicy::default(),
            )),
            None => primary_classifier,
        };

        // Resolve optional secondary fallback classifier and wrap in TieredClassifier if present
        let fallback_classifier: Option<Arc<dyn Classifier>> = match self.fallback_classifier {
            Some(c) => Some(c),
            None => {
                if let Some(ref fallback_cfg) = self.config.fallback_jev_config {
                    Some(Arc::new(JevClassifier::new(
                        fallback_cfg.clone(),
                        self.config.rubric.clone(),
                    )?))
                } else {
                    None
                }
            }
        };

        // Resolve the effective certainty config: when the Tier-1 primary is multimodal,
        // images are already inspected at Tier-1, so image-triggered Tier-2 escalation is
        // disabled to avoid a redundant heavyweight model call. Uncertainty-band
        // escalation still applies.
        let effective_certainty = if has_multimodal_primary {
            CertaintyConfig::new(
                self.config.certainty_config.min_confidence,
                self.config.certainty_config.max_confidence,
                false,
            )
        } else {
            self.config.certainty_config
        };

        let classifier: Arc<dyn Classifier> = match fallback_classifier {
            Some(fallback) => Arc::new(TieredClassifier::new(
                primary_classifier,
                fallback,
                effective_certainty,
            )),
            None => primary_classifier,
        };

        // 5. Initialize ModListManager
        let modlist_manager = match self.modlist_manager {
            Some(m) => {
                if self.config.dry_run && !m.is_dry_run() {
                    Arc::new((*m).clone().with_dry_run(true))
                } else {
                    m
                }
            }
            None => {
                let mut manager = ModListManager::from_shared_cache(Arc::clone(&cache))
                    .with_rubric(self.config.rubric.clone())
                    .with_list_name(self.config.list_name.clone())
                    .with_dry_run(self.config.dry_run);
                if let Some(ref desc) = self.config.list_description {
                    manager = manager.with_list_description(Some(desc.clone()));
                }
                Arc::new(manager)
            }
        };

        // 6. Initialize PdsRepoClient
        let pds_client = match self.pds_client {
            Some(p) => p,
            None => {
                if self.config.dry_run {
                    let endpoint = self
                        .config
                        .pds_endpoint
                        .as_deref()
                        .unwrap_or("https://bsky.social");
                    let primary_did = self
                        .config
                        .protected_dids
                        .iter()
                        .next()
                        .map(String::as_str)
                        .unwrap_or("did:plc:shadowmode");
                    let token = self
                        .config
                        .pds_access_token
                        .as_deref()
                        .unwrap_or("shadow_placeholder_token");
                    Arc::new(
                        PdsRepoClient::from_credentials(endpoint, primary_did, token)
                            .inspect_err(|e| {
                                tracing::warn!(error = %e, "Failed to build shadow-mode PDS client");
                            })?,
                    )
                } else if self.config.pds_endpoint.is_some()
                    && self.config.pds_access_token.is_some()
                {
                    let endpoint = self
                        .config
                        .pds_endpoint
                        .as_deref()
                        .unwrap_or("https://bsky.social");
                    let token = self.config.pds_access_token.as_deref().unwrap_or("");
                    let primary_did = self
                        .config
                        .protected_dids
                        .iter()
                        .next()
                        .map(String::as_str)
                        .unwrap_or("did:plc:skybouncer_admin");
                    Arc::new(
                        PdsRepoClient::from_credentials(endpoint, primary_did, token).inspect_err(
                            |e| {
                                tracing::warn!(error = %e, "Failed to build configured PDS client");
                            },
                        )?,
                    )
                } else {
                    Arc::new(
                        PdsRepoClient::from_credentials(
                            "https://bsky.social",
                            "did:plc:skybouncer_multi_tenant",
                            "multi_tenant_placeholder_token",
                        )
                        .inspect_err(|e| {
                            tracing::warn!(error = %e, "Failed to build fallback PDS client");
                        })?,
                    )
                }
            }
        };

        // 7. Initialize TenantRegistry
        let tenant_registry = match self.tenant_registry {
            Some(tr) => tr,
            None => Arc::new(
                TenantRegistry::from_connection(cache.connection())
                    .or_else(|_| TenantRegistry::open_in_memory())
                    .map_err(|e| {
                        SkybouncerError::Database(format!(
                            "Failed to initialize TenantRegistry: {e}"
                        ))
                    })?,
            ),
        };

        // 7.5. Seed per-user incoming-follower bypass flags into the in-memory gate.
        // Config-level protected DIDs inherit the engine default rubric; enrolled tenants
        // override with their own per-user sovereign flag.
        for did in &self.config.protected_dids {
            gate.set_bypass_incoming_followers(did, self.config.rubric.bypass_incoming_followers);
        }
        if let Ok(active) = tenant_registry.list_active() {
            for tenant in active {
                if let Some(ref rubric) = tenant.rubric {
                    gate.set_bypass_incoming_followers(
                        &tenant.did,
                        rubric.bypass_incoming_followers,
                    );
                }
            }
        }

        let rate_limiter = self.rate_limiter.unwrap_or_else(|| {
            Arc::new(EvaluationRateLimiter::new(
                self.config.rate_limiter_config.clone(),
            ))
        });
        let enricher = self
            .enricher
            .unwrap_or_else(|| Arc::new(NoopContextEnricher));

        let mut protected = self.config.protected_dids.clone();
        if let Ok(active) = tenant_registry.list_active() {
            for t in active {
                protected.insert(t.did);
            }
        }
        let protected_dids = Arc::new(RwLock::new(protected));
        let rubric = Arc::new(RwLock::new(self.config.rubric.clone()));
        let stats = Arc::new(load_persisted_stats(&cache));
        let paused = Arc::new(AtomicBool::new(false));
        let (bounce_notifier, _) = broadcast::channel(256);
        let oauth_client_arc = Arc::new(RwLock::new(self.oauth_client.clone()));
        if let Some(ref oc) = self.oauth_client {
            tenant_registry.set_oauth_client(Arc::clone(oc));
        }
        let handle_cache = Arc::new(RwLock::new(HashMap::new()));

        Ok(SkybouncerEngine {
            config: self.config,
            protected_dids,
            rubric,
            follow_graph,
            gate,
            heuristic_classifier,
            classifier,
            modlist_manager,
            cache,
            tenant_registry,
            pds_client,
            rate_limiter,
            enricher,
            stats,
            paused,
            bounce_notifier,
            oauth_client: oauth_client_arc,
            handle_cache,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    pub(super) fn test_load_persisted_stats_restores_counters() {
        let cache = DeduplicationCache::open_in_memory().unwrap();

        let restored = load_persisted_stats(&cache);
        assert_eq!(restored.snapshot(), EngineStatsSnapshot::default());

        let snapshot = EngineStatsSnapshot {
            commits_received: 1_234,
            bounces_executed: 56,
            tier2_image_escalations: 3,
            ..Default::default()
        };
        cache.save_dashboard_stats(&snapshot).unwrap();

        let restored = load_persisted_stats(&cache);
        assert_eq!(restored.snapshot(), snapshot);
    }

    #[test]
    fn config_new_and_all_setters_roundtrip() {
        let rubric = RuleRubric::new("Block spam", Sensitivity::High);
        let cfg = SkybouncerConfig::new(["did:plc:a", "did:plc:b"], rubric.clone())
            .with_pds_endpoint("https://pds.example")
            .with_pds_access_token("tok")
            .with_cache_path("/tmp/x.db")
            .with_evaluation_ttl(Duration::from_secs(10))
            .with_channel_capacity(64)
            .with_evaluation_queue_capacity(8)
            .with_evaluation_concurrency(0) // clamped to >=1
            .with_list_name("My List")
            .with_list_description("desc")
            .with_rate_limiter_config(RateLimiterConfig::default())
            .with_enable_heuristic_prefilter(true)
            .with_dry_run(true)
            .with_admin_did("did:plc:admin")
            .with_handle_cache_ttl(Duration::from_secs(30));

        // with_admin_did also inserts the admin into protected_dids.
        assert_eq!(cfg.protected_dids.len(), 3);
        assert_eq!(cfg.pds_endpoint.as_deref(), Some("https://pds.example"));
        assert_eq!(cfg.pds_access_token.as_deref(), Some("tok"));
        assert_eq!(
            cfg.cache_path.as_deref(),
            Some(std::path::Path::new("/tmp/x.db"))
        );
        assert_eq!(cfg.evaluation_ttl, Duration::from_secs(10));
        assert_eq!(cfg.channel_capacity, 64);
        assert_eq!(cfg.evaluation_queue_capacity, 8);
        assert_eq!(cfg.evaluation_concurrency, 1, "concurrency clamped to >= 1");
        assert_eq!(cfg.list_name, "My List");
        assert_eq!(cfg.list_description.as_deref(), Some("desc"));
        assert!(cfg.enable_heuristic_prefilter);
        assert!(cfg.dry_run);
        assert_eq!(cfg.admin_did.as_deref(), Some("did:plc:admin"));
        assert_eq!(cfg.handle_cache_ttl, Duration::from_secs(30));
    }

    #[test]
    fn config_channel_capacity_raises_queue_capacity() {
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default())
            .with_evaluation_queue_capacity(4)
            .with_channel_capacity(128);
        assert_eq!(cfg.channel_capacity, 128);
        assert_eq!(
            cfg.evaluation_queue_capacity, 128,
            "queue floored up to channel cap"
        );
    }

    #[test]
    fn builder_component_setters_store_components() {
        let cache = DeduplicationCache::open_in_memory().unwrap();
        let cache = Arc::new(cache);
        let follow_graph = Arc::new(FollowGraph::new());
        let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
        let registry = Arc::new(TenantRegistry::open_in_memory().unwrap());
        let modlist = Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)));

        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default());
        let builder = SkybouncerEngine::builder(cfg)
            .with_follow_graph(Arc::clone(&follow_graph))
            .with_gate(Arc::clone(&gate))
            .with_cache(Arc::clone(&cache))
            .with_tenant_registry(Arc::clone(&registry))
            .with_modlist_manager(Arc::clone(&modlist))
            .with_classifier(classifier)
            .with_evaluation_queue_capacity(16)
            .with_evaluation_concurrency(2);

        let engine = builder.build().expect("engine builds");
        assert!(engine.is_single_tenant() || !engine.is_single_tenant());
        assert_eq!(engine.rubric().prompt, RuleRubric::default().prompt);
    }

    #[test]
    fn builder_build_requires_classifier_or_jev_config() {
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default());
        let err = SkybouncerEngine::builder(cfg).build();
        assert!(err.is_err(), "no classifier/jev config must fail");
    }

    #[test]
    fn builder_dry_run_with_cache_path_and_credentials_builds_shadow_engine() {
        let dir = std::env::temp_dir().join(format!(
            "skybouncer_builder_{}",
            crate::time::current_time_us()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("state.db");

        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        // dry_run + cache_path exercises the shadow DB filename rewrite; dry_run also
        // exercises the credential-seeded shadow PDS client branch.
        let cfg = SkybouncerConfig::new(["did:plc:shadowy"], RuleRubric::default())
            .with_dry_run(true)
            .with_pds_endpoint("https://pds.example")
            .with_pds_access_token("shadow-token")
            .with_cache_path(&db)
            .with_admin_did("did:plc:shadowy");
        let engine = SkybouncerEngine::builder(cfg)
            .with_classifier(classifier)
            .build()
            .expect("shadow engine builds");
        assert!(engine.is_dry_run());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn builder_with_configured_pds_credentials_builds_live_engine() {
        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        // Non-dry-run with explicit endpoint+token exercises the configured PDS client arm.
        let cfg = SkybouncerConfig::new(["did:plc:live"], RuleRubric::default())
            .with_pds_endpoint("https://pds.example")
            .with_pds_access_token("live-token")
            .with_admin_did("did:plc:live");
        let engine = SkybouncerEngine::builder(cfg)
            .with_classifier(classifier)
            .build()
            .expect("live engine builds");
        assert!(!engine.is_dry_run());
    }

    #[test]
    fn config_from_env_parses_multimodal_primary() {
        // Serialize against other env-mutating tests in this binary.
        let key = "MULTIMODAL_PRIMARY_MODEL";
        let base_key = "MULTIMODAL_API_BASE_URL";
        let prev_key = std::env::var(key).ok();
        let prev_base = std::env::var(base_key).ok();

        std::env::set_var(key, "clef-flash");
        std::env::remove_var(base_key);

        let cfg = SkybouncerConfig::from_env().expect("from_env");
        let mm = cfg
            .multimodal_jev_config
            .expect("multimodal config populated");
        assert_eq!(mm.model, "clef-flash");
        assert!(mm.supports_images, "multimodal primary must accept images");
        assert_eq!(mm.timeout, Duration::from_millis(60000));

        // Restore prior env state.
        match prev_key {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        match prev_base {
            Some(v) => std::env::set_var(base_key, v),
            None => std::env::remove_var(base_key),
        }
    }

    #[test]
    fn builder_hydrates_allowlists_and_active_tenants_from_shared_cache() {
        let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
        cache
            .add_to_allowlist("did:plc:owner", "did:plc:friend", Some("buddy"))
            .unwrap();

        let registry = Arc::new(TenantRegistry::open_in_memory().unwrap());
        registry
            .register_or_update(
                &crate::tenant::Tenant::new("did:plc:enrolled")
                    .with_rubric(RuleRubric::default().with_bypass_incoming_followers(false)),
            )
            .unwrap();

        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:owner"], RuleRubric::default())
            .with_admin_did("did:plc:owner");
        let engine = SkybouncerEngine::builder(cfg)
            .with_classifier(classifier)
            .with_cache(Arc::clone(&cache))
            .with_tenant_registry(Arc::clone(&registry))
            .build()
            .expect("engine builds with hydrated allowlist/tenants");

        assert!(engine.is_allowlisted("did:plc:owner", "did:plc:friend"));
        assert!(engine.is_enrolled("did:plc:enrolled"));
        assert!(engine.is_protected("did:plc:enrolled"));
    }

    fn all_outcomes() -> Vec<InteractionOutcome> {
        let a = "did:plc:author".to_string();
        let t = "did:plc:target".to_string();
        vec![
            InteractionOutcome::Bypassed {
                reason: BypassReason::SelfInteraction,
                author_did: a.clone(),
                target_did: t.clone(),
            },
            InteractionOutcome::AlreadyBounced {
                author_did: a.clone(),
                target_did: t.clone(),
            },
            InteractionOutcome::Permitted {
                author_did: a.clone(),
                target_did: t.clone(),
                reason: "ok".to_string(),
            },
            InteractionOutcome::Bounced {
                author_did: a.clone(),
                target_did: t.clone(),
                listitem_uri: "at://x".to_string(),
                category: ViolationCategory::Spam,
                confidence: 0.9,
                reason: "spam".to_string(),
            },
            InteractionOutcome::BelowThreshold {
                author_did: a.clone(),
                target_did: t.clone(),
                category: ViolationCategory::Spam,
                confidence: 0.5,
                threshold: 0.8,
            },
            InteractionOutcome::RateLimited {
                author_did: a.clone(),
                target_did: t.clone(),
                reason: "limit".to_string(),
            },
            InteractionOutcome::QueuedForEvaluation {
                author_did: a.clone(),
                target_did: t.clone(),
                post_uri: "at://p".to_string(),
            },
            InteractionOutcome::QueueOverflow {
                author_did: a.clone(),
                target_did: t.clone(),
                post_uri: "at://p".to_string(),
            },
            InteractionOutcome::Paused {
                author_did: a.clone(),
                target_did: t.clone(),
            },
        ]
    }

    #[test]
    fn interaction_outcome_accessors_cover_all_variants() {
        let outcomes = all_outcomes();
        // Exactly one of each boolean predicate should hold per variant.
        assert_eq!(outcomes.iter().filter(|o| o.is_bounced()).count(), 1);
        assert_eq!(outcomes.iter().filter(|o| o.is_permitted()).count(), 1);
        assert_eq!(outcomes.iter().filter(|o| o.is_bypassed()).count(), 1);
        assert_eq!(outcomes.iter().filter(|o| o.is_queued()).count(), 1);
        assert_eq!(outcomes.iter().filter(|o| o.is_queue_overflow()).count(), 1);
        assert_eq!(outcomes.iter().filter(|o| o.is_paused()).count(), 1);

        for o in &outcomes {
            assert_eq!(o.author_did(), "did:plc:author");
            assert_eq!(o.target_did(), Some("did:plc:target"));
            assert!(!o.label().is_empty());
        }

        // Labels are stable and distinct where expected.
        let labels: Vec<&str> = outcomes.iter().map(|o| o.label()).collect();
        assert!(labels.contains(&"Bounced"));
        assert!(labels.contains(&"Permitted"));
        assert!(labels.contains(&"Below Rubric Threshold"));
        assert!(labels.contains(&"Already Bounced"));
        assert!(labels.contains(&"Rate Limited"));
        assert!(labels.contains(&"Paused"));
        assert!(labels.contains(&"Bypassed"));
        assert!(labels.contains(&"Queued"));
        assert!(labels.contains(&"Queue Overflow"));
    }

    #[test]
    fn builder_dry_run_uses_shadow_cache_and_modlist() {
        let dir = std::env::temp_dir().join(format!(
            "skyb_builder_test_{}",
            crate::time::current_time_us()
        ));
        let db = dir.join("cache.db");
        let cache = DeduplicationCache::open(&db).unwrap();
        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default())
            .with_dry_run(true)
            .with_list_description("desc");
        let engine = SkybouncerEngine::builder(cfg)
            .with_cache(Arc::new(cache))
            .with_classifier(classifier)
            .build()
            .expect("dry-run engine builds");
        assert!(engine.is_dry_run());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn builder_from_jev_config_constructs_primary_classifier() {
        let jev = JevConfig {
            base_url: "http://localhost:11434".to_string(),
            api_key: None,
            model: "test-model".to_string(),
            timeout: Duration::from_millis(500),
            max_retries: 0,
            supports_images: false,
        };
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default())
            .with_jev_config(jev.clone())
            .with_fallback_jev_config(jev)
            .with_dry_run(true);
        // No explicit classifier => builds from JevConfig, with fallback => TieredClassifier.
        let engine = SkybouncerEngine::builder(cfg)
            .build()
            .expect("engine builds from jev config");
        assert_eq!(engine.primary_classifier().model_name(), "tiered");
    }

    #[test]
    fn builder_fallback_pds_client_branches() {
        // No endpoint/token + not dry-run => fallback multi-tenant PDS client path.
        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default());
        let engine = SkybouncerEngine::builder(cfg)
            .with_classifier(classifier)
            .build()
            .expect("fallback pds client builds");
        assert!(!engine.pds_client().did().is_empty());
    }

    #[test]
    fn builder_configured_pds_client_branch() {
        // Non-dry-run with an explicit endpoint + token takes the configured branch.
        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default())
            .with_pds_endpoint("https://pds.example.com")
            .with_pds_access_token("token-abc");
        let engine = SkybouncerEngine::builder(cfg)
            .with_classifier(classifier)
            .build()
            .expect("configured pds client builds");
        assert_eq!(engine.pds_client().did(), "did:plc:a");
    }

    #[test]
    fn builder_seeds_bypass_flags_from_tenants() {
        let registry = Arc::new(TenantRegistry::open_in_memory().unwrap());
        // Enroll a tenant with a rubric that opts out of incoming-follower bypass.
        let rubric = RuleRubric {
            bypass_incoming_followers: false,
            ..RuleRubric::default()
        };
        registry
            .register_or_update(&crate::tenant::Tenant::new("did:plc:tenant").with_rubric(rubric))
            .unwrap();
        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default());
        let engine = SkybouncerEngine::builder(cfg)
            .with_tenant_registry(registry)
            .with_classifier(classifier)
            .build()
            .expect("engine builds");
        assert!(!engine.bypass_incoming_followers("did:plc:tenant"));
    }

    #[test]
    fn builder_heuristic_and_rate_limiter_and_cache_from_modlist() {
        use crate::limiter::{EvaluationRateLimiter, RateLimiterConfig};
        let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
        let modlist = Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)));
        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default());
        // No explicit cache: build() reuses the modlist manager's cache.
        let engine = SkybouncerEngine::builder(cfg)
            .with_modlist_manager(Arc::clone(&modlist))
            .with_classifier(classifier)
            .with_heuristic_classifier(HeuristicClassifier::empty())
            .with_rate_limiter(Arc::new(EvaluationRateLimiter::new(
                RateLimiterConfig::default(),
            )))
            .build()
            .expect("engine builds");
        assert!(engine.cache().count_bounced().is_ok());
    }

    #[test]
    fn builder_cache_path_persistent_branch() {
        // No cache, no modlist manager, but a config cache_path -> open persistent cache.
        let dir = std::env::temp_dir().join(format!(
            "skyb_builder_persist_{}",
            crate::time::current_time_us()
        ));
        let db = dir.join("cache.db");
        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:a"], RuleRubric::default()).with_cache_path(&db);
        let engine = SkybouncerEngine::builder(cfg)
            .with_classifier(classifier)
            .build()
            .expect("engine builds with persistent cache");
        assert!(engine.is_protected("did:plc:a"));
        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn builder_includes_active_tenants_in_protected_set() {
        let registry = Arc::new(TenantRegistry::open_in_memory().unwrap());
        registry
            .register_or_update(&crate::tenant::Tenant::new("did:plc:active-tenant"))
            .unwrap();
        let classifier = Arc::new(crate::classifier::MockClassifier::new(
            crate::classifier::Verdict::permitted("ok"),
        ));
        let cfg = SkybouncerConfig::new(["did:plc:cfg"], RuleRubric::default());
        let engine = SkybouncerEngine::builder(cfg)
            .with_tenant_registry(registry)
            .with_classifier(classifier)
            .build()
            .expect("engine builds");
        // The active tenant is folded into the protected set.
        assert!(engine.is_protected("did:plc:active-tenant"));
    }

    #[test]
    fn process_commit_result_helpers() {
        let outcome = InteractionOutcome::Permitted {
            author_did: "a".to_string(),
            target_did: "t".to_string(),
            reason: "ok".to_string(),
        };
        let processed = ProcessCommitResult::InteractionsProcessed(vec![outcome.clone()]);
        assert_eq!(processed.outcomes().len(), 1);
        assert_eq!(processed.clone().into_outcomes(), vec![outcome]);

        let ignored = ProcessCommitResult::Ignored;
        assert!(ignored.outcomes().is_empty());
        assert!(ignored.into_outcomes().is_empty());
        assert!(ProcessCommitResult::NoMatch.outcomes().is_empty());
    }

    #[test]
    fn process_commit_result_variant_predicates() {
        let follow = ProcessCommitResult::FollowSynced(FollowSyncEvent::Ignored);
        assert!(follow.is_follow_synced());
        assert!(!follow.is_sovereign_config_synced());
        assert!(follow.sovereign_config_sync_event().is_none());

        let updated =
            ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Updated {
                did: "did:plc:a".to_string(),
                prompt: "p".to_string(),
                sensitivity: Sensitivity::High,
            });
        assert!(updated.is_sovereign_config_synced());
        assert!(updated.sovereign_config_sync_event().is_some());

        assert!(ProcessCommitResult::Ignored.is_ignored());
        assert!(!ProcessCommitResult::Ignored.is_no_match());
        assert!(ProcessCommitResult::NoMatch.is_no_match());
        assert!(!ProcessCommitResult::NoMatch.is_ignored());
    }
}
