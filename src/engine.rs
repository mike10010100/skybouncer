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
    CertaintyConfig, Classifier, HeuristicClassifier, JevClassifier, JevConfig, RuleRubric,
    Sensitivity, TieredClassifier, Verdict, ViolationCategory,
};
use crate::enricher::{ContextEnricher, NoopContextEnricher};
use crate::error::SkybouncerError;
use crate::limiter::{EvaluationRateLimiter, RateLimiterConfig};
use crate::matcher::{
    BypassReason, FollowGraph, FollowSyncEvent, GateDecision, Interaction, NonFollowedGate,
    TargetMatcher,
};
use crate::modlist::cache::current_time_us;
use crate::modlist::{BouncedUser, DeduplicationCache, ModListManager, DEFAULT_MOD_LIST_NAME};
use crate::tenant::{Tenant, TenantRegistry};

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
    /// Certainty threshold configuration governing when evaluations escalate to the fallback model.
    pub certainty_config: CertaintyConfig,
    /// Title assigned to provisioned moderation lists.
    pub list_name: String,
    /// Optional description for provisioned moderation lists.
    pub list_description: Option<String>,
    /// Configuration parameters for the Tier-4 per-user evaluation rate limiter.
    pub rate_limiter_config: RateLimiterConfig,
    /// Whether to operate in stateless mode (resolving rules directly from sovereign PDS).
    pub stateless_mode: bool,
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
            certainty_config: CertaintyConfig::default(),
            list_name: DEFAULT_MOD_LIST_NAME.to_string(),
            list_description: None,
            rate_limiter_config: RateLimiterConfig::default(),
            stateless_mode: false,
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
        let dids_str = std::env::var("PROTECTED_DIDS")
            .or_else(|_| std::env::var("SKYBOUNCER_PROTECTED_DIDS"))
            .unwrap_or_default();
        for did in dids_str.split(',') {
            let trimmed = did.trim();
            if !trimmed.is_empty() {
                protected_dids.insert(trimmed.to_string());
            }
        }

        let admin_did = std::env::var("ADMIN_DID")
            .or_else(|_| std::env::var("SKYBOUNCER_ADMIN_DID"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(ref admin) = admin_did {
            protected_dids.insert(admin.clone());
        }

        let rubric_prompt = std::env::var("MODERATION_RUBRIC")
            .or_else(|_| std::env::var("SKYBOUNCER_RULES"))
            .unwrap_or_else(|_| {
                "Block crypto airdrop spam, scam bots, phishing, targeted harassment, and bad-faith sea-lioning."
                    .to_string()
            });
        let rubric = RuleRubric::parse(&rubric_prompt)?;

        let pds_endpoint = std::env::var("PDS_ENDPOINT")
            .or_else(|_| std::env::var("SKYBOUNCER_PDS_URL"))
            .ok()
            .and_then(|s| {
                let t = s.trim().to_string();
                if t.is_empty() {
                    None
                } else {
                    Some(t)
                }
            });

        let pds_access_token = std::env::var("PDS_ACCESS_TOKEN").ok().and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        });

        let cache_path = std::env::var("SKYBOUNCER_DB_PATH")
            .or_else(|_| std::env::var("SKYBOUNCER_DATABASE_PATH"))
            .ok()
            .map(PathBuf::from);

        let jev_config = JevConfig::from_env().ok();

        let fallback_jev_config = if let Ok(fb_model) =
            std::env::var("FALLBACK_MODEL").or_else(|_| std::env::var("SKYBOUNCER_FALLBACK_MODEL"))
        {
            let fb_base = std::env::var("FALLBACK_API_BASE_URL")
                .or_else(|_| std::env::var("SKYBOUNCER_FALLBACK_BASE_URL"))
                .unwrap_or_else(|_| "http://localhost:11434".to_string());
            let fb_key = std::env::var("FALLBACK_API_KEY").ok();
            let fb_timeout_ms = std::env::var("FALLBACK_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5000);
            let fb_max_retries = std::env::var("FALLBACK_MAX_RETRIES")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1);
            Some(JevConfig {
                base_url: fb_base,
                api_key: fb_key,
                model: fb_model,
                timeout: Duration::from_millis(fb_timeout_ms),
                max_retries: fb_max_retries,
            })
        } else {
            None
        };

        let uncertainty_min = std::env::var("UNCERTAINTY_MIN")
            .or_else(|_| std::env::var("SKYBOUNCER_UNCERTAINTY_MIN"))
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(crate::classifier::tiered::DEFAULT_UNCERTAINTY_MIN_CONFIDENCE);

        let uncertainty_max = std::env::var("UNCERTAINTY_MAX")
            .or_else(|_| std::env::var("SKYBOUNCER_UNCERTAINTY_MAX"))
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(crate::classifier::tiered::DEFAULT_UNCERTAINTY_MAX_CONFIDENCE);

        let escalate_on_images = std::env::var("ESCALATE_ON_IMAGES")
            .or_else(|_| std::env::var("SKYBOUNCER_ESCALATE_ON_IMAGES"))
            .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
            .unwrap_or(true);

        let certainty_config =
            CertaintyConfig::new(uncertainty_min, uncertainty_max, escalate_on_images);

        let rate_limiter_config = RateLimiterConfig::from_env();
        let stateless_mode = std::env::var("SKYBOUNCER_STATELESS_MODE")
            .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
            .unwrap_or(false);

        let enable_heuristic_prefilter = std::env::var("ENABLE_HEURISTIC_PREFILTER")
            .or_else(|_| std::env::var("SKYBOUNCER_ENABLE_HEURISTIC_PREFILTER"))
            .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
            .unwrap_or(false);

        let dry_run = std::env::var("DRY_RUN")
            .or_else(|_| std::env::var("SKYBOUNCER_DRY_RUN"))
            .or_else(|_| std::env::var("SKYBOUNCER_SHADOW_MODE"))
            .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
            .unwrap_or(false);

        let evaluation_queue_capacity = std::env::var("SKYBOUNCER_EVAL_QUEUE_CAPACITY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_EVALUATION_QUEUE_CAPACITY);

        let evaluation_concurrency = std::env::var("SKYBOUNCER_EVAL_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_EVALUATION_CONCURRENCY);

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
            certainty_config,
            list_name: DEFAULT_MOD_LIST_NAME.to_string(),
            list_description: None,
            rate_limiter_config,
            stateless_mode,
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
    /// Dropped at the gate (self-interaction, followed author, or allowlisted author) with zero network/model cost.
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

impl SkybouncerEngine {
    /// Creates a builder to configure and instantiate a [`SkybouncerEngine`].
    #[must_use]
    pub fn builder(config: SkybouncerConfig) -> SkybouncerEngineBuilder {
        SkybouncerEngineBuilder::new(config)
    }

    /// Creates a new [`SkybouncerEngine`] with direct component references.
    #[must_use]
    pub fn new(
        config: SkybouncerConfig,
        follow_graph: Arc<FollowGraph>,
        gate: Arc<NonFollowedGate>,
        classifier: Arc<dyn Classifier>,
        modlist_manager: Arc<ModListManager>,
        pds_client: Arc<PdsRepoClient>,
    ) -> Self {
        let cache = Arc::clone(modlist_manager.cache());
        let tenant_registry = Arc::new(
            TenantRegistry::from_connection(cache.connection())
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "Failed to initialize TenantRegistry from cache connection; falling back to in-memory registry");
                    TenantRegistry::open_in_memory().unwrap_or_else(|e2| {
                        tracing::error!(error = %e2, "Failed to initialize in-memory TenantRegistry; using emergency fallback");
                        TenantRegistry::fallback()
                    })
                }),
        );
        let heuristic_classifier = if config.enable_heuristic_prefilter {
            HeuristicClassifier::default()
        } else {
            HeuristicClassifier::empty()
        };
        let modlist_manager = if config.dry_run && !modlist_manager.is_dry_run() {
            Arc::new((*modlist_manager).clone().with_dry_run(true))
        } else {
            modlist_manager
        };
        let mut protected = config.protected_dids.clone();
        if let Ok(active) = tenant_registry.list_active() {
            for t in active {
                protected.insert(t.did);
            }
        }
        let protected_dids = Arc::new(RwLock::new(protected));
        let rubric = Arc::new(RwLock::new(config.rubric.clone()));
        let rate_limiter = Arc::new(EvaluationRateLimiter::new(
            config.rate_limiter_config.clone(),
        ));
        let enricher: Arc<dyn ContextEnricher> = Arc::new(NoopContextEnricher);
        let stats = Arc::new(load_persisted_stats(&cache));
        let paused = Arc::new(AtomicBool::new(false));
        let (bounce_notifier, _) = broadcast::channel(256);
        let oauth_client = Arc::new(RwLock::new(None));
        let handle_cache = Arc::new(RwLock::new(HashMap::new()));

        if let Ok(loaded_allowlists) = cache.load_all_allowlists() {
            let mut guard = gate.allowlist().write();
            for (prot, authors) in loaded_allowlists {
                guard.entry(prot).or_default().extend(authors);
            }
        }

        Self {
            config,
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
            oauth_client,
            handle_cache,
        }
    }

    /// Configures the active [`AtprotoOAuthClient`] for automatic background session refreshes.
    pub fn set_oauth_client(&self, client: Arc<AtprotoOAuthClient>) {
        *self.oauth_client.write() = Some(Arc::clone(&client));
        self.tenant_registry.set_oauth_client(client);
    }

    /// Returns a reference to the active [`AtprotoOAuthClient`], if configured.
    #[must_use]
    pub fn oauth_client(&self) -> Option<Arc<AtprotoOAuthClient>> {
        self.oauth_client.read().clone()
    }

    /// Evaluates a single Jetstream commit through the full moderation pipeline.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if classifier evaluation, cache query, or PDS mutation fails.
    #[instrument(skip(self, commit), fields(collection = %commit.collection, did = %commit.did, rkey = %commit.rkey))]
    pub async fn process_commit(
        &self,
        commit: &JetstreamCommit,
    ) -> Result<ProcessCommitResult, SkybouncerError> {
        self.stats.commits_received.fetch_add(1, Ordering::Relaxed);

        // Tier 0: Follow Collection Intercept
        if commit.collection.as_str() == "app.bsky.graph.follow" {
            let sync_event = {
                let guard = self.protected_dids.read();
                self.follow_graph.handle_commit(commit, &guard)
            };
            if sync_event != FollowSyncEvent::Ignored {
                self.stats
                    .follow_sync_events
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.follows_synced.fetch_add(1, Ordering::Relaxed);
                debug!(event = ?sync_event, "Synchronized follow graph from firehose commit");
            }
            return Ok(ProcessCommitResult::FollowSynced(sync_event));
        }

        // Tier 0.5: Sovereign Config Collection Intercept (PRD §2.2)
        if commit.collection.as_str() == crate::modlist::SOVEREIGN_CONFIG_COLLECTION {
            if self.is_protected(&commit.did) {
                return Ok(self.handle_sovereign_config_commit(commit));
            }
            return Ok(ProcessCommitResult::Ignored);
        }

        // Tier 0.6: List Metadata Intercept (PRD §2.2)
        if commit.collection.as_str() == "app.bsky.graph.list" {
            if self.is_protected(&commit.did) {
                return Ok(self.handle_list_commit(commit));
            }
            return Ok(ProcessCommitResult::Ignored);
        }

        // Tier 1: Post Collection & Operation Filter
        if commit.collection.as_str() != "app.bsky.feed.post"
            || commit.operation != CommitOperation::Create
        {
            return Ok(ProcessCommitResult::Ignored);
        }

        // Tier 2: Target Matcher Extraction
        let interactions = {
            let guard = self.protected_dids.read();
            TargetMatcher::match_all_interactions(commit, &guard)
        };
        if interactions.is_empty() {
            return Ok(ProcessCommitResult::NoMatch);
        }

        let count = u64::try_from(interactions.len()).unwrap_or(0);
        self.stats
            .interactions_matched
            .fetch_add(count, Ordering::Relaxed);

        let mut outcomes = Vec::with_capacity(interactions.len());
        for interaction in interactions {
            let outcome = self.process_interaction(interaction).await?;
            outcomes.push(outcome);
        }

        Ok(ProcessCommitResult::InteractionsProcessed(outcomes))
    }

    /// Evaluates a single Jetstream commit, dispatching candidate interactions to a decoupled evaluation queue.
    ///
    /// Fast-path operations (follow graph sync, non-post filtering, self/followed gate checks,
    /// dedup cache hits, and evaluation cache hits) are completed immediately (<1µs to <50µs).
    /// Candidates requiring model evaluation are enqueued to `eval_tx` without blocking the caller.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if cache query or PDS mutation fails.
    #[instrument(skip(self, commit, eval_tx), fields(collection = %commit.collection, did = %commit.did, rkey = %commit.rkey))]
    pub async fn process_commit_queued(
        &self,
        commit: &JetstreamCommit,
        eval_tx: &mpsc::Sender<Interaction>,
    ) -> Result<ProcessCommitResult, SkybouncerError> {
        self.stats.commits_received.fetch_add(1, Ordering::Relaxed);

        // Tier 0: Follow Collection Intercept
        if commit.collection.as_str() == "app.bsky.graph.follow" {
            let sync_event = {
                let guard = self.protected_dids.read();
                self.follow_graph.handle_commit(commit, &guard)
            };
            if sync_event != FollowSyncEvent::Ignored {
                self.stats
                    .follow_sync_events
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.follows_synced.fetch_add(1, Ordering::Relaxed);
                debug!(event = ?sync_event, "Synchronized follow graph from firehose commit");
            }
            return Ok(ProcessCommitResult::FollowSynced(sync_event));
        }

        // Tier 0.5: Sovereign Config Collection Intercept (PRD §2.2)
        if commit.collection.as_str() == crate::modlist::SOVEREIGN_CONFIG_COLLECTION {
            if self.is_protected(&commit.did) {
                return Ok(self.handle_sovereign_config_commit(commit));
            }
            return Ok(ProcessCommitResult::Ignored);
        }

        // Tier 0.6: List Metadata Intercept (PRD §2.2)
        if commit.collection.as_str() == "app.bsky.graph.list" {
            if self.is_protected(&commit.did) {
                return Ok(self.handle_list_commit(commit));
            }
            return Ok(ProcessCommitResult::Ignored);
        }

        // Tier 1: Post Collection & Operation Filter
        if commit.collection.as_str() != "app.bsky.feed.post"
            || commit.operation != CommitOperation::Create
        {
            return Ok(ProcessCommitResult::Ignored);
        }

        // Tier 2: Target Matcher Extraction
        let interactions = {
            let guard = self.protected_dids.read();
            TargetMatcher::match_all_interactions(commit, &guard)
        };
        if interactions.is_empty() {
            return Ok(ProcessCommitResult::NoMatch);
        }

        let count = u64::try_from(interactions.len()).unwrap_or(0);
        self.stats
            .interactions_matched
            .fetch_add(count, Ordering::Relaxed);

        let mut outcomes = Vec::with_capacity(interactions.len());
        for interaction in interactions {
            let outcome = self
                .process_interaction_queued(interaction, eval_tx)
                .await?;
            outcomes.push(outcome);
        }

        Ok(ProcessCommitResult::InteractionsProcessed(outcomes))
    }

    /// Evaluates an extracted interaction through the fast-path gates and caches,
    /// enqueueing surviving candidates to the decoupled background evaluation queue.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if cache query or PDS mutation fails.
    #[instrument(skip(self, interaction, eval_tx), fields(author = %interaction.author_did, target = %interaction.target_did, post_uri = %interaction.post_uri))]
    pub async fn process_interaction_queued(
        &self,
        interaction: Interaction,
        eval_tx: &mpsc::Sender<Interaction>,
    ) -> Result<InteractionOutcome, SkybouncerError> {
        let author_did = interaction.author_did.clone();
        let target_did = interaction.target_did.clone();
        let post_uri = interaction.post_uri.clone();

        // Tier 3: Non-Followed Cost Control Gate (<1µs, $0 cost)
        let decision = self.gate.evaluate(interaction.clone());
        if let GateDecision::Bypassed { reason, .. } = decision {
            match reason {
                BypassReason::SelfInteraction => {
                    self.stats
                        .gate_bypassed_self
                        .fetch_add(1, Ordering::Relaxed);
                }
                BypassReason::FollowedAuthor => {
                    self.stats
                        .gate_bypassed_followed
                        .fetch_add(1, Ordering::Relaxed);
                }
                BypassReason::AllowlistedAuthor => {
                    self.stats
                        .gate_bypassed_allowlist
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            debug!(reason = ?reason, "Bypassed interaction at gate with zero cost");
            return Ok(InteractionOutcome::Bypassed {
                reason,
                author_did,
                target_did,
            });
        }

        // Tier 3.5: Moderation Pause Check
        if self.is_tenant_paused(&target_did) {
            debug!(
                author = %author_did,
                target = %target_did,
                "Engine or tenant is paused; bypassing interaction evaluation"
            );
            return Ok(InteractionOutcome::Paused {
                author_did,
                target_did,
            });
        }

        // Tier 4: Deduplication Cache Check (<50µs, $0 cost)
        self.stats
            .candidates_evaluated
            .fetch_add(1, Ordering::Relaxed);
        if self.cache.is_bounced_for(&target_did, &author_did)? {
            self.stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!("Author already bounced in deduplication cache; skipping evaluation");
            return Ok(InteractionOutcome::AlreadyBounced {
                author_did,
                target_did,
            });
        }

        // Tier 5: Evaluation TTL Cache Check (<50µs, $0 cost)
        let eval_cache_key = format!("{}:{}", post_uri, target_did);
        let cached_verdict = self.cache.get_evaluation(&eval_cache_key)?;
        if let Some(verdict) = cached_verdict {
            self.stats.eval_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!("Evaluation cache hit for post; reusing verdict");
            return self.act_on_verdict(&interaction, verdict).await;
        }

        // Tier 6: Zero-Cost Regex Heuristic Pre-Filter (<500ns, $0 cost)
        let heuristic_verdict = self.heuristic_classifier.evaluate(&interaction);
        if heuristic_verdict.is_violation() {
            self.stats
                .heuristic_violations
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .violations_detected
                .fetch_add(1, Ordering::Relaxed);
            debug!("Heuristic regex pre-filter detected violation at zero cost");
            let _ = self.cache.set_evaluation(
                &eval_cache_key,
                &author_did,
                &heuristic_verdict,
                self.config.evaluation_ttl,
            );
            return self.act_on_verdict(&interaction, heuristic_verdict).await;
        }

        // Enqueue candidate for background evaluation
        match eval_tx.try_send(interaction) {
            Ok(()) => {
                self.stats
                    .eval_queue_enqueued
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    author = %author_did,
                    target = %target_did,
                    "Candidate enqueued for background evaluation"
                );
                Ok(InteractionOutcome::QueuedForEvaluation {
                    author_did,
                    target_did,
                    post_uri,
                })
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats
                    .eval_queue_overflows
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    author = %author_did,
                    target = %target_did,
                    "Evaluation queue saturated; shedding load to preserve Jetstream subscriber throughput"
                );
                Ok(InteractionOutcome::QueueOverflow {
                    author_did,
                    target_did,
                    post_uri,
                })
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("Evaluation queue channel closed");
                Err(SkybouncerError::Ingestion(
                    "Evaluation queue channel closed".to_string(),
                ))
            }
        }
    }

    /// Evaluates an extracted interaction through the non-followed gate, caches, classifiers, and modlist mutator synchronously.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if classifier evaluation, cache query, or PDS mutation fails.
    #[instrument(skip(self, interaction), fields(author = %interaction.author_did, target = %interaction.target_did, post_uri = %interaction.post_uri))]
    pub async fn process_interaction(
        &self,
        interaction: Interaction,
    ) -> Result<InteractionOutcome, SkybouncerError> {
        let author_did = interaction.author_did.clone();
        let target_did = interaction.target_did.clone();
        let post_uri = interaction.post_uri.clone();

        // Tier 3: Non-Followed Cost Control Gate (<1µs, $0 cost)
        let decision = self.gate.evaluate(interaction.clone());
        if let GateDecision::Bypassed { reason, .. } = decision {
            match reason {
                BypassReason::SelfInteraction => {
                    self.stats
                        .gate_bypassed_self
                        .fetch_add(1, Ordering::Relaxed);
                }
                BypassReason::FollowedAuthor => {
                    self.stats
                        .gate_bypassed_followed
                        .fetch_add(1, Ordering::Relaxed);
                }
                BypassReason::AllowlistedAuthor => {
                    self.stats
                        .gate_bypassed_allowlist
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            debug!(reason = ?reason, "Bypassed interaction at gate with zero cost");
            return Ok(InteractionOutcome::Bypassed {
                reason,
                author_did,
                target_did,
            });
        }

        // Tier 3.5: Moderation Pause Check
        if self.is_tenant_paused(&target_did) {
            debug!(
                author = %author_did,
                target = %target_did,
                "Engine or tenant is paused; bypassing interaction evaluation"
            );
            return Ok(InteractionOutcome::Paused {
                author_did,
                target_did,
            });
        }

        // Tier 4: Deduplication Cache Check (<50µs, $0 cost)
        self.stats
            .candidates_evaluated
            .fetch_add(1, Ordering::Relaxed);
        if self.cache.is_bounced_for(&target_did, &author_did)? {
            self.stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!("Author already bounced in deduplication cache; skipping evaluation");
            return Ok(InteractionOutcome::AlreadyBounced {
                author_did,
                target_did,
            });
        }

        // Tier 5: Evaluation TTL Cache Check (<50µs, $0 cost)
        let eval_cache_key = format!("{}:{}", post_uri, target_did);
        let cached_verdict = self.cache.get_evaluation(&eval_cache_key)?;
        if let Some(verdict) = cached_verdict {
            self.stats.eval_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!("Evaluation cache hit for post; reusing verdict");
            return self.act_on_verdict(&interaction, verdict).await;
        }

        // Tier 6: Zero-Cost Regex Heuristic Pre-Filter (<500ns, $0 cost)
        let heuristic_verdict = self.heuristic_classifier.evaluate(&interaction);
        if heuristic_verdict.is_violation() {
            self.stats
                .heuristic_violations
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .violations_detected
                .fetch_add(1, Ordering::Relaxed);
            debug!("Heuristic regex pre-filter detected violation at zero cost");

            // Cache the verdict with configured TTL
            let _ = self.cache.set_evaluation(
                &eval_cache_key,
                &author_did,
                &heuristic_verdict,
                self.config.evaluation_ttl,
            );

            let outcome = self
                .act_on_verdict(&interaction, heuristic_verdict.clone())
                .await;

            let outcome_str = match &outcome {
                Ok(InteractionOutcome::Bounced { .. }) => "Bounced (Regex Pre-filter)",
                Ok(InteractionOutcome::BelowThreshold { .. }) => {
                    "Below Threshold (Regex Pre-filter)"
                }
                Ok(InteractionOutcome::AlreadyBounced { .. }) => "Already Bounced",
                Ok(InteractionOutcome::RateLimited { .. }) => "Rate Limited",
                Ok(InteractionOutcome::Paused { .. }) => "Paused",
                Ok(InteractionOutcome::Permitted { .. }) => "Permitted",
                Ok(InteractionOutcome::Bypassed { .. }) => "Bypassed",
                Ok(InteractionOutcome::QueuedForEvaluation { .. }) => "Queued",
                Ok(InteractionOutcome::QueueOverflow { .. }) => "Queue Overflow",
                Err(_) => "Error (Regex Pre-filter)",
            };

            let target_handle = self
                .tenant_registry
                .get(&target_did)
                .ok()
                .flatten()
                .and_then(|t| t.handle)
                .unwrap_or_default();

            let log_entry = crate::modlist::cache::NewEvaluationLog {
                timestamp_us: crate::modlist::cache::current_time_us(),
                source: "live".to_string(),
                post_uri: interaction.post_uri.clone(),
                post_text: interaction.text.clone(),
                author_did: interaction.author_did.clone(),
                author_handle: String::new(),
                target_did: interaction.target_did.clone(),
                target_handle,
                has_images: interaction.has_images(),
                primary_model: "heuristic_prefilter".to_string(),
                primary_action: "violation".to_string(),
                primary_confidence: 1.0,
                primary_category: heuristic_verdict
                    .category()
                    .map(|c| c.to_string())
                    .unwrap_or_default(),
                primary_reason: heuristic_verdict.reason().to_string(),
                escalated: false,
                escalation_reason: Some("Heuristic regex instant match".to_string()),
                fallback_model: None,
                fallback_action: None,
                fallback_confidence: None,
                fallback_category: None,
                fallback_reason: None,
                final_action: "violation".to_string(),
                final_confidence: 1.0,
                outcome: outcome_str.to_string(),
            };
            if let Err(e) = self.cache.record_evaluation_log(&log_entry) {
                tracing::warn!(error = %e, "Failed to record evaluation log in cache");
                self.stats
                    .errors_encountered
                    .fetch_add(1, Ordering::Relaxed);
            }

            return outcome;
        }

        self.evaluate_candidate(interaction).await
    }

    /// Evaluates a candidate interaction against the primary classifier model and performs PDS bounce if violated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if classifier evaluation, cache query, or PDS mutation fails.
    #[instrument(skip(self, interaction), fields(author = %interaction.author_did, target = %interaction.target_did, post_uri = %interaction.post_uri))]
    pub async fn evaluate_candidate(
        &self,
        interaction: Interaction,
    ) -> Result<InteractionOutcome, SkybouncerError> {
        let author_did = interaction.author_did.clone();
        let target_did = interaction.target_did.clone();
        let post_uri = interaction.post_uri.clone();

        if self.is_tenant_paused(&target_did) {
            debug!(
                author = %author_did,
                target = %target_did,
                "Engine or tenant is paused; bypassing queued evaluation"
            );
            return Ok(InteractionOutcome::Paused {
                author_did,
                target_did,
            });
        }

        // Double check dedup cache before making expensive model call,
        // in case a prior candidate from the same author already resulted in a bounce while this was queued!
        if self.cache.is_bounced_for(&target_did, &author_did)? {
            self.stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!(
                author = %author_did,
                target = %target_did,
                "Author bounced while candidate was queued; skipping model call"
            );
            return Ok(InteractionOutcome::AlreadyBounced {
                author_did,
                target_did,
            });
        }

        // Tier 4: Per-User Evaluation Rate Limiter (Anti-Denial-of-Wallet, PRD §5.2) - checked at dequeue
        if !self.rate_limiter.check_and_record(&target_did) {
            self.stats
                .rate_limited_evaluations
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                target = %target_did,
                author = %author_did,
                "Evaluation rate limit reached for target user; skipping external model call"
            );
            return Ok(InteractionOutcome::RateLimited {
                author_did,
                target_did,
                reason: "Tier-4 Anti-Denial-of-Wallet rate limit exceeded".to_string(),
            });
        }

        // Context Enricher: Fetch author profile & parent post context (PRD §3 & §4.2)
        let enriched = self.enricher.enrich(&interaction).await;
        let interaction = if !enriched.is_empty() {
            self.stats
                .context_enrichments
                .fetch_add(1, Ordering::Relaxed);
            interaction.with_enriched_context(enriched)
        } else {
            interaction
        };

        // Tier 7: Primary Model Evaluation
        self.stats.model_evaluations.fetch_add(1, Ordering::Relaxed);
        self.stats.tier1_evaluations.fetch_add(1, Ordering::Relaxed);
        let target_rubric = self.rubric_for(&target_did);
        let interaction = interaction.with_rubric(target_rubric.clone());
        let detailed_eval = self
            .classifier
            .classify_detailed_with_stats_and_rubric(&interaction, Some(&target_rubric), true)
            .await
            .inspect_err(|_e| {
                self.stats
                    .errors_encountered
                    .fetch_add(1, Ordering::Relaxed);
            })?;

        if detailed_eval.escalated {
            self.stats.tier2_evaluations.fetch_add(1, Ordering::Relaxed);
            if detailed_eval
                .escalation_reason
                .as_deref()
                .unwrap_or("")
                .contains("image")
            {
                self.stats
                    .tier2_image_escalations
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                self.stats
                    .tier2_uncertainty_escalations
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        let model_verdict = detailed_eval.final_verdict.clone();
        if model_verdict.is_violation() {
            self.stats
                .violations_detected
                .fetch_add(1, Ordering::Relaxed);
        }

        // Cache the verdict with configured TTL
        let eval_cache_key = format!("{}:{}", post_uri, target_did);
        let _ = self.cache.set_evaluation(
            &eval_cache_key,
            &author_did,
            &model_verdict,
            self.config.evaluation_ttl,
        );

        // Tier 8: Rubric Sensitivity Gate & Sovereign PDS Bounce
        let outcome = self
            .act_on_verdict(&interaction, model_verdict.clone())
            .await;

        let outcome_str = match &outcome {
            Ok(InteractionOutcome::Bounced { .. }) => "Bounced",
            Ok(InteractionOutcome::Permitted { .. }) => "Permitted",
            Ok(InteractionOutcome::BelowThreshold { .. }) => "Below Rubric Threshold",
            Ok(InteractionOutcome::AlreadyBounced { .. }) => "Already Bounced",
            Ok(InteractionOutcome::RateLimited { .. }) => "Rate Limited",
            Ok(InteractionOutcome::Paused { .. }) => "Paused",
            Ok(InteractionOutcome::Bypassed { .. }) => "Bypassed",
            Ok(InteractionOutcome::QueuedForEvaluation { .. }) => "Queued",
            Ok(InteractionOutcome::QueueOverflow { .. }) => "Queue Overflow",
            Err(_) => "Error",
        };

        let author_handle = interaction
            .enriched_context
            .as_ref()
            .and_then(|c| c.author.as_ref())
            .and_then(|a| a.handle.clone())
            .unwrap_or_default();

        let target_handle = self
            .tenant_registry
            .get(&target_did)
            .ok()
            .flatten()
            .and_then(|t| t.handle)
            .unwrap_or_default();

        let primary_confidence = detailed_eval.primary_verdict.confidence().unwrap_or(1.0);

        let fallback_confidence = detailed_eval
            .fallback_verdict
            .as_ref()
            .and_then(|v| v.confidence());

        let final_confidence = model_verdict.confidence().unwrap_or(1.0);

        let log_entry = crate::modlist::cache::NewEvaluationLog {
            timestamp_us: crate::modlist::cache::current_time_us(),
            source: "live".to_string(),
            post_uri: interaction.post_uri.clone(),
            post_text: interaction.text.clone(),
            author_did: interaction.author_did.clone(),
            author_handle,
            target_did: interaction.target_did.clone(),
            target_handle,
            has_images: interaction.has_images(),
            primary_model: detailed_eval.primary_model,
            primary_action: if detailed_eval.primary_verdict.is_violation() {
                "violation".to_string()
            } else {
                "allow".to_string()
            },
            primary_confidence,
            primary_category: detailed_eval
                .primary_verdict
                .category()
                .map(|c| c.to_string())
                .unwrap_or_default(),
            primary_reason: detailed_eval.primary_verdict.reason().to_string(),
            escalated: detailed_eval.escalated,
            escalation_reason: detailed_eval.escalation_reason,
            fallback_model: detailed_eval.fallback_model,
            fallback_action: detailed_eval.fallback_verdict.as_ref().map(|v| {
                if v.is_violation() {
                    "violation".to_string()
                } else {
                    "allow".to_string()
                }
            }),
            fallback_confidence,
            fallback_category: detailed_eval
                .fallback_verdict
                .as_ref()
                .and_then(|v| v.category().map(|c| c.to_string())),
            fallback_reason: detailed_eval
                .fallback_verdict
                .as_ref()
                .map(|v| v.reason().to_string()),
            final_action: if model_verdict.is_violation() {
                "violation".to_string()
            } else {
                "allow".to_string()
            },
            final_confidence,
            outcome: outcome_str.to_string(),
        };

        if let Err(e) = self.cache.record_evaluation_log(&log_entry) {
            tracing::warn!(error = %e, "Failed to record evaluation log in cache");
            self.stats
                .errors_encountered
                .fetch_add(1, Ordering::Relaxed);
        }

        outcome
    }

    /// Evaluates a classifier verdict against the rubric sensitivity threshold and executes PDS bounce if actionable.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS mutation or cache recording fails.
    #[instrument(skip(self, interaction, verdict), fields(author = %interaction.author_did, target = %interaction.target_did, post_uri = %interaction.post_uri))]
    pub async fn act_on_verdict(
        &self,
        interaction: &Interaction,
        verdict: Verdict,
    ) -> Result<InteractionOutcome, SkybouncerError> {
        let author_did = interaction.author_did.clone();
        let target_did = interaction.target_did.clone();
        let post_uri = interaction.post_uri.clone();
        let post_text = interaction.text.clone();

        match verdict {
            Verdict::Permitted { reason, .. } => {
                self.stats.permitted.fetch_add(1, Ordering::Relaxed);
                Ok(InteractionOutcome::Permitted {
                    author_did,
                    target_did,
                    reason,
                })
            }
            Verdict::Violation {
                category,
                confidence,
                reason,
            } => {
                let rubric = self.rubric_for(&target_did);
                let threshold = rubric.sensitivity.threshold();
                if !rubric.meets_threshold(&category, confidence) {
                    self.stats
                        .bounces_skipped_rubric
                        .fetch_add(1, Ordering::Relaxed);
                    self.stats.permitted.fetch_add(1, Ordering::Relaxed);
                    debug!(
                        confidence = %confidence,
                        threshold = %threshold,
                        "Violation confidence below rubric threshold; skipping bounce"
                    );
                    return Ok(InteractionOutcome::BelowThreshold {
                        author_did,
                        target_did,
                        category,
                        confidence,
                        threshold,
                    });
                }

                // Actionable violation: bounce on sovereign PDS
                let expires_at = rubric.bounce_duration.expires_at_us(current_time_us());
                let pds_client = self.resolve_pds_client_for(&target_did).await?;
                let bounce_result = self
                    .modlist_manager
                    .bounce_user_with_text(
                        &pds_client,
                        &target_did,
                        &author_did,
                        &category,
                        confidence,
                        &reason,
                        &post_uri,
                        &post_text,
                        expires_at,
                    )
                    .await
                    .inspect_err(|_e| {
                        self.stats
                            .errors_encountered
                            .fetch_add(1, Ordering::Relaxed);
                    })?;

                match bounce_result {
                    Some(listitem_uri) => {
                        self.stats.bounces_executed.fetch_add(1, Ordering::Relaxed);
                        self.stats.bounced.fetch_add(1, Ordering::Relaxed);
                        info!(
                            violator = %author_did,
                            listitem = %listitem_uri,
                            category = %category,
                            confidence = %confidence,
                            "Bounced violator on sovereign PDS"
                        );

                        // Emit proactive bounce notification for alert dispatchers
                        let _ = self.bounce_notifier.send(BounceNotification {
                            target_did: target_did.clone(),
                            violator_did: author_did.clone(),
                            category: category.clone(),
                            confidence,
                            reason: reason.clone(),
                            post_uri: post_uri.clone(),
                            post_snippet: interaction.text.chars().take(200).collect(),
                        });

                        Ok(InteractionOutcome::Bounced {
                            author_did,
                            target_did,
                            listitem_uri,
                            category,
                            confidence,
                            reason,
                        })
                    }
                    None => {
                        // Double-checked locking detected concurrent task already bounced author
                        self.stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);
                        Ok(InteractionOutcome::AlreadyBounced {
                            author_did,
                            target_did,
                        })
                    }
                }
            }
        }
    }

    /// Dynamically adds a protected user DID to the engine's active watch set.
    pub fn add_protected_did(&self, did: impl Into<String>) {
        let mut guard = self.protected_dids.write();
        guard.insert(did.into());
    }

    /// Removes a protected user DID from the engine's active watch set.
    pub fn remove_protected_did(&self, did: &str) -> bool {
        let mut guard = self.protected_dids.write();
        guard.remove(did)
    }

    /// Checks whether a DID is currently protected.
    #[must_use]
    pub fn is_protected(&self, did: &str) -> bool {
        let guard = self.protected_dids.read();
        guard.contains(did)
    }

    /// Returns a snapshot of all currently protected DIDs.
    #[must_use]
    pub fn protected_dids(&self) -> HashSet<String> {
        let guard = self.protected_dids.read();
        guard.clone()
    }

    /// Sub-microsecond check verifying if a protected user follows a candidate.
    #[must_use]
    pub fn is_following(&self, protected_did: &str, candidate_did: &str) -> bool {
        self.follow_graph.is_following(protected_did, candidate_did)
    }

    /// Pre-seeds followed DIDs for a protected user on cold start.
    pub fn hydrate_follows<I, S>(&self, protected_did: impl Into<String>, dids: I) -> usize
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let target = protected_did.into();
        let mut count: usize = 0;
        for (idx, did) in dids.into_iter().enumerate() {
            let rkey = format!("hydrate_{idx}");
            self.follow_graph.add_follow(&target, rkey, did.into());
            count = count.saturating_add(1);
        }
        count
    }

    /// Pre-seeds followed DIDs with real repository rkeys on cold start.
    pub fn hydrate_follow_records<I, K, S>(
        &self,
        protected_did: impl Into<String>,
        records: I,
    ) -> usize
    where
        I: IntoIterator<Item = (K, S)>,
        K: Into<String>,
        S: Into<String>,
    {
        let target = protected_did.into();
        let mut count: usize = 0;
        for (rkey, did) in records {
            self.follow_graph
                .add_follow(&target, rkey.into(), did.into());
            count = count.saturating_add(1);
        }
        count
    }

    /// Checks whether an account is currently recorded as bounced in the SQLite cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_bounced(&self, subject_did: &str) -> Result<bool, SkybouncerError> {
        self.cache.is_bounced(subject_did)
    }

    /// Retrieves detailed record of a bounced violator if present.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_bounced_user(
        &self,
        subject_did: &str,
    ) -> Result<Option<BouncedUser>, SkybouncerError> {
        self.cache.get_bounced_user(subject_did)
    }

    /// Lists recently bounced violators ordered by most recent bounce timestamp descending.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_recent_bounces(&self, limit: usize) -> Result<Vec<BouncedUser>, SkybouncerError> {
        self.cache.list_recent_bounces(limit)
    }

    /// Lists recently bounced violators filtered by an optional protected user DID,
    /// ordered by most recent bounce timestamp descending.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_recent_bounces_for(
        &self,
        protected_did: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BouncedUser>, SkybouncerError> {
        self.cache.list_recent_bounces_for(protected_did, limit)
    }

    /// Pardons an account by deleting its listitems from the PDS and purging the cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS deletion or cache mutation fails.
    pub async fn pardon_user(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        self.modlist_manager
            .pardon_user(&pds_client, protected_did, subject_did)
            .await
    }

    /// Pardons an account by deleting its listitems from the PDS, purging the cache,
    /// and immunizes them from future moderation actions by adding them to the allowlist.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS deletion, cache mutation, or allowlist insertion fails.
    pub async fn pardon_and_allowlist(
        &self,
        protected_did: &str,
        subject_did: &str,
        reason: Option<&str>,
    ) -> Result<bool, SkybouncerError> {
        let pardoned = self.pardon_user(protected_did, subject_did).await?;
        self.add_to_allowlist(
            protected_did,
            subject_did,
            reason.or(Some("Immunized via pardon")),
        )?;
        Ok(pardoned)
    }

    /// Checks whether an author is in the protected user's allowlist (<1µs in-memory lookup).
    #[must_use]
    pub fn is_allowlisted(&self, protected_did: &str, author_did: &str) -> bool {
        self.gate.is_allowlisted(protected_did, author_did)
    }

    /// Adds an author to both persistent SQLite cache and in-memory allowlist for a protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if database insertion fails.
    pub fn add_to_allowlist(
        &self,
        protected_did: &str,
        author_did: &str,
        reason: Option<&str>,
    ) -> Result<(), SkybouncerError> {
        self.cache
            .add_to_allowlist(protected_did, author_did, reason)?;
        self.gate.add_to_allowlist(protected_did, author_did);
        Ok(())
    }

    /// Removes an author from both persistent SQLite cache and in-memory allowlist for a protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if database deletion fails.
    pub fn remove_from_allowlist(
        &self,
        protected_did: &str,
        author_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let removed = self
            .cache
            .remove_from_allowlist(protected_did, author_did)?;
        self.gate.remove_from_allowlist(protected_did, author_did);
        Ok(removed)
    }

    /// Lists all allowlisted authors for a protected user from the persistent database.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if database query fails.
    pub fn list_allowlist(
        &self,
        protected_did: &str,
    ) -> Result<Vec<crate::modlist::AllowlistEntry>, SkybouncerError> {
        self.cache.list_allowlist(protected_did)
    }

    /// Ensures that the parent moderation list exists on the sovereign PDS.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if list provisioning fails.
    pub async fn ensure_mod_list(&self, protected_did: &str) -> Result<String, SkybouncerError> {
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        self.modlist_manager
            .ensure_mod_list(&pds_client, protected_did)
            .await
    }

    /// Ensures that an `app.bsky.graph.listblock` record exists on the sovereign PDS to auto-block list members.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if listblock creation fails.
    pub async fn ensure_list_blocked(
        &self,
        protected_did: &str,
        list_uri: &str,
    ) -> Result<(), SkybouncerError> {
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        self.modlist_manager
            .ensure_list_blocked(&pds_client, protected_did, list_uri)
            .await
    }

    /// Returns `true` if this engine operates in shadow dry-run mode.
    #[must_use]
    pub fn is_dry_run(&self) -> bool {
        self.config.dry_run
    }

    /// Returns `true` if automated moderation actions are temporarily paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Temporarily pauses automated moderation evaluations and PDS list mutations.
    ///
    /// Returns the previous pause state.
    pub fn pause(&self) -> bool {
        self.paused.swap(true, Ordering::SeqCst)
    }

    /// Resumes automated moderation evaluations and PDS list mutations.
    ///
    /// Returns the previous pause state.
    pub fn resume(&self) -> bool {
        self.paused.swap(false, Ordering::SeqCst)
    }

    /// Subscribes to real-time bounce notifications emitted when accounts are bounced on PDS.
    #[must_use]
    pub fn subscribe_bounces(&self) -> broadcast::Receiver<BounceNotification> {
        self.bounce_notifier.subscribe()
    }

    /// Resolves an ATProto handle to a DID using in-memory monotonic caching,
    /// tenant registry handle-mapping TTL caching, the persisted SQLite handle
    /// cache, and the configured context enricher.
    ///
    /// If the provided handle is already a DID (starts with `did:`), it is returned directly.
    pub async fn resolve_handle(&self, handle: &str) -> Option<String> {
        let clean = handle.trim().trim_start_matches('@');
        if clean.starts_with("did:") {
            return Some(clean.to_string());
        }
        let now = std::time::Instant::now();

        // 1. In-memory monotonic check
        {
            let guard = self.handle_cache.read();
            if let Some((did, cached_at)) = guard.get(clean) {
                if now.saturating_duration_since(*cached_at) < self.config.handle_cache_ttl {
                    return Some(did.clone());
                }
            }
        }

        // 2. Tenant registry check with handle-mapping TTL
        if let Ok(Some(tenant)) = self
            .tenant_registry
            .get_by_handle_with_ttl(clean, self.config.handle_cache_ttl)
        {
            let _ = self.cache.set_handle_for_did(&tenant.did, clean);
            self.handle_cache
                .write()
                .insert(clean.to_string(), (tenant.did.clone(), now));
            return Some(tenant.did);
        }

        // 3. Persisted SQLite did_handles cache (TTL-bounded to avoid identity shadowing)
        let ttl_us = u64::try_from(self.config.handle_cache_ttl.as_micros()).unwrap_or(u64::MAX);
        if let Ok(Some(cached_did)) = self.cache.get_did_for_handle_with_ttl(clean, ttl_us) {
            self.handle_cache
                .write()
                .insert(clean.to_string(), (cached_did.clone(), now));
            return Some(cached_did);
        }

        // 4. Remote AppView resolution via enricher
        if let Some(live_did) = self.enricher.resolve_handle(clean).await {
            let _ = self.cache.set_handle_for_did(&live_did, clean);
            self.handle_cache
                .write()
                .insert(clean.to_string(), (live_did.clone(), now));
            return Some(live_did);
        }

        None
    }

    /// Invalidates a handle across the in-memory cache, the tenant registry, and
    /// the persisted SQLite handle cache.
    pub fn invalidate_handle(&self, handle: &str) {
        let clean = handle.trim().trim_start_matches('@');
        self.handle_cache.write().remove(clean);
        let _ = self.tenant_registry.invalidate_handle(clean);
        let _ = self.cache.remove_handle_for_handle(clean);
    }

    /// Clears all entries from the in-memory handle cache.
    pub fn clear_handle_cache(&self) {
        self.handle_cache.write().clear();
    }

    /// Resolves an ATProto DID to a handle using only local caches (tenant registry and SQLite).
    ///
    /// This never performs network I/O and is intended for enriching list responses where
    /// outbound resolution would otherwise cause an N+1 fan-out of remote lookups.
    #[must_use]
    pub fn cached_handle_for_did(&self, did: &str) -> Option<String> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }

        // 1. Check local tenant cache
        if let Ok(Some(tenant)) = self.tenant_registry.get(clean) {
            if let Some(handle) = tenant.handle {
                let trimmed = handle.trim().trim_start_matches('@').to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }

        // 2. Check SQLite did_handles cache
        if let Ok(Some(cached_handle)) = self.cache.get_handle_for_did(clean) {
            let trimmed = cached_handle.trim().trim_start_matches('@').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }

        None
    }

    /// Resolves an ATProto DID to a handle using cached tenant data, local handle cache, or the configured context enricher.
    ///
    /// If the handle was not already cached in the local tenant registry and is successfully resolved
    /// via the enricher, it is automatically cached into SQLite for future instant retrieval.
    pub async fn resolve_did_to_handle(&self, did: &str) -> Option<String> {
        let clean = did.trim();
        if !clean.starts_with("did:") {
            return None;
        }

        if let Some(cached) = self.cached_handle_for_did(clean) {
            return Some(cached);
        }

        // Resolve via enricher
        if let Some(resolved) = self.enricher.resolve_did(clean).await {
            let trimmed = resolved.trim().trim_start_matches('@').to_string();
            if !trimmed.is_empty() {
                let _ = self.cache.set_handle_for_did(clean, &trimmed);
                let _ = self.tenant_registry.update_handle(clean, &trimmed);
                return Some(trimmed);
            }
        }

        None
    }

    /// Returns a copy of the active configuration with the current live rubric.
    #[must_use]
    pub fn config(&self) -> SkybouncerConfig {
        let mut cfg = self.config.clone();
        cfg.rubric = self.rubric();
        cfg
    }

    /// Returns a copy of the active rule rubric.
    #[must_use]
    pub fn rubric(&self) -> RuleRubric {
        self.rubric.read().clone()
    }

    /// Updates the active moderation rubric in real time across the engine, modlist manager, and classifier.
    pub fn set_rubric(&self, rubric: RuleRubric) {
        *self.rubric.write() = rubric.clone();
        self.modlist_manager.set_rubric(rubric.clone());
        self.classifier.set_rubric(rubric);
    }

    /// Returns a reference to the heuristic classifier.
    #[must_use]
    pub fn heuristic_classifier(&self) -> &HeuristicClassifier {
        &self.heuristic_classifier
    }

    /// Returns a reference to the primary classifier.
    #[must_use]
    pub fn primary_classifier(&self) -> &Arc<dyn Classifier> {
        &self.classifier
    }

    /// Returns a reference to the follow graph.
    #[must_use]
    pub fn follow_graph(&self) -> &Arc<FollowGraph> {
        &self.follow_graph
    }

    /// Returns a reference to the non-followed gate.
    #[must_use]
    pub fn gate(&self) -> &Arc<NonFollowedGate> {
        &self.gate
    }

    /// Returns a reference to the deduplication cache.
    #[must_use]
    pub fn cache(&self) -> &Arc<DeduplicationCache> {
        &self.cache
    }

    /// Returns a reference to the PDS repository client.
    #[must_use]
    pub fn pds_client(&self) -> &Arc<PdsRepoClient> {
        &self.pds_client
    }

    /// Returns a reference to the operational statistics.
    #[must_use]
    pub fn stats(&self) -> &Arc<EngineStats> {
        &self.stats
    }

    /// Persists the current cumulative telemetry counters to durable storage.
    ///
    /// Called periodically and during graceful shutdown so dashboard KPI totals survive
    /// process restarts and deployments.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the snapshot cannot be serialized or written.
    pub fn persist_stats(&self) -> Result<(), SkybouncerError> {
        let snapshot = self.stats.snapshot();
        self.cache.save_dashboard_stats(&snapshot)
    }

    /// Returns a reference to the evaluation rate limiter.
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<EvaluationRateLimiter> {
        &self.rate_limiter
    }

    /// Returns a reference to the context enricher.
    #[must_use]
    pub fn enricher(&self) -> &Arc<dyn ContextEnricher> {
        &self.enricher
    }

    /// Returns a reference to the multi-tenant registry.
    #[must_use]
    pub fn tenant_registry(&self) -> &Arc<TenantRegistry> {
        &self.tenant_registry
    }

    /// Enrolls or updates an active tenant in the registry and active watch set.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if tenant registration fails.
    pub fn enroll_tenant(&self, tenant: Tenant) -> Result<(), SkybouncerError> {
        let did = tenant.did.clone();
        self.tenant_registry.register_or_update(&tenant)?;
        self.add_protected_did(did);
        Ok(())
    }

    /// Checks whether a DID is an enrolled tenant in the registry.
    #[must_use]
    pub fn is_enrolled(&self, did: &str) -> bool {
        self.tenant_registry.is_enrolled(did).unwrap_or(false)
    }

    /// Checks whether the given DID has administrator privileges.
    #[must_use]
    pub fn is_admin(&self, did: &str) -> bool {
        let clean = did.trim();
        if clean.is_empty() {
            return false;
        }

        if let Some(ref admin) = self.config.admin_did {
            let admin_clean = admin.trim();
            if !admin_clean.is_empty() && admin_clean.eq_ignore_ascii_case(clean) {
                return true;
            }
        }

        false
    }

    /// Returns true if running in single-tenant mode (at most one protected DID besides admin, and no multi-tenant enrollments).
    #[must_use]
    pub fn is_single_tenant(&self) -> bool {
        if self.tenant_registry.count().unwrap_or(0) > 1 {
            return false;
        }
        let guard = self.protected_dids.read();
        let non_admin_count = guard.iter().filter(|d| !self.is_admin(d)).count();
        non_admin_count <= 1
    }

    /// Checks whether a tenant is paused (or the entire engine is paused).
    #[must_use]
    pub fn is_tenant_paused(&self, did: &str) -> bool {
        if self.is_paused() {
            return true;
        }
        match self.tenant_registry.get(did) {
            Ok(Some(tenant)) => !tenant.is_active,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "Failed to query tenant status; failing closed (paused)");
                true
            }
        }
    }

    /// Retrieves the moderation rubric for a specific protected user, falling back to engine default rubric.
    #[must_use]
    pub fn rubric_for(&self, did: &str) -> RuleRubric {
        if let Ok(Some(tenant)) = self.tenant_registry.get(did) {
            if let Some(rubric) = tenant.rubric {
                return rubric;
            }
        }
        self.rubric()
    }

    /// Resolves the [`PdsRepoClient`] for a specific protected user, failing closed if tenant resolution fails.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the tenant is enrolled but client resolution or token refresh fails,
    /// or if no client is available for the given DID.
    pub async fn resolve_pds_client_for(
        &self,
        did: &str,
    ) -> Result<Arc<PdsRepoClient>, SkybouncerError> {
        let oc = self.oauth_client.read().clone();
        match self.tenant_registry.get_pds_client(did, oc.as_ref()).await {
            Ok(Some(client)) => Ok(client),
            Ok(None) => {
                let has_enrolled_tenants = self.tenant_registry.count().unwrap_or(0) > 0;
                if self.pds_client.did() == did
                    || self.is_admin(did)
                    || (!has_enrolled_tenants && self.is_protected(did))
                    || (self.is_single_tenant() && self.is_protected(did))
                {
                    Ok(Arc::clone(&self.pds_client))
                } else {
                    Err(SkybouncerError::Config(format!(
                        "No PDS client or OAuth credentials found for tenant {did}"
                    )))
                }
            }
            Err(e) => {
                tracing::error!(
                    did = %did,
                    error = %e,
                    "Failed to resolve PDS client for tenant; refusing to fall back to admin client"
                );
                Err(e)
            }
        }
    }

    /// Retrieves the [`PdsRepoClient`] for a specific protected user, falling back to default engine client.
    ///
    /// Prefer [`Self::resolve_pds_client_for`] to propagate resolution and authentication errors safely.
    pub async fn pds_client_for(&self, did: &str) -> Arc<PdsRepoClient> {
        self.resolve_pds_client_for(did)
            .await
            .unwrap_or_else(|_| Arc::clone(&self.pds_client))
    }

    /// Synchronizes sovereign moderation rules from the protected user's PDS repository.
    ///
    /// Reads `social.skybouncer.config` or list metadata description on the user's PDS.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS communication fails.
    pub async fn sync_sovereign_config(
        &self,
        protected_did: &str,
    ) -> Result<Option<RuleRubric>, SkybouncerError> {
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        let pds_rubric = crate::modlist::fetch_sovereign_config(&pds_client, protected_did).await?;
        if let Some(ref rubric) = pds_rubric {
            if self.is_enrolled(protected_did) {
                let _ = self.tenant_registry.update_rubric(protected_did, rubric);
            }
            if self.is_admin(protected_did)
                || (self.is_single_tenant() && self.is_protected(protected_did))
            {
                self.set_rubric(rubric.clone());
            }
            info!(
                did = %protected_did,
                rubric = %rubric.prompt,
                "Synchronized sovereign rules from PDS repo"
            );
        }
        Ok(pds_rubric)
    }

    /// Publishes current active rules to the user's sovereign ATProto repository.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS mutation fails.
    pub async fn publish_sovereign_config(
        &self,
        protected_did: &str,
    ) -> Result<String, SkybouncerError> {
        let rubric = self.rubric_for(protected_did);
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        crate::modlist::publish_sovereign_config(&pds_client, protected_did, &rubric).await
    }

    /// Handles a commit event on `social.skybouncer.config` for a protected user.
    fn handle_sovereign_config_commit(&self, commit: &JetstreamCommit) -> ProcessCommitResult {
        match commit.operation {
            CommitOperation::Create | CommitOperation::Update => {
                if let Some(ref record_val) = commit.record {
                    match serde_json::from_value::<crate::modlist::SovereignConfigRecord>(
                        record_val.clone(),
                    ) {
                        Ok(config_record) => {
                            let rubric = config_record.to_rubric();
                            if self.is_enrolled(&commit.did) {
                                let _ = self.tenant_registry.update_rubric(&commit.did, &rubric);
                            }
                            if self.is_admin(&commit.did)
                                || (self.is_single_tenant() && self.is_protected(&commit.did))
                            {
                                self.set_rubric(rubric.clone());
                            }
                            self.stats
                                .sovereign_configs_synced
                                .fetch_add(1, Ordering::Relaxed);
                            info!(
                                did = %commit.did,
                                prompt = %rubric.prompt,
                                sensitivity = %rubric.sensitivity,
                                "Hot-reloaded sovereign moderation rules from Jetstream firehose"
                            );
                            ProcessCommitResult::SovereignConfigSynced(
                                SovereignConfigSyncEvent::Updated {
                                    did: commit.did.clone(),
                                    prompt: rubric.prompt,
                                    sensitivity: rubric.sensitivity,
                                },
                            )
                        }
                        Err(e) => {
                            warn!(
                                did = %commit.did,
                                error = %e,
                                "Failed to parse sovereign config record from firehose commit"
                            );
                            ProcessCommitResult::Ignored
                        }
                    }
                } else {
                    ProcessCommitResult::Ignored
                }
            }
            CommitOperation::Delete => {
                if commit.rkey == crate::modlist::SOVEREIGN_CONFIG_RKEY {
                    let default_rubric = self.config.rubric.clone();
                    if self.is_enrolled(&commit.did) {
                        if let Err(e) = self
                            .tenant_registry
                            .update_rubric(&commit.did, &default_rubric)
                        {
                            warn!(
                                did = %commit.did,
                                error = %e,
                                "Failed to reset tenant rubric in registry on sovereign config deletion"
                            );
                        }
                    }
                    if self.is_admin(&commit.did)
                        || (self.is_single_tenant() && self.is_protected(&commit.did))
                    {
                        self.set_rubric(default_rubric);
                    }
                    self.stats
                        .sovereign_configs_synced
                        .fetch_add(1, Ordering::Relaxed);
                    info!(
                        did = %commit.did,
                        "Sovereign configuration record deleted from PDS via firehose; reset to default rubric"
                    );
                    ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted {
                        did: commit.did.clone(),
                    })
                } else {
                    ProcessCommitResult::Ignored
                }
            }
        }
    }

    /// Handles a commit event on `app.bsky.graph.list` for a protected user.
    fn handle_list_commit(&self, commit: &JetstreamCommit) -> ProcessCommitResult {
        if commit.operation != CommitOperation::Create
            && commit.operation != CommitOperation::Update
        {
            return ProcessCommitResult::Ignored;
        }

        if let Some(ref record_val) = commit.record {
            if let Some(desc) = record_val.get("description").and_then(|d| d.as_str()) {
                if let Some(rubric) = crate::modlist::extract_rubric_from_list_description(desc) {
                    if self.is_enrolled(&commit.did) {
                        let _ = self.tenant_registry.update_rubric(&commit.did, &rubric);
                    }
                    if self.is_admin(&commit.did)
                        || (self.is_single_tenant() && self.is_protected(&commit.did))
                    {
                        self.set_rubric(rubric.clone());
                    }
                    self.stats
                        .sovereign_configs_synced
                        .fetch_add(1, Ordering::Relaxed);
                    info!(
                        did = %commit.did,
                        prompt = %rubric.prompt,
                        sensitivity = %rubric.sensitivity,
                        "Hot-reloaded sovereign moderation rules from list description metadata"
                    );
                    return ProcessCommitResult::SovereignConfigSynced(
                        SovereignConfigSyncEvent::ListMetadataUpdated {
                            did: commit.did.clone(),
                            prompt: rubric.prompt,
                            sensitivity: rubric.sensitivity,
                        },
                    );
                }
            }
        }
        ProcessCommitResult::Ignored
    }

    /// Runs the pipeline event processing loop reading from `rx` until cancelled.
    ///
    /// Commits from Jetstream are ingested on the fast path without blocking. Surviving
    /// candidate interactions are enqueued into a decoupled bounded evaluation channel,
    /// where background worker(s) evaluate candidates against the primary classifier model
    /// at controlled concurrency (`config.evaluation_concurrency`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if unrecoverable pipeline failure occurs.
    pub async fn run(
        &self,
        mut rx: mpsc::Receiver<JetstreamCommit>,
        cancel: CancellationToken,
    ) -> Result<EngineStatsSnapshot, SkybouncerError> {
        let queue_capacity = self.config.evaluation_queue_capacity.max(100);
        let (eval_tx, mut eval_rx) = mpsc::channel::<Interaction>(queue_capacity);
        let concurrency = self.config.evaluation_concurrency.max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));

        let eval_engine = self.clone();
        let mut eval_tasks = JoinSet::new();

        // Spawn background evaluation worker
        let queue_worker = async move {
            let mut active_evals = JoinSet::new();

            while let Ok(permit) = semaphore.clone().acquire_owned().await {
                match eval_rx.recv().await {
                    Some(candidate) => {
                        let eng = eval_engine.clone();
                        active_evals.spawn(async move {
                            let _permit = permit;
                            eng.stats
                                .eval_queue_processed
                                .fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = eng.evaluate_candidate(candidate).await {
                                warn!(error = %e, "Background candidate evaluation failed");
                            }
                        });
                    }
                    None => {
                        // Channel closed (eval_tx dropped) and empty
                        drop(permit);
                        break;
                    }
                }

                while let Some(res) = active_evals.try_join_next() {
                    let _ = res;
                }
            }

            // Drain remaining active evaluations
            while let Some(res) = active_evals.join_next().await {
                let _ = res;
            }
        };

        eval_tasks.spawn(queue_worker);

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    debug!("Engine processing loop received cancellation; draining buffered commits");
                    while let Ok(commit) = rx.try_recv() {
                        let _ = self.process_commit_queued(&commit, &eval_tx).await;
                    }
                    break;
                }
                commit_opt = rx.recv() => {
                    match commit_opt {
                        Some(commit) => {
                            let _ = self.process_commit_queued(&commit, &eval_tx).await;
                        }
                        None => {
                            debug!("Commit channel closed; shutting down engine loop");
                            break;
                        }
                    }
                }
            }
        }

        // Drop eval_tx so queue worker receives None after draining remaining queue items
        drop(eval_tx);

        // Wait for queue worker to finish draining (bounded by shutdown timeout)
        let drain_future = async {
            while let Some(res) = eval_tasks.join_next().await {
                let _ = res;
            }
        };

        if tokio::time::timeout(DEFAULT_SHUTDOWN_TIMEOUT, drain_future)
            .await
            .is_err()
        {
            warn!("Evaluation queue worker drain timed out; aborting background evaluations");
            eval_tasks.abort_all();
            while eval_tasks.join_next().await.is_some() {}
        }

        Ok(self.stats.snapshot())
    }

    /// Runs the pipeline event processing loop (alias for [`Self::run`]).
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if unrecoverable pipeline failure occurs.
    pub async fn run_pipeline(
        &self,
        rx: mpsc::Receiver<JetstreamCommit>,
        cancel: CancellationToken,
    ) -> Result<EngineStatsSnapshot, SkybouncerError> {
        self.run(rx, cancel).await
    }

    /// Prunes expired temporary bounces from both sovereign PDS moderation lists and the SQLite cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if querying expired bounces fails.
    pub async fn prune_expired_bounces(&self) -> Result<usize, SkybouncerError> {
        let now_us = current_time_us();
        let expired = self.cache.list_expired_bounces(now_us)?;
        if expired.is_empty() {
            return Ok(0);
        }

        let mut pruned_count = 0;
        for record in expired {
            match self
                .pardon_user(&record.protected_did, &record.subject_did)
                .await
            {
                Ok(true) => {
                    pruned_count += 1;
                    info!(
                        subject_did = %record.subject_did,
                        protected_did = %record.protected_did,
                        "Pruned expired temporary bounce from PDS and cache"
                    );
                }
                Ok(false) => {
                    debug!(
                        subject_did = %record.subject_did,
                        protected_did = %record.protected_did,
                        "Expired bounce record was already removed"
                    );
                }
                Err(e) => {
                    warn!(
                        subject_did = %record.subject_did,
                        protected_did = %record.protected_did,
                        error = %e,
                        "Failed to pardon expired bounce on PDS"
                    );
                }
            }
        }

        Ok(pruned_count)
    }

    /// Runs the periodic background maintenance loop to prune expired evaluation cache entries.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if cache maintenance fails.
    pub async fn run_maintenance(
        &self,
        interval_dur: Duration,
        cancel: CancellationToken,
    ) -> Result<usize, SkybouncerError> {
        let mut interval = tokio::time::interval(interval_dur);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut total_pruned: usize = 0;

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    match self.cache.prune_expired_evaluations() {
                        Ok(pruned) => {
                            total_pruned = total_pruned.saturating_add(pruned);
                            debug!(pruned, "Pruned expired evaluations from cache");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to prune expired evaluations in maintenance task");
                        }
                    }
                    if let Err(e) = self.persist_stats() {
                        warn!(error = %e, "Failed to persist dashboard telemetry counters in maintenance task");
                    }
                    self.rate_limiter.prune_stale();
                    match self.tenant_registry.prune_expired_web_sessions() {
                        Ok(count) => {
                            if count > 0 {
                                debug!(count, "Pruned expired web sessions");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to prune expired web sessions in maintenance task");
                        }
                    }
                    match self.prune_expired_bounces().await {
                        Ok(count) => {
                            if count > 0 {
                                info!(count, "Pruned expired temporary bounces from PDS and cache");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to prune expired bounces in maintenance task");
                        }
                    }
                    let now_us = current_time_us();
                    let did_handle_cutoff = now_us.saturating_sub(
                        u64::try_from(DEFAULT_DID_HANDLE_CACHE_TTL.as_micros()).unwrap_or(u64::MAX),
                    );
                    match self
                        .cache
                        .prune_did_handles(did_handle_cutoff, DEFAULT_DID_HANDLE_CACHE_MAX_ENTRIES)
                    {
                        Ok(count) => {
                            if count > 0 {
                                debug!(count, "Pruned stale DID-to-handle cache entries");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to prune DID-to-handle cache in maintenance task");
                        }
                    }
                }
            }
        }

        Ok(total_pruned)
    }

    /// Spawns the pipeline worker into a managed [`JoinSet`], returning an MPSC sender for commits.
    pub fn spawn_in_join_set(
        &self,
        join_set: &mut JoinSet<Result<EngineStatsSnapshot, SkybouncerError>>,
        cancel: CancellationToken,
    ) -> mpsc::Sender<JetstreamCommit> {
        let (tx, rx) = mpsc::channel(self.config.channel_capacity);
        let engine = self.clone();
        join_set.spawn(async move { engine.run(rx, cancel).await });
        tx
    }

    /// Gracefully drains in-flight tasks in a [`JoinSet`] with bounded timeout abort.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if shutdown coordination fails.
    pub async fn drain_and_shutdown<T: 'static>(
        join_set: &mut JoinSet<T>,
        cancel: &CancellationToken,
        timeout: Duration,
    ) -> Result<(), SkybouncerError> {
        cancel.cancel();
        let drain_future = async {
            while let Some(res) = join_set.join_next().await {
                let _ = res;
            }
        };

        if tokio::time::timeout(timeout, drain_future).await.is_err() {
            warn!(
                timeout = ?timeout,
                "Engine shutdown timed out; aborting remaining background tasks"
            );
            join_set.abort_all();
            while join_set.join_next().await.is_some() {}
        }

        Ok(())
    }
}

/// Builder for constructing [`SkybouncerEngine`] with optional component overrides.
pub struct SkybouncerEngineBuilder {
    config: SkybouncerConfig,
    follow_graph: Option<Arc<FollowGraph>>,
    gate: Option<Arc<NonFollowedGate>>,
    heuristic_classifier: Option<HeuristicClassifier>,
    classifier: Option<Arc<dyn Classifier>>,
    fallback_classifier: Option<Arc<dyn Classifier>>,
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

        let classifier: Arc<dyn Classifier> = match fallback_classifier {
            Some(fallback) => Arc::new(TieredClassifier::new(
                primary_classifier,
                fallback,
                self.config.certainty_config,
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
                        PdsRepoClient::from_credentials(endpoint, primary_did, token).map_err(
                            |e| SkybouncerError::Config(format!("Failed to build PDS client: {e}")),
                        )?,
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
                        PdsRepoClient::from_credentials(endpoint, primary_did, token).map_err(
                            |e| SkybouncerError::Config(format!("Failed to build PDS client: {e}")),
                        )?,
                    )
                } else {
                    Arc::new(
                        PdsRepoClient::from_credentials(
                            "https://bsky.social",
                            "did:plc:skybouncer_multi_tenant",
                            "multi_tenant_placeholder_token",
                        )
                        .map_err(|e| {
                            SkybouncerError::Config(format!(
                                "Failed to build fallback PDS client: {e}"
                            ))
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
    fn test_load_persisted_stats_restores_counters() {
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
}
