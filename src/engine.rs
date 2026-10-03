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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use skybase::ingest::{CommitOperation, JetstreamCommit};
use skybase::repo::PdsRepoClient;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};

use crate::classifier::{
    Classifier, HeuristicClassifier, JevClassifier, JevConfig, RuleRubric, Verdict,
    ViolationCategory,
};
use crate::enricher::{ContextEnricher, NoopContextEnricher};
use crate::error::SkybouncerError;
use crate::limiter::{EvaluationRateLimiter, RateLimiterConfig};
use crate::matcher::{
    BypassReason, FollowGraph, FollowSyncEvent, GateDecision, Interaction, NonFollowedGate,
    TargetMatcher,
};
use crate::modlist::{BouncedUser, DeduplicationCache, ModListManager, DEFAULT_MOD_LIST_NAME};

/// Default capacity for the engine's internal commit event processing channel.
pub const DEFAULT_ENGINE_CHANNEL_CAPACITY: usize = 1024;

/// Default evaluation verdict cache TTL (24 hours).
pub const DEFAULT_EVALUATION_CACHE_TTL: Duration = Duration::from_secs(86400);

/// Default periodic cache maintenance interval (1 hour).
pub const DEFAULT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(3600);

/// Default graceful shutdown timeout (5 seconds).
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Jev classification client configuration, if Jev is used as the primary model.
    pub jev_config: Option<JevConfig>,
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
            jev_config: None,
            list_name: DEFAULT_MOD_LIST_NAME.to_string(),
            list_description: None,
            rate_limiter_config: RateLimiterConfig::default(),
            stateless_mode: false,
            enable_heuristic_prefilter: false,
            dry_run: false,
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
        self
    }

    /// Sets the Jev classification configuration.
    #[must_use]
    pub fn with_jev_config(mut self, config: JevConfig) -> Self {
        self.jev_config = Some(config);
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

        Ok(Self {
            protected_dids,
            rubric,
            pds_endpoint,
            pds_access_token,
            cache_path,
            evaluation_ttl: DEFAULT_EVALUATION_CACHE_TTL,
            channel_capacity: DEFAULT_ENGINE_CHANNEL_CAPACITY,
            jev_config,
            list_name: DEFAULT_MOD_LIST_NAME.to_string(),
            list_description: None,
            rate_limiter_config,
            stateless_mode,
            enable_heuristic_prefilter,
            dry_run,
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
}

impl EngineStats {
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
            candidates_evaluated: self.candidates_evaluated.load(Ordering::Relaxed),
            dedup_cache_hits: self.dedup_cache_hits.load(Ordering::Relaxed),
            eval_cache_hits: self.eval_cache_hits.load(Ordering::Relaxed),
            heuristic_violations: self.heuristic_violations.load(Ordering::Relaxed),
            model_evaluations: self.model_evaluations.load(Ordering::Relaxed),
            rate_limited_evaluations: self.rate_limited_evaluations.load(Ordering::Relaxed),
            context_enrichments: self.context_enrichments.load(Ordering::Relaxed),
            violations_detected: self.violations_detected.load(Ordering::Relaxed),
            bounces_executed: self.bounces_executed.load(Ordering::Relaxed),
            bounced: self.bounced.load(Ordering::Relaxed),
            permitted: self.permitted.load(Ordering::Relaxed),
            bounces_skipped_rubric: self.bounces_skipped_rubric.load(Ordering::Relaxed),
            errors_encountered: self.errors_encountered.load(Ordering::Relaxed),
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
}

/// Outcome of evaluating an interaction candidate through the moderation pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum InteractionOutcome {
    /// Dropped at the gate (self-interaction or followed author) with zero network/model cost.
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
}

impl InteractionOutcome {
    /// Returns the author DID associated with this outcome.
    #[must_use]
    pub fn author_did(&self) -> &str {
        match self {
            Self::Bypassed { author_did, .. }
            | Self::AlreadyBounced { author_did }
            | Self::Permitted { author_did, .. }
            | Self::Bounced { author_did, .. }
            | Self::BelowThreshold { author_did, .. }
            | Self::RateLimited { author_did, .. } => author_did.as_str(),
        }
    }

    /// Returns the protected target DID associated with this outcome, if applicable.
    #[must_use]
    pub fn target_did(&self) -> Option<&str> {
        match self {
            Self::Bypassed { target_did, .. }
            | Self::Permitted { target_did, .. }
            | Self::Bounced { target_did, .. }
            | Self::BelowThreshold { target_did, .. }
            | Self::RateLimited { target_did, .. } => Some(target_did.as_str()),
            Self::AlreadyBounced { .. } => None,
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
}

/// Backward compatibility alias for [`InteractionOutcome`].
pub type ProcessOutcome = InteractionOutcome;

/// Outcome of processing a single [`JetstreamCommit`] through [`SkybouncerEngine`].
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessCommitResult {
    /// Commit updated the follow graph for a protected user.
    FollowSynced(FollowSyncEvent),
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
    pds_client: Arc<PdsRepoClient>,
    rate_limiter: Arc<EvaluationRateLimiter>,
    enricher: Arc<dyn ContextEnricher>,
    stats: Arc<EngineStats>,
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
        let protected_dids = Arc::new(RwLock::new(config.protected_dids.clone()));
        let rubric = Arc::new(RwLock::new(config.rubric.clone()));
        let rate_limiter = Arc::new(EvaluationRateLimiter::new(
            config.rate_limiter_config.clone(),
        ));
        let enricher: Arc<dyn ContextEnricher> = Arc::new(NoopContextEnricher);
        let stats = Arc::new(EngineStats::default());

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
            pds_client,
            rate_limiter,
            enricher,
            stats,
        }
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
            let p_dids = {
                let guard = self.protected_dids.read();
                guard.clone()
            };

            let sync_event = self.follow_graph.handle_commit(commit, &p_dids);
            if sync_event != FollowSyncEvent::Ignored {
                self.stats
                    .follow_sync_events
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.follows_synced.fetch_add(1, Ordering::Relaxed);
                debug!(event = ?sync_event, "Synchronized follow graph from firehose commit");
            }
            return Ok(ProcessCommitResult::FollowSynced(sync_event));
        }

        // Tier 1: Post Collection & Operation Filter
        if commit.collection.as_str() != "app.bsky.feed.post"
            || commit.operation != CommitOperation::Create
        {
            return Ok(ProcessCommitResult::Ignored);
        }

        // Tier 2: Target Matcher Extraction
        let p_dids = {
            let guard = self.protected_dids.read();
            guard.clone()
        };

        let interactions = TargetMatcher::match_all_interactions(commit, &p_dids);
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

    /// Evaluates an extracted interaction through the non-followed gate, caches, classifiers, and modlist mutator.
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
            }
            debug!(reason = ?reason, "Bypassed interaction at gate with zero cost");
            return Ok(InteractionOutcome::Bypassed {
                reason,
                author_did,
                target_did,
            });
        }

        // Tier 4: Deduplication Cache Check (<50µs, $0 cost)
        self.stats
            .candidates_evaluated
            .fetch_add(1, Ordering::Relaxed);
        if self.cache.is_bounced(&author_did)? {
            self.stats.dedup_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!("Author already bounced in deduplication cache; skipping evaluation");
            return Ok(InteractionOutcome::AlreadyBounced { author_did });
        }

        // Tier 5: Evaluation TTL Cache Check (<50µs, $0 cost)
        let cached_verdict = self.cache.get_evaluation(&post_uri)?;
        let verdict = if let Some(verdict) = cached_verdict {
            self.stats.eval_cache_hits.fetch_add(1, Ordering::Relaxed);
            debug!("Evaluation cache hit for post; reusing verdict");
            verdict
        } else {
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
                heuristic_verdict
            } else {
                // Tier 4: Per-User Evaluation Rate Limiter (Anti-Denial-of-Wallet, PRD §5.2)
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
                let model_verdict =
                    self.classifier
                        .classify(&interaction)
                        .await
                        .inspect_err(|_e| {
                            self.stats
                                .errors_encountered
                                .fetch_add(1, Ordering::Relaxed);
                        })?;

                if model_verdict.is_violation() {
                    self.stats
                        .violations_detected
                        .fetch_add(1, Ordering::Relaxed);
                }
                model_verdict
            }
        };

        // Cache the verdict with configured TTL
        let _ =
            self.cache
                .set_evaluation(&post_uri, &author_did, &verdict, self.config.evaluation_ttl);

        // Tier 8: Rubric Sensitivity Gate & Sovereign PDS Bounce
        match verdict {
            Verdict::Permitted { reason } => {
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
                let rubric = self.rubric();
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
                let bounce_result = self
                    .modlist_manager
                    .bounce_user(
                        &self.pds_client,
                        &target_did,
                        &author_did,
                        &category,
                        confidence,
                        &reason,
                        &post_uri,
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
                        Ok(InteractionOutcome::AlreadyBounced { author_did })
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

    /// Pardons an account by deleting its listitems from the PDS and purging the cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS deletion or cache mutation fails.
    pub async fn pardon_user(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        self.modlist_manager
            .pardon_user(&self.pds_client, protected_did, subject_did)
            .await
    }

    /// Ensures that the parent moderation list exists on the sovereign PDS.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if list provisioning fails.
    pub async fn ensure_mod_list(&self, protected_did: &str) -> Result<String, SkybouncerError> {
        self.modlist_manager
            .ensure_mod_list(&self.pds_client, protected_did)
            .await
    }

    /// Returns `true` if this engine operates in shadow dry-run mode.
    #[must_use]
    pub fn is_dry_run(&self) -> bool {
        self.config.dry_run
    }

    /// Returns a reference to the active configuration.
    #[must_use]
    pub fn config(&self) -> &SkybouncerConfig {
        &self.config
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
        let pds_rubric =
            crate::modlist::fetch_sovereign_config(&self.pds_client, protected_did).await?;
        if let Some(ref rubric) = pds_rubric {
            self.set_rubric(rubric.clone());
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
        let rubric = self.rubric();
        crate::modlist::publish_sovereign_config(&self.pds_client, protected_did, &rubric).await
    }

    /// Runs the pipeline event processing loop reading from `rx` until cancelled.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if unrecoverable pipeline failure occurs.
    pub async fn run(
        &self,
        mut rx: mpsc::Receiver<JetstreamCommit>,
        cancel: CancellationToken,
    ) -> Result<EngineStatsSnapshot, SkybouncerError> {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    debug!("Engine processing loop received cancellation; draining buffered commits");
                    while let Ok(commit) = rx.try_recv() {
                        let _ = self.process_commit(&commit).await;
                    }
                    break;
                }
                commit_opt = rx.recv() => {
                    match commit_opt {
                        Some(commit) => {
                            let _ = self.process_commit(&commit).await;
                        }
                        None => {
                            debug!("Commit channel closed; shutting down engine loop");
                            break;
                        }
                    }
                }
            }
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
    modlist_manager: Option<Arc<ModListManager>>,
    cache: Option<Arc<DeduplicationCache>>,
    pds_client: Option<Arc<PdsRepoClient>>,
    rate_limiter: Option<Arc<EvaluationRateLimiter>>,
    enricher: Option<Arc<dyn ContextEnricher>>,
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
            modlist_manager: None,
            cache: None,
            pds_client: None,
            rate_limiter: None,
            enricher: None,
        }
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

        // 3. Initialize HeuristicClassifier
        let heuristic_classifier = self.heuristic_classifier.unwrap_or_else(|| {
            if self.config.enable_heuristic_prefilter {
                HeuristicClassifier::default()
            } else {
                HeuristicClassifier::empty()
            }
        });

        // 4. Initialize Primary Classifier
        let classifier: Arc<dyn Classifier> = match self.classifier {
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
                } else {
                    let endpoint = self.config.pds_endpoint.as_ref().ok_or_else(|| {
                        SkybouncerError::Config(
                            "PDS endpoint is required to build SkybouncerEngine".to_string(),
                        )
                    })?;
                    let token = self.config.pds_access_token.as_ref().ok_or_else(|| {
                        SkybouncerError::Config(
                            "PDS access token is required to build SkybouncerEngine".to_string(),
                        )
                    })?;
                    let primary_did =
                        self.config.protected_dids.iter().next().ok_or_else(|| {
                            SkybouncerError::Config(
                                "At least one protected DID is required to initialize PDS client"
                                    .to_string(),
                            )
                        })?;
                    Arc::new(
                        PdsRepoClient::from_credentials(endpoint, primary_did, token).map_err(
                            |e| SkybouncerError::Config(format!("Failed to build PDS client: {e}")),
                        )?,
                    )
                }
            }
        };

        let rate_limiter = self.rate_limiter.unwrap_or_else(|| {
            Arc::new(EvaluationRateLimiter::new(
                self.config.rate_limiter_config.clone(),
            ))
        });
        let enricher = self
            .enricher
            .unwrap_or_else(|| Arc::new(NoopContextEnricher));

        let protected_dids = Arc::new(RwLock::new(self.config.protected_dids.clone()));
        let rubric = Arc::new(RwLock::new(self.config.rubric.clone()));
        let stats = Arc::new(EngineStats::default());

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
            pds_client,
            rate_limiter,
            enricher,
            stats,
        })
    }
}
