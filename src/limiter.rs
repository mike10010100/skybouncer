//! Tier-4 evaluation rate limiter protecting against Denial-of-Wallet attacks.
//!
//! Enforces a configurable sliding-window ceiling on model evaluations per protected user,
//! preventing malicious actors from triggering expensive external classifier calls via mention floods.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Default evaluation rate limit ceiling (100 evaluations per hour per protected user).
pub const DEFAULT_MAX_EVALUATIONS_PER_WINDOW: usize = 100;

/// Default sliding window duration (1 hour).
pub const DEFAULT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);

/// Number of independent internal mutex shards to minimize lock contention.
const NUM_SHARDS: usize = 16;

/// Configuration parameters for [`EvaluationRateLimiter`].
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum model evaluations permitted within a rolling window.
    pub max_evaluations: usize,
    /// Duration of the rolling rate limit window.
    pub window_duration: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_evaluations: DEFAULT_MAX_EVALUATIONS_PER_WINDOW,
            window_duration: DEFAULT_RATE_LIMIT_WINDOW,
        }
    }
}

impl RateLimiterConfig {
    /// Constructs configuration loaded from environment variables with fallback defaults.
    ///
    /// # Environment Variables
    /// - `SKYBOUNCER_RATE_LIMIT_EVALS_PER_HOUR`: Max evaluations per hour (defaults to 100).
    #[must_use]
    pub fn from_env() -> Self {
        let max_evaluations = std::env::var("SKYBOUNCER_RATE_LIMIT_EVALS_PER_HOUR")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_EVALUATIONS_PER_WINDOW);

        Self {
            max_evaluations,
            window_duration: DEFAULT_RATE_LIMIT_WINDOW,
        }
    }

    /// Constructs an unlimited configuration for testing or high-volume environments.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_evaluations: usize::MAX,
            window_duration: DEFAULT_RATE_LIMIT_WINDOW,
        }
    }
}

/// Sharded sliding-window rate limiter evaluating per-target model evaluation allowances.
#[derive(Debug)]
pub struct EvaluationRateLimiter {
    config: RateLimiterConfig,
    shards: Vec<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl Default for EvaluationRateLimiter {
    fn default() -> Self {
        Self::new(RateLimiterConfig::default())
    }
}

impl EvaluationRateLimiter {
    /// Creates a new [`EvaluationRateLimiter`] with the given configuration.
    #[must_use]
    pub fn new(config: RateLimiterConfig) -> Self {
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self { config, shards }
    }

    /// Selects the internal shard index for a target DID.
    fn shard_idx(&self, target_did: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        target_did.hash(&mut hasher);
        (hasher.finish() as usize) % NUM_SHARDS
    }

    /// Checks whether an evaluation is permitted for `target_did` and records it if allowed.
    ///
    /// Evaluates timestamps using clock-warp safe `saturating_duration_since`.
    ///
    /// Returns `true` if permitted and recorded, or `false` if the rate limit ceiling is reached.
    #[must_use]
    pub fn check_and_record(&self, target_did: &str) -> bool {
        if self.config.max_evaluations == 0 || self.config.max_evaluations == usize::MAX {
            return true;
        }

        let now = Instant::now();
        let idx = self.shard_idx(target_did);
        let mut shard = self.shards[idx].lock();

        let timestamps = shard.entry(target_did.to_string()).or_default();

        // Prune entries outside the sliding window using clock-warp safe duration
        let window = self.config.window_duration;
        timestamps.retain(|&ts| now.saturating_duration_since(ts) < window);

        if timestamps.len() < self.config.max_evaluations {
            timestamps.push(now);
            true
        } else {
            false
        }
    }

    /// Returns the number of remaining evaluations for `target_did` in the current window.
    #[must_use]
    pub fn remaining(&self, target_did: &str) -> usize {
        let now = Instant::now();
        let idx = self.shard_idx(target_did);
        let mut shard = self.shards[idx].lock();

        if let Some(timestamps) = shard.get_mut(target_did) {
            let window = self.config.window_duration;
            timestamps.retain(|&ts| now.saturating_duration_since(ts) < window);
            let rem = self.config.max_evaluations.saturating_sub(timestamps.len());
            if timestamps.is_empty() {
                shard.remove(target_did);
            }
            rem
        } else {
            self.config.max_evaluations
        }
    }

    /// Prunes stale entries across all shards whose recorded timestamps have all expired.
    pub fn prune_stale(&self) {
        let now = Instant::now();
        let window = self.config.window_duration;
        for shard in &self.shards {
            let mut map = shard.lock();
            map.retain(|_, timestamps| {
                timestamps.retain(|&ts| now.saturating_duration_since(ts) < window);
                !timestamps.is_empty()
            });
        }
    }

    /// Clears recorded evaluations for a given target DID.
    pub fn reset(&self, target_did: &str) {
        let idx = self.shard_idx(target_did);
        let mut shard = self.shards[idx].lock();
        shard.remove(target_did);
    }

    /// Clears all recorded evaluations across all shards.
    pub fn clear_all(&self) {
        for shard in &self.shards {
            shard.lock().clear();
        }
    }

    /// Returns a reference to the active configuration.
    #[must_use]
    pub fn config(&self) -> &RateLimiterConfig {
        &self.config
    }
}
