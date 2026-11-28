//! In-memory sharded rolling-window surge tracker, Storm Mode state, and digest buffer.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use crate::dogpile::math::{
    canonical_focal_post_uri, compute_burst_acceleration, compute_structural_score,
};
use crate::dogpile::types::{
    DigestBounceSummary, DogpileConfig, SampleReply, StormDigestNotification, StormMetrics,
    StormSeverity, SurgeCandidate,
};
use crate::matcher::{Interaction, InteractionType};

const MAX_RECENT_QUOTES: usize = 25;
const MAX_DIGEST_SAMPLES: usize = 5;
const MAX_EVAL_OUTCOMES: usize = 512;
const MAX_POSTGATE_STATES: usize = 4096;
const MAX_ALERT_COOLDOWNS: usize = 4096;
const MAX_BUCKET_EVENTS: usize = 2048;
const MAX_DEFENSIVE_EVENTS: usize = 1024;
const POSTGATE_STATE_TTL_US: u64 = 24 * 3600 * 1_000_000;

#[derive(Debug, Clone)]
struct TrackedEvent {
    post_uri: String,
    timestamp_us: u64,
    author_did: String,
    is_oon: bool,
    interaction_type: InteractionType,
    is_quote_of_focal: bool,
}

#[derive(Debug, Default)]
struct DefensiveWindow {
    recent_blocks: VecDeque<u64>,
    recent_detaches: VecDeque<u64>,
}

impl DefensiveWindow {
    fn prune(&mut self, cutoff_us: u64) {
        while self.recent_blocks.front().is_some_and(|&ts| ts < cutoff_us) {
            self.recent_blocks.pop_front();
        }
        while self
            .recent_detaches
            .front()
            .is_some_and(|&ts| ts < cutoff_us)
        {
            self.recent_detaches.pop_front();
        }
    }

    fn push_block(&mut self, now_us: u64, cutoff_us: u64) {
        self.prune(cutoff_us);
        if self.recent_blocks.len() >= MAX_DEFENSIVE_EVENTS {
            self.recent_blocks.pop_front();
        }
        self.recent_blocks.push_back(now_us);
    }

    fn push_detaches(&mut self, now_us: u64, cutoff_us: u64, delta: usize) {
        self.prune(cutoff_us);
        for _ in 0..delta {
            if self.recent_detaches.len() >= MAX_DEFENSIVE_EVENTS {
                self.recent_detaches.pop_front();
            }
            self.recent_detaches.push_back(now_us);
        }
    }

    fn counts(&mut self, cutoff_us: u64) -> (usize, usize) {
        self.prune(cutoff_us);
        (self.recent_blocks.len(), self.recent_detaches.len())
    }

    fn is_empty(&self) -> bool {
        self.recent_blocks.is_empty() && self.recent_detaches.is_empty()
    }
}

#[derive(Debug, Default)]
struct FocalPostBucket {
    events: VecDeque<TrackedEvent>,
    seen_post_uris: HashSet<String>,
    short_cursor: usize,
    short_count: usize,
    short_author_counts: HashMap<String, usize>,
    short_oon_author_counts: HashMap<String, usize>,
    reply_count_short: usize,
    quote_count_short: usize,
    mention_count_short: usize,
    oon_samples: VecDeque<(u64, SampleReply)>,
    oon_sample_seen_count: usize,
    recent_quote_uris: VecDeque<String>,
    eval_outcomes: VecDeque<(u64, bool)>,
    eval_violation_count: usize,
    last_eval_us: Option<u64>,
    last_activity_us: u64,
    active_storm_id: Option<i64>,
    active_severity: Option<StormSeverity>,
    last_alert_us: Option<u64>,
    storm_expires_us: Option<u64>,
    dismissed_until_us: Option<u64>,
    digest_window_start_us: Option<u64>,
    digest_bounced_count: u64,
    digest_sample_violators: Vec<DigestBounceSummary>,
}

impl FocalPostBucket {
    fn increment_short_metrics(&mut self, ev: &TrackedEvent) {
        self.short_count = self.short_count.saturating_add(1);
        *self
            .short_author_counts
            .entry(ev.author_did.clone())
            .or_insert(0) += 1;
        if ev.is_oon {
            *self
                .short_oon_author_counts
                .entry(ev.author_did.clone())
                .or_insert(0) += 1;
        }
        match ev.interaction_type {
            InteractionType::DirectReply | InteractionType::ThreadReply => {
                self.reply_count_short = self.reply_count_short.saturating_add(1);
            }
            InteractionType::Quote => {
                self.quote_count_short = self.quote_count_short.saturating_add(1);
            }
            InteractionType::Mention => {
                self.mention_count_short = self.mention_count_short.saturating_add(1);
            }
        }
        if ev.is_quote_of_focal && ev.interaction_type != InteractionType::Quote {
            self.quote_count_short = self.quote_count_short.saturating_add(1);
        }
    }

    fn decrement_short_metrics(&mut self, ev: &TrackedEvent) {
        self.short_count = self.short_count.saturating_sub(1);
        if let Some(cnt) = self.short_author_counts.get_mut(&ev.author_did) {
            if *cnt <= 1 {
                self.short_author_counts.remove(&ev.author_did);
            } else {
                *cnt -= 1;
            }
        }
        if ev.is_oon {
            if let Some(cnt) = self.short_oon_author_counts.get_mut(&ev.author_did) {
                if *cnt <= 1 {
                    self.short_oon_author_counts.remove(&ev.author_did);
                } else {
                    *cnt -= 1;
                }
            }
        }
        match ev.interaction_type {
            InteractionType::DirectReply | InteractionType::ThreadReply => {
                self.reply_count_short = self.reply_count_short.saturating_sub(1);
            }
            InteractionType::Quote => {
                self.quote_count_short = self.quote_count_short.saturating_sub(1);
            }
            InteractionType::Mention => {
                self.mention_count_short = self.mention_count_short.saturating_sub(1);
            }
        }
        if ev.is_quote_of_focal && ev.interaction_type != InteractionType::Quote {
            self.quote_count_short = self.quote_count_short.saturating_sub(1);
        }
    }

    fn evict_front_event(&mut self) {
        let Some(ev) = self.events.pop_front() else {
            return;
        };
        self.seen_post_uris.remove(&ev.post_uri);
        if self.short_cursor > 0 {
            self.short_cursor -= 1;
        } else {
            self.decrement_short_metrics(&ev);
        }
    }

    fn advance_short_cursor(&mut self, short_cutoff_us: u64) {
        while self.short_cursor < self.events.len()
            && self.events[self.short_cursor].timestamp_us < short_cutoff_us
        {
            let ev = self.events[self.short_cursor].clone();
            self.decrement_short_metrics(&ev);
            self.short_cursor += 1;
        }
    }

    fn rebuild_short_metrics(&mut self, short_cutoff_us: u64) {
        self.short_count = 0;
        self.short_author_counts.clear();
        self.short_oon_author_counts.clear();
        self.reply_count_short = 0;
        self.quote_count_short = 0;
        self.mention_count_short = 0;
        let idx = self
            .events
            .iter()
            .position(|ev| ev.timestamp_us >= short_cutoff_us)
            .unwrap_or(self.events.len());
        self.short_cursor = idx;
        for i in idx..self.events.len() {
            let ev = self.events[i].clone();
            self.increment_short_metrics(&ev);
        }
    }

    fn push_event(&mut self, ev: TrackedEvent, short_cutoff_us: u64) {
        while self.events.len() >= MAX_BUCKET_EVENTS {
            self.evict_front_event();
        }
        let is_monotonic = self
            .events
            .back()
            .is_none_or(|back| ev.timestamp_us >= back.timestamp_us);
        if is_monotonic {
            self.events.push_back(ev);
            let idx = self.events.len() - 1;
            if self.events[idx].timestamp_us >= short_cutoff_us {
                let inserted = self.events[idx].clone();
                self.increment_short_metrics(&inserted);
            } else {
                self.short_cursor = self.events.len();
            }
        } else {
            let insert_pos = self
                .events
                .iter()
                .position(|existing| existing.timestamp_us > ev.timestamp_us)
                .unwrap_or(self.events.len());
            self.events.insert(insert_pos, ev);
            self.rebuild_short_metrics(short_cutoff_us);
        }
    }

    fn prune(&mut self, medium_cutoff_us: u64, short_cutoff_us: Option<u64>) {
        while self
            .events
            .front()
            .is_some_and(|ev| ev.timestamp_us < medium_cutoff_us)
        {
            self.evict_front_event();
        }
        if let Some(sc) = short_cutoff_us {
            self.advance_short_cursor(sc);
        }
        if self.events.is_empty()
            || self.seen_post_uris.len() > self.events.len().saturating_mul(2).max(64)
        {
            self.seen_post_uris.clear();
            for ev in &self.events {
                self.seen_post_uris.insert(ev.post_uri.clone());
            }
        }
        let prev_evals = self.eval_outcomes.len();
        self.eval_outcomes.retain(|&(ts, _)| ts >= medium_cutoff_us);
        if self.eval_outcomes.len() != prev_evals {
            self.eval_violation_count = self.eval_outcomes.iter().filter(|&&(_, v)| v).count();
        }
        self.oon_samples.retain(|(ts, _)| *ts >= medium_cutoff_us);
        if self.oon_samples.is_empty() {
            self.oon_sample_seen_count = 0;
        }
    }

    fn has_active_storm(&self, now_us: u64) -> bool {
        self.active_storm_id.is_some() && self.storm_expires_us.is_some_and(|exp| exp > now_us)
    }

    fn active_storm_expires_us(&self, now_us: u64) -> Option<u64> {
        if self.active_storm_id.is_some() {
            self.storm_expires_us.filter(|&exp| exp > now_us)
        } else {
            None
        }
    }

    fn is_suppressed(&self, now_us: u64) -> bool {
        self.dismissed_until_us.is_some_and(|until| until > now_us)
    }

    fn clear_storm(&mut self) {
        self.active_storm_id = None;
        self.active_severity = None;
        self.storm_expires_us = None;
    }

    fn clear_buffers(&mut self) {
        self.events.clear();
        self.seen_post_uris.clear();
        self.short_cursor = 0;
        self.short_count = 0;
        self.short_author_counts.clear();
        self.short_oon_author_counts.clear();
        self.reply_count_short = 0;
        self.quote_count_short = 0;
        self.mention_count_short = 0;
        self.oon_samples.clear();
        self.oon_sample_seen_count = 0;
        self.recent_quote_uris.clear();
        self.eval_outcomes.clear();
        self.eval_violation_count = 0;
        self.last_eval_us = None;
    }
}

#[derive(Debug, Default)]
struct TargetDogpileState {
    buckets: HashMap<String, FocalPostBucket>,
    defensive: DefensiveWindow,
    postgate_state: HashMap<String, (usize, bool, u64)>,
    alert_cooldowns: HashMap<String, u64>,
    manual_storm_mode_until_us: Option<u64>,
}

impl TargetDogpileState {
    fn max_active_until_us(&self, now_us: u64) -> Option<u64> {
        let mut max_until = self.manual_storm_mode_until_us.filter(|&u| u > now_us);
        for bucket in self.buckets.values() {
            if let Some(exp) = bucket.active_storm_expires_us(now_us) {
                max_until = Some(max_until.map_or(exp, |m| m.max(exp)));
            }
        }
        max_until
    }

    fn is_empty(&self) -> bool {
        self.buckets.is_empty()
            && self.defensive.is_empty()
            && self.postgate_state.is_empty()
            && self.alert_cooldowns.is_empty()
            && self.manual_storm_mode_until_us.is_none()
    }

    fn evict_oldest_bucket(&mut self, medium_cutoff: u64, now_us: u64, max_tracked_posts: usize) {
        for bucket in self.buckets.values_mut() {
            bucket.prune(medium_cutoff, None);
        }
        self.buckets.retain(|_, b| {
            !b.events.is_empty()
                || !b.eval_outcomes.is_empty()
                || b.active_storm_id.is_some()
                || b.digest_bounced_count > 0
                || b.is_suppressed(now_us)
        });
        if self.buckets.len() < max_tracked_posts || self.buckets.is_empty() {
            return;
        }
        let victim = self
            .buckets
            .iter()
            .filter(|(_, b)| !b.has_active_storm(now_us) && !b.is_suppressed(now_us))
            .min_by_key(|(_, b)| b.last_activity_us)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                self.buckets
                    .iter()
                    .min_by_key(|(_, b)| b.last_activity_us)
                    .map(|(k, _)| k.clone())
            });
        if let Some(key) = victim {
            self.buckets.remove(&key);
        }
    }

    fn drain_due_digests(
        &mut self,
        target_did: &str,
        now_us: u64,
        interval_us: u64,
        force_flush_expired: bool,
    ) -> Vec<StormDigestNotification> {
        let manual_active = self
            .manual_storm_mode_until_us
            .is_some_and(|until| until > now_us);
        let mut out = Vec::new();
        for (focal_uri, bucket) in &mut self.buckets {
            if bucket.digest_bounced_count == 0 {
                continue;
            }
            let storm_still_active = bucket.has_active_storm(now_us) || manual_active;
            let start_us = bucket.digest_window_start_us.unwrap_or(now_us);
            let elapsed_us = now_us.saturating_sub(start_us);
            let due = elapsed_us >= interval_us || (force_flush_expired && !storm_still_active);
            if due {
                let bounced_count = bucket.digest_bounced_count;
                let sample_violators = std::mem::take(&mut bucket.digest_sample_violators);
                bucket.digest_bounced_count = 0;
                bucket.digest_window_start_us = if storm_still_active {
                    Some(now_us)
                } else {
                    None
                };
                out.push(StormDigestNotification {
                    target_did: target_did.to_string(),
                    focal_post_uri: focal_uri.clone(),
                    bounced_count,
                    sample_violators,
                    window_secs: (elapsed_us / 1_000_000).max(1),
                    storm_still_active,
                });
            }
        }
        out
    }
}

/// Thread-safe, per-target sharded sliding-window dogpile detector and Storm Mode coordinator.
///
/// Tracks per-`(target_did, focal_post_uri)` interaction velocity with O(1) incremental
/// short-window author refcounts, target defensive distress signals (`app.bsky.graph.block` /
/// `app.bsky.feed.postgate`), alert cooldowns, Storm Mode bounce digests, and an O(1)
/// lock-ordered `active_storms` lookup index.
#[derive(Clone, Debug)]
pub struct DogpileTracker {
    config: DogpileConfig,
    targets: Arc<RwLock<HashMap<String, Arc<Mutex<TargetDogpileState>>>>>,
    active_storms: Arc<RwLock<HashMap<String, u64>>>,
}

impl DogpileTracker {
    /// Creates a new [`DogpileTracker`] with the provided configuration.
    #[must_use]
    pub fn new(config: DogpileConfig) -> Self {
        Self {
            config,
            targets: Arc::new(RwLock::new(HashMap::new())),
            active_storms: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns a reference to the active [`DogpileConfig`].
    #[must_use]
    pub fn config(&self) -> &DogpileConfig {
        &self.config
    }

    fn get_target_shard(&self, target_did: &str) -> Option<Arc<Mutex<TargetDogpileState>>> {
        self.targets.read().get(target_did).map(Arc::clone)
    }

    fn get_or_create_target_shard(&self, target_did: &str) -> Arc<Mutex<TargetDogpileState>> {
        if let Some(existing) = self.get_target_shard(target_did) {
            return existing;
        }
        let mut guard = self.targets.write();
        Arc::clone(
            guard
                .entry(target_did.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(TargetDogpileState::default()))),
        )
    }

    fn sync_active_storm(&self, target_did: &str, state: &TargetDogpileState, now_us: u64) {
        let max_until = state.max_active_until_us(now_us);
        let mut active = self.active_storms.write();
        if let Some(until) = max_until {
            active.insert(target_did.to_string(), until);
        } else {
            active.remove(target_did);
        }
    }

    /// Records a matched interaction for Stage 1 streaming velocity tracking.
    ///
    /// Returns `Some(SurgeCandidate)` when the focal post crosses either the
    /// out-of-network surge threshold or a defensive-distress-boosted burst threshold,
    /// subject to `eval_recheck_interval`.
    #[must_use]
    pub fn record_interaction(
        &self,
        interaction: &Interaction,
        is_out_of_network: bool,
        now_us: u64,
    ) -> Option<SurgeCandidate> {
        if !self.config.enabled || interaction.is_self_interaction() {
            return None;
        }

        let focal_uri = canonical_focal_post_uri(interaction);
        let target_did = interaction.target_did.clone();
        let short_us = dur_to_us(self.config.short_window);
        let medium_us = dur_to_us(self.config.medium_window);
        let recheck_us = dur_to_us(self.config.eval_recheck_interval);
        let short_cutoff = now_us.saturating_sub(short_us);
        let medium_cutoff = now_us.saturating_sub(medium_us);

        let shard = self.get_or_create_target_shard(&target_did);
        let mut guard = shard.lock();

        // Read target defensive signals (blocks/detaches in short_window) before bucket insertion
        let (defensive_blocks, defensive_detaches) = guard.defensive.counts(short_cutoff);

        if !guard.buckets.contains_key(&focal_uri)
            && guard.buckets.len() >= self.config.max_tracked_posts
        {
            guard.evict_oldest_bucket(medium_cutoff, now_us, self.config.max_tracked_posts);
        }

        let bucket = guard.buckets.entry(focal_uri.clone()).or_default();
        bucket.prune(medium_cutoff, Some(short_cutoff));
        if bucket.is_suppressed(now_us) {
            return None;
        }
        bucket.dismissed_until_us = None;
        bucket.last_activity_us = bucket.last_activity_us.max(now_us);

        let is_quote_of_focal = interaction.interaction_type == InteractionType::Quote
            || interaction.quote_uri.as_deref() == Some(focal_uri.as_str());

        // Deduplicate identical post URIs (e.g., if matched via both reply + mention)
        if bucket.seen_post_uris.insert(interaction.post_uri.clone()) {
            bucket.push_event(
                TrackedEvent {
                    post_uri: interaction.post_uri.clone(),
                    timestamp_us: now_us,
                    author_did: interaction.author_did.clone(),
                    is_oon: is_out_of_network,
                    interaction_type: interaction.interaction_type,
                    is_quote_of_focal,
                },
                short_cutoff,
            );
        }

        if is_quote_of_focal
            && !bucket
                .recent_quote_uris
                .iter()
                .any(|u| u == &interaction.post_uri)
        {
            if bucket.recent_quote_uris.len() >= MAX_RECENT_QUOTES {
                bucket.recent_quote_uris.pop_front();
            }
            bucket
                .recent_quote_uris
                .push_back(interaction.post_uri.clone());
        }

        if is_out_of_network && !interaction.text.trim().is_empty() {
            let already_sampled = bucket
                .oon_samples
                .iter()
                .any(|(_, s)| s.author_did == interaction.author_did);
            if !already_sampled {
                let sample = SampleReply {
                    author_did: interaction.author_did.clone(),
                    interaction_type: interaction.interaction_type,
                    post_uri: interaction.post_uri.clone(),
                    text_snippet: interaction.text.chars().take(280).collect(),
                };
                bucket.oon_sample_seen_count = bucket.oon_sample_seen_count.saturating_add(1);
                if bucket.oon_samples.len() < self.config.max_sample_replies {
                    bucket.oon_samples.push_back((now_us, sample));
                } else if bucket.oon_sample_seen_count > 0 {
                    use std::hash::{Hash, Hasher};
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    now_us.hash(&mut hasher);
                    bucket.oon_sample_seen_count.hash(&mut hasher);
                    interaction.post_uri.hash(&mut hasher);
                    let slot = (hasher.finish() as usize) % bucket.oon_sample_seen_count;
                    if slot < self.config.max_sample_replies {
                        bucket.oon_samples[slot] = (now_us, sample);
                    }
                }
            }
        }

        let short_count = bucket.short_count;
        let medium_count = bucket.events.len();
        let reply_count_short = bucket.reply_count_short;
        let quote_count_short = bucket.quote_count_short;
        let mention_count_short = bucket.mention_count_short;
        let unique_authors_short = bucket.short_author_counts.len();
        let unique_oon_authors_short = bucket.short_oon_author_counts.len();
        let out_of_network_ratio = if unique_authors_short > 0 {
            unique_oon_authors_short as f64 / unique_authors_short as f64
        } else {
            0.0
        };

        let defensive_distress = defensive_blocks >= self.config.defensive_block_burst
            || defensive_detaches >= self.config.defensive_detach_burst;
        let reduced_min = (self.config.min_unique_authors / 2).max(3);

        let volume_triggered = unique_oon_authors_short >= self.config.min_unique_authors
            && out_of_network_ratio >= self.config.min_out_of_network_ratio;
        let distress_triggered = defensive_distress && unique_oon_authors_short >= reduced_min;

        if !volume_triggered && !distress_triggered {
            return None;
        }

        if let Some(last_eval) = bucket.last_eval_us {
            if now_us.saturating_sub(last_eval) < recheck_us {
                return None;
            }
        }
        bucket.last_eval_us = Some(now_us);

        let eval_total = bucket.eval_outcomes.len();
        let violation_rate = if eval_total > 0 {
            bucket.eval_violation_count as f64 / eval_total as f64
        } else {
            0.0
        };

        let burst_z_score = compute_burst_acceleration(
            short_count,
            self.config.short_window.as_secs_f64(),
            medium_count,
            self.config.medium_window.as_secs_f64(),
        );

        let mut initial_metrics = StormMetrics {
            unique_authors_short,
            unique_oon_authors_short,
            reply_count_short,
            quote_count_short,
            mention_count_short,
            out_of_network_ratio,
            direct_ratio: 0.0,
            dunk_ratio: 0.0,
            power_asymmetry: 1.0,
            violation_rate,
            burst_z_score,
            defensive_blocks,
            defensive_detaches,
            structural_score: 0.0,
            composite_score: 0.0,
        };
        initial_metrics.structural_score = compute_structural_score(&initial_metrics, &self.config);
        initial_metrics.composite_score = initial_metrics.structural_score;

        Some(SurgeCandidate {
            target_did,
            focal_post_uri: focal_uri,
            observed_at_us: now_us,
            initial_metrics,
            sample_replies: bucket.oon_samples.iter().map(|(_, s)| s.clone()).collect(),
            recent_quote_uris: bucket.recent_quote_uris.iter().cloned().collect(),
        })
    }

    /// Rolls back `last_eval_us` if a [`SurgeCandidate`] could not be dispatched onto
    /// `storm_tx` (channel full), ensuring backpressure does not lock out Stage 2 for 60s.
    pub fn rollback_eval_recheck(&self, target_did: &str, focal_uri: &str, observed_at_us: u64) {
        let Some(shard) = self.get_target_shard(target_did) else {
            return;
        };
        let mut guard = shard.lock();
        if let Some(bucket) = guard.buckets.get_mut(focal_uri) {
            if bucket.last_eval_us == Some(observed_at_us) {
                bucket.last_eval_us = None;
            }
        }
    }

    /// Records the classifier evaluation outcome (`violated`) for a focal post so
    /// subsequent surges incorporate live violation rates.
    pub fn record_evaluation_outcome(
        &self,
        target_did: &str,
        focal_uri: &str,
        violated: bool,
        now_us: u64,
    ) {
        if !self.config.enabled {
            return;
        }
        let Some(shard) = self.get_target_shard(target_did) else {
            return;
        };
        let medium_cutoff = now_us.saturating_sub(dur_to_us(self.config.medium_window));
        let mut guard = shard.lock();
        if let Some(bucket) = guard.buckets.get_mut(focal_uri) {
            bucket.prune(medium_cutoff, None);
            bucket.eval_outcomes.push_back((now_us, violated));
            if violated {
                bucket.eval_violation_count = bucket.eval_violation_count.saturating_add(1);
            }
            while bucket.eval_outcomes.len() > MAX_EVAL_OUTCOMES {
                if let Some((_, was_violation)) = bucket.eval_outcomes.pop_front() {
                    if was_violation {
                        bucket.eval_violation_count = bucket.eval_violation_count.saturating_sub(1);
                    }
                }
            }
        }
    }

    /// Records a target user creating an `app.bsky.graph.block` record (distress signal).
    pub fn record_defensive_block(&self, target_did: &str, now_us: u64) {
        if !self.config.enabled {
            return;
        }
        let short_cutoff = now_us.saturating_sub(dur_to_us(self.config.short_window));
        let shard = self.get_or_create_target_shard(target_did);
        let mut guard = shard.lock();
        guard.defensive.push_block(now_us, short_cutoff);
    }

    /// Records a target user creating or updating an `app.bsky.feed.postgate` record.
    ///
    /// Computes the incremental delta of newly detached URIs or newly disabled embedding rules
    /// so repeated `postgate` edits on the same post do not double-count earlier detaches.
    pub fn record_defensive_postgate(
        &self,
        target_did: &str,
        post_uri: &str,
        detached_count: usize,
        disabled_quotes: bool,
        now_us: u64,
    ) {
        if !self.config.enabled {
            return;
        }
        let short_cutoff = now_us.saturating_sub(dur_to_us(self.config.short_window));
        let shard = self.get_or_create_target_shard(target_did);
        let mut guard = shard.lock();
        let (prev_count, prev_disabled, _) = guard
            .postgate_state
            .get(post_uri)
            .copied()
            .unwrap_or((0, false, now_us));
        let new_detaches = detached_count.saturating_sub(prev_count);
        let new_disable = usize::from(disabled_quotes && !prev_disabled);
        let delta = new_detaches.saturating_add(new_disable).min(50);

        guard.postgate_state.insert(
            post_uri.to_string(),
            (detached_count, disabled_quotes, now_us),
        );
        if guard.postgate_state.len() > MAX_POSTGATE_STATES {
            guard
                .postgate_state
                .retain(|_, (_, _, ts)| now_us.saturating_sub(*ts) <= POSTGATE_STATE_TTL_US);
            if guard.postgate_state.len() > MAX_POSTGATE_STATES {
                if let Some(oldest_key) = guard
                    .postgate_state
                    .iter()
                    .min_by_key(|(_, (_, _, ts))| *ts)
                    .map(|(k, _)| k.clone())
                {
                    guard.postgate_state.remove(&oldest_key);
                }
            }
        }

        guard.defensive.push_detaches(now_us, short_cutoff, delta);
    }

    /// Activates or updates an active storm bucket and returns `(should_emit_alert, is_escalation)`.
    ///
    /// Honors `alert_cooldown` for the same focal post unless the new `severity` strictly
    /// exceeds the previously alerted severity.
    pub fn activate_storm(
        &self,
        target_did: &str,
        focal_uri: &str,
        storm_id: i64,
        severity: StormSeverity,
        now_us: u64,
    ) -> (bool, bool) {
        let ttl_us = dur_to_us(self.config.storm_mode_ttl);
        let cooldown_us = dur_to_us(self.config.alert_cooldown);
        let medium_cutoff = now_us.saturating_sub(dur_to_us(self.config.medium_window));

        let shard = self.get_or_create_target_shard(target_did);
        let mut guard = shard.lock();
        if !guard.buckets.contains_key(focal_uri)
            && guard.buckets.len() >= self.config.max_tracked_posts
        {
            guard.evict_oldest_bucket(medium_cutoff, now_us, self.config.max_tracked_posts);
        }
        let persisted_last_alert = guard.alert_cooldowns.get(focal_uri).copied();
        let bucket = guard.buckets.entry(focal_uri.to_string()).or_default();
        bucket.last_activity_us = bucket.last_activity_us.max(now_us);

        let was_active = bucket.has_active_storm(now_us);
        let escalated = was_active && bucket.active_severity.is_some_and(|prev| severity > prev);

        let effective_last_alert = bucket.last_alert_us.or(persisted_last_alert);
        let should_emit = match effective_last_alert {
            None => true,
            Some(_) if escalated => true,
            Some(last) => now_us.saturating_sub(last) >= cooldown_us,
        };

        bucket.active_storm_id = Some(storm_id);
        bucket.active_severity = Some(match bucket.active_severity {
            Some(prev) if was_active && prev > severity => prev,
            _ => severity,
        });
        bucket.storm_expires_us = Some(now_us.saturating_add(ttl_us));
        bucket.dismissed_until_us = None;
        if bucket.digest_window_start_us.is_none() {
            bucket.digest_window_start_us = Some(now_us);
        }
        if should_emit {
            bucket.last_alert_us = Some(now_us);
            if guard.alert_cooldowns.len() >= MAX_ALERT_COOLDOWNS
                && !guard.alert_cooldowns.contains_key(focal_uri)
            {
                guard
                    .alert_cooldowns
                    .retain(|_, &mut ts| now_us.saturating_sub(ts) < cooldown_us);
                if guard.alert_cooldowns.len() >= MAX_ALERT_COOLDOWNS {
                    if let Some(oldest_key) = guard
                        .alert_cooldowns
                        .iter()
                        .min_by_key(|(_, &ts)| ts)
                        .map(|(k, _)| k.clone())
                    {
                        guard.alert_cooldowns.remove(&oldest_key);
                    }
                }
            }
            guard.alert_cooldowns.insert(focal_uri.to_string(), now_us);
        }

        self.sync_active_storm(target_did, &guard, now_us);
        (should_emit, escalated)
    }

    /// Rehydrates an unexpired active storm loaded from SQLite on engine startup.
    pub fn rehydrate_storm(
        &self,
        target_did: &str,
        focal_uri: &str,
        storm_id: i64,
        severity: StormSeverity,
        updated_at_us: u64,
        expires_at_us: u64,
    ) {
        let shard = self.get_or_create_target_shard(target_did);
        let mut guard = shard.lock();
        guard
            .alert_cooldowns
            .insert(focal_uri.to_string(), updated_at_us);
        let bucket = guard.buckets.entry(focal_uri.to_string()).or_default();
        bucket.active_storm_id = Some(storm_id);
        bucket.active_severity = Some(severity);
        bucket.storm_expires_us = Some(expires_at_us);
        bucket.last_activity_us = bucket.last_activity_us.max(updated_at_us);
        bucket.last_alert_us = Some(updated_at_us);
        if bucket.digest_window_start_us.is_none() {
            bucket.digest_window_start_us = Some(updated_at_us);
        }
        self.sync_active_storm(target_did, &guard, updated_at_us);
    }

    /// Returns `true` if Storm Mode is currently active for `target_did`
    /// (either via an active confirmed storm or manual Storm Mode toggle) in O(1) time.
    #[must_use]
    pub fn is_storm_mode_active(&self, target_did: &str, now_us: u64) -> bool {
        self.active_storms
            .read()
            .get(target_did)
            .is_some_and(|&until| until > now_us)
    }

    /// Manually enables or disables Storm Mode for `target_did`.
    ///
    /// When disabled (`enabled == false`), clears any active storm flags for `target_did`
    /// and returns the cleared `(focal_post_uri, storm_id)` pairs so SQLite can be resolved.
    pub fn set_manual_storm_mode(
        &self,
        target_did: &str,
        enabled: bool,
        now_us: u64,
    ) -> Vec<(String, i64)> {
        if enabled {
            let shard = self.get_or_create_target_shard(target_did);
            let mut guard = shard.lock();
            let until = now_us.saturating_add(dur_to_us(self.config.storm_mode_ttl));
            guard.manual_storm_mode_until_us = Some(until);
            self.sync_active_storm(target_did, &guard, now_us);
            Vec::new()
        } else {
            let Some(shard) = self.get_target_shard(target_did) else {
                self.active_storms.write().remove(target_did);
                return Vec::new();
            };
            let mut guard = shard.lock();
            guard.manual_storm_mode_until_us = None;
            let mut cleared = Vec::new();
            for (focal_uri, bucket) in &mut guard.buckets {
                if let Some(id) = bucket.active_storm_id {
                    cleared.push((focal_uri.clone(), id));
                }
                bucket.clear_storm();
            }
            self.sync_active_storm(target_did, &guard, now_us);
            cleared
        }
    }

    /// Dismisses active storm state matching `storm_id` for `target_did`, installs a
    /// `storm_mode_ttl` suppression window so the same focal post does not re-activate 60s
    /// later, clears sliding-window buffers, and drains any pending bounce digest immediately.
    pub fn dismiss_storm(
        &self,
        target_did: &str,
        focal_uri: &str,
        storm_id: i64,
        now_us: u64,
    ) -> Option<StormDigestNotification> {
        let ttl_us = dur_to_us(self.config.storm_mode_ttl);
        let shard = self.get_or_create_target_shard(target_did);
        let mut guard = shard.lock();
        let target_focal = if guard.buckets.contains_key(focal_uri) {
            focal_uri.to_string()
        } else {
            guard
                .buckets
                .iter()
                .find(|(_, b)| b.active_storm_id == Some(storm_id))
                .map(|(k, _)| k.clone())
                .unwrap_or_else(|| focal_uri.to_string())
        };
        let digest = {
            let bucket = guard.buckets.entry(target_focal.clone()).or_default();
            Self::clear_dismissed_bucket(target_did, &target_focal, bucket, now_us, ttl_us)
        };
        self.sync_active_storm(target_did, &guard, now_us);
        digest
    }

    fn clear_dismissed_bucket(
        target_did: &str,
        focal_uri: &str,
        bucket: &mut FocalPostBucket,
        now_us: u64,
        ttl_us: u64,
    ) -> Option<StormDigestNotification> {
        bucket.clear_storm();
        bucket.dismissed_until_us = Some(now_us.saturating_add(ttl_us));
        bucket.clear_buffers();

        if bucket.digest_bounced_count > 0 {
            let bounced_count = bucket.digest_bounced_count;
            let sample_violators = std::mem::take(&mut bucket.digest_sample_violators);
            let start_us = bucket.digest_window_start_us.unwrap_or(now_us);
            let elapsed_us = now_us.saturating_sub(start_us);
            bucket.digest_bounced_count = 0;
            bucket.digest_window_start_us = None;
            Some(StormDigestNotification {
                target_did: target_did.to_string(),
                focal_post_uri: focal_uri.to_string(),
                bounced_count,
                sample_violators,
                window_secs: (elapsed_us / 1_000_000).max(1),
                storm_still_active: false,
            })
        } else {
            None
        }
    }

    /// Buffers a bounce into the Storm Mode digest if Storm Mode is active for `target_did`.
    ///
    /// Returns `true` if Storm Mode absorbed the bounce (suppressing individual bounce DM spam),
    /// or `false` if Storm Mode is inactive and the caller should emit a normal bounce alert.
    pub fn record_storm_bounce(
        &self,
        target_did: &str,
        focal_uri: Option<&str>,
        violator_did: &str,
        violator_handle: Option<String>,
        category: &str,
        now_us: u64,
    ) -> bool {
        let Some(shard) = self.get_target_shard(target_did) else {
            return false;
        };
        let mut guard = shard.lock();
        let manual_active = guard
            .manual_storm_mode_until_us
            .is_some_and(|until| until > now_us);

        // Prefer exact focal_uri match when that bucket has an active storm.
        let exact_active = focal_uri
            .and_then(|u| guard.buckets.get(u))
            .is_some_and(|b| b.has_active_storm(now_us));

        let chosen_key = if exact_active {
            focal_uri.map(str::to_string)
        } else {
            // Fall back to the most recently updated active storm bucket for target_did, if any.
            let active_fallback = guard
                .buckets
                .iter()
                .filter(|(_, b)| b.has_active_storm(now_us))
                .max_by_key(|(_, b)| b.last_activity_us)
                .map(|(k, _)| k.clone());

            match active_fallback {
                Some(k) => Some(k),
                None if manual_active => Some(
                    focal_uri
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("at://{target_did}/app.bsky.feed.post/_storm")),
                ),
                None => None,
            }
        };

        let Some(bucket_key) = chosen_key else {
            return false;
        };

        let medium_cutoff = now_us.saturating_sub(dur_to_us(self.config.medium_window));
        if !guard.buckets.contains_key(&bucket_key)
            && guard.buckets.len() >= self.config.max_tracked_posts
        {
            guard.evict_oldest_bucket(medium_cutoff, now_us, self.config.max_tracked_posts);
        }

        let bucket = guard.buckets.entry(bucket_key).or_default();
        bucket.last_activity_us = bucket.last_activity_us.max(now_us);
        if bucket.digest_window_start_us.is_none() {
            bucket.digest_window_start_us = Some(now_us);
        }
        bucket.digest_bounced_count = bucket.digest_bounced_count.saturating_add(1);

        if bucket.digest_sample_violators.len() < MAX_DIGEST_SAMPLES
            && !bucket
                .digest_sample_violators
                .iter()
                .any(|v| v.violator_did == violator_did)
        {
            bucket.digest_sample_violators.push(DigestBounceSummary {
                violator_did: violator_did.to_string(),
                violator_handle,
                category: category.to_string(),
            });
        }

        true
    }

    /// Drains any pending Storm Mode digests whose `digest_interval` has elapsed
    /// (or whose storm has expired/been dismissed when `force_flush_expired` is true).
    #[must_use]
    pub fn drain_due_digests(
        &self,
        now_us: u64,
        force_flush_expired: bool,
    ) -> Vec<StormDigestNotification> {
        let interval_us = dur_to_us(self.config.digest_interval);
        let snapshot: Vec<(String, Arc<Mutex<TargetDogpileState>>)> = {
            let guard = self.targets.read();
            guard
                .iter()
                .map(|(k, v)| (k.clone(), Arc::clone(v)))
                .collect()
        };
        let mut out = Vec::new();
        for (target_did, shard) in snapshot {
            let mut guard = shard.lock();
            out.extend(guard.drain_due_digests(
                &target_did,
                now_us,
                interval_us,
                force_flush_expired,
            ));
        }
        out
    }

    /// Expires stale storms/manual toggles, prunes old sliding-window buffers,
    /// and flushes due or final Storm Mode digests.
    ///
    /// Returns `(expired_storms, due_digests)` where `expired_storms` contains
    /// `(target_did, focal_post_uri, storm_id)` entries to mark [`StormStatus::Resolved`](crate::dogpile::StormStatus::Resolved).
    #[must_use]
    pub fn prune_and_expire(
        &self,
        now_us: u64,
    ) -> (Vec<(String, String, i64)>, Vec<StormDigestNotification>) {
        let medium_cutoff = now_us.saturating_sub(dur_to_us(self.config.medium_window));
        let short_cutoff = now_us.saturating_sub(dur_to_us(self.config.short_window));
        let interval_us = dur_to_us(self.config.digest_interval);
        let cooldown_us = dur_to_us(self.config.alert_cooldown);

        let snapshot: Vec<(String, Arc<Mutex<TargetDogpileState>>)> = {
            let guard = self.targets.read();
            guard
                .iter()
                .map(|(k, v)| (k.clone(), Arc::clone(v)))
                .collect()
        };

        let mut expired = Vec::new();
        let mut digests = Vec::new();
        let mut empty_candidates = Vec::new();

        for (target_did, shard) in snapshot {
            let mut guard = shard.lock();
            if guard
                .manual_storm_mode_until_us
                .is_some_and(|until| until <= now_us)
            {
                guard.manual_storm_mode_until_us = None;
            }

            for (focal_uri, bucket) in &mut guard.buckets {
                bucket.prune(medium_cutoff, Some(short_cutoff));
                if let Some(exp) = bucket.storm_expires_us {
                    if exp <= now_us {
                        if let Some(id) = bucket.active_storm_id {
                            expired.push((target_did.clone(), focal_uri.clone(), id));
                        }
                        bucket.clear_storm();
                    }
                }
            }

            guard.defensive.prune(short_cutoff);
            digests.extend(guard.drain_due_digests(&target_did, now_us, interval_us, true));

            guard.buckets.retain(|_, bucket| {
                !bucket.events.is_empty()
                    || !bucket.eval_outcomes.is_empty()
                    || bucket.active_storm_id.is_some()
                    || bucket.digest_bounced_count > 0
                    || bucket.is_suppressed(now_us)
            });
            guard
                .alert_cooldowns
                .retain(|_, &mut ts| now_us.saturating_sub(ts) < cooldown_us);
            guard
                .postgate_state
                .retain(|_, (_, _, ts)| now_us.saturating_sub(*ts) <= POSTGATE_STATE_TTL_US);

            self.sync_active_storm(&target_did, &guard, now_us);
            if guard.is_empty() {
                empty_candidates.push(target_did);
            }
        }

        if !empty_candidates.is_empty() {
            let mut targets_guard = self.targets.write();
            for did in empty_candidates {
                if let Some(arc) = targets_guard.get(&did) {
                    let can_remove =
                        Arc::strong_count(arc) == 1 && arc.try_lock().is_some_and(|g| g.is_empty());
                    if can_remove {
                        targets_guard.remove(&did);
                    }
                }
            }
        }

        (expired, digests)
    }
}

fn dur_to_us(dur: std::time::Duration) -> u64 {
    u64::try_from(dur.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn reply_from(
        author: &str,
        target: &str,
        rkey: &str,
        post_rkey: &str,
        text: &str,
    ) -> Interaction {
        Interaction::new(
            author,
            target,
            InteractionType::DirectReply,
            format!("at://{author}/app.bsky.feed.post/{post_rkey}"),
            format!("cid_{post_rkey}"),
            text,
        )
        .with_parent_uri(format!("at://{target}/app.bsky.feed.post/{rkey}"))
        .with_root_uri(format!("at://{target}/app.bsky.feed.post/{rkey}"))
    }

    #[test]
    fn tracker_ignores_in_network_burst_and_triggers_on_oon_surge() {
        let cfg = DogpileConfig::default()
            .with_min_unique_authors(5)
            .with_min_out_of_network_ratio(0.70)
            .with_eval_recheck_interval(Duration::from_secs(60));
        let tracker = DogpileTracker::new(cfg);
        let t0 = 1_750_000_000_000_000_u64;

        // 8 in-network followers replying -> must never trigger
        for i in 0..8 {
            let inter = reply_from(
                &format!("did:plc:friend{i}"),
                "did:plc:alice",
                "root1",
                &format!("fr{i}"),
                "good post!",
            );
            assert!(tracker
                .record_interaction(&inter, false, t0 + i * 1_000_000)
                .is_none());
        }

        // 5 out-of-network strangers on a different post -> triggers on 5th
        let mut candidate = None;
        for i in 0..5 {
            let inter = reply_from(
                &format!("did:plc:stranger{i}"),
                "did:plc:alice",
                "root2",
                &format!("st{i}"),
                "ratio!",
            );
            candidate = tracker.record_interaction(&inter, true, t0 + i * 1_000_000);
        }
        let cand = candidate.expect("expected surge candidate on 5th OON reply");
        assert_eq!(
            cand.focal_post_uri,
            "at://did:plc:alice/app.bsky.feed.post/root2"
        );
        assert_eq!(cand.initial_metrics.unique_oon_authors_short, 5);
        assert_eq!(cand.sample_replies.len(), 5);

        // Immediate 6th reply is gated by eval_recheck_interval
        let extra = reply_from(
            "did:plc:stranger5",
            "did:plc:alice",
            "root2",
            "st5",
            "another!",
        );
        assert!(tracker
            .record_interaction(&extra, true, t0 + 10_000_000)
            .is_none());

        // After recheck interval elapses, 7th reply re-triggers Stage 2
        let later = reply_from(
            "did:plc:stranger6",
            "did:plc:alice",
            "root2",
            "st6",
            "more!",
        );
        assert!(tracker
            .record_interaction(&later, true, t0 + 65_000_000)
            .is_some());
    }

    #[test]
    fn tracker_defensive_distress_lowers_threshold_and_dedups_postgate_deltas() {
        let cfg = DogpileConfig::default()
            .with_min_unique_authors(10)
            .with_defensive_block_burst(3)
            .with_defensive_detach_burst(2);
        let tracker = DogpileTracker::new(cfg);
        let t0 = 1_750_000_000_000_000_u64;

        // 3 blocks from target user -> distress active -> reduced threshold = 10/2 = 5
        tracker.record_defensive_block("did:plc:alice", t0);
        tracker.record_defensive_block("did:plc:alice", t0 + 1_000_000);
        tracker.record_defensive_block("did:plc:alice", t0 + 2_000_000);

        let mut triggered = None;
        for i in 0..5 {
            let inter = reply_from(
                &format!("did:plc:mob{i}"),
                "did:plc:alice",
                "root_distress",
                &format!("m{i}"),
                "delete this",
            );
            triggered = tracker.record_interaction(&inter, true, t0 + 3_000_000 + i * 1_000_000);
        }
        let cand = triggered.expect("distress should trigger at reduced threshold");
        assert_eq!(cand.initial_metrics.defensive_blocks, 3);

        // Postgate delta check on bob
        tracker.record_defensive_postgate(
            "did:plc:bob",
            "at://did:plc:bob/app.bsky.feed.post/p1",
            1,
            false,
            t0,
        );
        // Re-updating same post with 1 detach + disableRule adds only 1 new signal (total 2)
        tracker.record_defensive_postgate(
            "did:plc:bob",
            "at://did:plc:bob/app.bsky.feed.post/p1",
            1,
            true,
            t0 + 1_000_000,
        );
        let mut bob_cand = None;
        for i in 0..5 {
            let inter = reply_from(
                &format!("did:plc:bmob{i}"),
                "did:plc:bob",
                "p1",
                &format!("bm{i}"),
                "dunk",
            );
            bob_cand = tracker.record_interaction(&inter, true, t0 + 2_000_000 + i * 1_000_000);
        }
        let bob = bob_cand.expect("postgate burst should trigger");
        assert_eq!(bob.initial_metrics.defensive_detaches, 2);
    }

    #[test]
    fn tracker_cooldown_escalation_digests_and_expiration() {
        let cfg = DogpileConfig::default()
            .with_alert_cooldown(Duration::from_secs(600))
            .with_storm_mode_ttl(Duration::from_secs(900))
            .with_digest_interval(Duration::from_secs(120));
        let tracker = DogpileTracker::new(cfg);
        let t0 = 1_750_000_000_000_000_u64;
        let focal = "at://did:plc:alice/app.bsky.feed.post/p1";

        // First activation alerts
        assert_eq!(
            tracker.activate_storm("did:plc:alice", focal, 42, StormSeverity::Elevated, t0),
            (true, false)
        );
        assert!(tracker.is_storm_mode_active("did:plc:alice", t0 + 1_000_000));

        // Same severity within cooldown does NOT alert
        assert_eq!(
            tracker.activate_storm(
                "did:plc:alice",
                focal,
                42,
                StormSeverity::Elevated,
                t0 + 60_000_000
            ),
            (false, false)
        );

        // Escalation to High DOES alert immediately
        assert_eq!(
            tracker.activate_storm(
                "did:plc:alice",
                focal,
                42,
                StormSeverity::High,
                t0 + 65_000_000
            ),
            (true, true)
        );

        // Bounces during Storm Mode are digested
        assert!(tracker.record_storm_bounce(
            "did:plc:alice",
            Some(focal),
            "did:plc:troll1",
            Some("troll1.bsky.social".to_string()),
            "harassment",
            t0 + 70_000_000
        ));
        assert!(tracker.record_storm_bounce(
            "did:plc:alice",
            Some(focal),
            "did:plc:troll2",
            None,
            "harassment",
            t0 + 80_000_000
        ));

        // Before digest_interval, nothing due
        assert!(tracker.drain_due_digests(t0 + 90_000_000, false).is_empty());

        // After digest_interval (120s), digest flushes
        let digests = tracker.drain_due_digests(t0 + 130_000_000, false);
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].bounced_count, 2);
        assert_eq!(digests[0].sample_violators.len(), 2);
        assert!(digests[0].storm_still_active);

        // Buffer another bounce, then let storm expire past TTL (65 + 900 = 965s)
        assert!(tracker.record_storm_bounce(
            "did:plc:alice",
            Some(focal),
            "did:plc:troll3",
            None,
            "spam",
            t0 + 140_000_000
        ));
        let (expired, final_digests) = tracker.prune_and_expire(t0 + 1_000_000_000);
        assert_eq!(
            expired,
            vec![("did:plc:alice".to_string(), focal.to_string(), 42)]
        );
        assert_eq!(final_digests.len(), 1);
        assert_eq!(final_digests[0].bounced_count, 1);
        assert!(!final_digests[0].storm_still_active);
        assert!(!tracker.is_storm_mode_active("did:plc:alice", t0 + 1_000_000_000));
    }

    #[test]
    fn tracker_manual_storm_mode_dismiss_and_bounded_eviction() {
        let cfg = DogpileConfig::default().with_max_tracked_posts(2);
        let tracker = DogpileTracker::new(cfg);
        let t0 = 1_750_000_000_000_000_u64;

        // Manual storm mode absorbs bounces even with no auto-detected storm
        tracker.set_manual_storm_mode("did:plc:alice", true, t0);
        assert!(tracker.is_storm_mode_active("did:plc:alice", t0 + 10));
        assert!(tracker.record_storm_bounce(
            "did:plc:alice",
            None,
            "did:plc:x",
            None,
            "spam",
            t0 + 20
        ));
        tracker.set_manual_storm_mode("did:plc:alice", false, t0 + 30);
        assert!(!tracker.is_storm_mode_active("did:plc:alice", t0 + 31));
        assert!(!tracker.record_storm_bounce(
            "did:plc:alice",
            None,
            "did:plc:y",
            None,
            "spam",
            t0 + 32
        ));

        // Dismiss clears active storm
        let _ = tracker.activate_storm(
            "did:plc:bob",
            "at://did:plc:bob/app.bsky.feed.post/1",
            7,
            StormSeverity::Elevated,
            t0,
        );
        assert!(tracker.is_storm_mode_active("did:plc:bob", t0 + 1));
        assert!(tracker
            .dismiss_storm(
                "did:plc:bob",
                "at://did:plc:bob/app.bsky.feed.post/1",
                7,
                t0 + 2
            )
            .is_none());
        assert!(!tracker.is_storm_mode_active("did:plc:bob", t0 + 2));

        // Bounded capacity eviction keeps bucket count <= max_tracked_posts
        for idx in 0..5 {
            let inter = reply_from(
                "did:plc:attacker",
                "did:plc:alice",
                &format!("post{idx}"),
                &format!("rep{idx}"),
                "hi",
            );
            let _ = tracker.record_interaction(&inter, true, t0 + idx * 1000);
        }
        let alice_shard = tracker.get_target_shard("did:plc:alice").unwrap();
        assert!(alice_shard.lock().buckets.len() <= 2);
    }

    #[test]
    fn tracker_dismiss_suppression_out_of_order_outcomes_quote_mention_and_eviction_guards() {
        let cfg = DogpileConfig::default()
            .with_min_unique_authors(4)
            .with_storm_mode_ttl(Duration::from_secs(600))
            .with_alert_cooldown(Duration::from_secs(300))
            .with_max_tracked_posts(2)
            .with_max_sample_replies(3);
        let tracker = DogpileTracker::new(cfg);
        let t0 = 1_750_000_000_000_000_u64;
        let focal = "at://did:plc:alice/app.bsky.feed.post/focal1";

        // 1. Quote+mention hybrid (`InteractionType::Mention` with `quote_uri == focal`) counts as quote catalyst.
        for i in 0..4 {
            let mut inter = Interaction::new(
                format!("did:plc:qtmention{i}"),
                "did:plc:alice",
                InteractionType::Mention,
                format!("at://did:plc:qtmention{i}/app.bsky.feed.post/qm{i}"),
                format!("cid{i}"),
                format!("look at @alice {i}"),
            )
            .with_quote_uri(focal);
            if i == 3 {
                inter.interaction_type = InteractionType::DirectReply;
            }
            let cand = tracker.record_interaction(&inter, true, t0 + i * 1_000_000);
            if i == 3 {
                let c = cand.expect("4th interaction should trigger");
                assert_eq!(c.recent_quote_uris.len(), 4);
                assert_eq!(c.initial_metrics.quote_count_short, 4);
            }
        }

        // 2. Out-of-order eval_outcomes prune cleanly via `retain` and respect cap.
        tracker.record_evaluation_outcome("did:plc:alice", focal, false, t0 + 10_000_000);
        tracker.record_evaluation_outcome("did:plc:alice", focal, true, t0 + 1_000); // older than later cutoff
        tracker.record_evaluation_outcome(
            "did:plc:alice",
            focal,
            true,
            t0 + 2_000_000_000, // advances medium_cutoff past both prior entries
        );
        {
            let shard = tracker.get_target_shard("did:plc:alice").unwrap();
            let guard = shard.lock();
            let b = guard.buckets.get(focal).unwrap();
            assert_eq!(b.eval_outcomes.len(), 1);
            assert!(b.eval_outcomes[0].1);
            assert_eq!(b.eval_violation_count, 1);
        }

        // 3. `dismiss_storm` flushes pending digest immediately and suppresses re-triggering for TTL.
        let _ = tracker.activate_storm("did:plc:alice", focal, 99, StormSeverity::High, t0);
        assert!(tracker.record_storm_bounce(
            "did:plc:alice",
            Some(focal),
            "did:plc:bad1",
            None,
            "harassment",
            t0 + 10_000_000,
        ));
        let flushed = tracker
            .dismiss_storm("did:plc:alice", focal, 99, t0 + 20_000_000)
            .expect("pending digest must flush on dismiss");
        assert_eq!(flushed.bounced_count, 1);
        assert!(!flushed.storm_still_active);

        // Subsequent surge interaction within TTL is suppressed.
        let suppressed_inter = reply_from("did:plc:extra", "did:plc:alice", "focal1", "ex1", "hi");
        assert!(tracker
            .record_interaction(&suppressed_inter, true, t0 + 30_000_000)
            .is_none());

        // 4. `postgate_state` survives 5m `DefensiveWindow` prune in `prune_and_expire`.
        tracker.record_defensive_postgate(
            "did:plc:carol",
            "at://did:plc:carol/app.bsky.feed.post/p1",
            2,
            false,
            t0,
        );
        let _ = tracker.prune_and_expire(t0 + 400_000_000); // > 5m short window
        tracker.record_defensive_postgate(
            "did:plc:carol",
            "at://did:plc:carol/app.bsky.feed.post/p1",
            2, // unchanged count!
            false,
            t0 + 401_000_000,
        );
        assert_eq!(
            tracker.get_target_shard("did:plc:carol").map_or(0, |s| s
                .lock()
                .defensive
                .recent_detaches
                .len()),
            0,
            "unchanged postgate after 5m prune must not double-count prior detaches"
        );

        // 5. Alert cooldowns survive bucket event pruning.
        let cooldown_focal = "at://did:plc:dave/app.bsky.feed.post/cd1";
        assert_eq!(
            tracker.activate_storm(
                "did:plc:dave",
                cooldown_focal,
                10,
                StormSeverity::Elevated,
                t0
            ),
            (true, false)
        );
        // Expire storm and prune empty bucket, then re-activate within alert_cooldown (300s).
        let _ = tracker.prune_and_expire(t0 + 700_000_000);
        // Use a fresh tracker to test alert_cooldown < storm_mode_ttl directly:
        let cd_tracker = DogpileTracker::new(
            DogpileConfig::default()
                .with_storm_mode_ttl(Duration::from_secs(60))
                .with_alert_cooldown(Duration::from_secs(300)),
        );
        assert_eq!(
            cd_tracker.activate_storm(
                "did:plc:dave",
                cooldown_focal,
                11,
                StormSeverity::Elevated,
                t0
            ),
            (true, false)
        );
        let _ = cd_tracker.prune_and_expire(t0 + 70_000_000); // storm expired & bucket pruned
        assert_eq!(
            cd_tracker.activate_storm(
                "did:plc:dave",
                cooldown_focal,
                12,
                StormSeverity::Elevated,
                t0 + 100_000_000
            ),
            (false, false),
            "cooldown must be retained even after bucket was pruned"
        );

        // 6. `evict_oldest_locked` stops once below `max_tracked_posts` after pruning stale buckets.
        let evict_tracker = DogpileTracker::new(
            DogpileConfig::default()
                .with_max_tracked_posts(2)
                .with_medium_window(Duration::from_secs(60)),
        );
        let _ = evict_tracker.record_interaction(
            &reply_from("did:plc:a1", "did:plc:eve", "stale", "s1", "old"),
            true,
            t0,
        );
        let _ = evict_tracker.record_interaction(
            &reply_from("did:plc:a2", "did:plc:eve", "live", "l1", "recent"),
            true,
            t0 + 100_000_000,
        );
        let _ = evict_tracker.record_interaction(
            &reply_from("did:plc:a3", "did:plc:eve", "live2", "l2", "recent2"),
            true,
            t0 + 101_000_000,
        );
        assert!(evict_tracker
            .get_target_shard("did:plc:eve")
            .unwrap()
            .lock()
            .buckets
            .contains_key("at://did:plc:eve/app.bsky.feed.post/live"));

        // 7. rollback_eval_recheck clears last_eval_us; oon_samples reservoir-samples > max_sample_replies;
        //    dismiss_storm drains immediate digest and clears bucket buffers; rehydrate_storm restores active state.
        let r_tracker = DogpileTracker::new(
            DogpileConfig::default()
                .with_min_unique_authors(6)
                .with_min_out_of_network_ratio(0.5)
                .with_max_sample_replies(3)
                .with_eval_recheck_interval(Duration::from_secs(60))
                .with_storm_mode_ttl(Duration::from_secs(120)),
        );
        let mut surge_ts = t0;
        let mut last_cand = None;
        for i in 0..8 {
            surge_ts += 1_000_000;
            if let Some(c) = r_tracker.record_interaction(
                &reply_from(
                    &format!("did:plc:res_{i}"),
                    "did:plc:faye",
                    "p_res",
                    &format!("r{i}"),
                    "reply text",
                ),
                true,
                surge_ts,
            ) {
                last_cand = Some(c);
            }
        }
        let cand = last_cand.expect("should produce surge candidate");
        assert_eq!(cand.sample_replies.len(), 3);
        r_tracker.rollback_eval_recheck(
            "did:plc:faye",
            "at://did:plc:faye/app.bsky.feed.post/p_res",
            cand.observed_at_us,
        );
        assert!(r_tracker
            .record_interaction(
                &reply_from(
                    "did:plc:res_extra",
                    "did:plc:faye",
                    "p_res",
                    "re",
                    "after rollback"
                ),
                true,
                surge_ts + 500_000,
            )
            .is_some());

        r_tracker.rehydrate_storm(
            "did:plc:faye",
            "at://did:plc:faye/app.bsky.feed.post/p_res",
            99,
            StormSeverity::High,
            surge_ts,
            surge_ts + 120_000_000,
        );
        assert!(r_tracker.is_storm_mode_active("did:plc:faye", surge_ts + 1_000_000));
        r_tracker.record_storm_bounce(
            "did:plc:faye",
            Some("at://did:plc:faye/app.bsky.feed.post/p_res"),
            "did:plc:bad",
            Some("bouncer.bsky.social".to_string()),
            "spam",
            surge_ts + 2_000_000,
        );
        let digest_on_dismiss = r_tracker.dismiss_storm(
            "did:plc:faye",
            "at://did:plc:faye/app.bsky.feed.post/p_res",
            99,
            surge_ts + 3_000_000,
        );
        assert!(digest_on_dismiss.is_some());
        assert!(!r_tracker.is_storm_mode_active("did:plc:faye", surge_ts + 4_000_000));
    }

    #[test]
    fn tracker_sharding_bounds_events_defensive_and_short_cursor_incrementally() {
        let cfg = DogpileConfig::default()
            .with_short_window(Duration::from_secs(300))
            .with_medium_window(Duration::from_secs(1800))
            .with_min_unique_authors(5000);
        let tracker = DogpileTracker::new(cfg);
        let t0 = 1_750_000_000_000_000_u64;

        // Exceed MAX_BUCKET_EVENTS on one focal post and verify cap holds.
        for i in 0..(MAX_BUCKET_EVENTS + 120) {
            let inter = reply_from(
                &format!("did:plc:flood_{i}"),
                "did:plc:alice",
                "flood_post",
                &format!("fp_{i}"),
                "flood",
            );
            let _ = tracker.record_interaction(&inter, true, t0 + (i as u64) * 100);
        }
        {
            let shard = tracker.get_target_shard("did:plc:alice").unwrap();
            let guard = shard.lock();
            let bucket = guard
                .buckets
                .get("at://did:plc:alice/app.bsky.feed.post/flood_post")
                .unwrap();
            assert_eq!(bucket.events.len(), MAX_BUCKET_EVENTS);
            assert_eq!(bucket.seen_post_uris.len(), MAX_BUCKET_EVENTS);
            assert_eq!(bucket.short_count, MAX_BUCKET_EVENTS);
        }

        // Advance time past short_window for old events while keeping them inside medium_window,
        // verifying short_cursor advances and short_author_counts drops to only new events.
        let t_later = t0 + 400_000_000;
        let fresh = reply_from(
            "did:plc:fresh",
            "did:plc:alice",
            "flood_post",
            "fresh_1",
            "hi",
        );
        let _ = tracker.record_interaction(&fresh, true, t_later);
        {
            let shard = tracker.get_target_shard("did:plc:alice").unwrap();
            let guard = shard.lock();
            let bucket = guard
                .buckets
                .get("at://did:plc:alice/app.bsky.feed.post/flood_post")
                .unwrap();
            assert_eq!(bucket.short_count, 1);
            assert_eq!(bucket.short_author_counts.len(), 1);
            assert_eq!(bucket.short_oon_author_counts.len(), 1);
        }

        // Exceed MAX_DEFENSIVE_EVENTS on blocks & detaches.
        for i in 0..(MAX_DEFENSIVE_EVENTS + 50) {
            tracker.record_defensive_block("did:plc:alice", t_later + i as u64);
        }
        {
            let shard = tracker.get_target_shard("did:plc:alice").unwrap();
            assert_eq!(
                shard.lock().defensive.recent_blocks.len(),
                MAX_DEFENSIVE_EVENTS
            );
        }
    }
}
