//! In-memory rolling-window surge tracker, Storm Mode state, and digest buffer.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use parking_lot::RwLock;

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

#[derive(Debug, Clone)]
struct TrackedEvent {
    timestamp_us: u64,
    author_did: String,
    is_oon: bool,
    interaction_type: InteractionType,
}

#[derive(Debug, Default)]
struct DefensiveWindow {
    recent_blocks: VecDeque<u64>,
    recent_detaches: VecDeque<u64>,
    last_postgate_state: HashMap<String, (usize, bool)>,
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

    fn counts(&mut self, cutoff_us: u64) -> (usize, usize) {
        self.prune(cutoff_us);
        (self.recent_blocks.len(), self.recent_detaches.len())
    }
}

#[derive(Debug, Default)]
struct FocalPostBucket {
    events: VecDeque<TrackedEvent>,
    seen_post_uris: HashSet<String>,
    oon_samples: VecDeque<SampleReply>,
    recent_quote_uris: VecDeque<String>,
    eval_outcomes: VecDeque<(u64, bool)>,
    last_eval_us: Option<u64>,
    last_activity_us: u64,
    active_storm_id: Option<i64>,
    active_severity: Option<StormSeverity>,
    last_alert_us: Option<u64>,
    storm_expires_us: Option<u64>,
    digest_window_start_us: Option<u64>,
    digest_bounced_count: u64,
    digest_sample_violators: Vec<DigestBounceSummary>,
}

impl FocalPostBucket {
    fn prune(&mut self, medium_cutoff_us: u64) {
        while self
            .events
            .front()
            .is_some_and(|ev| ev.timestamp_us < medium_cutoff_us)
        {
            self.events.pop_front();
        }
        if self.events.is_empty()
            || self.seen_post_uris.len() > self.events.len().saturating_mul(2).max(64)
        {
            self.seen_post_uris.clear();
        }
        while self
            .eval_outcomes
            .front()
            .is_some_and(|&(ts, _)| ts < medium_cutoff_us)
        {
            self.eval_outcomes.pop_front();
        }
    }

    fn has_active_storm(&self, now_us: u64) -> bool {
        self.active_storm_id.is_some() && self.storm_expires_us.is_some_and(|exp| exp > now_us)
    }

    fn clear_storm(&mut self) {
        self.active_storm_id = None;
        self.active_severity = None;
        self.storm_expires_us = None;
    }
}

#[derive(Debug, Default)]
struct TrackerState {
    buckets: HashMap<(String, String), FocalPostBucket>,
    defensive: HashMap<String, DefensiveWindow>,
    manual_storm_mode_until_us: HashMap<String, u64>,
}

/// Thread-safe, sliding-window dogpile detector and Storm Mode coordinator.
///
/// Tracks per-`(target_did, focal_post_uri)` interaction velocity, out-of-network
/// author ratio, target defensive distress signals (`app.bsky.graph.block` /
/// `app.bsky.feed.postgate`), alert cooldowns, and Storm Mode bounce digests.
#[derive(Clone, Debug)]
pub struct DogpileTracker {
    config: DogpileConfig,
    state: Arc<RwLock<TrackerState>>,
}

impl DogpileTracker {
    /// Creates a new [`DogpileTracker`] with the provided configuration.
    #[must_use]
    pub fn new(config: DogpileConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(TrackerState::default())),
        }
    }

    /// Returns a reference to the active [`DogpileConfig`].
    #[must_use]
    pub fn config(&self) -> &DogpileConfig {
        &self.config
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

        let mut guard = self.state.write();

        // Read target defensive signals (blocks/detaches in short_window) before bucket insertion
        let (defensive_blocks, defensive_detaches) = guard
            .defensive
            .get_mut(&target_did)
            .map_or((0, 0), |d| d.counts(short_cutoff));

        let key = (target_did.clone(), focal_uri.clone());
        if !guard.buckets.contains_key(&key) && guard.buckets.len() >= self.config.max_tracked_posts
        {
            Self::evict_oldest_locked(&mut guard, medium_cutoff, now_us);
        }

        let bucket = guard.buckets.entry(key).or_default();
        bucket.prune(medium_cutoff);
        bucket.last_activity_us = bucket.last_activity_us.max(now_us);

        // Deduplicate identical post URIs (e.g., if matched via both reply + mention)
        if bucket.seen_post_uris.insert(interaction.post_uri.clone()) {
            bucket.events.push_back(TrackedEvent {
                timestamp_us: now_us,
                author_did: interaction.author_did.clone(),
                is_oon: is_out_of_network,
                interaction_type: interaction.interaction_type,
            });
        }

        if interaction.interaction_type == InteractionType::Quote
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
                .any(|s| s.author_did == interaction.author_did);
            if !already_sampled {
                if bucket.oon_samples.len() >= self.config.max_sample_replies {
                    bucket.oon_samples.pop_front();
                }
                bucket.oon_samples.push_back(SampleReply {
                    author_did: interaction.author_did.clone(),
                    interaction_type: interaction.interaction_type,
                    post_uri: interaction.post_uri.clone(),
                    text_snippet: interaction.text.chars().take(280).collect(),
                });
            }
        }

        // Compute short & medium counts and unique author sets
        let mut unique_short: HashSet<&str> = HashSet::new();
        let mut unique_oon_short: HashSet<&str> = HashSet::new();
        let mut short_count = 0usize;
        let mut reply_count_short = 0usize;
        let mut quote_count_short = 0usize;
        let mut mention_count_short = 0usize;
        let medium_count = bucket.events.len();

        for ev in &bucket.events {
            if ev.timestamp_us >= short_cutoff {
                short_count += 1;
                unique_short.insert(ev.author_did.as_str());
                if ev.is_oon {
                    unique_oon_short.insert(ev.author_did.as_str());
                }
                match ev.interaction_type {
                    InteractionType::DirectReply | InteractionType::ThreadReply => {
                        reply_count_short += 1;
                    }
                    InteractionType::Quote => quote_count_short += 1,
                    InteractionType::Mention => mention_count_short += 1,
                }
            }
        }

        let unique_authors_short = unique_short.len();
        let unique_oon_authors_short = unique_oon_short.len();
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
        let eval_violations = bucket.eval_outcomes.iter().filter(|&&(_, v)| v).count();
        let violation_rate = if eval_total > 0 {
            eval_violations as f64 / eval_total as f64
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
            sample_replies: bucket.oon_samples.iter().cloned().collect(),
            recent_quote_uris: bucket.recent_quote_uris.iter().cloned().collect(),
        })
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
        let medium_cutoff = now_us.saturating_sub(dur_to_us(self.config.medium_window));
        let mut guard = self.state.write();
        if let Some(bucket) = guard
            .buckets
            .get_mut(&(target_did.to_string(), focal_uri.to_string()))
        {
            bucket.prune(medium_cutoff);
            bucket.eval_outcomes.push_back((now_us, violated));
        }
    }

    /// Records a target user creating an `app.bsky.graph.block` record (distress signal).
    pub fn record_defensive_block(&self, target_did: &str, now_us: u64) {
        if !self.config.enabled {
            return;
        }
        let short_cutoff = now_us.saturating_sub(dur_to_us(self.config.short_window));
        let mut guard = self.state.write();
        let win = guard.defensive.entry(target_did.to_string()).or_default();
        win.prune(short_cutoff);
        win.recent_blocks.push_back(now_us);
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
        let mut guard = self.state.write();
        let win = guard.defensive.entry(target_did.to_string()).or_default();
        win.prune(short_cutoff);

        let (prev_count, prev_disabled) = win
            .last_postgate_state
            .get(post_uri)
            .copied()
            .unwrap_or((0, false));
        let new_detaches = detached_count.saturating_sub(prev_count);
        let new_disable = usize::from(disabled_quotes && !prev_disabled);
        let delta = new_detaches.saturating_add(new_disable).min(50);

        for _ in 0..delta {
            win.recent_detaches.push_back(now_us);
        }
        win.last_postgate_state
            .insert(post_uri.to_string(), (detached_count, disabled_quotes));
        if win.last_postgate_state.len() > 256 {
            win.last_postgate_state.clear();
        }
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

        let mut guard = self.state.write();
        let key = (target_did.to_string(), focal_uri.to_string());
        if !guard.buckets.contains_key(&key) && guard.buckets.len() >= self.config.max_tracked_posts
        {
            Self::evict_oldest_locked(&mut guard, medium_cutoff, now_us);
        }
        let bucket = guard.buckets.entry(key).or_default();
        bucket.last_activity_us = bucket.last_activity_us.max(now_us);

        let was_active = bucket.has_active_storm(now_us);
        let escalated = was_active && bucket.active_severity.is_some_and(|prev| severity > prev);

        let should_emit = match bucket.last_alert_us {
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
        if bucket.digest_window_start_us.is_none() {
            bucket.digest_window_start_us = Some(now_us);
        }
        if should_emit {
            bucket.last_alert_us = Some(now_us);
        }

        (should_emit, escalated)
    }

    /// Returns `true` if Storm Mode is currently active for `target_did`
    /// (either via an active confirmed storm or manual Storm Mode toggle).
    #[must_use]
    pub fn is_storm_mode_active(&self, target_did: &str, now_us: u64) -> bool {
        let guard = self.state.read();
        if guard
            .manual_storm_mode_until_us
            .get(target_did)
            .is_some_and(|&until| until > now_us)
        {
            return true;
        }
        guard
            .buckets
            .iter()
            .any(|((did, _), bucket)| did == target_did && bucket.has_active_storm(now_us))
    }

    /// Manually enables or disables Storm Mode for `target_did`.
    ///
    /// When disabled (`enabled == false`), also clears any active storm flags for `target_did`
    /// so Storm Mode exits immediately.
    pub fn set_manual_storm_mode(&self, target_did: &str, enabled: bool, now_us: u64) {
        let mut guard = self.state.write();
        if enabled {
            let until = now_us.saturating_add(dur_to_us(self.config.storm_mode_ttl));
            guard
                .manual_storm_mode_until_us
                .insert(target_did.to_string(), until);
        } else {
            guard.manual_storm_mode_until_us.remove(target_did);
            for ((did, _), bucket) in &mut guard.buckets {
                if did == target_did {
                    bucket.clear_storm();
                }
            }
        }
    }

    /// Clears in-memory active storm state matching `storm_id` for `target_did`.
    pub fn dismiss_storm(&self, target_did: &str, storm_id: i64) {
        let mut guard = self.state.write();
        for ((did, _), bucket) in &mut guard.buckets {
            if did == target_did && bucket.active_storm_id == Some(storm_id) {
                bucket.clear_storm();
            }
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
        let mut guard = self.state.write();
        let manual_active = guard
            .manual_storm_mode_until_us
            .get(target_did)
            .is_some_and(|&until| until > now_us);

        // Prefer exact focal_uri match when that bucket has an active storm.
        let exact_key = focal_uri.map(|u| (target_did.to_string(), u.to_string()));
        let exact_active = exact_key
            .as_ref()
            .and_then(|k| guard.buckets.get(k))
            .is_some_and(|b| b.has_active_storm(now_us));

        let chosen_key = if exact_active {
            exact_key
        } else {
            // Fall back to the most recently updated active storm bucket for target_did, if any.
            let active_fallback = guard
                .buckets
                .iter()
                .filter(|((did, _), b)| did == target_did && b.has_active_storm(now_us))
                .max_by_key(|(_, b)| b.last_activity_us)
                .map(|(k, _)| k.clone());

            match active_fallback {
                Some(k) => Some(k),
                None if manual_active => Some((
                    target_did.to_string(),
                    focal_uri
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("at://{target_did}/app.bsky.feed.post/_storm")),
                )),
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
            Self::evict_oldest_locked(&mut guard, medium_cutoff, now_us);
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
        let mut guard = self.state.write();
        let manual_map = guard.manual_storm_mode_until_us.clone();
        let mut out = Vec::new();

        for ((target_did, focal_uri), bucket) in &mut guard.buckets {
            if bucket.digest_bounced_count == 0 {
                continue;
            }
            let manual_active = manual_map
                .get(target_did)
                .is_some_and(|&until| until > now_us);
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
                    target_did: target_did.clone(),
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
        let mut expired = Vec::new();

        {
            let mut guard = self.state.write();
            guard
                .manual_storm_mode_until_us
                .retain(|_, &mut until| until > now_us);

            for ((target_did, focal_uri), bucket) in &mut guard.buckets {
                bucket.prune(medium_cutoff);
                if let Some(exp) = bucket.storm_expires_us {
                    if exp <= now_us {
                        if let Some(id) = bucket.active_storm_id {
                            expired.push((target_did.clone(), focal_uri.clone(), id));
                        }
                        bucket.clear_storm();
                    }
                }
            }

            for win in guard.defensive.values_mut() {
                win.prune(short_cutoff);
            }
            guard
                .defensive
                .retain(|_, win| !win.recent_blocks.is_empty() || !win.recent_detaches.is_empty());
        }

        let digests = self.drain_due_digests(now_us, true);

        {
            let mut guard = self.state.write();
            guard.buckets.retain(|_, bucket| {
                !bucket.events.is_empty()
                    || !bucket.eval_outcomes.is_empty()
                    || bucket.active_storm_id.is_some()
                    || bucket.digest_bounced_count > 0
            });
        }

        (expired, digests)
    }

    fn evict_oldest_locked(state: &mut TrackerState, medium_cutoff: u64, now_us: u64) {
        for bucket in state.buckets.values_mut() {
            bucket.prune(medium_cutoff);
        }
        state.buckets.retain(|_, b| {
            !b.events.is_empty() || b.active_storm_id.is_some() || b.digest_bounced_count > 0
        });
        if state.buckets.is_empty() {
            return;
        }
        let victim = state
            .buckets
            .iter()
            .filter(|(_, b)| !b.has_active_storm(now_us))
            .min_by_key(|(_, b)| b.last_activity_us)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                state
                    .buckets
                    .iter()
                    .min_by_key(|(_, b)| b.last_activity_us)
                    .map(|(k, _)| k.clone())
            });
        if let Some(key) = victim {
            state.buckets.remove(&key);
        }
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
        tracker.dismiss_storm("did:plc:bob", 7);
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
        assert!(tracker.state.read().buckets.len() <= 2);
    }
}
