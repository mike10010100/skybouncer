//! Core data structures and configuration for dogpile detection and Storm Mode.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::SkybouncerError;
use crate::matcher::InteractionType;

/// Configuration governing rolling-window surge tracking, structural scoring,
/// LLM batch stance verification, alert cooldowns, and Storm Mode digesting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DogpileConfig {
    /// Whether real-time dogpile detection is enabled.
    pub enabled: bool,
    /// Short rolling window duration for burst detection (default: 300s / 5 minutes).
    pub short_window: Duration,
    /// Medium rolling baseline window duration (default: 1800s / 30 minutes).
    pub medium_window: Duration,
    /// Minimum distinct interaction authors in `short_window` to trigger Stage 2 enrichment.
    pub min_unique_authors: usize,
    /// Minimum fraction of out-of-network authors (`[0.0, 1.0]`) to qualify as an external surge.
    pub min_out_of_network_ratio: f64,
    /// Minimum interval before re-emitting an alert for the same focal post unless severity escalates.
    pub alert_cooldown: Duration,
    /// Default Storm Mode duration after a confirmed storm update or manual toggle.
    pub storm_mode_ttl: Duration,
    /// Interval at which Storm Mode bounce digests are flushed via DM.
    pub digest_interval: Duration,
    /// Maximum number of `(target_did, focal_post_uri)` buckets kept in memory.
    pub max_tracked_posts: usize,
    /// Maximum out-of-network sample replies retained per focal post for batch stance verification.
    pub max_sample_replies: usize,
    /// Number of target defensive blocks within `short_window` that signals user distress.
    pub defensive_block_burst: usize,
    /// Number of target postgate QT detaches / disables within `short_window` that signals user distress.
    pub defensive_detach_burst: usize,
    /// Whether to run Stage 3 bundled LLM stance verification on Stage 2 candidates.
    pub enable_llm_stance: bool,
    /// Minimum `structural_score` required before invoking Stage 3 LLM stance verification.
    pub structural_trigger_score: f64,
    /// Confirmation score threshold used when LLM stance verification is unavailable or disabled.
    pub structural_fallback_threshold: f64,
    /// Minimum `composite_score` required to confirm a storm when Stage 3 LLM stance succeeds.
    pub confirmed_score_threshold: f64,
    /// Minimum interval between Stage 2 re-evaluations for the same focal post URI.
    pub eval_recheck_interval: Duration,
}

impl Default for DogpileConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            short_window: Duration::from_secs(300),
            medium_window: Duration::from_secs(1800),
            min_unique_authors: 10,
            min_out_of_network_ratio: 0.70,
            alert_cooldown: Duration::from_secs(1800),
            storm_mode_ttl: Duration::from_secs(1800),
            digest_interval: Duration::from_secs(300),
            max_tracked_posts: 2048,
            max_sample_replies: 15,
            defensive_block_burst: 5,
            defensive_detach_burst: 2,
            enable_llm_stance: true,
            structural_trigger_score: 0.55,
            structural_fallback_threshold: 0.70,
            confirmed_score_threshold: 0.65,
            eval_recheck_interval: Duration::from_secs(60),
        }
    }
}

fn sanitize_finite_unit(val: f64, default: f64) -> f64 {
    if val.is_finite() {
        val.clamp(0.0, 1.0)
    } else {
        default
    }
}

impl DogpileConfig {
    /// Loads dogpile detection parameters from `SKYBOUNCER_DOGPILE_*` / `DOGPILE_*`
    /// environment variables, falling back to [`Self::default`].
    #[must_use]
    pub fn from_env() -> Self {
        let d = Self::default();
        let short_secs = crate::env::parsed_or(
            &[
                "SKYBOUNCER_DOGPILE_SHORT_WINDOW_SECS",
                "DOGPILE_SHORT_WINDOW_SECS",
            ],
            d.short_window.as_secs(),
        )
        .max(10);
        let medium_secs = crate::env::parsed_or(
            &[
                "SKYBOUNCER_DOGPILE_MEDIUM_WINDOW_SECS",
                "DOGPILE_MEDIUM_WINDOW_SECS",
            ],
            d.medium_window.as_secs(),
        )
        .max(short_secs);
        let alert_cooldown_secs = crate::env::parsed_or(
            &[
                "SKYBOUNCER_DOGPILE_ALERT_COOLDOWN_SECS",
                "DOGPILE_ALERT_COOLDOWN_SECS",
            ],
            d.alert_cooldown.as_secs(),
        );
        let storm_ttl_secs = crate::env::parsed_or(
            &[
                "SKYBOUNCER_DOGPILE_STORM_MODE_TTL_SECS",
                "DOGPILE_STORM_MODE_TTL_SECS",
            ],
            d.storm_mode_ttl.as_secs(),
        )
        .max(30);
        let digest_secs = crate::env::parsed_or(
            &[
                "SKYBOUNCER_DOGPILE_DIGEST_INTERVAL_SECS",
                "DOGPILE_DIGEST_INTERVAL_SECS",
            ],
            d.digest_interval.as_secs(),
        )
        .max(10);
        let recheck_secs = crate::env::parsed_or(
            &[
                "SKYBOUNCER_DOGPILE_EVAL_RECHECK_INTERVAL_SECS",
                "DOGPILE_EVAL_RECHECK_INTERVAL_SECS",
            ],
            d.eval_recheck_interval.as_secs(),
        )
        .max(5);

        Self {
            enabled: crate::env::bool_or(
                &["SKYBOUNCER_DOGPILE_ENABLED", "DOGPILE_ENABLED"],
                d.enabled,
            ),
            short_window: Duration::from_secs(short_secs),
            medium_window: Duration::from_secs(medium_secs),
            min_unique_authors: crate::env::parsed_or(
                &[
                    "SKYBOUNCER_DOGPILE_MIN_UNIQUE_AUTHORS",
                    "DOGPILE_MIN_UNIQUE_AUTHORS",
                ],
                d.min_unique_authors,
            )
            .max(2),
            min_out_of_network_ratio: sanitize_finite_unit(
                crate::env::parsed_or(
                    &[
                        "SKYBOUNCER_DOGPILE_MIN_OON_RATIO",
                        "SKYBOUNCER_DOGPILE_MIN_OUT_OF_NETWORK_RATIO",
                        "DOGPILE_MIN_OON_RATIO",
                    ],
                    d.min_out_of_network_ratio,
                ),
                d.min_out_of_network_ratio,
            ),
            alert_cooldown: Duration::from_secs(alert_cooldown_secs),
            storm_mode_ttl: Duration::from_secs(storm_ttl_secs),
            digest_interval: Duration::from_secs(digest_secs),
            max_tracked_posts: crate::env::parsed_or(
                &[
                    "SKYBOUNCER_DOGPILE_MAX_TRACKED_POSTS",
                    "DOGPILE_MAX_TRACKED_POSTS",
                ],
                d.max_tracked_posts,
            )
            .max(16),
            max_sample_replies: crate::env::parsed_or(
                &[
                    "SKYBOUNCER_DOGPILE_MAX_SAMPLE_REPLIES",
                    "DOGPILE_MAX_SAMPLE_REPLIES",
                ],
                d.max_sample_replies,
            )
            .clamp(1, 50),
            defensive_block_burst: crate::env::parsed_or(
                &[
                    "SKYBOUNCER_DOGPILE_DEFENSIVE_BLOCK_BURST",
                    "DOGPILE_DEFENSIVE_BLOCK_BURST",
                ],
                d.defensive_block_burst,
            )
            .max(1),
            defensive_detach_burst: crate::env::parsed_or(
                &[
                    "SKYBOUNCER_DOGPILE_DEFENSIVE_DETACH_BURST",
                    "DOGPILE_DEFENSIVE_DETACH_BURST",
                ],
                d.defensive_detach_burst,
            )
            .max(1),
            enable_llm_stance: crate::env::bool_or(
                &[
                    "SKYBOUNCER_DOGPILE_ENABLE_LLM_STANCE",
                    "DOGPILE_ENABLE_LLM_STANCE",
                ],
                d.enable_llm_stance,
            ),
            structural_trigger_score: sanitize_finite_unit(
                crate::env::parsed_or(
                    &[
                        "SKYBOUNCER_DOGPILE_STRUCTURAL_TRIGGER_SCORE",
                        "DOGPILE_STRUCTURAL_TRIGGER_SCORE",
                    ],
                    d.structural_trigger_score,
                ),
                d.structural_trigger_score,
            ),
            structural_fallback_threshold: sanitize_finite_unit(
                crate::env::parsed_or(
                    &[
                        "SKYBOUNCER_DOGPILE_STRUCTURAL_FALLBACK_THRESHOLD",
                        "DOGPILE_STRUCTURAL_FALLBACK_THRESHOLD",
                    ],
                    d.structural_fallback_threshold,
                ),
                d.structural_fallback_threshold,
            ),
            confirmed_score_threshold: sanitize_finite_unit(
                crate::env::parsed_or(
                    &[
                        "SKYBOUNCER_DOGPILE_CONFIRMED_SCORE_THRESHOLD",
                        "DOGPILE_CONFIRMED_SCORE_THRESHOLD",
                    ],
                    d.confirmed_score_threshold,
                ),
                d.confirmed_score_threshold,
            ),
            eval_recheck_interval: Duration::from_secs(recheck_secs),
        }
    }

    /// Enables or disables real-time dogpile detection.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets the short rolling burst window.
    #[must_use]
    pub fn with_short_window(mut self, window: Duration) -> Self {
        self.short_window = window.max(Duration::from_secs(1));
        self
    }

    /// Sets the medium rolling baseline window.
    #[must_use]
    pub fn with_medium_window(mut self, window: Duration) -> Self {
        self.medium_window = window.max(self.short_window);
        self
    }

    /// Sets the minimum unique author count required to trigger Stage 2 enrichment.
    #[must_use]
    pub fn with_min_unique_authors(mut self, min_authors: usize) -> Self {
        self.min_unique_authors = min_authors.max(1);
        self
    }

    /// Sets the minimum out-of-network author fraction in `[0.0, 1.0]`.
    #[must_use]
    pub fn with_min_out_of_network_ratio(mut self, ratio: f64) -> Self {
        self.min_out_of_network_ratio = if ratio.is_nan() {
            0.0
        } else {
            ratio.clamp(0.0, 1.0)
        };
        self
    }

    /// Sets the cooldown before re-alerting on the same focal post without escalation.
    #[must_use]
    pub fn with_alert_cooldown(mut self, cooldown: Duration) -> Self {
        self.alert_cooldown = cooldown;
        self
    }

    /// Sets the Storm Mode TTL duration.
    #[must_use]
    pub fn with_storm_mode_ttl(mut self, ttl: Duration) -> Self {
        self.storm_mode_ttl = ttl.max(Duration::from_secs(1));
        self
    }

    /// Sets the digest emission interval for Storm Mode bounce summaries.
    #[must_use]
    pub fn with_digest_interval(mut self, interval: Duration) -> Self {
        self.digest_interval = interval.max(Duration::from_secs(1));
        self
    }

    /// Sets the maximum number of tracked `(target, focal_post)` buckets in memory.
    #[must_use]
    pub fn with_max_tracked_posts(mut self, cap: usize) -> Self {
        self.max_tracked_posts = cap.max(1);
        self
    }

    /// Sets the maximum sample replies retained per focal post for stance checks.
    #[must_use]
    pub fn with_max_sample_replies(mut self, max_samples: usize) -> Self {
        self.max_sample_replies = max_samples.max(1);
        self
    }

    /// Sets the defensive block count threshold within `short_window`.
    #[must_use]
    pub fn with_defensive_block_burst(mut self, threshold: usize) -> Self {
        self.defensive_block_burst = threshold.max(1);
        self
    }

    /// Sets the defensive postgate detach/disable burst threshold within `short_window`.
    #[must_use]
    pub fn with_defensive_detach_burst(mut self, threshold: usize) -> Self {
        self.defensive_detach_burst = threshold.max(1);
        self
    }

    /// Enables or disables Stage 3 bundled LLM stance verification.
    #[must_use]
    pub fn with_enable_llm_stance(mut self, enabled: bool) -> Self {
        self.enable_llm_stance = enabled;
        self
    }

    /// Sets the minimum structural score required to invoke Stage 3 LLM stance verification.
    #[must_use]
    pub fn with_structural_trigger_score(mut self, score: f64) -> Self {
        self.structural_trigger_score = if score.is_nan() {
            0.0
        } else {
            score.clamp(0.0, 1.0)
        };
        self
    }

    /// Sets the structural-only confirmation threshold when LLM stance is unavailable.
    #[must_use]
    pub fn with_structural_fallback_threshold(mut self, score: f64) -> Self {
        self.structural_fallback_threshold = if score.is_nan() {
            0.0
        } else {
            score.clamp(0.0, 1.0)
        };
        self
    }

    /// Sets the composite confirmation score threshold when LLM stance is available.
    #[must_use]
    pub fn with_confirmed_score_threshold(mut self, score: f64) -> Self {
        self.confirmed_score_threshold = if score.is_nan() {
            0.0
        } else {
            score.clamp(0.0, 1.0)
        };
        self
    }

    /// Sets the minimum interval between Stage 2 evaluations on the same focal post.
    #[must_use]
    pub fn with_eval_recheck_interval(mut self, interval: Duration) -> Self {
        self.eval_recheck_interval = interval;
        self
    }
}

/// Severity level assigned to a detected dogpile storm.
///
/// Ordered from lowest (`Elevated`) to highest (`Critical`) to support escalation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StormSeverity {
    /// Moderate surge crossing confirmation threshold (`composite_score >= 0.65`).
    Elevated,
    /// Severe surge (`composite_score >= 0.75`).
    High,
    /// Extreme cascade or high-asymmetry swarm (`composite_score >= 0.90`).
    Critical,
}

impl StormSeverity {
    /// Returns the static lowercase string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for StormSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for StormSeverity {
    type Err = SkybouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "elevated" => Ok(Self::Elevated),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(SkybouncerError::Config(format!(
                "Invalid storm severity '{other}'; expected 'elevated', 'high', or 'critical'"
            ))),
        }
    }
}

/// Lifecycle state of a persisted dogpile storm event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StormStatus {
    /// Storm is currently ongoing.
    Active,
    /// Storm subsided and expired naturally after `storm_mode_ttl`.
    Resolved,
    /// Storm was manually dismissed by the user or administrator.
    Dismissed,
}

impl StormStatus {
    /// Returns the static lowercase string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Resolved => "resolved",
            Self::Dismissed => "dismissed",
        }
    }
}

impl fmt::Display for StormStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for StormStatus {
    type Err = SkybouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "resolved" => Ok(Self::Resolved),
            "dismissed" => Ok(Self::Dismissed),
            other => Err(SkybouncerError::Config(format!(
                "Invalid storm status '{other}'; expected 'active', 'resolved', or 'dismissed'"
            ))),
        }
    }
}

/// Engagement snapshot for a single Bluesky post returned by `app.bsky.feed.getPosts`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PostEngagementSnapshot {
    /// Canonical AT-URI of the post.
    pub uri: String,
    /// Author DID of the post.
    pub author_did: String,
    /// Author handle, if present in the AppView post view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_handle: Option<String>,
    /// Author follower count, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_followers: Option<u64>,
    /// Plaintext body of the post.
    #[serde(default)]
    pub text: String,
    /// Total reply count reported by AppView.
    #[serde(default)]
    pub reply_count: u64,
    /// Total repost count reported by AppView.
    #[serde(default)]
    pub repost_count: u64,
    /// Total like count reported by AppView.
    #[serde(default)]
    pub like_count: u64,
    /// Total quote count reported by AppView.
    #[serde(default)]
    pub quote_count: u64,
}

/// Identifying details for the top amplifying quote-post catalyst driving a storm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalystInfo {
    /// Canonical AT-URI of the catalyst quote-post.
    pub post_uri: String,
    /// Author DID of the catalyst quote-post.
    pub author_did: String,
    /// Author handle of the catalyst quote-post, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_handle: Option<String>,
    /// Follower count of the catalyst author, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_followers: Option<u64>,
    /// Like count on the catalyst quote-post.
    pub like_count: u64,
    /// Repost count on the catalyst quote-post.
    pub repost_count: u64,
    /// Quote count on the catalyst quote-post.
    pub quote_count: u64,
    /// Ratio of catalyst likes to `(root_likes + 1)`.
    pub dunk_ratio: f64,
    /// Truncated text snippet of the catalyst quote-post.
    pub text_snippet: String,
}

/// Aggregate Stage 3 stance verdict evaluating a surge bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StormStanceVerdict {
    /// Whether the sampled crowd response is collectively hostile/mocking/norm-enforcing against Target.
    pub collective_hostility: bool,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Classification label (`"dogpile"`, `"heated_debate"`, `"benign_viral"`, etc.).
    pub classification: String,
    /// Concise summary explaining the crowd reaction.
    pub summary: String,
    /// Evaluator identifier (model name or `"structural_fallback"`).
    pub evaluator: String,
}

impl StormStanceVerdict {
    /// Constructs a [`StormStanceVerdict`], sanitizing `confidence` into `[0.0, 1.0]`.
    #[must_use]
    pub fn new(
        collective_hostility: bool,
        confidence: f64,
        classification: impl Into<String>,
        summary: impl Into<String>,
        evaluator: impl Into<String>,
    ) -> Self {
        let sanitized = if confidence.is_nan() {
            0.0
        } else {
            confidence.clamp(0.0, 1.0)
        };
        Self {
            collective_hostility,
            confidence: sanitized,
            classification: classification.into(),
            summary: summary.into(),
            evaluator: evaluator.into(),
        }
    }
}

/// Quantitative cascade, ratio, and defensive distress metrics for a focal post.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct StormMetrics {
    /// Distinct interaction authors within `short_window`.
    pub unique_authors_short: usize,
    /// Distinct out-of-network interaction authors within `short_window`.
    pub unique_oon_authors_short: usize,
    /// Replies (direct + thread) observed in `short_window`.
    pub reply_count_short: usize,
    /// Quote posts observed in `short_window`.
    pub quote_count_short: usize,
    /// Mentions observed in `short_window`.
    pub mention_count_short: usize,
    /// Fraction of unique authors in `short_window` outside Target's follow/follower graph.
    pub out_of_network_ratio: f64,
    /// Ratio `(replies + quotes) / (likes + reposts + 1.0)` on the focal post.
    pub direct_ratio: f64,
    /// Maximum `catalyst_likes / (root_likes + 1.0)` across recent quote posts.
    pub dunk_ratio: f64,
    /// Ratio `catalyst_followers / (target_followers + 10.0)` (defaults to `1.0` if unknown).
    pub power_asymmetry: f64,
    /// Rolling violation rate among evaluated interactions on this focal post (`[0.0, 1.0]`).
    pub violation_rate: f64,
    /// Poisson-normalized burst acceleration comparing `short_window` against `medium_window`.
    pub burst_z_score: f64,
    /// Number of target defensive `app.bsky.graph.block` records observed in `short_window`.
    pub defensive_blocks: usize,
    /// Number of target `app.bsky.feed.postgate` detach/disable actions observed in `short_window`.
    pub defensive_detaches: usize,
    /// Structural score computed from velocity, OON share, ratios, burst, and distress (`[0.0, 1.0]`).
    pub structural_score: f64,
    /// Final composite score combining `structural_score` and Stage 3 LLM stance (`[0.0, 1.0]`).
    pub composite_score: f64,
}

/// A sampled out-of-network interaction retained for Stage 3 batch stance verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleReply {
    /// Author DID of the sampled interaction.
    pub author_did: String,
    /// Vector by which the interaction reached the target.
    pub interaction_type: InteractionType,
    /// Canonical AT-URI of the interaction post.
    pub post_uri: String,
    /// Truncated plaintext snippet of the interaction post.
    pub text_snippet: String,
}

/// Stage 1 snapshot emitted when a focal post crosses velocity or distress thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurgeCandidate {
    /// Protected target DID experiencing the surge.
    pub target_did: String,
    /// Canonical AT-URI of the focal post (or synthetic `_mentions` bucket URI).
    pub focal_post_uri: String,
    /// Microsecond Unix timestamp of the triggering interaction.
    pub observed_at_us: u64,
    /// Initial Stage 1 structural metrics prior to AppView enrichment and LLM stance check.
    pub initial_metrics: StormMetrics,
    /// Bounded sample of out-of-network replies/quotes targeting this focal post.
    pub sample_replies: Vec<SampleReply>,
    /// Recent quote-post AT-URIs referencing `focal_post_uri`.
    pub recent_quote_uris: Vec<String>,
}

/// Persisted dogpile storm event surfaced in DM alerts, `/api/storms`, and the UI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StormEvent {
    /// Database row identifier (`0` before persistence).
    pub id: i64,
    /// Protected target DID.
    pub target_did: String,
    /// Resolved handle of the protected target user, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_handle: Option<String>,
    /// Canonical AT-URI of the focal post being dogpiled.
    pub focal_post_uri: String,
    /// Truncated snippet of the focal post body.
    pub focal_post_snippet: String,
    /// Current lifecycle status (`Active`, `Resolved`, or `Dismissed`).
    pub status: StormStatus,
    /// Severity tier (`Elevated`, `High`, or `Critical`).
    pub severity: StormSeverity,
    /// Microsecond Unix timestamp when the storm was first confirmed.
    pub started_at_us: u64,
    /// Microsecond Unix timestamp of the latest storm update.
    pub updated_at_us: u64,
    /// Microsecond Unix timestamp when the storm was resolved or dismissed, if closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at_us: Option<u64>,
    /// Latest computed cascade metrics.
    pub metrics: StormMetrics,
    /// Highest-amplification quote-post catalyst identified during enrichment, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_catalyst: Option<CatalystInfo>,
    /// All known catalyst quote-post AT-URIs ranked by engagement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub catalyst_qt_uris: Vec<String>,
    /// Stage 3 batch stance verdict, if evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stance: Option<StormStanceVerdict>,
    /// Total violators bounced during this storm.
    pub bounces_during_storm: u64,
    /// Whether an `app.bsky.feed.threadgate` was applied to this focal post via Skybouncer.
    pub threadgate_applied: bool,
    /// Number of quote-post URIs detached via `app.bsky.feed.postgate` through Skybouncer.
    pub postgate_detaches_applied: u64,
}

/// Broadcast notification emitted when a storm is detected or escalates in severity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StormNotification {
    /// The confirmed or escalated [`StormEvent`].
    pub storm: StormEvent,
    /// `true` if this notification represents an escalation of an already-active storm.
    pub is_escalation: bool,
}

/// Summary of a single bounced account included inside a Storm Mode DM digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestBounceSummary {
    /// DID of the bounced violator.
    pub violator_did: String,
    /// Resolved handle of the bounced violator, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violator_handle: Option<String>,
    /// Violation category slug.
    pub category: String,
}

/// Periodic Storm Mode summary notification replacing individual bounce DMs during a surge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StormDigestNotification {
    /// Protected target DID receiving the digest.
    pub target_did: String,
    /// Focal post AT-URI associated with the digested bounces.
    pub focal_post_uri: String,
    /// Total accounts bounced during this digest interval.
    pub bounced_count: u64,
    /// Representative sample of bounced accounts (capped for concise DMs).
    pub sample_violators: Vec<DigestBounceSummary>,
    /// Elapsed window duration in seconds covered by this digest.
    pub window_secs: u64,
    /// Whether Storm Mode remains active after this digest emission.
    pub storm_still_active: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn config_builders_and_from_env_clamping() {
        let cfg = DogpileConfig::default()
            .with_enabled(false)
            .with_short_window(Duration::from_secs(120))
            .with_medium_window(Duration::from_secs(600))
            .with_min_unique_authors(12)
            .with_min_out_of_network_ratio(0.85)
            .with_alert_cooldown(Duration::from_secs(900))
            .with_storm_mode_ttl(Duration::from_secs(1200))
            .with_digest_interval(Duration::from_secs(180))
            .with_max_tracked_posts(512)
            .with_max_sample_replies(10)
            .with_defensive_block_burst(3)
            .with_defensive_detach_burst(2)
            .with_enable_llm_stance(false)
            .with_structural_trigger_score(0.5)
            .with_structural_fallback_threshold(0.75)
            .with_confirmed_score_threshold(0.66)
            .with_eval_recheck_interval(Duration::from_secs(30));

        assert!(!cfg.enabled);
        assert_eq!(cfg.short_window, Duration::from_secs(120));
        assert_eq!(cfg.medium_window, Duration::from_secs(600));
        assert_eq!(cfg.min_unique_authors, 12);
        assert!((cfg.min_out_of_network_ratio - 0.85).abs() < 1e-9);
        assert_eq!(cfg.alert_cooldown, Duration::from_secs(900));
        assert_eq!(cfg.storm_mode_ttl, Duration::from_secs(1200));
        assert_eq!(cfg.digest_interval, Duration::from_secs(180));
        assert_eq!(cfg.max_tracked_posts, 512);
        assert_eq!(cfg.max_sample_replies, 10);
        assert_eq!(cfg.defensive_block_burst, 3);
        assert_eq!(cfg.defensive_detach_burst, 2);
        assert!(!cfg.enable_llm_stance);
        assert!((cfg.structural_trigger_score - 0.5).abs() < 1e-9);
        assert!((cfg.structural_fallback_threshold - 0.75).abs() < 1e-9);
        assert!((cfg.confirmed_score_threshold - 0.66).abs() < 1e-9);
        assert_eq!(cfg.eval_recheck_interval, Duration::from_secs(30));

        // NaN clamping paths
        let nan_cfg = DogpileConfig::default()
            .with_min_out_of_network_ratio(f64::NAN)
            .with_structural_trigger_score(f64::NAN)
            .with_structural_fallback_threshold(f64::NAN)
            .with_confirmed_score_threshold(f64::NAN);
        assert_eq!(nan_cfg.min_out_of_network_ratio, 0.0);
        assert_eq!(nan_cfg.structural_trigger_score, 0.0);
        assert_eq!(nan_cfg.structural_fallback_threshold, 0.0);
        assert_eq!(nan_cfg.confirmed_score_threshold, 0.0);

        let env_cfg = DogpileConfig::from_env();
        assert!(env_cfg.short_window >= Duration::from_secs(10));

        assert_eq!(sanitize_finite_unit(f64::NAN, 0.72), 0.72);
        assert_eq!(sanitize_finite_unit(f64::INFINITY, 0.72), 0.72);
        assert_eq!(sanitize_finite_unit(f64::NEG_INFINITY, 0.72), 0.72);
        assert_eq!(sanitize_finite_unit(-0.3, 0.72), 0.0);
        assert_eq!(sanitize_finite_unit(1.8, 0.72), 1.0);
        assert!((sanitize_finite_unit(0.65, 0.72) - 0.65).abs() < f64::EPSILON);
    }

    #[test]
    fn severity_and_status_parsing_ordering_and_verdict_clamp() {
        assert!(StormSeverity::Elevated < StormSeverity::High);
        assert!(StormSeverity::High < StormSeverity::Critical);
        assert_eq!(StormSeverity::Elevated.to_string(), "elevated");
        assert_eq!(StormSeverity::High.to_string(), "high");
        assert_eq!(StormSeverity::Critical.to_string(), "critical");
        assert_eq!(
            "CRITICAL".parse::<StormSeverity>().unwrap(),
            StormSeverity::Critical
        );
        assert!("invalid".parse::<StormSeverity>().is_err());

        assert_eq!(StormStatus::Active.to_string(), "active");
        assert_eq!(StormStatus::Resolved.to_string(), "resolved");
        assert_eq!(StormStatus::Dismissed.to_string(), "dismissed");
        assert_eq!(
            "Resolved".parse::<StormStatus>().unwrap(),
            StormStatus::Resolved
        );
        assert_eq!(
            "dismissed".parse::<StormStatus>().unwrap(),
            StormStatus::Dismissed
        );
        assert!("unknown".parse::<StormStatus>().is_err());

        let v_nan = StormStanceVerdict::new(true, f64::NAN, "dogpile", "sum", "m");
        assert_eq!(v_nan.confidence, 0.0);
        let v_hi = StormStanceVerdict::new(false, 4.2, "benign_viral", "sum", "m");
        assert_eq!(v_hi.confidence, 1.0);
    }
}
