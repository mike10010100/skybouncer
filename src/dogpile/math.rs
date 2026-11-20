//! Pure, zero-I/O cascade scoring and ratio functions for dogpile detection.
//!
//! Structured as stateless math helpers so both `skybouncer` and future network-wide
//! radar services (`skydoppler`) can share identical scoring primitives.

use crate::dogpile::types::{DogpileConfig, StormMetrics, StormSeverity, StormStanceVerdict};
use crate::matcher::{extract_did_for_collection, Interaction};

const POST_COLLECTION: &str = "app.bsky.feed.post";

/// Computes the direct engagement hostility/controversy ratio:
/// `(replies + quotes) / (likes + reposts + 1.0)`.
#[must_use]
pub fn compute_direct_ratio(replies: u64, quotes: u64, likes: u64, reposts: u64) -> f64 {
    let numerator = replies.saturating_add(quotes) as f64;
    let denominator = likes.saturating_add(reposts) as f64 + 1.0;
    numerator / denominator
}

/// Computes the quote-dunk amplification ratio:
/// `catalyst_likes / (root_likes + 1.0)`.
#[must_use]
pub fn compute_dunk_ratio(catalyst_likes: u64, root_likes: u64) -> f64 {
    catalyst_likes as f64 / (root_likes as f64 + 1.0)
}

/// Computes reach asymmetry between a catalyst author and the target user:
/// `catalyst_followers / (target_followers + 10.0)`, defaulting to `1.0` if either count is unknown.
#[must_use]
pub fn compute_power_asymmetry(
    catalyst_followers: Option<u64>,
    target_followers: Option<u64>,
) -> f64 {
    match (catalyst_followers, target_followers) {
        (Some(cat), Some(target)) => cat as f64 / (target as f64 + 10.0),
        _ => 1.0,
    }
}

/// Computes Poisson-normalized burst acceleration comparing `short_count` in `short_secs`
/// against the prior baseline rate observed across `(medium_secs - short_secs)`.
///
/// Returns a non-negative z-score (clamped `>= 0.0`).
#[must_use]
pub fn compute_burst_acceleration(
    short_count: usize,
    short_secs: f64,
    medium_count: usize,
    medium_secs: f64,
) -> f64 {
    if short_secs <= 0.0 || short_secs.is_nan() || medium_secs.is_nan() {
        return 0.0;
    }
    if medium_secs <= short_secs {
        return short_count as f64;
    }

    let prior_secs = medium_secs - short_secs;
    let prior_count = medium_count.saturating_sub(short_count);
    let min_rate = 1.0 / medium_secs;
    let rate_bg = (prior_count as f64 / prior_secs).max(min_rate);
    let expected_short = rate_bg * short_secs;
    let z = (short_count as f64 - expected_short) / expected_short.max(1.0).sqrt();
    if z.is_nan() || z < 0.0 {
        0.0
    } else {
        z
    }
}

/// Computes the structural cascade score in `[0.0, 1.0]` combining velocity,
/// out-of-network share, direct/dunk engagement ratios, violation/burst signal,
/// target defensive distress, and high-asymmetry dunk bonus.
#[must_use]
pub fn compute_structural_score(metrics: &StormMetrics, config: &DogpileConfig) -> f64 {
    let min_authors = (config.min_unique_authors.max(1) as f64) * 2.0;
    let vel_norm = (metrics.unique_oon_authors_short as f64 / min_authors).clamp(0.0, 1.0);
    let oon_norm = if metrics.out_of_network_ratio.is_nan() {
        0.0
    } else {
        metrics.out_of_network_ratio.clamp(0.0, 1.0)
    };
    let direct_norm = if metrics.direct_ratio.is_nan() {
        0.0
    } else {
        (metrics.direct_ratio / 2.0).clamp(0.0, 1.0)
    };
    let dunk_norm = if metrics.dunk_ratio.is_nan() {
        0.0
    } else {
        (metrics.dunk_ratio / 4.0).clamp(0.0, 1.0)
    };
    let ratio_signal = direct_norm.max(dunk_norm);

    let burst_norm = if metrics.burst_z_score.is_nan() {
        0.0
    } else {
        (metrics.burst_z_score / 6.0).clamp(0.0, 1.0)
    };
    let viol_norm = if metrics.violation_rate.is_nan() {
        0.0
    } else {
        metrics.violation_rate.clamp(0.0, 1.0)
    };
    let viol_or_burst = viol_norm.max(burst_norm * 0.85);

    let block_norm = (metrics.defensive_blocks as f64 / config.defensive_block_burst.max(1) as f64)
        .clamp(0.0, 1.0);
    let detach_norm = (metrics.defensive_detaches as f64
        / config.defensive_detach_burst.max(1) as f64)
        .clamp(0.0, 1.0);
    let defensive_norm = block_norm.max(detach_norm);

    let mut score = 0.28 * vel_norm
        + 0.18 * oon_norm
        + 0.22 * ratio_signal
        + 0.16 * viol_or_burst
        + 0.16 * defensive_norm;

    if !metrics.power_asymmetry.is_nan()
        && !metrics.dunk_ratio.is_nan()
        && metrics.power_asymmetry >= 5.0
        && metrics.dunk_ratio >= 2.0
    {
        let asym_bonus = ((metrics.power_asymmetry.log10() / 3.0) * 0.08).clamp(0.0, 0.08);
        score += asym_bonus;
    }

    score.clamp(0.0, 1.0)
}

/// Combines `structural_score` with an optional Stage 3 [`StormStanceVerdict`].
///
/// Benign viral surges (`collective_hostility == false`) are strongly attenuated
/// (`structural_score * (1.0 - 0.70 * confidence)`), while confirmed hostile bundles
/// blend structure and semantics (`0.45 * structural + 0.55 * confidence`).
/// Fallback verdicts (`evaluator == "structural_fallback"`) leave `structural_score` unchanged.
#[must_use]
pub fn compute_composite_score(structural_score: f64, stance: Option<&StormStanceVerdict>) -> f64 {
    let base = if structural_score.is_nan() {
        0.0
    } else {
        structural_score.clamp(0.0, 1.0)
    };

    match stance {
        Some(verdict) if verdict.evaluator != "structural_fallback" => {
            let conf = if verdict.confidence.is_nan() {
                0.0
            } else {
                verdict.confidence.clamp(0.0, 1.0)
            };
            if verdict.collective_hostility {
                (0.45 * base + 0.55 * conf).clamp(0.0, 1.0)
            } else {
                (base * (1.0 - 0.70 * conf)).clamp(0.0, 1.0)
            }
        }
        _ => base,
    }
}

/// Maps a composite confirmation score in `[0.0, 1.0]` to [`StormSeverity`].
#[must_use]
pub fn severity_from_score(score: f64) -> StormSeverity {
    if score.is_nan() {
        return StormSeverity::Elevated;
    }
    if score >= 0.90 {
        StormSeverity::Critical
    } else if score >= 0.75 {
        StormSeverity::High
    } else {
        StormSeverity::Elevated
    }
}

/// Extracts the canonical focal post AT-URI owned by `interaction.target_did`
/// for grouping replies, thread replies, quotes, and mentions into one storm bucket.
///
/// Precedence:
/// 1. `quote_uri` if owned by `target_did`
/// 2. `root_uri` if owned by `target_did`
/// 3. `parent_uri` if owned by `target_did`
/// 4. Synthetic `at://{target_did}/app.bsky.feed.post/_mentions` bucket
#[must_use]
pub fn canonical_focal_post_uri(interaction: &Interaction) -> String {
    let target = interaction.target_did.as_str();
    for candidate in [
        interaction.quote_uri.as_deref(),
        interaction.root_uri.as_deref(),
        interaction.parent_uri.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if extract_did_for_collection(candidate, POST_COLLECTION) == Some(target) {
            return candidate.to_string();
        }
    }
    format!("at://{target}/{POST_COLLECTION}/_mentions")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::InteractionType;

    #[test]
    fn ratios_and_power_asymmetry_behave_accurately() {
        // High reply+quote vs low likes/reposts => high direct ratio
        let dr = compute_direct_ratio(80, 20, 4, 0);
        assert!((dr - 20.0).abs() < 1e-9);
        assert!((compute_direct_ratio(0, 0, 0, 0)).abs() < 1e-9);

        // Dunk ratio: 1500 likes on QT vs 14 likes on target post => 100.0
        let dunk = compute_dunk_ratio(1500, 14);
        assert!((dunk - 100.0).abs() < 1e-9);

        // Power asymmetry: unknown defaults to 1.0
        assert!((compute_power_asymmetry(None, Some(100)) - 1.0).abs() < 1e-9);
        assert!((compute_power_asymmetry(Some(500), None) - 1.0).abs() < 1e-9);
        let asym = compute_power_asymmetry(Some(50_000), Some(90));
        assert!((asym - 500.0).abs() < 1e-9);
    }

    #[test]
    fn burst_acceleration_distinguishes_spikes_from_steady_traffic() {
        // Sudden 15 events in 300s after silent 25m baseline
        let spike = compute_burst_acceleration(15, 300.0, 15, 1800.0);
        assert!(spike > 10.0, "expected large z-score, got {spike}");

        // Steady 15 events every 5 minutes (90 across 30 minutes)
        let steady = compute_burst_acceleration(15, 300.0, 90, 1800.0);
        assert!(steady < 0.01, "expected ~0 z-score, got {steady}");

        // Edge cases
        assert_eq!(compute_burst_acceleration(5, 0.0, 10, 100.0), 0.0);
        assert_eq!(compute_burst_acceleration(5, f64::NAN, 10, 100.0), 0.0);
        assert_eq!(compute_burst_acceleration(5, 300.0, 10, 300.0), 5.0);
    }

    #[test]
    fn structural_and_composite_scoring_suppresses_benign_viral_and_confirms_dogpiles() {
        let cfg = DogpileConfig::default();

        // Scenario A: Hostile quote-dunk pile-on
        let dogpile_metrics = StormMetrics {
            unique_authors_short: 16,
            unique_oon_authors_short: 15,
            out_of_network_ratio: 0.94,
            direct_ratio: 3.2,
            dunk_ratio: 12.0,
            power_asymmetry: 50.0,
            violation_rate: 0.4,
            burst_z_score: 10.0,
            defensive_blocks: 0,
            defensive_detaches: 0,
            ..Default::default()
        };
        let struct_dogpile = compute_structural_score(&dogpile_metrics, &cfg);
        assert!(struct_dogpile >= cfg.structural_fallback_threshold);

        let hostile_stance = StormStanceVerdict::new(
            true,
            0.92,
            "dogpile",
            "Coordinated mockery from dunk QT",
            "ollama",
        );
        let composite_hostile = compute_composite_score(struct_dogpile, Some(&hostile_stance));
        assert!(composite_hostile >= cfg.confirmed_score_threshold);
        assert!(severity_from_score(composite_hostile) >= StormSeverity::High);

        // Scenario B: Benign viral meme ("post your pets")
        let benign_metrics = StormMetrics {
            unique_authors_short: 22,
            unique_oon_authors_short: 20,
            out_of_network_ratio: 0.91,
            direct_ratio: 0.08,
            dunk_ratio: 0.1,
            power_asymmetry: 1.0,
            violation_rate: 0.0,
            burst_z_score: 8.0,
            ..Default::default()
        };
        let struct_benign = compute_structural_score(&benign_metrics, &cfg);
        assert!(struct_benign >= cfg.structural_trigger_score);
        assert!(struct_benign < cfg.structural_fallback_threshold);

        let benign_stance = StormStanceVerdict::new(
            false,
            0.95,
            "benign_viral",
            "Enthusiastic pet photos",
            "ollama",
        );
        let composite_benign = compute_composite_score(struct_benign, Some(&benign_stance));
        assert!(composite_benign < 0.30);

        // Fallback leaves structural score untouched
        let fallback = StormStanceVerdict::new(
            false,
            0.0,
            "structural_only",
            "LLM offline",
            "structural_fallback",
        );
        assert!((compute_composite_score(0.77, Some(&fallback)) - 0.77).abs() < 1e-9);
        assert!((compute_composite_score(f64::NAN, None)).abs() < 1e-9);
        assert_eq!(severity_from_score(f64::NAN), StormSeverity::Elevated);
        assert_eq!(severity_from_score(0.91), StormSeverity::Critical);
        assert_eq!(severity_from_score(0.75), StormSeverity::High);
        assert_eq!(severity_from_score(0.65), StormSeverity::Elevated);
    }

    #[test]
    fn canonical_focal_post_uri_precedence() {
        let mut i = Interaction::new(
            "did:plc:attacker",
            "did:plc:alice",
            InteractionType::DirectReply,
            "at://did:plc:attacker/app.bsky.feed.post/reply1",
            "cid1",
            "bad take",
        )
        .with_parent_uri("at://did:plc:other/app.bsky.feed.post/other1")
        .with_root_uri("at://did:plc:alice/app.bsky.feed.post/root1")
        .with_quote_uri("at://did:plc:alice/app.bsky.feed.post/quoted1");

        assert_eq!(
            canonical_focal_post_uri(&i),
            "at://did:plc:alice/app.bsky.feed.post/quoted1"
        );

        i.quote_uri = Some("at://did:plc:other/app.bsky.feed.post/foreign".to_string());
        assert_eq!(
            canonical_focal_post_uri(&i),
            "at://did:plc:alice/app.bsky.feed.post/root1"
        );

        i.root_uri = None;
        i.parent_uri = Some("at://did:plc:alice/app.bsky.feed.post/parent1".to_string());
        assert_eq!(
            canonical_focal_post_uri(&i),
            "at://did:plc:alice/app.bsky.feed.post/parent1"
        );

        i.parent_uri = None;
        assert_eq!(
            canonical_focal_post_uri(&i),
            "at://did:plc:alice/app.bsky.feed.post/_mentions"
        );
    }
}
