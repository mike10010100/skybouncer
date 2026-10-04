//! Two-tier hierarchical moderation classifier with multimodal vision fallback.
//!
//! Coordinates a fast, lightweight System-1 primary classifier (e.g. Jev or local 1B/3B text model)
//! with an escalating multimodal System-2 fallback classifier (e.g. `gemma4:12b`, `llama3.2-vision`,
//! or `qwen2.5-vl`).
//!
//! # Escalation Invariants
//! Escalation to the secondary classifier is triggered when either:
//! 1. **Uncertainty Band**: The primary classifier's confidence score falls in the configured
//!    uncertainty zone (e.g. `0.40 <= confidence < 0.85`), indicating ambiguous or borderline content.
//! 2. **Visual Presence**: The candidate interaction contains attached images (`interaction.has_images()`),
//!    and the text alone was not already an unambiguous high-confidence violation (`confidence >= max_confidence`).
//!
//! If neither condition is met (e.g. decisive text-only violation or clearly benign text with no images),
//! the primary classifier's verdict resolves immediately in <40ms without invoking the heavier vision model.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::classifier::{Classifier, RuleRubric, Verdict};
use crate::error::SkybouncerError;
use crate::matcher::Interaction;

/// Default lower bound for the classifier uncertainty band (0.40).
pub const DEFAULT_UNCERTAINTY_MIN_CONFIDENCE: f64 = 0.40;

/// Default upper bound for the classifier uncertainty band (0.85).
pub const DEFAULT_UNCERTAINTY_MAX_CONFIDENCE: f64 = 0.85;

/// Configuration governing when primary evaluations escalate to the fallback model.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CertaintyConfig {
    /// Lower bound of the uncertainty band. Confidences below this are either uncertain or benign.
    pub min_confidence: f64,
    /// Upper bound of the uncertainty band. Confidences at or above this are considered decisive.
    pub max_confidence: f64,
    /// Whether to automatically escalate interactions with attached images to the multimodal model.
    pub escalate_on_images: bool,
}

impl Default for CertaintyConfig {
    fn default() -> Self {
        Self {
            min_confidence: DEFAULT_UNCERTAINTY_MIN_CONFIDENCE,
            max_confidence: DEFAULT_UNCERTAINTY_MAX_CONFIDENCE,
            escalate_on_images: true,
        }
    }
}

impl CertaintyConfig {
    /// Creates a new [`CertaintyConfig`] with specified bounds and image escalation behavior.
    #[must_use]
    pub fn new(min_confidence: f64, max_confidence: f64, escalate_on_images: bool) -> Self {
        let min = if min_confidence.is_nan() {
            0.0
        } else {
            min_confidence.clamp(0.0, 1.0)
        };
        let max = if max_confidence.is_nan() {
            1.0
        } else {
            max_confidence.clamp(0.0, 1.0)
        };
        Self {
            min_confidence: min.min(max),
            max_confidence: max.max(min),
            escalate_on_images,
        }
    }

    /// Evaluates whether a raw confidence score falls inside the uncertainty band.
    #[must_use]
    pub fn is_uncertain(&self, confidence: f64) -> bool {
        if confidence.is_nan() {
            return true;
        }
        confidence >= self.min_confidence && confidence < self.max_confidence
    }

    /// Determines whether a primary verdict should escalate to the secondary fallback classifier.
    #[must_use]
    pub fn should_escalate(&self, primary_verdict: &Verdict, has_images: bool) -> bool {
        // If candidate post contains attached images and escalation on images is enabled:
        if self.escalate_on_images && has_images {
            // If primary verdict was already a decisive, high-confidence violation on text alone,
            // we do NOT need to escalate to the vision model (saves GPU cycles and latency).
            if let Verdict::Violation { confidence, .. } = primary_verdict {
                if *confidence >= self.max_confidence {
                    return false;
                }
            }
            return true;
        }

        // Uncertainty band escalation:
        match primary_verdict.confidence() {
            Some(conf) => self.is_uncertain(conf),
            None => false,
        }
    }
}

/// Operational telemetry counters for [`TieredClassifier`].
#[derive(Debug, Default)]
pub struct TieredClassifierStats {
    /// Total evaluations received by the tiered classifier.
    pub total_evaluations: AtomicU64,
    /// Evaluations resolved definitively by the primary classifier.
    pub primary_resolved: AtomicU64,
    /// Evaluations escalated to the fallback classifier.
    pub fallback_escalated: AtomicU64,
    /// Escalations triggered by the presence of attached visual images.
    pub image_escalations: AtomicU64,
    /// Escalations triggered by confidence falling in the uncertainty band.
    pub uncertainty_escalations: AtomicU64,
}

impl TieredClassifierStats {
    /// Captures an immutable snapshot of all tiered classifier counters.
    #[must_use]
    pub fn snapshot(&self) -> TieredStatsSnapshot {
        TieredStatsSnapshot {
            total_evaluations: self.total_evaluations.load(Ordering::Relaxed),
            primary_resolved: self.primary_resolved.load(Ordering::Relaxed),
            fallback_escalated: self.fallback_escalated.load(Ordering::Relaxed),
            image_escalations: self.image_escalations.load(Ordering::Relaxed),
            uncertainty_escalations: self.uncertainty_escalations.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time immutable snapshot of [`TieredClassifierStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TieredStatsSnapshot {
    /// Total evaluations received.
    pub total_evaluations: u64,
    /// Evaluations resolved definitively by the primary classifier.
    pub primary_resolved: u64,
    /// Evaluations escalated to the fallback classifier.
    pub fallback_escalated: u64,
    /// Escalations triggered by the presence of attached visual images.
    pub image_escalations: u64,
    /// Escalations triggered by confidence falling in the uncertainty band.
    pub uncertainty_escalations: u64,
}

/// Two-tier moderation classifier combining a fast primary System-1 classifier
/// with an escalating multimodal System-2 fallback classifier.
#[derive(Clone)]
pub struct TieredClassifier {
    primary: Arc<dyn Classifier>,
    fallback: Arc<dyn Classifier>,
    certainty: CertaintyConfig,
    stats: Arc<TieredClassifierStats>,
}

impl TieredClassifier {
    /// Creates a new [`TieredClassifier`] pairing a primary and fallback classifier.
    #[must_use]
    pub fn new(
        primary: Arc<dyn Classifier>,
        fallback: Arc<dyn Classifier>,
        certainty: CertaintyConfig,
    ) -> Self {
        Self {
            primary,
            fallback,
            certainty,
            stats: Arc::new(TieredClassifierStats::default()),
        }
    }

    /// Returns a reference to the primary classifier.
    #[must_use]
    pub fn primary(&self) -> &Arc<dyn Classifier> {
        &self.primary
    }

    /// Returns a reference to the fallback classifier.
    #[must_use]
    pub fn fallback(&self) -> &Arc<dyn Classifier> {
        &self.fallback
    }

    /// Returns the active [`CertaintyConfig`].
    #[must_use]
    pub fn certainty(&self) -> &CertaintyConfig {
        &self.certainty
    }

    /// Returns the operational statistics tracker.
    #[must_use]
    pub fn stats(&self) -> &Arc<TieredClassifierStats> {
        &self.stats
    }
}

#[async_trait]
impl Classifier for TieredClassifier {
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        self.stats.total_evaluations.fetch_add(1, Ordering::Relaxed);

        // 1. Evaluate candidate using the fast primary System-1 classifier
        let primary_verdict = self.primary.classify(interaction).await?;

        let has_images = interaction.has_images();

        // 2. Check escalation criteria
        if self.certainty.should_escalate(&primary_verdict, has_images) {
            self.stats
                .fallback_escalated
                .fetch_add(1, Ordering::Relaxed);

            if has_images {
                self.stats.image_escalations.fetch_add(1, Ordering::Relaxed);
                debug!(
                    post_uri = %interaction.post_uri,
                    image_count = interaction.image_cids.len(),
                    "Escalating candidate to secondary multimodal classifier due to attached images"
                );
            } else {
                self.stats
                    .uncertainty_escalations
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    post_uri = %interaction.post_uri,
                    confidence = ?primary_verdict.confidence(),
                    "Escalating candidate to secondary classifier due to uncertainty band"
                );
            }

            let escalation_prefix = if has_images {
                "[Tiered Fallback: visual image]"
            } else {
                "[Tiered Fallback: uncertainty escalation]"
            };

            // 3. Evaluate candidate with the heavier System-2 fallback model
            match self.fallback.classify(interaction).await? {
                Verdict::Violation {
                    category,
                    confidence,
                    reason,
                } => Ok(Verdict::violation(
                    category,
                    confidence,
                    format!("{escalation_prefix} {reason}"),
                )),
                Verdict::Permitted { reason, confidence } => {
                    let formatted = format!("{escalation_prefix} {reason}");
                    if let Some(c) = confidence {
                        Ok(Verdict::permitted_with_confidence(formatted, c))
                    } else {
                        Ok(Verdict::permitted(formatted))
                    }
                }
            }
        } else {
            // Decisive result: resolved directly by primary classifier
            self.stats.primary_resolved.fetch_add(1, Ordering::Relaxed);
            Ok(primary_verdict)
        }
    }

    fn set_rubric(&self, rubric: RuleRubric) {
        self.primary.set_rubric(rubric.clone());
        self.fallback.set_rubric(rubric);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::classifier::{MockClassifier, ViolationCategory};

    #[tokio::test]
    async fn test_tiered_classifier_decisive_violation_skips_fallback() {
        let primary = Arc::new(MockClassifier::violation(
            ViolationCategory::CryptoSpam,
            0.98,
            "Blatant crypto scam",
        ));
        let fallback = Arc::new(MockClassifier::permitted());
        let certainty = CertaintyConfig::default();

        let tiered = TieredClassifier::new(primary.clone(), fallback.clone(), certainty);

        let mut interaction = Interaction::mock_test_candidate(
            "did:plc:spammer",
            "did:plc:victim",
            "Free crypto airdrop now!",
        );
        interaction.image_cids = vec!["bafkimg1".to_string()];

        let verdict = tiered.classify(&interaction).await.unwrap();
        assert!(verdict.is_violation());
        assert_eq!(verdict.confidence(), Some(0.98));

        assert_eq!(primary.call_count(), 1);
        assert_eq!(fallback.call_count(), 0);
        assert_eq!(tiered.stats().primary_resolved.load(Ordering::Relaxed), 1);
        assert_eq!(tiered.stats().fallback_escalated.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_tiered_classifier_uncertainty_escalates_to_fallback() {
        // Primary returns uncertain violation (confidence 0.65 in [0.40, 0.85))
        let primary = Arc::new(MockClassifier::violation(
            ViolationCategory::Harassment,
            0.65,
            "Borderline comment",
        ));
        // Fallback determines it is permitted
        let fallback = Arc::new(MockClassifier::new(Verdict::permitted(
            "Fallback verified: benign banter",
        )));
        let certainty = CertaintyConfig::default();

        let tiered = TieredClassifier::new(primary.clone(), fallback.clone(), certainty);
        let interaction = Interaction::mock_test_candidate(
            "did:plc:user1",
            "did:plc:user2",
            "You are ridiculous lol",
        );

        let verdict = tiered.classify(&interaction).await.unwrap();
        assert!(verdict.is_permitted());
        assert!(verdict
            .reason()
            .contains("Fallback verified: benign banter"));

        assert_eq!(primary.call_count(), 1);
        assert_eq!(fallback.call_count(), 1);
        assert_eq!(
            tiered
                .stats()
                .uncertainty_escalations
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_tiered_classifier_images_escalate_to_fallback() {
        // Primary text classifier says text is benign
        let primary = Arc::new(MockClassifier::new(Verdict::permitted(
            "Text appears innocent",
        )));
        // Fallback vision classifier spots visual abuse in the image
        let fallback = Arc::new(MockClassifier::violation(
            ViolationCategory::CryptoSpam,
            0.92,
            "Image contains QR code for malicious crypto wallet drainer",
        ));
        let certainty = CertaintyConfig::default();

        let tiered = TieredClassifier::new(primary.clone(), fallback.clone(), certainty);

        let mut interaction = Interaction::mock_test_candidate(
            "did:plc:scammer",
            "did:plc:victim",
            "Look at this cool picture!",
        );
        interaction.image_cids = vec!["bafkqrcode".to_string()];

        let verdict = tiered.classify(&interaction).await.unwrap();
        assert!(verdict.is_violation());
        assert_eq!(verdict.category(), Some(&ViolationCategory::CryptoSpam));
        assert_eq!(verdict.confidence(), Some(0.92));

        assert_eq!(primary.call_count(), 1);
        assert_eq!(fallback.call_count(), 1);
        assert_eq!(tiered.stats().image_escalations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_tiered_classifier_benign_text_no_images_resolves_primary() {
        // High confidence benign text, no images
        let primary = Arc::new(MockClassifier::new(Verdict::permitted_with_confidence(
            "Friendly greeting",
            0.99,
        )));
        let fallback = Arc::new(MockClassifier::permitted());
        let certainty = CertaintyConfig::default();

        let tiered = TieredClassifier::new(primary.clone(), fallback.clone(), certainty);
        let interaction =
            Interaction::mock_test_candidate("did:plc:alice", "did:plc:bob", "Good morning!");

        let verdict = tiered.classify(&interaction).await.unwrap();
        assert!(verdict.is_permitted());
        assert_eq!(primary.call_count(), 1);
        assert_eq!(fallback.call_count(), 0);
        assert_eq!(tiered.stats().primary_resolved.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_tiered_classifier_set_rubric_propagates_both() {
        let primary = Arc::new(MockClassifier::permitted());
        let fallback = Arc::new(MockClassifier::permitted());
        let tiered = TieredClassifier::new(
            primary.clone(),
            fallback.clone(),
            CertaintyConfig::default(),
        );

        let new_rubric = RuleRubric::new("New policy", crate::classifier::Sensitivity::High);
        tiered.set_rubric(new_rubric.clone());

        assert_eq!(primary.rubric(), Some(new_rubric.clone()));
        assert_eq!(fallback.rubric(), Some(new_rubric));
    }
}
