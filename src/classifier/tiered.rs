//! Two-tier hierarchical moderation classifier with multimodal vision fallback.
//!
//! Coordinates a fast, lightweight System-1 primary classifier (e.g. Jev or local 1B/3B text model)
//! with an escalating multimodal System-2 fallback classifier (e.g. `gemma4:26b`, `llama3.2-vision`,
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

const fn default_true() -> bool {
    true
}

/// Configuration governing when primary evaluations escalate to the fallback model.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CertaintyConfig {
    /// Lower bound of the uncertainty band. Confidences below this are either uncertain or benign.
    pub min_confidence: f64,
    /// Upper bound of the uncertainty band. Confidences at or above this are considered decisive.
    pub max_confidence: f64,
    /// Whether to automatically escalate interactions with attached images to the multimodal model.
    pub escalate_on_images: bool,
    /// Whether nuanced interpersonal violation categories (`harassment`, `sea_lioning`,
    /// `hate_speech`, or custom rules) emitted by Tier-1 always escalate to Tier-2 for
    /// contextual verification before bouncing an account.
    #[serde(default = "default_true")]
    pub escalate_nuanced_violations: bool,
}

impl Default for CertaintyConfig {
    fn default() -> Self {
        Self {
            min_confidence: DEFAULT_UNCERTAINTY_MIN_CONFIDENCE,
            max_confidence: DEFAULT_UNCERTAINTY_MAX_CONFIDENCE,
            escalate_on_images: true,
            escalate_nuanced_violations: true,
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
            escalate_nuanced_violations: true,
        }
    }

    /// Overrides whether attached images trigger Tier-2 escalation.
    #[must_use]
    pub const fn with_escalate_on_images(mut self, escalate: bool) -> Self {
        self.escalate_on_images = escalate;
        self
    }

    /// Overrides whether nuanced interpersonal violations (`harassment`, `sea_lioning`,
    /// `hate_speech`, `custom`) always escalate to Tier-2 regardless of Tier-1 confidence.
    #[must_use]
    pub const fn with_escalate_nuanced_violations(mut self, escalate: bool) -> Self {
        self.escalate_nuanced_violations = escalate;
        self
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
        // Nuanced interpersonal violation categories require System-2 contextual verification
        // (target directionality, sarcasm, quoted-post context, thread referents) before
        // bouncing a human commenter, whereas automated spam/crypto/phishing resolve at Tier-1.
        if self.escalate_nuanced_violations {
            if let Verdict::Violation { category, .. } = primary_verdict {
                if category.is_nuanced_interpersonal() {
                    return true;
                }
            }
        }

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

/// Comprehensive multi-tier inspection result breakdown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TieredEvaluationResult {
    /// Initial verdict emitted by the primary Tier-1 System-1 classifier.
    pub primary_verdict: Verdict,
    /// Model name of the primary Tier-1 classifier.
    pub primary_model: String,
    /// Whether evaluation escalated to the secondary Tier-2 fallback classifier.
    pub escalated: bool,
    /// Detailed rationale explaining why escalation was triggered or bypassed.
    pub escalation_reason: Option<String>,
    /// Secondary verdict emitted by the fallback Tier-2 classifier, if escalated.
    pub fallback_verdict: Option<Verdict>,
    /// Model name of the secondary Tier-2 fallback classifier.
    pub fallback_model: Option<String>,
    /// Final arbitration verdict adopted by the engine.
    pub final_verdict: Verdict,
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
    primary: Arc<dyn Classifier + Send + Sync>,
    fallback: Arc<dyn Classifier + Send + Sync>,
    certainty: CertaintyConfig,
    context_enricher: Option<Arc<dyn crate::enricher::ContextEnricher>>,
    stats: Arc<TieredClassifierStats>,
}

impl TieredClassifier {
    /// Creates a new [`TieredClassifier`] pairing a primary and fallback classifier.
    #[must_use]
    pub fn new(
        primary: Arc<dyn Classifier + Send + Sync>,
        fallback: Arc<dyn Classifier + Send + Sync>,
        certainty: CertaintyConfig,
    ) -> Self {
        Self {
            primary,
            fallback,
            certainty,
            context_enricher: None,
            stats: Arc::new(TieredClassifierStats::default()),
        }
    }

    /// Attaches a [`ContextEnricher`](crate::enricher::ContextEnricher) so parent/quoted
    /// context image thumbnails can be lazily hydrated when Tier-1 escalates to System-2.
    #[must_use]
    pub fn with_context_enricher(
        mut self,
        enricher: Arc<dyn crate::enricher::ContextEnricher>,
    ) -> Self {
        self.context_enricher = Some(enricher);
        self
    }

    /// Returns a reference to the primary classifier.
    #[must_use]
    pub fn primary(&self) -> &Arc<dyn Classifier + Send + Sync> {
        &self.primary
    }

    /// Returns a reference to the fallback classifier.
    #[must_use]
    pub fn fallback(&self) -> &Arc<dyn Classifier + Send + Sync> {
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

    /// Evaluates an incoming candidate interaction with complete multi-tier inspection breakdown.
    ///
    /// # Arguments
    /// * `interaction` - The candidate ATProto post interaction to evaluate.
    /// * `record_stats` - When `true`, operational telemetry counters are incremented.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if classifier evaluation fails or times out.
    pub async fn evaluate_tiered(
        &self,
        interaction: &Interaction,
        record_stats: bool,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        self.evaluate_tiered_with_rubric(interaction, None, record_stats)
            .await
    }

    /// Evaluates an incoming candidate interaction with complete multi-tier inspection breakdown against a specific rubric.
    ///
    /// # Arguments
    /// * `interaction` - The candidate ATProto post interaction to evaluate.
    /// * `rubric` - Optional moderation rule rubric override.
    /// * `record_stats` - When `true`, operational telemetry counters are incremented.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if classifier evaluation fails or times out.
    pub async fn evaluate_tiered_with_rubric(
        &self,
        interaction: &Interaction,
        rubric: Option<&RuleRubric>,
        record_stats: bool,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        if record_stats {
            self.stats.total_evaluations.fetch_add(1, Ordering::Relaxed);
        }

        let effective_rubric = rubric.or(interaction.rubric.as_ref());

        // 1. Evaluate candidate using the fast primary System-1 classifier
        let primary_verdict = self
            .primary
            .classify_with_rubric(interaction, effective_rubric)
            .await?;
        let primary_model = self.primary.model_name().to_string();
        let fallback_model = Some(self.fallback.model_name().to_string());
        let has_images = interaction.has_images();

        // 2. Check escalation criteria
        if self.certainty.should_escalate(&primary_verdict, has_images) {
            if record_stats {
                self.stats
                    .fallback_escalated
                    .fetch_add(1, Ordering::Relaxed);
            }

            let (escalation_prefix, escalation_reason) = if has_images
                && self.certainty.escalate_on_images
            {
                if record_stats {
                    self.stats.image_escalations.fetch_add(1, Ordering::Relaxed);
                }
                debug!(
                    post_uri = %interaction.post_uri,
                    image_count = interaction.image_cids.len(),
                    "Escalating candidate to secondary multimodal classifier due to attached images"
                );
                (
                    "[Tiered Fallback: visual image]",
                    "Attached visual media requires multimodal inspection".to_string(),
                )
            } else {
                if record_stats {
                    self.stats
                        .uncertainty_escalations
                        .fetch_add(1, Ordering::Relaxed);
                }
                let conf = primary_verdict.confidence().unwrap_or(0.0);
                let reason = match &primary_verdict {
                    Verdict::Violation { category, .. }
                        if self.certainty.escalate_nuanced_violations
                            && category.is_nuanced_interpersonal()
                            && !self.certainty.is_uncertain(conf) =>
                    {
                        debug!(
                            post_uri = %interaction.post_uri,
                            category = %category,
                            confidence = conf,
                            "Escalating nuanced interpersonal Tier-1 violation to System-2 for verification"
                        );
                        format!(
                            "Nuanced interpersonal category '{}' ({:.2}) escalated for System-2 verification",
                            category.as_str(),
                            conf
                        )
                    }
                    _ => {
                        debug!(
                            post_uri = %interaction.post_uri,
                            confidence = ?primary_verdict.confidence(),
                            "Escalating candidate to secondary classifier due to uncertainty band"
                        );
                        format!(
                            "Confidence {:.2} in uncertainty band [{:.2}..{:.2})",
                            conf, self.certainty.min_confidence, self.certainty.max_confidence
                        )
                    }
                };
                ("[Tiered Fallback: uncertainty escalation]", reason)
            };

            // Lazily hydrate parent/quoted context thumbnails only after Tier-1 has already
            // escalated so benign replies never incur extra CDN fetches or vision cost.
            let mut hydrated_interaction: Option<Interaction> = None;
            if let (Some(ref enricher), Some(ref ctx)) =
                (&self.context_enricher, &interaction.enriched_context)
            {
                if ctx.context_images_base64.is_empty() && !ctx.context_image_refs.is_empty() {
                    let limit = crate::enricher::MAX_CONTEXT_IMAGES.min(
                        crate::enricher::MAX_POST_IMAGES.saturating_sub(ctx.images_base64.len()),
                    );
                    let mut fetched = Vec::with_capacity(limit);
                    for img_ref in ctx.context_image_refs.iter().take(limit) {
                        if let Some(b64) = enricher
                            .fetch_image_base64(&img_ref.author_did, &img_ref.cid)
                            .await
                        {
                            fetched.push(b64);
                        }
                    }
                    if !fetched.is_empty() {
                        let mut updated_ctx = ctx.clone();
                        updated_ctx.context_images_base64 = fetched;
                        hydrated_interaction =
                            Some(interaction.clone().with_enriched_context(updated_ctx));
                    }
                }
            }
            let fallback_interaction = hydrated_interaction.as_ref().unwrap_or(interaction);

            // 3. Evaluate candidate with the heavier System-2 fallback model
            let fallback_raw = self
                .fallback
                .classify_with_rubric(fallback_interaction, effective_rubric)
                .await?;
            let final_verdict = match fallback_raw.clone() {
                Verdict::Violation {
                    category,
                    confidence,
                    reason,
                } => Verdict::violation(
                    category,
                    confidence,
                    format!("{escalation_prefix} {reason}"),
                ),
                Verdict::Permitted { reason, confidence } => {
                    let formatted = format!("{escalation_prefix} {reason}");
                    if let Some(c) = confidence {
                        Verdict::permitted_with_confidence(formatted, c)
                    } else {
                        Verdict::permitted(formatted)
                    }
                }
            };

            Ok(TieredEvaluationResult {
                primary_verdict,
                primary_model,
                escalated: true,
                escalation_reason: Some(escalation_reason),
                fallback_verdict: Some(fallback_raw),
                fallback_model,
                final_verdict,
            })
        } else {
            // Decisive result: resolved directly by primary classifier
            if record_stats {
                self.stats.primary_resolved.fetch_add(1, Ordering::Relaxed);
            }
            let reason = if has_images {
                "Decisive high-confidence violation on text alone (multimodal inspection bypassed)"
            } else {
                "Decisive confidence outside uncertainty band (System-2 escalation bypassed)"
            };
            Ok(TieredEvaluationResult {
                primary_verdict: primary_verdict.clone(),
                primary_model,
                escalated: false,
                escalation_reason: Some(reason.to_string()),
                fallback_verdict: None,
                fallback_model,
                final_verdict: primary_verdict,
            })
        }
    }
}

#[async_trait]
impl Classifier for TieredClassifier {
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        self.classify_with_rubric(interaction, interaction.rubric.as_ref())
            .await
    }

    async fn classify_with_rubric(
        &self,
        interaction: &Interaction,
        rubric: Option<&RuleRubric>,
    ) -> Result<Verdict, SkybouncerError> {
        let result = self
            .evaluate_tiered_with_rubric(interaction, rubric, true)
            .await?;
        Ok(result.final_verdict)
    }

    fn model_name(&self) -> &str {
        "tiered"
    }

    async fn classify_detailed(
        &self,
        interaction: &Interaction,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        self.evaluate_tiered_with_rubric(interaction, interaction.rubric.as_ref(), false)
            .await
    }

    async fn classify_detailed_with_rubric(
        &self,
        interaction: &Interaction,
        rubric: Option<&RuleRubric>,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        self.evaluate_tiered_with_rubric(interaction, rubric, false)
            .await
    }

    async fn classify_detailed_with_stats(
        &self,
        interaction: &Interaction,
        record_stats: bool,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        self.evaluate_tiered_with_rubric(interaction, interaction.rubric.as_ref(), record_stats)
            .await
    }

    async fn classify_detailed_with_stats_and_rubric(
        &self,
        interaction: &Interaction,
        rubric: Option<&RuleRubric>,
        record_stats: bool,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        self.evaluate_tiered_with_rubric(interaction, rubric, record_stats)
            .await
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

    #[test]
    fn certainty_config_nan_clamp_and_uncertain() {
        // NaN inputs fall back to safe bounds and min<=max is enforced.
        let c = CertaintyConfig::new(f64::NAN, f64::NAN, true);
        assert_eq!(c.min_confidence, 0.0);
        assert_eq!(c.max_confidence, 1.0);
        // Inverted bounds are ordered.
        let c = CertaintyConfig::new(0.9, 0.2, false);
        assert!(c.min_confidence <= c.max_confidence);
        // Uncertainty band is [min, max); NaN is uncertain.
        assert!(c.is_uncertain(f64::NAN));
        assert!(c.is_uncertain(0.5));
        assert!(!c.is_uncertain(1.0));
    }

    #[test]
    fn certainty_should_escalate_matrix() {
        let c = CertaintyConfig::new(0.4, 0.85, true);
        // Decisive high-confidence violation with images does NOT escalate.
        let decisive = Verdict::violation(ViolationCategory::Spam, 0.95, "clear");
        assert!(!c.should_escalate(&decisive, true));
        // Lower-confidence violation with images escalates.
        let borderline = Verdict::violation(ViolationCategory::Spam, 0.5, "maybe");
        assert!(c.should_escalate(&borderline, true));
        // Permitted with no confidence + no images does not escalate.
        let permitted = Verdict::permitted("ok");
        assert!(!c.should_escalate(&permitted, false));
        // Uncertainty-band confidence without images escalates.
        let uncertain = Verdict::permitted_with_confidence("hmm", 0.6);
        assert!(c.should_escalate(&uncertain, false));
    }

    #[tokio::test]
    async fn tiered_accessors_and_detailed_methods() {
        let primary = Arc::new(MockClassifier::new(Verdict::permitted("ok")));
        let fallback = Arc::new(MockClassifier::new(Verdict::permitted("fb")));
        let certainty = CertaintyConfig::default();
        let tiered = TieredClassifier::new(primary, fallback, certainty);

        let _ = tiered.primary();
        let _ = tiered.fallback();
        let _ = tiered.certainty();
        let _ = tiered.stats();
        assert_eq!(tiered.model_name(), "tiered");

        let i = Interaction::mock_test_candidate("did:plc:a", "did:plc:t", "hi");
        assert!(tiered.classify(&i).await.is_ok());
        assert!(tiered.classify_with_rubric(&i, None).await.is_ok());
        assert!(tiered.classify_detailed(&i).await.is_ok());
        assert!(tiered.classify_detailed_with_rubric(&i, None).await.is_ok());
        assert!(tiered.classify_detailed_with_stats(&i, false).await.is_ok());
        assert!(tiered
            .classify_detailed_with_stats_and_rubric(&i, None, false)
            .await
            .is_ok());
        let _ = tiered.evaluate_tiered(&i, false).await;
        tiered.set_rubric(RuleRubric::default());
    }
}
