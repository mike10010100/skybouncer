//! Dynamically-routed primary System-1 classifier.
//!
//! [`DynamicPrimaryClassifier`] chooses between a text-only fast primary and a
//! multimodal primary on a per-interaction basis. Interactions carrying attached
//! images are routed to the multimodal model (e.g. `clef-flash`) so that visual
//! content is inspected by the lightweight Tier-1 evaluator instead of being
//! pushed straight into the heavier Tier-2 fallback. Text-only interactions keep
//! the cheapest, fastest primary.
//!
//! This is distinct from [`crate::classifier::TieredClassifier`]: the tiered
//! classifier picks a *single* primary for all inputs and only escalates to a
//! secondary tier. Here the Tier-1 model itself is swapped before evaluation,
//! with no second inference call.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::classifier::{Classifier, RuleRubric, Verdict};
use crate::error::SkybouncerError;
use crate::matcher::Interaction;

/// Default text-only primary model identifier.
pub const DEFAULT_TEXT_ONLY_PRIMARY_MODEL: &str = "nimble";

/// Default multimodal primary model identifier.
pub const DEFAULT_MULTIMODAL_PRIMARY_MODEL: &str = "clef-flash";

/// Policy governing which Tier-1 primary model is selected per interaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DynamicModelPolicy {
    /// Model used for interactions without attached images.
    pub text_only_model: String,
    /// Model used for interactions carrying attached images.
    pub multimodal_model: String,
    /// Whether interactions with images are routed to the multimodal model.
    ///
    /// When `false`, all interactions use the text-only model and image handling
    /// is left to the downstream tiered fallback.
    pub escalate_on_images: bool,
    /// Whether a decisive high-confidence text violation bypasses the multimodal model.
    ///
    /// Mirrors [`crate::classifier::CertaintyConfig`] image escalation semantics: a
    /// confident violation on text alone does not need visual inspection, saving
    /// vision-model compute.
    pub bypass_decisive_text_violation: bool,
    /// Confidence at or above which a text violation is considered decisive.
    pub decisive_confidence: f64,
}

impl Default for DynamicModelPolicy {
    fn default() -> Self {
        Self {
            text_only_model: DEFAULT_TEXT_ONLY_PRIMARY_MODEL.to_string(),
            multimodal_model: DEFAULT_MULTIMODAL_PRIMARY_MODEL.to_string(),
            escalate_on_images: true,
            bypass_decisive_text_violation: true,
            decisive_confidence: crate::classifier::DEFAULT_UNCERTAINTY_MAX_CONFIDENCE,
        }
    }
}

impl DynamicModelPolicy {
    /// Creates a policy with explicit model names and image-routing behavior.
    #[must_use]
    pub fn new(
        text_only_model: impl Into<String>,
        multimodal_model: impl Into<String>,
        escalate_on_images: bool,
    ) -> Self {
        Self {
            text_only_model: text_only_model.into(),
            multimodal_model: multimodal_model.into(),
            escalate_on_images,
            ..Self::default()
        }
    }

    /// Returns `true` if an interaction with `has_images` should use the multimodal model,
    /// optionally accounting for an already-decisive text violation verdict.
    #[must_use]
    pub fn should_route_to_multimodal(
        &self,
        has_images: bool,
        primary_verdict: Option<&Verdict>,
    ) -> bool {
        if !self.escalate_on_images || !has_images {
            return false;
        }
        if self.bypass_decisive_text_violation {
            if let Some(Verdict::Violation { confidence, .. }) = primary_verdict {
                if *confidence >= self.decisive_confidence {
                    return false;
                }
            }
        }
        true
    }

    /// Returns the model identifier selected for an interaction with the given image presence.
    #[must_use]
    pub fn select_model(&self, has_images: bool) -> &str {
        if self.should_route_to_multimodal(has_images, None) {
            &self.multimodal_model
        } else {
            &self.text_only_model
        }
    }
}

/// Operational counters for [`DynamicPrimaryClassifier`].
#[derive(Debug, Default)]
pub struct DynamicPrimaryStats {
    /// Interactions routed to the text-only primary.
    pub text_routed: AtomicU64,
    /// Interactions routed to the multimodal primary.
    pub multimodal_routed: AtomicU64,
}

impl DynamicPrimaryStats {
    /// Captures an immutable snapshot of the routing counters.
    #[must_use]
    pub fn snapshot(&self) -> DynamicPrimaryStatsSnapshot {
        DynamicPrimaryStatsSnapshot {
            text_routed: self.text_routed.load(Ordering::Relaxed),
            multimodal_routed: self.multimodal_routed.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of [`DynamicPrimaryStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DynamicPrimaryStatsSnapshot {
    /// Interactions routed to the text-only primary.
    pub text_routed: u64,
    /// Interactions routed to the multimodal primary.
    pub multimodal_routed: u64,
}

/// A primary classifier that swaps its underlying Tier-1 model based on interaction content.
#[derive(Clone)]
pub struct DynamicPrimaryClassifier {
    text_only: Arc<dyn Classifier + Send + Sync>,
    multimodal: Arc<dyn Classifier + Send + Sync>,
    policy: DynamicModelPolicy,
    stats: Arc<DynamicPrimaryStats>,
}

impl DynamicPrimaryClassifier {
    /// Creates a new dynamically-routed primary classifier.
    #[must_use]
    pub fn new(
        text_only: Arc<dyn Classifier + Send + Sync>,
        multimodal: Arc<dyn Classifier + Send + Sync>,
        policy: DynamicModelPolicy,
    ) -> Self {
        Self {
            text_only,
            multimodal,
            policy,
            stats: Arc::new(DynamicPrimaryStats::default()),
        }
    }

    /// Returns a reference to the text-only primary classifier.
    #[must_use]
    pub fn text_only(&self) -> &Arc<dyn Classifier + Send + Sync> {
        &self.text_only
    }

    /// Returns a reference to the multimodal primary classifier.
    #[must_use]
    pub fn multimodal(&self) -> &Arc<dyn Classifier + Send + Sync> {
        &self.multimodal
    }

    /// Returns the active [`DynamicModelPolicy`].
    #[must_use]
    pub fn policy(&self) -> &DynamicModelPolicy {
        &self.policy
    }

    /// Returns the routing statistics tracker.
    #[must_use]
    pub fn stats(&self) -> &Arc<DynamicPrimaryStats> {
        &self.stats
    }

    /// Selects the concrete classifier for an interaction and records routing telemetry.
    fn route(&self, interaction: &Interaction) -> (&Arc<dyn Classifier + Send + Sync>, &str) {
        if self
            .policy
            .should_route_to_multimodal(interaction.has_images(), None)
        {
            self.stats.multimodal_routed.fetch_add(1, Ordering::Relaxed);
            (&self.multimodal, self.policy.multimodal_model.as_str())
        } else {
            self.stats.text_routed.fetch_add(1, Ordering::Relaxed);
            (&self.text_only, self.policy.text_only_model.as_str())
        }
    }

    /// Records the routing counters without invoking a model (used by dry-run simulations).
    pub fn record_routing(&self, interaction: &Interaction) {
        let _ = self.route(interaction);
    }
}

#[async_trait]
impl Classifier for DynamicPrimaryClassifier {
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        self.classify_with_rubric(interaction, interaction.rubric.as_ref())
            .await
    }

    async fn classify_with_rubric(
        &self,
        interaction: &Interaction,
        rubric: Option<&RuleRubric>,
    ) -> Result<Verdict, SkybouncerError> {
        let (classifier, _model) = self.route(interaction);
        classifier.classify_with_rubric(interaction, rubric).await
    }

    fn model_name(&self) -> &str {
        self.text_only.model_name()
    }

    fn set_rubric(&self, rubric: RuleRubric) {
        self.text_only.set_rubric(rubric.clone());
        self.multimodal.set_rubric(rubric);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::classifier::{MockClassifier, ViolationCategory};

    fn image_interaction() -> Interaction {
        let mut i = Interaction::mock_test_candidate("did:plc:author", "did:plc:target", "look");
        i.image_cids = vec!["bafkimg".to_string()];
        i
    }

    #[tokio::test]
    async fn routes_images_to_multimodal_and_text_to_text_only() {
        let text = Arc::new(MockClassifier::permitted());
        let mm = Arc::new(MockClassifier::violation(
            ViolationCategory::CryptoSpam,
            0.95,
            "image contains wallet drainer",
        ));
        let dynamic =
            DynamicPrimaryClassifier::new(text.clone(), mm.clone(), DynamicModelPolicy::default());

        let text_interaction =
            Interaction::mock_test_candidate("did:plc:a", "did:plc:t", "hello world");
        let v1 = dynamic.classify(&text_interaction).await.unwrap();
        assert!(v1.is_permitted());
        assert_eq!(text.call_count(), 1);
        assert_eq!(mm.call_count(), 0);

        let v2 = dynamic.classify(&image_interaction()).await.unwrap();
        assert!(v2.is_violation());
        assert_eq!(mm.call_count(), 1);

        let snap = dynamic.stats().snapshot();
        assert_eq!(snap.text_routed, 1);
        assert_eq!(snap.multimodal_routed, 1);
    }

    #[tokio::test]
    async fn image_routing_disabled_uses_text_only() {
        let text = Arc::new(MockClassifier::permitted());
        let mm = Arc::new(MockClassifier::permitted());
        let policy = DynamicModelPolicy::new("nimble", "clef-flash", false);
        let dynamic = DynamicPrimaryClassifier::new(text.clone(), mm.clone(), policy);

        let _ = dynamic.classify(&image_interaction()).await.unwrap();
        assert_eq!(text.call_count(), 1);
        assert_eq!(mm.call_count(), 0);
    }

    #[test]
    fn decisive_text_violation_bypasses_multimodal() {
        let policy = DynamicModelPolicy::default();
        let decisive = Verdict::violation(ViolationCategory::Spam, 0.99, "clear");
        assert!(!policy.should_route_to_multimodal(true, Some(&decisive)));
        let borderline = Verdict::violation(ViolationCategory::Spam, 0.5, "maybe");
        assert!(policy.should_route_to_multimodal(true, Some(&borderline)));
        assert!(!policy.should_route_to_multimodal(false, None));
        assert_eq!(policy.select_model(false), "nimble");
        assert_eq!(policy.select_model(true), "clef-flash");
    }

    #[tokio::test]
    async fn rubric_propagates_to_both_primaries() {
        let text = Arc::new(MockClassifier::permitted());
        let mm = Arc::new(MockClassifier::permitted());
        let dynamic =
            DynamicPrimaryClassifier::new(text.clone(), mm.clone(), DynamicModelPolicy::default());
        let rubric = RuleRubric::new("no spam", crate::classifier::Sensitivity::High);
        dynamic.set_rubric(rubric.clone());
        assert_eq!(text.rubric(), Some(rubric.clone()));
        assert_eq!(mm.rubric(), Some(rubric));
        let _ = dynamic.text_only();
        let _ = dynamic.multimodal();
        let _ = dynamic.policy();
        let _ = dynamic.stats();
    }
}
