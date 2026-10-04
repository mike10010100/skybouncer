//! Pluggable classifier engine, verdict data models, and rule rubric definitions.

use crate::error::SkybouncerError;
use crate::matcher::Interaction;
use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

pub mod heuristic;
pub mod jev;
pub mod mock;
pub mod rubric;
pub mod tiered;

pub use heuristic::{HeuristicClassifier, HeuristicRule};
pub use jev::{JevClassifier, JevConfig, JevEndpointKind};
pub use mock::MockClassifier;
pub use rubric::{RuleRubric, Sensitivity};
pub use tiered::{
    CertaintyConfig, TieredClassifier, TieredClassifierStats, TieredEvaluationResult,
    TieredStatsSnapshot,
};

/// Category classification for house rule violations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ViolationCategory {
    /// Unsolicited commercial spam, token promotion, or bot spam.
    Spam,
    /// Crypto giveaways, airdrop lures, wallet drains.
    CryptoSpam,
    /// Targeted harassment, intimidation, or persistent abuse.
    Harassment,
    /// Bad-faith sea-lioning and conversational derailment.
    SeaLioning,
    /// Phishing or malicious redirection links.
    Phishing,
    /// Hate speech or banned slurs.
    HateSpeech,
    /// Custom user-defined rule category.
    Custom(String),
}

impl ViolationCategory {
    /// Returns the static string representation of standard categories, or the inner custom string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Spam => "spam",
            Self::CryptoSpam => "crypto_spam",
            Self::Harassment => "harassment",
            Self::SeaLioning => "sea_lioning",
            Self::Phishing => "phishing",
            Self::HateSpeech => "hate_speech",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parses a category from a string slug, mapping unrecognized slugs to [`ViolationCategory::Custom`].
    #[must_use]
    pub fn from_slug(slug: &str) -> Self {
        match slug.trim().to_ascii_lowercase().as_str() {
            "spam" => Self::Spam,
            "crypto_spam" | "crypto" | "cryptospam" => Self::CryptoSpam,
            "harassment" => Self::Harassment,
            "sea_lioning" | "sealioning" => Self::SeaLioning,
            "phishing" => Self::Phishing,
            "hate_speech" | "hatespeech" => Self::HateSpeech,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for ViolationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ViolationCategory {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_slug(s))
    }
}

impl Serialize for ViolationCategory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ViolationCategory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_slug(&s))
    }
}

/// Structured verdict returned by a moderation classifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Verdict {
    /// Interaction violates moderation rules and meets confidence threshold.
    Violation {
        /// Categorization of the violation.
        category: ViolationCategory,
        /// Confidence score between 0.0 and 1.0.
        confidence: f64,
        /// Rationale or explanation for the decision.
        reason: String,
    },
    /// Interaction is permitted / benign.
    Permitted {
        /// Rationale why the interaction is permitted.
        reason: String,
        /// Optional confidence score between 0.0 and 1.0.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<f64>,
    },
}

impl Verdict {
    /// Constructs a new [`Verdict::Violation`], clamping confidence to `0.0..=1.0`.
    #[must_use]
    pub fn violation(
        category: ViolationCategory,
        confidence: f64,
        reason: impl Into<String>,
    ) -> Self {
        let sanitized = if confidence.is_nan() {
            0.0
        } else {
            confidence.clamp(0.0, 1.0)
        };
        Self::Violation {
            category,
            confidence: sanitized,
            reason: reason.into(),
        }
    }

    /// Constructs a new [`Verdict::Permitted`] with the given rationale.
    #[must_use]
    pub fn permitted(reason: impl Into<String>) -> Self {
        Self::Permitted {
            reason: reason.into(),
            confidence: None,
        }
    }

    /// Constructs a new [`Verdict::Permitted`] with the given rationale and confidence score.
    #[must_use]
    pub fn permitted_with_confidence(reason: impl Into<String>, confidence: f64) -> Self {
        let sanitized = if confidence.is_nan() {
            0.0
        } else {
            confidence.clamp(0.0, 1.0)
        };
        Self::Permitted {
            reason: reason.into(),
            confidence: Some(sanitized),
        }
    }

    /// Returns `true` if the verdict is a [`Verdict::Violation`].
    #[must_use]
    pub fn is_violation(&self) -> bool {
        matches!(self, Self::Violation { .. })
    }

    /// Returns `true` if the verdict is a [`Verdict::Permitted`].
    #[must_use]
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permitted { .. })
    }

    /// Returns the confidence score if available.
    #[must_use]
    pub fn confidence(&self) -> Option<f64> {
        match self {
            Self::Violation { confidence, .. } => Some(*confidence),
            Self::Permitted { confidence, .. } => *confidence,
        }
    }

    /// Returns the rationale string explaining the decision.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Violation { reason, .. } | Self::Permitted { reason, .. } => reason.as_str(),
        }
    }

    /// Returns the violation category if a violation occurred, or `None` if permitted.
    #[must_use]
    pub fn category(&self) -> Option<&ViolationCategory> {
        match self {
            Self::Violation { category, .. } => Some(category),
            Self::Permitted { .. } => None,
        }
    }
}

/// Pluggable asynchronous classification engine interface for ATProto interactions.
#[async_trait]
pub trait Classifier: Send + Sync {
    /// Classifies an incoming candidate interaction against moderation rules.
    ///
    /// # Errors
    ///
    /// Returns [`SkybouncerError`] if external API evaluation fails or times out.
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError>;

    /// Returns the model identifier or name for this classifier.
    fn model_name(&self) -> &str {
        "model"
    }

    /// Returns detailed multi-tier inspection breakdown if this classifier performs tiered evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`SkybouncerError`] if underlying model evaluation fails.
    async fn classify_detailed(
        &self,
        interaction: &Interaction,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        self.classify_detailed_with_stats(interaction, false).await
    }

    /// Returns detailed multi-tier inspection breakdown, optionally updating operational telemetry.
    ///
    /// # Errors
    ///
    /// Returns [`SkybouncerError`] if underlying model evaluation fails.
    async fn classify_detailed_with_stats(
        &self,
        interaction: &Interaction,
        _record_stats: bool,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        let verdict = self.classify(interaction).await?;
        Ok(TieredEvaluationResult {
            primary_verdict: verdict.clone(),
            primary_model: self.model_name().to_string(),
            escalated: false,
            escalation_reason: Some("Single-tier standalone classifier configured".to_string()),
            fallback_verdict: None,
            fallback_model: None,
            final_verdict: verdict,
        })
    }

    /// Dynamically updates the active moderation rubric across the classifier.
    fn set_rubric(&self, _rubric: RuleRubric) {}
}

#[async_trait]
impl<T: Classifier + ?Sized> Classifier for std::sync::Arc<T> {
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        (**self).classify(interaction).await
    }

    fn model_name(&self) -> &str {
        (**self).model_name()
    }

    async fn classify_detailed(
        &self,
        interaction: &Interaction,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        (**self).classify_detailed(interaction).await
    }

    async fn classify_detailed_with_stats(
        &self,
        interaction: &Interaction,
        record_stats: bool,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        (**self)
            .classify_detailed_with_stats(interaction, record_stats)
            .await
    }

    fn set_rubric(&self, rubric: RuleRubric) {
        (**self).set_rubric(rubric);
    }
}

#[async_trait]
impl<T: Classifier + ?Sized> Classifier for Box<T> {
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        (**self).classify(interaction).await
    }

    fn model_name(&self) -> &str {
        (**self).model_name()
    }

    async fn classify_detailed(
        &self,
        interaction: &Interaction,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        (**self).classify_detailed(interaction).await
    }

    async fn classify_detailed_with_stats(
        &self,
        interaction: &Interaction,
        record_stats: bool,
    ) -> Result<TieredEvaluationResult, SkybouncerError> {
        (**self)
            .classify_detailed_with_stats(interaction, record_stats)
            .await
    }

    fn set_rubric(&self, rubric: RuleRubric) {
        (**self).set_rubric(rubric);
    }
}
