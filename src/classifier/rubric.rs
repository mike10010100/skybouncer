//! Moderation rule rubric and sensitivity threshold definitions.

use crate::classifier::Verdict;
use crate::error::SkybouncerError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Sensitivity level determining confidence thresholds for automated list actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// High precision, low false-positive rate. Flags when confidence >= 0.90.
    Low,
    /// Balanced default. Flags when confidence >= 0.75.
    #[default]
    Medium,
    /// High recall, aggressive filtering. Flags when confidence >= 0.60.
    High,
}

impl Sensitivity {
    /// Returns the minimum confidence threshold required to confirm a violation.
    #[must_use]
    pub const fn threshold(&self) -> f64 {
        match self {
            Self::Low => 0.90,
            Self::Medium => 0.75,
            Self::High => 0.60,
        }
    }

    /// Returns the static string representation of this sensitivity level.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Sensitivity {
    type Err = SkybouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            other => Err(SkybouncerError::Config(format!(
                "Invalid sensitivity level '{other}'; expected 'low', 'medium', or 'high'"
            ))),
        }
    }
}

/// Configured house rules and sensitivity rubric for moderation evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleRubric {
    /// Natural language moderation prompt or policy instructions.
    pub prompt: String,
    /// Operating sensitivity level governing confidence thresholds.
    pub sensitivity: Sensitivity,
}

impl RuleRubric {
    /// Creates a new rubric with the given prompt and sensitivity level.
    #[must_use]
    pub fn new(prompt: impl Into<String>, sensitivity: Sensitivity) -> Self {
        Self {
            prompt: prompt.into(),
            sensitivity,
        }
    }

    /// Creates a new rubric with the given prompt and default sensitivity ([`Sensitivity::Medium`]).
    #[must_use]
    pub fn with_default_sensitivity(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            sensitivity: Sensitivity::default(),
        }
    }

    /// Evaluates whether a raw confidence score meets or exceeds the actionable threshold.
    #[must_use]
    pub fn is_actionable(&self, confidence: f64) -> bool {
        if confidence.is_nan() {
            return false;
        }
        confidence >= self.sensitivity.threshold()
    }

    /// Evaluates whether a candidate violation meets or exceeds the actionable sensitivity threshold.
    #[must_use]
    pub fn meets_threshold(
        &self,
        _category: &crate::classifier::ViolationCategory,
        confidence: f64,
    ) -> bool {
        self.is_actionable(confidence)
    }

    /// Applies the rubric's sensitivity threshold to a [`Verdict`].
    ///
    /// If the verdict is a [`Verdict::Violation`] but its confidence falls below the
    /// rubric's threshold, it is downgraded to [`Verdict::Permitted`] with an explanatory reason.
    #[must_use]
    pub fn evaluate_verdict(&self, verdict: Verdict) -> Verdict {
        match verdict {
            Verdict::Violation {
                category,
                confidence,
                reason,
            } => {
                if self.is_actionable(confidence) {
                    Verdict::Violation {
                        category,
                        confidence,
                        reason,
                    }
                } else {
                    Verdict::Permitted {
                        reason: format!(
                            "Confidence {confidence:.2} is below the {} sensitivity threshold ({:.2}): {reason}",
                            self.sensitivity,
                            self.sensitivity.threshold()
                        ),
                    }
                }
            }
            permitted @ Verdict::Permitted { .. } => permitted,
        }
    }

    /// Parses a rubric from a raw configuration or prompt string.
    ///
    /// Supports optional sensitivity headers (e.g. `sensitivity: high\n<prompt>`
    /// or `[sensitivity: low]\n<prompt>`). If omitted, defaults to [`Sensitivity::Medium`].
    ///
    /// # Errors
    ///
    /// Returns [`SkybouncerError::Config`] if the sensitivity string is invalid or prompt is empty.
    pub fn parse(raw: &str) -> Result<Self, SkybouncerError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(SkybouncerError::Config(
                "Rule rubric prompt cannot be empty".to_string(),
            ));
        }

        let mut sensitivity = Sensitivity::Medium;
        let mut prompt_lines = Vec::new();

        for line in trimmed.lines() {
            let line_trimmed = line.trim();
            let directive = line_trimmed
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(line_trimmed);

            if let Some(rest) = directive.strip_prefix("sensitivity:") {
                let level_str = rest.trim();
                sensitivity = level_str.parse::<Sensitivity>()?;
            } else if let Some(rest) = directive.strip_prefix("sensitivity =") {
                let level_str = rest.trim().trim_matches('"');
                sensitivity = level_str.parse::<Sensitivity>()?;
            } else {
                prompt_lines.push(line);
            }
        }

        let prompt = prompt_lines.join("\n").trim().to_string();
        if prompt.is_empty() {
            return Err(SkybouncerError::Config(
                "Rule rubric prompt cannot be empty after stripping sensitivity directive"
                    .to_string(),
            ));
        }

        Ok(Self {
            prompt,
            sensitivity,
        })
    }
}

impl Default for RuleRubric {
    fn default() -> Self {
        Self {
            prompt: "Block crypto airdrop spam, scam bots, phishing, targeted harassment, and bad-faith sea-lioning.".to_string(),
            sensitivity: Sensitivity::Medium,
        }
    }
}

impl FromStr for RuleRubric {
    type Err = SkybouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
