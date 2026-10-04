//! Moderation rule rubric and sensitivity threshold definitions.

use crate::classifier::Verdict;
use crate::error::SkybouncerError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// Sensitivity level determining confidence thresholds for automated list actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Sensitivity {
    /// High precision, low false-positive rate. Flags when confidence >= 0.90.
    Low,
    /// Balanced default. Flags when confidence >= 0.75.
    #[default]
    Medium,
    /// High recall, aggressive filtering. Flags when confidence >= 0.60.
    High,
}

impl Serialize for Sensitivity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Sensitivity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Self>().map_err(serde::de::Error::custom)
    }
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

/// Configurable duration for moderation list entries (permanent vs temporary timeout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BounceDuration {
    /// Permanent moderation list entry (no expiration).
    #[default]
    Permanent,
    /// 24-hour temporary timeout.
    Cooldown24h,
    /// 7-day temporary timeout.
    Timeout7d,
    /// 30-day temporary timeout.
    Timeout30d,
    /// Custom duration in seconds.
    Custom(u64),
}

impl BounceDuration {
    /// Returns the timeout duration as a [`Duration`], or `None` if permanent.
    #[must_use]
    pub fn to_duration(&self) -> Option<Duration> {
        match self {
            Self::Permanent => None,
            Self::Cooldown24h => Some(Duration::from_secs(86_400)),
            Self::Timeout7d => Some(Duration::from_secs(7 * 86_400)),
            Self::Timeout30d => Some(Duration::from_secs(30 * 86_400)),
            Self::Custom(secs) => Some(Duration::from_secs(*secs)),
        }
    }

    /// Computes the expiration microsecond timestamp relative to `now_us`.
    #[must_use]
    pub fn expires_at_us(&self, now_us: u64) -> Option<u64> {
        let dur = self.to_duration()?;
        let dur_us = u64::try_from(dur.as_micros()).unwrap_or(u64::MAX);
        Some(now_us.saturating_add(dur_us))
    }

    /// Returns a human-readable display label.
    #[must_use]
    pub fn display_label(&self) -> &'static str {
        match self {
            Self::Permanent => "Permanent",
            Self::Cooldown24h => "24-Hour Cooldown",
            Self::Timeout7d => "7-Day Timeout",
            Self::Timeout30d => "30-Day Timeout",
            Self::Custom(_) => "Custom",
        }
    }
}

impl FromStr for BounceDuration {
    type Err = SkybouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_lowercase();
        match normalized.as_str() {
            "permanent" | "perm" | "none" | "forever" => Ok(Self::Permanent),
            "cooldown24h" | "24h" | "24-hour" | "24_hours" | "1d" | "day" => Ok(Self::Cooldown24h),
            "timeout7d" | "7d" | "7-day" | "7_days" | "1w" | "week" => Ok(Self::Timeout7d),
            "timeout30d" | "30d" | "30-day" | "30_days" | "1m" | "month" => Ok(Self::Timeout30d),
            _ => {
                if let Ok(secs) = normalized.parse::<u64>() {
                    Ok(Self::Custom(secs))
                } else {
                    Err(SkybouncerError::Config(format!(
                        "Unknown bounce duration: `{s}`. Valid values: permanent, 24h, 7d, 30d, or seconds."
                    )))
                }
            }
        }
    }
}

impl fmt::Display for BounceDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_label())
    }
}

/// Configured house rules and sensitivity rubric for moderation evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleRubric {
    /// Natural language moderation prompt or policy instructions.
    pub prompt: String,
    /// Operating sensitivity level governing confidence thresholds.
    pub sensitivity: Sensitivity,
    /// Configurable bounce duration / timeout for violations (defaults to Permanent).
    #[serde(default)]
    pub bounce_duration: BounceDuration,
}

impl RuleRubric {
    /// Creates a new rubric with the given prompt and sensitivity level.
    #[must_use]
    pub fn new(prompt: impl Into<String>, sensitivity: Sensitivity) -> Self {
        Self {
            prompt: prompt.into(),
            sensitivity,
            bounce_duration: BounceDuration::Permanent,
        }
    }

    /// Creates a new rubric with the given prompt and default sensitivity ([`Sensitivity::Medium`]).
    #[must_use]
    pub fn with_default_sensitivity(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            sensitivity: Sensitivity::default(),
            bounce_duration: BounceDuration::Permanent,
        }
    }

    /// Sets the bounce duration / timeout.
    #[must_use]
    pub fn with_bounce_duration(mut self, bounce_duration: BounceDuration) -> Self {
        self.bounce_duration = bounce_duration;
        self
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
                    Verdict::permitted_with_confidence(
                        format!(
                            "Confidence {confidence:.2} is below the {} sensitivity threshold ({:.2}): {reason}",
                            self.sensitivity,
                            self.sensitivity.threshold()
                        ),
                        confidence,
                    )
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
        let mut bounce_duration = BounceDuration::Permanent;
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
            } else if let Some(rest) = directive.strip_prefix("duration:") {
                let dur_str = rest.trim();
                bounce_duration = dur_str.parse::<BounceDuration>()?;
            } else if let Some(rest) = directive.strip_prefix("duration =") {
                let dur_str = rest.trim().trim_matches('"');
                bounce_duration = dur_str.parse::<BounceDuration>()?;
            } else if let Some(rest) = directive.strip_prefix("timeout:") {
                let dur_str = rest.trim();
                bounce_duration = dur_str.parse::<BounceDuration>()?;
            } else if let Some(rest) = directive.strip_prefix("timeout =") {
                let dur_str = rest.trim().trim_matches('"');
                bounce_duration = dur_str.parse::<BounceDuration>()?;
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
            bounce_duration,
        })
    }
}

impl Default for RuleRubric {
    fn default() -> Self {
        Self {
            prompt: "Block crypto airdrop spam, scam bots, phishing, targeted harassment, and bad-faith sea-lioning.".to_string(),
            sensitivity: Sensitivity::Medium,
            bounce_duration: BounceDuration::Permanent,
        }
    }
}

impl FromStr for RuleRubric {
    type Err = SkybouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
