//! Moderation rule rubric and sensitivity threshold definitions.

use crate::classifier::Verdict;
use crate::error::SkybouncerError;
use crate::types::default_true;
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

/// Parses a persisted sensitivity string, defaulting to [`Sensitivity::Medium`] when
/// the value is absent or unrecognized (legacy database compatibility).
#[must_use]
pub fn sensitivity_from_db(value: Option<&str>) -> Sensitivity {
    value
        .and_then(|s| s.parse::<Sensitivity>().ok())
        .unwrap_or(Sensitivity::Medium)
}

/// Configurable duration for moderation list entries (permanent vs temporary timeout).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
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

impl Serialize for BounceDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Permanent => serializer.serialize_str("permanent"),
            Self::Cooldown24h => serializer.serialize_str("cooldown24h"),
            Self::Timeout7d => serializer.serialize_str("timeout7d"),
            Self::Timeout30d => serializer.serialize_str("timeout30d"),
            Self::Custom(secs) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("custom", secs)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for BounceDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BounceDurationVisitor;

        impl<'de> serde::de::Visitor<'de> for BounceDurationVisitor {
            type Value = BounceDuration;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "a bounce duration string (e.g. 'permanent', '24h', '7d', '30d') or numeric seconds",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<BounceDuration, E>
            where
                E: serde::de::Error,
            {
                value
                    .parse::<BounceDuration>()
                    .map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(self, value: u64) -> Result<BounceDuration, E>
            where
                E: serde::de::Error,
            {
                match value {
                    0 => Ok(BounceDuration::Permanent),
                    86_400 => Ok(BounceDuration::Cooldown24h),
                    604_800 => Ok(BounceDuration::Timeout7d),
                    2_592_000 => Ok(BounceDuration::Timeout30d),
                    secs => Ok(BounceDuration::Custom(secs)),
                }
            }

            fn visit_i64<E>(self, value: i64) -> Result<BounceDuration, E>
            where
                E: serde::de::Error,
            {
                if value <= 0 {
                    Ok(BounceDuration::Permanent)
                } else {
                    let u = u64::try_from(value).map_err(serde::de::Error::custom)?;
                    self.visit_u64(u)
                }
            }

            fn visit_map<M>(self, mut map: M) -> Result<BounceDuration, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                if let Some(key) = map.next_key::<String>()? {
                    if key.eq_ignore_ascii_case("custom") {
                        let val = map.next_value::<u64>()?;
                        return Ok(BounceDuration::Custom(val));
                    }
                }
                Err(serde::de::Error::custom(
                    "expected object with 'custom' field",
                ))
            }
        }

        deserializer.deserialize_any(BounceDurationVisitor)
    }
}

impl BounceDuration {
    /// Returns the canonical machine-readable string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Permanent => "permanent",
            Self::Cooldown24h => "cooldown24h",
            Self::Timeout7d => "timeout7d",
            Self::Timeout30d => "timeout30d",
            Self::Custom(_) => "custom",
        }
    }

    /// Formats the duration as a string suitable for database storage.
    #[must_use]
    pub fn to_db_string(&self) -> String {
        match self {
            Self::Permanent => "permanent".to_string(),
            Self::Cooldown24h => "cooldown24h".to_string(),
            Self::Timeout7d => "timeout7d".to_string(),
            Self::Timeout30d => "timeout30d".to_string(),
            Self::Custom(secs) => secs.to_string(),
        }
    }

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
            "permanent" | "perm" | "none" | "forever" | "0" => Ok(Self::Permanent),
            "cooldown24h" | "cooldown_24h" | "24h" | "24-hour" | "24_hours" | "1d" | "day" => {
                Ok(Self::Cooldown24h)
            }
            "timeout7d" | "timeout_7d" | "7d" | "7-day" | "7_days" | "1w" | "week" => {
                Ok(Self::Timeout7d)
            }
            "timeout30d" | "timeout_30d" | "30d" | "30-day" | "30_days" | "1m" | "month" => {
                Ok(Self::Timeout30d)
            }
            _ => {
                if let Ok(secs) = normalized.parse::<u64>() {
                    match secs {
                        0 => Ok(Self::Permanent),
                        86_400 => Ok(Self::Cooldown24h),
                        604_800 => Ok(Self::Timeout7d),
                        2_592_000 => Ok(Self::Timeout30d),
                        _ => Ok(Self::Custom(secs)),
                    }
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

/// Parses a persisted bounce-duration string, defaulting to [`BounceDuration::default`]
/// when the value is absent or unrecognized.
#[must_use]
pub fn bounce_duration_from_db(value: Option<&str>) -> BounceDuration {
    value
        .and_then(|s| s.parse::<BounceDuration>().ok())
        .unwrap_or_default()
}

/// Configured house rules and sensitivity rubric for moderation evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleRubric {
    /// Natural language moderation prompt or policy instructions.
    pub prompt: String,
    /// Operating sensitivity level governing confidence thresholds.
    pub sensitivity: Sensitivity,
    /// Configurable bounce duration / timeout for violations (defaults to Permanent).
    #[serde(default)]
    pub bounce_duration: BounceDuration,
    /// Whether accounts that follow the protected user bypass moderation evaluation.
    ///
    /// Defaults to `true` so that incoming followers inherit the same zero-cost trust
    /// as accounts the protected user follows.
    #[serde(default = "default_true")]
    pub bypass_incoming_followers: bool,
}

impl RuleRubric {
    /// Creates a new rubric with the given prompt and sensitivity level.
    #[must_use]
    pub fn new(prompt: impl Into<String>, sensitivity: Sensitivity) -> Self {
        Self {
            prompt: prompt.into(),
            sensitivity,
            bounce_duration: BounceDuration::Permanent,
            bypass_incoming_followers: true,
        }
    }

    /// Creates a new rubric with the given prompt and default sensitivity ([`Sensitivity::Medium`]).
    #[must_use]
    pub fn with_default_sensitivity(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            sensitivity: Sensitivity::default(),
            bounce_duration: BounceDuration::Permanent,
            bypass_incoming_followers: true,
        }
    }

    /// Sets the bounce duration / timeout.
    #[must_use]
    pub fn with_bounce_duration(mut self, bounce_duration: BounceDuration) -> Self {
        self.bounce_duration = bounce_duration;
        self
    }

    /// Sets whether accounts following the protected user bypass moderation evaluation.
    #[must_use]
    pub fn with_bypass_incoming_followers(mut self, bypass: bool) -> Self {
        self.bypass_incoming_followers = bypass;
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
        let mut bypass_incoming_followers = true;
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
            } else if let Some(rest) = directive.strip_prefix("bypass_followers:") {
                let flag = rest.trim();
                bypass_incoming_followers = flag.parse::<bool>().map_err(|_| {
                    SkybouncerError::Config(format!(
                        "Invalid bypass_followers value '{flag}'; expected true or false"
                    ))
                })?;
            } else if let Some(rest) = directive.strip_prefix("bypass_followers =") {
                let flag = rest.trim().trim_matches('"');
                bypass_incoming_followers = flag.parse::<bool>().map_err(|_| {
                    SkybouncerError::Config(format!(
                        "Invalid bypass_followers value '{flag}'; expected true or false"
                    ))
                })?;
            } else if let Some(idx) = line_trimmed.rfind('[') {
                if let Some(rest) = line_trimmed[idx..].strip_suffix(']') {
                    let inline_dir = &rest[1..];
                    if let Some(dur_str) = inline_dir.strip_prefix("duration:") {
                        bounce_duration = dur_str.trim().parse::<BounceDuration>()?;
                        let rem = line_trimmed[..idx].trim();
                        if !rem.is_empty() {
                            prompt_lines.push(rem);
                        }
                    } else if let Some(dur_str) = inline_dir.strip_prefix("timeout:") {
                        bounce_duration = dur_str.trim().parse::<BounceDuration>()?;
                        let rem = line_trimmed[..idx].trim();
                        if !rem.is_empty() {
                            prompt_lines.push(rem);
                        }
                    } else if let Some(sens_str) = inline_dir.strip_prefix("sensitivity:") {
                        sensitivity = sens_str.trim().parse::<Sensitivity>()?;
                        let rem = line_trimmed[..idx].trim();
                        if !rem.is_empty() {
                            prompt_lines.push(rem);
                        }
                    } else {
                        prompt_lines.push(line);
                    }
                } else {
                    prompt_lines.push(line);
                }
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
            bypass_incoming_followers,
        })
    }
}

impl Default for RuleRubric {
    fn default() -> Self {
        Self {
            prompt: "Block crypto airdrop spam, scam bots, phishing, targeted harassment, and bad-faith sea-lioning.".to_string(),
            sensitivity: Sensitivity::Medium,
            bounce_duration: BounceDuration::Permanent,
            bypass_incoming_followers: true,
        }
    }
}

impl FromStr for RuleRubric {
    type Err = SkybouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_bounce_duration_serde_flexibility() {
        // Test parsing various strings
        let d1: BounceDuration = serde_json::from_str("\"24h\"").unwrap();
        assert_eq!(d1, BounceDuration::Cooldown24h);

        let d2: BounceDuration = serde_json::from_str("\"cooldown24h\"").unwrap();
        assert_eq!(d2, BounceDuration::Cooldown24h);

        let d3: BounceDuration = serde_json::from_str("\"7d\"").unwrap();
        assert_eq!(d3, BounceDuration::Timeout7d);

        let d4: BounceDuration = serde_json::from_str("\"timeout7d\"").unwrap();
        assert_eq!(d4, BounceDuration::Timeout7d);

        let d5: BounceDuration = serde_json::from_str("\"30d\"").unwrap();
        assert_eq!(d5, BounceDuration::Timeout30d);

        let d6: BounceDuration = serde_json::from_str("\"timeout30d\"").unwrap();
        assert_eq!(d6, BounceDuration::Timeout30d);

        let d7: BounceDuration = serde_json::from_str("\"permanent\"").unwrap();
        assert_eq!(d7, BounceDuration::Permanent);

        let d8: BounceDuration = serde_json::from_str("\"perm\"").unwrap();
        assert_eq!(d8, BounceDuration::Permanent);

        // Test numbers
        let d9: BounceDuration = serde_json::from_str("86400").unwrap();
        assert_eq!(d9, BounceDuration::Cooldown24h);

        let d10: BounceDuration = serde_json::from_str("0").unwrap();
        assert_eq!(d10, BounceDuration::Permanent);

        let d11: BounceDuration = serde_json::from_str("3600").unwrap();
        assert_eq!(d11, BounceDuration::Custom(3600));

        // Test object format
        let d12: BounceDuration = serde_json::from_str("{\"custom\": 7200}").unwrap();
        assert_eq!(d12, BounceDuration::Custom(7200));

        // Test serialization round-trip
        let serialized = serde_json::to_string(&BounceDuration::Cooldown24h).unwrap();
        assert_eq!(serialized, "\"cooldown24h\"");
        let round_trip: BounceDuration = serde_json::from_str(&serialized).unwrap();
        assert_eq!(round_trip, BounceDuration::Cooldown24h);
    }

    #[test]
    fn test_rubric_bypass_incoming_followers_default_and_parse() {
        // Default is enabled.
        assert!(RuleRubric::default().bypass_incoming_followers);
        assert!(RuleRubric::new("block spam", Sensitivity::Medium).bypass_incoming_followers);

        // Legacy JSON without the field deserializes to the enabled default.
        let legacy: RuleRubric =
            serde_json::from_str(r#"{"prompt":"block spam","sensitivity":"medium"}"#).unwrap();
        assert!(legacy.bypass_incoming_followers);

        // Explicit opt-out is honored and round-trips.
        let parsed = RuleRubric::parse("block spam\nbypass_followers: false").unwrap();
        assert!(!parsed.bypass_incoming_followers);
        let round_trip: RuleRubric =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert!(!round_trip.bypass_incoming_followers);

        // Invalid directive value is a typed config error.
        assert!(RuleRubric::parse("block spam\nbypass_followers: maybe").is_err());
    }

    #[test]
    fn test_rubric_parse_directives() {
        let rubric = RuleRubric::parse("Block crypto spam [duration: 24h]").unwrap();
        assert_eq!(rubric.prompt, "Block crypto spam");
        assert_eq!(rubric.bounce_duration, BounceDuration::Cooldown24h);

        let rubric7d = RuleRubric::parse("No harassment\ntimeout: 7d").unwrap();
        assert_eq!(rubric7d.prompt, "No harassment");
        assert_eq!(rubric7d.bounce_duration, BounceDuration::Timeout7d);
    }
}
