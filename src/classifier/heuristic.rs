//! Zero-cost heuristic pre-filter classifier using compiled regular expressions.
//!
//! Provides sub-microsecond classification for high-confidence spam, scam, and phishing patterns
//! with zero network overhead and zero database queries.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use regex::Regex;

use crate::classifier::{Classifier, Verdict, ViolationCategory};
use crate::error::SkybouncerError;
use crate::matcher::Interaction;

/// Built-in regular expression pattern for crypto airdrops, wallet drainers, and token lures.
pub const CRYPTO_AIRDROP_PATTERN: &str = r"(?i)\b(airdrop|claim\s+free|presale\s+live|connect\s+wallet|whitelist\s+now|dm\s+for\s+crypto|send\s+eth|send\s+btc|send\s+sol|giveaway\s+winner|free\s+mint|claim\s+(?:your\s+)?(?:allocation|tokens?|reward)|connect\s+(?:your\s+)?wallet)\b";

/// Built-in regular expression pattern for off-platform messaging lures (Telegram, WhatsApp, Discord).
pub const MESSAGING_LURE_PATTERN: &str = r"(?i)\b(?:https?:\/\/)?(?:t\.me|telegram\.me|wa\.me|chat\.whatsapp\.com|discord\.gg|discord\.com\/invite)\/[a-zA-Z0-9_+]+";

/// Built-in regular expression pattern for suspicious, high-risk top-level domains (TLDs) frequently abused by phishing bots.
pub const SUSPICIOUS_TLD_PATTERN: &str = r"(?i)https?:\/\/[a-zA-Z0-9.-]+\.(?:xyz|top|buzz|click|loan|gq|cf|ml|tk|ga|rest|cam)(?::\d+)?(?:\/[^\s]*)?";

/// A compiled heuristic rule mapping a regex pattern to a violation category and explanatory reason.
#[derive(Debug, Clone)]
pub struct HeuristicRule {
    /// Compiled regular expression.
    pub pattern: Regex,
    /// Category of rule violation when matched.
    pub category: ViolationCategory,
    /// Human-readable explanation of why this rule triggered.
    pub description: String,
}

/// Global cache of default compiled rules to avoid recompilation across multiple instances.
static DEFAULT_RULES: OnceLock<Arc<Vec<HeuristicRule>>> = OnceLock::new();

/// Zero-cost heuristic classifier using compiled regular expressions for instant pre-filtering.
///
/// Designed to execute in $< 500\,\text{ns}$ per interaction candidate with zero network calls,
/// short-circuiting obvious spam before calling external model APIs.
#[derive(Debug, Clone)]
pub struct HeuristicClassifier {
    rules: Arc<Vec<HeuristicRule>>,
}

impl HeuristicClassifier {
    /// Compiles the default rule set (crypto airdrops, messaging lures, suspicious TLDs).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Classifier`] if pattern compilation fails.
    pub fn new() -> Result<Self, SkybouncerError> {
        if let Some(cached) = DEFAULT_RULES.get() {
            return Ok(Self {
                rules: Arc::clone(cached),
            });
        }

        let crypto_regex = Regex::new(CRYPTO_AIRDROP_PATTERN).map_err(|e| {
            SkybouncerError::Classifier(format!("Failed to compile crypto regex: {e}"))
        })?;
        let messaging_regex = Regex::new(MESSAGING_LURE_PATTERN).map_err(|e| {
            SkybouncerError::Classifier(format!("Failed to compile messaging regex: {e}"))
        })?;
        let tld_regex = Regex::new(SUSPICIOUS_TLD_PATTERN).map_err(|e| {
            SkybouncerError::Classifier(format!("Failed to compile TLD regex: {e}"))
        })?;

        let rules = vec![
            HeuristicRule {
                pattern: crypto_regex,
                category: ViolationCategory::CryptoSpam,
                description: "unsolicited crypto airdrop or wallet drain lure".to_string(),
            },
            HeuristicRule {
                pattern: tld_regex,
                category: ViolationCategory::Phishing,
                description: "URL using high-risk suspicious top-level domain".to_string(),
            },
            HeuristicRule {
                pattern: messaging_regex,
                category: ViolationCategory::Spam,
                description: "deceptive off-platform messaging lure (Telegram/WhatsApp/Discord)"
                    .to_string(),
            },
        ];

        let rules_arc = Arc::new(rules);
        let _ = DEFAULT_RULES.set(Arc::clone(&rules_arc));

        Ok(Self { rules: rules_arc })
    }

    /// Creates an empty `HeuristicClassifier` with no rules configured.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rules: Arc::new(Vec::new()),
        }
    }

    /// Adds a custom regex pattern rule to this classifier.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Classifier`] if `pattern` is not a valid regular expression.
    pub fn add_rule(
        &mut self,
        pattern: &str,
        category: ViolationCategory,
        description: impl Into<String>,
    ) -> Result<(), SkybouncerError> {
        let compiled = Regex::new(pattern).map_err(|e| {
            SkybouncerError::Classifier(format!("Invalid custom regex '{pattern}': {e}"))
        })?;
        Arc::make_mut(&mut self.rules).push(HeuristicRule {
            pattern: compiled,
            category,
            description: description.into(),
        });
        Ok(())
    }

    /// Returns the number of compiled heuristic rules in this classifier.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Synchronously evaluates raw text against all compiled heuristic rules.
    ///
    /// Execution is sub-microsecond and purely computational.
    #[must_use]
    pub fn evaluate_text(&self, text: &str) -> Verdict {
        for rule in self.rules.iter() {
            if let Some(matched) = rule.pattern.find(text) {
                return Verdict::Violation {
                    category: rule.category.clone(),
                    confidence: 1.0,
                    reason: format!(
                        "Heuristic match: {} (pattern matched: '{}')",
                        rule.description,
                        matched.as_str()
                    ),
                };
            }
        }
        Verdict::permitted("No heuristic violations detected")
    }

    /// Synchronously evaluates an incoming interaction candidate.
    #[must_use]
    pub fn evaluate(&self, interaction: &Interaction) -> Verdict {
        self.evaluate_text(&interaction.text)
    }
}

impl Default for HeuristicClassifier {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self::empty())
    }
}

#[async_trait]
impl Classifier for HeuristicClassifier {
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        Ok(self.evaluate(interaction))
    }
}
