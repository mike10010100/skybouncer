//! Hermetic mock classifier implementation for offline unit, property, and integration tests.
//!
//! Provides deterministic verdicts, atomic invocation tracking, keyword-based override mapping,
//! simulated delays for latency/timeout testing, and synthetic error injection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::classifier::{Classifier, RuleRubric, Verdict, ViolationCategory};
use crate::error::SkybouncerError;
use crate::matcher::Interaction;

/// Thread-safe deterministic mock classifier for testing moderation pipelines.
#[derive(Debug, Clone)]
pub struct MockClassifier {
    default_verdict: Arc<RwLock<Verdict>>,
    keyword_verdicts: Arc<RwLock<HashMap<String, Verdict>>>,
    call_count: Arc<AtomicUsize>,
    simulated_delay: Arc<RwLock<Option<Duration>>>,
    simulated_error: Arc<RwLock<Option<String>>>,
    rubric: Arc<RwLock<Option<RuleRubric>>>,
    last_evaluated_rubric: Arc<RwLock<Option<RuleRubric>>>,
    rubric_keyword_verdicts: Arc<RwLock<HashMap<String, Verdict>>>,
}

impl MockClassifier {
    /// Creates a new `MockClassifier` with the specified default verdict.
    #[must_use]
    pub fn new(default_verdict: Verdict) -> Self {
        Self {
            default_verdict: Arc::new(RwLock::new(default_verdict)),
            keyword_verdicts: Arc::new(RwLock::new(HashMap::new())),
            call_count: Arc::new(AtomicUsize::new(0)),
            simulated_delay: Arc::new(RwLock::new(None)),
            simulated_error: Arc::new(RwLock::new(None)),
            rubric: Arc::new(RwLock::new(None)),
            last_evaluated_rubric: Arc::new(RwLock::new(None)),
            rubric_keyword_verdicts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Convenience constructor returning `Verdict::Permitted` by default.
    #[must_use]
    pub fn permitted() -> Self {
        Self::new(Verdict::permitted("Mock permitted by default"))
    }

    /// Convenience constructor returning `Verdict::Violation` by default.
    #[must_use]
    pub fn violation(
        category: ViolationCategory,
        confidence: f64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(Verdict::violation(category, confidence, reason))
    }

    /// Builder method configuring an artificial evaluation delay.
    #[must_use]
    pub fn with_simulated_delay(self, delay: Duration) -> Self {
        *self.simulated_delay.write() = Some(delay);
        self
    }

    /// Sets or updates the default verdict returned when no keyword matches.
    pub fn set_default_verdict(&self, verdict: Verdict) {
        *self.default_verdict.write() = verdict;
    }

    /// Configures a verdict override when candidate text contains the specified keyword (case-insensitive).
    pub fn set_keyword_verdict(&self, keyword: impl Into<String>, verdict: Verdict) {
        let key = keyword.into().to_lowercase();
        self.keyword_verdicts.write().insert(key, verdict);
    }

    /// Removes a keyword override.
    pub fn remove_keyword_verdict(&self, keyword: &str) -> Option<Verdict> {
        let key = keyword.to_lowercase();
        self.keyword_verdicts.write().remove(&key)
    }

    /// Clears all keyword-specific verdict overrides.
    pub fn clear_keyword_verdicts(&self) {
        self.keyword_verdicts.write().clear();
    }

    /// Configures or clears the simulated evaluation delay.
    pub fn set_simulated_delay(&self, delay: Option<Duration>) {
        *self.simulated_delay.write() = delay;
    }

    /// Injects or clears a synthetic error returned on classification attempts.
    pub fn set_error(&self, error_message: Option<impl Into<String>>) {
        *self.simulated_error.write() = error_message.map(Into::into);
    }

    /// Returns the cumulative number of times `classify` has been invoked.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Resets the invocation call counter back to zero.
    pub fn reset_call_count(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }

    /// Returns the currently active rubric, if set.
    #[must_use]
    pub fn rubric(&self) -> Option<RuleRubric> {
        self.rubric.read().clone()
    }

    /// Returns the last moderation rubric passed into classification, if any.
    #[must_use]
    pub fn last_evaluated_rubric(&self) -> Option<RuleRubric> {
        self.last_evaluated_rubric.read().clone()
    }

    /// Configures a verdict override when the evaluated rubric's prompt contains the specified keyword (case-insensitive).
    pub fn set_rubric_keyword_verdict(&self, keyword: impl Into<String>, verdict: Verdict) {
        let key = keyword.into().to_lowercase();
        self.rubric_keyword_verdicts.write().insert(key, verdict);
    }

    /// Removes a rubric keyword override.
    pub fn remove_rubric_keyword_verdict(&self, keyword: &str) -> Option<Verdict> {
        let key = keyword.to_lowercase();
        self.rubric_keyword_verdicts.write().remove(&key)
    }

    /// Clears all rubric keyword-specific verdict overrides.
    pub fn clear_rubric_keyword_verdicts(&self) {
        self.rubric_keyword_verdicts.write().clear();
    }
}

impl Default for MockClassifier {
    fn default() -> Self {
        Self::permitted()
    }
}

#[async_trait]
impl Classifier for MockClassifier {
    fn set_rubric(&self, rubric: RuleRubric) {
        *self.rubric.write() = Some(rubric);
    }

    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        self.classify_with_rubric(interaction, interaction.rubric.as_ref())
            .await
    }

    async fn classify_with_rubric(
        &self,
        interaction: &Interaction,
        rubric: Option<&RuleRubric>,
    ) -> Result<Verdict, SkybouncerError> {
        // Atomically record invocation
        self.call_count.fetch_add(1, Ordering::SeqCst);

        // Read and drop simulated error lock before any async operation
        let error_opt = {
            let guard = self.simulated_error.read();
            guard.clone()
        };
        if let Some(err_msg) = error_opt {
            return Err(SkybouncerError::Classifier(err_msg));
        }

        // Record effective rubric
        let effective_rubric = rubric
            .or(interaction.rubric.as_ref())
            .cloned()
            .or_else(|| self.rubric.read().clone());
        *self.last_evaluated_rubric.write() = effective_rubric.clone();

        // Read and drop simulated delay lock before sleeping across await point
        let delay_opt = {
            let guard = self.simulated_delay.read();
            *guard
        };
        if let Some(delay) = delay_opt {
            tokio::time::sleep(delay).await;
        }

        // 1. Inspect rubric keyword overrides (case-insensitive substring search on prompt)
        if let Some(ref r) = effective_rubric {
            let lower_prompt = r.prompt.to_lowercase();
            let rubric_kw_match = {
                let guard = self.rubric_keyword_verdicts.read();
                guard.iter().find_map(|(kw, verdict)| {
                    if lower_prompt.contains(kw) {
                        Some(verdict.clone())
                    } else {
                        None
                    }
                })
            };
            if let Some(verdict) = rubric_kw_match {
                return Ok(verdict);
            }
        }

        // 2. Inspect candidate text keyword overrides (case-insensitive substring search)
        let lower_text = interaction.text.to_lowercase();
        let keyword_match = {
            let guard = self.keyword_verdicts.read();
            guard.iter().find_map(|(kw, verdict)| {
                if lower_text.contains(kw) {
                    Some(verdict.clone())
                } else {
                    None
                }
            })
        };

        if let Some(verdict) = keyword_match {
            return Ok(verdict);
        }

        // Fall back to default verdict
        let default_v = {
            let guard = self.default_verdict.read();
            guard.clone()
        };
        Ok(default_v)
    }

    fn model_name(&self) -> &str {
        "mock"
    }
}
