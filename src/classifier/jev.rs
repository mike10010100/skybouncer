//! Asynchronous HTTP client for Jev structured decision classification.
//!
//! Evaluates candidate interactions against natural-language moderation rubrics
//! using TypeSafe AI's Jev "System 1" model or compatible HTTP endpoints.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::classifier::{Classifier, RuleRubric, Verdict, ViolationCategory};
use crate::error::SkybouncerError;
use crate::matcher::Interaction;

/// Default endpoint URL for Jev classification API.
pub const DEFAULT_JEV_BASE_URL: &str = "https://nmo.purdlauski.net";

/// Default model identifier for Jev classification.
pub const DEFAULT_JEV_MODEL: &str = "jev-system1-mod-v1";

/// Default timeout in milliseconds for Jev API requests.
pub const DEFAULT_JEV_TIMEOUT_MS: u64 = 3000;

/// Default maximum retry count on transient errors.
pub const DEFAULT_JEV_MAX_RETRIES: usize = 1;

/// Configuration parameters for [`JevClassifier`].
#[derive(Debug, Clone)]
pub struct JevConfig {
    /// Base URL of the Jev classification API (e.g. `<https://nmo.purdlauski.net>`).
    pub base_url: String,
    /// API authentication key (bearer token), if required.
    pub api_key: Option<String>,
    /// Model name or version tag to evaluate with.
    pub model: String,
    /// Client-side HTTP request timeout duration.
    pub timeout: Duration,
    /// Maximum number of retries on transient errors (5xx or connection drops).
    pub max_retries: usize,
}

impl Default for JevConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_JEV_BASE_URL.to_string(),
            api_key: None,
            model: DEFAULT_JEV_MODEL.to_string(),
            timeout: Duration::from_millis(DEFAULT_JEV_TIMEOUT_MS),
            max_retries: DEFAULT_JEV_MAX_RETRIES,
        }
    }
}

impl JevConfig {
    /// Constructs a [`JevConfig`] loaded from environment variables with fallback defaults.
    ///
    /// # Environment Variables
    /// - `JEV_API_BASE_URL`: Base URL (defaults to `<https://nmo.purdlauski.net>`)
    /// - `JEV_API_KEY`: API key for authentication (optional in development, recommended in production)
    /// - `JEV_MODEL`: Model name (defaults to `"jev-system1-mod-v1"`)
    /// - `JEV_TIMEOUT_MS`: Request timeout in milliseconds (defaults to `3000`)
    /// - `JEV_MAX_RETRIES`: Maximum retries on transient errors (defaults to `1`)
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if numeric environment variables cannot be parsed.
    pub fn from_env() -> Result<Self, SkybouncerError> {
        let base_url =
            std::env::var("JEV_API_BASE_URL").unwrap_or_else(|_| DEFAULT_JEV_BASE_URL.to_string());

        let api_key = std::env::var("JEV_API_KEY").ok().and_then(|k| {
            let trimmed = k.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        let model = std::env::var("JEV_MODEL").unwrap_or_else(|_| DEFAULT_JEV_MODEL.to_string());

        let timeout_ms = match std::env::var("JEV_TIMEOUT_MS") {
            Ok(val) => val.parse::<u64>().map_err(|e| {
                SkybouncerError::Config(format!("Invalid JEV_TIMEOUT_MS '{val}': {e}"))
            })?,
            Err(_) => DEFAULT_JEV_TIMEOUT_MS,
        };

        let max_retries = match std::env::var("JEV_MAX_RETRIES") {
            Ok(val) => val.parse::<usize>().map_err(|e| {
                SkybouncerError::Config(format!("Invalid JEV_MAX_RETRIES '{val}': {e}"))
            })?,
            Err(_) => DEFAULT_JEV_MAX_RETRIES,
        };

        Ok(Self {
            base_url,
            api_key,
            model,
            timeout: Duration::from_millis(timeout_ms),
            max_retries,
        })
    }
}

/// Outbound context object for Jev classification requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JevRequestContext {
    /// Author DID of the candidate interaction.
    pub author_did: String,
    /// Protected user DID targeted by the interaction.
    pub target_did: String,
    /// String representation of the interaction vector (e.g. `"direct_reply"`).
    pub interaction_type: String,
}

/// Outbound JSON payload sent to the Jev classification API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevClassifyRequest {
    /// Model name to evaluate with.
    pub model: String,
    /// Candidate post text content.
    pub text: String,
    /// Natural-language moderation rubric prompt.
    pub rubric: String,
    /// Interaction context metadata.
    pub context: JevRequestContext,
    /// Sensitivity string (`"low"`, `"medium"`, `"high"`).
    pub sensitivity: String,
}

/// Inbound JSON response schema received from the Jev classification API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevClassifyResponse {
    /// Whether the candidate interaction violates the configured rubric.
    pub violates: bool,
    /// Category tag describing the violation, if any.
    #[serde(default)]
    pub category: Option<String>,
    /// Model confidence score between 0.0 and 1.0.
    pub confidence: f64,
    /// Natural-language explanation for the decision.
    pub reason: String,
}

/// Asynchronous HTTP client evaluating ATProto interactions against Jev APIs.
#[derive(Debug, Clone)]
pub struct JevClassifier {
    config: JevConfig,
    rubric: RuleRubric,
    http_client: reqwest::Client,
    classify_url: String,
}

impl JevClassifier {
    /// Creates a new [`JevClassifier`] with the given configuration and rubric.
    ///
    /// Configures an internal [`reqwest::Client`] enforcing pure Rustls TLS.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if the URL is invalid or HTTP client construction fails.
    pub fn new(config: JevConfig, rubric: RuleRubric) -> Result<Self, SkybouncerError> {
        let http_client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(config.timeout)
            .build()
            .map_err(|e| SkybouncerError::Config(format!("Failed to build HTTP client: {e}")))?;

        Self::with_client(config, rubric, http_client)
    }

    /// Creates a new [`JevClassifier`] reusing an existing [`reqwest::Client`].
    ///
    /// Useful for dependency injection in testing and shared connection pools.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if the resolved classify URL is malformed.
    pub fn with_client(
        config: JevConfig,
        rubric: RuleRubric,
        http_client: reqwest::Client,
    ) -> Result<Self, SkybouncerError> {
        let base = config.base_url.trim_end_matches('/');
        let classify_url = if base.ends_with("/v1/classify") {
            base.to_string()
        } else if base.ends_with("/v1") {
            format!("{base}/classify")
        } else {
            format!("{base}/v1/classify")
        };

        // Validate resolved URL
        url::Url::parse(&classify_url).map_err(|e| {
            SkybouncerError::Config(format!("Invalid Jev endpoint URL '{classify_url}': {e}"))
        })?;

        Ok(Self {
            config,
            rubric,
            http_client,
            classify_url,
        })
    }

    /// Creates a [`JevClassifier`] by loading configuration from environment variables.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if environment configuration parsing fails.
    pub fn from_env(rubric: RuleRubric) -> Result<Self, SkybouncerError> {
        let config = JevConfig::from_env()?;
        Self::new(config, rubric)
    }

    /// Returns a reference to the active [`JevConfig`].
    #[must_use]
    pub fn config(&self) -> &JevConfig {
        &self.config
    }

    /// Returns a reference to the active [`RuleRubric`].
    #[must_use]
    pub fn rubric(&self) -> &RuleRubric {
        &self.rubric
    }

    /// Returns the resolved classification URL string.
    #[must_use]
    pub fn classify_url(&self) -> &str {
        &self.classify_url
    }

    /// Evaluates an interaction candidate by calling the Jev classification API.
    ///
    /// Retries at most once on transient 5xx or connection errors with a 100ms backoff.
    /// Never retries 4xx client errors.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Classifier`] on HTTP client errors, exhausted retries,
    /// or JSON parsing failures.
    pub async fn evaluate(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        let payload = JevClassifyRequest {
            model: self.config.model.clone(),
            text: interaction.text.clone(),
            rubric: self.rubric.prompt.clone(),
            context: JevRequestContext {
                author_did: interaction.author_did.clone(),
                target_did: interaction.target_did.clone(),
                interaction_type: interaction.interaction_type.as_str().to_string(),
            },
            sensitivity: self.rubric.sensitivity.as_str().to_string(),
        };

        let mut last_err = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                tracing::debug!(attempt, "Retrying transient Jev API request after backoff");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            let mut request_builder = self
                .http_client
                .post(&self.classify_url)
                .header("Content-Type", "application/json");

            if let Some(ref key) = self.config.api_key {
                request_builder = request_builder.header("Authorization", format!("Bearer {key}"));
            }

            let response = match request_builder.json(&payload).send().await {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::warn!(attempt, %err, "Jev API network error");
                    last_err = Some(SkybouncerError::Classifier(format!(
                        "Jev API network error: {err}"
                    )));
                    continue;
                }
            };

            let status = response.status();

            if status.is_success() {
                let classify_resp: JevClassifyResponse = response.json().await.map_err(|e| {
                    SkybouncerError::Classifier(format!("Failed to parse Jev JSON response: {e}"))
                })?;
                return Ok(self.build_verdict(classify_resp));
            }

            // Client errors (4xx) are permanent — NEVER RETRY
            if status.is_client_error() {
                let err_body = response.text().await.unwrap_or_default();
                return Err(SkybouncerError::Classifier(format!(
                    "Jev API client error (HTTP {}): {err_body}",
                    status.as_u16()
                )));
            }

            // Server errors (5xx) are transient — record error and retry if attempts remain
            let err_body = response.text().await.unwrap_or_default();
            tracing::warn!(attempt, %status, body = %err_body, "Jev API server error");
            last_err = Some(SkybouncerError::Classifier(format!(
                "Jev API server error (HTTP {}): {err_body}",
                status.as_u16()
            )));
        }

        Err(last_err.unwrap_or_else(|| {
            SkybouncerError::Classifier("Jev API request failed after retries".to_string())
        }))
    }

    /// Evaluates raw Jev response against configured rubric sensitivity.
    fn build_verdict(&self, resp: JevClassifyResponse) -> Verdict {
        if resp.violates && self.rubric.is_actionable(resp.confidence) {
            let category = match resp.category.as_deref() {
                Some("spam") => ViolationCategory::Spam,
                Some("crypto_spam") | Some("crypto-spam") | Some("crypto") => {
                    ViolationCategory::CryptoSpam
                }
                Some("harassment") => ViolationCategory::Harassment,
                Some("sea_lioning") | Some("sealioning") => ViolationCategory::SeaLioning,
                Some("phishing") => ViolationCategory::Phishing,
                Some("hate_speech") | Some("hatespeech") => ViolationCategory::HateSpeech,
                Some(other) => ViolationCategory::Custom(other.to_string()),
                None => ViolationCategory::Custom("unspecified".to_string()),
            };

            Verdict::violation(category, resp.confidence, resp.reason)
        } else {
            Verdict::permitted(resp.reason)
        }
    }
}

#[async_trait]
impl Classifier for JevClassifier {
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        self.evaluate(interaction).await
    }
}
