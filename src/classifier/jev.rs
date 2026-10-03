//! Asynchronous HTTP client for Jev structured decision classification.
//!
//! Evaluates candidate interactions against natural-language moderation rubrics
//! using TypeSafe AI's Jev "System 1" model or compatible HTTP endpoints.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::classifier::{Classifier, RuleRubric, Verdict, ViolationCategory};
use crate::error::SkybouncerError;
use crate::matcher::Interaction;

/// Default endpoint URL for Jev classification API.
pub const DEFAULT_JEV_BASE_URL: &str = "https://api.jev.ai";

/// Default model identifier for Jev classification.
pub const DEFAULT_JEV_MODEL: &str = "jev-system1-mod-v1";

/// Default timeout in milliseconds for Jev API requests.
pub const DEFAULT_JEV_TIMEOUT_MS: u64 = 15000;

/// Default maximum retry count on transient errors.
pub const DEFAULT_JEV_MAX_RETRIES: usize = 1;

/// Configuration parameters for [`JevClassifier`].
#[derive(Debug, Clone)]
pub struct JevConfig {
    /// Base URL of the Jev classification API (e.g. `<https://api.jev.ai>`).
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
    /// - `JEV_API_BASE_URL`: Base URL (defaults to `<https://api.jev.ai>`)
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
    /// Optional base64-encoded visual image attachments for multimodal models.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<String>>,
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

/// The detected or configured protocol dialect for Jev-like endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JevEndpointKind {
    /// Standard Jev endpoint (`POST /v1/classify`).
    StandardJev,
    /// Ollama native chat endpoint (`POST /api/chat`).
    Ollama,
    /// System-One decision gateway endpoint (`POST /v1/systemone`).
    SystemOne,
}

impl JevEndpointKind {
    /// Returns the static string representation of the endpoint kind.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StandardJev => "standard_jev",
            Self::Ollama => "ollama",
            Self::SystemOne => "system_one",
        }
    }
}

/// Outbound conversational message for Ollama chat requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OllamaChatMessage {
    /// Role identifier (`"system"`, `"user"`, `"assistant"`).
    pub role: String,
    /// Text content of the message.
    pub content: String,
    /// Optional base64-encoded visual image attachments for multimodal models.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<String>>,
}

/// Outbound request payload for Ollama chat classification (`/api/chat`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OllamaChatRequest {
    /// Target model identifier.
    pub model: String,
    /// Sequence of conversational messages.
    pub messages: Vec<OllamaChatMessage>,
    /// Format specification (`"json"` for structured output).
    pub format: String,
    /// Whether to stream partial tokens (always `false` for classification).
    pub stream: bool,
}

/// Inbound response payload from Ollama chat classification (`/api/chat`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OllamaChatResponse {
    /// Evaluated model identifier.
    #[serde(default)]
    pub model: Option<String>,
    /// Assistant response message containing the structured JSON decision.
    pub message: OllamaChatMessage,
    /// Completion indicator.
    #[serde(default)]
    pub done: bool,
}

/// A typed classification question submitted to the System-One Decision Gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneQuestion {
    /// Question type (always `"choice"` for classification).
    #[serde(rename = "type")]
    pub kind: String,
    /// Mapping of discrete option keys to descriptive criteria.
    pub criteria: std::collections::BTreeMap<String, String>,
}

/// Outbound request payload for the System-One Decision Gateway (`/v1/systemone`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneRequest {
    /// Target model identifier override (e.g. `"tev1"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Text state to evaluate.
    pub state: String,
    /// Dictionary of typed decision questions.
    pub questions: std::collections::BTreeMap<String, SystemOneQuestion>,
}

/// Evaluated answer returned by the System-One Decision Gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneAnswer {
    /// Question type (e.g. `"choice"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// The winning discrete option choice (e.g. `"crypto_spam"`, `"permitted"`).
    pub choice: String,
    /// Probability distribution over evaluated choices.
    #[serde(default)]
    pub probabilities: Option<std::collections::BTreeMap<String, f64>>,
    /// Aggregate confidence score for the selected choice.
    #[serde(default)]
    pub confidence: Option<f64>,
}

/// Inbound response payload from the System-One Decision Gateway (`/v1/systemone`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemOneResponse {
    /// Evaluated model identifier.
    #[serde(default)]
    pub model: Option<String>,
    /// Dictionary of evaluated question answers.
    pub answers: std::collections::BTreeMap<String, SystemOneAnswer>,
}

/// Asynchronous HTTP client evaluating ATProto interactions against Jev APIs.
#[derive(Debug, Clone)]
pub struct JevClassifier {
    config: JevConfig,
    rubric: Arc<RwLock<RuleRubric>>,
    http_client: reqwest::Client,
    classify_url: String,
    endpoint_kind: JevEndpointKind,
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

        let (endpoint_kind, classify_url) = if base.contains(":8000")
            || base.ends_with("/systemone")
            || base.ends_with("/v1/systemone")
            || base.ends_with("/auto")
            || base.ends_with("/v1/auto")
        {
            let url = if base.ends_with("/v1/systemone")
                || base.ends_with("/v1/auto")
                || base.ends_with("/systemone")
                || base.ends_with("/auto")
            {
                base.to_string()
            } else {
                format!("{base}/v1/systemone")
            };
            (JevEndpointKind::SystemOne, url)
        } else if base.contains(":11434")
            || base.ends_with("/api/chat")
            || base.ends_with("/api/generate")
        {
            let url = if base.ends_with("/api/chat") {
                base.to_string()
            } else if base.ends_with("/api") {
                format!("{base}/chat")
            } else {
                format!("{base}/api/chat")
            };
            (JevEndpointKind::Ollama, url)
        } else {
            let url = if base.ends_with("/v1/classify") {
                base.to_string()
            } else if base.ends_with("/v1") {
                format!("{base}/classify")
            } else {
                format!("{base}/v1/classify")
            };
            (JevEndpointKind::StandardJev, url)
        };

        // Validate resolved URL
        url::Url::parse(&classify_url).map_err(|e| {
            SkybouncerError::Config(format!("Invalid Jev endpoint URL '{classify_url}': {e}"))
        })?;

        Ok(Self {
            config,
            rubric: Arc::new(RwLock::new(rubric)),
            http_client,
            classify_url,
            endpoint_kind,
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

    /// Returns a copy of the active [`RuleRubric`].
    #[must_use]
    pub fn rubric(&self) -> RuleRubric {
        self.rubric.read().clone()
    }

    /// Dynamically updates the active moderation rubric in thread-safe memory.
    pub fn set_rubric(&self, rubric: RuleRubric) {
        *self.rubric.write() = rubric;
    }

    /// Returns the resolved classification URL string.
    #[must_use]
    pub fn classify_url(&self) -> &str {
        &self.classify_url
    }

    /// Returns the detected [`JevEndpointKind`].
    #[must_use]
    pub fn endpoint_kind(&self) -> JevEndpointKind {
        self.endpoint_kind
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

            let (rubric_prompt, sensitivity_str) = {
                let r = self.rubric.read();
                (r.prompt.clone(), r.sensitivity.as_str().to_string())
            };

            let images = interaction
                .enriched_context
                .as_ref()
                .map(|ctx| ctx.images_base64.clone())
                .filter(|imgs| !imgs.is_empty());

            let send_result = match self.endpoint_kind {
                JevEndpointKind::StandardJev => {
                    let payload = JevClassifyRequest {
                        model: self.config.model.clone(),
                        text: interaction.text.clone(),
                        rubric: rubric_prompt.clone(),
                        context: JevRequestContext {
                            author_did: interaction.author_did.clone(),
                            target_did: interaction.target_did.clone(),
                            interaction_type: interaction.interaction_type.as_str().to_string(),
                        },
                        sensitivity: sensitivity_str,
                        images,
                    };
                    request_builder.json(&payload).send().await
                }
                JevEndpointKind::Ollama => {
                    let has_images = images
                        .as_ref()
                        .map(|imgs| !imgs.is_empty())
                        .unwrap_or(false);
                    let system_prompt = if has_images {
                        format!(
                            "You are an automated multimodal content moderation classifier. \
                            Evaluate candidate posts and any attached visual images (including embedded text, screenshots, or graphics) against this rubric: \"{rubric_prompt}\". \
                            Output ONLY a single valid JSON object matching: \
                            {{\"violates\": boolean, \"category\": string or null, \"confidence\": float (0.0 to 1.0), \"reason\": string}}"
                        )
                    } else {
                        format!(
                            "You are an automated content moderation classifier. \
                            Evaluate candidate posts against this rubric: \"{rubric_prompt}\". \
                            Output ONLY a single valid JSON object matching: \
                            {{\"violates\": boolean, \"category\": string or null, \"confidence\": float (0.0 to 1.0), \"reason\": string}}"
                        )
                    };
                    let enrichment_str = interaction
                        .enriched_context
                        .as_ref()
                        .map(|ctx| ctx.format_for_classifier())
                        .filter(|s| !s.is_empty())
                        .map(|s| format!("\n{s}"))
                        .unwrap_or_default();

                    let user_prompt = format!(
                        "Interaction: {}\nAuthor: {}\nTarget: {}\nPost text: \"{}\"{}",
                        interaction.interaction_type.as_str(),
                        interaction.author_did,
                        interaction.target_did,
                        interaction.text,
                        enrichment_str
                    );
                    let payload = OllamaChatRequest {
                        model: self.config.model.clone(),
                        messages: vec![
                            OllamaChatMessage {
                                role: "system".to_string(),
                                content: system_prompt,
                                images: None,
                            },
                            OllamaChatMessage {
                                role: "user".to_string(),
                                content: user_prompt,
                                images,
                            },
                        ],
                        format: "json".to_string(),
                        stream: false,
                    };
                    request_builder.json(&payload).send().await
                }
                JevEndpointKind::SystemOne => {
                    let mut criteria = std::collections::BTreeMap::new();
                    criteria.insert(
                        "crypto_spam".to_string(),
                        "Cryptocurrency scam, airdrop lure, fake giveaway, wallet drainer, phishing token, or investment spam".to_string(),
                    );
                    criteria.insert(
                        "harassment".to_string(),
                        "Targeted harassment, personal attacks, insults, slurs, threats, abusive hostility".to_string(),
                    );
                    criteria.insert(
                        "phishing".to_string(),
                        "Credential harvesting, phishing links, fake account suspension warnings, fake security alerts, or malicious links".to_string(),
                    );
                    criteria.insert(
                        "sealioning_or_bad_faith".to_string(),
                        "Bad-faith sea-lioning, disingenuous badgering, relentless interrogation, feigned ignorance, or debate-bro trolling".to_string(),
                    );
                    criteria.insert(
                        "spam".to_string(),
                        format!(
                            "Unsolicited promotional spam, mass-mention tag spam, unsolicited livestream or channel promotion, scam bots, commercial solicitations, or content violating: {rubric_prompt}"
                        ),
                    );
                    criteria.insert(
                        "permitted".to_string(),
                        "Benign social discussion, genuine questions, technical debate, respectful disagreement, humor, or normal social chatter conforming to house rules"
                            .to_string(),
                    );
                    let mut questions = std::collections::BTreeMap::new();
                    questions.insert(
                        "moderation".to_string(),
                        SystemOneQuestion {
                            kind: "choice".to_string(),
                            criteria,
                        },
                    );
                    let enrichment_str = interaction
                        .enriched_context
                        .as_ref()
                        .map(|ctx| ctx.format_for_classifier())
                        .filter(|s| !s.is_empty())
                        .map(|s| format!("\n{s}"))
                        .unwrap_or_default();

                    let payload = SystemOneRequest {
                        model: Some(self.config.model.clone()),
                        state: format!(
                            "Interaction: {}\nAuthor: {}\nTarget: {}\nText: \"{}\"{}",
                            interaction.interaction_type.as_str(),
                            interaction.author_did,
                            interaction.target_did,
                            interaction.text,
                            enrichment_str
                        ),
                        questions,
                    };
                    request_builder.json(&payload).send().await
                }
            };

            let response = match send_result {
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
                let classify_resp = match self.endpoint_kind {
                    JevEndpointKind::StandardJev => {
                        response.json::<JevClassifyResponse>().await.map_err(|e| {
                            SkybouncerError::Classifier(format!(
                                "Failed to parse Jev JSON response: {e}"
                            ))
                        })?
                    }
                    JevEndpointKind::Ollama => {
                        let ollama_resp =
                            response.json::<OllamaChatResponse>().await.map_err(|e| {
                                SkybouncerError::Classifier(format!(
                                    "Failed to parse Ollama JSON wrapper response: {e}"
                                ))
                            })?;
                        let raw = ollama_resp.message.content.trim();
                        let cleaned = raw
                            .trim_start_matches("```json")
                            .trim_start_matches("```")
                            .trim_end_matches("```")
                            .trim();
                        serde_json::from_str::<JevClassifyResponse>(cleaned).map_err(|e| {
                            SkybouncerError::Classifier(format!(
                                "Failed to parse Ollama content as JevClassifyResponse: {e}; raw: {cleaned}"
                            ))
                        })?
                    }
                    JevEndpointKind::SystemOne => {
                        let sys_resp = response.json::<SystemOneResponse>().await.map_err(|e| {
                            SkybouncerError::Classifier(format!(
                                "Failed to parse SystemOne JSON response: {e}"
                            ))
                        })?;
                        let answer = sys_resp.answers.get("moderation").ok_or_else(|| {
                            SkybouncerError::Classifier(
                                "SystemOne response missing 'moderation' answer".to_string(),
                            )
                        })?;
                        let is_violation = answer.choice != "permitted";
                        let conf = if is_violation {
                            answer
                                .probabilities
                                .as_ref()
                                .and_then(|p| {
                                    p.get("permitted").map(|perm| (1.0 - perm).clamp(0.0, 1.0))
                                })
                                .or_else(|| {
                                    answer
                                        .probabilities
                                        .as_ref()
                                        .and_then(|p| p.get(&answer.choice).copied())
                                })
                                .or(answer.confidence)
                                .unwrap_or(0.95)
                        } else {
                            answer
                                .probabilities
                                .as_ref()
                                .and_then(|p| p.get("permitted").copied())
                                .or(answer.confidence)
                                .unwrap_or(0.95)
                        };
                        JevClassifyResponse {
                            violates: is_violation,
                            category: if is_violation {
                                Some(answer.choice.clone())
                            } else {
                                None
                            },
                            confidence: conf,
                            reason: format!(
                                "SystemOne choice '{}' with confidence {:.2}",
                                answer.choice, conf
                            ),
                        }
                    }
                };
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
        let is_actionable = self.rubric.read().is_actionable(resp.confidence);
        if resp.violates && is_actionable {
            let category = match resp.category.as_deref() {
                Some("spam") => ViolationCategory::Spam,
                Some("crypto_spam") | Some("crypto-spam") | Some("crypto") => {
                    ViolationCategory::CryptoSpam
                }
                Some("harassment") => ViolationCategory::Harassment,
                Some("sea_lioning")
                | Some("sealioning")
                | Some("sealioning_or_bad_faith")
                | Some("bad_faith") => ViolationCategory::SeaLioning,
                Some("phishing") => ViolationCategory::Phishing,
                Some("hate_speech") | Some("hatespeech") => ViolationCategory::HateSpeech,
                Some(other) => ViolationCategory::Custom(other.to_string()),
                None => ViolationCategory::Custom("unspecified".to_string()),
            };

            Verdict::violation(category, resp.confidence, resp.reason)
        } else {
            Verdict::permitted_with_confidence(resp.reason, resp.confidence)
        }
    }
}

#[async_trait]
impl Classifier for JevClassifier {
    async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError> {
        self.evaluate(interaction).await
    }

    fn set_rubric(&self, rubric: RuleRubric) {
        self.set_rubric(rubric);
    }
}
