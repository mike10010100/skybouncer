//! Stage 3 batch stance classification for candidate dogpile surges.
//!
//! Evaluates a bundled snapshot `(focal_post + top quote posts + sample replies)` in a
//! single classifier request to separate collective hostility/mockery/norm-enforcement
//! from benign viral engagement or good-faith debate.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::classifier::jev::{
    JevClassifyRequest, JevClassifyResponse, JevConfig, JevEndpointKind, JevRequestContext,
    OllamaChatMessage, OllamaChatOptions, OllamaChatRequest, OllamaChatResponse, SystemOneQuestion,
    SystemOneRequest, SystemOneResponse, DEFAULT_OLLAMA_NUM_CTX,
};
use crate::dogpile::types::{
    PostEngagementSnapshot, SampleReply, StormMetrics, StormStanceVerdict,
};
use crate::error::SkybouncerError;

/// Consolidated bundle submitted to [`StormStanceClassifier`] for Stage 3 verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StormStanceInput {
    /// Protected target account DID.
    pub target_did: String,
    /// Resolved target handle, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_handle: Option<String>,
    /// Focal post AT-URI experiencing the surge.
    pub focal_post_uri: String,
    /// Focal post engagement snapshot and body text, if resolved from AppView.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focal_post: Option<PostEngagementSnapshot>,
    /// Top quote posts referencing the focal post (ranked by engagement).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_quotes: Vec<PostEngagementSnapshot>,
    /// Bounded sample of out-of-network replies/quotes targeting the focal post.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample_replies: Vec<SampleReply>,
    /// Current structural metrics computed from Stage 1 and Stage 2.
    pub metrics: StormMetrics,
}

/// Asynchronous Stage 3 batch stance classifier for candidate dogpiles.
#[async_trait]
pub trait StormStanceClassifier: Send + Sync {
    /// Evaluates a surge bundle and returns a [`StormStanceVerdict`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Classifier`] when no LLM endpoint is configured or on
    /// transport/parse failure, signaling the engine to fall back to structural scoring.
    async fn classify_storm(
        &self,
        input: &StormStanceInput,
    ) -> Result<StormStanceVerdict, SkybouncerError>;

    /// Returns the human-readable identifier of the underlying stance model.
    fn model_name(&self) -> &str {
        "storm-stance"
    }
}

/// No-op stance classifier used when no LLM endpoint is configured.
///
/// Always returns an error so the engine transparently falls back to structural-only scoring.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopStormStanceClassifier;

#[async_trait]
impl StormStanceClassifier for NoopStormStanceClassifier {
    async fn classify_storm(
        &self,
        _input: &StormStanceInput,
    ) -> Result<StormStanceVerdict, SkybouncerError> {
        Err(SkybouncerError::Classifier(
            "Storm stance LLM classifier is not configured".to_string(),
        ))
    }

    fn model_name(&self) -> &str {
        "structural_fallback"
    }
}

/// Deterministic mock stance classifier for hermetic unit and integration tests.
#[derive(Debug, Clone)]
pub struct MockStormStanceClassifier {
    verdict: Arc<RwLock<Result<StormStanceVerdict, String>>>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl MockStormStanceClassifier {
    /// Creates a mock returning `verdict` for every surge evaluation.
    #[must_use]
    pub fn new(verdict: StormStanceVerdict) -> Self {
        Self {
            verdict: Arc::new(RwLock::new(Ok(verdict))),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Creates a mock returning an error (simulating LLM outage / structural fallback).
    #[must_use]
    pub fn failing(reason: impl Into<String>) -> Self {
        Self {
            verdict: Arc::new(RwLock::new(Err(reason.into()))),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Updates the verdict returned on subsequent calls.
    pub fn set_verdict(&self, verdict: StormStanceVerdict) {
        *self.verdict.write() = Ok(verdict);
    }

    /// Returns the total number of `classify_storm` calls observed.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl StormStanceClassifier for MockStormStanceClassifier {
    async fn classify_storm(
        &self,
        _input: &StormStanceInput,
    ) -> Result<StormStanceVerdict, SkybouncerError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match &*self.verdict.read() {
            Ok(v) => Ok(v.clone()),
            Err(msg) => Err(SkybouncerError::Classifier(msg.clone())),
        }
    }

    fn model_name(&self) -> &str {
        "mock-storm-stance"
    }
}

#[derive(Debug, Deserialize)]
struct OllamaStormJson {
    collective_hostility: bool,
    confidence: f64,
    #[serde(default)]
    classification: Option<String>,
    #[serde(default)]
    summary: Option<String>,
}

/// LLM-backed batch stance classifier reusing [`JevConfig`] (`Ollama`, `StandardJev`, or `SystemOne`).
#[derive(Debug, Clone)]
pub struct LlmStormStanceClassifier {
    config: JevConfig,
    http_client: reqwest::Client,
    endpoint_url: String,
    endpoint_kind: JevEndpointKind,
    num_ctx: usize,
}

impl LlmStormStanceClassifier {
    /// Creates a new [`LlmStormStanceClassifier`] from a [`JevConfig`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if the HTTP client or endpoint URL is invalid.
    pub fn new(config: JevConfig) -> Result<Self, SkybouncerError> {
        let http_client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(config.timeout)
            .build()
            .map_err(|e| {
                SkybouncerError::Config(format!("Failed to build stance HTTP client: {e}"))
            })?;
        Self::with_client(config, http_client)
    }

    /// Creates a new [`LlmStormStanceClassifier`] reusing a supplied [`reqwest::Client`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if the endpoint URL is malformed.
    pub fn with_client(
        config: JevConfig,
        http_client: reqwest::Client,
    ) -> Result<Self, SkybouncerError> {
        let base = config.base_url.trim_end_matches('/');
        let (endpoint_kind, endpoint_url) = if base.contains(":8000")
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

        url::Url::parse(&endpoint_url).map_err(|e| {
            SkybouncerError::Config(format!(
                "Invalid storm stance endpoint URL '{endpoint_url}': {e}"
            ))
        })?;

        let num_ctx = crate::env::parsed_or(
            &[
                "OLLAMA_NUM_CTX",
                "SKYBOUNCER_OLLAMA_NUM_CTX",
                "JEV_NUM_CTX",
                "FALLBACK_NUM_CTX",
            ],
            DEFAULT_OLLAMA_NUM_CTX,
        )
        .max(1024);

        Ok(Self {
            config,
            http_client,
            endpoint_url,
            endpoint_kind,
            num_ctx,
        })
    }

    /// Returns the detected endpoint dialect.
    #[must_use]
    pub const fn endpoint_kind(&self) -> JevEndpointKind {
        self.endpoint_kind
    }

    /// Returns the resolved HTTP URL used for stance classification requests.
    #[must_use]
    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }

    /// Formats a compact, bounded prompt summarizing the focal post, top quotes,
    /// structural signals, and sampled out-of-network replies.
    #[must_use]
    pub fn format_bundle_prompt(input: &StormStanceInput) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(2048);

        let target_label = input
            .target_handle
            .as_deref()
            .map(|h| {
                format!(
                    "@{} ({})",
                    crate::util::normalize_handle(h),
                    input.target_did
                )
            })
            .unwrap_or_else(|| input.target_did.clone());

        let _ = writeln!(out, "Target User: {target_label}");
        let _ = writeln!(out, "Focal Post URI: {}", input.focal_post_uri);

        if let Some(ref focal) = input.focal_post {
            let snippet: String = focal.text.chars().take(500).collect();
            let _ = writeln!(
                out,
                "Target's Focal Post (likes={}, reposts={}, replies={}, quotes={}): \"{}\"",
                focal.like_count, focal.repost_count, focal.reply_count, focal.quote_count, snippet
            );
        }

        let _ = writeln!(
            out,
            "Surge Metrics (5m): unique_oon_authors={}, oon_ratio={:.0}%, direct_ratio={:.2}, dunk_ratio={:.2}, power_asymmetry={:.1}x, defensive_blocks={}, defensive_detaches={}",
            input.metrics.unique_oon_authors_short,
            input.metrics.out_of_network_ratio * 100.0,
            input.metrics.direct_ratio,
            input.metrics.dunk_ratio,
            input.metrics.power_asymmetry,
            input.metrics.defensive_blocks,
            input.metrics.defensive_detaches
        );

        if !input.top_quotes.is_empty() {
            out.push_str("\nTop Amplifying Quote Posts:\n");
            for (idx, qt) in input.top_quotes.iter().take(3).enumerate() {
                let handle = qt
                    .author_handle
                    .as_deref()
                    .map(|h| format!("@{}", crate::util::normalize_handle(h)))
                    .unwrap_or_else(|| qt.author_did.clone());
                let snippet: String = qt.text.chars().take(280).collect();
                let _ = writeln!(
                    out,
                    "{}. {} (followers={:?}, likes={}, reposts={}, quotes={}): \"{}\"",
                    idx + 1,
                    handle,
                    qt.author_followers,
                    qt.like_count,
                    qt.repost_count,
                    qt.quote_count,
                    snippet
                );
            }
        }

        if !input.sample_replies.is_empty() {
            out.push_str("\nSample Out-of-Network Incoming Interactions:\n");
            for (idx, rep) in input.sample_replies.iter().take(15).enumerate() {
                let snippet: String = rep.text_snippet.chars().take(220).collect();
                let _ = writeln!(
                    out,
                    "{}. [{}] {}: \"{}\"",
                    idx + 1,
                    rep.interaction_type,
                    rep.author_did,
                    snippet
                );
            }
        }

        out
    }

    async fn read_bounded_error_body(response: reqwest::Response) -> String {
        use futures_util::StreamExt;
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk_res) = stream.next().await {
            if let Ok(chunk) = chunk_res {
                let remaining = 4096_usize.saturating_sub(body.len());
                let to_take = chunk.len().min(remaining);
                body.extend_from_slice(&chunk[..to_take]);
                if body.len() >= 4096 {
                    break;
                }
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&body).trim().to_string()
    }
}

#[async_trait]
impl StormStanceClassifier for LlmStormStanceClassifier {
    async fn classify_storm(
        &self,
        input: &StormStanceInput,
    ) -> Result<StormStanceVerdict, SkybouncerError> {
        let bundle = Self::format_bundle_prompt(input);
        let mut last_err = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            let mut req = self
                .http_client
                .post(&self.endpoint_url)
                .header("Content-Type", "application/json");
            if let Some(ref key) = self.config.api_key {
                req = req.header("Authorization", format!("Bearer {key}"));
            }

            let send_res = match self.endpoint_kind {
                JevEndpointKind::Ollama => {
                    let system_prompt = "You are a Trust & Safety analyst classifying whether a sudden wave of out-of-network replies and quote-posts directed at a Bluesky user is a hostile dogpile / pile-on / mass mockery vs. benign viral engagement or ordinary topic debate. \
                    Look at the COLLECTIVE stance across the top quote-posts and sample replies (including sarcastic dismissal, mocking memes, piling-on insults, 'delete your account' / ratio gloating, and norm-enforcing scolding aimed at Target). \
                    Open-ended viral prompts (e.g. 'post your pets', 'what is your favorite film') and enthusiastic praise or friendly replies are 'benign_viral' (collective_hostility = false). \
                    Disagreement about an external topic without piling onto Target personally is 'heated_debate' (collective_hostility = false). \
                    Output ONLY valid JSON: {\"collective_hostility\": boolean, \"confidence\": float (0.0 to 1.0), \"classification\": \"dogpile\" | \"heated_debate\" | \"benign_viral\", \"summary\": string (<= 160 chars)}.";

                    let payload = OllamaChatRequest {
                        model: self.config.model.clone(),
                        messages: vec![
                            OllamaChatMessage {
                                role: "system".to_string(),
                                content: system_prompt.to_string(),
                                images: None,
                            },
                            OllamaChatMessage {
                                role: "user".to_string(),
                                content: bundle.clone(),
                                images: None,
                            },
                        ],
                        format: "json".to_string(),
                        stream: false,
                        options: OllamaChatOptions {
                            num_ctx: self.num_ctx,
                            temperature: 0.0,
                        },
                    };
                    req.json(&payload).send().await
                }
                JevEndpointKind::StandardJev => {
                    let payload = JevClassifyRequest {
                        model: self.config.model.clone(),
                        text: bundle.clone(),
                        rubric: "Classify whether this interaction bundle represents a hostile dogpile, pile-on, or mass mockery directed at Target (violates = true), versus benign viral participation or ordinary debate (violates = false).".to_string(),
                        context: JevRequestContext {
                            author_did: input
                                .top_quotes
                                .first()
                                .map_or_else(|| input.target_did.clone(), |q| q.author_did.clone()),
                            target_did: input.target_did.clone(),
                            interaction_type: "dogpile_bundle".to_string(),
                        },
                        sensitivity: "medium".to_string(),
                        images: None,
                    };
                    req.json(&payload).send().await
                }
                JevEndpointKind::SystemOne => {
                    let mut criteria = std::collections::BTreeMap::new();
                    criteria.insert(
                        "dogpile".to_string(),
                        "Collective hostile pile-on, dunk cascade, coordinated mockery, or norm-enforcing harassment directed at Target".to_string(),
                    );
                    criteria.insert(
                        "heated_debate".to_string(),
                        "Substantive disagreement or argument over a topic/policy without collective personal hostility aimed at Target".to_string(),
                    );
                    criteria.insert(
                        "benign_viral".to_string(),
                        "Benign viral prompt, meme participation, praise, or friendly engagement"
                            .to_string(),
                    );
                    let mut questions = std::collections::BTreeMap::new();
                    questions.insert(
                        "storm_stance".to_string(),
                        SystemOneQuestion {
                            kind: "choice".to_string(),
                            criteria,
                        },
                    );
                    let payload = SystemOneRequest {
                        model: Some(self.config.model.clone()),
                        state: bundle.clone(),
                        questions,
                        images: None,
                    };
                    req.json(&payload).send().await
                }
            };

            let resp = match send_res {
                Ok(r) => r,
                Err(err) => {
                    last_err = Some(SkybouncerError::Classifier(format!(
                        "Storm stance network error: {err}"
                    )));
                    continue;
                }
            };

            let status = resp.status();
            if status.is_success() {
                let verdict = match self.endpoint_kind {
                    JevEndpointKind::Ollama => {
                        let parsed_wrap = resp.json::<OllamaChatResponse>().await.map_err(|e| {
                            SkybouncerError::Classifier(format!(
                                "Failed to parse Ollama stance wrapper: {e}"
                            ))
                        })?;
                        let raw = parsed_wrap.message.content.trim();
                        let cleaned = raw
                            .trim_start_matches("```json")
                            .trim_start_matches("```")
                            .trim_end_matches("```")
                            .trim();
                        let parsed =
                            serde_json::from_str::<OllamaStormJson>(cleaned).map_err(|e| {
                                SkybouncerError::Classifier(format!(
                                    "Failed to parse Ollama storm stance JSON: {e}; raw: {cleaned}"
                                ))
                            })?;
                        let default_class = if parsed.collective_hostility {
                            "dogpile"
                        } else {
                            "benign_viral"
                        };
                        StormStanceVerdict::new(
                            parsed.collective_hostility,
                            parsed.confidence,
                            parsed
                                .classification
                                .unwrap_or_else(|| default_class.to_string()),
                            parsed.summary.unwrap_or_default(),
                            self.config.model.clone(),
                        )
                    }
                    JevEndpointKind::StandardJev => {
                        let parsed = resp.json::<JevClassifyResponse>().await.map_err(|e| {
                            SkybouncerError::Classifier(format!(
                                "Failed to parse StandardJev stance JSON: {e}"
                            ))
                        })?;
                        let classification = if parsed.violates {
                            parsed.category.unwrap_or_else(|| "dogpile".to_string())
                        } else {
                            "benign_viral".to_string()
                        };
                        StormStanceVerdict::new(
                            parsed.violates,
                            parsed.confidence,
                            classification,
                            parsed.reason,
                            self.config.model.clone(),
                        )
                    }
                    JevEndpointKind::SystemOne => {
                        let parsed = resp.json::<SystemOneResponse>().await.map_err(|e| {
                            SkybouncerError::Classifier(format!(
                                "Failed to parse SystemOne stance JSON: {e}"
                            ))
                        })?;
                        let answer = parsed.answers.get("storm_stance").ok_or_else(|| {
                            SkybouncerError::Classifier(
                                "SystemOne stance response missing 'storm_stance' answer"
                                    .to_string(),
                            )
                        })?;
                        let conf = answer
                            .probabilities
                            .as_ref()
                            .and_then(|p| p.get(&answer.choice).copied())
                            .or(answer.confidence)
                            .unwrap_or(0.5);
                        let is_dogpile = answer.choice == "dogpile";
                        StormStanceVerdict::new(
                            is_dogpile,
                            conf,
                            answer.choice.clone(),
                            format!(
                                "SystemOne stance '{}' ({:.0}% confidence)",
                                answer.choice,
                                conf * 100.0
                            ),
                            self.config.model.clone(),
                        )
                    }
                };
                return Ok(verdict);
            }

            if status.is_client_error() {
                let err_body = Self::read_bounded_error_body(resp).await;
                return Err(SkybouncerError::Classifier(format!(
                    "Storm stance client error (HTTP {}): {err_body}",
                    status.as_u16()
                )));
            }

            let err_body = Self::read_bounded_error_body(resp).await;
            last_err = Some(SkybouncerError::Classifier(format!(
                "Storm stance server error (HTTP {}): {err_body}",
                status.as_u16()
            )));
        }

        Err(last_err.unwrap_or_else(|| {
            SkybouncerError::Classifier("Storm stance request failed after retries".to_string())
        }))
    }

    fn model_name(&self) -> &str {
        &self.config.model
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::matcher::InteractionType;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_input() -> StormStanceInput {
        StormStanceInput {
            target_did: "did:plc:alice".to_string(),
            target_handle: Some("alice.bsky.social".to_string()),
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3root".to_string(),
            focal_post: Some(PostEngagementSnapshot {
                uri: "at://did:plc:alice/app.bsky.feed.post/3root".to_string(),
                author_did: "did:plc:alice".to_string(),
                author_handle: Some("alice.bsky.social".to_string()),
                author_followers: Some(300),
                text: "Hot take on coffee".to_string(),
                reply_count: 50,
                repost_count: 1,
                like_count: 4,
                quote_count: 15,
            }),
            top_quotes: vec![PostEngagementSnapshot {
                uri: "at://did:plc:big/app.bsky.feed.post/qt1".to_string(),
                author_did: "did:plc:big".to_string(),
                author_handle: Some("big.bsky.social".to_string()),
                author_followers: Some(90_000),
                text: "Look at this clown".to_string(),
                reply_count: 10,
                repost_count: 80,
                like_count: 900,
                quote_count: 5,
            }],
            sample_replies: vec![SampleReply {
                author_did: "did:plc:r1".to_string(),
                interaction_type: InteractionType::DirectReply,
                post_uri: "at://did:plc:r1/app.bsky.feed.post/1".to_string(),
                text_snippet: "delete your account".to_string(),
            }],
            metrics: StormMetrics {
                unique_oon_authors_short: 25,
                out_of_network_ratio: 0.95,
                direct_ratio: 13.0,
                dunk_ratio: 180.0,
                power_asymmetry: 290.0,
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn noop_and_mock_stance_classifiers() {
        let noop = NoopStormStanceClassifier;
        assert_eq!(noop.model_name(), "structural_fallback");
        assert!(noop.classify_storm(&sample_input()).await.is_err());

        let mock = MockStormStanceClassifier::new(StormStanceVerdict::new(
            true,
            0.91,
            "dogpile",
            "Hostile wave",
            "mock",
        ));
        assert_eq!(mock.model_name(), "mock-storm-stance");
        let v = mock.classify_storm(&sample_input()).await.unwrap();
        assert!(v.collective_hostility);
        assert_eq!(mock.call_count(), 1);
        mock.set_verdict(StormStanceVerdict::new(
            false,
            0.85,
            "benign_viral",
            "ok",
            "mock",
        ));
        let v2 = mock.classify_storm(&sample_input()).await.unwrap();
        assert!(!v2.collective_hostility);

        let failing = MockStormStanceClassifier::failing("down");
        assert!(failing.classify_storm(&sample_input()).await.is_err());
    }

    #[tokio::test]
    async fn llm_stance_supports_ollama_systemone_standard_and_error_paths() {
        // 1. Ollama dialect
        let ollama = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "gemma4:26b",
                "message": {
                    "role": "assistant",
                    "content": "```json\n{\"collective_hostility\": true, \"confidence\": 0.93, \"classification\": \"dogpile\", \"summary\": \"Mockery wave from large quote post\"}\n```"
                },
                "done": true
            })))
            .mount(&ollama)
            .await;

        let cfg = JevConfig {
            base_url: format!("{}/api/chat", ollama.uri()),
            model: "gemma4:26b".to_string(),
            max_retries: 0,
            ..Default::default()
        };
        let cls = LlmStormStanceClassifier::new(cfg).unwrap();
        assert_eq!(cls.endpoint_kind(), JevEndpointKind::Ollama);
        assert_eq!(cls.model_name(), "gemma4:26b");
        let v = cls.classify_storm(&sample_input()).await.unwrap();
        assert!(v.collective_hostility);
        assert_eq!(v.classification, "dogpile");
        assert!((v.confidence - 0.93).abs() < 1e-6);

        // 2. SystemOne dialect
        let sys1 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "tev1",
                "answers": {
                    "storm_stance": {
                        "type": "choice",
                        "choice": "benign_viral",
                        "probabilities": {"benign_viral": 0.94, "dogpile": 0.03}
                    }
                }
            })))
            .mount(&sys1)
            .await;

        let sys_cfg = JevConfig {
            base_url: format!("{}/v1/systemone", sys1.uri()),
            model: "tev1".to_string(),
            max_retries: 0,
            ..Default::default()
        };
        let sys_cls = LlmStormStanceClassifier::new(sys_cfg).unwrap();
        assert_eq!(sys_cls.endpoint_kind(), JevEndpointKind::SystemOne);
        let sv = sys_cls.classify_storm(&sample_input()).await.unwrap();
        assert!(!sv.collective_hostility);
        assert_eq!(sv.classification, "benign_viral");

        // 3. StandardJev dialect
        let jev = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/classify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "violates": true,
                "category": "harassment",
                "confidence": 0.88,
                "reason": "Mass mockery"
            })))
            .mount(&jev)
            .await;

        let jev_cfg = JevConfig {
            base_url: jev.uri(),
            api_key: Some("secret".to_string()),
            model: "jev-v1".to_string(),
            max_retries: 0,
            ..Default::default()
        };
        let jev_cls = LlmStormStanceClassifier::new(jev_cfg).unwrap();
        assert_eq!(jev_cls.endpoint_kind(), JevEndpointKind::StandardJev);
        let jv = jev_cls.classify_storm(&sample_input()).await.unwrap();
        assert!(jv.collective_hostility);
        assert_eq!(jv.summary, "Mass mockery");

        // 4. 4xx error fails cleanly without retry
        let bad = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/classify"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad input"))
            .expect(1)
            .mount(&bad)
            .await;
        let bad_cls = LlmStormStanceClassifier::new(JevConfig {
            base_url: bad.uri(),
            max_retries: 1,
            ..Default::default()
        })
        .unwrap();
        assert!(bad_cls.classify_storm(&sample_input()).await.is_err());

        // 5. 5xx retries once and returns error
        let err5 = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/classify"))
            .respond_with(ResponseTemplate::new(503).set_body_string("overloaded"))
            .expect(2)
            .mount(&err5)
            .await;
        let err5_cls = LlmStormStanceClassifier::new(JevConfig {
            base_url: err5.uri(),
            max_retries: 1,
            ..Default::default()
        })
        .unwrap();
        assert!(err5_cls.classify_storm(&sample_input()).await.is_err());
    }
}
