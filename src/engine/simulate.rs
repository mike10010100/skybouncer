//! Dry-run evaluation simulation shared by the web `/api/simulate` handler and
//! the CLI `simulate` subcommand.
//!
//! Runs the interaction through the zero-cost heuristic pre-filter and then the
//! tiered primary classifier, producing a [`SimulationResult`] with per-tier
//! breakdowns. No PDS mutations are performed and no evaluation-log entry is
//! written; callers decide whether to persist an audit record.

use crate::classifier::Verdict;
use crate::error::SkybouncerError;
use crate::matcher::{Interaction, InteractionType};
use crate::modlist::cache::{EvaluationLogContext, NewEvaluationLog};
use crate::types::now_iso8601;

/// Per-tier evaluation detail for a [`SimulationResult`].
#[derive(Debug, Clone, PartialEq)]
pub struct SimulateTierStage {
    /// Human-readable stage label (e.g. "Tier 1 • System-1 Fast Text").
    pub stage_name: String,
    /// Model identifier used for this stage.
    pub model: String,
    /// Stage status ("resolved", "escalated", or "bypassed").
    pub status: String,
    /// Whether this stage classified the interaction as a violation.
    pub violates: bool,
    /// Violation category emitted by this stage, if any.
    pub category: Option<String>,
    /// Confidence score emitted by this stage.
    pub confidence: f64,
    /// Rationale emitted by this stage.
    pub reason: String,
}

/// Result of a dry-run simulation.
#[derive(Debug, Clone, PartialEq)]
pub struct SimulationResult {
    /// Whether the interaction was classified as a violation.
    pub violates: bool,
    /// Category of violation detected, if applicable.
    pub category: Option<String>,
    /// Observed classifier confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Rationale or explanatory reason for the verdict.
    pub reason: String,
    /// Which evaluator produced the verdict.
    pub evaluator: String,
    /// Whether the confidence score meets or exceeds the rubric threshold.
    pub meets_threshold: bool,
    /// Active sensitivity threshold required for action.
    pub threshold: f64,
    /// Number of images decoded and inspected during evaluation.
    pub images_evaluated: usize,
    /// Detailed Tier-1 System-1 evaluation stage.
    pub tier1: Option<SimulateTierStage>,
    /// Detailed Tier-2 System-2 fallback evaluation stage.
    pub tier2: Option<SimulateTierStage>,
    /// Whether the synthetic interaction carried a URL-fetched image.
    pub fetched_url_image: bool,
    /// Evaluation timestamp (ISO-8601).
    pub created_at: String,
}

/// Inputs for [`crate::engine::SkybouncerEngine::run_simulation`].
#[derive(Debug, Clone, Default)]
pub struct SimulationInputs {
    /// Sample post text to evaluate.
    pub text: String,
    /// Synthetic author DID.
    pub author_did: String,
    /// Target protected DID whose rubric governs the evaluation.
    pub target_did: String,
    /// Optional base64-encoded image attached to the candidate post.
    pub image_base64: Option<String>,
    /// Whether the image originated from a URL (affects the reported post URI/label).
    pub fetched_url_image: bool,
    /// Whether to persist a `source = "simulation"` audit log entry for this run.
    pub persist_log: bool,
}

impl SimulationInputs {
    /// Creates simulation inputs for the given text, author, and target (no log persistence).
    #[must_use]
    pub fn new(
        text: impl Into<String>,
        author_did: impl Into<String>,
        target_did: impl Into<String>,
    ) -> Self {
        Self {
            text: text.into(),
            author_did: author_did.into(),
            target_did: target_did.into(),
            image_base64: None,
            fetched_url_image: false,
            persist_log: false,
        }
    }

    /// Attaches a base64-encoded image, flagging whether it came from a URL.
    #[must_use]
    pub fn with_image(mut self, base64: Option<String>, fetched_url: bool) -> Self {
        self.image_base64 = base64;
        self.fetched_url_image = fetched_url;
        self
    }

    /// Enables or disables persistence of a simulation audit log entry.
    #[must_use]
    pub fn with_persist_log(mut self, persist_log: bool) -> Self {
        self.persist_log = persist_log;
        self
    }
}

impl crate::engine::SkybouncerEngine {
    /// Runs a dry-run evaluation of `inputs` through the heuristic pre-filter and
    /// tiered classifier, returning a [`SimulationResult`].
    ///
    /// Performs no PDS mutations and writes no evaluation-log entry; the caller is
    /// responsible for any audit persistence.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the classifier evaluation fails.
    pub async fn run_simulation(
        &self,
        inputs: SimulationInputs,
    ) -> Result<SimulationResult, SkybouncerError> {
        let SimulationInputs {
            text,
            author_did,
            target_did,
            image_base64,
            fetched_url_image,
            persist_log,
        } = inputs;

        let rubric = self.rubric_for(&target_did);
        let threshold = rubric.sensitivity.threshold();

        let mut image_cids = Vec::new();
        let mut images_base64 = Vec::new();
        if let Some(b64) = image_base64.filter(|s| !s.trim().is_empty()) {
            images_base64.push(b64);
            image_cids.push(if fetched_url_image {
                "simulate-url-image".to_string()
            } else {
                "simulate-base64-image".to_string()
            });
        }
        let images_evaluated = images_base64.len();

        let enriched_context = if images_base64.is_empty() {
            None
        } else {
            let mut ctx = crate::enricher::EnrichedContext::empty();
            ctx.images_base64 = images_base64;
            Some(ctx)
        };

        let post_uri = if fetched_url_image {
            format!("at://{author_did}/app.bsky.feed.post/simulated")
        } else {
            "at://did:plc:sample/app.bsky.feed.post/sample123".to_string()
        };

        let interaction = Interaction::synthetic(
            &author_did,
            &target_did,
            &text,
            InteractionType::DirectReply,
        )
        .with_post_uri(&post_uri)
        .with_post_cid("bafysample123")
        .with_images(image_cids, Vec::new())
        .with_enriched_context_opt(enriched_context)
        .with_rubric(rubric.clone());

        let created_at = now_iso8601();

        // 1. Zero-cost heuristic pre-filter.
        let heuristic_verdict = self.heuristic_classifier().evaluate(&interaction);
        if let Verdict::Violation {
            category,
            confidence,
            reason,
        } = heuristic_verdict
        {
            let meets_threshold = rubric.meets_threshold(&category, confidence);
            if persist_log {
                let log = NewEvaluationLog::heuristic(
                    &interaction,
                    &format!("at://{author_did}/app.bsky.feed.post/simulated"),
                    &Verdict::Violation {
                        category: category.clone(),
                        confidence: 1.0,
                        reason: reason.clone(),
                    },
                    EvaluationLogContext {
                        source: "simulation",
                        outcome: "Simulated: Would Bounce (Regex Pre-filter)",
                    },
                    "simulated-test.bsky.social".to_string(),
                    self.target_handle(&target_did),
                );
                if let Err(e) = self.cache.record_evaluation_log(&log) {
                    tracing::warn!(error = %e, "Failed to record simulated evaluation log");
                }
            }
            let bypassed = |stage_name: &str, model: &str, reason: &str| SimulateTierStage {
                stage_name: stage_name.to_string(),
                model: model.to_string(),
                status: "bypassed".to_string(),
                violates: false,
                category: None,
                confidence: 0.0,
                reason: reason.to_string(),
            };
            return Ok(SimulationResult {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                reason,
                evaluator: "heuristic_prefilter".to_string(),
                meets_threshold,
                threshold,
                images_evaluated,
                tier1: Some(bypassed(
                    "Tier 1 • System-1 Fast Text",
                    "nimble",
                    "Bypassed: Heuristic regex pre-filter matched instantly (0ms)",
                )),
                tier2: Some(bypassed(
                    "Tier 2 • System-2 Fallback",
                    "gemma4:12b",
                    "Bypassed: Heuristic regex pre-filter matched instantly (0ms)",
                )),
                fetched_url_image,
                created_at,
            });
        }
        let detailed = self
            .primary_classifier()
            .classify_detailed(&interaction)
            .await?;

        let tier1 = SimulateTierStage {
            stage_name: "Tier 1 • System-1 Fast Text".to_string(),
            model: detailed.primary_model.clone(),
            status: if detailed.escalated {
                "escalated".to_string()
            } else {
                "resolved".to_string()
            },
            violates: detailed.primary_verdict.is_violation(),
            category: detailed.primary_verdict.category().map(|c| c.to_string()),
            confidence: detailed.primary_verdict.confidence().unwrap_or(0.0),
            reason: detailed.primary_verdict.reason().to_string(),
        };

        let tier2_model = detailed
            .fallback_model
            .clone()
            .unwrap_or_else(|| "fallback".to_string());
        let tier2 = if detailed.escalated {
            if let Some(ref fb) = detailed.fallback_verdict {
                SimulateTierStage {
                    stage_name: "Tier 2 • System-2 Fallback".to_string(),
                    model: tier2_model,
                    status: "resolved".to_string(),
                    violates: fb.is_violation(),
                    category: fb.category().map(|c| c.to_string()),
                    confidence: fb.confidence().unwrap_or(0.0),
                    reason: fb.reason().to_string(),
                }
            } else {
                SimulateTierStage {
                    stage_name: "Tier 2 • System-2 Fallback".to_string(),
                    model: tier2_model,
                    status: "escalated".to_string(),
                    violates: false,
                    category: None,
                    confidence: 0.0,
                    reason: detailed.escalation_reason.clone().unwrap_or_default(),
                }
            }
        } else {
            SimulateTierStage {
                stage_name: "Tier 2 • System-2 Fallback".to_string(),
                model: tier2_model,
                status: "bypassed".to_string(),
                violates: false,
                category: None,
                confidence: 0.0,
                reason: detailed.escalation_reason.clone().unwrap_or_else(|| {
                    "Bypassed: Tier 1 resolved decisively (System-2 GPU inference spared)"
                        .to_string()
                }),
            }
        };

        let evaluator = |reason: &str| -> String {
            if reason.contains("uncertainty escalation") {
                "fallback_uncertainty_classifier".to_string()
            } else if reason.contains("Fallback") || reason.contains("Tiered") {
                "fallback_vision_classifier".to_string()
            } else if images_evaluated > 0 {
                "primary_classifier (multimodal)".to_string()
            } else {
                "primary_classifier".to_string()
            }
        };

        if persist_log {
            let sim_outcome_str = match &detailed.final_verdict {
                Verdict::Violation {
                    category,
                    confidence,
                    ..
                } => {
                    if rubric.meets_threshold(category, *confidence) {
                        "Simulated: Would Bounce"
                    } else {
                        "Simulated: Below Rubric Threshold"
                    }
                }
                Verdict::Permitted { .. } => "Simulated: Permitted",
            };
            let log = NewEvaluationLog::from_tiered(
                &interaction,
                &format!("at://{author_did}/app.bsky.feed.post/simulated"),
                &detailed,
                &detailed.final_verdict,
                EvaluationLogContext {
                    source: "simulation",
                    outcome: sim_outcome_str,
                },
                "simulated-test.bsky.social".to_string(),
                self.target_handle(&target_did),
            );
            if let Err(e) = self.cache.record_evaluation_log(&log) {
                tracing::warn!(error = %e, "Failed to record simulated evaluation log");
            }
        }

        match detailed.final_verdict.clone() {
            Verdict::Violation {
                category,
                confidence,
                reason,
            } => Ok(SimulationResult {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                meets_threshold: rubric.meets_threshold(&category, confidence),
                evaluator: evaluator(&reason),
                reason,
                threshold,
                images_evaluated,
                tier1: Some(tier1),
                tier2: Some(tier2),
                fetched_url_image,
                created_at,
            }),
            Verdict::Permitted { reason, confidence } => Ok(SimulationResult {
                violates: false,
                category: None,
                confidence: confidence.unwrap_or(0.05),
                reason: reason.clone(),
                evaluator: evaluator(&reason),
                meets_threshold: false,
                threshold,
                images_evaluated,
                tier1: Some(tier1),
                tier2: Some(tier2),
                fetched_url_image,
                created_at,
            }),
        }
    }
}
