//! REST API handlers and payload models for the Skybouncer Web Dashboard.
//!
//! Provides endpoints for:
//! - Engine telemetry and status inspection (`GET /api/status`).
//! - Moderation rubric inspection and live updates (`GET /api/rules`, `POST /api/rules`).
//! - Bounced violator listing (`GET /api/bounces`).
//! - One-click account pardon and unban (`POST /api/pardon`).
//! - Interactive dry-run evaluation simulator (`POST /api/simulate`).

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::classifier::{RuleRubric, Sensitivity, Verdict};
use crate::engine::{EngineStatsSnapshot, SkybouncerEngine};
use crate::matcher::{Interaction, InteractionType};
use crate::modlist::BouncedUser;

/// Shared application state injected into web route handlers.
#[derive(Clone)]
pub struct ApiState {
    /// Reference to the core moderation engine.
    pub engine: Arc<SkybouncerEngine>,
}

/// Response payload for service health check endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Operational status (e.g. `"healthy"`).
    pub status: String,
    /// Crate version.
    pub version: String,
}

/// Response payload containing current moderation rubric configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RulesResponse {
    /// Natural-language prompt evaluated by classifiers.
    pub prompt: String,
    /// Active sensitivity level.
    pub sensitivity: Sensitivity,
    /// Minimum confidence threshold for automated action.
    pub threshold: f64,
}

/// Request payload to update the moderation rubric prompt and/or sensitivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRulesRequest {
    /// Optional updated natural language prompt.
    #[serde(default)]
    pub prompt: Option<String>,
    /// Optional updated sensitivity level.
    #[serde(default)]
    pub sensitivity: Option<Sensitivity>,
}

/// Query parameters for fetching bounced accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub struct BouncesQuery {
    /// Maximum number of records to return (defaults to 50, maximum 200).
    pub limit: Option<usize>,
}

/// Request payload to pardon and remove a user from the moderation list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PardonRequest {
    /// Decentralized identifier (DID) of the violator to pardon.
    pub subject_did: String,
    /// Optional protected DID whose list the violator should be removed from.
    #[serde(default)]
    pub protected_did: Option<String>,
}

/// Response payload following a pardon execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PardonResponse {
    /// Whether an existing bounced record was found and deleted.
    pub pardoned: bool,
    /// The subject DID that was processed.
    pub subject_did: String,
    /// Status description message.
    pub message: String,
}

/// Request payload to run a dry-run evaluation on sample text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulateRequest {
    /// Sample post text to evaluate.
    pub text: String,
    /// Optional synthetic author DID (defaults to sample DID).
    #[serde(default)]
    pub author_did: Option<String>,
    /// Optional target protected DID (defaults to first protected DID).
    #[serde(default)]
    pub target_did: Option<String>,
}

/// Detailed result of a dry-run evaluation simulation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulateResponse {
    /// Whether the interaction was classified as a violation.
    pub violates: bool,
    /// Category of violation detected, if applicable.
    pub category: Option<String>,
    /// Observed classifier confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Rationale or explanatory reason for the verdict.
    pub reason: String,
    /// Which evaluator produced the verdict ("heuristic_prefilter" or "primary_classifier").
    pub evaluator: String,
    /// Whether the confidence score meets or exceeds the rubric threshold.
    pub meets_threshold: bool,
    /// Active sensitivity threshold required for action.
    pub threshold: f64,
}

/// Overall engine operational status and telemetry response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Real-time engine event and performance metrics.
    pub stats: EngineStatsSnapshot,
    /// List of actively protected user DIDs.
    pub protected_dids: Vec<String>,
    /// Currently active moderation rubric.
    pub rubric: RulesResponse,
    /// Whether the engine operates in shadow dry-run mode.
    pub dry_run: bool,
    /// Skybouncer package version string.
    pub version: String,
}

/// Handler for `GET /api/status`: returns engine operational telemetry.
pub async fn get_status(State(state): State<ApiState>) -> Json<StatusResponse> {
    let stats = state.engine.stats().snapshot();
    let mut protected_dids: Vec<String> = state.engine.protected_dids().into_iter().collect();
    protected_dids.sort();
    let rubric = state.engine.rubric();

    Json(StatusResponse {
        stats,
        protected_dids,
        rubric: RulesResponse {
            prompt: rubric.prompt,
            sensitivity: rubric.sensitivity,
            threshold: rubric.sensitivity.threshold(),
        },
        dry_run: state.engine.is_dry_run(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Handler for `GET /healthz` and `GET /api/health`: service liveness and readiness probe.
pub async fn health_check() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
}

/// Handler for `GET /api/rules`: returns active moderation rubric.
pub async fn get_rules(State(state): State<ApiState>) -> Json<RulesResponse> {
    let rubric = state.engine.rubric();
    Json(RulesResponse {
        prompt: rubric.prompt,
        sensitivity: rubric.sensitivity,
        threshold: rubric.sensitivity.threshold(),
    })
}

/// Handler for `POST /api/rules`: updates the active moderation rubric.
pub async fn update_rules(
    State(state): State<ApiState>,
    Json(payload): Json<UpdateRulesRequest>,
) -> Result<Json<RulesResponse>, (StatusCode, String)> {
    let mut rubric = state.engine.rubric();

    if let Some(prompt) = payload.prompt {
        let trimmed = prompt.trim();
        if trimmed.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Prompt cannot be empty".to_string(),
            ));
        }
        let parsed = RuleRubric::parse(trimmed)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid rubric: {e}")))?;
        rubric.prompt = parsed.prompt;
    }

    if let Some(sens) = payload.sensitivity {
        rubric.sensitivity = sens;
    }

    state.engine.set_rubric(rubric.clone());

    Ok(Json(RulesResponse {
        prompt: rubric.prompt,
        sensitivity: rubric.sensitivity,
        threshold: rubric.sensitivity.threshold(),
    }))
}

/// Handler for `GET /api/bounces`: returns recent bounced violators.
pub async fn get_bounces(
    State(state): State<ApiState>,
    Query(query): Query<BouncesQuery>,
) -> Result<Json<Vec<BouncedUser>>, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let bounces = state
        .engine
        .list_recent_bounces(limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(bounces))
}

/// Handler for `POST /api/pardon`: unbans a user and removes their listitem from PDS.
pub async fn pardon_user(
    State(state): State<ApiState>,
    Json(payload): Json<PardonRequest>,
) -> Result<Json<PardonResponse>, (StatusCode, String)> {
    let subject_did = payload.subject_did.trim().to_string();
    if subject_did.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "subject_did cannot be empty".to_string(),
        ));
    }

    let protected_did = if let Some(ref pd) = payload.protected_did {
        pd.trim().to_string()
    } else {
        state
            .engine
            .protected_dids()
            .into_iter()
            .next()
            .unwrap_or_else(|| "did:plc:default".to_string())
    };

    match state.engine.pardon_user(&protected_did, &subject_did).await {
        Ok(true) => Ok(Json(PardonResponse {
            pardoned: true,
            subject_did: subject_did.clone(),
            message: format!(
                "Account {subject_did} was pardoned and removed from moderation list."
            ),
        })),
        Ok(false) => Ok(Json(PardonResponse {
            pardoned: false,
            subject_did: subject_did.clone(),
            message: format!("Account {subject_did} was not found in the bounced cache."),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to pardon: {e}"),
        )),
    }
}

/// Handler for `POST /api/simulate`: runs a dry-run evaluation on sample text.
pub async fn simulate_interaction(
    State(state): State<ApiState>,
    Json(payload): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>, (StatusCode, String)> {
    let text = payload.text.trim();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Text cannot be empty".to_string()));
    }

    let author_did = payload
        .author_did
        .unwrap_or_else(|| "did:plc:sample-author".to_string());
    let target_did = payload.target_did.unwrap_or_else(|| {
        state
            .engine
            .protected_dids()
            .into_iter()
            .next()
            .unwrap_or_else(|| "did:plc:protected-sample".to_string())
    });

    let synthetic_interaction = Interaction {
        post_uri: "at://did:plc:sample/app.bsky.feed.post/sample123".to_string(),
        post_cid: Some("bafysample123".to_string()),
        author_did,
        target_did,
        text: text.to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: None,
        root_uri: None,
        created_at_us: 0,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
    };

    let rubric = state.engine.rubric();
    let threshold = rubric.sensitivity.threshold();

    // 1. Check zero-cost heuristic pre-filter
    let heuristic_verdict = state
        .engine
        .heuristic_classifier()
        .evaluate(&synthetic_interaction);

    if heuristic_verdict.is_violation() {
        if let Verdict::Violation {
            category,
            confidence,
            reason,
        } = heuristic_verdict
        {
            let meets_threshold = rubric.meets_threshold(&category, confidence);
            return Ok(Json(SimulateResponse {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                reason,
                evaluator: "heuristic_prefilter".to_string(),
                meets_threshold,
                threshold,
            }));
        }
    }

    // 2. Primary classifier evaluation (Jev or Mock)
    match state
        .engine
        .primary_classifier()
        .classify(&synthetic_interaction)
        .await
    {
        Ok(Verdict::Violation {
            category,
            confidence,
            reason,
        }) => {
            let meets_threshold = rubric.meets_threshold(&category, confidence);
            Ok(Json(SimulateResponse {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                reason,
                evaluator: "primary_classifier".to_string(),
                meets_threshold,
                threshold,
            }))
        }
        Ok(Verdict::Permitted { reason, confidence }) => Ok(Json(SimulateResponse {
            violates: false,
            category: None,
            confidence: confidence.unwrap_or(0.05),
            reason,
            evaluator: "primary_classifier".to_string(),
            meets_threshold: false,
            threshold,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Classification failed: {e}"),
        )),
    }
}
