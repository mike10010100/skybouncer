//! REST API handlers and payload models for the Skybouncer Web Dashboard.
//!
//! Provides endpoints for:
//! - Engine telemetry and status inspection (`GET /api/status`).
//! - Moderation rubric inspection and live updates (`GET /api/rules`, `POST /api/rules`).
//! - Bounced violator listing (`GET /api/bounces`).
//! - One-click account pardon and unban (`POST /api/pardon`).
//! - Interactive dry-run evaluation simulator (`POST /api/simulate`).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::classifier::{BounceDuration, RuleRubric, Sensitivity, Verdict};
use crate::engine::{EngineStatsSnapshot, SkybouncerEngine};
use crate::matcher::{Interaction, InteractionType};
use crate::modlist::cache::{EvaluationLogEntry, NewEvaluationLog};
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
    /// Configured bounce duration / timeout.
    #[serde(default)]
    pub bounce_duration: BounceDuration,
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
    /// Optional updated bounce duration / timeout.
    #[serde(default)]
    pub bounce_duration: Option<BounceDuration>,
}

/// Query parameters for fetching bounced accounts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct BouncesQuery {
    /// Maximum number of records to return (defaults to 50, maximum 200).
    pub limit: Option<usize>,
    /// Optional protected DID to filter bounces for a specific user.
    pub user_did: Option<String>,
}

/// Request payload to pardon and remove a user from the moderation list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PardonRequest {
    /// Decentralized identifier (DID) of the violator to pardon.
    pub subject_did: String,
    /// Optional protected DID whose list the violator should be removed from.
    #[serde(default)]
    pub protected_did: Option<String>,
    /// Whether to permanently immunize the user against future moderation by adding them to the allowlist.
    #[serde(default)]
    pub allowlist: bool,
    /// Optional explanatory reason for allowlisting.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Response payload following a pardon execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PardonResponse {
    /// Whether an existing bounced record was found and deleted.
    pub pardoned: bool,
    /// Whether the user was immunized on the allowlist.
    #[serde(default)]
    pub allowlisted: bool,
    /// The subject DID that was processed.
    pub subject_did: String,
    /// Status description message.
    pub message: String,
}

/// Query parameters for listing allowlisted accounts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AllowlistQuery {
    /// Optional protected DID to filter allowlist for a specific user.
    pub user_did: Option<String>,
}

/// Request payload to add an account to the moderation allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddAllowlistRequest {
    /// Decentralized identifier (DID) or @handle of the account to allowlist.
    pub subject: String,
    /// Optional protected DID whose allowlist should be updated.
    #[serde(default)]
    pub protected_did: Option<String>,
    /// Optional reason or justification for allowlisting.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Response payload following allowlist addition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddAllowlistResponse {
    /// The allowlisted subject DID.
    pub subject_did: String,
    /// ATProto handle if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Status description message.
    pub message: String,
}

/// Response payload following allowlist removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveAllowlistResponse {
    /// Whether the entry was found and removed.
    pub removed: bool,
    /// The removed subject DID.
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
    /// Optional base64-encoded image attached to the candidate post.
    #[serde(default)]
    pub image_base64: Option<String>,
    /// Optional image URL to fetch and evaluate.
    #[serde(default)]
    pub image_url: Option<String>,
}

/// Detailed stage breakdown for a single tier in the simulation pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TierStageDetail {
    /// Stage title (e.g. "Tier 1 • System-1 Primary (Text)").
    pub stage_name: String,
    /// Model identifier (e.g. "nimble" or "gemma4:12b").
    pub model: String,
    /// Execution status ("resolved", "escalated", or "bypassed").
    pub status: String,
    /// Whether this stage classified the post as a violation.
    pub violates: bool,
    /// Violation category if violation occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Model confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Rationale provided by this model or bypass explanation.
    pub reason: String,
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
    /// Which evaluator produced the verdict ("heuristic_prefilter", "primary_classifier", or "fallback_vision_classifier").
    pub evaluator: String,
    /// Whether the confidence score meets or exceeds the rubric threshold.
    pub meets_threshold: bool,
    /// Active sensitivity threshold required for action.
    pub threshold: f64,
    /// Number of images decoded and inspected during evaluation.
    #[serde(default)]
    pub images_evaluated: usize,
    /// Detailed Tier-1 System-1 evaluation stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier1: Option<TierStageDetail>,
    /// Detailed Tier-2 System-2 fallback evaluation stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier2: Option<TierStageDetail>,
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
    /// Number of actively monitored accounts across the fleet (only visible to authenticated administrators).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitored_users_count: Option<usize>,
}

/// Handler for `GET /api/status`: returns engine operational telemetry.
pub async fn get_status(State(state): State<ApiState>, headers: HeaderMap) -> Json<StatusResponse> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine);
    let is_admin = caller_did
        .as_deref()
        .is_some_and(|did| state.engine.is_admin(did));

    let stats = if caller_did.is_some() || is_admin {
        state.engine.stats().snapshot()
    } else {
        EngineStatsSnapshot::default()
    };

    let protected_dids = if is_admin {
        let mut dids: Vec<String> = state.engine.protected_dids().into_iter().collect();
        dids.sort();
        dids
    } else if let Some(ref did) = caller_did {
        if state.engine.is_protected(did) {
            vec![did.clone()]
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let rubric = if let Some(ref did) = caller_did {
        state.engine.rubric_for(did)
    } else {
        RuleRubric {
            prompt: "[Protected sovereign rubric - sign in to view]".to_string(),
            sensitivity: state.engine.rubric().sensitivity,
            bounce_duration: state.engine.rubric().bounce_duration,
        }
    };

    let monitored_users_count = if is_admin {
        Some(state.engine.protected_dids().len())
    } else {
        None
    };

    Json(StatusResponse {
        stats,
        protected_dids,
        rubric: RulesResponse {
            prompt: rubric.prompt,
            sensitivity: rubric.sensitivity,
            threshold: rubric.sensitivity.threshold(),
            bounce_duration: rubric.bounce_duration,
        },
        dry_run: state.engine.is_dry_run(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        monitored_users_count,
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

/// Handler for `GET /metrics` and `GET /api/metrics`: exports telemetry counters and gauges in Prometheus text exposition format.
pub async fn get_prometheus_metrics(State(state): State<ApiState>) -> Response {
    let stats = state.engine.stats().snapshot();
    let protected_count = state.engine.protected_dids().len();
    let tenant_count = state.engine.tenant_registry().count().unwrap_or(0);
    let dry_run = if state.engine.is_dry_run() { 1 } else { 0 };
    let queue_depth = stats
        .eval_queue_enqueued
        .saturating_sub(stats.eval_queue_processed);

    let mut out = String::with_capacity(4096);
    use std::fmt::Write;

    let _ = writeln!(
        out,
        "# HELP skybouncer_commits_received_total Total incoming Jetstream commits processed."
    );
    let _ = writeln!(out, "# TYPE skybouncer_commits_received_total counter");
    let _ = writeln!(
        out,
        "skybouncer_commits_received_total {}",
        stats.commits_received
    );

    let _ = writeln!(out, "\n# HELP skybouncer_follow_sync_events_total Total follow/unfollow events synchronized to the follow graph.");
    let _ = writeln!(out, "# TYPE skybouncer_follow_sync_events_total counter");
    let _ = writeln!(
        out,
        "skybouncer_follow_sync_events_total {}",
        stats.follow_sync_events
    );

    let _ = writeln!(out, "\n# HELP skybouncer_interactions_matched_total Total candidate interactions extracted targeting protected users.");
    let _ = writeln!(out, "# TYPE skybouncer_interactions_matched_total counter");
    let _ = writeln!(
        out,
        "skybouncer_interactions_matched_total {}",
        stats.interactions_matched
    );

    let _ = writeln!(out, "\n# HELP skybouncer_gate_bypassed_total Interactions dropped by zero-cost pre-evaluation gates.");
    let _ = writeln!(out, "# TYPE skybouncer_gate_bypassed_total counter");
    let _ = writeln!(
        out,
        "skybouncer_gate_bypassed_total{{reason=\"self\"}} {}",
        stats.gate_bypassed_self
    );
    let _ = writeln!(
        out,
        "skybouncer_gate_bypassed_total{{reason=\"followed\"}} {}",
        stats.gate_bypassed_followed
    );
    let _ = writeln!(
        out,
        "skybouncer_gate_bypassed_total{{reason=\"allowlist\"}} {}",
        stats.gate_bypassed_allowlist
    );

    let _ = writeln!(out, "\n# HELP skybouncer_candidates_evaluated_total Interactions that passed all gates and were evaluated.");
    let _ = writeln!(out, "# TYPE skybouncer_candidates_evaluated_total counter");
    let _ = writeln!(
        out,
        "skybouncer_candidates_evaluated_total {}",
        stats.candidates_evaluated
    );

    let _ = writeln!(out, "\n# HELP skybouncer_dedup_cache_hits_total Interactions dropped because author was already recorded as bounced.");
    let _ = writeln!(out, "# TYPE skybouncer_dedup_cache_hits_total counter");
    let _ = writeln!(
        out,
        "skybouncer_dedup_cache_hits_total {}",
        stats.dedup_cache_hits
    );

    let _ = writeln!(out, "\n# HELP skybouncer_eval_cache_hits_total Candidate evaluations served from SQLite TTL evaluation cache.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_cache_hits_total counter");
    let _ = writeln!(
        out,
        "skybouncer_eval_cache_hits_total {}",
        stats.eval_cache_hits
    );

    let _ = writeln!(out, "\n# HELP skybouncer_heuristic_violations_total High-confidence violations matched instantly by heuristic regex rules.");
    let _ = writeln!(out, "# TYPE skybouncer_heuristic_violations_total counter");
    let _ = writeln!(
        out,
        "skybouncer_heuristic_violations_total {}",
        stats.heuristic_violations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_model_evaluations_total Candidate interactions evaluated by primary and secondary classifiers.");
    let _ = writeln!(out, "# TYPE skybouncer_model_evaluations_total counter");
    let _ = writeln!(
        out,
        "skybouncer_model_evaluations_total {}",
        stats.model_evaluations
    );

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_tier1_evaluations_total Tier-1 primary model evaluations."
    );
    let _ = writeln!(out, "# TYPE skybouncer_tier1_evaluations_total counter");
    let _ = writeln!(
        out,
        "skybouncer_tier1_evaluations_total {}",
        stats.tier1_evaluations
    );

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_tier2_evaluations_total Tier-2 fallback model escalations."
    );
    let _ = writeln!(out, "# TYPE skybouncer_tier2_evaluations_total counter");
    let _ = writeln!(
        out,
        "skybouncer_tier2_evaluations_total {}",
        stats.tier2_evaluations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_tier2_image_escalations_total Tier-2 escalations triggered by attached images.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_tier2_image_escalations_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_tier2_image_escalations_total {}",
        stats.tier2_image_escalations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_tier2_uncertainty_escalations_total Tier-2 escalations triggered by confidence uncertainty band.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_tier2_uncertainty_escalations_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_tier2_uncertainty_escalations_total {}",
        stats.tier2_uncertainty_escalations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_eval_queue_enqueued_total Candidate interactions enqueued to background evaluation queue.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_queue_enqueued_total counter");
    let _ = writeln!(
        out,
        "skybouncer_eval_queue_enqueued_total {}",
        stats.eval_queue_enqueued
    );

    let _ = writeln!(out, "\n# HELP skybouncer_eval_queue_processed_total Candidate interactions processed by background evaluation worker.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_queue_processed_total counter");
    let _ = writeln!(
        out,
        "skybouncer_eval_queue_processed_total {}",
        stats.eval_queue_processed
    );

    let _ = writeln!(out, "\n# HELP skybouncer_eval_queue_overflows_total Candidate interactions dropped due to evaluation queue capacity saturation.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_queue_overflows_total counter");
    let _ = writeln!(
        out,
        "skybouncer_eval_queue_overflows_total {}",
        stats.eval_queue_overflows
    );

    let _ = writeln!(out, "\n# HELP skybouncer_rate_limited_evaluations_total Evaluations dropped due to per-user evaluation rate limits.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_rate_limited_evaluations_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_rate_limited_evaluations_total {}",
        stats.rate_limited_evaluations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_context_enrichments_total Candidates enriched with author profile and parent post context.");
    let _ = writeln!(out, "# TYPE skybouncer_context_enrichments_total counter");
    let _ = writeln!(
        out,
        "skybouncer_context_enrichments_total {}",
        stats.context_enrichments
    );

    let _ = writeln!(out, "\n# HELP skybouncer_violations_detected_total Total violations confirmed across heuristic and model classifiers.");
    let _ = writeln!(out, "# TYPE skybouncer_violations_detected_total counter");
    let _ = writeln!(
        out,
        "skybouncer_violations_detected_total {}",
        stats.violations_detected
    );

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_bounces_total Successful listitem mutations created on sovereign PDS."
    );
    let _ = writeln!(out, "# TYPE skybouncer_bounces_total counter");
    let _ = writeln!(out, "skybouncer_bounces_total {}", stats.bounces_executed);

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_permitted_total Total interactions classified as permitted or benign."
    );
    let _ = writeln!(out, "# TYPE skybouncer_permitted_total counter");
    let _ = writeln!(out, "skybouncer_permitted_total {}", stats.permitted);

    let _ = writeln!(out, "\n# HELP skybouncer_bounces_skipped_rubric_total Violations dropped because confidence fell below rubric sensitivity threshold.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_bounces_skipped_rubric_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_bounces_skipped_rubric_total {}",
        stats.bounces_skipped_rubric
    );

    let _ = writeln!(out, "\n# HELP skybouncer_errors_total Total operational or network errors encountered during pipeline execution.");
    let _ = writeln!(out, "# TYPE skybouncer_errors_total counter");
    let _ = writeln!(out, "skybouncer_errors_total {}", stats.errors_encountered);

    let _ = writeln!(out, "\n# HELP skybouncer_sovereign_configs_synced_total Sovereign configuration hot-reload events synchronized from the firehose.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_sovereign_configs_synced_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_sovereign_configs_synced_total {}",
        stats.sovereign_configs_synced
    );

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_protected_users Number of protected accounts currently monitored."
    );
    let _ = writeln!(out, "# TYPE skybouncer_protected_users gauge");
    let _ = writeln!(out, "skybouncer_protected_users {protected_count}");

    let _ = writeln!(out, "\n# HELP skybouncer_eval_queue_depth Current number of candidate interactions queued awaiting evaluation.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_queue_depth gauge");
    let _ = writeln!(out, "skybouncer_eval_queue_depth {queue_depth}");

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_enrolled_tenants Number of sovereign multi-tenant users registered."
    );
    let _ = writeln!(out, "# TYPE skybouncer_enrolled_tenants gauge");
    let _ = writeln!(out, "skybouncer_enrolled_tenants {tenant_count}");

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_dry_run Whether dry-run shadow mode is active (1) or disabled (0)."
    );
    let _ = writeln!(out, "# TYPE skybouncer_dry_run gauge");
    let _ = writeln!(out, "skybouncer_dry_run {dry_run}");

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_build_info Build and version metadata."
    );
    let _ = writeln!(out, "# TYPE skybouncer_build_info gauge");
    let _ = writeln!(
        out,
        "skybouncer_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

/// Extracts the verified authenticated caller DID strictly from a valid session token in Cookie or Authorization header.
///
/// Unsigned `x-skybouncer-did` headers and unverified cookie DIDs are strictly rejected.
pub fn extract_authenticated_caller(
    headers: &HeaderMap,
    engine: &SkybouncerEngine,
) -> Option<String> {
    // 1. Check Authorization: Bearer <session_token>
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(s) = auth_header.to_str() {
            let trimmed = s.trim();
            if let Some(token) = trimmed.strip_prefix("Bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    if let Ok(Some(did)) = engine.tenant_registry().validate_web_session(token) {
                        return Some(did);
                    }
                }
            }
        }
    }

    // 2. Check Cookie: skybouncer_session=<session_token>
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(s) = cookie_header.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("skybouncer_session=") {
                    let token = val.trim();
                    if !token.is_empty() {
                        if let Ok(Some(did)) = engine.tenant_registry().validate_web_session(token)
                        {
                            return Some(did);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Resolves the authenticated caller identity and enforces authorization on the target DID for rules endpoints.
///
/// # Errors
/// Returns `StatusCode::UNAUTHORIZED` if caller is not authenticated,
/// or `StatusCode::FORBIDDEN` if caller attempts to access another user's rules without admin privileges.
pub fn resolve_rules_target_did(
    engine: &SkybouncerEngine,
    headers: &HeaderMap,
    query_did: Option<&str>,
    action_desc: &str,
) -> Result<String, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(headers, engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            format!("Authentication required to {action_desc}. Please sign in with Bluesky."),
        )
    })?;

    let is_admin = engine.is_admin(&caller_did);
    let is_enrolled = engine.is_enrolled(&caller_did);
    let is_protected = engine.is_protected(&caller_did);

    if !is_admin && !is_enrolled && !is_protected {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("Account {caller_did} is not enrolled or recognized. Please sign in."),
        ));
    }

    // Target DID: if caller requests a different target, must be admin
    if let Some(target) = query_did.map(str::trim).filter(|s| !s.is_empty()) {
        if target != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Access denied: you may only {action_desc} for your own account."),
            ));
        }
        Ok(target.to_string())
    } else {
        Ok(caller_did)
    }
}

/// Handler for `GET /api/rules`: returns active moderation rubric for authenticated caller.
pub async fn get_rules(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SessionQuery>,
) -> Result<Json<RulesResponse>, (StatusCode, String)> {
    let target_did = resolve_rules_target_did(
        &state.engine,
        &headers,
        query.did.as_deref(),
        "view moderation rules",
    )?;

    let rubric = state.engine.rubric_for(&target_did);
    Ok(Json(RulesResponse {
        prompt: rubric.prompt,
        sensitivity: rubric.sensitivity,
        threshold: rubric.sensitivity.threshold(),
        bounce_duration: rubric.bounce_duration,
    }))
}

/// Handler for `POST /api/rules`: updates the active moderation rubric for authenticated caller and persists to sovereign PDS.
pub async fn update_rules(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SessionQuery>,
    Json(payload): Json<UpdateRulesRequest>,
) -> Result<Json<RulesResponse>, (StatusCode, String)> {
    let target_did = resolve_rules_target_did(
        &state.engine,
        &headers,
        query.did.as_deref(),
        "modify moderation rules",
    )?;

    let mut rubric = state.engine.rubric_for(&target_did);

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

    if let Some(dur) = payload.bounce_duration {
        rubric.bounce_duration = dur;
    }

    let is_enrolled = state
        .engine
        .tenant_registry()
        .is_enrolled(&target_did)
        .unwrap_or(false);
    if is_enrolled {
        state
            .engine
            .tenant_registry()
            .update_rubric(&target_did, &rubric)
            .map_err(|e| {
                tracing::error!(did = %target_did, error = %e, "Failed to persist updated rubric");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to persist rubric: {e}"),
                )
            })?;
    } else if state.engine.is_protected(&target_did) {
        // Only non-enrolled protected accounts update the default engine rubric
        state.engine.set_rubric(rubric.clone());
    }

    // Asynchronously persist updated rubric to user's sovereign PDS repository
    let eng = state.engine.clone();
    let publish_did = target_did.clone();
    tokio::spawn(async move {
        if let Err(e) = eng.publish_sovereign_config(&publish_did).await {
            tracing::warn!(did = %publish_did, error = %e, "Failed to publish sovereign config to PDS in background task");
        }
    });

    Ok(Json(RulesResponse {
        prompt: rubric.prompt,
        sensitivity: rubric.sensitivity,
        threshold: rubric.sensitivity.threshold(),
        bounce_duration: rubric.bounce_duration,
    }))
}

/// Record of a bounced violator enriched with the resolved ATProto handle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BouncedUserWithHandle {
    /// The underlying bounced user record.
    #[serde(flatten)]
    pub user: BouncedUser,
    /// Resolved ATProto handle of the bounced violator, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// Handler for `GET /api/bounces`: returns recent bounced violators.
///
/// Authentication is strictly required. Non-admin users are restricted to viewing
/// only bounces on their own posts; admins may view fleet-wide or specify a target DID.
pub async fn get_bounces(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<BouncesQuery>,
) -> Result<Json<Vec<BouncedUserWithHandle>>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to view bounces. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let is_admin = state.engine.is_admin(&caller_did);

    let filter_did = if is_admin {
        query.user_did.as_deref().filter(|s| !s.trim().is_empty())
    } else {
        if let Some(requested_did) = query.user_did.as_deref().filter(|s| !s.trim().is_empty()) {
            if requested_did != caller_did {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Access denied: you may only view bounces for your own account.".to_string(),
                ));
            }
        }
        Some(caller_did.as_str())
    };

    let bounces = state
        .engine
        .list_recent_bounces_for(filter_did, limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let enriched = bounces
        .into_iter()
        .map(|b| {
            let handle = state.engine.cached_handle_for_did(&b.subject_did);
            BouncedUserWithHandle { user: b, handle }
        })
        .collect();
    Ok(Json(enriched))
}

/// Handler for `POST /api/pardon`: unbans a user and removes their listitem from PDS.
///
/// Authentication is strictly required. Non-admin callers may only pardon accounts
/// from their own sovereign moderation list.
pub async fn pardon_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<PardonRequest>,
) -> Result<Json<PardonResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to pardon accounts. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let subject_did = payload.subject_did.trim().to_string();
    if subject_did.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "subject_did cannot be empty".to_string(),
        ));
    }

    let is_admin = state.engine.is_admin(&caller_did);
    let protected_did = if let Some(ref pd) = payload.protected_did {
        let requested = pd.trim();
        if requested != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                "Access denied: you may only pardon users from your own moderation list."
                    .to_string(),
            ));
        }
        requested.to_string()
    } else {
        caller_did.clone()
    };

    if payload.allowlist {
        match state
            .engine
            .pardon_and_allowlist(
                &protected_did,
                &subject_did,
                payload
                    .reason
                    .as_deref()
                    .or(Some("Immunized via web API pardon")),
            )
            .await
        {
            Ok(pardoned) => Ok(Json(PardonResponse {
                pardoned,
                allowlisted: true,
                subject_did: subject_did.clone(),
                message: format!(
                    "Account {subject_did} was pardoned and immunized on the allowlist."
                ),
            })),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to pardon and allowlist: {e}"),
            )),
        }
    } else {
        match state.engine.pardon_user(&protected_did, &subject_did).await {
            Ok(true) => Ok(Json(PardonResponse {
                pardoned: true,
                allowlisted: false,
                subject_did: subject_did.clone(),
                message: format!(
                    "Account {subject_did} was pardoned and removed from moderation list."
                ),
            })),
            Ok(false) => Ok(Json(PardonResponse {
                pardoned: false,
                allowlisted: false,
                subject_did: subject_did.clone(),
                message: format!("Account {subject_did} was not found in the bounced cache."),
            })),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to pardon: {e}"),
            )),
        }
    }
}

/// Handler for `GET /api/allowlist`: lists allowlisted accounts for the authenticated user or target user (admin).
pub async fn get_allowlist(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AllowlistQuery>,
) -> Result<Json<Vec<crate::modlist::AllowlistEntry>>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to view allowlist. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let target_did = if let Some(ref ud) = query.user_did {
        let requested = ud.trim();
        if requested != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                "Access denied: you may only view your own allowlist.".to_string(),
            ));
        }
        requested
    } else {
        &caller_did
    };

    match state.engine.list_allowlist(target_did) {
        Ok(mut entries) => {
            for entry in &mut entries {
                if entry.handle.is_none() {
                    entry.handle = state.engine.cached_handle_for_did(&entry.subject_did);
                }
            }
            Ok(Json(entries))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to list allowlist: {e}"),
        )),
    }
}

/// Handler for `POST /api/allowlist`: adds an account to the moderation allowlist.
pub async fn add_to_allowlist(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<AddAllowlistRequest>,
) -> Result<Json<AddAllowlistResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to update allowlist. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let protected_did = if let Some(ref pd) = payload.protected_did {
        let requested = pd.trim();
        if requested != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                "Access denied: you may only update your own allowlist.".to_string(),
            ));
        }
        requested.to_string()
    } else {
        caller_did.clone()
    };

    let raw_subject = payload.subject.trim();
    if raw_subject.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "subject cannot be empty".to_string(),
        ));
    }

    let clean = raw_subject.trim_start_matches('@');
    let (subject_did, resolved_handle) = if clean.starts_with("did:") {
        let handle = state.engine.resolve_did_to_handle(clean).await;
        (clean.to_string(), handle)
    } else {
        match state.engine.resolve_handle(clean).await {
            Some(did) => {
                let _ = state.engine.cache().set_handle_for_did(&did, clean);
                (did, Some(clean.to_string()))
            }
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Could not resolve handle `@{clean}` to a DID."),
                ));
            }
        }
    };

    match state.engine.add_to_allowlist(
        &protected_did,
        &subject_did,
        payload.reason.as_deref().or(Some("Added via web API")),
    ) {
        Ok(()) => Ok(Json(AddAllowlistResponse {
            subject_did: subject_did.clone(),
            handle: resolved_handle,
            message: format!("Account {subject_did} was added to the allowlist."),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to add to allowlist: {e}"),
        )),
    }
}

/// Handler for `DELETE /api/allowlist/:did`: removes an account from the moderation allowlist.
pub async fn remove_from_allowlist(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(subject_did): Path<String>,
    Query(query): Query<AllowlistQuery>,
) -> Result<Json<RemoveAllowlistResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to update allowlist. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let protected_did = if let Some(ref ud) = query.user_did {
        let requested = ud.trim();
        if requested != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                "Access denied: you may only update your own allowlist.".to_string(),
            ));
        }
        requested
    } else {
        &caller_did
    };

    let clean_did = subject_did.trim();
    if clean_did.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "DID path parameter cannot be empty".to_string(),
        ));
    }

    match state.engine.remove_from_allowlist(protected_did, clean_did) {
        Ok(removed) => Ok(Json(RemoveAllowlistResponse {
            removed,
            subject_did: clean_did.to_string(),
            message: if removed {
                format!("Account {clean_did} was removed from the allowlist.")
            } else {
                format!("Account {clean_did} was not found on the allowlist.")
            },
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to remove from allowlist: {e}"),
        )),
    }
}

/// Securely fetches a remote image URL for the simulator while enforcing strict SSRF defenses.
///
/// Prevents access to private RFC 1918 networks, loopback (`127.0.0.1`, `::1`),
/// link-local/cloud metadata (`169.254.169.254`), IPv6 ULA, and internal hostnames.
/// Disallows HTTP redirects to prevent open-redirect SSRF evasions.
async fn fetch_simulation_image(url_str: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let parsed_url = url::Url::parse(url_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid image URL: {e}")))?;

    let scheme = parsed_url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Only http and https schemes are permitted for image simulation".to_string(),
        ));
    }

    let host = parsed_url.host_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Missing host in image URL".to_string(),
        )
    })?;

    if skyauth::ssrf::is_blocked_hostname(host) {
        return Err((
            StatusCode::BAD_REQUEST,
            "SSRF protection: image URL target host is restricted".to_string(),
        ));
    }

    // Resolve DNS ahead-of-time and verify all returned addresses against restricted IP ranges
    let port = parsed_url
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let host_port = format!("{host}:{port}");
    let addrs: Vec<_> = tokio::net::lookup_host(&host_port)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to resolve image URL host: {e}"),
            )
        })?
        .collect();

    let mut target_addr = None;
    for addr in &addrs {
        let ip = addr.ip();
        if skyauth::ssrf::is_restricted_ip(ip) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("SSRF protection: image URL resolves to restricted IP ({ip})"),
            ));
        }
        if target_addr.is_none() {
            target_addr = Some(*addr);
        }
    }

    let pinned_addr = target_addr.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Could not resolve any IP address for host".to_string(),
        )
    })?;

    // Fetch with redirect::Policy::none() and pinned IP address to eliminate DNS-rebinding TOCTOU (M9)
    let client = reqwest::Client::builder()
        .resolve(host, pinned_addr)
        .timeout(Duration::from_millis(5000))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!(
            "skybouncer/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/mike10010100/skybouncer)"
        ))
        .build()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("HTTP client error: {e}"),
            )
        })?;

    let resp = client.get(url_str).send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Failed to fetch simulation image: {e}"),
        )
    })?;

    if !resp.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "Simulation image request failed with status: {}",
                resp.status()
            ),
        ));
    }

    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to read image stream: {e}"),
            )
        })?;
        if bytes.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "Simulation image exceeds 2MB limit".to_string(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok(bytes)
}

/// Handler for `POST /api/simulate`: runs a dry-run evaluation on sample text and optional images.
pub async fn simulate_interaction(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to run evaluation simulation".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);

    let text = payload.text.trim();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Text cannot be empty".to_string()));
    }

    let author_did = payload
        .author_did
        .unwrap_or_else(|| "did:plc:sample-author".to_string());
    let target_did = if is_admin {
        payload.target_did.unwrap_or_else(|| caller_did.clone())
    } else {
        caller_did.clone()
    };

    let mut image_cids = Vec::new();
    let mut images_base64 = Vec::new();

    if let Some(b64) = payload.image_base64.filter(|s| !s.trim().is_empty()) {
        images_base64.push(b64);
        image_cids.push("simulate-base64-image".to_string());
    } else if let Some(url) = payload.image_url.filter(|s| !s.trim().is_empty()) {
        let bytes = fetch_simulation_image(&url).await?;
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        images_base64.push(encoded);
        image_cids.push("simulate-url-image".to_string());
    }

    let images_evaluated = images_base64.len();
    let enriched_context = if !images_base64.is_empty() {
        let mut ctx = crate::enricher::EnrichedContext::empty();
        ctx.images_base64 = images_base64;
        Some(ctx)
    } else {
        None
    };

    let synthetic_interaction = Interaction {
        post_uri: "at://did:plc:sample/app.bsky.feed.post/sample123".to_string(),
        post_cid: Some("bafysample123".to_string()),
        author_did: author_did.clone(),
        target_did: target_did.clone(),
        text: text.to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: None,
        root_uri: None,
        created_at_us: 0,
        image_cids,
        image_alts: Vec::new(),
        enriched_context,
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
            let tier1 = TierStageDetail {
                stage_name: "Tier 1 • System-1 Fast Text".to_string(),
                model: "nimble".to_string(),
                status: "bypassed".to_string(),
                violates: false,
                category: None,
                confidence: 0.0,
                reason: "Bypassed: Heuristic regex pre-filter matched instantly (0ms)".to_string(),
            };
            let tier2 = TierStageDetail {
                stage_name: "Tier 2 • System-2 Fallback".to_string(),
                model: "gemma4:12b".to_string(),
                status: "bypassed".to_string(),
                violates: false,
                category: None,
                confidence: 0.0,
                reason: "Bypassed: Heuristic regex pre-filter matched instantly (0ms)".to_string(),
            };
            let target_handle = state
                .engine
                .tenant_registry()
                .get(&target_did)
                .ok()
                .flatten()
                .and_then(|t| t.handle)
                .unwrap_or_default();

            if let Err(e) = state
                .engine
                .cache()
                .record_evaluation_log(&NewEvaluationLog {
                    timestamp_us: crate::modlist::cache::current_time_us(),
                    source: "simulation".to_string(),
                    post_uri: format!("at://{author_did}/app.bsky.feed.post/simulated"),
                    post_text: text.to_string(),
                    author_did: author_did.clone(),
                    author_handle: "simulated-test.bsky.social".to_string(),
                    target_did: target_did.clone(),
                    target_handle,
                    has_images: images_evaluated > 0,
                    primary_model: "heuristic_prefilter".to_string(),
                    primary_action: "violation".to_string(),
                    primary_confidence: 1.0,
                    primary_category: category.to_string(),
                    primary_reason: reason.clone(),
                    escalated: false,
                    escalation_reason: Some("Heuristic regex instant match".to_string()),
                    fallback_model: None,
                    fallback_action: None,
                    fallback_confidence: None,
                    fallback_category: None,
                    fallback_reason: None,
                    final_action: "violation".to_string(),
                    final_confidence: 1.0,
                    outcome: "Simulated: Would Bounce (Regex Pre-filter)".to_string(),
                })
            {
                tracing::warn!(error = %e, "Failed to record simulated evaluation log");
            }

            return Ok(Json(SimulateResponse {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                reason,
                evaluator: "heuristic_prefilter".to_string(),
                meets_threshold,
                threshold,
                images_evaluated,
                tier1: Some(tier1),
                tier2: Some(tier2),
            }));
        }
    }

    // 2. Primary classifier evaluation (Tiered Jev / Multimodal Fallback)
    let detailed = match state
        .engine
        .primary_classifier()
        .classify_detailed(&synthetic_interaction)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Classification failed: {e}"),
            ));
        }
    };

    let tier1_violates = detailed.primary_verdict.is_violation();
    let tier1_cat = detailed.primary_verdict.category().map(|c| c.to_string());
    let tier1_conf = detailed.primary_verdict.confidence().unwrap_or(0.0);
    let tier1_reason = detailed.primary_verdict.reason().to_string();
    let tier1_status = if detailed.escalated {
        "escalated".to_string()
    } else {
        "resolved".to_string()
    };

    let tier1 = TierStageDetail {
        stage_name: "Tier 1 • System-1 Fast Text".to_string(),
        model: detailed.primary_model.clone(),
        status: tier1_status,
        violates: tier1_violates,
        category: tier1_cat.clone(),
        confidence: tier1_conf,
        reason: tier1_reason.clone(),
    };

    let tier2 = if detailed.escalated {
        if let Some(ref fb) = detailed.fallback_verdict {
            TierStageDetail {
                stage_name: "Tier 2 • System-2 Fallback".to_string(),
                model: detailed
                    .fallback_model
                    .clone()
                    .unwrap_or_else(|| "fallback".to_string()),
                status: "resolved".to_string(),
                violates: fb.is_violation(),
                category: fb.category().map(|c| c.to_string()),
                confidence: fb.confidence().unwrap_or(0.0),
                reason: fb.reason().to_string(),
            }
        } else {
            TierStageDetail {
                stage_name: "Tier 2 • System-2 Fallback".to_string(),
                model: detailed
                    .fallback_model
                    .clone()
                    .unwrap_or_else(|| "fallback".to_string()),
                status: "escalated".to_string(),
                violates: false,
                category: None,
                confidence: 0.0,
                reason: detailed.escalation_reason.clone().unwrap_or_default(),
            }
        }
    } else {
        TierStageDetail {
            stage_name: "Tier 2 • System-2 Fallback".to_string(),
            model: detailed
                .fallback_model
                .clone()
                .unwrap_or_else(|| "fallback".to_string()),
            status: "bypassed".to_string(),
            violates: false,
            category: None,
            confidence: 0.0,
            reason: detailed.escalation_reason.clone().unwrap_or_else(|| {
                "Bypassed: Tier 1 resolved decisively (System-2 GPU inference spared)".to_string()
            }),
        }
    };

    let target_handle = state
        .engine
        .tenant_registry()
        .get(&target_did)
        .ok()
        .flatten()
        .and_then(|t| t.handle)
        .unwrap_or_default();

    let final_violates = detailed.final_verdict.is_violation();
    let final_confidence = detailed.final_verdict.confidence().unwrap_or(1.0);

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

    let fallback_confidence = detailed
        .fallback_verdict
        .as_ref()
        .and_then(|v| v.confidence());

    let primary_conf = tier1_conf;

    if let Err(e) = state
        .engine
        .cache()
        .record_evaluation_log(&NewEvaluationLog {
            timestamp_us: crate::modlist::cache::current_time_us(),
            source: "simulation".to_string(),
            post_uri: format!("at://{author_did}/app.bsky.feed.post/simulated"),
            post_text: text.to_string(),
            author_did: author_did.clone(),
            author_handle: "simulated-test.bsky.social".to_string(),
            target_did: target_did.clone(),
            target_handle,
            has_images: images_evaluated > 0,
            primary_model: detailed.primary_model.clone(),
            primary_action: if tier1_violates {
                "violation".to_string()
            } else {
                "allow".to_string()
            },
            primary_confidence: primary_conf,
            primary_category: tier1_cat.clone().unwrap_or_default(),
            primary_reason: tier1_reason.clone(),
            escalated: detailed.escalated,
            escalation_reason: detailed.escalation_reason.clone(),
            fallback_model: detailed.fallback_model.clone(),
            fallback_action: detailed.fallback_verdict.as_ref().map(|v| {
                if v.is_violation() {
                    "violation".to_string()
                } else {
                    "allow".to_string()
                }
            }),
            fallback_confidence,
            fallback_category: detailed
                .fallback_verdict
                .as_ref()
                .and_then(|v| v.category().map(|c| c.to_string())),
            fallback_reason: detailed
                .fallback_verdict
                .as_ref()
                .map(|v| v.reason().to_string()),
            final_action: if final_violates {
                "violation".to_string()
            } else {
                "allow".to_string()
            },
            final_confidence,
            outcome: sim_outcome_str.to_string(),
        })
    {
        tracing::warn!(error = %e, "Failed to record simulated evaluation log");
    }

    match detailed.final_verdict {
        Verdict::Violation {
            category,
            confidence,
            reason,
        } => {
            let meets_threshold = rubric.meets_threshold(&category, confidence);
            let evaluator = if reason.contains("uncertainty escalation") {
                "fallback_uncertainty_classifier".to_string()
            } else if reason.contains("Fallback") || reason.contains("Tiered") {
                "fallback_vision_classifier".to_string()
            } else if images_evaluated > 0 {
                "primary_classifier (multimodal)".to_string()
            } else {
                "primary_classifier".to_string()
            };
            Ok(Json(SimulateResponse {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                reason,
                evaluator,
                meets_threshold,
                threshold,
                images_evaluated,
                tier1: Some(tier1),
                tier2: Some(tier2),
            }))
        }
        Verdict::Permitted { reason, confidence } => {
            let evaluator = if reason.contains("uncertainty escalation") {
                "fallback_uncertainty_classifier".to_string()
            } else if reason.contains("Fallback") || reason.contains("Tiered") {
                "fallback_vision_classifier".to_string()
            } else if images_evaluated > 0 {
                "primary_classifier (multimodal)".to_string()
            } else {
                "primary_classifier".to_string()
            };
            Ok(Json(SimulateResponse {
                violates: false,
                category: None,
                confidence: confidence.unwrap_or(0.05),
                reason,
                evaluator,
                meets_threshold: false,
                threshold,
                images_evaluated,
                tier1: Some(tier1),
                tier2: Some(tier2),
            }))
        }
    }
}

/// Query parameter for session-aware endpoints.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SessionQuery {
    /// Optional DID passed as query parameter.
    pub did: Option<String>,
}

/// Details of the currently authenticated user session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionResponse {
    /// Whether a valid user session is active.
    pub authenticated: bool,
    /// Authenticated decentralized identifier (DID), if signed in.
    pub did: Option<String>,
    /// Bluesky handle if known.
    pub handle: Option<String>,
    /// Whether the user has system administrator privileges.
    pub is_admin: bool,
    /// Whether automated defense is active for this tenant.
    pub is_active: bool,
    /// AT-URI of the sovereign moderation list on PDS, if provisioned.
    pub mod_list_uri: Option<String>,
    /// Active moderation rubric for this user.
    pub rubric: Option<RulesResponse>,
    /// Whether auto-blocking is actively established on the user's sovereign PDS via app.bsky.graph.listblock.
    #[serde(default)]
    pub is_list_blocked: bool,
    /// Number of actively monitored accounts across the fleet (only visible to administrators).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitored_users_count: Option<usize>,
}

/// Summary of an enrolled tenant for administrative fleet oversight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSummary {
    /// Decentralized identifier (DID) of the tenant.
    pub did: String,
    /// Bluesky handle if known.
    pub handle: Option<String>,
    /// Whether automated moderation is active.
    pub is_active: bool,
    /// Whether an active OAuth session exists.
    pub has_session: bool,
    /// AT-URI of the sovereign moderation list on PDS.
    pub mod_list_uri: Option<String>,
    /// Unix timestamp in microseconds when enrolled.
    pub created_at: u64,
    /// Unix timestamp in microseconds when last updated.
    pub updated_at: u64,
}

/// Response payload for administrative multi-tenant fleet overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTenantsResponse {
    /// Total enrolled tenants count.
    pub total: usize,
    /// Count of actively defended tenants.
    pub active_count: usize,
    /// Count of paused tenants.
    pub paused_count: usize,
    /// Total count of users actively monitored by the moderation engine.
    #[serde(default)]
    pub monitored_count: usize,
    /// List of tenant summaries.
    pub tenants: Vec<TenantSummary>,
}

/// Request payload to toggle defense activation for a tenant.
#[derive(Debug, Clone, Deserialize)]
pub struct ToggleTenantRequest {
    /// Target DID to toggle (defaults to caller's DID).
    pub did: Option<String>,
    /// Explicit target active state (`true` for active, `false` for paused).
    pub is_active: Option<bool>,
}

/// Response payload after toggling tenant activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToggleTenantResponse {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Target DID.
    pub did: String,
    /// Resulting active status (`true` if active, `false` if paused).
    pub is_active: bool,
    /// Status message.
    pub message: String,
}

/// Handler for `GET /api/me`: returns authenticated session info and permissions.
pub async fn get_current_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Json<UserSessionResponse> {
    let did_opt = extract_authenticated_caller(&headers, &state.engine);

    if let Some(did) = did_opt {
        let is_admin = state.engine.is_admin(&did);
        let mod_list_uri = state
            .engine
            .cache()
            .get_mod_list(&did)
            .ok()
            .flatten()
            .map(|c| c.list_uri);
        let is_list_blocked = state.engine.cache().is_list_blocked(&did).unwrap_or(false);

        // Dynamically resolve handle if missing or empty
        let resolved_handle = state.engine.resolve_did_to_handle(&did).await;

        let monitored_users_count = if is_admin {
            Some(state.engine.protected_dids().len())
        } else {
            None
        };

        if let Ok(Some(tenant)) = state.engine.tenant_registry().get(&did) {
            let rubric = tenant.rubric.unwrap_or_else(|| state.engine.rubric());
            let handle = tenant.handle.or(resolved_handle);
            return Json(UserSessionResponse {
                authenticated: true,
                did: Some(tenant.did),
                handle,
                is_admin,
                is_active: tenant.is_active,
                mod_list_uri,
                rubric: Some(RulesResponse {
                    prompt: rubric.prompt,
                    sensitivity: rubric.sensitivity,
                    threshold: rubric.sensitivity.threshold(),
                    bounce_duration: rubric.bounce_duration,
                }),
                is_list_blocked,
                monitored_users_count,
            });
        }

        if state.engine.is_protected(&did) || is_admin {
            let rubric = state.engine.rubric();
            return Json(UserSessionResponse {
                authenticated: true,
                did: Some(did.clone()),
                handle: resolved_handle,
                is_admin,
                is_active: !state.engine.is_tenant_paused(&did),
                mod_list_uri,
                rubric: Some(RulesResponse {
                    prompt: rubric.prompt,
                    sensitivity: rubric.sensitivity,
                    threshold: rubric.sensitivity.threshold(),
                    bounce_duration: rubric.bounce_duration,
                }),
                is_list_blocked,
                monitored_users_count,
            });
        }
    }

    Json(UserSessionResponse {
        authenticated: false,
        did: None,
        handle: None,
        is_admin: false,
        is_active: false,
        mod_list_uri: None,
        rubric: None,
        is_list_blocked: false,
        monitored_users_count: None,
    })
}

/// Handler for `GET /api/admin/tenants`: returns multi-tenant fleet overview (admin only).
pub async fn get_admin_tenants(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<AdminTenantsResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to access tenant fleet. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    if !state.engine.is_admin(&caller_did) {
        return Err((
            StatusCode::FORBIDDEN,
            "Administrator privileges required to access tenant fleet".to_string(),
        ));
    }

    let all_tenants = state
        .engine
        .tenant_registry()
        .list_all()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut active_count = 0;
    let mut paused_count = 0;
    let mut summaries = Vec::with_capacity(all_tenants.len());

    for t in all_tenants {
        if t.is_active {
            active_count += 1;
        } else {
            paused_count += 1;
        }

        let mod_list_uri = state
            .engine
            .cache()
            .get_mod_list(&t.did)
            .ok()
            .flatten()
            .map(|c| c.list_uri);

        let handle = t
            .handle
            .or_else(|| state.engine.cached_handle_for_did(&t.did));

        summaries.push(TenantSummary {
            did: t.did,
            handle,
            is_active: t.is_active,
            has_session: t.session.is_some(),
            mod_list_uri,
            created_at: t.created_at,
            updated_at: t.updated_at,
        });
    }

    let monitored_count = state.engine.protected_dids().len();

    Ok(Json(AdminTenantsResponse {
        total: summaries.len(),
        active_count,
        paused_count,
        monitored_count,
        tenants: summaries,
    }))
}

/// Query parameters for administrative evaluation log requests.
#[derive(Debug, Deserialize, Default)]
pub struct AdminEvaluationsQuery {
    /// Active authenticated caller DID (or session parameter).
    pub did: Option<String>,
    /// Optional target DID filter.
    pub target_did: Option<String>,
    /// Optional source filter: "all", "live", or "simulation".
    pub source: Option<String>,
    /// Max entries to return (default: 50, max: 200).
    pub limit: Option<usize>,
    /// Pagination offset.
    pub offset: Option<usize>,
}

/// Response payload containing evaluation logs for administrative audit.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminEvaluationsResponse {
    /// Total count of evaluation logs matching filter.
    pub total: usize,
    /// List of evaluation log entries.
    pub evaluations: Vec<EvaluationLogEntry>,
}

/// Query parameters for tenant evaluation logs (`GET /api/evaluations`).
#[derive(Debug, Deserialize)]
pub struct EvaluationsQuery {
    /// Optional target DID filter (for admins; regular users can only view their own).
    pub target_did: Option<String>,
    /// Optional source filter: "all", "live", or "simulation".
    pub source: Option<String>,
    /// Max entries to return (default: 50, max: 200).
    pub limit: Option<usize>,
    /// Pagination offset.
    pub offset: Option<usize>,
}

/// Response payload containing evaluation logs for tenant or administrative audit.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluationsResponse {
    /// Total count of evaluation logs matching filter.
    pub total: usize,
    /// List of evaluation log entries.
    pub evaluations: Vec<EvaluationLogEntry>,
}

/// Handler for `GET /api/evaluations`: returns evaluation audit logs scoped to the authenticated caller
/// (or target DID for admins) adhering to PRD §7.1 Item 3.
pub async fn get_evaluations(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<EvaluationsQuery>,
) -> Result<Json<EvaluationsResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to access evaluation audit logs. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let target_filter = if is_admin {
        query.target_did.as_deref().filter(|s| !s.trim().is_empty())
    } else {
        if let Some(requested_did) = query.target_did.as_deref().filter(|s| !s.trim().is_empty()) {
            if requested_did != caller_did {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Access denied: you may only view evaluation logs for your own account."
                        .to_string(),
                ));
            }
        }
        Some(caller_did.as_str())
    };

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let source_filter = query.source.as_deref();

    let total = state
        .engine
        .cache()
        .count_evaluation_logs(target_filter, source_filter)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let evaluations = state
        .engine
        .cache()
        .list_evaluation_logs(target_filter, source_filter, limit, offset)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(EvaluationsResponse { total, evaluations }))
}

/// Handler for `GET /api/admin/evaluations`: returns comprehensive Tier 1 & Tier 2 evaluation log (admin only).
pub async fn get_admin_evaluations(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AdminEvaluationsQuery>,
) -> Result<Json<AdminEvaluationsResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Administrator privileges required to access evaluation audit logs. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    if !state.engine.is_admin(&caller_did) {
        return Err((
            StatusCode::FORBIDDEN,
            "Administrator privileges required to access evaluation audit logs".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let target_filter = query.target_did.as_deref();
    let source_filter = query.source.as_deref();

    let total = state
        .engine
        .cache()
        .count_evaluation_logs(target_filter, source_filter)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let evaluations = state
        .engine
        .cache()
        .list_evaluation_logs(target_filter, source_filter, limit, offset)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AdminEvaluationsResponse { total, evaluations }))
}

/// Handler for `POST /api/tenant/toggle`: toggles defense active/paused state for a tenant.
pub async fn toggle_tenant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<ToggleTenantRequest>,
) -> Result<Json<ToggleTenantResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to change defense status. Please sign in with Bluesky."
                .to_string(),
        )
    })?;
    let is_admin = state.engine.is_admin(&caller_did);

    let target_did = payload.did.unwrap_or_else(|| caller_did.clone());

    if !is_admin && caller_did != target_did {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot modify other tenant status without admin privileges".to_string(),
        ));
    }

    let current_tenant = state
        .engine
        .tenant_registry()
        .get(&target_did)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let new_active = match payload.is_active {
        Some(explicit) => explicit,
        None => match current_tenant {
            Some(ref t) => !t.is_active,
            None => false,
        },
    };

    state
        .engine
        .tenant_registry()
        .set_active(&target_did, new_active)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update tenant status: {e}"),
            )
        })?;

    if (state.engine.is_admin(&target_did) || state.engine.is_single_tenant())
        && state.engine.is_protected(&target_did)
    {
        if new_active {
            state.engine.resume();
        } else {
            state.engine.pause();
        }
    }

    let status_str = if new_active { "resumed" } else { "paused" };
    Ok(Json(ToggleTenantResponse {
        success: true,
        did: target_did.clone(),
        is_active: new_active,
        message: format!("Automated defense {status_str} for {target_did}"),
    }))
}

/// Handler for `POST /api/auth/logout`: clears session cookie and returns unauthenticated state.
pub async fn logout(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(s) = cookie_header.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("skybouncer_session=") {
                    let token = val.trim();
                    if !token.is_empty() {
                        let _ = state.engine.tenant_registry().delete_web_session(token);
                    }
                }
            }
        }
    }

    let mut resp = Json(serde_json::json!({ "logged_out": true })).into_response();
    if let Ok(cookie_val) = HeaderValue::from_str(
        "skybouncer_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure",
    ) {
        resp.headers_mut().insert(header::SET_COOKIE, cookie_val);
    }
    resp
}

/// Query parameters for resolving a Bluesky identity.
#[derive(Debug, Clone, Deserialize)]
pub struct ResolveQuery {
    /// Generic identifier (DID or handle).
    #[serde(default)]
    pub actor: Option<String>,
    /// Decentralized identifier (DID).
    #[serde(default)]
    pub did: Option<String>,
    /// Bluesky handle.
    #[serde(default)]
    pub handle: Option<String>,
}

/// Response payload containing resolved DID and handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveResponse {
    /// Decentralized identifier (DID), if resolved or provided.
    pub did: Option<String>,
    /// Bluesky handle without leading '@', if resolved or provided.
    pub handle: Option<String>,
}

/// Handler for `GET /api/resolve`: resolves a DID to a handle, or a handle to a DID.
///
/// Authentication is strictly required, as resolution may perform outbound AppView/PLC
/// lookups for cache misses.
pub async fn resolve_identity(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ResolveQuery>,
) -> Result<Json<ResolveResponse>, (StatusCode, String)> {
    extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to resolve identities. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    let raw_did = query.did.as_deref().or_else(|| {
        query
            .actor
            .as_deref()
            .filter(|s| s.trim().starts_with("did:"))
    });
    if let Some(did) = raw_did {
        let clean_did = did.trim();
        let handle = state.engine.resolve_did_to_handle(clean_did).await;
        return Ok(Json(ResolveResponse {
            did: Some(clean_did.to_string()),
            handle,
        }));
    }

    let raw_handle = query.handle.as_deref().or_else(|| {
        query
            .actor
            .as_deref()
            .filter(|s| !s.trim().starts_with("did:"))
    });
    if let Some(handle) = raw_handle.filter(|s| !s.trim().is_empty()) {
        let clean_handle = handle.trim().trim_start_matches('@');
        let did = state.engine.resolve_handle(clean_handle).await;
        return Ok(Json(ResolveResponse {
            did,
            handle: Some(clean_handle.to_string()),
        }));
    }

    Err((
        StatusCode::BAD_REQUEST,
        "Query parameter 'did', 'handle', or 'actor' is required".to_string(),
    ))
}
