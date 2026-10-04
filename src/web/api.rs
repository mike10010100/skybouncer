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

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
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
    /// Optional base64-encoded image attached to the candidate post.
    #[serde(default)]
    pub image_base64: Option<String>,
    /// Optional image URL to fetch and evaluate.
    #[serde(default)]
    pub image_url: Option<String>,
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
    let stats = state.engine.stats().snapshot();
    let mut protected_dids: Vec<String> = state.engine.protected_dids().into_iter().collect();
    protected_dids.sort();

    // Redact private prompt for unauthenticated callers
    let caller_did = extract_authenticated_caller(&headers);
    let is_admin = caller_did
        .as_deref()
        .is_some_and(|did| state.engine.is_admin(did));

    let rubric = if let Some(ref did) = caller_did {
        state.engine.rubric_for(did)
    } else {
        RuleRubric {
            prompt: "[Protected sovereign rubric - sign in to view]".to_string(),
            sensitivity: state.engine.rubric().sensitivity,
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

/// Extracts the verified authenticated caller DID strictly from Cookie or x-skybouncer-did header.
pub fn extract_authenticated_caller(headers: &HeaderMap) -> Option<String> {
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(s) = cookie_header.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("skybouncer_did=") {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }

    if let Some(h) = headers.get("x-skybouncer-did") {
        if let Ok(s) = h.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
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
    let caller_did = extract_authenticated_caller(headers).ok_or_else(|| {
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

    let is_enrolled = state
        .engine
        .tenant_registry()
        .is_enrolled(&target_did)
        .unwrap_or(false);
    if is_enrolled {
        let _ = state
            .engine
            .tenant_registry()
            .update_rubric(&target_did, &rubric);
    }

    if state.engine.is_admin(&target_did) || state.engine.is_protected(&target_did) {
        state.engine.set_rubric(rubric.clone());
    }

    // Asynchronously persist updated rubric to user's sovereign PDS repository
    let eng = state.engine.clone();
    let publish_did = target_did.clone();
    tokio::spawn(async move {
        let _ = eng.publish_sovereign_config(&publish_did).await;
    });

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

/// Handler for `POST /api/simulate`: runs a dry-run evaluation on sample text and optional images.
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

    let mut image_cids = Vec::new();
    let mut images_base64 = Vec::new();

    if let Some(b64) = payload.image_base64.filter(|s| !s.trim().is_empty()) {
        images_base64.push(b64);
        image_cids.push("simulate-base64-image".to_string());
    } else if let Some(url) = payload.image_url.filter(|s| !s.trim().is_empty()) {
        // Fetch remote image if valid HTTP/HTTPS URL
        if url.starts_with("http://") || url.starts_with("https://") {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_millis(5000))
                .user_agent("skybouncer/0.1.0 (+https://github.com/mike10010100/skybouncer)")
                .build()
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("HTTP client error: {e}"),
                    )
                })?;
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().is_success() {
                    if let Ok(bytes) = resp.bytes().await {
                        if bytes.len() <= 4 * 1024 * 1024 {
                            use base64::Engine;
                            let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                            images_base64.push(encoded);
                            image_cids.push("simulate-url-image".to_string());
                        }
                    }
                }
            }
        }
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
        author_did,
        target_did,
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
            return Ok(Json(SimulateResponse {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                reason,
                evaluator: "heuristic_prefilter".to_string(),
                meets_threshold,
                threshold,
                images_evaluated,
            }));
        }
    }

    // 2. Primary classifier evaluation (Tiered Jev / Multimodal Fallback)
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
            let evaluator = if reason.contains("Fallback") || reason.contains("Tiered") {
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
            }))
        }
        Ok(Verdict::Permitted { reason, confidence }) => {
            let evaluator = if reason.contains("Fallback") || reason.contains("Tiered") {
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
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Classification failed: {e}"),
        )),
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

/// Extracts caller DID from query string, custom headers, or cookie.
fn extract_did_from_headers(headers: &HeaderMap, query_did: Option<&str>) -> Option<String> {
    if let Some(d) = query_did {
        let trimmed = d.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Some(h) = headers.get("x-skybouncer-did") {
        if let Ok(s) = h.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(s) = cookie_header.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("skybouncer_did=") {
                    let val = val.trim();
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Handler for `GET /api/me`: returns authenticated session info and permissions.
pub async fn get_current_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SessionQuery>,
) -> Json<UserSessionResponse> {
    let did_opt = extract_did_from_headers(&headers, query.did.as_deref());

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
    Query(query): Query<SessionQuery>,
) -> Result<Json<AdminTenantsResponse>, (StatusCode, String)> {
    let did_opt = extract_did_from_headers(&headers, query.did.as_deref());
    let caller_did = did_opt.unwrap_or_default();

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

        let handle = if let Some(h) = t.handle {
            Some(h)
        } else {
            state.engine.resolve_did_to_handle(&t.did).await
        };

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

/// Handler for `POST /api/tenant/toggle`: toggles defense active/paused state for a tenant.
pub async fn toggle_tenant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SessionQuery>,
    Json(payload): Json<ToggleTenantRequest>,
) -> Result<Json<ToggleTenantResponse>, (StatusCode, String)> {
    let caller_did = extract_did_from_headers(&headers, query.did.as_deref()).unwrap_or_default();
    let is_admin = state.engine.is_admin(&caller_did);

    let target_did = payload
        .did
        .or_else(|| {
            if !caller_did.is_empty() {
                Some(caller_did.clone())
            } else {
                None
            }
        })
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing target DID".to_string()))?;

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

    let _ = state
        .engine
        .tenant_registry()
        .set_active(&target_did, new_active);

    if state.engine.protected_dids().contains(&target_did) && is_admin {
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
pub async fn logout() -> Response {
    let mut resp = Json(serde_json::json!({ "logged_out": true })).into_response();
    if let Ok(cookie_val) =
        HeaderValue::from_str("skybouncer_did=; Path=/; Max-Age=0; SameSite=Lax")
    {
        resp.headers_mut().insert(header::SET_COOKIE, cookie_val);
    }
    resp
}
