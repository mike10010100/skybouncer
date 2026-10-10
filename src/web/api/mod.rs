//! REST API handlers and payload models for the Skybouncer Web Dashboard.
//!
//! Provides endpoints for:
//! - Engine telemetry and status inspection (`GET /api/status`).
//! - Moderation rubric inspection and live updates (`GET /api/rules`, `POST /api/rules`).
//! - Bounced violator listing (`GET /api/bounces`).
//! - One-click account pardon and unban (`POST /api/pardon`).
//! - Interactive dry-run evaluation simulator (`POST /api/simulate`).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::classifier::{BounceDuration, RuleRubric, Sensitivity};
use crate::engine::{EngineStatsSnapshot, SkybouncerEngine};
use crate::modlist::cache::EvaluationLogEntry;
use crate::modlist::BouncedUser;
use crate::types::default_true;

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
    /// Whether accounts following the protected user bypass moderation evaluation.
    #[serde(default = "default_true")]
    pub bypass_incoming_followers: bool,
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
    /// Optional updated incoming-follower bypass toggle.
    #[serde(default)]
    pub bypass_incoming_followers: Option<bool>,
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

/// Record of a bounced violator enriched with the resolved ATProto handle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BouncedUserWithHandle {
    /// The underlying bounced user record.
    #[serde(flatten)]
    pub user: BouncedUser,
    /// Resolved ATProto handle of the bounced violator, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Resolved ATProto handle of the protected user whose moderation list the violator was added to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_handle: Option<String>,
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

mod auth;
mod bounces;
mod resolve;
mod simulate;
mod telemetry;
mod tenant;
pub use auth::*;
pub use bounces::*;
pub use resolve::*;
pub use simulate::*;
pub use telemetry::*;
pub use tenant::*;
