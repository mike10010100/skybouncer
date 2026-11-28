//! REST API handlers and payload models for the Skybouncer Web Dashboard.
//!
//! Provides endpoints for:
//! - Engine telemetry and status inspection (`GET /api/status`).
//! - Moderation rubric inspection and live updates (`GET /api/rules`, `POST /api/rules`).
//! - Bounced violator listing (`GET /api/bounces`).
//! - One-click account pardon and unban (`POST /api/pardon`).
//! - Interactive dry-run evaluation simulator (`POST /api/simulate`).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

/// Extracts `ConnectInfo<SocketAddr>` when present on request extensions, or `None`
/// in unit tests invoking the router via `ServiceExt::oneshot`.
#[derive(Debug, Clone, Copy)]
pub struct OptionalConnectInfo(pub Option<SocketAddr>);

impl<S> FromRequestParts<S> for OptionalConnectInfo
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let addr = parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        Ok(Self(addr))
    }
}

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
    /// Bounded sliding-window rate limiter for the anonymous live sandbox (`POST /api/simulate/guest`).
    pub guest_limiter: Arc<GuestSandboxLimiter>,
    /// Per-DID rate limiter for authenticated simulator evaluations (`POST /api/simulate`).
    pub simulate_limiter: Arc<crate::limiter::EvaluationRateLimiter>,
    /// Dedicated concurrency semaphore bounding simultaneous simulator LLM evaluations.
    pub simulate_semaphore: Arc<tokio::sync::Semaphore>,
    /// IP-based sliding-window rate limiter for `GET /api/auth/typeahead`.
    pub auth_typeahead_limiter: Arc<GuestSandboxLimiter>,
    /// IP-based sliding-window rate limiter for `GET /api/auth/preview`.
    pub auth_preview_limiter: Arc<GuestSandboxLimiter>,
    /// Publicly configured base URL for origin/CSRF validation and HTTPS cookie flags.
    pub public_url: String,
    /// Optional trusted reverse-proxy client-IP header (`cf-connecting-ip`, `x-real-ip`, or `x-forwarded-for`).
    pub trusted_proxy_header: Option<String>,
    /// Trusted proxy IP/CIDR allowlist required before honoring `trusted_proxy_header`.
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

impl ApiState {
    /// Creates a new [`ApiState`] wrapping `engine` and default rate limiters.
    #[must_use]
    pub fn new(engine: Arc<SkybouncerEngine>) -> Self {
        Self {
            engine,
            guest_limiter: Arc::new(GuestSandboxLimiter::default()),
            simulate_limiter: Arc::new(crate::limiter::EvaluationRateLimiter::new(
                crate::limiter::RateLimiterConfig {
                    max_evaluations: 20,
                    window_duration: std::time::Duration::from_secs(60),
                },
            )),
            simulate_semaphore: Arc::new(tokio::sync::Semaphore::new(2)),
            auth_typeahead_limiter: Arc::new(GuestSandboxLimiter::new(
                30,
                300,
                std::time::Duration::from_secs(60),
            )),
            auth_preview_limiter: Arc::new(GuestSandboxLimiter::new(
                20,
                200,
                std::time::Duration::from_secs(60),
            )),
            public_url: format!(
                "http://{}:{}",
                crate::web::DEFAULT_WEB_HOST,
                crate::web::DEFAULT_WEB_PORT
            ),
            trusted_proxy_header: None,
            trusted_proxies: Vec::new(),
        }
    }

    /// Configures the public base URL used for HTTPS cookie flags and CSRF origin matching.
    #[must_use]
    pub fn with_public_url(mut self, public_url: impl Into<String>) -> Self {
        self.public_url = public_url.into().trim_end_matches('/').to_string();
        self
    }

    /// Configures the trusted reverse-proxy header and CIDR allowlist for client IP extraction.
    #[must_use]
    pub fn with_trusted_proxy(
        mut self,
        header: Option<String>,
        proxies: Vec<ipnet::IpNet>,
    ) -> Self {
        self.trusted_proxy_header = header;
        self.trusted_proxies = proxies;
        self
    }

    /// Configures per-DID rate limits and concurrency semaphore for `POST /api/simulate`.
    #[must_use]
    pub fn with_simulate_limits(mut self, rate_per_min: usize, concurrency: usize) -> Self {
        self.simulate_limiter = Arc::new(crate::limiter::EvaluationRateLimiter::new(
            crate::limiter::RateLimiterConfig {
                max_evaluations: rate_per_min.max(1),
                window_duration: std::time::Duration::from_secs(60),
            },
        ));
        self.simulate_semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        self
    }

    /// Returns `true` if `public_url` uses HTTPS.
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    /// Extracts `(scheme, lowercase_host, effective_port)` for `public_url`.
    #[must_use]
    pub fn public_origin(&self) -> Option<(String, String, u16)> {
        parse_url_origin(&self.public_url)
    }
}

pub(crate) fn parse_url_origin(raw: &str) -> Option<(String, String, u16)> {
    let parsed = url::Url::parse(raw.trim()).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port = parsed.port_or_known_default()?;
    Some((scheme, host, port))
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

/// Request payload to upgrade a temporary bounce on the moderation list to permanent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeBounceRequest {
    /// Decentralized identifier (DID) of the bounced violator to upgrade to permanent.
    pub subject_did: String,
    /// Optional protected DID whose list entry should be upgraded.
    #[serde(default)]
    pub protected_did: Option<String>,
}

/// Response payload following a bounce-to-permanent upgrade execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeBounceResponse {
    /// Whether a temporary bounce was found and upgraded to permanent.
    pub upgraded: bool,
    /// Whether a bounce record existed and was already permanent.
    #[serde(default)]
    pub already_permanent: bool,
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
    /// Optional unsaved draft prompt from the live rules editor.
    #[serde(default)]
    pub draft_prompt: Option<String>,
    /// Optional unsaved draft sensitivity from the live rules editor.
    #[serde(default)]
    pub draft_sensitivity: Option<Sensitivity>,
}

/// Request payload for the rate-limited anonymous live sandbox (`POST /api/simulate/guest`).
///
/// Anonymous callers select one of the built-in public rubric presets rather than supplying
/// arbitrary LLM prompt instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestSimulateRequest {
    /// Sample post text to evaluate (capped to 500 characters).
    pub text: String,
    /// Built-in preset key (`"balanced"`, `"anti_crypto"`, `"anti_hostility"`, or `"anti_ragebait"`).
    #[serde(default)]
    pub preset: Option<String>,
}

/// Response payload for the rate-limited anonymous live sandbox (`POST /api/simulate/guest`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestSimulateResponse {
    /// Core dry-run evaluation verdict and multi-tier breakdown.
    #[serde(flatten)]
    pub simulation: SimulateResponse,
    /// Canonical preset key evaluated for this request.
    pub preset: String,
    /// Remaining evaluations allowed for this client IP within the rolling window.
    pub remaining_quota: usize,
    /// Total evaluations allowed per rolling window for a single client IP.
    pub quota_limit: usize,
    /// Rolling rate-limit window duration in seconds.
    pub window_seconds: u64,
}

/// Detailed stage breakdown for a single tier in the simulation pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TierStageDetail {
    /// Stage title (e.g. "Tier 1 • System-1 Primary (Text)").
    pub stage_name: String,
    /// Model identifier (e.g. "nimble" or "gemma4:26b").
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

/// Query parameters for pre-authentication handle typeahead (`GET /api/auth/typeahead`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthTypeaheadQuery {
    /// Handle or display-name prefix query string.
    #[serde(default)]
    pub q: Option<String>,
    /// Maximum number of suggestions to return (defaults to 6, clamped to `1..=15`).
    #[serde(default)]
    pub limit: Option<u8>,
}

/// A single actor suggestion returned by `GET /api/auth/typeahead`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthActorSuggestion {
    /// Decentralized Identifier of the actor (`did:plc:...` or `did:web:...`).
    pub did: String,
    /// Handle of the actor (e.g. `"alice.bsky.social"`).
    pub handle: String,
    /// Optional user-defined display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional profile avatar URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

/// Response payload for `GET /api/auth/typeahead`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthTypeaheadResponse {
    /// Matching actor suggestions.
    pub actors: Vec<AuthActorSuggestion>,
}

/// Query parameters for pre-flight login identity and provider preview (`GET /api/auth/preview`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthPreviewQuery {
    /// Handle or DID to preview prior to OAuth redirect.
    #[serde(default)]
    pub handle: Option<String>,
}

/// Pre-flight identity and provider resolution response for `GET /api/auth/preview`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPreviewResponse {
    /// Resolved Decentralized Identifier (`did:plc:...` or `did:web:...`).
    pub did: String,
    /// Canonical AT Protocol handle (e.g. `"alice.bsky.social"`).
    pub handle: String,
    /// Optional user-defined display name from AppView profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional profile avatar URL from AppView profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// Authoritative Personal Data Server endpoint URL.
    pub pds_endpoint: String,
    /// Hostname of the user's Personal Data Server (e.g. `"bsky.social"` or `"pds.example.com"`).
    pub pds_host: String,
    /// Hostname of the OAuth Authorization Server guarding the PDS.
    pub auth_server_host: String,
    /// Whether a bare handle without a domain was expanded to `.bsky.social`.
    pub assumed_bsky_social: bool,
}

mod auth;
mod bounces;
mod resolve;
mod simulate;
mod storms;
mod telemetry;
mod tenant;
pub use auth::*;
pub use bounces::*;
pub use resolve::*;
pub use simulate::*;
pub use storms::*;
pub use telemetry::*;
pub use tenant::*;

/// Query parameters for fetching dogpile storms (`GET /api/storms`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct StormsQuery {
    /// Optional target DID filter (admin-only when targeting another account).
    #[serde(default)]
    pub user_did: Option<String>,
    /// If `true`, returns only currently active storms.
    #[serde(default)]
    pub active_only: Option<bool>,
    /// Maximum number of storms to return (defaults to 20, clamped to `1..=100`).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Response payload returned by `GET /api/storms`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StormsResponse {
    /// Whether Storm Mode is currently active for the target account.
    pub storm_mode_active: bool,
    /// Matching dogpile storm events ordered newest-first.
    pub storms: Vec<crate::dogpile::StormEvent>,
}

/// Request payload to toggle Storm Mode (`POST /api/storms/mode`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StormModeRequest {
    /// Whether to activate (`true`) or exit (`false`) Storm Mode.
    pub enabled: bool,
    /// Optional target DID (admin-only for another user).
    #[serde(default)]
    pub target_did: Option<String>,
}

/// Response payload returned by `POST /api/storms/mode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StormModeResponse {
    /// Protected target DID whose Storm Mode state was updated.
    pub target_did: String,
    /// Updated Storm Mode state.
    pub storm_mode_active: bool,
}

/// Request payload to dismiss a storm event (`POST /api/storms/dismiss`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DismissStormRequest {
    /// Database identifier of the storm to dismiss.
    pub storm_id: i64,
}

/// Response payload returned by `POST /api/storms/dismiss`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DismissStormResponse {
    /// Database identifier of the dismissed storm.
    pub storm_id: i64,
    /// `true` if a matching storm row was updated to dismissed.
    pub dismissed: bool,
}

/// Request payload to lock replies on a user's post via `app.bsky.feed.threadgate` (`POST /api/storms/lock`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockThreadRequest {
    /// Canonical AT-URI, Bluesky web URL, or bare `rkey` of the user's post.
    pub post_uri: String,
    /// Optional policy slug (`following`, `followers`, `mentions`, `nobody`; defaults to `following`).
    #[serde(default)]
    pub policy: Option<String>,
    /// Optional protected account DID (admin-only for another user).
    #[serde(default)]
    pub protected_did: Option<String>,
}

/// Request payload to remove a threadgate lock (`POST /api/storms/unlock`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockThreadRequest {
    /// Canonical AT-URI, Bluesky web URL, or bare `rkey` of the user's post.
    pub post_uri: String,
    /// Optional protected account DID (admin-only for another user).
    #[serde(default)]
    pub protected_did: Option<String>,
}

/// Request payload to detach quote-posts via `app.bsky.feed.postgate` (`POST /api/storms/detach`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachQuotesRequest {
    /// Canonical AT-URI, Bluesky web URL, or bare `rkey` of the user's post.
    pub post_uri: String,
    /// Optional explicit catalyst quote-post AT-URIs to detach (defaults to stored catalysts when empty).
    #[serde(default)]
    pub qt_uris: Option<Vec<String>>,
    /// When `true`, also adds `app.bsky.feed.postgate#disableRule` to disable all future quote-posts.
    #[serde(default)]
    pub disable_all_quotes: Option<bool>,
    /// Optional protected account DID (admin-only for another user).
    #[serde(default)]
    pub protected_did: Option<String>,
}

/// Response payload for sovereign PDS shield mutations (`lock`, `unlock`, `detach`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldActionResponse {
    /// Whether the PDS shield mutation succeeded.
    pub success: bool,
    /// Action identifier (`"lock"`, `"unlock"`, or `"detach"`).
    pub action: String,
    /// Canonical AT-URI of the protected post.
    pub post_uri: String,
    /// Canonical AT-URI of the written `threadgate` or `postgate` record, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_uri: Option<String>,
    /// Total number of detached quote-post URIs currently stored on the `postgate`, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detached_count: Option<usize>,
    /// Whether the engine executed in dry-run shadow mode without writing to PDS.
    pub dry_run: bool,
}
