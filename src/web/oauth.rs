//! ATProto OAuth 2.0 PKCE and DPoP authentication endpoints.
//!
//! Provides endpoints compliant with the ATProto OAuth 2.0 specification:
//! - `GET /oauth/client-metadata.json`: Serves the OAuth Client Metadata Document.
//! - `GET /oauth/login`: Initiates OAuth authorization flow with user handle.
//! - `GET /oauth/callback`: Handles the redirect callback, verifies PKCE + DPoP, and exchanges code for session.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use tracing::{error, info, warn};

use skyauth::client::{AtprotoOAuthClient, OAuthClientMetadata};
use skyauth::integrations::axum::{client_metadata_response, redirect_to_authorization};
use skyauth::integrations::OAuthCallbackQuery;

use crate::engine::SkybouncerEngine;
use crate::tenant::Tenant;

/// Shared state for OAuth route handlers.
#[derive(Clone)]
pub struct OAuthState {
    /// Initialized ATProto OAuth client, if configured.
    pub oauth_client: Option<Arc<AtprotoOAuthClient>>,
    /// Client metadata document.
    pub metadata: OAuthClientMetadata,
    /// Reference to moderation engine for multi-tenant enrollment.
    pub engine: Option<Arc<SkybouncerEngine>>,
}

/// Query parameters for initiating OAuth login.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginQuery {
    /// Bluesky handle or DID to authenticate (e.g. `alice.bsky.social`).
    pub handle: Option<String>,
}

/// Handler for `GET /oauth/client-metadata.json`.
///
/// Serves the compliant RFC 7591 / ATProto OAuth client metadata document.
pub async fn get_client_metadata(
    State(state): State<OAuthState>,
) -> Result<Response, (StatusCode, String)> {
    client_metadata_response(&state.metadata).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to generate client metadata response: {e}"),
        )
    })
}

/// Handler for `GET /oauth/login`.
///
/// Initiates the PAR and PKCE authorization flow for the provided Bluesky handle.
pub async fn oauth_login(
    State(state): State<OAuthState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, (StatusCode, String)> {
    let handle = query
        .handle
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Query parameter 'handle' is required (e.g. ?handle=alice.bsky.social)".to_string(),
            )
        })?;

    let client = state.oauth_client.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "ATProto OAuth client is not configured on this server".to_string(),
        )
    })?;

    info!(handle = %handle, "Initiating ATProto OAuth login flow");

    match client.authorize(handle).await {
        Ok(auth_req) => redirect_to_authorization(&auth_req).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to construct authorization redirect: {e}"),
            )
        }),
        Err(e) => {
            error!(error = %e, handle = %handle, "OAuth authorization request failed");
            Err((
                StatusCode::BAD_GATEWAY,
                format!("Failed to initiate authorization with user's PDS: {e}"),
            ))
        }
    }
}

/// Handler for `GET /oauth/callback`.
///
/// Processes the OAuth code exchange and redirects back to the dashboard with auth status.
pub async fn oauth_callback(
    State(state): State<OAuthState>,
    query: OAuthCallbackQuery,
) -> Result<Response, (StatusCode, String)> {
    if query.code.is_none() && query.error.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing authorization code or error in callback".to_string(),
        ));
    }

    let client = state.oauth_client.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "ATProto OAuth client is not configured on this server".to_string(),
        )
    })?;

    let params = match query.to_callback_params() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Invalid or error OAuth callback query");
            return Ok(Redirect::to(&format!(
                "/?auth=error&error={}",
                urlencoding_simple(&e.to_string())
            ))
            .into_response());
        }
    };

    match client.handle_callback(&params).await {
        Ok(session) => {
            let did = session.sub.clone();
            info!(did = %did, "OAuth authorization completed successfully");

            if let Some(ref engine) = state.engine {
                let tenant = Tenant::new(did.clone()).with_session(session);
                if let Err(e) = engine.enroll_tenant(tenant) {
                    error!(error = %e, did = %did, "Failed to enroll tenant into registry");
                } else {
                    info!(did = %did, "Enrolled tenant into Skybouncer engine");
                    let eng = Arc::clone(engine);
                    let enroll_did = did.clone();
                    tokio::spawn(async move {
                        let _ = eng.resolve_did_to_handle(&enroll_did).await;
                        if let Err(e) = eng.ensure_mod_list(&enroll_did).await {
                            tracing::warn!(error = %e, did = %enroll_did, "Failed to ensure mod list on enrollment");
                        }
                        if let Err(e) = eng.sync_sovereign_config(&enroll_did).await {
                            tracing::warn!(error = %e, did = %enroll_did, "Failed to sync sovereign config on enrollment");
                        }
                    });
                }
            }

            let session_token = if let Some(ref engine) = state.engine {
                match engine
                    .tenant_registry()
                    .create_web_session(&did, Duration::from_secs(30 * 86400))
                {
                    Ok(t) => t,
                    Err(e) => {
                        error!(error = %e, did = %did, "Failed to create web session in SQLite");
                        return Ok(
                            Redirect::to("/?auth=error&reason=session_failed").into_response()
                        );
                    }
                }
            } else {
                return Ok(Redirect::to("/?auth=error&reason=no_engine").into_response());
            };

            let redirect_target = "/?auth=success";
            let mut response = Redirect::to(redirect_target).into_response();

            // Detect if running on HTTPS
            let is_https = state.metadata.redirect_uri.starts_with("https://");
            let secure_attr = if is_https { "; Secure" } else { "" };

            let cookie_header = format!(
                "skybouncer_session={session_token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax{secure_attr}"
            );
            if let Ok(cookie_val) = axum::http::HeaderValue::from_str(&cookie_header) {
                response
                    .headers_mut()
                    .insert(axum::http::header::SET_COOKIE, cookie_val);
            }

            Ok(response)
        }
        Err(e) => {
            error!(error = %e, "Failed to exchange OAuth authorization code for session");
            Ok(Redirect::to(&format!(
                "/?auth=error&error={}",
                urlencoding_simple(&e.to_string())
            ))
            .into_response())
        }
    }
}

/// Handler for `GET /auth` convenience onboarding route.
///
/// Redirects to `/oauth/login` with user handle if provided, or to the dashboard login page.
pub async fn auth_redirect(Query(query): Query<LoginQuery>) -> Redirect {
    if let Some(ref handle) = query.handle {
        let trimmed = handle.trim();
        if !trimmed.is_empty() {
            return Redirect::to(&format!(
                "/oauth/login?handle={}",
                urlencoding_simple(trimmed)
            ));
        }
    }
    Redirect::to("/?auth=login")
}

/// Simple URL encoder for error and success redirect query parameters.
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
