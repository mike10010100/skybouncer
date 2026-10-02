//! ATProto OAuth 2.0 PKCE and DPoP authentication endpoints.
//!
//! Provides endpoints compliant with the ATProto OAuth 2.0 specification:
//! - `GET /oauth/client-metadata.json`: Serves the OAuth Client Metadata Document.
//! - `GET /oauth/login`: Initiates OAuth authorization flow with user handle.
//! - `GET /oauth/callback`: Handles the redirect callback, verifies PKCE + DPoP, and exchanges code for session.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Redirect, Response};
use serde::Deserialize;
use tracing::{error, info, warn};

use skyauth::client::{AtprotoOAuthClient, OAuthClientMetadata};
use skyauth::integrations::axum::{client_metadata_response, redirect_to_authorization};
use skyauth::integrations::OAuthCallbackQuery;

/// Shared state for OAuth route handlers.
#[derive(Clone)]
pub struct OAuthState {
    /// Initialized ATProto OAuth client, if configured.
    pub oauth_client: Option<Arc<AtprotoOAuthClient>>,
    /// Client metadata document.
    pub metadata: OAuthClientMetadata,
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
) -> Result<Redirect, (StatusCode, String)> {
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
            )));
        }
    };

    match client.handle_callback(&params).await {
        Ok(session) => {
            info!(did = %session.sub, "OAuth authorization completed successfully");
            Ok(Redirect::to(&format!(
                "/?auth=success&did={}",
                urlencoding_simple(&session.sub)
            )))
        }
        Err(e) => {
            error!(error = %e, "Failed to exchange OAuth authorization code for session");
            Ok(Redirect::to(&format!(
                "/?auth=error&error={}",
                urlencoding_simple(&e.to_string())
            )))
        }
    }
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
