//! ATProto OAuth 2.0 PKCE and DPoP authentication endpoints.
//!
//! Provides endpoints compliant with the ATProto OAuth 2.0 specification:
//! - `GET /oauth/client-metadata.json`: Serves the OAuth Client Metadata Document.
//! - `GET /oauth/login`: Initiates OAuth authorization flow with user handle.
//! - `GET /oauth/callback`: Handles the redirect callback, verifies PKCE + DPoP, and exchanges code for session.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use tracing::{error, info, warn};

use skyauth::client::{AtprotoOAuthClient, OAuthClientMetadata};
use skyauth::integrations::axum::{client_metadata_response, redirect_to_authorization};
use skyauth::integrations::OAuthCallbackQuery;

use crate::engine::SkybouncerEngine;

const OAUTH_STATE_COOKIE: &str = "skybouncer_oauth_state";

fn sha256_hex(raw: &str) -> String {
    let digest = skyauth::crypto::sha256_digest(raw.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(val) = trimmed.strip_prefix(&prefix) {
            let val = val.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Shared state for OAuth route handlers.
#[derive(Clone)]
pub struct OAuthState {
    /// Initialized ATProto OAuth client, if configured.
    pub oauth_client: Option<Arc<AtprotoOAuthClient>>,
    /// Client metadata document.
    pub metadata: OAuthClientMetadata,
    /// Reference to moderation engine for multi-tenant enrollment.
    pub engine: Option<Arc<SkybouncerEngine>>,
    /// Publicly configured base URL for HTTPS cookie flags.
    pub public_url: String,
}

impl OAuthState {
    fn is_https(&self) -> bool {
        self.public_url.starts_with("https://")
            || self.metadata.redirect_uri.starts_with("https://")
    }
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
        error!(error = %e, "Failed to generate OAuth client metadata response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate client metadata response".to_string(),
        )
    })
}

/// Handler for `GET /oauth/login`.
///
/// Initiates the PAR and PKCE authorization flow for the provided Bluesky handle,
/// binding the browser session to the issued OAuth `state` parameter via an `HttpOnly`
/// SHA-256 state cookie to defeat OAuth Login CSRF attacks.
pub async fn oauth_login(
    State(state): State<OAuthState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, (StatusCode, String)> {
    let raw_handle = query
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

    let handle = crate::util::normalize_handle_or_default(raw_handle);

    let client = state.oauth_client.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "ATProto OAuth client is not configured on this server".to_string(),
        )
    })?;

    info!(handle = %handle, "Initiating ATProto OAuth login flow");

    match client.authorize(&handle).await {
        Ok(auth_req) => {
            let mut response = redirect_to_authorization(&auth_req).map_err(|e| {
                error!(error = %e, "Failed to construct OAuth authorization redirect");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to construct authorization redirect".to_string(),
                )
            })?;
            let state_hash = sha256_hex(&auth_req.state);
            let secure_attr = if state.is_https() { "; Secure" } else { "" };
            let cookie = format!(
                "{OAUTH_STATE_COOKIE}={state_hash}; Path=/oauth/callback; Max-Age=300; HttpOnly; SameSite=Lax{secure_attr}"
            );
            if let Ok(cookie_val) = HeaderValue::from_str(&cookie) {
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, cookie_val);
            }
            Ok(response)
        }
        Err(e) => {
            error!(error = %e, handle = %handle, "OAuth authorization request failed");
            Err((
                StatusCode::BAD_GATEWAY,
                "Failed to initiate authorization with user's PDS".to_string(),
            ))
        }
    }
}

fn redirect_with_clear_cookie(target: &str, clear_state_cookie: &str) -> Response {
    let mut resp = Redirect::to(target).into_response();
    if let Ok(val) = HeaderValue::from_str(clear_state_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, val);
    }
    resp
}

/// Handler for `GET /oauth/callback`.
///
/// Verifies the browser-bound OAuth state cookie, processes the OAuth code exchange,
/// atomically enrolls the tenant session, revokes any prior web session, and redirects
/// back to the dashboard.
pub async fn oauth_callback(
    State(state): State<OAuthState>,
    headers: HeaderMap,
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

    let secure_attr = if state.is_https() { "; Secure" } else { "" };
    let clear_state_cookie = format!(
        "{OAUTH_STATE_COOKIE}=; Path=/oauth/callback; Max-Age=0; HttpOnly; SameSite=Lax{secure_attr}"
    );

    if query.error.is_none() {
        let state_cookie = extract_cookie_value(&headers, OAUTH_STATE_COOKIE);
        let valid_state = match (state_cookie, query.state.as_deref()) {
            (Some(cookie_hash), Some(query_state)) => {
                let expected = sha256_hex(query_state);
                cookie_hash.len() == expected.len()
                    && skyauth::crypto::constant_time_eq(
                        cookie_hash.as_bytes(),
                        expected.as_bytes(),
                    )
            }
            _ => false,
        };
        if !valid_state {
            warn!("Rejected OAuth callback due to missing or mismatched state cookie (Login CSRF protection)");
            return Ok(redirect_with_clear_cookie(
                "/?auth=error&reason=invalid_state",
                &clear_state_cookie,
            ));
        }
    }

    let params = match query.to_callback_params() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Invalid or error OAuth callback query");
            return Ok(redirect_with_clear_cookie(
                "/?auth=error&reason=invalid_callback",
                &clear_state_cookie,
            ));
        }
    };

    match client.handle_callback(&params).await {
        Ok(session) => {
            let did = session.sub.clone();
            info!(did = %did, "OAuth authorization completed successfully");

            let Some(ref engine) = state.engine else {
                return Ok(redirect_with_clear_cookie(
                    "/?auth=error&reason=no_engine",
                    &clear_state_cookie,
                ));
            };

            if let Err(e) = engine.enroll_oauth_tenant(&did, None, &session) {
                error!(error = %e, did = %did, "Failed to enroll tenant into registry; aborting session issuance");
                return Ok(redirect_with_clear_cookie(
                    "/?auth=error&reason=enrollment_failed",
                    &clear_state_cookie,
                ));
            }

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

            if let Some(old_token) = extract_cookie_value(&headers, "skybouncer_session") {
                let _ = engine.tenant_registry().delete_web_session(&old_token);
            }

            let session_token = match engine
                .tenant_registry()
                .create_web_session(&did, Duration::from_secs(30 * 86400))
            {
                Ok(t) => t,
                Err(e) => {
                    error!(error = %e, did = %did, "Failed to create web session in SQLite");
                    return Ok(redirect_with_clear_cookie(
                        "/?auth=error&reason=session_failed",
                        &clear_state_cookie,
                    ));
                }
            };

            let mut response = Redirect::to("/?auth=success").into_response();
            if let Ok(clear_val) = HeaderValue::from_str(&clear_state_cookie) {
                response.headers_mut().append(header::SET_COOKIE, clear_val);
            }

            let cookie_header = format!(
                "skybouncer_session={session_token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax{secure_attr}"
            );
            if let Ok(cookie_val) = HeaderValue::from_str(&cookie_header) {
                response
                    .headers_mut()
                    .append(header::SET_COOKIE, cookie_val);
            }

            Ok(response)
        }
        Err(e) => {
            error!(error = %e, "Failed to exchange OAuth authorization code for session");
            Ok(redirect_with_clear_cookie(
                "/?auth=error&reason=oauth_failed",
                &clear_state_cookie,
            ))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use axum::extract::{Query, State};
    use skyauth::client::OAuthClientMetadata;

    fn state_without_client() -> OAuthState {
        OAuthState {
            oauth_client: None,
            metadata: OAuthClientMetadata::new(
                "http://127.0.0.1:3000/oauth/client-metadata.json",
                "http://127.0.0.1:3000/oauth/callback",
            ),
            engine: None,
            public_url: "http://127.0.0.1:3000".to_string(),
        }
    }

    #[test]
    fn urlencoding_simple_escapes_reserved_chars() {
        assert_eq!(urlencoding_simple("abc-_.~123"), "abc-_.~123");
        assert_eq!(urlencoding_simple("a b"), "a%20b");
        assert_eq!(urlencoding_simple("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(urlencoding_simple("é"), "%C3%A9");
        assert_eq!(urlencoding_simple(""), "");
    }

    #[tokio::test]
    async fn get_client_metadata_serves_document() {
        let state = state_without_client();
        let resp = get_client_metadata(State(state)).await.expect("metadata");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oauth_login_requires_handle() {
        let state = state_without_client();
        let err = oauth_login(State(state.clone()), Query(LoginQuery { handle: None }))
            .await
            .expect_err("missing handle");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);

        let err = oauth_login(
            State(state.clone()),
            Query(LoginQuery {
                handle: Some("   ".to_string()),
            }),
        )
        .await
        .expect_err("blank handle");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oauth_login_without_client_is_unavailable() {
        let state = state_without_client();
        let err = oauth_login(
            State(state),
            Query(LoginQuery {
                handle: Some("alice.bsky.social".to_string()),
            }),
        )
        .await
        .expect_err("no oauth client");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn oauth_callback_requires_code_or_error() {
        let state = state_without_client();
        let query = OAuthCallbackQuery {
            code: None,
            state: None,
            iss: None,
            error: None,
            error_description: None,
        };
        let err = oauth_callback(State(state), HeaderMap::new(), query)
            .await
            .expect_err("missing code/error");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oauth_callback_without_client_is_unavailable() {
        let state = state_without_client();
        let query = OAuthCallbackQuery::new("code123", "state123");
        let err = oauth_callback(State(state), HeaderMap::new(), query)
            .await
            .expect_err("no oauth client");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn oauth_callback_error_query_redirects() {
        // No client, but an error query short-circuits BEFORE the client lookup only
        // when code and error are both absent; an error query still requires the
        // client to translate, so this exercises the missing-code/error guard.
        let state = state_without_client();
        let query = OAuthCallbackQuery::new_error("access_denied", None);
        // With a client absent, returns SERVICE_UNAVAILABLE.
        let err = oauth_callback(State(state), HeaderMap::new(), query)
            .await
            .expect_err("no client");
        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    fn location_of(r: Redirect) -> String {
        r.into_response()
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    #[tokio::test]
    async fn auth_redirect_encodes_handle_or_defaults() {
        let r = auth_redirect(Query(LoginQuery {
            handle: Some("alice.bsky.social".to_string()),
        }))
        .await;
        assert_eq!(location_of(r), "/oauth/login?handle=alice.bsky.social");

        let r = auth_redirect(Query(LoginQuery {
            handle: Some("a b".to_string()),
        }))
        .await;
        assert_eq!(location_of(r), "/oauth/login?handle=a%20b");

        let r = auth_redirect(Query(LoginQuery {
            handle: Some("  ".to_string()),
        }))
        .await;
        assert_eq!(location_of(r), "/?auth=login");

        let r = auth_redirect(Query(LoginQuery { handle: None })).await;
        assert_eq!(location_of(r), "/?auth=login");
    }
}
