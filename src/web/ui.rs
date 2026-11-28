//! Embedded HTML, CSS, and client-side JavaScript for the Skybouncer Web Dashboard.
//!
//! Serves a self-contained, zero-dependency single-page application (SPA) featuring:
//! - Real-time operational telemetry and KPI metrics.
//! - Interactive dry-run rule evaluation simulator and playground.
//! - Audit timeline of recent bounced violators with one-click pardon buttons.
//! - Dynamic moderation rubric and sensitivity threshold controls.
//! - ATProto OAuth 2.0 PKCE sign-in modal.

use std::fmt::Write as _;
use std::sync::LazyLock;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// HTML payload for the single-page application dashboard, loaded from `assets/dashboard.html`.
pub const DASHBOARD_HTML: &str = include_str!("../../assets/dashboard.html");

/// Stylesheet payload for the single-page application dashboard, loaded from `assets/dashboard.css`.
pub const DASHBOARD_CSS: &str = include_str!("../../assets/dashboard.css");

/// Early head-blocking theme bootstrap script, loaded from `assets/theme-init.js`.
pub const THEME_INIT_JS: &str = include_str!("../../assets/theme-init.js");

/// Main deferred client-side SPA script, loaded from `assets/dashboard.js`.
pub const DASHBOARD_JS: &str = include_str!("../../assets/dashboard.js");

static DASHBOARD_HTML_ETAG: LazyLock<String> = LazyLock::new(|| compute_etag(DASHBOARD_HTML));
static DASHBOARD_CSS_ETAG: LazyLock<String> = LazyLock::new(|| compute_etag(DASHBOARD_CSS));
static THEME_INIT_JS_ETAG: LazyLock<String> = LazyLock::new(|| compute_etag(THEME_INIT_JS));
static DASHBOARD_JS_ETAG: LazyLock<String> = LazyLock::new(|| compute_etag(DASHBOARD_JS));

fn compute_etag(body: &str) -> String {
    let digest = skyauth::crypto::sha256_digest(body.as_bytes());
    let mut out = String::with_capacity(34);
    out.push('"');
    for b in &digest[..16] {
        let _ = write!(&mut out, "{b:02x}");
    }
    out.push('"');
    out
}

fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(raw) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    raw.split(',').any(|candidate| {
        let trimmed = candidate.trim();
        if trimmed == "*" {
            return true;
        }
        let normalized = trimmed.strip_prefix("W/").unwrap_or(trimmed).trim();
        normalized == etag
    })
}

fn serve_static_asset(
    headers: &HeaderMap,
    body: &'static str,
    content_type: &'static str,
    cache_control: &'static str,
    etag: &str,
) -> Response {
    let etag_val =
        HeaderValue::from_str(etag).unwrap_or_else(|_| HeaderValue::from_static("\"skybouncer\""));
    let cache_val = HeaderValue::from_static(cache_control);

    if if_none_match_matches(headers, etag) {
        let mut resp = StatusCode::NOT_MODIFIED.into_response();
        resp.headers_mut().insert(header::ETAG, etag_val);
        resp.headers_mut().insert(header::CACHE_CONTROL, cache_val);
        return resp;
    }

    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp.headers_mut().insert(header::ETAG, etag_val);
    resp.headers_mut().insert(header::CACHE_CONTROL, cache_val);
    resp
}

/// Handler for `GET /`: serves the Single-Page Application dashboard HTML with `ETag` support.
pub async fn serve_dashboard(headers: HeaderMap) -> Response {
    serve_static_asset(
        &headers,
        DASHBOARD_HTML,
        "text/html; charset=utf-8",
        "no-cache",
        &DASHBOARD_HTML_ETAG,
    )
}

/// Handler for `GET /assets/dashboard.css`: serves the dashboard stylesheet with `ETag` caching.
pub async fn serve_dashboard_css(headers: HeaderMap) -> Response {
    serve_static_asset(
        &headers,
        DASHBOARD_CSS,
        "text/css; charset=utf-8",
        "public, max-age=300, must-revalidate",
        &DASHBOARD_CSS_ETAG,
    )
}

/// Handler for `GET /assets/theme-init.js`: serves the synchronous theme bootstrap script.
pub async fn serve_theme_init_js(headers: HeaderMap) -> Response {
    serve_static_asset(
        &headers,
        THEME_INIT_JS,
        "application/javascript; charset=utf-8",
        "public, max-age=300, must-revalidate",
        &THEME_INIT_JS_ETAG,
    )
}

/// Handler for `GET /assets/dashboard.js`: serves the deferred SPA application script.
pub async fn serve_dashboard_js(headers: HeaderMap) -> Response {
    serve_static_asset(
        &headers,
        DASHBOARD_JS,
        "application/javascript; charset=utf-8",
        "public, max-age=300, must-revalidate",
        &DASHBOARD_JS_ETAG,
    )
}
