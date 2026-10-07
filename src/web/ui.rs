//! Embedded HTML, CSS, and client-side JavaScript for the Skybouncer Web Dashboard.
//!
//! Serves a self-contained, zero-dependency single-page application (SPA) featuring:
//! - Real-time operational telemetry and KPI metrics.
//! - Interactive dry-run rule evaluation simulator and playground.
//! - Audit timeline of recent bounced violators with one-click pardon buttons.
//! - Dynamic moderation rubric and sensitivity threshold controls.
//! - ATProto OAuth 2.0 PKCE sign-in modal.

use axum::response::Html;

/// HTML payload for the single-page application dashboard, loaded from `assets/dashboard.html`.
pub const DASHBOARD_HTML: &str = include_str!("../../assets/dashboard.html");

/// Handler for `GET /`: serves the Single-Page Application dashboard HTML.
pub async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}
