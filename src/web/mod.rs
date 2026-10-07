//! Sovereign Web Dashboard and ATProto OAuth 2.0 PKCE server.
//!
//! Provides an embedded HTTP service powering:
//! - Interactive browser dashboard (`GET /`).
//! - ATProto OAuth 2.0 PKCE client endpoints (`/oauth/*`).
//! - REST API for telemetry, rules management, simulator, and pardons (`/api/*`).

pub mod api;
pub mod oauth;
pub mod ui;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, Method};
use axum::routing::{get, post};
use axum::Router;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

pub use api::{
    get_prometheus_metrics, health_check, resolve_identity, AddAllowlistRequest,
    AddAllowlistResponse, AdminEvaluationsQuery, AdminEvaluationsResponse, AdminTenantsResponse,
    AllowlistQuery, ApiState, BouncedUserWithHandle, BouncesQuery, EvaluationsQuery,
    EvaluationsResponse, HealthResponse, PardonRequest, PardonResponse, RemoveAllowlistResponse,
    ResolveQuery, ResolveResponse, RulesResponse, SimulateRequest, SimulateResponse,
    StatusResponse, TenantSummary, ToggleTenantRequest, ToggleTenantResponse, UpdateRulesRequest,
    UserSessionResponse,
};
pub use oauth::{LoginQuery, OAuthState};
pub use ui::{serve_dashboard, DASHBOARD_HTML};

use crate::engine::SkybouncerEngine;
use crate::error::SkybouncerError;
use skyauth::client::{AtprotoOAuthClient, OAuthClientMetadata};
use skyauth::store::OAuthStateStore;

/// Default host address for the web dashboard (127.0.0.1).
pub const DEFAULT_WEB_HOST: &str = "127.0.0.1";

/// Default TCP port for the web dashboard (3000).
pub const DEFAULT_WEB_PORT: u16 = 3000;

/// Configuration options for the embedded web dashboard server.
#[derive(Debug, Clone)]
pub struct WebServerConfig {
    /// Host IP address to bind to (e.g. `"127.0.0.1"` or `"0.0.0.0"`).
    pub host: String,
    /// TCP port to bind to (e.g. 3000).
    pub port: u16,
    /// Publicly accessible base URL (e.g. `<http://127.0.0.1:3000>` or `<https://skybouncer.example.com>`).
    pub public_url: String,
    /// Optional custom OAuth client ID (defaults to `{public_url}/oauth/client-metadata.json`).
    pub client_id: Option<String>,
    /// Optional custom OAuth redirect URI (defaults to `{public_url}/oauth/callback`).
    pub redirect_uri: Option<String>,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_WEB_HOST.to_string(),
            port: DEFAULT_WEB_PORT,
            public_url: format!("http://{DEFAULT_WEB_HOST}:{DEFAULT_WEB_PORT}"),
            client_id: None,
            redirect_uri: None,
        }
    }
}

impl WebServerConfig {
    /// Creates a new `WebServerConfig` with the specified host and port.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host = host.into();
        let public_url = format!("http://{host}:{port}");
        Self {
            host,
            port,
            public_url,
            client_id: None,
            redirect_uri: None,
        }
    }

    /// Sets the publicly accessible base URL.
    #[must_use]
    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// Sets custom OAuth client ID and redirect URI.
    #[must_use]
    pub fn with_oauth_endpoints(
        mut self,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        self.client_id = Some(client_id.into());
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    /// Returns the resolved OAuth client ID.
    #[must_use]
    pub fn client_id(&self) -> String {
        self.client_id
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/client-metadata.json", self.public_url))
    }

    /// Returns the resolved OAuth redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        self.redirect_uri
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/callback", self.public_url))
    }

    /// Loads web server configuration from environment variables with fallback defaults.
    #[must_use]
    pub fn from_env() -> Self {
        let host = crate::env::var_or(&["HOST", "SKYBOUNCER_HOST"], DEFAULT_WEB_HOST);

        let port = crate::env::parsed_or(&["PORT", "SKYBOUNCER_PORT"], DEFAULT_WEB_PORT);

        let public_url = crate::env::var_or(
            &["PUBLIC_URL", "SKYBOUNCER_PUBLIC_URL"],
            &format!("http://{host}:{port}"),
        );

        let client_id = crate::env::var(&["OAUTH_CLIENT_ID", "SKYBOUNCER_OAUTH_CLIENT_ID"]);

        let redirect_uri =
            crate::env::var(&["OAUTH_REDIRECT_URI", "SKYBOUNCER_OAUTH_REDIRECT_URI"]);

        Self {
            host,
            port,
            public_url,
            client_id,
            redirect_uri,
        }
    }
}

/// Constructs the full Axum router for the dashboard, REST API, and OAuth endpoints.
pub fn create_web_router(
    engine: Arc<SkybouncerEngine>,
    oauth_client: Option<Arc<AtprotoOAuthClient>>,
    metadata: OAuthClientMetadata,
) -> Router {
    let api_state = ApiState {
        engine: Arc::clone(&engine),
    };

    let oauth_state = OAuthState {
        oauth_client,
        metadata,
        engine: Some(Arc::clone(&engine)),
    };

    let api_router = Router::new()
        .route("/health", get(api::health_check))
        .route("/metrics", get(api::get_prometheus_metrics))
        .route("/status", get(api::get_status))
        .route("/rules", get(api::get_rules).post(api::update_rules))
        .route("/bounces", get(api::get_bounces))
        .route("/pardon", post(api::pardon_user))
        .route(
            "/allowlist",
            get(api::get_allowlist).post(api::add_to_allowlist),
        )
        .route(
            "/allowlist/:did",
            axum::routing::delete(api::remove_from_allowlist),
        )
        .route("/simulate", post(api::simulate_interaction))
        .route("/me", get(api::get_current_user))
        .route("/admin/tenants", get(api::get_admin_tenants))
        .route("/admin/evaluations", get(api::get_admin_evaluations))
        .route("/evaluations", get(api::get_evaluations))
        .route("/tenant/toggle", post(api::toggle_tenant))
        .route("/auth/logout", post(api::logout))
        .route("/resolve", get(api::resolve_identity))
        .with_state(api_state.clone());

    let oauth_router = Router::new()
        .route("/client-metadata.json", get(oauth::get_client_metadata))
        .route("/login", get(oauth::oauth_login))
        .route("/callback", get(oauth::oauth_callback))
        .with_state(oauth_state.clone());

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT]);

    Router::new()
        .route("/", get(ui::serve_dashboard))
        .route("/auth", get(oauth::auth_redirect))
        .route("/healthz", get(api::health_check))
        .route(
            "/metrics",
            get(api::get_prometheus_metrics).with_state(api_state),
        )
        .route(
            "/client-metadata.json",
            get(oauth::get_client_metadata).with_state(oauth_state),
        )
        .nest("/api", api_router)
        .nest("/oauth", oauth_router)
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(TraceLayer::new_for_http())
}

async fn security_headers_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
        ),
    );
    resp
}

/// Constructs the [`AtprotoOAuthClient`] and [`OAuthClientMetadata`] from server configuration.
#[must_use]
pub fn build_oauth_client(
    config: &WebServerConfig,
) -> (Option<Arc<AtprotoOAuthClient>>, OAuthClientMetadata) {
    let client_id = config.client_id();
    let redirect_uri = config.redirect_uri();

    let metadata = OAuthClientMetadata::new(client_id, redirect_uri)
        .with_client_name("Skybouncer Moderation")
        .with_scope("atproto transition:generic");

    // Initialize OAuth client with a 64-shard partitioned state store
    let state_store = Arc::new(OAuthStateStore::new(Duration::from_secs(300)));
    let oauth_client = match AtprotoOAuthClient::builder()
        .metadata(metadata.clone())
        .state_store(state_store)
        .state_ttl(Duration::from_secs(300))
        .build()
    {
        Ok(client) => Some(Arc::new(client)),
        Err(e) => {
            info!(
                error = %e,
                "ATProto OAuth client not activated; running in local dashboard mode"
            );
            None
        }
    };

    (oauth_client, metadata)
}

/// Runs the Axum HTTP web server until `cancel` is triggered.
///
/// # Errors
/// Returns [`SkybouncerError::Config`] or [`SkybouncerError::Http`] if binding or serving fails.
pub async fn run_web_server(
    config: WebServerConfig,
    engine: Arc<SkybouncerEngine>,
    cancel: CancellationToken,
) -> Result<(), SkybouncerError> {
    let (oauth_client, metadata) = if let Some(client) = engine.oauth_client() {
        let client_id = config.client_id();
        let redirect_uri = config.redirect_uri();
        let metadata = OAuthClientMetadata::new(client_id, redirect_uri)
            .with_client_name("Skybouncer Moderation")
            .with_scope("atproto transition:generic");
        (Some(client), metadata)
    } else {
        let (client, meta) = build_oauth_client(&config);
        if let Some(ref c) = client {
            engine.set_oauth_client(Arc::clone(c));
        }
        (client, meta)
    };

    let app = create_web_router(engine, oauth_client, metadata);

    let addr_str = format!("{}:{}", config.host, config.port);
    let addr: SocketAddr = addr_str.parse().map_err(|e| {
        SkybouncerError::Config(format!("Invalid listen address '{addr_str}': {e}"))
    })?;

    info!(
        address = %addr,
        public_url = %config.public_url,
        "🌐 Starting Skybouncer Web Dashboard server"
    );

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        SkybouncerError::Config(format!("Failed to bind TCP listener on {addr}: {e}"))
    })?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel.cancelled().await;
            info!("Web dashboard server received cancellation; shutting down");
        })
        .await
        .map_err(|e| SkybouncerError::Config(format!("Web server failure: {e}")))?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn web_server_config_default_new_and_accessors() {
        let d = WebServerConfig::default();
        assert_eq!(d.host, DEFAULT_WEB_HOST);
        assert_eq!(d.port, DEFAULT_WEB_PORT);
        assert!(d.client_id().ends_with("/oauth/client-metadata.json"));
        assert!(d.redirect_uri().ends_with("/oauth/callback"));

        let c = WebServerConfig::new("0.0.0.0", 8080)
            .with_public_url("https://example.com/")
            .with_oauth_endpoints("https://example.com/cid.json", "https://example.com/cb");
        assert_eq!(c.host, "0.0.0.0");
        assert_eq!(c.port, 8080);
        assert_eq!(c.public_url, "https://example.com");
        assert_eq!(c.client_id(), "https://example.com/cid.json");
        assert_eq!(c.redirect_uri(), "https://example.com/cb");
    }

    #[test]
    fn web_server_config_resolves_redirect_from_public_url() {
        let c = WebServerConfig::new("127.0.0.1", 3000).with_public_url("https://sky.example");
        assert_eq!(c.redirect_uri(), "https://sky.example/oauth/callback");
        // An explicit redirect override wins.
        let c2 = c.with_oauth_endpoints("id", "https://custom/cb");
        assert_eq!(c2.redirect_uri(), "https://custom/cb");
    }

    #[test]
    fn web_server_config_from_env_uses_defaults_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for k in [
            "HOST",
            "SKYBOUNCER_HOST",
            "PORT",
            "SKYBOUNCER_PORT",
            "PUBLIC_URL",
            "SKYBOUNCER_PUBLIC_URL",
        ] {
            std::env::remove_var(k);
        }
        let c = WebServerConfig::from_env();
        assert_eq!(c.host, DEFAULT_WEB_HOST);
        assert_eq!(c.port, DEFAULT_WEB_PORT);
    }

    #[test]
    fn build_oauth_client_returns_metadata_always() {
        let cfg = WebServerConfig::new("127.0.0.1", 3000);
        let (_client, metadata) = build_oauth_client(&cfg);
        assert!(metadata.client_id.contains("client-metadata.json"));
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
