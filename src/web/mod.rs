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

use axum::routing::{get, post};
use axum::Router;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

pub use api::{
    health_check, AdminEvaluationsQuery, AdminEvaluationsResponse, AdminTenantsResponse, ApiState,
    BouncesQuery, HealthResponse, PardonRequest, PardonResponse, RulesResponse, SimulateRequest,
    SimulateResponse, StatusResponse, TenantSummary, ToggleTenantRequest, ToggleTenantResponse,
    UpdateRulesRequest, UserSessionResponse,
};
pub use oauth::{LoginQuery, OAuthState};
pub use ui::serve_dashboard;

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
        let host = std::env::var("HOST")
            .or_else(|_| std::env::var("SKYBOUNCER_HOST"))
            .unwrap_or_else(|_| DEFAULT_WEB_HOST.to_string());

        let port = std::env::var("PORT")
            .or_else(|_| std::env::var("SKYBOUNCER_PORT"))
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(DEFAULT_WEB_PORT);

        let public_url = std::env::var("PUBLIC_URL")
            .or_else(|_| std::env::var("SKYBOUNCER_PUBLIC_URL"))
            .unwrap_or_else(|_| format!("http://{host}:{port}"));

        let client_id = std::env::var("OAUTH_CLIENT_ID")
            .or_else(|_| std::env::var("SKYBOUNCER_OAUTH_CLIENT_ID"))
            .ok();

        let redirect_uri = std::env::var("OAUTH_REDIRECT_URI")
            .or_else(|_| std::env::var("SKYBOUNCER_OAUTH_REDIRECT_URI"))
            .ok();

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
        .route("/status", get(api::get_status))
        .route("/rules", get(api::get_rules).post(api::update_rules))
        .route("/bounces", get(api::get_bounces))
        .route("/pardon", post(api::pardon_user))
        .route("/simulate", post(api::simulate_interaction))
        .route("/me", get(api::get_current_user))
        .route("/admin/tenants", get(api::get_admin_tenants))
        .route("/admin/evaluations", get(api::get_admin_evaluations))
        .route("/tenant/toggle", post(api::toggle_tenant))
        .route("/auth/logout", post(api::logout))
        .with_state(api_state);

    let oauth_router = Router::new()
        .route("/client-metadata.json", get(oauth::get_client_metadata))
        .route("/login", get(oauth::oauth_login))
        .route("/callback", get(oauth::oauth_callback))
        .with_state(oauth_state.clone());

    Router::new()
        .route("/", get(ui::serve_dashboard))
        .route("/auth", get(oauth::auth_redirect))
        .route("/healthz", get(api::health_check))
        .route(
            "/client-metadata.json",
            get(oauth::get_client_metadata).with_state(oauth_state),
        )
        .nest("/api", api_router)
        .nest("/oauth", oauth_router)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
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
