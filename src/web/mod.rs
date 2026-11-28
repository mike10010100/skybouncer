//! Sovereign Web Dashboard and ATProto OAuth 2.0 PKCE server.
//!
//! Provides an embedded HTTP service powering:
//! - Interactive browser dashboard (`GET /`).
//! - ATProto OAuth 2.0 PKCE client endpoints (`/oauth/*`).
//! - REST API for telemetry, rules management, simulator, and pardons (`/api/*`).

pub mod api;
pub mod oauth;
pub mod ui;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, Method};
use axum::routing::{get, post};
use axum::Router;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

pub use api::{
    auth_preview, auth_typeahead, get_prometheus_metrics, health_check, resolve_identity,
    simulate_guest_interaction, AddAllowlistRequest, AddAllowlistResponse, AdminEvaluationsQuery,
    AdminEvaluationsResponse, AdminTenantsResponse, AllowlistQuery, ApiState, AuthActorSuggestion,
    AuthPreviewQuery, AuthPreviewResponse, AuthTypeaheadQuery, AuthTypeaheadResponse,
    BouncedUserWithHandle, BouncesQuery, DetachQuotesRequest, DismissStormRequest,
    DismissStormResponse, EvaluationsQuery, EvaluationsResponse, GuestRateLimitDecision,
    GuestSandboxLimiter, GuestSimulateRequest, GuestSimulateResponse, HealthResponse,
    LockThreadRequest, PardonRequest, PardonResponse, RemoveAllowlistResponse, ResolveQuery,
    ResolveResponse, RulesResponse, ShieldActionResponse, SimulateRequest, SimulateResponse,
    StatusResponse, StormModeRequest, StormModeResponse, StormsQuery, StormsResponse,
    TenantSummary, ToggleTenantRequest, ToggleTenantResponse, UnlockThreadRequest,
    UpdateRulesRequest, UpgradeBounceRequest, UpgradeBounceResponse, UserSessionResponse,
    GUEST_SANDBOX_GLOBAL_LIMIT, GUEST_SANDBOX_MAX_TEXT_CHARS, GUEST_SANDBOX_PER_IP_LIMIT,
    GUEST_SANDBOX_WINDOW_SECS,
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

/// Default HTTP request timeout applied across the Axum router (130 seconds, matching Nginx).
const DEFAULT_WEB_REQUEST_TIMEOUT: Duration = Duration::from_secs(130);

/// Default Hyper HTTP/1 header-read timeout mitigating Slowloris connection exhaustion.
const DEFAULT_HTTP1_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Default maximum concurrent in-flight HTTP requests across the web router.
const DEFAULT_WEB_CONCURRENCY_LIMIT: usize = 128;

/// Default maximum request body size across routes without a dedicated override (64 KiB).
const DEFAULT_WEB_BODY_LIMIT_BYTES: usize = 64 * 1024;

/// Parses a `TRUSTED_PROXY_HEADER` configuration value, accepting only known client-IP
/// proxy headers (`cf-connecting-ip`, `x-real-ip`, or `x-forwarded-for`).
#[must_use]
pub fn parse_trusted_proxy_header(raw: &str) -> Option<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    match normalized.as_str() {
        "cf-connecting-ip" | "x-real-ip" | "x-forwarded-for" => Some(normalized),
        other => {
            warn!(
                header = %other,
                "Ignoring unsupported TRUSTED_PROXY_HEADER (expected cf-connecting-ip, x-real-ip, or x-forwarded-for)"
            );
            None
        }
    }
}

/// Parses a comma-separated `TRUSTED_PROXIES` list supporting both single IP addresses
/// (e.g. `127.0.0.1`, `::1`) and CIDR blocks (e.g. `172.21.0.0/16`).
#[must_use]
pub fn parse_trusted_proxies(raw: &str) -> Vec<ipnet::IpNet> {
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
            out.push(net);
        } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
            let canon = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
                v4 => v4,
            };
            out.push(ipnet::IpNet::from(canon));
        } else {
            warn!(entry = %trimmed, "Ignoring invalid IP/CIDR entry in TRUSTED_PROXIES");
        }
    }
    out
}

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
    /// Optional trusted reverse-proxy client-IP header (`cf-connecting-ip`, `x-real-ip`, or `x-forwarded-for`).
    pub trusted_proxy_header: Option<String>,
    /// Trusted proxy IP/CIDR allowlist required before honoring `trusted_proxy_header`.
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_WEB_HOST.to_string(),
            port: DEFAULT_WEB_PORT,
            public_url: format!("http://{DEFAULT_WEB_HOST}:{DEFAULT_WEB_PORT}"),
            client_id: None,
            redirect_uri: None,
            trusted_proxy_header: None,
            trusted_proxies: Vec::new(),
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
            trusted_proxy_header: None,
            trusted_proxies: Vec::new(),
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

    /// Configures the trusted reverse-proxy client-IP header (e.g. `"cf-connecting-ip"`).
    #[must_use]
    pub fn with_trusted_proxy_header(mut self, header: impl Into<String>) -> Self {
        self.trusted_proxy_header = parse_trusted_proxy_header(&header.into());
        self
    }

    /// Configures the trusted reverse-proxy IP/CIDR allowlist.
    #[must_use]
    pub fn with_trusted_proxies(mut self, proxies: Vec<ipnet::IpNet>) -> Self {
        self.trusted_proxies = proxies;
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

        let trusted_proxy_header =
            crate::env::var(&["TRUSTED_PROXY_HEADER", "SKYBOUNCER_TRUSTED_PROXY_HEADER"])
                .and_then(|v| parse_trusted_proxy_header(&v));

        let trusted_proxies = crate::env::var(&["TRUSTED_PROXIES", "SKYBOUNCER_TRUSTED_PROXIES"])
            .map(|v| parse_trusted_proxies(&v))
            .unwrap_or_default();

        Self {
            host,
            port,
            public_url,
            client_id,
            redirect_uri,
            trusted_proxy_header,
            trusted_proxies,
        }
    }
}

fn derive_public_url_from_metadata(metadata: &OAuthClientMetadata) -> String {
    for candidate in [&metadata.redirect_uri, &metadata.client_id] {
        if let Ok(parsed) = url::Url::parse(candidate) {
            if let Some(host) = parsed.host_str() {
                let scheme = parsed.scheme();
                return match parsed.port() {
                    Some(port) => format!("{scheme}://{host}:{port}"),
                    None => format!("{scheme}://{host}"),
                };
            }
        }
    }
    format!("http://{DEFAULT_WEB_HOST}:{DEFAULT_WEB_PORT}")
}

/// Constructs the full Axum router for the dashboard, REST API, and OAuth endpoints.
pub fn create_web_router(
    engine: Arc<SkybouncerEngine>,
    oauth_client: Option<Arc<AtprotoOAuthClient>>,
    metadata: OAuthClientMetadata,
) -> Router {
    let public_url = derive_public_url_from_metadata(&metadata);
    create_web_router_with_public_url(engine, oauth_client, metadata, public_url)
}

/// Constructs the full Axum router with an explicit `public_url` for HTTPS cookie flags,
/// HSTS, and same-site CSRF origin matching.
pub fn create_web_router_with_public_url(
    engine: Arc<SkybouncerEngine>,
    oauth_client: Option<Arc<AtprotoOAuthClient>>,
    metadata: OAuthClientMetadata,
    public_url: impl Into<String>,
) -> Router {
    let config = WebServerConfig::default().with_public_url(public_url);
    create_web_router_with_config(engine, oauth_client, metadata, &config)
}

/// Constructs the full Axum router from an explicit [`WebServerConfig`] (including
/// `public_url`, `trusted_proxy_header`, and `trusted_proxies`).
pub fn create_web_router_with_config(
    engine: Arc<SkybouncerEngine>,
    oauth_client: Option<Arc<AtprotoOAuthClient>>,
    metadata: OAuthClientMetadata,
    config: &WebServerConfig,
) -> Router {
    let public_url = config.public_url.trim_end_matches('/').to_string();
    if let Some(ref c) = oauth_client {
        if engine.oauth_client().is_none() {
            engine.set_oauth_client(Arc::clone(c));
        }
    }

    let api_state = ApiState::new(Arc::clone(&engine))
        .with_public_url(public_url.clone())
        .with_trusted_proxy(
            config.trusted_proxy_header.clone(),
            config.trusted_proxies.clone(),
        );

    let oauth_state = OAuthState {
        oauth_client,
        metadata,
        engine: Some(Arc::clone(&engine)),
        public_url,
        oauth_login_limiter: Arc::new(GuestSandboxLimiter::new(15, 150, Duration::from_secs(60))),
        trusted_proxy_header: config.trusted_proxy_header.clone(),
        trusted_proxies: config.trusted_proxies.clone(),
    };

    let api_router = Router::new()
        .route("/health", get(api::health_check))
        .route("/metrics", get(api::get_prometheus_metrics))
        .route("/status", get(api::get_status))
        .route("/rules", get(api::get_rules).post(api::update_rules))
        .route("/bounces", get(api::get_bounces))
        .route("/bounces/upgrade", post(api::upgrade_bounce))
        .route("/pardon", post(api::pardon_user))
        .route("/storms", get(api::get_storms))
        .route("/storms/mode", post(api::toggle_storm_mode))
        .route("/storms/dismiss", post(api::dismiss_storm))
        .route("/storms/lock", post(api::lock_thread_handler))
        .route("/storms/unlock", post(api::unlock_thread_handler))
        .route("/storms/detach", post(api::detach_quotes_handler))
        .route(
            "/allowlist",
            get(api::get_allowlist).post(api::add_to_allowlist),
        )
        .route(
            "/allowlist/{did}",
            axum::routing::delete(api::remove_from_allowlist),
        )
        .route(
            "/simulate",
            post(api::simulate_interaction)
                .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024)),
        )
        .route(
            "/simulate/guest",
            post(api::simulate_guest_interaction)
                .layer(axum::extract::DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/me", get(api::get_current_user))
        .route("/admin/tenants", get(api::get_admin_tenants))
        .route("/admin/evaluations", get(api::get_admin_evaluations))
        .route("/evaluations", get(api::get_evaluations))
        .route("/tenant/toggle", post(api::toggle_tenant))
        .route("/auth/logout", post(api::logout))
        .route("/auth/typeahead", get(api::auth_typeahead))
        .route("/auth/preview", get(api::auth_preview))
        .route("/resolve", get(api::resolve_identity))
        .layer(axum::middleware::from_fn_with_state(
            api_state.clone(),
            same_site_csrf_middleware,
        ))
        .with_state(api_state.clone());

    let oauth_router = Router::new()
        .route("/client-metadata.json", get(oauth::get_client_metadata))
        .route("/login", get(oauth::oauth_login))
        .route("/callback", get(oauth::oauth_callback))
        .with_state(oauth_state.clone());

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT]);

    let is_https = api_state.is_https();

    Router::new()
        .route("/", get(ui::serve_dashboard))
        .route("/auth", get(oauth::auth_redirect))
        .route(
            "/healthz",
            get(api::health_check).with_state(api_state.clone()),
        )
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
        .layer(axum::extract::DefaultBodyLimit::max(
            DEFAULT_WEB_BODY_LIMIT_BYTES,
        ))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            DEFAULT_WEB_REQUEST_TIMEOUT,
        ))
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            DEFAULT_WEB_CONCURRENCY_LIMIT,
        ))
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(
            is_https,
            security_headers_middleware,
        ))
        .layer(TraceLayer::new_for_http())
}

async fn same_site_csrf_middleware(
    axum::extract::State(state): axum::extract::State<ApiState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let method = req.method();
    if *method == Method::GET || *method == Method::HEAD {
        return next.run(req).await;
    }

    let headers = req.headers();
    let has_bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim().starts_with("Bearer "));

    let has_session_cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|raw| {
            raw.split(';')
                .any(|part| part.trim().starts_with("skybouncer_session="))
        });

    if !has_bearer && has_session_cookie {
        let same_origin_fetch_site = headers
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("same-origin"));

        let same_origin_header = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .and_then(api::parse_url_origin)
            .zip(state.public_origin())
            .is_some_and(|(req_origin, expected)| req_origin == expected);

        if !same_origin_fetch_site && !same_origin_header {
            return (
                StatusCode::FORBIDDEN,
                "CSRF validation failed: cross-origin cookie request rejected",
            )
                .into_response();
        }
    }

    next.run(req).await
}

async fn security_headers_middleware(
    axum::extract::State(is_https): axum::extract::State<bool>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_api_path = req.uri().path().starts_with("/api/");
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
    if is_api_path {
        headers.insert(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
    }
    if is_https {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    resp
}

/// Constructs the [`AtprotoOAuthClient`] and [`OAuthClientMetadata`] from server configuration,
/// optionally attaching a confidential client ES256 signing key (`private_key_jwt`).
#[must_use]
pub fn build_oauth_client_with_key(
    config: &WebServerConfig,
    client_key: Option<skyauth::dpop::DPoPKey>,
) -> (Option<Arc<AtprotoOAuthClient>>, OAuthClientMetadata) {
    let client_id = config.client_id();
    let redirect_uri = config.redirect_uri();

    let mut metadata = OAuthClientMetadata::new(client_id, redirect_uri)
        .with_client_name("Skybouncer Moderation")
        .with_scope("atproto transition:generic");
    if let Some(key) = client_key {
        metadata = metadata.with_client_key(key);
    }

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

/// Constructs the [`AtprotoOAuthClient`] and [`OAuthClientMetadata`] from server configuration.
#[must_use]
pub fn build_oauth_client(
    config: &WebServerConfig,
) -> (Option<Arc<AtprotoOAuthClient>>, OAuthClientMetadata) {
    let env_key = crate::env::var(&[
        "OAUTH_CLIENT_PRIVATE_KEY",
        "SKYBOUNCER_OAUTH_CLIENT_PRIVATE_KEY",
    ])
    .and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.starts_with("-----BEGIN") {
            skyauth::dpop::DPoPKey::from_pkcs8_pem(trimmed).ok()
        } else {
            skyauth::dpop::DPoPKey::from_bytes_b64(trimmed).ok()
        }
    });
    build_oauth_client_with_key(config, env_key)
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
        let metadata = client.metadata().clone();
        (Some(client), metadata)
    } else {
        let client_key = engine
            .tenant_registry()
            .load_or_create_oauth_client_key()
            .ok();
        let (client, meta) = build_oauth_client_with_key(&config, client_key);
        if let Some(ref c) = client {
            engine.set_oauth_client(Arc::clone(c));
        }
        (client, meta)
    };

    let app = create_web_router_with_config(engine, oauth_client, metadata, &config);

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

    let mut http1 = hyper::server::conn::http1::Builder::new();
    http1
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(DEFAULT_HTTP1_HEADER_READ_TIMEOUT);
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("Web dashboard server received cancellation; shutting down");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "Failed to accept incoming HTTP connection");
                        continue;
                    }
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                let router = app.clone();
                let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let router_inner = router.clone();
                    async move {
                        use tower::ServiceExt;
                        let (mut parts, body) = req.into_parts();
                        parts.extensions.insert(axum::extract::ConnectInfo(peer_addr));
                        let axum_req = axum::http::Request::from_parts(parts, axum::body::Body::new(body));
                        let resp = match router_inner.oneshot(axum_req).await {
                            Ok(r) => r,
                            Err(infallible) => match infallible {},
                        };
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let conn = http1.serve_connection(io, service);
                let fut = graceful.watch(conn);
                tokio::spawn(async move {
                    if let Err(e) = fut.await {
                        tracing::debug!(error = %e, peer = %peer_addr, "HTTP connection closed with error");
                    }
                });
            }
        }
    }

    tokio::select! {
        _ = graceful.shutdown() => {}
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            warn!("Timed out waiting for active HTTP connections to close during shutdown");
        }
    }

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

        let key = skyauth::dpop::DPoPKey::generate();
        let expected_kid = key.jwk_thumbprint();
        let cfg_https =
            WebServerConfig::new("127.0.0.1", 3000).with_public_url("https://sky.example");
        let (client_conf, metadata_conf) = build_oauth_client_with_key(&cfg_https, Some(key));
        assert!(client_conf.is_some());
        assert!(metadata_conf.is_confidential());
        let json_val = metadata_conf.to_json_value();
        assert_eq!(json_val["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(json_val["token_endpoint_auth_signing_alg"], "ES256");
        assert_eq!(json_val["jwks"]["keys"][0]["kid"], expected_kid);
    }

    #[test]
    fn parse_trusted_proxy_header_and_proxies_validate_inputs() {
        assert_eq!(
            parse_trusted_proxy_header("  CF-Connecting-IP "),
            Some("cf-connecting-ip".to_string())
        );
        assert_eq!(
            parse_trusted_proxy_header("X-Real-IP"),
            Some("x-real-ip".to_string())
        );
        assert_eq!(
            parse_trusted_proxy_header("x-forwarded-for"),
            Some("x-forwarded-for".to_string())
        );
        assert_eq!(parse_trusted_proxy_header(""), None);
        assert_eq!(parse_trusted_proxy_header("x-evil-custom-header"), None);

        let parsed =
            parse_trusted_proxies("127.0.0.1, ::1/128, 172.21.0.0/16, ::ffff:10.0.0.1, not-an-ip");
        assert_eq!(parsed.len(), 4);
        assert!(parsed[0].contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(parsed[2].contains(&"172.21.5.4".parse::<IpAddr>().unwrap()));
        assert!(parsed[3].contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn web_server_config_from_env_reads_trusted_proxy_settings() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved_hdr = std::env::var_os("TRUSTED_PROXY_HEADER");
        let saved_proxies = std::env::var_os("TRUSTED_PROXIES");
        std::env::set_var("TRUSTED_PROXY_HEADER", "cf-connecting-ip");
        std::env::set_var("TRUSTED_PROXIES", "172.21.0.0/16,127.0.0.1");

        let cfg = WebServerConfig::from_env();
        assert_eq!(
            cfg.trusted_proxy_header.as_deref(),
            Some("cf-connecting-ip")
        );
        assert_eq!(cfg.trusted_proxies.len(), 2);

        match saved_hdr {
            Some(v) => std::env::set_var("TRUSTED_PROXY_HEADER", v),
            None => std::env::remove_var("TRUSTED_PROXY_HEADER"),
        }
        match saved_proxies {
            Some(v) => std::env::set_var("TRUSTED_PROXIES", v),
            None => std::env::remove_var("TRUSTED_PROXIES"),
        }
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
