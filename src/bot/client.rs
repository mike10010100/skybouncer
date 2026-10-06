//! Asynchronous HTTP client for ATProto Chat (`chat.bsky.convo.*`).

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::bot::types::{
    AcceptConvoRequest, AcceptConvoResponse, ConvoView, GetMessagesResponse,
    ListConvoRequestsResponse, ListConvosResponse, MessageView, SendMessagePayload,
    SendMessageRequest, UpdateReadRequest,
};
use crate::error::SkybouncerError;

/// Default public Bluesky chat service endpoint.
pub const DEFAULT_CHAT_ENDPOINT: &str = "https://api.bsky.chat";

/// Service DID for Bluesky chat backend proxying through PDS.
pub const ATPROTO_CHAT_PROXY_DID: &str = "did:web:api.bsky.chat#bsky_chat";

#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    did: String,
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt", default)]
    refresh_jwt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RefreshSessionResponse {
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt", default)]
    refresh_jwt: Option<String>,
}

#[derive(Debug, Clone)]
struct BotCredentials {
    pds_endpoint: String,
    identifier: String,
    password: String,
}

#[derive(Debug, Clone)]
struct AuthState {
    access_jwt: String,
    refresh_jwt: Option<String>,
    credentials: Option<BotCredentials>,
}

/// Asynchronous HTTP client for interacting with the ATProto Chat service.
#[derive(Clone)]
pub struct ChatClient {
    base_url: String,
    client: reqwest::Client,
    auth_state: Arc<RwLock<AuthState>>,
}

impl ChatClient {
    /// Creates a new [`ChatClient`] targeting the specified base URL and bearer token.
    ///
    /// If `base_url` is a PDS rather than `api.bsky.chat`, the required `atproto-proxy`
    /// header is automatically attached to route chat XRPC requests through the gateway.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if HTTP client configuration or headers fail.
    pub fn new(
        base_url: impl Into<String>,
        access_token: impl Into<String>,
    ) -> Result<Self, SkybouncerError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let token = access_token.into();

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if !base_url.contains("api.bsky.chat") {
            headers.insert(
                HeaderName::from_static("atproto-proxy"),
                HeaderValue::from_static(ATPROTO_CHAT_PROXY_DID),
            );
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()?;

        let auth_state = Arc::new(RwLock::new(AuthState {
            access_jwt: token,
            refresh_jwt: None,
            credentials: None,
        }));

        Ok(Self {
            base_url,
            client,
            auth_state,
        })
    }

    /// Attaches a refresh JWT token for automatic session refresh upon token expiry.
    #[must_use]
    pub fn with_refresh_token(self, refresh_jwt: impl Into<String>) -> Self {
        let token = refresh_jwt.into();
        if !token.trim().is_empty() {
            if let Ok(mut state) = self.auth_state.try_write() {
                state.refresh_jwt = Some(token);
            }
        }
        self
    }

    /// Attaches bot credentials for automatic re-authentication if session tokens expire.
    #[must_use]
    pub fn with_credentials(
        self,
        pds_endpoint: impl Into<String>,
        identifier: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        if let Ok(mut state) = self.auth_state.try_write() {
            state.credentials = Some(BotCredentials {
                pds_endpoint: pds_endpoint.into().trim_end_matches('/').to_string(),
                identifier: identifier.into(),
                password: password.into(),
            });
        }
        self
    }

    /// Returns the currently active bearer access JWT.
    pub async fn current_access_token(&self) -> String {
        self.auth_state.read().await.access_jwt.clone()
    }

    /// Authenticates with an ATProto account identifier and App Password via `com.atproto.server.createSession`.
    ///
    /// Returns a configured [`ChatClient`] proxied through the PDS and the resolved account DID.
    /// The client retains credentials and refresh token to automatically recover from session expiry.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if authentication or session parsing fails.
    pub async fn login_with_app_password(
        pds_endpoint: &str,
        chat_endpoint: &str,
        identifier: &str,
        password: &str,
    ) -> Result<(Self, String), SkybouncerError> {
        let pds_url = pds_endpoint.trim_end_matches('/');
        let login_url = format!("{pds_url}/xrpc/com.atproto.server.createSession");

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;

        let body = serde_json::json!({
            "identifier": identifier,
            "password": password,
        });

        let resp = http.post(&login_url).json(&body).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            return Err(SkybouncerError::Chat(format!(
                "Failed to authenticate bot account ({identifier}) at {pds_url} (HTTP {status}): {err_body}"
            )));
        }

        let session: CreateSessionResponse = resp.json().await.map_err(|e| {
            SkybouncerError::Chat(format!("Failed to parse createSession response: {e}"))
        })?;

        let mut chat_client = Self::new(chat_endpoint, &session.access_jwt)?;
        if let Some(ref refresh) = session.refresh_jwt {
            chat_client = chat_client.with_refresh_token(refresh);
        }
        chat_client = chat_client.with_credentials(pds_url, identifier, password);

        Ok((chat_client, session.did))
    }

    /// Checks if token refresh or re-authentication is possible.
    async fn can_refresh(&self) -> bool {
        let state = self.auth_state.read().await;
        state.refresh_jwt.is_some() || state.credentials.is_some()
    }

    /// Attempts to refresh the session using `refreshJwt` or re-login with stored credentials.
    ///
    /// If the token was already refreshed by another concurrent request, this is a no-op.
    async fn refresh_session_or_relogin(&self, failed_token: &str) -> Result<(), SkybouncerError> {
        let mut state = self.auth_state.write().await;
        // If another task already refreshed the token, do nothing
        if state.access_jwt != failed_token {
            debug!("ATProto chat session token was already refreshed by another task");
            return Ok(());
        }

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;

        // Strategy 1: Attempt refreshSession via refreshJwt if available
        if let (Some(ref refresh_jwt), Some(ref creds)) = (&state.refresh_jwt, &state.credentials) {
            let refresh_url = format!(
                "{}/xrpc/com.atproto.server.refreshSession",
                creds.pds_endpoint.trim_end_matches('/')
            );
            match http
                .post(&refresh_url)
                .header(AUTHORIZATION, format!("Bearer {refresh_jwt}"))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<RefreshSessionResponse>().await {
                        Ok(refreshed) => {
                            info!("Successfully refreshed ATProto chat session token via refreshSession");
                            state.access_jwt = refreshed.access_jwt;
                            if let Some(new_refresh) = refreshed.refresh_jwt {
                                if !new_refresh.trim().is_empty() {
                                    state.refresh_jwt = Some(new_refresh);
                                }
                            }
                            return Ok(());
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "Failed to parse refreshSession response; falling back to full re-login"
                            );
                        }
                    }
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    warn!(
                        status = %status,
                        body = %body,
                        "refreshSession failed; falling back to full re-login"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Network error during refreshSession; falling back to full re-login"
                    );
                }
            }
        }

        // Strategy 2: Full re-login using stored App Password credentials
        if let Some(ref creds) = state.credentials {
            info!(
                identifier = %creds.identifier,
                "Re-authenticating ATProto chat session via App Password..."
            );
            let login_url = format!(
                "{}/xrpc/com.atproto.server.createSession",
                creds.pds_endpoint.trim_end_matches('/')
            );
            let body = serde_json::json!({
                "identifier": creds.identifier,
                "password": creds.password,
            });

            let resp = http.post(&login_url).json(&body).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let err_body = resp.text().await.unwrap_or_default();
                return Err(SkybouncerError::Chat(format!(
                    "Failed to re-authenticate bot session at {login_url} (HTTP {status}): {err_body}"
                )));
            }

            let session: CreateSessionResponse = resp.json().await.map_err(|e| {
                SkybouncerError::Chat(format!("Failed to parse createSession response: {e}"))
            })?;

            info!("Successfully re-authenticated ATProto chat session via App Password");
            state.access_jwt = session.access_jwt;
            if let Some(new_refresh) = session.refresh_jwt {
                if !new_refresh.trim().is_empty() {
                    state.refresh_jwt = Some(new_refresh);
                }
            }
            return Ok(());
        }

        Err(SkybouncerError::Chat(
            "Session token expired, but no refresh token or credentials configured to refresh"
                .to_string(),
        ))
    }

    /// Internal request helper with automatic single-flight token refresh retry.
    async fn send_request(
        &self,
        op_name: &str,
        method: reqwest::Method,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, SkybouncerError> {
        let current_token = self.auth_state.read().await.access_jwt.clone();
        let req = self.build_request(method.clone(), url, &current_token, body.as_ref());

        let resp = req.send().await?;
        let status = resp.status();

        if status.is_success() {
            return Ok(resp);
        }

        let body_text = resp.text().await.unwrap_or_default();
        let is_token_expired = status == reqwest::StatusCode::UNAUTHORIZED
            || (status == reqwest::StatusCode::BAD_REQUEST && body_text.contains("ExpiredToken"));

        if is_token_expired && self.can_refresh().await {
            warn!(
                op = op_name,
                status = %status,
                "ATProto chat session token expired; refreshing and retrying..."
            );
            if let Err(e) = self.refresh_session_or_relogin(&current_token).await {
                error!(error = %e, "Failed to refresh ATProto chat session");
                return Err(SkybouncerError::Chat(format!(
                    "{op_name} failed with status {status}: {body_text} (refresh failed: {e})"
                )));
            }

            let new_token = self.auth_state.read().await.access_jwt.clone();
            let retry_req = self.build_request(method, url, &new_token, body.as_ref());

            let retry_resp = retry_req.send().await?;
            if !retry_resp.status().is_success() {
                let retry_status = retry_resp.status();
                let retry_body = retry_resp.text().await.unwrap_or_default();
                return Err(SkybouncerError::Chat(format!(
                    "{op_name} failed with status {retry_status}: {retry_body}"
                )));
            }

            return Ok(retry_resp);
        }

        Err(SkybouncerError::Chat(format!(
            "{op_name} failed with status {status}: {body_text}"
        )))
    }

    /// Builds a bearer-authenticated XRPC request, optionally attaching a JSON body.
    fn build_request(
        &self,
        method: reqwest::Method,
        url: &str,
        token: &str,
        body: Option<&serde_json::Value>,
    ) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .request(method, url)
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if let Some(b) = body {
            req = req.json(b);
        }
        req
    }

    /// Lists active conversations for the authenticated user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request or JSON deserialization fails.
    pub async fn list_convos(
        &self,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<ListConvosResponse, SkybouncerError> {
        let mut url = format!("{}/xrpc/chat.bsky.convo.listConvos", self.base_url);
        let mut query_params = Vec::new();

        if let Some(limit) = limit {
            query_params.push(format!("limit={limit}"));
        }
        if let Some(cursor) = cursor {
            query_params.push(format!("cursor={cursor}"));
        }
        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }

        let resp = self
            .send_request("listConvos", reqwest::Method::GET, &url, None)
            .await?;
        let result = resp.json::<ListConvosResponse>().await?;
        debug!(count = result.convos.len(), "Fetched chat conversations");
        Ok(result)
    }

    /// Lists incoming conversation requests for the authenticated user via `chat.bsky.convo.listConvoRequests`.
    ///
    /// Non-followed accounts initiating conversations land in the requests state until accepted.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request or JSON deserialization fails.
    pub async fn list_convo_requests(
        &self,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<ListConvoRequestsResponse, SkybouncerError> {
        let mut url = format!("{}/xrpc/chat.bsky.convo.listConvoRequests", self.base_url);
        let mut query_params = Vec::new();

        if let Some(limit) = limit {
            query_params.push(format!("limit={limit}"));
        }
        if let Some(cursor) = cursor {
            query_params.push(format!("cursor={cursor}"));
        }
        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }

        let resp = self
            .send_request("listConvoRequests", reqwest::Method::GET, &url, None)
            .await?;
        let result = resp.json::<ListConvoRequestsResponse>().await?;
        debug!(
            count = result.requests.len(),
            "Fetched chat conversation requests"
        );
        Ok(result)
    }

    /// Accepts an incoming conversation request via `chat.bsky.convo.acceptConvo`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request or JSON deserialization fails.
    pub async fn accept_convo(
        &self,
        convo_id: &str,
    ) -> Result<AcceptConvoResponse, SkybouncerError> {
        let url = format!("{}/xrpc/chat.bsky.convo.acceptConvo", self.base_url);
        let req = AcceptConvoRequest {
            convo_id: convo_id.to_string(),
        };
        let body = serde_json::to_value(&req)?;

        let resp = self
            .send_request("acceptConvo", reqwest::Method::POST, &url, Some(body))
            .await?;
        let result = resp.json::<AcceptConvoResponse>().await?;
        debug!(
            convo_id = %convo_id,
            rev = ?result.rev,
            "Accepted chat conversation request"
        );
        Ok(result)
    }

    /// Fetches messages for a specific conversation.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request or JSON deserialization fails.
    pub async fn get_messages(
        &self,
        convo_id: &str,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<GetMessagesResponse, SkybouncerError> {
        let mut url = format!(
            "{}/xrpc/chat.bsky.convo.getMessages?convoId={convo_id}",
            self.base_url
        );
        if let Some(limit) = limit {
            url.push_str(&format!("&limit={limit}"));
        }
        if let Some(cursor) = cursor {
            url.push_str(&format!("&cursor={cursor}"));
        }

        let resp = self
            .send_request("getMessages", reqwest::Method::GET, &url, None)
            .await?;
        let result = resp.json::<GetMessagesResponse>().await?;
        Ok(result)
    }

    /// Sends a text message to the specified conversation, automatically extracting and attaching link facets.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request or JSON deserialization fails.
    pub async fn send_message(
        &self,
        convo_id: &str,
        text: &str,
    ) -> Result<MessageView, SkybouncerError> {
        let payload = SendMessagePayload::new(text);
        self.send_message_payload(convo_id, payload).await
    }

    /// Sends a structured message payload via `chat.bsky.convo.sendMessage`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request or JSON deserialization fails.
    pub async fn send_message_payload(
        &self,
        convo_id: &str,
        payload: SendMessagePayload,
    ) -> Result<MessageView, SkybouncerError> {
        let url = format!("{}/xrpc/chat.bsky.convo.sendMessage", self.base_url);
        let req = SendMessageRequest {
            convo_id: convo_id.to_string(),
            message: payload,
        };
        let body = serde_json::to_value(&req)?;

        let resp = self
            .send_request("sendMessage", reqwest::Method::POST, &url, Some(body))
            .await?;
        let result = resp.json::<MessageView>().await?;
        Ok(result)
    }

    /// Marks messages up to `message_id` as read in the conversation.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request fails.
    pub async fn update_read(
        &self,
        convo_id: &str,
        message_id: &str,
    ) -> Result<(), SkybouncerError> {
        let url = format!("{}/xrpc/chat.bsky.convo.updateRead", self.base_url);
        let req = UpdateReadRequest {
            convo_id: convo_id.to_string(),
            message_id: message_id.to_string(),
        };
        let body = serde_json::to_value(&req)?;

        self.send_request("updateRead", reqwest::Method::POST, &url, Some(body))
            .await?;
        Ok(())
    }

    /// Finds or initializes a conversation for the specified member DIDs via `chat.bsky.convo.getConvoForMembers`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request or JSON deserialization fails.
    pub async fn get_convo_for_members(
        &self,
        members: &[&str],
    ) -> Result<ConvoView, SkybouncerError> {
        let mut url = format!("{}/xrpc/chat.bsky.convo.getConvoForMembers?", self.base_url);
        let params: Vec<String> = members.iter().map(|m| format!("members={m}")).collect();
        url.push_str(&params.join("&"));

        let resp = self
            .send_request("getConvoForMembers", reqwest::Method::GET, &url, None)
            .await?;

        #[derive(Deserialize)]
        struct GetConvoResponse {
            convo: ConvoView,
        }

        let result = resp.json::<GetConvoResponse>().await?;
        Ok(result.convo)
    }

    /// Attempts to find an existing conversation containing the specified DID or initialize one.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if conversation lookup fails.
    pub async fn find_or_create_convo_for_did(&self, did: &str) -> Result<String, SkybouncerError> {
        // Try get_convo_for_members first
        if let Ok(convo) = self.get_convo_for_members(&[did]).await {
            return Ok(convo.id);
        }

        // Fallback: search existing conversations from listConvos
        let resp = self.list_convos(Some(50), None).await?;
        for convo in resp.convos {
            if convo.members.iter().any(|m| m.did == did) {
                return Ok(convo.id);
            }
        }

        Err(SkybouncerError::Chat(format!(
            "Could not find or establish conversation with {did}"
        )))
    }
}
