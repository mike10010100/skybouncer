//! Asynchronous HTTP client for ATProto Chat (`chat.bsky.convo.*`).

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use tracing::debug;

use crate::bot::types::{
    ConvoView, GetMessagesResponse, ListConvosResponse, MessageView, SendMessagePayload,
    SendMessageRequest, UpdateReadRequest,
};
use crate::error::SkybouncerError;

/// Default public Bluesky chat service endpoint.
pub const DEFAULT_CHAT_ENDPOINT: &str = "https://api.bsky.chat";

/// Asynchronous HTTP client for interacting with the ATProto Chat service.
#[derive(Clone)]
pub struct ChatClient {
    base_url: String,
    client: reqwest::Client,
}

impl ChatClient {
    /// Creates a new [`ChatClient`] targeting the specified base URL and bearer token.
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
        let auth_val = format!("Bearer {token}");
        let mut header_value = HeaderValue::from_str(&auth_val)
            .map_err(|e| SkybouncerError::Config(format!("Invalid auth token header: {e}")))?;
        header_value.set_sensitive(true);
        headers.insert(AUTHORIZATION, header_value);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self { base_url, client })
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

        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SkybouncerError::Chat(format!(
                "listConvos failed with status {status}: {body}"
            )));
        }

        let result = resp.json::<ListConvosResponse>().await?;
        debug!(count = result.convos.len(), "Fetched chat conversations");
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

        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SkybouncerError::Chat(format!(
                "getMessages failed with status {status}: {body}"
            )));
        }

        let result = resp.json::<GetMessagesResponse>().await?;
        Ok(result)
    }

    /// Sends a text message to the specified conversation.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if the HTTP request or JSON deserialization fails.
    pub async fn send_message(
        &self,
        convo_id: &str,
        text: &str,
    ) -> Result<MessageView, SkybouncerError> {
        let url = format!("{}/xrpc/chat.bsky.convo.sendMessage", self.base_url);
        let req = SendMessageRequest {
            convo_id: convo_id.to_string(),
            message: SendMessagePayload {
                text: text.to_string(),
            },
        };

        let resp = self.client.post(&url).json(&req).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SkybouncerError::Chat(format!(
                "sendMessage failed with status {status}: {body}"
            )));
        }

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

        let resp = self.client.post(&url).json(&req).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SkybouncerError::Chat(format!(
                "updateRead failed with status {status}: {body}"
            )));
        }

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

        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SkybouncerError::Chat(format!(
                "getConvoForMembers failed with status {status}: {body}"
            )));
        }

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
