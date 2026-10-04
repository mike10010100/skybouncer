//! Strongly typed data structures for ATProto Chat (`chat.bsky.convo.*`).

use serde::{Deserialize, Serialize};

/// Member within an ATProto Chat conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvoMember {
    /// Decentralized identifier (DID) of the member.
    pub did: String,
    /// Handle of the member if available.
    #[serde(default)]
    pub handle: Option<String>,
    /// Display name of the member if available.
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
}

/// Sender details for an individual chat message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSender {
    /// DID of the message sender.
    pub did: String,
}

/// Individual message representation in `chat.bsky.convo.defs#messageView`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageView {
    /// Unique message identifier string.
    pub id: String,
    /// Revision identifier.
    #[serde(default)]
    pub rev: String,
    /// Text payload of the message.
    pub text: String,
    /// Sender metadata.
    pub sender: MessageSender,
    /// ISO 8601 timestamp string when the message was sent.
    #[serde(rename = "sentAt")]
    pub sent_at: String,
}

/// Conversation representation in `chat.bsky.convo.defs#convoView`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvoView {
    /// Unique conversation identifier string.
    pub id: String,
    /// Revision identifier.
    #[serde(default)]
    pub rev: String,
    /// Members participating in the conversation.
    #[serde(default)]
    pub members: Vec<ConvoMember>,
    /// Most recent message in the conversation, if any.
    #[serde(rename = "lastMessage", default)]
    pub last_message: Option<MessageView>,
    /// Number of unread messages for the authenticated caller.
    #[serde(rename = "unreadCount", default)]
    pub unread_count: u64,
    /// Status of the conversation for the caller ("request" | "accepted").
    #[serde(default)]
    pub status: Option<String>,
}

/// Response payload from `chat.bsky.convo.listConvos`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListConvosResponse {
    /// Conversations returned in the current page.
    #[serde(default)]
    pub convos: Vec<ConvoView>,
    /// Pagination cursor string if more conversations exist.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Response payload from `chat.bsky.convo.listConvoRequests`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListConvoRequestsResponse {
    /// Conversation requests returned in the current page.
    #[serde(default)]
    pub requests: Vec<ConvoView>,
    /// Pagination cursor string if more conversation requests exist.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Request body for `chat.bsky.convo.acceptConvo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptConvoRequest {
    /// Target conversation ID to accept.
    #[serde(rename = "convoId")]
    pub convo_id: String,
}

/// Response payload from `chat.bsky.convo.acceptConvo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptConvoResponse {
    /// Revision identifier when accepted, or None if already accepted.
    #[serde(default)]
    pub rev: Option<String>,
}

/// Response payload from `chat.bsky.convo.getMessages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetMessagesResponse {
    /// Messages returned in the current page.
    #[serde(default)]
    pub messages: Vec<MessageView>,
    /// Pagination cursor string if more messages exist.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Request payload to send a message via `chat.bsky.convo.sendMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessagePayload {
    /// Content of the message.
    pub text: String,
}

/// Request body for `chat.bsky.convo.sendMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Target conversation ID.
    #[serde(rename = "convoId")]
    pub convo_id: String,
    /// Message details.
    pub message: SendMessagePayload,
}

/// Request body for `chat.bsky.convo.updateRead`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateReadRequest {
    /// Target conversation ID.
    #[serde(rename = "convoId")]
    pub convo_id: String,
    /// Message ID marked as read.
    #[serde(rename = "messageId")]
    pub message_id: String,
}
