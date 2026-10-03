//! ATProto Chat (`chat.bsky.convo.*`) DM Bot Interface.
//!
//! Provides direct-message conversational moderation management for Bluesky users:
//! - Users can DM the bot account to query or update their rules, check stats, view recent bounces, or pardon accounts.
//! - [`ChatClient`]: Asynchronous client for Bluesky chat service endpoints.
//! - [`BotCommandHandler`]: Command parser and dispatcher for conversational commands.
//! - [`run_bot_poller`]: Supervised polling worker for processing incoming DMs.

pub mod client;
pub mod dispatcher;
pub mod handler;
pub mod poller;
pub mod types;

pub use client::{ChatClient, DEFAULT_CHAT_ENDPOINT};
pub use dispatcher::{format_bounce_alert, run_bounce_alert_dispatcher};
pub use handler::BotCommandHandler;
pub use poller::{run_bot_poller, DEFAULT_BOT_POLL_INTERVAL};
pub use types::{
    ConvoMember, ConvoView, GetMessagesResponse, ListConvosResponse, MessageSender, MessageView,
    SendMessagePayload, SendMessageRequest, UpdateReadRequest,
};
