//! ATProto Chat (`chat.bsky.convo.*`) DM Bot Interface.
//!
//! Provides direct-message conversational moderation management for Bluesky users:
//! - Users can DM the bot account to query or update their rules, check stats, view recent bounces, or pardon accounts.
//! - [`ChatClient`]: Re-exported asynchronous client for Bluesky chat service endpoints.
//! - [`BotCommandHandler`]: Command parser and dispatcher for conversational commands.
//! - [`run_bot_poller`]: Supervised polling worker for processing incoming DMs.

pub mod dispatcher;
pub mod handler;
pub mod poller;
pub mod render;

pub use dispatcher::{format_bounce_alert, run_bounce_alert_dispatcher};
pub use handler::BotCommandHandler;
pub use poller::{run_bot_poller, DEFAULT_BOT_POLL_INTERVAL};
pub use render::{
    account_label, account_label_with_url, bsky_post_url, bsky_post_url_from_at_uri,
    bsky_profile_url, command_target, BSKY_WEB_ORIGIN,
};

// The ATProto Chat client and its data models now live in `skybase::chat`.
pub use skybase::chat::{
    AcceptConvoRequest, AcceptConvoResponse, ChatClient, ConvoMember, ConvoView,
    GetMessagesResponse, ListConvoRequestsResponse, ListConvosResponse, MessageSender, MessageView,
    SendMessagePayload, SendMessageRequest, UpdateReadRequest, DEFAULT_CHAT_ENDPOINT,
};
pub use skybase::lexicon::{extract_link_facets, Facet, FacetFeature, FacetIndex};
