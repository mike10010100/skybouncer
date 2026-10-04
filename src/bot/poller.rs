//! Background polling loop for the ATProto DM bot.
//!
//! Regularly polls the Bluesky chat service (`chat.bsky.convo.listConvos`),
//! identifies unread messages from other users, dispatches them to [`BotCommandHandler`],
//! sends automated responses, and acknowledges read status.

use std::collections::HashSet;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::bot::client::ChatClient;
use crate::bot::handler::BotCommandHandler;
use crate::bot::types::MessageView;
use crate::error::SkybouncerError;

/// Default polling interval for checking unread direct messages (3 seconds).
pub const DEFAULT_BOT_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum processed message IDs kept in memory to deduplicate across retries.
const MAX_PROCESSED_MESSAGE_IDS: usize = 2048;

/// Runs the ATProto Chat DM bot polling loop until `cancel` is triggered.
///
/// # Errors
/// Returns [`SkybouncerError`] if unrecoverable initialization error occurs.
pub async fn run_bot_poller(
    client: ChatClient,
    handler: BotCommandHandler,
    poll_interval: Duration,
    cancel: CancellationToken,
) -> Result<(), SkybouncerError> {
    info!(
        bot_did = %handler.bot_did(),
        interval = ?poll_interval,
        "Starting ATProto DM bot polling worker"
    );

    let mut interval = tokio::time::interval(poll_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut processed_msg_ids: HashSet<String> = HashSet::new();

    while !cancel.is_cancelled() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("Bot poller received cancellation; shutting down");
                break;
            }
            _ = interval.tick() => {
                match client.list_convos(Some(20), None).await {
                    Ok(resp) => {
                        for convo in resp.convos {
                            if convo.unread_count == 0 {
                                continue;
                            }

                            // Fetch all unread messages if multiple unread, otherwise use last_message
                            let mut messages: Vec<MessageView> = if convo.unread_count > 1 {
                                let fetch_limit = usize::try_from(convo.unread_count).unwrap_or(20).clamp(1, 50);
                                match client.get_messages(&convo.id, Some(fetch_limit), None).await {
                                    Ok(msg_resp) => {
                                        let mut msgs = msg_resp.messages;
                                        // Messages from getMessages are returned newest-first; reverse to chronological order
                                        msgs.reverse();
                                        msgs
                                    }
                                    Err(e) => {
                                        warn!(error = %e, convo_id = %convo.id, "Failed to fetch full message history; falling back to last_message");
                                        convo.last_message.into_iter().collect()
                                    }
                                }
                            } else {
                                convo.last_message.into_iter().collect()
                            };

                            let mut latest_processed_id: Option<String> = None;

                            for msg in messages.drain(..) {
                                // Ignore messages authored by the bot itself
                                if msg.sender.did == handler.bot_did() {
                                    latest_processed_id = Some(msg.id);
                                    continue;
                                }

                                // Skip if already processed in previous tick
                                if processed_msg_ids.contains(&msg.id) {
                                    continue;
                                }

                                debug!(
                                    sender = %msg.sender.did,
                                    convo_id = %convo.id,
                                    msg_id = %msg.id,
                                    text = %msg.text,
                                    "Processing incoming direct message"
                                );

                                match handler.handle_command(&msg.sender.did, &msg.text).await {
                                    Ok(reply_text) => {
                                        if let Err(e) = client.send_message(&convo.id, &reply_text).await {
                                            error!(error = %e, convo_id = %convo.id, "Failed to send bot reply");
                                        } else {
                                            debug!(convo_id = %convo.id, "Dispatched bot reply");
                                        }

                                        if processed_msg_ids.len() >= MAX_PROCESSED_MESSAGE_IDS {
                                            processed_msg_ids.clear();
                                        }
                                        processed_msg_ids.insert(msg.id.clone());
                                        latest_processed_id = Some(msg.id);
                                    }
                                    Err(e) => {
                                        error!(error = %e, "Error executing bot command");
                                    }
                                }
                            }

                            if let Some(msg_id) = latest_processed_id {
                                if let Err(e) = client.update_read(&convo.id, &msg_id).await {
                                    warn!(error = %e, convo_id = %convo.id, msg_id = %msg_id, "Failed to update read state");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to poll chat conversations; will retry on next tick");
                    }
                }
            }
        }
    }

    Ok(())
}
