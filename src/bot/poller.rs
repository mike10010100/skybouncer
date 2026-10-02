//! Background polling loop for the ATProto DM bot.
//!
//! Regularly polls the Bluesky chat service (`chat.bsky.convo.listConvos`),
//! identifies unread messages from other users, dispatches them to [`BotCommandHandler`],
//! sends automated responses, and acknowledges read status.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::bot::client::ChatClient;
use crate::bot::handler::BotCommandHandler;
use crate::error::SkybouncerError;

/// Default polling interval for checking unread direct messages (3 seconds).
pub const DEFAULT_BOT_POLL_INTERVAL: Duration = Duration::from_secs(3);

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

                            if let Some(msg) = convo.last_message {
                                // Ignore messages authored by the bot itself
                                if msg.sender.did == handler.bot_did() {
                                    continue;
                                }

                                debug!(
                                    sender = %msg.sender.did,
                                    convo_id = %convo.id,
                                    text = %msg.text,
                                    "Received incoming direct message"
                                );

                                match handler.handle_command(&msg.sender.did, &msg.text).await {
                                    Ok(reply_text) => {
                                        if let Err(e) = client.send_message(&convo.id, &reply_text).await {
                                            error!(error = %e, convo_id = %convo.id, "Failed to send bot reply");
                                        } else {
                                            debug!(convo_id = %convo.id, "Dispatched bot reply");
                                        }

                                        if let Err(e) = client.update_read(&convo.id, &msg.id).await {
                                            warn!(error = %e, convo_id = %convo.id, "Failed to update read state");
                                        }
                                    }
                                    Err(e) => {
                                        error!(error = %e, "Error executing bot command");
                                    }
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
