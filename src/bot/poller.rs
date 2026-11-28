//! Background polling loop for the ATProto DM bot.
//!
//! Regularly polls the Bluesky chat service (`chat.bsky.convo.listConvos` and `chat.bsky.convo.listConvoRequests`),
//! auto-accepts incoming conversation requests from non-followed accounts,
//! identifies unread messages from other users, dispatches them to [`BotCommandHandler`],
//! sends automated responses, and acknowledges read status.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::bot::handler::BotCommandHandler;
use crate::error::SkybouncerError;
use skybase::chat::ChatClient;
use skybase::chat::{ConvoView, MessageView};

/// Default polling interval for checking unread direct messages (3 seconds).
pub const DEFAULT_BOT_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Maximum processed message IDs kept in memory to deduplicate across retries.
const MAX_PROCESSED_MESSAGE_IDS: usize = 2048;

/// Maximum pagination pages per polling tick for `list_convos` / `list_convo_requests`.
const MAX_CONVO_PAGES: usize = 20;

/// Maximum pagination pages per conversation for `get_messages`.
const MAX_MESSAGE_PAGES: usize = 10;

/// Bounded FIFO LRU cache of recently processed DM message IDs.
struct ProcessedMessageCache {
    order: VecDeque<String>,
    set: HashSet<String>,
    cap: usize,
}

impl ProcessedMessageCache {
    fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(cap.min(256)),
            set: HashSet::with_capacity(cap.min(256)),
            cap: cap.max(1),
        }
    }

    fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }

    fn insert(&mut self, id: String) {
        if self.set.contains(&id) {
            return;
        }
        while self.order.len() >= self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
        self.set.insert(id.clone());
        self.order.push_back(id);
    }
}

/// Processes unread messages for an individual conversation or conversation request.
async fn process_convo(
    convo: &ConvoView,
    client: &ChatClient,
    handler: &BotCommandHandler,
    processed_msg_ids: &mut ProcessedMessageCache,
    already_accepted: bool,
) {
    let should_process = convo.unread_count > 0
        || (convo.status.as_deref() == Some("request")
            && convo.last_message.as_ref().is_some_and(|m| {
                m.sender.did != handler.bot_did() && !processed_msg_ids.contains(&m.id)
            }));

    if !should_process {
        return;
    }

    if !already_accepted && convo.status.as_deref() == Some("request") {
        info!(
            convo_id = %convo.id,
            "Accepting pending DM conversation request before replying"
        );
        if let Err(e) = client.accept_convo(&convo.id).await {
            warn!(
                convo_id = %convo.id,
                error = %e,
                "Failed to accept convo request; proceeding to process messages"
            );
        }
    }

    // Fetch message history when multiple messages are unread, when `last_message` is missing
    // (e.g. `#deletedMessageView`), OR when a proactive bot alert interleaved after the user's
    // unread DM. Paginate across `getMessages` pages so >10 interleaved bot alerts cannot push
    // unread user DMs out of the window.
    let last_is_bot = convo
        .last_message
        .as_ref()
        .is_some_and(|m| m.sender.did == handler.bot_did());
    let need_history = convo.unread_count > 1
        || (convo.unread_count > 0 && (last_is_bot || convo.last_message.is_none()));

    let mut messages: Vec<MessageView> = if need_history {
        let max_user_msgs = usize::try_from(convo.unread_count)
            .unwrap_or(1)
            .clamp(1, 50);
        let fetch_limit = max_user_msgs.saturating_add(10).clamp(10, 50);
        let mut selected: Vec<MessageView> = Vec::with_capacity(max_user_msgs);
        let mut cursor: Option<String> = None;
        let mut seen_cursors: HashSet<String> = HashSet::new();
        let mut pages = 0usize;
        let mut fetch_failed = false;

        loop {
            match client
                .get_messages(&convo.id, Some(fetch_limit), cursor.as_deref())
                .await
            {
                Ok(msg_resp) => {
                    for m in msg_resp.messages {
                        if m.sender.did == handler.bot_did() {
                            continue;
                        }
                        selected.push(m);
                        if selected.len() >= max_user_msgs {
                            break;
                        }
                    }
                    pages += 1;
                    if selected.len() >= max_user_msgs || pages >= MAX_MESSAGE_PAGES {
                        break;
                    }
                    match msg_resp
                        .cursor
                        .map(|c| c.trim().to_string())
                        .filter(|c| !c.is_empty())
                    {
                        Some(next_cursor) if seen_cursors.insert(next_cursor.clone()) => {
                            cursor = Some(next_cursor);
                        }
                        _ => break,
                    }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        convo_id = %convo.id,
                        "Failed to fetch message history"
                    );
                    fetch_failed = pages == 0;
                    break;
                }
            }
        }

        if fetch_failed && selected.is_empty() {
            // Only fall back to `last_message` when it is genuinely authored by the user;
            // never fall back to a bot message or advance `update_read` over unread user DMs.
            convo
                .last_message
                .clone()
                .filter(|m| m.sender.did != handler.bot_did())
                .into_iter()
                .collect()
        } else {
            selected.reverse();
            selected
        }
    } else {
        convo
            .last_message
            .clone()
            .filter(|m| m.sender.did != handler.bot_did())
            .into_iter()
            .collect()
    };

    if messages.is_empty() {
        return;
    }

    let mut latest_processed_id: Option<String> = None;

    for msg in messages.drain(..) {
        if msg.sender.did == handler.bot_did() {
            continue;
        }

        // Skip if already processed in a previous tick (e.g. if prior `update_read` failed).
        if processed_msg_ids.contains(&msg.id) {
            latest_processed_id = Some(msg.id);
            continue;
        }

        debug!(
            sender = %msg.sender.did,
            convo_id = %convo.id,
            msg_id = %msg.id,
            text = %msg.text,
            "Processing incoming direct message"
        );

        let reply_to_send = match handler.handle_command(&msg.sender.did, &msg.text).await {
            Ok(reply_text) => reply_text,
            Err(e) => {
                error!(
                    error = %e,
                    convo_id = %convo.id,
                    msg_id = %msg.id,
                    "Unexpected error executing bot command; sending generic error reply"
                );
                "⚠️ Sorry, an internal error occurred while processing that command. Please try again later.".to_string()
            }
        };

        if reply_to_send.trim().is_empty() {
            // Suppressed reply (e.g. rate-limit / unknown-command cooldown): mark processed & read.
            processed_msg_ids.insert(msg.id.clone());
            latest_processed_id = Some(msg.id);
            continue;
        }

        match crate::bot::render::send_dm_chunked(client, &convo.id, &reply_to_send).await {
            Ok(()) => {
                debug!(convo_id = %convo.id, "Dispatched bot reply");
                processed_msg_ids.insert(msg.id.clone());
                latest_processed_id = Some(msg.id);
            }
            Err(e) => {
                error!(
                    error = %e,
                    convo_id = %convo.id,
                    msg_id = %msg.id,
                    "Failed to send bot reply; leaving message unread for retry"
                );
                break;
            }
        }
    }

    if let Some(msg_id) = latest_processed_id {
        if let Err(e) = client.update_read(&convo.id, &msg_id).await {
            warn!(
                error = %e,
                convo_id = %convo.id,
                msg_id = %msg_id,
                "Failed to update read state"
            );
        }
    }
}

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

    let mut processed_msg_ids = ProcessedMessageCache::new(MAX_PROCESSED_MESSAGE_IDS);

    while !cancel.is_cancelled() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("Bot poller received cancellation; shutting down");
                break;
            }
            _ = interval.tick() => {
                // 1. Check for incoming conversation requests from non-followed accounts and auto-accept (paginated)
                let mut req_cursor: Option<String> = None;
                let mut seen_req_cursors: HashSet<String> = HashSet::new();
                for _page in 0..MAX_CONVO_PAGES {
                    if cancel.is_cancelled() {
                        break;
                    }
                    match client.list_convo_requests(Some(50), req_cursor.as_deref()).await {
                        Ok(resp) => {
                            for req_convo in resp.requests {
                                info!(
                                    convo_id = %req_convo.id,
                                    "Auto-accepting incoming DM conversation request"
                                );
                                if let Err(e) = client.accept_convo(&req_convo.id).await {
                                    warn!(
                                        convo_id = %req_convo.id,
                                        error = %e,
                                        "Failed to accept convo request; proceeding to process messages"
                                    );
                                }
                                process_convo(&req_convo, &client, &handler, &mut processed_msg_ids, true).await;
                            }
                            match resp.cursor.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()) {
                                Some(next_cursor) if seen_req_cursors.insert(next_cursor.clone()) => {
                                    req_cursor = Some(next_cursor);
                                }
                                _ => break,
                            }
                        }
                        Err(e) => {
                            debug!(error = %e, "Failed to poll convo requests; will retry next tick");
                            break;
                        }
                    }
                }

                // 2. Check for active conversations (paginated)
                let mut convo_cursor: Option<String> = None;
                let mut seen_convo_cursors: HashSet<String> = HashSet::new();
                for _page in 0..MAX_CONVO_PAGES {
                    if cancel.is_cancelled() {
                        break;
                    }
                    match client.list_convos(Some(50), convo_cursor.as_deref()).await {
                        Ok(resp) => {
                            for convo in resp.convos {
                                process_convo(&convo, &client, &handler, &mut processed_msg_ids, false).await;
                            }
                            match resp.cursor.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()) {
                                Some(next_cursor) if seen_convo_cursors.insert(next_cursor.clone()) => {
                                    convo_cursor = Some(next_cursor);
                                }
                                _ => break,
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to poll chat conversations; will retry on next tick");
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::ProcessedMessageCache;

    #[test]
    fn processed_message_cache_fifo_evicts_oldest_and_keeps_newer() {
        let mut cache = ProcessedMessageCache::new(3);
        cache.insert("m1".to_string());
        cache.insert("m2".to_string());
        cache.insert("m3".to_string());
        // Duplicate insert must not evict older entries.
        cache.insert("m2".to_string());
        assert!(cache.contains("m1"));
        assert!(cache.contains("m2"));
        assert!(cache.contains("m3"));

        // Inserting a 4th item evicts "m1" while preserving "m2" and "m3".
        cache.insert("m4".to_string());
        assert!(!cache.contains("m1"));
        assert!(cache.contains("m2"));
        assert!(cache.contains("m3"));
        assert!(cache.contains("m4"));
    }
}
