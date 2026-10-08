//! Proactive ATProto direct message alert dispatcher for moderation bounces.
//!
//! Subscribes to real-time [`BounceNotification`] events emitted by [`SkybouncerEngine`],
//! resolves or establishes direct chat conversations with protected target users, and sends
//! structured, actionable moderation alerts with one-click pardon instructions.

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bot::render::{
    account_label, bsky_post_url_from_at_uri, bsky_profile_url, command_target,
};
use crate::engine::BounceNotification;
use crate::error::SkybouncerError;
use skybase::chat::ChatClient;

/// Formats a proactive ATProto direct message alert for a bounced violator.
#[must_use]
pub fn format_bounce_alert(notification: &BounceNotification) -> String {
    let pct = notification.confidence * 100.0;

    let violator = account_label(
        &notification.violator_did,
        notification.violator_handle.as_deref(),
    );
    let profile_url = bsky_profile_url(
        notification
            .violator_handle
            .as_deref()
            .unwrap_or(&notification.violator_did),
    );
    let post_url = bsky_post_url_from_at_uri(&notification.post_uri)
        .unwrap_or_else(|| notification.post_uri.clone());

    let snippet_section = if notification.post_snippet.trim().is_empty() {
        String::new()
    } else {
        format!("\nSnippet: \"{}\"", notification.post_snippet.trim())
    };

    let profile_section = if profile_url.is_empty() {
        String::new()
    } else {
        format!("\nProfile: {profile_url}")
    };

    format!(
        "🛡️ Skybouncer Action Alert:\n\n\
         Bounced violator: {violator}\n\
         Violation: **{}** ({pct:.0}% confidence)\n\
         Reason: {}{snippet_section}{profile_section}\n\
         Post: {post_url}\n\n\
         To undo, reply with:\n\
         pardon {}",
        notification.category,
        notification.reason,
        command_target(
            &notification.violator_did,
            notification.violator_handle.as_deref()
        ),
    )
}

/// Runs the proactive bounce alert dispatcher worker until `cancel` is triggered.
///
/// # Errors
/// Returns [`SkybouncerError`] if unrecoverable initialization error occurs.
pub async fn run_bounce_alert_dispatcher(
    client: ChatClient,
    mut bounce_rx: tokio::sync::broadcast::Receiver<BounceNotification>,
    cancel: CancellationToken,
) -> Result<(), SkybouncerError> {
    info!("Starting proactive ATProto DM bounce alert dispatcher worker");

    while !cancel.is_cancelled() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("Bounce alert dispatcher received cancellation; shutting down");
                break;
            }
            received = bounce_rx.recv() => {
                match received {
                    Ok(notification) => {
                        let target_did = notification.target_did.clone();
                        let alert_text = format_bounce_alert(&notification);

                        debug!(target = %target_did, violator = %notification.violator_did, "Dispatching proactive bounce alert DM");

                        match client.find_or_create_convo_for_did(&target_did).await {
                            Ok(convo_id) => {
                                if let Err(e) = client.send_message(&convo_id, &alert_text).await {
                                    warn!(error = %e, target = %target_did, "Failed to send proactive DM bounce alert");
                                } else {
                                    info!(target = %target_did, violator = %notification.violator_did, "Proactive DM bounce alert delivered successfully");
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, target = %target_did, "Could not locate chat conversation to deliver proactive DM bounce alert");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        warn!(missed = missed, "Bounce alert dispatcher lagged behind event stream");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("Bounce notification channel closed; terminating alert dispatcher");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
