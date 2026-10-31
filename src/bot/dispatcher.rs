//! Proactive ATProto direct message alert dispatcher for moderation bounces.
//!
//! Subscribes to real-time [`BounceNotification`] events emitted by [`SkybouncerEngine`],
//! resolves or establishes direct chat conversations with protected target users, and sends
//! structured, actionable moderation alerts with one-click pardon instructions.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bot::render::{
    account_label, bsky_post_url_from_at_uri, bsky_profile_url, command_target,
};
use crate::engine::{BounceNotification, ReauthNotification};
use crate::error::SkybouncerError;
use crate::tenant::TenantRegistry;
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

    let target = command_target(
        &notification.violator_did,
        notification.violator_handle.as_deref(),
    );

    let duration_section =
        if notification.bounce_duration != crate::classifier::BounceDuration::Permanent {
            format!(
                "\nDuration: {}",
                notification.bounce_duration.display_label()
            )
        } else {
            String::new()
        };

    let upgrade_section =
        if notification.bounce_duration != crate::classifier::BounceDuration::Permanent {
            format!("\n\nOr to upgrade this temporary block to permanent:\nperm {target}")
        } else {
            String::new()
        };

    format!(
        "🛡️ Skybouncer Action Alert:\n\n\
         Bounced violator: {violator}\n\
         Violation: **{}** ({pct:.0}% confidence)\n\
         Reason: {}{duration_section}{snippet_section}{profile_section}\n\
         Post: {post_url}\n\n\
         To undo, reply with:\n\
         pardon {target}\n\n\
         Or to undo and permanently allowlist:\n\
         pardon and allow {target}{upgrade_section}",
        notification.category, notification.reason,
    )
}

/// Formats a proactive ATProto direct message alert prompting an enrolled user to
/// re-authenticate when their OAuth refresh token has expired or been revoked.
#[must_use]
pub fn format_reauth_alert(notification: &ReauthNotification, public_url: &str) -> String {
    let account = account_label(&notification.target_did, notification.handle.as_deref());
    let base = public_url.trim_end_matches('/');
    let auth_url = if base.is_empty() {
        "https://skybouncer.mike10010100.com/?auth=login".to_string()
    } else {
        format!("{base}/?auth=login")
    };

    format!(
        "🔑 Skybouncer Re-Authentication Needed:\n\n\
         Your Bluesky OAuth session for {account} has expired or was revoked by your PDS, \
         so Skybouncer cannot update your moderation list until you sign in again.\n\n\
         Please reconnect your account (takes ~10 seconds):\n\
         {auth_url}\n\n\
         Your house rules, allowlist, and moderation history are safely preserved."
    )
}

async fn deliver_reauth_dm(
    client: &ChatClient,
    tenant_registry: &TenantRegistry,
    notification: &ReauthNotification,
    public_url: &str,
) -> bool {
    let target_did = &notification.target_did;
    if !tenant_registry
        .is_reauth_notification_pending(target_did)
        .unwrap_or(false)
    {
        return false;
    }

    let alert_text = format_reauth_alert(notification, public_url);
    debug!(
        target = %target_did,
        "Dispatching proactive OAuth re-authentication alert DM"
    );

    match client.find_or_create_convo_for_did(target_did).await {
        Ok(convo_id) => match client.send_message(&convo_id, &alert_text).await {
            Ok(_) => {
                if let Err(e) = tenant_registry.mark_reauth_notified(target_did) {
                    warn!(
                        error = %e,
                        target = %target_did,
                        "Sent re-authentication DM but failed to record reauth_notified_at in SQLite"
                    );
                }
                info!(
                    target = %target_did,
                    "Proactive DM re-authentication alert delivered successfully"
                );
                true
            }
            Err(e) => {
                warn!(
                    error = %e,
                    target = %target_did,
                    "Failed to send proactive DM re-authentication alert"
                );
                false
            }
        },
        Err(e) => {
            warn!(
                error = %e,
                target = %target_did,
                "Could not locate chat conversation to deliver proactive DM re-authentication alert"
            );
            false
        }
    }
}

/// Runs the proactive OAuth re-authentication DM alert dispatcher until `cancel` is triggered.
///
/// On startup, immediately dispatches one-shot DMs for any active tenants already flagged with
/// `reauth_required = 1 AND reauth_notified_at IS NULL` in [`TenantRegistry`] (for example,
/// sessions that failed refresh during cold-start PDS provisioning), then listens for live
/// [`ReauthNotification`] events. Each tenant is notified at most once per expiration cycle.
///
/// # Errors
/// Returns [`SkybouncerError`] if an unrecoverable initialization error occurs.
pub async fn run_reauth_alert_dispatcher(
    client: ChatClient,
    tenant_registry: Arc<TenantRegistry>,
    mut reauth_rx: tokio::sync::broadcast::Receiver<ReauthNotification>,
    public_url: String,
    cancel: CancellationToken,
) -> Result<(), SkybouncerError> {
    info!("Starting proactive ATProto DM re-authentication alert dispatcher worker");

    if let Ok(pending) = tenant_registry.list_pending_reauth_notifications() {
        for (did, handle) in pending {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let notification = ReauthNotification {
                target_did: did,
                handle,
            };
            deliver_reauth_dm(&client, &tenant_registry, &notification, &public_url).await;
        }
    }

    while !cancel.is_cancelled() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("Re-authentication alert dispatcher received cancellation; shutting down");
                break;
            }
            received = reauth_rx.recv() => {
                match received {
                    Ok(notification) => {
                        deliver_reauth_dm(&client, &tenant_registry, &notification, &public_url).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        warn!(missed = missed, "Re-authentication alert dispatcher lagged behind event stream");
                        if let Ok(pending) = tenant_registry.list_pending_reauth_notifications() {
                            for (did, handle) in pending {
                                if cancel.is_cancelled() {
                                    break;
                                }
                                let notif = ReauthNotification {
                                    target_did: did,
                                    handle,
                                };
                                deliver_reauth_dm(&client, &tenant_registry, &notif, &public_url).await;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("Re-authentication notification channel closed; terminating dispatcher");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_format_reauth_alert_includes_handle_and_login_url() {
        let notif = ReauthNotification {
            target_did: "did:plc:alice".to_string(),
            handle: Some("alice.bsky.social".to_string()),
        };
        let text = format_reauth_alert(&notif, "https://skybouncer.mike10010100.com/");
        assert!(text.contains("Re-Authentication Needed"));
        assert!(text.contains("@alice.bsky.social"));
        assert!(text.contains("https://skybouncer.mike10010100.com/?auth=login"));

        let fallback_text = format_reauth_alert(&notif, "");
        assert!(fallback_text.contains("https://skybouncer.mike10010100.com/?auth=login"));
    }

    #[test]
    fn test_format_bounce_alert_permanent_and_temporary_upgrade_reminder() {
        let perm_notif = BounceNotification {
            target_did: "did:plc:alice".to_string(),
            violator_did: "did:plc:spammer".to_string(),
            violator_handle: Some("spammer.bsky.social".to_string()),
            category: crate::classifier::ViolationCategory::CryptoSpam,
            confidence: 0.96,
            reason: "Crypto airdrop link".to_string(),
            post_uri: "at://did:plc:spammer/app.bsky.feed.post/123".to_string(),
            post_snippet: "Free tokens".to_string(),
            bounce_duration: crate::classifier::BounceDuration::Permanent,
        };
        let perm_text = format_bounce_alert(&perm_notif);
        assert!(perm_text.contains("pardon spammer.bsky.social"));
        assert!(perm_text.contains("pardon and allow spammer.bsky.social"));
        assert!(!perm_text.contains("perm spammer.bsky.social"));
        assert!(!perm_text.contains("Duration:"));

        let temp_notif = BounceNotification {
            bounce_duration: crate::classifier::BounceDuration::Cooldown24h,
            ..perm_notif
        };
        let temp_text = format_bounce_alert(&temp_notif);
        assert!(temp_text.contains("Duration: 24-Hour Cooldown"));
        assert!(temp_text.contains("pardon spammer.bsky.social"));
        assert!(temp_text.contains("pardon and allow spammer.bsky.social"));
        assert!(temp_text.contains(
            "Or to upgrade this temporary block to permanent:\nperm spammer.bsky.social"
        ));
    }

    #[tokio::test]
    async fn test_run_reauth_alert_dispatcher_delivers_once_and_deduplicates() {
        let mock_chat = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getConvoForMembers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "convo": {
                    "id": "convo-reauth-1",
                    "rev": "1",
                    "members": [],
                    "muted": false,
                    "unreadCount": 0
                }
            })))
            .mount(&mock_chat)
            .await;

        Mock::given(method("POST"))
            .and(path("/xrpc/chat.bsky.convo.sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg-reauth-1",
                "rev": "2",
                "text": "ok",
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-10-28T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_chat)
            .await;

        let registry = Arc::new(TenantRegistry::open_in_memory().unwrap());
        registry
            .register_or_update(
                &crate::tenant::Tenant::new("did:plc:alice").with_handle("alice.bsky.social"),
            )
            .unwrap();
        assert!(registry.mark_reauth_required("did:plc:alice").unwrap());

        let chat_client = ChatClient::new(mock_chat.uri(), "bot-token").unwrap();
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let cancel = CancellationToken::new();

        // Emit a duplicate live event for the same DID in addition to startup pending state
        let _ = tx.send(ReauthNotification {
            target_did: "did:plc:alice".to_string(),
            handle: Some("alice.bsky.social".to_string()),
        });
        drop(tx);

        run_reauth_alert_dispatcher(
            chat_client,
            Arc::clone(&registry),
            rx,
            "https://skybouncer.mike10010100.com".to_string(),
            cancel,
        )
        .await
        .unwrap();

        assert!(!registry
            .is_reauth_notification_pending("did:plc:alice")
            .unwrap());
    }
}
