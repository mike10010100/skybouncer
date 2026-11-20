//! Proactive ATProto direct message alert dispatcher for moderation bounces.
//!
//! Subscribes to real-time [`BounceNotification`] events emitted by [`SkybouncerEngine`],
//! resolves or establishes direct chat conversations with protected target users, and sends
//! structured, actionable moderation alerts with one-click pardon instructions.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bot::render::{
    account_label, bsky_post_or_web_url, bsky_post_url_from_at_uri, bsky_profile_url,
    command_target, send_dm_chunked, truncate_chars,
};
use crate::dogpile::{StormDigestNotification, StormNotification};
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

    let reason = truncate_chars(notification.reason.trim(), 150);

    let snippet_trimmed = notification.post_snippet.trim();
    let snippet_section = if snippet_trimmed.is_empty() {
        String::new()
    } else {
        format!("\nSnippet: \"{}\"", truncate_chars(snippet_trimmed, 140))
    };

    let profile_section = if profile_url.is_empty() {
        String::new()
    } else {
        format!("\nProfile: {profile_url}")
    };

    let reply_to_section = notification
        .reply_to_uri
        .as_deref()
        .and_then(bsky_post_or_web_url)
        .map(|url| format!("\nReplying to: {url}"))
        .unwrap_or_default();

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
         Reason: {reason}{duration_section}{snippet_section}{profile_section}\n\
         Post: {post_url}{reply_to_section}\n\n\
         To undo, reply with:\n\
         pardon {target}\n\n\
         Or to undo and permanently allowlist:\n\
         pardon and allow {target}{upgrade_section}",
        notification.category,
    )
}

/// Formats a proactive ATProto DM alert for a detected or escalated dogpile storm.
#[must_use]
pub fn format_storm_alert(notification: &StormNotification) -> String {
    let storm = &notification.storm;
    let sev = storm.severity.as_str().to_ascii_uppercase();
    let header = if notification.is_escalation {
        format!("🚨 Skybouncer Storm Escalation [{sev}]:")
    } else {
        format!("⛈️ Skybouncer Dogpile Alert [{sev}]:")
    };

    let is_mentions = storm.focal_post_uri.ends_with("/_mentions");
    let post_section = if is_mentions {
        "Target: Coordinated @mentions / multi-thread surge".to_string()
    } else {
        let post_url = bsky_post_url_from_at_uri(&storm.focal_post_uri)
            .unwrap_or_else(|| storm.focal_post_uri.clone());
        let snippet = truncate_chars(storm.focal_post_snippet.trim(), 140);
        if snippet.is_empty() {
            format!("Post: {post_url}")
        } else {
            format!("Post: {post_url}\nSnippet: \"{snippet}\"")
        }
    };

    let m = &storm.metrics;
    let oon_pct = m.out_of_network_ratio * 100.0;
    let score_pct = m.composite_score * 100.0;
    let defensive_line = if m.defensive_blocks > 0 || m.defensive_detaches > 0 {
        format!(
            "\nDefensive signals: {} blocks, {} postgate detaches",
            m.defensive_blocks, m.defensive_detaches
        )
    } else {
        String::new()
    };

    let catalyst_section = if let Some(ref cat) = storm.top_catalyst {
        let cat_author = account_label(&cat.author_did, cat.author_handle.as_deref());
        let cat_url =
            bsky_post_url_from_at_uri(&cat.post_uri).unwrap_or_else(|| cat.post_uri.clone());
        let cat_snippet = truncate_chars(cat.text_snippet.trim(), 120);
        let snippet_line = if cat_snippet.is_empty() {
            String::new()
        } else {
            format!("\nCatalyst Text: \"{cat_snippet}\"")
        };
        format!(
            "\n\nCatalyst QT by {cat_author}: {} likes, {} reposts ({:.1}x root likes)\nCatalyst Post: {cat_url}{snippet_line}",
            cat.like_count, cat.repost_count, cat.dunk_ratio
        )
    } else {
        String::new()
    };

    let stance_section = if let Some(ref stance) = storm.stance {
        let summary = truncate_chars(stance.summary.trim(), 180);
        format!(
            "\n\nStance Check: {} ({:.0}% conf) — {}",
            stance.classification,
            stance.confidence * 100.0,
            summary
        )
    } else {
        String::new()
    };

    let target_arg = if is_mentions {
        "latest"
    } else {
        storm
            .focal_post_uri
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("latest")
    };

    let shield_hints = if is_mentions {
        "Quick commands:\n\
         • `storms` — View active surge details\n\
         • `lock <post_url|rkey> following` — Lock replies on a post\n\
         • `storm off` — Resume per-bounce DMs"
            .to_string()
    } else {
        format!(
            "Quick shield replies:\n\
             • `lock {target_arg} following` (or `nobody` / `followers`)\n\
             • `detach {target_arg}` (or `detach {target_arg} all`)\n\
             • `storm off` — Resume per-bounce DMs"
        )
    };

    format!(
        "{header}\n\n\
         {post_section}\n\
         Velocity: {} out-of-network authors / {} total ({oon_pct:.0}% OON)\n\
         Signals: direct_ratio={:.2}, dunk_ratio={:.1}x, power={:.1}x, burst_z={:.1}, score={score_pct:.0}%{defensive_line}\
         {catalyst_section}{stance_section}\n\n\
         ⚡ Storm Mode is active: individual bounce DMs are batched into periodic digests and evaluation headroom is 3x.\n\n\
         {shield_hints}",
        m.unique_oon_authors_short,
        m.unique_authors_short,
        m.direct_ratio,
        m.dunk_ratio,
        m.power_asymmetry,
        m.burst_z_score,
    )
}

/// Formats a periodic Storm Mode digest DM summarizing aggregated bounces.
#[must_use]
pub fn format_storm_digest(digest: &StormDigestNotification) -> String {
    let focal_line = if digest.focal_post_uri.ends_with("/_mentions") {
        "Target: Recent @mentions surge".to_string()
    } else {
        let url = bsky_post_url_from_at_uri(&digest.focal_post_uri)
            .unwrap_or_else(|| digest.focal_post_uri.clone());
        format!("Post: {url}")
    };

    let mut samples = String::new();
    for (idx, item) in digest.sample_violators.iter().enumerate() {
        let label = account_label(&item.violator_did, item.violator_handle.as_deref());
        if idx > 0 {
            samples.push('\n');
        }
        samples.push_str(&format!("• {label} — **{}**", item.category));
    }

    let sample_len = u64::try_from(digest.sample_violators.len()).unwrap_or(u64::MAX);
    let remainder_line = if digest.bounced_count > sample_len {
        format!(
            "\n• … and {} more account(s)",
            digest.bounced_count.saturating_sub(sample_len)
        )
    } else {
        String::new()
    };

    let sample_block = if samples.is_empty() {
        String::new()
    } else {
        format!("\n\nSample bounced accounts:\n{samples}{remainder_line}")
    };

    let footer = if digest.storm_still_active {
        "⚡ Storm Mode remains active. Reply `storms`, `lock latest following`, or `storm off`."
    } else {
        "✅ Surge subsided — Storm Mode has automatically deactivated."
    };

    format!(
        "📦 Skybouncer Storm Mode Digest ({}s window):\n\n\
         {focal_line}\n\
         Bounced during window: **{}** account(s){sample_block}\n\n\
         {footer}",
        digest.window_secs, digest.bounced_count
    )
}

/// Formats a proactive ATProto direct message alert prompting an enrolled user to
/// re-authenticate when their OAuth refresh token has expired or been revoked.
#[must_use]
pub fn format_reauth_alert(notification: &ReauthNotification, public_url: &str) -> String {
    format_reauth_alert_with_count(notification, public_url, 0)
}

/// Formats a proactive ATProto direct message alert for either the initial expiration
/// (`notify_count == 0`), the first weekly reminder (`notify_count == 1`), or the second/final
/// weekly reminder (`notify_count >= 2`).
#[must_use]
pub fn format_reauth_alert_with_count(
    notification: &ReauthNotification,
    public_url: &str,
    notify_count: u32,
) -> String {
    let account = account_label(&notification.target_did, notification.handle.as_deref());
    let base = public_url.trim_end_matches('/');
    let auth_url = if base.is_empty() {
        "https://skybouncer.mike10010100.com/?auth=login".to_string()
    } else {
        format!("{base}/?auth=login")
    };

    match notify_count {
        0 => format!(
            "🔑 Skybouncer Re-Authentication Needed:\n\n\
             Your Bluesky OAuth session for {account} has expired or was revoked by your PDS, \
             so Skybouncer cannot update your moderation list until you sign in again.\n\n\
             Please reconnect your account (takes ~10 seconds):\n\
             {auth_url}\n\n\
             Your house rules, allowlist, and moderation history are safely preserved."
        ),
        1 => format!(
            "🔑 Skybouncer Weekly Reminder (1/2) — Re-Authentication Needed:\n\n\
             Your Bluesky OAuth session for {account} is still expired, \
             so automated moderation remains paused until you sign in again.\n\n\
             Please reconnect your account (takes ~10 seconds):\n\
             {auth_url}\n\n\
             Your house rules, allowlist, and moderation history are safely preserved. \
             Reply `pause` if you want to stop these reminders."
        ),
        _ => format!(
            "🔑 Skybouncer Final Reminder (2/2) — Re-Authentication Needed:\n\n\
             Your Bluesky OAuth session for {account} is still expired, \
             so automated moderation remains paused until you sign in again.\n\n\
             Please reconnect your account whenever you're ready (takes ~10 seconds):\n\
             {auth_url}\n\n\
             This is our final automatic reminder so we don't clutter your DMs. \
             Your house rules, allowlist, and moderation history remain safely preserved."
        ),
    }
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

    let notify_count = tenant_registry.reauth_notify_count(target_did).unwrap_or(0);
    let alert_text = format_reauth_alert_with_count(notification, public_url, notify_count);
    debug!(
        target = %target_did,
        notify_count,
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
                    notify_count = notify_count + 1,
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
/// On startup and on a periodic sweep timer, dispatches DMs for any active tenants due for
/// an initial re-authentication alert or a weekly follow-up reminder (up to
/// [`crate::tenant::MAX_REAUTH_NOTIFICATIONS`] total alerts per expiration cycle, spaced by
/// [`crate::tenant::DEFAULT_REAUTH_REMINDER_INTERVAL`]), while also listening for live
/// [`ReauthNotification`] broadcast events.
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

    let mut reminder_sweep = tokio::time::interval(std::time::Duration::from_secs(60));
    reminder_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume the immediate first tick since we already ran the startup sweep above.
    reminder_sweep.tick().await;

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
            _ = reminder_sweep.tick() => {
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
                                if let Err(e) = send_dm_chunked(&client, &convo_id, &alert_text).await {
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

/// Runs the proactive dogpile storm alert dispatcher worker until `cancel` is triggered.
///
/// # Errors
/// Returns [`SkybouncerError`] if unrecoverable initialization error occurs.
pub async fn run_storm_alert_dispatcher(
    client: ChatClient,
    mut storm_rx: tokio::sync::broadcast::Receiver<StormNotification>,
    cancel: CancellationToken,
) -> Result<(), SkybouncerError> {
    info!("Starting proactive ATProto DM dogpile storm alert dispatcher worker");

    while !cancel.is_cancelled() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("Storm alert dispatcher received cancellation; shutting down");
                break;
            }
            received = storm_rx.recv() => {
                match received {
                    Ok(notification) => {
                        let target_did = notification.storm.target_did.clone();
                        let alert_text = format_storm_alert(&notification);

                        debug!(target = %target_did, focal = %notification.storm.focal_post_uri, "Dispatching proactive DM dogpile storm alert");

                        match client.find_or_create_convo_for_did(&target_did).await {
                            Ok(convo_id) => {
                                if let Err(e) = send_dm_chunked(&client, &convo_id, &alert_text).await {
                                    warn!(error = %e, target = %target_did, "Failed to send proactive DM storm alert");
                                } else {
                                    info!(target = %target_did, focal = %notification.storm.focal_post_uri, "Proactive DM storm alert delivered successfully");
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, target = %target_did, "Could not locate chat conversation to deliver proactive DM storm alert");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        warn!(missed = missed, "Storm alert dispatcher lagged behind event stream");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("Storm notification channel closed; terminating alert dispatcher");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Runs the proactive Storm Mode digest dispatcher worker until `cancel` is triggered.
///
/// # Errors
/// Returns [`SkybouncerError`] if unrecoverable initialization error occurs.
pub async fn run_storm_digest_dispatcher(
    client: ChatClient,
    mut digest_rx: tokio::sync::broadcast::Receiver<StormDigestNotification>,
    cancel: CancellationToken,
) -> Result<(), SkybouncerError> {
    info!("Starting proactive ATProto DM Storm Mode digest dispatcher worker");

    while !cancel.is_cancelled() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("Storm digest dispatcher received cancellation; shutting down");
                break;
            }
            received = digest_rx.recv() => {
                match received {
                    Ok(digest) => {
                        let target_did = digest.target_did.clone();
                        let digest_text = format_storm_digest(&digest);

                        debug!(target = %target_did, count = digest.bounced_count, "Dispatching proactive DM Storm Mode digest");

                        match client.find_or_create_convo_for_did(&target_did).await {
                            Ok(convo_id) => {
                                if let Err(e) = send_dm_chunked(&client, &convo_id, &digest_text).await {
                                    warn!(error = %e, target = %target_did, "Failed to send Storm Mode digest DM");
                                } else {
                                    info!(target = %target_did, count = digest.bounced_count, "Storm Mode digest DM delivered successfully");
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, target = %target_did, "Could not locate chat conversation to deliver Storm Mode digest DM");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        warn!(missed = missed, "Storm digest dispatcher lagged behind event stream");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("Storm digest channel closed; terminating dispatcher");
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

        let reminder_1 =
            format_reauth_alert_with_count(&notif, "https://skybouncer.mike10010100.com/", 1);
        assert!(reminder_1.contains("Weekly Reminder (1/2)"));
        assert!(reminder_1.contains("Reply `pause` if you want to stop these reminders."));

        let reminder_2 =
            format_reauth_alert_with_count(&notif, "https://skybouncer.mike10010100.com/", 2);
        assert!(reminder_2.contains("Final Reminder (2/2)"));
        assert!(reminder_2.contains("final automatic reminder"));
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
            reply_to_uri: None,
            post_snippet: "Free tokens".to_string(),
            bounce_duration: crate::classifier::BounceDuration::Permanent,
        };
        let perm_text = format_bounce_alert(&perm_notif);
        assert!(perm_text.contains("Profile: https://bsky.app/profile/spammer.bsky.social"));
        assert!(perm_text.contains("Post: https://bsky.app/profile/did:plc:spammer/post/123"));
        assert!(!perm_text.contains("Replying to:"));
        assert!(perm_text.contains("pardon spammer.bsky.social"));
        assert!(perm_text.contains("pardon and allow spammer.bsky.social"));
        assert!(!perm_text.contains("perm spammer.bsky.social"));
        assert!(!perm_text.contains("Duration:"));

        let temp_reply_notif = BounceNotification {
            reply_to_uri: Some("at://did:plc:alice/app.bsky.feed.post/root999".to_string()),
            bounce_duration: crate::classifier::BounceDuration::Cooldown24h,
            ..perm_notif
        };
        let temp_text = format_bounce_alert(&temp_reply_notif);
        assert!(temp_text.contains("Duration: 24-Hour Cooldown"));
        assert!(temp_text.contains(
            "Post: https://bsky.app/profile/did:plc:spammer/post/123\n\
             Replying to: https://bsky.app/profile/did:plc:alice/post/root999"
        ));
        assert!(temp_text.contains("pardon spammer.bsky.social"));
        assert!(temp_text.contains("pardon and allow spammer.bsky.social"));
        assert!(temp_text.contains(
            "Or to upgrade this temporary block to permanent:\nperm spammer.bsky.social"
        ));

        let facets = skybase::lexicon::extract_link_facets(&temp_text);
        assert_eq!(facets.len(), 3);
        let uris: Vec<&str> = facets
            .iter()
            .filter_map(|f| match f.features.first() {
                Some(skybase::lexicon::FacetFeature::Link { uri }) => Some(uri.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            uris,
            vec![
                "https://bsky.app/profile/spammer.bsky.social",
                "https://bsky.app/profile/did:plc:spammer/post/123",
                "https://bsky.app/profile/did:plc:alice/post/root999",
            ]
        );
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

    #[test]
    fn test_format_storm_alert_and_digest_with_link_facets() {
        let mut storm = crate::dogpile::StormEvent {
            id: 7,
            target_did: "did:plc:alice".to_string(),
            target_handle: Some("alice.bsky.social".to_string()),
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3kpost".to_string(),
            focal_post_snippet: "Hot take about widgets".to_string(),
            status: crate::dogpile::StormStatus::Active,
            severity: crate::dogpile::StormSeverity::High,
            started_at_us: 1_000_000,
            updated_at_us: 2_000_000,
            resolved_at_us: None,
            metrics: crate::dogpile::StormMetrics {
                unique_authors_short: 32,
                unique_oon_authors_short: 29,
                out_of_network_ratio: 0.906,
                direct_ratio: 6.5,
                dunk_ratio: 18.2,
                power_asymmetry: 120.0,
                burst_z_score: 7.4,
                defensive_blocks: 3,
                defensive_detaches: 1,
                composite_score: 0.84,
                ..Default::default()
            },
            top_catalyst: Some(crate::dogpile::CatalystInfo {
                post_uri: "at://did:plc:bigacct/app.bsky.feed.post/3kqt".to_string(),
                author_did: "did:plc:bigacct".to_string(),
                author_handle: Some("bigacct.bsky.social".to_string()),
                author_followers: Some(95_000),
                like_count: 1820,
                repost_count: 240,
                quote_count: 42,
                dunk_ratio: 18.2,
                text_snippet: "Look at this take lol".to_string(),
            }),
            catalyst_qt_uris: vec!["at://did:plc:bigacct/app.bsky.feed.post/3kqt".to_string()],
            stance: Some(crate::dogpile::StormStanceVerdict::new(
                true,
                0.91,
                "dogpile",
                "Coordinated hostile mockery from quote-post audience",
                "qwen3.5:9b",
            )),
            bounces_during_storm: 4,
            threadgate_applied: false,
            postgate_detaches_applied: 0,
        };

        let notif = StormNotification {
            storm: storm.clone(),
            is_escalation: false,
        };
        let text = format_storm_alert(&notif);
        assert!(text.contains("Dogpile Alert [HIGH]"));
        assert!(text.contains("https://bsky.app/profile/did:plc:alice/post/3kpost"));
        assert!(text.contains("@bigacct.bsky.social"));
        assert!(text.contains("https://bsky.app/profile/did:plc:bigacct/post/3kqt"));
        assert!(text.contains("Defensive signals: 3 blocks, 1 postgate detaches"));
        assert!(text.contains("lock 3kpost following"));
        assert!(text.contains("detach 3kpost"));
        assert_eq!(skybase::lexicon::extract_link_facets(&text).len(), 2);

        storm.focal_post_uri = "at://did:plc:alice/app.bsky.feed.post/_mentions".to_string();
        storm.severity = crate::dogpile::StormSeverity::Critical;
        let esc_text = format_storm_alert(&StormNotification {
            storm,
            is_escalation: true,
        });
        assert!(esc_text.contains("Storm Escalation [CRITICAL]"));
        assert!(esc_text.contains("lock <post_url|rkey> following"));

        let digest_active = format_storm_digest(&StormDigestNotification {
            target_did: "did:plc:alice".to_string(),
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3kpost".to_string(),
            bounced_count: 5,
            sample_violators: vec![crate::dogpile::DigestBounceSummary {
                violator_did: "did:plc:troll1".to_string(),
                violator_handle: Some("troll1.bsky.social".to_string()),
                category: "harassment".to_string(),
            }],
            window_secs: 300,
            storm_still_active: true,
        });
        assert!(digest_active.contains("Bounced during window: **5** account(s)"));
        assert!(digest_active.contains("… and 4 more account(s)"));
        assert!(digest_active.contains("Storm Mode remains active"));

        let digest_done = format_storm_digest(&StormDigestNotification {
            target_did: "did:plc:alice".to_string(),
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/_mentions".to_string(),
            bounced_count: 1,
            sample_violators: vec![],
            window_secs: 300,
            storm_still_active: false,
        });
        assert!(digest_done.contains("Recent @mentions surge"));
        assert!(digest_done.contains("automatically deactivated"));

        // Minimal alert without catalyst, stance, defensive signals, or snippet
        let minimal_alert = format_storm_alert(&StormNotification {
            storm: crate::dogpile::StormEvent {
                id: 9,
                target_did: "did:plc:alice".to_string(),
                target_handle: None,
                focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3min".to_string(),
                focal_post_snippet: String::new(),
                status: crate::dogpile::StormStatus::Active,
                severity: crate::dogpile::StormSeverity::Elevated,
                started_at_us: 1,
                updated_at_us: 1,
                resolved_at_us: None,
                metrics: crate::dogpile::StormMetrics::default(),
                top_catalyst: None,
                catalyst_qt_uris: vec![],
                stance: None,
                bounces_during_storm: 0,
                threadgate_applied: false,
                postgate_detaches_applied: 0,
            },
            is_escalation: false,
        });
        assert!(!minimal_alert.contains("Catalyst QT"));
        assert!(!minimal_alert.contains("Stance Check"));
    }

    #[tokio::test]
    async fn test_run_storm_alert_and_digest_dispatchers_deliver_and_exit() {
        let mock_chat = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getConvoForMembers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "convo": {
                    "id": "convo-storm-1",
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
                "id": "msg-storm-1",
                "rev": "2",
                "text": "ok",
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-11-20T00:00:00Z"
            })))
            .expect(2)
            .mount(&mock_chat)
            .await;

        let chat_client = ChatClient::new(mock_chat.uri(), "bot-token").unwrap();
        let (storm_tx, storm_rx) = tokio::sync::broadcast::channel(8);
        let (digest_tx, digest_rx) = tokio::sync::broadcast::channel(8);
        let cancel_a = CancellationToken::new();
        let cancel_d = CancellationToken::new();

        let _ = storm_tx.send(StormNotification {
            storm: crate::dogpile::StormEvent {
                id: 1,
                target_did: "did:plc:alice".to_string(),
                target_handle: None,
                focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3k1".to_string(),
                focal_post_snippet: "post".to_string(),
                status: crate::dogpile::StormStatus::Active,
                severity: crate::dogpile::StormSeverity::Elevated,
                started_at_us: 1,
                updated_at_us: 1,
                resolved_at_us: None,
                metrics: crate::dogpile::StormMetrics::default(),
                top_catalyst: None,
                catalyst_qt_uris: vec![],
                stance: None,
                bounces_during_storm: 0,
                threadgate_applied: false,
                postgate_detaches_applied: 0,
            },
            is_escalation: false,
        });
        drop(storm_tx);

        let _ = digest_tx.send(StormDigestNotification {
            target_did: "did:plc:alice".to_string(),
            focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/3k1".to_string(),
            bounced_count: 2,
            sample_violators: vec![],
            window_secs: 300,
            storm_still_active: true,
        });
        drop(digest_tx);

        run_storm_alert_dispatcher(chat_client.clone(), storm_rx, cancel_a)
            .await
            .unwrap();
        run_storm_digest_dispatcher(chat_client, digest_rx, cancel_d)
            .await
            .unwrap();

        // Also cover error + cancel + lagged branches cleanly
        let err_chat = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/chat.bsky.convo.getConvoForMembers"))
            .respond_with(ResponseTemplate::new(500).set_body_string("chat down"))
            .mount(&err_chat)
            .await;
        let err_client = ChatClient::new(err_chat.uri(), "tok").unwrap();
        let (s_tx2, s_rx2) = tokio::sync::broadcast::channel(1);
        let c_a2 = CancellationToken::new();
        // Fill capacity=1 then send a second to trigger RecvError::Lagged on first recv
        for id in [10, 11] {
            let _ = s_tx2.send(StormNotification {
                storm: crate::dogpile::StormEvent {
                    id,
                    target_did: "did:plc:alice".to_string(),
                    target_handle: None,
                    focal_post_uri: "at://did:plc:alice/app.bsky.feed.post/_mentions".to_string(),
                    focal_post_snippet: String::new(),
                    status: crate::dogpile::StormStatus::Active,
                    severity: crate::dogpile::StormSeverity::Elevated,
                    started_at_us: 1,
                    updated_at_us: 1,
                    resolved_at_us: None,
                    metrics: crate::dogpile::StormMetrics::default(),
                    top_catalyst: None,
                    catalyst_qt_uris: vec![],
                    stance: None,
                    bounces_during_storm: 0,
                    threadgate_applied: false,
                    postgate_detaches_applied: 0,
                },
                is_escalation: false,
            });
        }
        let c_a2_clone = c_a2.clone();
        let h_a2 = tokio::spawn(async move {
            run_storm_alert_dispatcher(err_client.clone(), s_rx2, c_a2_clone).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        c_a2.cancel();
        h_a2.await.unwrap().unwrap();
    }
}
