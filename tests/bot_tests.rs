//! Comprehensive Test Suite for the ATProto DM Bot Interface (`chat.bsky.convo.*`).
//!
//! Validates:
//! - `ChatClient` XRPC client operations, authorization headers, and error handling.
//! - `BotCommandHandler` command parsing (`help`, `rules`, `set rules`, `sensitivity`, `recent`, `pardon`, `status`, `test`).
//! - `run_bot_poller` background polling worker, automated dispatch, self-message filtering, and graceful cancellation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybouncer::bot::{run_bot_poller, BotCommandHandler, ChatClient};
use skybouncer::classifier::{RuleRubric, Sensitivity, Verdict};
use skybouncer::engine::{SkybouncerConfig, SkybouncerEngine};
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{BouncedUser, DeduplicationCache, ModListManager};

// =============================================================================
// Test Harness Helpers
// =============================================================================

async fn setup_test_engine(
    protected_did: &str,
) -> (
    Arc<SkybouncerEngine>,
    Arc<DeduplicationCache>,
    MockPdsServer,
) {
    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("in-memory cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));

    let rubric = RuleRubric::new("Block toxicity and crypto spam", Sensitivity::Medium);
    let modlist_manager =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client(protected_did));
    let classifier = Arc::new(skybouncer::classifier::MockClassifier::new(
        Verdict::Permitted {
            reason: "Default test verdict".to_string(),
        },
    ));

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected_did.to_string());
    let config =
        SkybouncerConfig::new(protected_dids, rubric).with_enable_heuristic_prefilter(true);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    ));

    (engine, cache, pds)
}

// =============================================================================
// ChatClient Unit & Mock XRPC Tests
// =============================================================================

#[tokio::test]
async fn test_chat_client_list_convos_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvos"))
        .respond_with(|req: &wiremock::Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(auth, "Bearer test_chat_token");

            let query = req.url.query().unwrap_or_default();
            assert!(query.contains("limit=10"));
            assert!(query.contains("cursor=cur123"));

            ResponseTemplate::new(200).set_body_json(json!({
                "convos": [
                    {
                        "id": "convo_1",
                        "rev": "rev_1",
                        "unreadCount": 1,
                        "members": [
                            { "did": "did:plc:user1" },
                            { "did": "did:plc:bot" }
                        ],
                        "lastMessage": {
                            "id": "msg_1",
                            "rev": "rev_1",
                            "text": "help",
                            "sender": { "did": "did:plc:user1" },
                            "sentAt": "2026-10-02T00:00:00Z"
                        }
                    }
                ],
                "cursor": "cur456"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "test_chat_token").expect("client creation");
    let resp = client
        .list_convos(Some(10), Some("cur123"))
        .await
        .expect("list_convos");

    assert_eq!(resp.convos.len(), 1);
    assert_eq!(resp.convos[0].id, "convo_1");
    assert_eq!(resp.convos[0].unread_count, 1);
    assert_eq!(resp.cursor, Some("cur456".to_string()));
}

#[tokio::test]
async fn test_chat_client_list_convos_error_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvos"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "AuthenticationRequired",
            "message": "Invalid token"
        })))
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "bad_token").expect("client creation");
    let err = client
        .list_convos(None, None)
        .await
        .expect_err("should fail with 401");
    assert!(err
        .to_string()
        .contains("listConvos failed with status 401"));
}

#[tokio::test]
async fn test_chat_client_get_messages_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.getMessages"))
        .respond_with(|req: &wiremock::Request| {
            let query = req.url.query().unwrap_or_default();
            assert!(query.contains("convoId=convo_xyz"));
            assert!(query.contains("limit=5"));

            ResponseTemplate::new(200).set_body_json(json!({
                "messages": [
                    {
                        "id": "msg_abc",
                        "rev": "rev_abc",
                        "text": "status",
                        "sender": { "did": "did:plc:sender" },
                        "sentAt": "2026-10-02T01:00:00Z"
                    }
                ],
                "cursor": null
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client creation");
    let resp = client
        .get_messages("convo_xyz", Some(5), None)
        .await
        .expect("get_messages");

    assert_eq!(resp.messages.len(), 1);
    assert_eq!(resp.messages[0].id, "msg_abc");
    assert_eq!(resp.messages[0].text, "status");
}

#[tokio::test]
async fn test_chat_client_send_message_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_target");
            assert_eq!(body["message"]["text"], "Bot reply test");

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_new_123",
                "rev": "rev_new_123",
                "text": "Bot reply test",
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-10-02T02:00:00Z"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client");
    let msg = client
        .send_message("convo_target", "Bot reply test")
        .await
        .expect("send_message");

    assert_eq!(msg.id, "msg_new_123");
    assert_eq!(msg.text, "Bot reply test");
}

#[tokio::test]
async fn test_chat_client_send_message_failure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "InvalidRequest",
            "message": "Message text exceeds limit"
        })))
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client");
    let err = client
        .send_message("convo_target", "Too long text")
        .await
        .expect_err("should fail");
    assert!(err
        .to_string()
        .contains("sendMessage failed with status 400"));
}

#[tokio::test]
async fn test_chat_client_update_read_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.updateRead"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_999");
            assert_eq!(body["messageId"], "msg_888");

            ResponseTemplate::new(200).set_body_json(json!({}))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client");
    client
        .update_read("convo_999", "msg_888")
        .await
        .expect("update_read");
}

// =============================================================================
// BotCommandHandler Command Tests
// =============================================================================

#[tokio::test]
async fn test_command_handler_help_and_empty() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    // Empty input returns prompt to type help
    let reply_empty = handler
        .handle_command("did:plc:user", "   ")
        .await
        .expect("handle");
    assert!(reply_empty.contains("Type `help` to see available Skybouncer commands"));

    // Help command
    let reply_help = handler
        .handle_command("did:plc:user", "help")
        .await
        .expect("handle");
    assert!(reply_help.contains("Skybouncer Bot Commands:"));
    assert!(reply_help.contains("• `rules`"));
    assert!(reply_help.contains("• `set rules <prompt>`"));
    assert!(reply_help.contains("• `pause`"));
    assert!(reply_help.contains("• `resume`"));
    assert!(reply_help.contains("• `pardon <did|@handle>`"));

    // Question mark alias
    let reply_q = handler
        .handle_command("did:plc:user", "?")
        .await
        .expect("handle");
    assert_eq!(reply_q, reply_help);
}

#[tokio::test]
async fn test_command_handler_rules_and_set_rules() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    // View default rules
    let reply_rules = handler
        .handle_command("did:plc:user", "rules")
        .await
        .expect("handle");
    assert!(reply_rules.contains("Current Moderation Rubric:"));
    assert!(reply_rules.contains("Block toxicity and crypto spam"));
    assert!(reply_rules.contains("Sensitivity: medium"));

    // Set new rules
    let reply_set = handler
        .handle_command(
            "did:plc:user",
            "set rules Block NFTs, airdrops, and harassment",
        )
        .await
        .expect("handle");
    assert!(reply_set.contains("Moderation rubric updated successfully!"));
    assert!(reply_set.contains("Block NFTs, airdrops, and harassment"));

    // Set rules with empty prompt
    let reply_empty_set = handler
        .handle_command("did:plc:user", "set rules   ")
        .await
        .expect("handle");
    assert!(reply_empty_set.contains("Please provide a moderation prompt"));
}

#[tokio::test]
async fn test_command_handler_sensitivity() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    let reply_low = handler
        .handle_command("did:plc:user", "sensitivity low")
        .await
        .expect("handle");
    assert!(reply_low.contains("Sensitivity threshold updated to **low** (confidence: 0.90)"));

    let reply_high = handler
        .handle_command("did:plc:user", "sensitivity high")
        .await
        .expect("handle");
    assert!(reply_high.contains("Sensitivity threshold updated to **high** (confidence: 0.60)"));

    let reply_invalid = handler
        .handle_command("did:plc:user", "sensitivity extreme")
        .await
        .expect("handle");
    assert!(reply_invalid.contains("Invalid sensitivity level"));

    let reply_no_arg = handler
        .handle_command("did:plc:user", "sensitivity")
        .await
        .expect("handle");
    assert!(reply_no_arg.contains("Usage: `sensitivity <low|medium|high>`"));
}

#[tokio::test]
async fn test_command_handler_recent_and_pardon() {
    let (engine, cache, pds) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    // Initially empty recent list
    let reply_empty = handler
        .handle_command("did:plc:user", "recent")
        .await
        .expect("handle");
    assert!(reply_empty.contains("No accounts have been bounced yet"));

    // Populate bounced user in cache
    cache
        .record_bounce(&BouncedUser {
            subject_did: "did:plc:spammer1".to_string(),
            listitem_uri: "at://did:plc:protected1/app.bsky.graph.listitem/item1".to_string(),
            listitem_rkey: "item1".to_string(),
            listitem_cid: "bafyitem1cid".to_string(),
            category: "spam".to_string(),
            confidence: 0.96,
            reason: "Detected crypto scam keyword".to_string(),
            post_uri: "at://did:plc:spammer1/app.bsky.feed.post/post1".to_string(),
            bounced_at: 1_700_000_000,
        })
        .expect("record bounce");

    // Check recent list has entry
    let reply_recent = handler
        .handle_command("did:plc:user", "recent")
        .await
        .expect("handle");
    assert!(reply_recent.contains("Recently Bounced Accounts (last 5):"));
    assert!(reply_recent.contains("did:plc:spammer1"));
    assert!(reply_recent.contains("96% confidence"));
    assert!(reply_recent.contains("Detected crypto scam keyword"));

    // Pardon an account that is not present
    let reply_pardon_miss = handler
        .handle_command("did:plc:user", "pardon did:plc:unknown")
        .await
        .expect("handle");
    assert!(reply_pardon_miss.contains("was not found in your bounced list"));

    // Pardon the bounced account (PDS deleteRecord succeeds on mock)
    let reply_pardon = handler
        .handle_command("did:plc:protected1", "pardon did:plc:spammer1")
        .await
        .expect("handle");
    assert!(reply_pardon.contains("has been pardoned and removed from your moderation list"));
    assert_eq!(pds.deleted_records.lock().len(), 1);

    // Verify cache was cleared
    assert!(cache
        .get_bounced_user("did:plc:spammer1")
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_command_handler_status_and_test() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    // Status output
    let reply_status = handler
        .handle_command("did:plc:user", "status")
        .await
        .expect("handle");
    assert!(reply_status.contains("Skybouncer Engine Status:"));
    assert!(reply_status.contains("Commits Received: 0"));
    assert!(reply_status.contains("Violations Detected: 0"));

    // Test command: heuristic matches "crypto scam"
    let reply_test_violation = handler
        .handle_command(
            "did:plc:user",
            "test Check out this free airdrop crypto scam!",
        )
        .await
        .expect("handle");
    assert!(reply_test_violation.contains("Test Evaluation: **VIOLATION**"));
    assert!(reply_test_violation.contains("Category: **crypto_spam**"));

    // Test command: polite message
    let reply_test_clean = handler
        .handle_command("did:plc:user", "test Hello, having a nice day!")
        .await
        .expect("handle");
    assert!(reply_test_clean.contains("Test Evaluation: **PERMITTED**"));

    // Unknown command
    let reply_unknown = handler
        .handle_command("did:plc:user", "launch missiles")
        .await
        .expect("handle");
    assert!(reply_unknown.contains("Unknown command: `launch missiles`"));
}

// =============================================================================
// run_bot_poller Lifecycle & Polling Tests
// =============================================================================

#[tokio::test]
async fn test_run_bot_poller_processes_dm_and_replies() {
    let server = MockServer::start().await;
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let bot_did = "did:plc:skybouncer-bot";
    let handler = BotCommandHandler::new(engine, bot_did);

    let list_called = Arc::new(AtomicUsize::new(0));
    let send_called = Arc::new(AtomicUsize::new(0));
    let read_called = Arc::new(AtomicUsize::new(0));

    let lc = Arc::clone(&list_called);
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvos"))
        .respond_with(move |_: &wiremock::Request| {
            let count = lc.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                // First poll: return unread conversation with "rules" command
                ResponseTemplate::new(200).set_body_json(json!({
                    "convos": [
                        {
                            "id": "convo_test_1",
                            "rev": "rev_1",
                            "unreadCount": 1,
                            "members": [
                                { "did": "did:plc:user_asker" },
                                { "did": "did:plc:skybouncer-bot" }
                            ],
                            "lastMessage": {
                                "id": "msg_cmd_1",
                                "rev": "rev_1",
                                "text": "rules",
                                "sender": { "did": "did:plc:user_asker" },
                                "sentAt": "2026-10-02T03:00:00Z"
                            }
                        }
                    ],
                    "cursor": null
                }))
            } else {
                // Subsequent polls: no unread messages
                ResponseTemplate::new(200).set_body_json(json!({
                    "convos": [
                        {
                            "id": "convo_test_1",
                            "rev": "rev_2",
                            "unreadCount": 0,
                            "members": [
                                { "did": "did:plc:user_asker" },
                                { "did": "did:plc:skybouncer-bot" }
                            ],
                            "lastMessage": None::<serde_json::Value>
                        }
                    ],
                    "cursor": null
                }))
            }
        })
        .mount(&server)
        .await;

    let sc = Arc::clone(&send_called);
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(move |req: &wiremock::Request| {
            sc.fetch_add(1, Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_test_1");
            let text = body["message"]["text"].as_str().unwrap_or_default();
            assert!(text.contains("Current Moderation Rubric:"));

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_reply_1",
                "rev": "rev_reply_1",
                "text": text,
                "sender": { "did": "did:plc:skybouncer-bot" },
                "sentAt": "2026-10-02T03:00:01Z"
            }))
        })
        .mount(&server)
        .await;

    let rc = Arc::clone(&read_called);
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.updateRead"))
        .respond_with(move |req: &wiremock::Request| {
            rc.fetch_add(1, Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_test_1");
            assert_eq!(body["messageId"], "msg_cmd_1");
            ResponseTemplate::new(200).set_body_json(json!({}))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "test_token").expect("client");
    let cancel = CancellationToken::new();
    let cancel_poller = cancel.clone();

    let poller_task = tokio::spawn(async move {
        run_bot_poller(client, handler, Duration::from_millis(20), cancel_poller).await
    });

    // Allow poller to run a tick
    tokio::time::sleep(Duration::from_millis(80)).await;
    cancel.cancel();

    let res = tokio::time::timeout(Duration::from_millis(500), poller_task)
        .await
        .expect("poller shutdown within timeout")
        .expect("join task");

    assert!(res.is_ok());
    assert!(send_called.load(Ordering::SeqCst) >= 1);
    assert!(read_called.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn test_run_bot_poller_filters_self_authored_messages() {
    let server = MockServer::start().await;
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let bot_did = "did:plc:skybouncer-bot";
    let handler = BotCommandHandler::new(engine, bot_did);

    let send_called = Arc::new(AtomicUsize::new(0));

    // Conversation where last message was sent by the bot itself
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvos"))
        .respond_with(|_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(json!({
                "convos": [
                    {
                        "id": "convo_self",
                        "rev": "rev_1",
                        "unreadCount": 1,
                        "members": [
                            { "did": "did:plc:user1" },
                            { "did": "did:plc:skybouncer-bot" }
                        ],
                        "lastMessage": {
                            "id": "msg_self_1",
                            "rev": "rev_1",
                            "text": "Existing bot reply",
                            "sender": { "did": "did:plc:skybouncer-bot" },
                            "sentAt": "2026-10-02T03:00:00Z"
                        }
                    }
                ],
                "cursor": null
            }))
        })
        .mount(&server)
        .await;

    let sc = Arc::clone(&send_called);
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(move |_: &wiremock::Request| {
            sc.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({}))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client");
    let cancel = CancellationToken::new();
    let cancel_poller = cancel.clone();

    let poller_task = tokio::spawn(async move {
        run_bot_poller(client, handler, Duration::from_millis(20), cancel_poller).await
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
    cancel.cancel();

    let res = poller_task.await.expect("join");
    assert!(res.is_ok());

    // Should NOT have sent any message in response to its own message
    assert_eq!(send_called.load(Ordering::SeqCst), 0);
}

// =============================================================================
// Pause, Resume, Handle Resolution, & Proactive Alert Dispatcher Tests
// =============================================================================

#[tokio::test]
async fn test_command_handler_pause_and_resume() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(Arc::clone(&engine), "did:plc:bot");

    assert!(!engine.is_paused());

    // 1. Send pause command
    let reply_pause = handler
        .handle_command("did:plc:user", "pause")
        .await
        .expect("handle");
    assert!(reply_pause.contains("Skybouncer has been **paused**"));
    assert!(engine.is_paused());

    // 2. Status shows paused state
    let reply_status = handler
        .handle_command("did:plc:user", "status")
        .await
        .expect("handle");
    assert!(reply_status.contains("State: ⏸️ PAUSED"));

    // 3. Process an interaction candidate while paused -> returns Paused
    let commit = make_reply_commit(
        "did:plc:spammer_paused",
        "did:plc:protected1",
        "rep_p1",
        "root_1",
        "Check out this free crypto scam airdrop!",
    );
    let result = engine.process_commit(&commit).await.expect("process");
    let outcomes = result.into_outcomes();
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].is_paused());
    assert!(matches!(
        outcomes[0],
        skybouncer::engine::InteractionOutcome::Paused { .. }
    ));

    // 4. Send resume command
    let reply_resume = handler
        .handle_command("did:plc:user", "resume")
        .await
        .expect("handle");
    assert!(reply_resume.contains("Skybouncer has been **resumed**"));
    assert!(!engine.is_paused());

    // 5. Status shows active state
    let reply_status_active = handler
        .handle_command("did:plc:user", "status")
        .await
        .expect("handle");
    assert!(reply_status_active.contains("State: ▶️ ACTIVE"));

    // 6. Process interaction now -> evaluated and bounced (matches heuristic)
    let commit_resumed = make_reply_commit(
        "did:plc:spammer_resumed",
        "did:plc:protected1",
        "rep_p2",
        "root_1",
        "Check out this free crypto scam airdrop!",
    );
    let result_resumed = engine
        .process_commit(&commit_resumed)
        .await
        .expect("process");
    let outcomes_resumed = result_resumed.into_outcomes();
    assert_eq!(outcomes_resumed.len(), 1);
    assert!(outcomes_resumed[0].is_bounced());
}

#[tokio::test]
async fn test_command_handler_pardon_with_handle_resolution() {
    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("cache"));
    let rubric = RuleRubric::new("Block toxicity", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client("did:plc:protected1"));
    let enricher = Arc::new(skybouncer::enricher::MockContextEnricher::new());
    enricher.set_handle("alice.bsky.social", "did:plc:alice123");

    let mut protected_dids = HashSet::new();
    protected_dids.insert("did:plc:protected1".to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric);

    let engine = Arc::new(
        SkybouncerEngine::builder(config)
            .with_cache(cache.clone())
            .with_modlist_manager(modlist)
            .with_pds_client(pds_client)
            .with_enricher(enricher)
            .with_classifier(Arc::new(skybouncer::classifier::MockClassifier::new(
                Verdict::Permitted {
                    reason: "ok".into(),
                },
            )))
            .build()
            .expect("engine build"),
    );

    let handler = BotCommandHandler::new(Arc::clone(&engine), "did:plc:bot");

    // Pre-populate Alice as bounced
    cache
        .record_bounce(&BouncedUser {
            subject_did: "did:plc:alice123".to_string(),
            listitem_uri: "at://did:plc:protected1/app.bsky.graph.listitem/item_alice".to_string(),
            listitem_rkey: "item_alice".to_string(),
            listitem_cid: "bafyalice".to_string(),
            category: "spam".to_string(),
            confidence: 0.95,
            reason: "spam".to_string(),
            post_uri: "at://did:plc:alice123/post/1".to_string(),
            bounced_at: 1_700_000_000,
        })
        .expect("record");

    // Pardon via handle with leading '@'
    let reply = handler
        .handle_command("did:plc:protected1", "pardon @alice.bsky.social")
        .await
        .expect("handle");
    assert!(reply.contains("Resolved `@alice.bsky.social` to `did:plc:alice123`"));
    assert!(reply.contains("Account `did:plc:alice123` has been pardoned"));
    assert_eq!(pds.deleted_records.lock().len(), 1);
    assert!(cache
        .get_bounced_user("did:plc:alice123")
        .unwrap()
        .is_none());

    // Try unresolvable handle
    let reply_unknown = handler
        .handle_command("did:plc:protected1", "pardon @ghost.unknown.domain")
        .await
        .expect("handle");
    assert!(reply_unknown.contains("Could not resolve handle `@ghost.unknown.domain` to a DID"));
}

#[tokio::test]
async fn test_chat_client_get_convo_for_members_and_find_or_create() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.getConvoForMembers"))
        .respond_with(|req: &wiremock::Request| {
            let query = req.url.query().unwrap_or_default();
            assert!(query.contains("members=did:plc:user42"));
            ResponseTemplate::new(200).set_body_json(json!({
                "convo": {
                    "id": "convo_user42",
                    "rev": "rev_42",
                    "unreadCount": 0,
                    "members": [
                        { "did": "did:plc:user42" },
                        { "did": "did:plc:bot" }
                    ]
                }
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client");
    let convo = client
        .get_convo_for_members(&["did:plc:user42"])
        .await
        .expect("get_convo");
    assert_eq!(convo.id, "convo_user42");

    let convo_id = client
        .find_or_create_convo_for_did("did:plc:user42")
        .await
        .expect("find_or_create");
    assert_eq!(convo_id, "convo_user42");
}

#[tokio::test]
async fn test_run_bounce_alert_dispatcher() {
    let server = MockServer::start().await;
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;

    let send_called = Arc::new(AtomicUsize::new(0));
    let last_sent_body = Arc::new(parking_lot::Mutex::new(String::new()));

    // Mock getConvoForMembers
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.getConvoForMembers"))
        .respond_with(|_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(json!({
                "convo": {
                    "id": "convo_alert_target",
                    "rev": "rev_alert",
                    "unreadCount": 0,
                    "members": [
                        { "did": "did:plc:protected1" },
                        { "did": "did:plc:bot" }
                    ]
                }
            }))
        })
        .mount(&server)
        .await;

    // Mock sendMessage
    let sc = Arc::clone(&send_called);
    let lsb = Arc::clone(&last_sent_body);
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(move |req: &wiremock::Request| {
            sc.fetch_add(1, Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let text = body["message"]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            *lsb.lock() = text;
            ResponseTemplate::new(200).set_body_json(json!({
                "id": "alert_msg_1",
                "rev": "rev_1",
                "text": "alert text",
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-10-02T12:00:00Z"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client");
    let bounce_rx = engine.subscribe_bounces();
    let cancel = CancellationToken::new();
    let cancel_disp = cancel.clone();

    let disp_task = tokio::spawn(async move {
        skybouncer::bot::run_bounce_alert_dispatcher(client, bounce_rx, cancel_disp).await
    });

    // Cause a bounce in the engine!
    let commit = make_reply_commit(
        "did:plc:bad_actor",
        "did:plc:protected1",
        "rep_alert_1",
        "root_1",
        "Check out this free crypto scam airdrop!",
    );
    let result = engine.process_commit(&commit).await.expect("process");
    let outcomes = result.into_outcomes();
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].is_bounced());

    // Give dispatcher task a moment to process the broadcast event and send DM
    tokio::time::sleep(Duration::from_millis(80)).await;
    cancel.cancel();

    let res = disp_task.await.expect("join");
    assert!(res.is_ok());

    assert_eq!(send_called.load(Ordering::SeqCst), 1);
    let sent_text = last_sent_body.lock().clone();
    assert!(sent_text.contains("🛡️ Skybouncer Action Alert:"));
    assert!(sent_text.contains("Bounced violator: `did:plc:bad_actor`"));
    assert!(sent_text.contains("Violation: **crypto_spam**"));
    assert!(sent_text.contains("pardon did:plc:bad_actor"));
}
