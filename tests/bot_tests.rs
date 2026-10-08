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
        Verdict::permitted("Default test verdict"),
    ));

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected_did.to_string());
    let config = SkybouncerConfig::new(protected_dids, rubric)
        .with_enable_heuristic_prefilter(true)
        .with_admin_did("did:plc:admin");

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
async fn test_chat_client_send_message_extracts_link_facet_with_exact_byte_offsets() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_facet_1");
            let text = body["message"]["text"].as_str().unwrap_or_default();
            let facets = body["message"]["facets"].as_array().expect("facets array");
            assert_eq!(facets.len(), 1);

            let facet = &facets[0];
            let byte_start = facet["index"]["byteStart"].as_u64().expect("byteStart") as usize;
            let byte_end = facet["index"]["byteEnd"].as_u64().expect("byteEnd") as usize;

            let sliced_str = &text[byte_start..byte_end];
            assert_eq!(sliced_str, "https://skybouncer.mike10010100.com/auth");

            let feature = &facet["features"][0];
            assert_eq!(feature["$type"], "app.bsky.richtext.facet#link");
            assert_eq!(feature["uri"], "https://skybouncer.mike10010100.com/auth");

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_facet_1",
                "rev": "rev_facet_1",
                "text": text,
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-10-04T12:00:00Z"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client creation");
    let text = "Please authorize here: https://skybouncer.mike10010100.com/auth to continue.";
    let msg = client
        .send_message("convo_facet_1", text)
        .await
        .expect("send_message");

    assert_eq!(msg.id, "msg_facet_1");
}

#[tokio::test]
async fn test_chat_client_send_message_multibyte_emoji_facet_offsets() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let text = body["message"]["text"].as_str().unwrap_or_default();
            let facets = body["message"]["facets"].as_array().expect("facets array");
            assert_eq!(facets.len(), 1);

            let facet = &facets[0];
            let byte_start = facet["index"]["byteStart"].as_u64().expect("byteStart") as usize;
            let byte_end = facet["index"]["byteEnd"].as_u64().expect("byteEnd") as usize;

            // Slicing by byte offsets must strictly yield the URL
            let sliced_str = &text[byte_start..byte_end];
            assert_eq!(sliced_str, "https://skybouncer.mike10010100.com/auth");

            // Ensure preceding UTF-8 multi-byte emoji offset is accurately represented (4 bytes per emoji)
            let char_index_before = text.find("https://").unwrap();
            assert_eq!(byte_start, char_index_before);

            let feature = &facet["features"][0];
            assert_eq!(feature["$type"], "app.bsky.richtext.facet#link");
            assert_eq!(feature["uri"], "https://skybouncer.mike10010100.com/auth");

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_emoji_1",
                "rev": "rev_emoji_1",
                "text": text,
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-10-04T12:00:00Z"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client creation");
    let text =
        "👋 Welcome to Skybouncer! 🛡️ Auth: https://skybouncer.mike10010100.com/auth ✨ Enjoy!";
    let msg = client
        .send_message("convo_emoji_target", text)
        .await
        .expect("send_message");

    assert_eq!(msg.id, "msg_emoji_1");
}

#[tokio::test]
async fn test_chat_client_send_message_multiple_links_and_trailing_punctuation() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let text = body["message"]["text"].as_str().unwrap_or_default();
            let facets = body["message"]["facets"].as_array().expect("facets array");
            assert_eq!(facets.len(), 2);

            // First facet: parenthesized with trailing dot "(https://alpha.example.com/login)."
            let f0_start = facets[0]["index"]["byteStart"].as_u64().unwrap() as usize;
            let f0_end = facets[0]["index"]["byteEnd"].as_u64().unwrap() as usize;
            let s0 = &text[f0_start..f0_end];
            assert_eq!(s0, "https://alpha.example.com/login");
            assert_eq!(
                facets[0]["features"][0]["uri"],
                "https://alpha.example.com/login"
            );

            // Second facet: with exclamation "https://beta.example.com/docs!"
            let f1_start = facets[1]["index"]["byteStart"].as_u64().unwrap() as usize;
            let f1_end = facets[1]["index"]["byteEnd"].as_u64().unwrap() as usize;
            let s1 = &text[f1_start..f1_end];
            assert_eq!(s1, "https://beta.example.com/docs");
            assert_eq!(
                facets[1]["features"][0]["uri"],
                "https://beta.example.com/docs"
            );

            // Strictly ascending order
            assert!(f0_end <= f1_start);

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_multi_1",
                "rev": "rev_multi_1",
                "text": text,
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-10-04T12:00:00Z"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client creation");
    let text = "Visit (https://alpha.example.com/login). Also see https://beta.example.com/docs!";
    let msg = client
        .send_message("convo_multi_target", text)
        .await
        .expect("send_message");

    assert_eq!(msg.id, "msg_multi_1");
}

#[tokio::test]
async fn test_chat_client_send_message_exotic_unicode_and_markdown_link_facets() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let text = body["message"]["text"].as_str().unwrap_or_default();
            let facets = body["message"]["facets"].as_array().expect("facets array");
            assert_eq!(facets.len(), 6);

            let expected_urls = [
                "https://skybouncer.mike10010100.com/bold",
                "https://skybouncer.mike10010100.com/quotes",
                "https://skybouncer.mike10010100.com/cjk",
                "https://skybouncer.mike10010100.com/adjacent",
                "https://skybouncer.mike10010100.com/cjk-continuous",
                "HTTPS://skybouncer.mike10010100.com/uppercase-trailing",
            ];

            for (i, expected_url) in expected_urls.iter().enumerate() {
                let facet = &facets[i];
                let byte_start = facet["index"]["byteStart"].as_u64().unwrap() as usize;
                let byte_end = facet["index"]["byteEnd"].as_u64().unwrap() as usize;
                let sliced = &text[byte_start..byte_end];
                assert_eq!(sliced, *expected_url, "mismatch at facet index {i}");
                assert_eq!(
                    facet["features"][0]["$type"],
                    "app.bsky.richtext.facet#link"
                );
                assert_eq!(facet["features"][0]["uri"], *expected_url);
            }

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_exotic_1",
                "rev": "rev_exotic_1",
                "text": text,
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-10-04T12:00:00Z"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client creation");
    let text = "Bold: **https://skybouncer.mike10010100.com/bold**, quotes: “https://skybouncer.mike10010100.com/quotes”, CJK: https://skybouncer.mike10010100.com/cjk。, and adjacent emoji: 🔗https://skybouncer.mike10010100.com/adjacent! Also: 请访问https://skybouncer.mike10010100.com/cjk-continuous进行授权 and 🚀HTTPS://skybouncer.mike10010100.com/uppercase-trailing🚀.";
    let msg = client
        .send_message("convo_exotic_target", text)
        .await
        .expect("send_message");

    assert_eq!(msg.id, "msg_exotic_1");
}

#[tokio::test]
async fn test_chat_client_send_message_ipv4_ipv6_and_heavy_unicode_facets() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let text = body["message"]["text"].as_str().unwrap_or_default();
            let facets = body["message"]["facets"].as_array().expect("facets array");
            assert_eq!(facets.len(), 3);

            let expected_urls = [
                "http://127.0.0.1:8080/auth",
                "http://[::1]:9090/v1/auth?step=2",
                "https://example.com/family",
            ];

            for (i, expected_url) in expected_urls.iter().enumerate() {
                let facet = &facets[i];
                let byte_start = facet["index"]["byteStart"].as_u64().unwrap() as usize;
                let byte_end = facet["index"]["byteEnd"].as_u64().unwrap() as usize;
                let sliced = &text[byte_start..byte_end];
                assert_eq!(sliced, *expected_url, "mismatch at facet index {i}");
                assert_eq!(
                    facet["features"][0]["$type"],
                    "app.bsky.richtext.facet#link"
                );
                assert_eq!(facet["features"][0]["uri"], *expected_url);
            }

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_heavy_1",
                "rev": "rev_heavy_1",
                "text": text,
                "sender": { "did": "did:plc:bot" },
                "sentAt": "2026-10-04T12:00:00Z"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client creation");
    let text = "IPv4: http://127.0.0.1:8080/auth, IPv6: http://[::1]:9090/v1/auth?step=2, and Family 👨‍👩‍👧‍👦: https://example.com/family!";
    let msg = client
        .send_message("convo_heavy_target", text)
        .await
        .expect("send_message");

    assert_eq!(msg.id, "msg_heavy_1");
}

#[tokio::test]
async fn test_onboarding_intro_formatting_and_facet_delivery() {
    let server = MockServer::start().await;
    let (engine, _, _) = setup_test_engine("did:plc:protected_onboard").await;
    let handler =
        BotCommandHandler::new(engine, "did:plc:skybouncer-bot").with_public_url(server.uri());

    let user_did = "did:plc:new-user-12345";
    let onboarding_text = handler
        .handle_command(user_did, "start")
        .await
        .expect("handle start");

    // R1 Verification: authorization URL is on its own dedicated line without adjacent emojis, brackets, or punctuation
    let lines: Vec<&str> = onboarding_text.lines().collect();
    let auth_url = handler.auth_url();
    let matching_lines: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| l.contains(&auth_url))
        .collect();
    assert_eq!(
        matching_lines.len(),
        1,
        "auth URL must appear exactly once in onboarding DM"
    );
    assert_eq!(
        matching_lines[0], auth_url,
        "auth URL must occupy its own dedicated line without leading or trailing characters"
    );
    assert!(
        !matching_lines[0].contains("🔗"),
        "must not have emoji glued to URL"
    );
    assert!(
        !matching_lines[0].contains('(') && !matching_lines[0].contains(')'),
        "must not have brackets glued"
    );

    // WireMock Verification: sendMessage automatically extracts and attaches the link facet
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let text = body["message"]["text"].as_str().unwrap_or_default();
            let facets = body["message"]["facets"].as_array().expect("facets array");
            assert_eq!(facets.len(), 1, "exactly one facet for auth url");

            let facet = &facets[0];
            let byte_start = facet["index"]["byteStart"].as_u64().unwrap() as usize;
            let byte_end = facet["index"]["byteEnd"].as_u64().unwrap() as usize;

            let sliced_url = &text[byte_start..byte_end];
            assert!(sliced_url.ends_with("/auth"));

            let feature = &facet["features"][0];
            assert_eq!(feature["$type"], "app.bsky.richtext.facet#link");
            assert_eq!(feature["uri"], sliced_url);

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_onboard_out",
                "rev": "rev_onboard_out",
                "text": text,
                "sender": { "did": "did:plc:skybouncer-bot" },
                "sentAt": "2026-10-04T12:00:00Z"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "token").expect("client creation");
    let sent = client
        .send_message("convo_onboard_conv", &onboarding_text)
        .await
        .expect("send_message");

    assert_eq!(sent.id, "msg_onboard_out");
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

#[tokio::test]
async fn test_chat_client_list_convo_requests() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvoRequests"))
        .respond_with(|req: &wiremock::Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(auth, "Bearer test_req_token");

            let query = req.url.query().unwrap_or_default();
            assert!(query.contains("limit=20"));

            ResponseTemplate::new(200).set_body_json(json!({
                "requests": [
                    {
                        "id": "convo_req_1",
                        "rev": "rev_req_1",
                        "status": "request",
                        "unreadCount": 1,
                        "members": [
                            { "did": "did:plc:stranger" },
                            { "did": "did:plc:bot" }
                        ],
                        "lastMessage": {
                            "id": "msg_stranger_1",
                            "rev": "rev_stranger_1",
                            "text": "Start",
                            "sender": { "did": "did:plc:stranger" },
                            "sentAt": "2026-10-04T00:00:00Z"
                        }
                    }
                ],
                "cursor": "req_cursor_123"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "test_req_token").expect("client creation");
    let resp = client
        .list_convo_requests(Some(20), None)
        .await
        .expect("list_convo_requests");

    assert_eq!(resp.requests.len(), 1);
    assert_eq!(resp.requests[0].id, "convo_req_1");
    assert_eq!(resp.requests[0].status.as_deref(), Some("request"));
    assert_eq!(resp.cursor, Some("req_cursor_123".to_string()));
}

#[tokio::test]
async fn test_chat_client_accept_convo() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.acceptConvo"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_to_accept");

            ResponseTemplate::new(200).set_body_json(json!({
                "rev": "accepted_rev_999"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "test_token").expect("client");
    let resp = client
        .accept_convo("convo_to_accept")
        .await
        .expect("accept_convo");

    assert_eq!(resp.rev, Some("accepted_rev_999".to_string()));
}

#[tokio::test]
async fn test_chat_client_auto_token_refresh_via_refresh_session() {
    let server = MockServer::start().await;

    // Chat endpoint returns 400 ExpiredToken on initial expired access token,
    // and returns 200 OK once the token has been refreshed.
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvos"))
        .respond_with(|req: &wiremock::Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();

            if auth == "Bearer expired_access_jwt" {
                ResponseTemplate::new(400).set_body_json(json!({
                    "error": "ExpiredToken",
                    "message": "Token has expired"
                }))
            } else if auth == "Bearer fresh_refreshed_access_jwt" {
                ResponseTemplate::new(200).set_body_json(json!({
                    "convos": [],
                    "cursor": null
                }))
            } else {
                ResponseTemplate::new(401).set_body_json(json!({
                    "error": "AuthenticationRequired",
                    "message": "Unexpected token"
                }))
            }
        })
        .mount(&server)
        .await;

    // RefreshSession endpoint returns new tokens
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.server.refreshSession"))
        .respond_with(|req: &wiremock::Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(auth, "Bearer active_refresh_jwt");

            ResponseTemplate::new(200).set_body_json(json!({
                "accessJwt": "fresh_refreshed_access_jwt",
                "refreshJwt": "next_refresh_jwt",
                "handle": "bot.bsky.social",
                "did": "did:plc:bot"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "expired_access_jwt")
        .expect("client")
        .with_refresh_token("active_refresh_jwt")
        .with_credentials(server.uri(), "bot.bsky.social", "secret-app-pass");

    // The call should detect ExpiredToken, invoke refreshSession, update token, and retry successfully!
    let resp = client
        .list_convos(None, None)
        .await
        .expect("should transparently refresh token and succeed");

    assert_eq!(resp.convos.len(), 0);
    assert_eq!(
        client.current_access_token().await,
        "fresh_refreshed_access_jwt"
    );
}

#[tokio::test]
async fn test_chat_client_auto_token_refresh_fallback_to_app_password() {
    let server = MockServer::start().await;

    // Chat endpoint returns 400 ExpiredToken on expired token
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvos"))
        .respond_with(|req: &wiremock::Request| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();

            if auth == "Bearer expired_access_jwt" {
                ResponseTemplate::new(400).set_body_json(json!({
                    "error": "ExpiredToken",
                    "message": "Token has expired"
                }))
            } else if auth == "Bearer app_password_logged_in_access_jwt" {
                ResponseTemplate::new(200).set_body_json(json!({
                    "convos": [],
                    "cursor": null
                }))
            } else {
                ResponseTemplate::new(401).set_body_json(json!({
                    "error": "AuthenticationRequired",
                    "message": "Unexpected token"
                }))
            }
        })
        .mount(&server)
        .await;

    // RefreshSession fails (e.g. refresh token also expired after long downtime)
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.server.refreshSession"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "ExpiredToken",
            "message": "Refresh token has expired"
        })))
        .mount(&server)
        .await;

    // createSession fallback with App Password credentials
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.server.createSession"))
        .respond_with(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["identifier"], "skybouncer.bsky.social");
            assert_eq!(body["password"], "app-password-123");

            ResponseTemplate::new(200).set_body_json(json!({
                "accessJwt": "app_password_logged_in_access_jwt",
                "refreshJwt": "new_refreshed_jwt",
                "handle": "skybouncer.bsky.social",
                "did": "did:plc:skybouncer-bot"
            }))
        })
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "expired_access_jwt")
        .expect("client")
        .with_refresh_token("expired_refresh_jwt")
        .with_credentials(server.uri(), "skybouncer.bsky.social", "app-password-123");

    let resp = client
        .list_convos(None, None)
        .await
        .expect("should recover via createSession fallback");

    assert_eq!(resp.convos.len(), 0);
    assert_eq!(
        client.current_access_token().await,
        "app_password_logged_in_access_jwt"
    );
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
async fn test_command_handler_onboarding_clean_url_formatting() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot")
        .with_public_url("https://skybouncer.mike10010100.com");

    let cmds = ["start", "onboard", "auth", "activate", "hi", "hello"];
    for cmd in cmds {
        let reply = handler
            .handle_command("did:plc:new-user", cmd)
            .await
            .expect("handle onboarding command");

        assert!(reply.contains("Welcome to **Skybouncer**"));
        assert!(reply.contains("did:plc:new-user"));

        // R1: Verify authorization URL is formatted on its own dedicated line without emojis or punctuation glued
        let lines: Vec<&str> = reply.lines().collect();
        let auth_url = handler.auth_url();
        let matching_lines: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|l| l.contains(&auth_url))
            .collect();
        assert_eq!(
            matching_lines.len(),
            1,
            "URL must appear once for command '{cmd}'"
        );
        assert_eq!(
            matching_lines[0], auth_url,
            "URL must be strictly isolated on its own line without adjacent emojis, brackets, or punctuation"
        );

        // Verify link facets can be cleanly extracted with exact byte offset matching
        let facets = skybouncer::bot::extract_link_facets(&reply);
        assert_eq!(facets.len(), 1);
        let f = &facets[0];
        let slice = &reply[f.index.byte_start..f.index.byte_end];
        assert_eq!(slice, auth_url);
    }
}

#[tokio::test]
async fn test_command_handler_rules_and_set_rules() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    // Stranger sending rules is rejected (Finding C1 auth gate)
    let reply_unauth = handler
        .handle_command("did:plc:stranger", "rules")
        .await
        .expect("handle");
    assert!(reply_unauth.contains("You do not have an active bouncer session"));

    // View default rules
    let reply_rules = handler
        .handle_command("did:plc:protected1", "rules")
        .await
        .expect("handle");
    assert!(reply_rules.contains("Current Moderation Rubric:"));
    assert!(reply_rules.contains("Block toxicity and crypto spam"));
    assert!(reply_rules.contains("Sensitivity: medium"));

    // Set new rules
    let reply_set = handler
        .handle_command(
            "did:plc:protected1",
            "set rules Block NFTs, airdrops, and harassment",
        )
        .await
        .expect("handle");
    assert!(reply_set.contains("Moderation rubric updated successfully!"));
    assert!(reply_set.contains("Block NFTs, airdrops, and harassment"));

    // Set rules with empty prompt
    let reply_empty_set = handler
        .handle_command("did:plc:protected1", "set rules   ")
        .await
        .expect("handle");
    assert!(reply_empty_set.contains("Please provide a moderation prompt"));
}

#[tokio::test]
async fn test_command_handler_sensitivity() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    // Stranger sending sensitivity is rejected
    let reply_unauth = handler
        .handle_command("did:plc:stranger", "sensitivity low")
        .await
        .expect("handle");
    assert!(reply_unauth.contains("You do not have an active bouncer session"));

    let reply_low = handler
        .handle_command("did:plc:protected1", "sensitivity low")
        .await
        .expect("handle");
    assert!(reply_low.contains("Sensitivity threshold updated to **low** (confidence: 0.90)"));

    let reply_high = handler
        .handle_command("did:plc:protected1", "sensitivity high")
        .await
        .expect("handle");
    assert!(reply_high.contains("Sensitivity threshold updated to **high** (confidence: 0.60)"));

    let reply_invalid = handler
        .handle_command("did:plc:protected1", "sensitivity extreme")
        .await
        .expect("handle");
    assert!(reply_invalid.contains("Invalid sensitivity level"));

    let reply_no_arg = handler
        .handle_command("did:plc:protected1", "sensitivity")
        .await
        .expect("handle");
    assert!(reply_no_arg.contains("Usage: `sensitivity <low|medium|high>`"));
}

#[tokio::test]
async fn test_command_handler_duration() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(Arc::clone(&engine), "did:plc:bot");

    // Stranger sending duration is rejected
    let reply_unauth = handler
        .handle_command("did:plc:stranger", "duration 24h")
        .await
        .expect("handle");
    assert!(reply_unauth.contains("You do not have an active bouncer session"));

    // Usage prompt when argument is missing
    let reply_no_arg = handler
        .handle_command("did:plc:protected1", "duration")
        .await
        .expect("handle");
    assert!(reply_no_arg.contains("Usage: `duration <permanent|24h|7d|30d>`"));

    // Set 24h cooldown
    let reply_24h = handler
        .handle_command("did:plc:protected1", "duration 24h")
        .await
        .expect("handle");
    assert!(reply_24h.contains("Moderation duration updated to **24-Hour Cooldown**"));
    assert_eq!(
        engine.rubric().bounce_duration,
        skybouncer::classifier::BounceDuration::Cooldown24h
    );

    // Set 7d timeout
    let reply_7d = handler
        .handle_command("did:plc:protected1", "set timeout 7d")
        .await
        .expect("handle");
    assert!(reply_7d.contains("Moderation duration updated to **7-Day Timeout**"));
    assert_eq!(
        engine.rubric().bounce_duration,
        skybouncer::classifier::BounceDuration::Timeout7d
    );

    // Rules command displays duration
    let reply_rules = handler
        .handle_command("did:plc:protected1", "rules")
        .await
        .expect("handle");
    assert!(reply_rules.contains("Duration: 7-Day Timeout"));

    // Set permanent
    let reply_perm = handler
        .handle_command("did:plc:protected1", "duration permanent")
        .await
        .expect("handle");
    assert!(reply_perm.contains("Moderation duration updated to **Permanent**"));
    assert_eq!(
        engine.rubric().bounce_duration,
        skybouncer::classifier::BounceDuration::Permanent
    );

    // Invalid duration
    let reply_invalid = handler
        .handle_command("did:plc:protected1", "duration eternity")
        .await
        .expect("handle");
    assert!(reply_invalid.contains("Invalid duration"));
}

#[tokio::test]
async fn test_command_handler_recent_and_pardon() {
    let (engine, cache, pds) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(Arc::clone(&engine), "did:plc:bot");

    // Initially empty recent list for protected1
    let reply_empty = handler
        .handle_command("did:plc:protected1", "recent")
        .await
        .expect("handle");
    assert!(reply_empty.contains("No accounts have been bounced from your replies yet"));

    // Populate bounced user in cache
    cache
        .record_bounce(&BouncedUser {
            subject_did: "did:plc:spammer1".to_string(),
            protected_did: "did:plc:protected1".to_string(),
            listitem_uri: "at://did:plc:protected1/app.bsky.graph.listitem/item1".to_string(),
            listitem_rkey: "item1".to_string(),
            listitem_cid: "bafyitem1cid".to_string(),
            category: "spam".to_string(),
            confidence: 0.96,
            reason: "Detected crypto scam keyword".to_string(),
            post_uri: "at://did:plc:spammer1/app.bsky.feed.post/post1".to_string(),
            post_text: "Scam post".to_string(),
            bounced_at: 1_700_000_000,
            expires_at: None,
        })
        .expect("record bounce");

    // Check recent list has entry when queried by protected1
    let reply_recent = handler
        .handle_command("did:plc:protected1", "recent")
        .await
        .expect("handle");
    assert!(reply_recent.contains("Recently Bounced Accounts from Your Replies (last 5):"));
    assert!(reply_recent.contains("did:plc:spammer1"));
    assert!(reply_recent.contains("96% confidence"));
    assert!(reply_recent.contains("Detected crypto scam keyword"));

    // Multi-tenant privacy: another tenant does NOT see protected1's bounces
    engine
        .enroll_tenant(skybouncer::tenant::Tenant::new("did:plc:other_tenant"))
        .expect("enroll");
    let reply_other = handler
        .handle_command("did:plc:other_tenant", "recent")
        .await
        .expect("handle");
    assert!(reply_other.contains("No accounts have been bounced from your replies yet"));

    // Pardon an account that is not present
    let reply_pardon_miss = handler
        .handle_command("did:plc:protected1", "pardon did:plc:unknown")
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

    // Tenant Status output (scoped privacy)
    let reply_status = handler
        .handle_command("did:plc:protected1", "status")
        .await
        .expect("handle");
    assert!(reply_status.contains("Skybouncer Status for Your Account:"));
    assert!(reply_status.contains("Defense State: ▶️ ACTIVE"));
    assert!(reply_status.contains("Accounts Bounced from Your Posts: 0"));

    // Admin Fleet Status output
    let reply_admin_status = handler
        .handle_command("did:plc:admin", "status")
        .await
        .expect("handle");
    assert!(reply_admin_status.contains("Skybouncer Engine Status (Admin Fleet View):"));
    assert!(reply_admin_status.contains("Commits Received: 0"));
    assert!(reply_admin_status.contains("Violations Detected: 0"));

    // Test command: heuristic matches "crypto scam"
    let reply_test_violation = handler
        .handle_command(
            "did:plc:protected1",
            "test Check out this free airdrop crypto scam!",
        )
        .await
        .expect("handle");
    assert!(reply_test_violation.contains("Test Evaluation: **VIOLATION**"));
    assert!(reply_test_violation.contains("Category: **crypto_spam**"));

    // Test command: polite message
    let reply_test_clean = handler
        .handle_command("did:plc:protected1", "test Hello, having a nice day!")
        .await
        .expect("handle");
    assert!(reply_test_clean.contains("Test Evaluation: **PERMITTED**"));

    // Unknown command
    let reply_unknown = handler
        .handle_command("did:plc:protected1", "launch missiles")
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
                                { "did": "did:plc:protected1" },
                                { "did": "did:plc:skybouncer-bot" }
                            ],
                            "lastMessage": {
                                "id": "msg_cmd_1",
                                "rev": "rev_1",
                                "text": "rules",
                                "sender": { "did": "did:plc:protected1" },
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
                                { "did": "did:plc:protected1" },
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
async fn test_run_bot_poller_auto_accepts_and_processes_convo_requests() {
    let server = MockServer::start().await;
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let bot_did = "did:plc:skybouncer-bot";
    let handler = BotCommandHandler::new(engine, bot_did);

    let requests_polled = Arc::new(AtomicUsize::new(0));
    let accept_called = Arc::new(AtomicUsize::new(0));
    let send_called = Arc::new(AtomicUsize::new(0));
    let read_called = Arc::new(AtomicUsize::new(0));

    // Incoming conversation requests endpoint
    let rp = Arc::clone(&requests_polled);
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvoRequests"))
        .respond_with(move |_: &wiremock::Request| {
            let count = rp.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                // First poll returns pending request from stranger huwupy with "help"
                ResponseTemplate::new(200).set_body_json(json!({
                    "requests": [
                        {
                            "id": "convo_huwupy_request",
                            "rev": "rev_req_0",
                            "status": "request",
                            "unreadCount": 1,
                            "members": [
                                { "did": "did:plc:huwupy" },
                                { "did": "did:plc:skybouncer-bot" }
                            ],
                            "lastMessage": {
                                "id": "msg_huwupy_1",
                                "rev": "rev_msg_1",
                                "text": "help",
                                "sender": { "did": "did:plc:huwupy" },
                                "sentAt": "2026-10-04T12:00:00Z"
                            }
                        }
                    ],
                    "cursor": null
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "requests": [],
                    "cursor": null
                }))
            }
        })
        .mount(&server)
        .await;

    // acceptConvo endpoint
    let ac = Arc::clone(&accept_called);
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.acceptConvo"))
        .respond_with(move |req: &wiremock::Request| {
            ac.fetch_add(1, Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_huwupy_request");
            ResponseTemplate::new(200).set_body_json(json!({
                "rev": "rev_accepted_1"
            }))
        })
        .mount(&server)
        .await;

    // listConvos endpoint returns empty list
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvos"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "convos": [],
            "cursor": null
        })))
        .mount(&server)
        .await;

    // sendMessage endpoint
    let sc = Arc::clone(&send_called);
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(move |req: &wiremock::Request| {
            sc.fetch_add(1, Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_huwupy_request");
            let text = body["message"]["text"].as_str().unwrap_or_default();
            assert!(text.contains("Skybouncer Bot Commands"));

            ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_reply_huwupy",
                "rev": "rev_rep_1",
                "text": text,
                "sender": { "did": "did:plc:skybouncer-bot" },
                "sentAt": "2026-10-04T12:00:01Z"
            }))
        })
        .mount(&server)
        .await;

    // updateRead endpoint
    let rc = Arc::clone(&read_called);
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.updateRead"))
        .respond_with(move |req: &wiremock::Request| {
            rc.fetch_add(1, Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            assert_eq!(body["convoId"], "convo_huwupy_request");
            assert_eq!(body["messageId"], "msg_huwupy_1");
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

    tokio::time::sleep(Duration::from_millis(80)).await;
    cancel.cancel();

    let res = tokio::time::timeout(Duration::from_millis(500), poller_task)
        .await
        .expect("poller shutdown within timeout")
        .expect("join task");

    assert!(res.is_ok());
    assert_eq!(
        accept_called.load(Ordering::SeqCst),
        1,
        "acceptConvo must be called exactly once"
    );
    assert_eq!(
        send_called.load(Ordering::SeqCst),
        1,
        "sendMessage must be called for the request command"
    );
    assert_eq!(
        read_called.load(Ordering::SeqCst),
        1,
        "updateRead must mark the request message read"
    );
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
    let (engine, _, _pds) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(Arc::clone(&engine), "did:plc:bot");

    assert!(!engine.is_paused());

    // Stranger sending pause is rejected (Finding C1 auth gate)
    let reply_unauth = handler
        .handle_command("did:plc:stranger", "pause")
        .await
        .expect("handle");
    assert!(reply_unauth.contains("You do not have an active bouncer session"));
    assert!(!engine.is_paused());

    // 1. Send pause command as protected user
    let reply_pause = handler
        .handle_command("did:plc:protected1", "pause")
        .await
        .expect("handle");
    assert!(reply_pause.contains("Skybouncer has been **paused**"));
    assert!(engine.is_paused());

    // 2. Status shows paused state
    let reply_status = handler
        .handle_command("did:plc:protected1", "status")
        .await
        .expect("handle");
    assert!(reply_status.contains("Defense State: ⏸️ PAUSED"));

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
        .handle_command("did:plc:protected1", "resume")
        .await
        .expect("handle");
    assert!(reply_resume.contains("Skybouncer has been **resumed**"));
    assert!(!engine.is_paused());

    // 5. Status shows active state
    let reply_status_active = handler
        .handle_command("did:plc:protected1", "status")
        .await
        .expect("handle");
    assert!(reply_status_active.contains("Defense State: ▶️ ACTIVE"));

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
                Verdict::permitted("ok"),
            )))
            .build()
            .expect("engine build"),
    );

    let handler = BotCommandHandler::new(Arc::clone(&engine), "did:plc:bot");

    // Pre-populate Alice as bounced
    cache
        .record_bounce(&BouncedUser {
            subject_did: "did:plc:alice123".to_string(),
            protected_did: "did:plc:protected1".to_string(),
            listitem_uri: "at://did:plc:protected1/app.bsky.graph.listitem/item_alice".to_string(),
            listitem_rkey: "item_alice".to_string(),
            listitem_cid: "bafyalice".to_string(),
            category: "spam".to_string(),
            confidence: 0.95,
            reason: "spam".to_string(),
            post_uri: "at://did:plc:alice123/post/1".to_string(),
            post_text: "Spam content".to_string(),
            bounced_at: 1_700_000_000,
            expires_at: None,
        })
        .expect("record");

    // Pardon via handle with leading '@'
    let reply = handler
        .handle_command("did:plc:protected1", "pardon @alice.bsky.social")
        .await
        .expect("handle");
    assert!(reply.contains("Resolved `@alice.bsky.social` to `did:plc:alice123`"));
    assert!(reply.contains("Account @alice.bsky.social"));
    assert!(reply.contains("has been pardoned"));
    assert!(reply.contains("https://bsky.app/profile/alice.bsky.social"));
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
    let (engine, cache, _) = setup_test_engine("did:plc:protected1").await;

    // Pre-cache a handle for the violator so the alert renders @handle + hotlinks.
    cache
        .set_handle_for_did("did:plc:bad_actor", "badactor.bsky.social")
        .expect("set handle");

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
    assert!(sent_text.contains("Bounced violator: @badactor.bsky.social"));
    assert!(sent_text.contains("Violation: **crypto_spam**"));
    assert!(sent_text.contains("https://bsky.app/profile/badactor.bsky.social"));
    assert!(sent_text.contains("Post: https://bsky.app/profile/did:plc:bad_actor/post/rep_alert_1"));
    assert!(sent_text.contains("pardon badactor.bsky.social"));
}

#[tokio::test]
async fn test_bot_handler_allowlist_and_pardon_immunization() {
    let (engine, cache, pds) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(Arc::clone(&engine), "did:plc:bot");

    // 1. Initial allowlist is empty
    let res = handler
        .handle_command("did:plc:protected1", "allowlist")
        .await
        .expect("handle");
    assert!(res.contains("Your moderation allowlist is empty"));

    // 2. Allow a friend
    let res = handler
        .handle_command("did:plc:protected1", "allow did:plc:friend1")
        .await
        .expect("handle");
    assert!(res.contains("Account did:plc:friend1"));
    assert!(res.contains("has been added to your moderation allowlist"));
    assert!(engine.is_allowlisted("did:plc:protected1", "did:plc:friend1"));

    // 3. Allowlist now shows friend
    let res = handler
        .handle_command("did:plc:protected1", "allowlist")
        .await
        .expect("handle");
    assert!(res.contains("Your Moderation Allowlist (1 account):"));
    assert!(res.contains("did:plc:friend1"));

    // 4. Unallow friend
    let res = handler
        .handle_command("did:plc:protected1", "unallow did:plc:friend1")
        .await
        .expect("handle");
    assert!(
        res.contains("Account did:plc:friend1")
            && res.contains("has been removed from your moderation allowlist")
    );
    assert!(!engine.is_allowlisted("did:plc:protected1", "did:plc:friend1"));

    // 5. Unallow again -> not found
    let res = handler
        .handle_command("did:plc:protected1", "unallow did:plc:friend1")
        .await
        .expect("handle");
    assert!(res.contains("was not found on your moderation allowlist"));

    // 6. Record a bounced violator in cache
    cache
        .record_bounce(&BouncedUser {
            subject_did: "did:plc:violator_to_immunize".to_string(),
            protected_did: "did:plc:protected1".to_string(),
            listitem_uri: "at://did:plc:protected1/app.bsky.graph.listitem/item123".to_string(),
            listitem_rkey: "item123".to_string(),
            listitem_cid: "bafyitem123".to_string(),
            category: "crypto_spam".to_string(),
            confidence: 0.99,
            reason: "airdrop spam".to_string(),
            post_uri: "at://did:plc:violator_to_immunize/app.bsky.feed.post/123".to_string(),
            post_text: "spam".to_string(),
            bounced_at: 1_700_000_000,
            expires_at: None,
        })
        .expect("record bounce");
    assert!(cache
        .is_bounced_for("did:plc:protected1", "did:plc:violator_to_immunize")
        .expect("is_bounced"));

    // 7. Pardon and allow!
    let res = handler
        .handle_command(
            "did:plc:protected1",
            "pardon and allow did:plc:violator_to_immunize",
        )
        .await
        .expect("handle");
    assert!(res.contains("has been pardoned and added to your allowlist"));
    assert!(res.contains("permanently immunized against future automatic bounces"));

    // Verify removed from PDS deleted_records
    assert_eq!(pds.deleted_records.lock().len(), 1);
    // Verify cleared from bounced cache
    assert!(!cache
        .is_bounced_for("did:plc:protected1", "did:plc:violator_to_immunize")
        .expect("is_bounced"));
    // Verify added to allowlist in both memory and db
    assert!(engine.is_allowlisted("did:plc:protected1", "did:plc:violator_to_immunize"));
}

// =============================================================================
// Command Branch Matrix: admin vs protected vs enrolled vs stranger,
// plus pause/resume/status/sensitivity/duration/allow/unallow branches.
// =============================================================================

#[tokio::test]
async fn test_command_branch_matrix_admin_and_stranger() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    // Enroll an extra tenant so is_single_tenant becomes false.
    engine
        .enroll_tenant(skybouncer::tenant::Tenant::new("did:plc:enrolled"))
        .expect("enroll");

    let handler = BotCommandHandler::new(engine, "did:plc:bot");
    let admin = "did:plc:admin";
    let protected = "did:plc:protected1";
    let enrolled = "did:plc:enrolled";
    let stranger = "did:plc:stranger";

    // pause/resume: admin + single-tenant protected allowed; stranger denied.
    assert!(handler
        .handle_command(admin, "pause")
        .await
        .unwrap()
        .contains("paused"));
    assert!(handler
        .handle_command(admin, "resume")
        .await
        .unwrap()
        .contains("resumed"));
    assert!(handler
        .handle_command(stranger, "pause")
        .await
        .unwrap()
        .contains("active bouncer session"));

    // status: admin fleet view vs per-account view.
    assert!(handler
        .handle_command(admin, "status")
        .await
        .unwrap()
        .contains("Admin Fleet View"));
    assert!(handler
        .handle_command(protected, "status")
        .await
        .unwrap()
        .contains("Status for Your Account"));

    // sensitivity: usage, admin set, enrolled set, stranger denied.
    assert!(handler
        .handle_command(protected, "sensitivity")
        .await
        .unwrap()
        .contains("Usage"));
    assert!(handler
        .handle_command(admin, "sensitivity high")
        .await
        .unwrap()
        .contains("Sensitivity threshold updated"));
    // Strangers are stopped at the authorization gate before command dispatch.
    assert!(handler
        .handle_command(stranger, "sensitivity low")
        .await
        .unwrap()
        .contains("active bouncer session"));

    // duration: usage, admin set, invalid.
    assert!(handler
        .handle_command(protected, "duration")
        .await
        .unwrap()
        .contains("Usage"));
    assert!(handler
        .handle_command(admin, "duration 24h")
        .await
        .unwrap()
        .contains("duration updated"));
    assert!(handler
        .handle_command(admin, "duration nonsense")
        .await
        .unwrap()
        .contains("Invalid duration"));

    // allow/unallow usage forms + enrollment.
    assert!(handler
        .handle_command(protected, "allow")
        .await
        .unwrap()
        .contains("Usage"));
    assert!(handler
        .handle_command(protected, "unallow")
        .await
        .unwrap()
        .contains("Usage"));
    assert!(handler
        .handle_command(protected, "pardon")
        .await
        .unwrap()
        .contains("Usage"));

    // Enrolled tenant can pause/resume via registry path.
    assert!(handler
        .handle_command(enrolled, "pause")
        .await
        .unwrap()
        .contains("paused"));
    assert!(handler
        .handle_command(enrolled, "resume")
        .await
        .unwrap()
        .contains("resumed"));
}

#[tokio::test]
async fn test_command_allowlist_lifecycle_via_bot() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");
    let protected = "did:plc:protected1";

    // Empty allowlist view.
    assert!(handler
        .handle_command(protected, "allowlist")
        .await
        .unwrap()
        .contains("allowlist"));

    // Add (DID form), then view, then remove.
    let add = handler
        .handle_command(protected, "allow did:plc:friend")
        .await
        .unwrap();
    assert!(add.contains("added to your moderation allowlist"));

    let view = handler
        .handle_command(protected, "allow list")
        .await
        .unwrap();
    assert!(view.contains("did:plc:friend"));

    let remove = handler
        .handle_command(protected, "unallow did:plc:friend")
        .await
        .unwrap();
    assert!(remove.contains("removed from your moderation allowlist"));

    // Removing again reports not found.
    let remove_again = handler
        .handle_command(protected, "unallow did:plc:friend")
        .await
        .unwrap();
    assert!(remove_again.contains("was not found"));
}

#[tokio::test]
async fn test_command_test_allowlist_status_variants() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");
    let protected = "did:plc:protected1";
    let admin = "did:plc:admin";

    // `test` command: heuristic-only path (permitted verdict from MockClassifier).
    let t = handler
        .handle_command(protected, "test A perfectly benign message")
        .await
        .unwrap();
    assert!(t.contains("Test Evaluation"));

    // `test` usage form.
    assert!(handler
        .handle_command(protected, "test")
        .await
        .unwrap()
        .contains("Usage"));

    // allowlist view with an entry (populated branch + pluralization).
    handler
        .handle_command(protected, "allow did:plc:friend1")
        .await
        .unwrap();
    let view = handler
        .handle_command(protected, "allowlist")
        .await
        .unwrap();
    assert!(view.contains("Allowlist (1 account)"));

    // Non-admin `status` shows the per-account view; admin shows the fleet view.
    assert!(handler
        .handle_command(protected, "status")
        .await
        .unwrap()
        .contains("Status for Your Account"));
    assert!(handler
        .handle_command(admin, "status")
        .await
        .unwrap()
        .contains("Admin Fleet View"));

    // `pardon and allow <did>` alias resolves to the pardon+allowlist handler.
    let pa = handler
        .handle_command(protected, "pardon and allow did:plc:someuser")
        .await
        .unwrap();
    assert!(!pa.is_empty());
}

#[tokio::test]
async fn test_command_enrolled_tenant_update_branches() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    // Enroll a tenant so the registry-update branches are exercised.
    engine
        .enroll_tenant(skybouncer::tenant::Tenant::new("did:plc:enrolled"))
        .expect("enroll");
    let handler = BotCommandHandler::new(engine, "did:plc:bot");
    let enrolled = "did:plc:enrolled";

    // set rules (enrolled) -> registry update path.
    let r = handler
        .handle_command(enrolled, "set rules Block all spam now")
        .await
        .unwrap();
    assert!(r.contains("Moderation rubric updated successfully"));

    // sensitivity (enrolled) -> registry update path.
    let s = handler
        .handle_command(enrolled, "sensitivity high")
        .await
        .unwrap();
    assert!(s.contains("Sensitivity threshold updated"));

    // duration (enrolled) -> registry update path (both usage + set forms).
    assert!(handler
        .handle_command(enrolled, "duration")
        .await
        .unwrap()
        .contains("Usage"));
    let d = handler
        .handle_command(enrolled, "duration 7d")
        .await
        .unwrap();
    assert!(d.contains("Moderation duration updated"));

    // recent (enrolled) -> empty-list branch.
    let rec = handler.handle_command(enrolled, "recent").await.unwrap();
    assert!(rec.contains("No accounts have been bounced"));
}

#[tokio::test]
async fn test_command_all_privileged_denied_for_stranger() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");
    let stranger = "did:plc:stranger";

    // Every privileged command form must be denied with the unauthorized response,
    // exercising each inline auth branch.
    let commands = [
        "pause",
        "resume",
        "rules",
        "set rules",
        "set rules Block spam",
        "sensitivity",
        "sensitivity high",
        "duration",
        "duration 24h",
        "timeout 7d",
        "set duration 30d",
        "set timeout 24h",
        "recent",
        "allowlist",
        "allow list",
        "allow",
        "allow did:plc:x",
        "unallow",
        "unallow did:plc:x",
        "pardon",
        "pardon and allow did:plc:x",
        "pardon did:plc:x",
        "pardon did:plc:x and allow did:plc:x",
        "status",
        "test",
        "test some text",
    ];
    for cmd in commands {
        let reply = handler.handle_command(stranger, cmd).await.expect("handle");
        assert!(
            reply.contains("active bouncer session"),
            "command '{cmd}' must be denied for a stranger, got: {reply}"
        );
    }
}

#[tokio::test]
async fn test_command_unknown_and_nested_pardon_and_allow() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");
    let protected = "did:plc:protected1";

    // Unknown command for an authorized (protected) user -> tip variant.
    let unknown = handler
        .handle_command(protected, "frobnicate")
        .await
        .unwrap();
    assert!(unknown.contains("Unknown command"));

    // `pardon <target> and allow <target2>` nested form.
    let nested = handler
        .handle_command(protected, "pardon did:plc:a and allow did:plc:b")
        .await
        .unwrap();
    assert!(!nested.is_empty());
}

#[tokio::test]
async fn test_command_pardon_allow_usage_and_resolution_failures() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");
    let protected = "did:plc:protected1";

    // Unresolvable handles exercise the Err(msg) branches of resolve_dm_target.
    assert!(handler
        .handle_command(protected, "pardon @ghost.invalid.handle")
        .await
        .unwrap()
        .contains("Could not resolve handle"));
    assert!(handler
        .handle_command(protected, "pardon and allow @ghost.invalid.handle")
        .await
        .unwrap()
        .contains("Could not resolve handle"));
    assert!(handler
        .handle_command(protected, "allow @ghost.invalid.handle")
        .await
        .unwrap()
        .contains("Could not resolve handle"));
    assert!(handler
        .handle_command(protected, "unallow @ghost.invalid.handle")
        .await
        .unwrap()
        .contains("Could not resolve handle"));
}

#[tokio::test]
async fn test_command_status_dry_run_variants() {
    // Build an engine in dry-run mode to hit the shadow-mode status strings.
    let pds = MockPdsServer::start().await;
    let cache = Arc::new(DeduplicationCache::open_in_memory().expect("cache"));
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client("did:plc:protected1"));
    let classifier = Arc::new(skybouncer::classifier::MockClassifier::new(
        Verdict::permitted("ok"),
    ));
    let mut dids = HashSet::new();
    dids.insert("did:plc:protected1".to_string());
    let config = SkybouncerConfig::new(dids, rubric)
        .with_admin_did("did:plc:admin")
        .with_dry_run(true);
    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist,
        pds_client,
    ));
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    // Admin status in dry-run -> "Yes (shadow)".
    let admin = handler
        .handle_command("did:plc:admin", "status")
        .await
        .unwrap();
    assert!(admin.contains("shadow") || admin.contains("Yes"));
    // Non-admin status in dry-run -> "Dry-Run (simulated)".
    let user = handler
        .handle_command("did:plc:protected1", "status")
        .await
        .unwrap();
    assert!(user.contains("Dry-Run") || user.contains("simulated"));
}

#[tokio::test]
async fn test_command_sensitivity_medium_and_stranger_unknown_tip() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let handler = BotCommandHandler::new(engine, "did:plc:bot");

    // `sensitivity medium` exercises the "medium" match arm.
    let m = handler
        .handle_command("did:plc:protected1", "sensitivity medium")
        .await
        .unwrap();
    assert!(m.contains("Sensitivity threshold updated"));

    // Unknown command from an unauthorized sender includes the activation tip.
    let tip = handler
        .handle_command("did:plc:stranger", "totally-unknown-cmd")
        .await
        .unwrap();
    assert!(tip.contains("Unknown command"));
    assert!(tip.contains("not yet protected") || tip.contains("activate"));
}

#[tokio::test]
async fn test_run_bot_poller_multiple_unread_fetches_history_and_handles_failures() {
    let server = MockServer::start().await;
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    let bot_did = "did:plc:skybouncer-bot";
    let handler = BotCommandHandler::new(engine, bot_did);

    let list_called = Arc::new(AtomicUsize::new(0));
    let lc = Arc::clone(&list_called);
    let get_called = Arc::new(AtomicUsize::new(0));
    let gc = Arc::clone(&get_called);

    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvos"))
        .respond_with(move |_: &wiremock::Request| {
            // First tick: convo with multiple unread messages; later ticks: none.
            if lc.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "convos": [{
                        "id": "convo_multi",
                        "rev": "rev_1",
                        "unreadCount": 2,
                        "members": [
                            {"did": "did:plc:protected1"},
                            {"did": "did:plc:skybouncer-bot"}
                        ],
                        "lastMessage": {
                            "id": "msg_newest",
                            "rev": "rev_1",
                            "text": "help",
                            "sender": {"did": "did:plc:protected1"},
                            "sentAt": "2026-10-02T03:00:00Z"
                        }
                    }],
                    "cursor": null
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({"convos": [], "cursor": null}))
            }
        })
        .mount(&server)
        .await;

    // getMessages returns newest-first; includes a self-authored message (skipped) + a real one.
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.getMessages"))
        .respond_with(move |_: &wiremock::Request| {
            gc.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({
                "messages": [
                    {
                        "id": "msg_real",
                        "rev": "rev_b",
                        "text": "help",
                        "sender": {"did": "did:plc:protected1"},
                        "sentAt": "2026-10-02T03:00:00Z"
                    },
                    {
                        "id": "msg_self",
                        "rev": "rev_a",
                        "text": "welcome",
                        "sender": {"did": "did:plc:skybouncer-bot"},
                        "sentAt": "2026-10-02T02:59:00Z"
                    }
                ]
            }))
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.sendMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_reply",
            "rev": "rev_r",
            "text": "reply",
            "sender": {"did": "did:plc:skybouncer-bot"},
            "sentAt": "2026-10-02T03:00:01Z"
        })))
        .mount(&server)
        .await;

    // updateRead fails -> warn branch.
    Mock::given(method("POST"))
        .and(path("/xrpc/chat.bsky.convo.updateRead"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    // listConvoRequests fails -> debug branch.
    Mock::given(method("GET"))
        .and(path("/xrpc/chat.bsky.convo.listConvoRequests"))
        .respond_with(ResponseTemplate::new(500).set_body_string("nope"))
        .mount(&server)
        .await;

    let client = ChatClient::new(server.uri(), "test_token").expect("client");
    let cancel = CancellationToken::new();
    let cancel_poller = cancel.clone();

    let poller_task = tokio::spawn(async move {
        run_bot_poller(client, handler, Duration::from_millis(20), cancel_poller).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();

    let res = tokio::time::timeout(Duration::from_millis(500), poller_task)
        .await
        .expect("poller shutdown within timeout")
        .expect("join task");
    assert!(res.is_ok());
    assert!(get_called.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn test_command_handler_second_protected_user_cannot_mutate_rules_sensitivity_or_duration() {
    let (engine, _, _) = setup_test_engine("did:plc:protected1").await;
    // Adding a second protected DID makes this a multi-tenant engine, so a protected
    // (authorized) but unenrolled sender hits the "own enrolled account only" reject.
    engine.add_protected_did("did:plc:protected2");
    let handler = BotCommandHandler::new(engine, "did:plc:bot");
    let sender = "did:plc:protected2";

    let r1 = handler
        .handle_command(sender, "set rules Block everything")
        .await
        .unwrap();
    assert!(
        r1.contains("You can only update rules for your own enrolled account"),
        "r1={r1}"
    );

    let r2 = handler
        .handle_command(sender, "sensitivity high")
        .await
        .unwrap();
    assert!(
        r2.contains("You can only update sensitivity for your own enrolled account"),
        "r2={r2}"
    );

    let r3 = handler.handle_command(sender, "duration 7d").await.unwrap();
    assert!(
        r3.contains("You can only update duration for your own enrolled account"),
        "r3={r3}"
    );
}
