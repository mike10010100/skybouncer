//! Integration and unit tests for ContextEnricher (PRD §3 & §4.2 Context-Aware Model Evaluation).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybouncer::enricher::{
    AppViewContextEnricher, AuthorContext, ContextEnricher, MockContextEnricher,
    NoopContextEnricher, ParentPostContext,
};
use skybouncer::matcher::{Interaction, InteractionType};

#[tokio::test]
async fn test_noop_context_enricher() {
    let enricher = NoopContextEnricher;
    let interaction = Interaction::new(
        "did:plc:author",
        "did:plc:target",
        InteractionType::DirectReply,
        "at://did:plc:author/app.bsky.feed.post/123",
        "cid_123",
        "Hello target!",
    );

    let ctx = enricher.enrich(&interaction).await;
    assert!(ctx.is_empty());
    assert!(ctx.author.is_none());
    assert!(ctx.parent_post.is_none());
    assert_eq!(ctx.format_for_classifier(), "");
}

#[tokio::test]
async fn test_mock_context_enricher() {
    let enricher = MockContextEnricher::new();
    let author_did = "did:plc:author456";
    let parent_uri = "at://did:plc:target/app.bsky.feed.post/parent789";

    enricher.set_author(
        author_did,
        AuthorContext {
            handle: Some("troll.bsky.social".to_string()),
            display_name: Some("Just Asking Questions".to_string()),
            description: Some("Free thinker debating everyone".to_string()),
            followers_count: Some(12),
            follows_count: Some(500),
            created_at: Some("2026-09-01T00:00:00Z".to_string()),
        },
    );

    enricher.set_parent_post(
        parent_uri,
        ParentPostContext {
            author_did: "did:plc:target".to_string(),
            text: "Excited to share our new research paper on climate science!".to_string(),
            cid: Some("cid_parent".to_string()),
        },
    );

    let interaction = Interaction::new(
        author_did,
        "did:plc:target",
        InteractionType::DirectReply,
        "at://did:plc:author456/app.bsky.feed.post/reply",
        "cid_reply",
        "Explain why you hate industry then?",
    )
    .with_parent_uri(parent_uri);

    let ctx = enricher.enrich(&interaction).await;
    assert!(!ctx.is_empty());

    let author = ctx.author.as_ref().unwrap();
    assert_eq!(author.handle.as_deref(), Some("troll.bsky.social"));
    assert_eq!(author.followers_count, Some(12));

    let parent = ctx.parent_post.as_ref().unwrap();
    assert_eq!(parent.author_did, "did:plc:target");
    assert!(parent.text.contains("research paper"));

    let formatted = ctx.format_for_classifier();
    assert!(formatted.contains("handle: @troll.bsky.social"));
    assert!(formatted.contains("name: \"Just Asking Questions\""));
    assert!(formatted.contains("followers: 12"));
    assert!(formatted.contains("In Reply To (by did:plc:target):"));
    assert!(formatted.contains("climate science"));
}

#[tokio::test]
async fn test_appview_enricher_success() {
    let mock_server = MockServer::start().await;
    let author_did = "did:plc:bob";
    let parent_uri = "at://did:plc:alice/app.bsky.feed.post/1";

    // 1. Mock app.bsky.actor.getProfile
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .and(query_param("actor", author_did))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": author_did,
            "handle": "bob.bsky.social",
            "displayName": "Bob The Builder",
            "description": "I build software in Rust",
            "followersCount": 420,
            "followsCount": 69,
            "createdAt": "2024-01-01T12:00:00.000Z"
        })))
        .mount(&mock_server)
        .await;

    // 2. Mock app.bsky.feed.getPosts
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .and(query_param("uris", parent_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [
                {
                    "uri": parent_uri,
                    "cid": "bafy_parent_cid",
                    "author": {
                        "did": "did:plc:alice",
                        "handle": "alice.bsky.social"
                    },
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": "What is everyone working on this weekend?",
                        "createdAt": "2026-10-01T10:00:00.000Z"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    let interaction = Interaction::new(
        author_did,
        "did:plc:alice",
        InteractionType::DirectReply,
        "at://did:plc:bob/app.bsky.feed.post/2",
        "cid_2",
        "Building Skybouncer with pair programming!",
    )
    .with_parent_uri(parent_uri);

    let ctx = enricher.enrich(&interaction).await;
    assert!(!ctx.is_empty());

    let author = ctx.author.unwrap();
    assert_eq!(author.handle.as_deref(), Some("bob.bsky.social"));
    assert_eq!(author.display_name.as_deref(), Some("Bob The Builder"));
    assert_eq!(
        author.description.as_deref(),
        Some("I build software in Rust")
    );
    assert_eq!(author.followers_count, Some(420));
    assert_eq!(author.follows_count, Some(69));

    let parent = ctx.parent_post.unwrap();
    assert_eq!(parent.author_did, "did:plc:alice");
    assert_eq!(parent.text, "What is everyone working on this weekend?");
    assert_eq!(parent.cid.as_deref(), Some("bafy_parent_cid"));
}

#[tokio::test]
async fn test_appview_enricher_graceful_degradation_on_error() {
    let mock_server = MockServer::start().await;
    let author_did = "did:plc:nonexistent";
    let parent_uri = "at://did:plc:target/app.bsky.feed.post/deleted";

    // AppView returns 404 for actor and 500 for post
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "ProfileNotFound",
            "message": "Account does not exist"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    let interaction = Interaction::new(
        author_did,
        "did:plc:target",
        InteractionType::DirectReply,
        "at://did:plc:nonexistent/app.bsky.feed.post/3",
        "cid_3",
        "Some comment",
    )
    .with_parent_uri(parent_uri);

    // Enrichment must NOT fail, but cleanly degrade to empty context
    let ctx = enricher.enrich(&interaction).await;
    assert!(ctx.is_empty());
    assert!(ctx.author.is_none());
    assert!(ctx.parent_post.is_none());
    assert_eq!(ctx.format_for_classifier(), "");
}
