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

#[tokio::test]
async fn test_appview_fetch_follows_and_followers_delegate() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.graph.getFollows"))
        .and(query_param("actor", "did:plc:alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "follows": [{"did": "did:plc:followed1"}, {"did": "did:plc:followed2"}],
            "cursor": null
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.graph.getFollowers"))
        .and(query_param("actor", "did:plc:alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "followers": [{"did": "did:plc:follower1"}],
            "cursor": null
        })))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    let follows = enricher.fetch_follows("did:plc:alice", 100).await;
    assert_eq!(follows, vec!["did:plc:followed1", "did:plc:followed2"]);
    let followers = enricher.fetch_followers("did:plc:alice", 100).await;
    assert_eq!(followers, vec!["did:plc:follower1"]);
}

#[tokio::test]
async fn test_appview_fetch_follow_records_extracts_rkey_and_subject() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                {
                    "uri": "at://did:plc:alice/app.bsky.graph.follow/3kabc",
                    "value": {"subject": "did:plc:bob"}
                },
                {
                    "uri": "at://did:plc:alice/app.bsky.graph.follow/3kdef",
                    "value": {"subject": null}
                }
            ],
            "cursor": null
        })))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    let records = enricher.fetch_follow_records("did:plc:alice", 100).await;
    // The record with a null subject is dropped.
    assert_eq!(
        records,
        vec![("3kabc".to_string(), "did:plc:bob".to_string())]
    );
}

#[tokio::test]
async fn test_appview_resolve_handle_and_did() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.identity.resolveHandle"))
        .and(query_param("handle", "alice.bsky.social"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"did": "did:plc:alice"})))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": "did:plc:alice",
            "handle": "alice.bsky.social"
        })))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());

    // Handle -> DID delegation (plus @ stripping and DID passthrough).
    assert_eq!(
        enricher.resolve_handle("@alice.bsky.social").await,
        Some("did:plc:alice".to_string())
    );
    assert_eq!(
        enricher.resolve_handle("did:plc:already").await,
        Some("did:plc:already".to_string())
    );

    // DID -> handle delegation via the AppView profile.
    assert_eq!(
        enricher.resolve_did("did:plc:alice").await,
        Some("alice.bsky.social".to_string())
    );
    // Non-DID input returns None without a network call.
    assert_eq!(enricher.resolve_did("alice.bsky.social").await, None);
}

#[tokio::test]
async fn test_appview_fetch_image_base64_and_batch() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/img/feed_thumbnail/plain/did:plc:bob/bafyimg@jpeg"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"PNGDATA".to_vec()))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoints(mock_server.uri(), mock_server.uri());

    let b64 = enricher.fetch_image_base64("did:plc:bob", "bafyimg").await;
    assert_eq!(b64.as_deref(), Some("UE5HREFUQQ==")); // base64("PNGDATA")

    // Invalid (empty after sanitizing) DID/CID short-circuits to None.
    assert!(enricher.fetch_image_base64("", "bafyimg").await.is_none());
    assert!(enricher
        .fetch_image_base64("did:plc:bob", "")
        .await
        .is_none());

    // Batch collects successfully-fetched images.
    let batch = enricher
        .fetch_images_base64("did:plc:bob", &["bafyimg".to_string()])
        .await;
    assert_eq!(batch.len(), 1);
}

#[tokio::test]
async fn test_appview_fetch_follows_paginates() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.graph.getFollows"))
        .and(query_param("cursor", "next"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "follows": [{"did": "did:plc:second"}],
            "cursor": null
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.graph.getFollows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "follows": [{"did": "did:plc:first"}],
            "cursor": "next"
        })))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    let follows = enricher.fetch_follows("did:plc:alice", 100).await;
    assert_eq!(follows, vec!["did:plc:first", "did:plc:second"]);
}
