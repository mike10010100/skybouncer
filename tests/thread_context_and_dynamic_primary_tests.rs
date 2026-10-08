//! Integration tests for conversation-thread ancestor enrichment and dynamic
//! multimodal Tier-1 primary routing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::sync::Arc;

use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybouncer::classifier::{
    Classifier, DynamicModelPolicy, DynamicPrimaryClassifier, MockClassifier, Verdict,
    ViolationCategory,
};
use skybouncer::enricher::{
    AppViewContextEnricher, ContextEnricher, EnrichedContext, ThreadPost,
    MAX_RENDERED_THREAD_ANCESTORS,
};
use skybouncer::matcher::{Interaction, InteractionType};

fn thread_node(author: &str, text: &str, parent: serde_json::Value) -> serde_json::Value {
    json!({
        "post": {
            "author": { "did": author },
            "record": { "$type": "app.bsky.feed.post", "text": text }
        },
        "parent": parent
    })
}

#[tokio::test]
async fn thread_ancestors_returned_oldest_first() {
    let mock_server = MockServer::start().await;
    let candidate = "at://did:plc:c/app.bsky.feed.post/3";
    let parent = "at://did:plc:b/app.bsky.feed.post/2";
    let root = "at://did:plc:a/app.bsky.feed.post/1";

    // getPostThread returns newest-first: candidate -> parent -> root.
    // The candidate node also carries a `post`; ancestors are its `parent` chain.
    let response = json!({
        "thread": thread_node(
            "did:plc:c",
            "candidate text",
            thread_node("did:plc:b", "parent text", thread_node("did:plc:a", "root text", serde_json::Value::Null))
        )
    });
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", candidate))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    let ancestors = enricher.fetch_thread_ancestors(candidate).await;
    assert_eq!(ancestors.len(), 2);
    assert_eq!(ancestors[0].author_did, "did:plc:a");
    assert_eq!(ancestors[0].text, "root text");
    assert_eq!(ancestors[1].author_did, "did:plc:b");
    assert_eq!(ancestors[1].text, "parent text");
    let _ = (parent, root);
}

#[tokio::test]
async fn thread_ancestors_degrade_gracefully_on_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;
    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    assert!(enricher
        .fetch_thread_ancestors("at://did:plc:x/app.bsky.feed.post/1")
        .await
        .is_empty());
}

#[tokio::test]
async fn enrich_fetches_threads_when_enabled() {
    let mock_server = MockServer::start().await;
    let author = "did:plc:bob";
    let parent_uri = "at://did:plc:alice/app.bsky.feed.post/1";

    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": author, "handle": "bob.bsky.social"
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [{
                "uri": parent_uri,
                "cid": "bafy_parent_cid",
                "author": { "did": "did:plc:alice" },
                "record": { "text": "parent body" }
            }]
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": thread_node(
                author,
                "reply body",
                thread_node("did:plc:alice", "parent body", serde_json::Value::Null)
            )
        })))
        .mount(&mock_server)
        .await;

    let enricher =
        AppViewContextEnricher::with_endpoint(mock_server.uri()).with_thread_context(true);
    assert!(enricher.thread_context_enabled());

    let interaction = Interaction::new(
        author,
        "did:plc:alice",
        InteractionType::DirectReply,
        "at://did:plc:bob/app.bsky.feed.post/2",
        "cid_2",
        "reply body",
    )
    .with_parent_uri(parent_uri);

    let ctx = enricher.enrich(&interaction).await;
    assert_eq!(ctx.thread_ancestors.len(), 1);
    assert_eq!(ctx.thread_ancestors[0].author_did, "did:plc:alice");
    let formatted = ctx.format_for_classifier();
    assert!(formatted.contains("Conversation Thread (oldest → newest):"));
    assert!(formatted.contains("parent body"));
    // Thread rendering replaces the single parent-post line.
    assert!(!formatted.contains("In Reply To"));
}

#[tokio::test]
async fn enrich_skips_threads_by_default() {
    let mock_server = MockServer::start().await;
    let author = "did:plc:bob";
    let parent_uri = "at://did:plc:alice/app.bsky.feed.post/1";
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [{
                "author": { "did": "did:plc:alice" },
                "record": { "text": "parent body" }
            }]
        })))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    assert!(!enricher.thread_context_enabled());
    let interaction = Interaction::new(
        author,
        "did:plc:alice",
        InteractionType::DirectReply,
        "at://did:plc:bob/app.bsky.feed.post/2",
        "cid_2",
        "reply body",
    )
    .with_parent_uri(parent_uri);

    let ctx = enricher.enrich(&interaction).await;
    assert!(ctx.thread_ancestors.is_empty());
    assert!(ctx.format_for_classifier().contains("In Reply To"));
}

#[tokio::test]
async fn enrich_caps_thread_ancestors_to_max_rendered() {
    // The mock returns a deep chain; only the newest MAX_RENDERED_THREAD_ANCESTORS
    // are retained.
    let mock_server = MockServer::start().await;
    let author = "did:plc:root";
    let parent_uri = "at://did:plc:p/app.bsky.feed.post/deep";

    let mut node = thread_node("did:plc:depth0", "text 0", serde_json::Value::Null);
    for i in 1..20 {
        node = thread_node(&format!("did:plc:depth{i}"), &format!("text {i}"), node);
    }
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "thread": node })))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    let ancestors = enricher.fetch_thread_ancestors(parent_uri).await;
    assert!(ancestors.len() <= MAX_RENDERED_THREAD_ANCESTORS);
    // The outer node is depth 19 (the candidate); its newest ancestor is depth 18.
    assert_eq!(ancestors.last().unwrap().author_did, "did:plc:depth18");
    assert_eq!(ancestors.first().unwrap().author_did, "did:plc:depth11");
    let _ = author;
}

#[tokio::test]
async fn dynamic_primary_routes_images_to_multimodal() {
    let text = Arc::new(MockClassifier::permitted());
    let mm = Arc::new(MockClassifier::violation(
        ViolationCategory::CryptoSpam,
        0.93,
        "image is a wallet-drainer QR code",
    ));
    let classifier =
        DynamicPrimaryClassifier::new(text.clone(), mm.clone(), DynamicModelPolicy::default());

    let text_only = Interaction::mock_test_candidate("did:plc:a", "did:plc:t", "just chatting");
    assert!(classifier
        .classify(&text_only)
        .await
        .unwrap()
        .is_permitted());
    assert_eq!(text.call_count(), 1);
    assert_eq!(mm.call_count(), 0);

    let mut with_image = Interaction::mock_test_candidate("did:plc:a", "did:plc:t", "look at this");
    with_image.image_cids = vec!["bafyimg".to_string()];
    let verdict = classifier.classify(&with_image).await.unwrap();
    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::CryptoSpam));
    assert_eq!(mm.call_count(), 1);

    let snap = classifier.stats().snapshot();
    assert_eq!(snap.text_routed, 1);
    assert_eq!(snap.multimodal_routed, 1);
}

#[tokio::test]
async fn dynamic_primary_disabled_image_routing_uses_text_primary() {
    let text = Arc::new(MockClassifier::permitted());
    let mm = Arc::new(MockClassifier::violation(
        ViolationCategory::Spam,
        0.9,
        "mm",
    ));
    let policy = DynamicModelPolicy::new("nimble", "clef-flash", false);
    let classifier = DynamicPrimaryClassifier::new(text.clone(), mm.clone(), policy);

    let mut with_image = Interaction::mock_test_candidate("did:plc:a", "did:plc:t", "look at this");
    with_image.image_cids = vec!["bafyimg".to_string()];
    let verdict = classifier.classify(&with_image).await.unwrap();
    assert!(verdict.is_permitted());
    assert_eq!(text.call_count(), 1);
    assert_eq!(mm.call_count(), 0);
    // With image escalation disabled, selection always uses the text-only model.
    assert_eq!(classifier.policy().select_model(false), "nimble");
    assert_eq!(classifier.policy().select_model(true), "nimble");
}

#[tokio::test]
async fn dynamic_primary_propagates_rubric_and_model_name() {
    let text = Arc::new(MockClassifier::permitted());
    let mm = Arc::new(MockClassifier::permitted());
    let classifier =
        DynamicPrimaryClassifier::new(text.clone(), mm.clone(), DynamicModelPolicy::default());
    let rubric = skybouncer::classifier::RuleRubric::default();
    classifier.set_rubric(rubric.clone());
    assert_eq!(text.rubric(), Some(rubric.clone()));
    assert_eq!(mm.rubric(), Some(rubric));
    assert_eq!(classifier.model_name(), "mock");
}

#[tokio::test]
async fn thread_context_renders_under_char_cap() {
    let mut ctx = EnrichedContext::empty();
    let long = "x".repeat(1000);
    ctx.thread_ancestors = vec![ThreadPost {
        author_did: "did:plc:a".to_string(),
        text: long,
    }];
    let rendered = ctx.format_for_classifier();
    // Snippet is capped well below the 1000-char input.
    assert!(rendered.len() < 400);
    assert!(rendered.contains("Conversation Thread"));
    let _ = Verdict::permitted("x");
}
