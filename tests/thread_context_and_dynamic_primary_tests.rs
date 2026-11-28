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

#[tokio::test]
async fn test_pr2_dynamic_primary_reports_actual_routed_model_and_builder_wiring() {
    use skybase::repo::PdsRepoClient;
    use skybouncer::classifier::{
        CertaintyConfig, JevClassifier, JevConfig, RuleRubric, Sensitivity, TieredClassifier,
    };
    use skybouncer::engine::{SkybouncerConfig, SkybouncerEngineBuilder};
    use skybouncer::modlist::DeduplicationCache;
    use std::collections::HashSet;
    use std::time::Duration;

    // 1. DynamicPrimaryClassifier + TieredClassifier report actual routed primary model name
    let text_srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": false,
            "confidence": 0.96,
            "reason": "clean text"
        })))
        .mount(&text_srv)
        .await;

    let mm_srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {
                "role": "assistant",
                "content": "{\"violates\": true, \"category\": \"spam\", \"confidence\": 0.93, \"reason\": \"crypto spam meme\"}"
            }
        })))
        .mount(&mm_srv)
        .await;

    let fallback_srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {
                "role": "assistant",
                "content": "{\"violates\": false, \"confidence\": 0.99, \"reason\": \"unused\"}"
            }
        })))
        .mount(&fallback_srv)
        .await;

    let text_cfg = JevConfig {
        base_url: text_srv.uri(),
        api_key: None,
        model: "text-model-builder".to_string(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        supports_images: false,
    };
    let mm_cfg = JevConfig {
        base_url: format!("{}/api/chat", mm_srv.uri()),
        api_key: None,
        model: "mm-model-builder".to_string(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        supports_images: true,
    };
    let fb_cfg = JevConfig {
        base_url: format!("{}/api/chat", fallback_srv.uri()),
        api_key: None,
        model: "fallback-model-builder".to_string(),
        timeout: Duration::from_secs(2),
        max_retries: 0,
        supports_images: false,
    };

    let text_primary: Arc<dyn Classifier> =
        Arc::new(JevClassifier::new(text_cfg.clone(), RuleRubric::default()).unwrap());
    let mm_primary: Arc<dyn Classifier> =
        Arc::new(JevClassifier::new(mm_cfg.clone(), RuleRubric::default()).unwrap());
    let fallback: Arc<dyn Classifier> =
        Arc::new(JevClassifier::new(fb_cfg.clone(), RuleRubric::default()).unwrap());

    let policy = DynamicModelPolicy::new("text-model-builder", "mm-model-builder", true);
    let dyn_primary: Arc<dyn Classifier> = Arc::new(DynamicPrimaryClassifier::new(
        text_primary,
        mm_primary,
        policy,
    ));
    let tiered = TieredClassifier::new(
        dyn_primary,
        fallback,
        CertaintyConfig::default().with_escalate_on_images(false),
    );

    let text_inter = Interaction {
        post_uri: "at://did:plc:auth/app.bsky.feed.post/1".to_string(),
        post_cid: None,
        author_did: "did:plc:auth".to_string(),
        target_did: "did:plc:target".to_string(),
        text: "hello".to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: None,
        root_uri: None,
        quote_uri: None,
        created_at_us: 1_700_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    };
    let mut img_inter = text_inter.clone();
    img_inter.post_uri = "at://did:plc:auth2/app.bsky.feed.post/2".to_string();
    img_inter.author_did = "did:plc:auth2".to_string();
    img_inter.image_cids = vec!["bafyrei_img".to_string()];

    let text_res = tiered.classify_detailed(&text_inter).await.unwrap();
    assert_eq!(text_res.primary_model, "text-model-builder");
    assert!(!text_res.escalated);

    let img_res = tiered.classify_detailed(&img_inter).await.unwrap();
    assert_eq!(img_res.primary_model, "mm-model-builder");
    assert!(!img_res.escalated);

    // 2. SkybouncerEngineBuilder wires jev_config, multimodal_jev_config, fallback_jev_config, certainty_config
    let mut protected = HashSet::new();
    protected.insert("did:plc:target".to_string());
    let mut cfg =
        SkybouncerConfig::new(protected, RuleRubric::new("Be polite", Sensitivity::Medium))
            .with_dry_run(true);
    cfg.jev_config = Some(text_cfg);
    cfg.multimodal_jev_config = Some(mm_cfg);
    cfg.fallback_jev_config = Some(fb_cfg);
    cfg.certainty_config = CertaintyConfig::new(0.45, 0.85, true);

    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let pds_client = Arc::new(
        PdsRepoClient::from_credentials("https://bsky.social", "did:plc:target", "mock_token")
            .unwrap(),
    );

    let engine = SkybouncerEngineBuilder::new(cfg)
        .with_cache(Arc::clone(&cache))
        .with_pds_client(pds_client)
        .build()
        .expect("builder should wire DynamicModelPolicy and TieredClassifier");

    let text_reqs_before = text_srv.received_requests().await.unwrap().len();
    let mm_reqs_before = mm_srv.received_requests().await.unwrap().len();
    let fb_reqs_before = fallback_srv.received_requests().await.unwrap().len();

    // Image candidate routes to mm_srv (and does NOT redundantly escalate to fallback_srv because mm handles images)
    let outcome = engine.evaluate_candidate(img_inter).await.unwrap();
    assert!(outcome.is_bounced());
    assert_eq!(
        mm_srv.received_requests().await.unwrap().len(),
        mm_reqs_before + 1
    );
    assert_eq!(
        text_srv.received_requests().await.unwrap().len(),
        text_reqs_before
    );
    assert_eq!(
        fallback_srv.received_requests().await.unwrap().len(),
        fb_reqs_before
    );

    // Check evaluation log recorded the actual routed multimodal model name, not static text model
    let logs = cache.list_evaluation_logs(None, None, 10, 0).unwrap();
    assert!(!logs.is_empty());
    assert_eq!(logs[0].primary_model, "mm-model-builder");
}
