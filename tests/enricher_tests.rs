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

#[tokio::test]
async fn test_appview_enricher_accessors_and_defaults() {
    let e = AppViewContextEnricher::new();
    assert_eq!(e.appview_url(), "https://public.api.bsky.app");
    assert_eq!(e.cdn_url(), "https://cdn.bsky.app");
    // Default delegates to new().
    let d = AppViewContextEnricher::default();
    assert_eq!(d.appview_url(), "https://public.api.bsky.app");
    // from_endpoint uses the default CDN.
    let ep = AppViewContextEnricher::with_endpoint("https://custom.example");
    assert_eq!(ep.appview_url(), "https://custom.example");
    assert_eq!(ep.cdn_url(), "https://cdn.bsky.app");
}

#[tokio::test]
async fn test_appview_fetch_image_sanitizes_and_handles_non_success() {
    let mock_server = MockServer::start().await;
    // A 404 on the sanitized URL returns None.
    Mock::given(method("GET"))
        .and(path(
            "/img/feed_thumbnail/plain/did:plc:bob/bafymissing@jpeg",
        ))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoints(mock_server.uri(), mock_server.uri());
    assert!(enricher
        .fetch_image_base64("did:plc:bob", "bafymissing")
        .await
        .is_none());

    // Non-alphanumeric characters are stripped from the DID/CID; if fully stripped, None.
    assert!(enricher.fetch_image_base64("!!!", "???").await.is_none());

    // Batch of none-fetchable images yields an empty vec.
    let batch = enricher
        .fetch_images_base64("did:plc:bob", &["bafymissing".to_string()])
        .await;
    assert!(batch.is_empty());
}

#[tokio::test]
async fn test_mock_enricher_handle_resolution_and_did() {
    let enricher = MockContextEnricher::new();
    enricher.set_handle("alice.bsky.social", "did:plc:alice");
    assert_eq!(
        enricher.resolve_handle("@alice.bsky.social").await,
        Some("did:plc:alice".to_string())
    );
    // DID passthrough.
    assert_eq!(
        enricher.resolve_handle("did:plc:existing").await,
        Some("did:plc:existing".to_string())
    );
    // Unknown handle -> None.
    assert_eq!(enricher.resolve_handle("nobody.bsky.social").await, None);

    // resolve_did via the handle map reverse lookup.
    assert_eq!(
        enricher.resolve_did("did:plc:alice").await,
        Some("alice.bsky.social".to_string())
    );
    assert_eq!(enricher.resolve_did("did:plc:unknown").await, None);
}

#[tokio::test]
async fn test_mock_enricher_target_and_quoted_post_formatting() {
    let enricher = MockContextEnricher::new();
    enricher.set_target(
        "did:plc:target",
        AuthorContext {
            handle: Some("protected.bsky.social".to_string()),
            display_name: Some("Protected User".to_string()),
            description: Some("Civic researcher".to_string()),
            ..Default::default()
        },
    );
    enricher.set_quoted_post(
        "at://did:plc:target/app.bsky.feed.post/quoted1",
        ParentPostContext {
            author_did: "did:plc:target".to_string(),
            text: "Full roll-call breakdown of Tuesday's vote.".to_string(),
            cid: Some("bafyquoted1".to_string()),
        },
    );

    let interaction = Interaction::new(
        "did:plc:commenter",
        "did:plc:target",
        InteractionType::Quote,
        "at://did:plc:commenter/app.bsky.feed.post/q1",
        "bafyq1",
        "Read this thread before yelling at them!",
    )
    .with_quote_uri("at://did:plc:target/app.bsky.feed.post/quoted1");

    let ctx = enricher.enrich(&interaction).await;
    assert!(!ctx.is_empty());
    assert!(ctx.target.is_some());
    assert!(ctx.quoted_post.is_some());

    let rendered = ctx.format_for_classifier();
    assert!(rendered.contains("Target Profile (protected user) [handle: @protected.bsky.social, name: \"Protected User\", bio: \"Civic researcher\"]"));
    assert!(rendered.contains(
        "Quoted Post (by did:plc:target): \"Full roll-call breakdown of Tuesday's vote.\""
    ));
}

#[tokio::test]
async fn test_appview_enricher_target_profile_cache_and_quoted_post() {
    let mock_server = MockServer::start().await;
    let author_did = "did:plc:commenter";
    let target_did = "did:plc:protected";
    let quote_uri = "at://did:plc:protected/app.bsky.feed.post/exp1";

    // Target profile endpoint MUST be hit only ONCE across two enrich() calls due to target_cache!
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .and(query_param("actor", target_did))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": target_did,
            "handle": "protected.example.com",
            "displayName": "Protected Host",
            "description": "Protected bio"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .and(query_param("actor", author_did))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": author_did,
            "handle": "commenter.bsky.social"
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .and(query_param("uris", quote_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [{
                "uri": quote_uri,
                "cid": "bafyexp1",
                "author": { "did": target_did, "handle": "protected.example.com" },
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "Explainer post content"
                }
            }]
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoint(mock_server.uri());
    let interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:commenter/app.bsky.feed.post/1",
        "bafy1",
        "Great breakdown here",
    )
    .with_quote_uri(quote_uri);

    let ctx1 = enricher.enrich(&interaction).await;
    let ctx2 = enricher.enrich(&interaction).await;
    assert_eq!(ctx1, ctx2);
    assert_eq!(
        ctx1.target.as_ref().and_then(|t| t.handle.as_deref()),
        Some("protected.example.com")
    );
    assert_eq!(
        ctx1.quoted_post.as_ref().map(|q| q.text.as_str()),
        Some("Explainer post content")
    );
}

#[tokio::test]
async fn test_appview_enricher_hops_across_blocked_post_boundary() {
    let mock_server = MockServer::start().await;
    let parent_uri = "at://did:plc:target/app.bsky.feed.post/parent";
    let blocked_gp_uri = "at://did:plc:other/app.bsky.feed.post/grandparent";
    let root_uri = "at://did:plc:troll/app.bsky.feed.post/root";

    // Hop 1: querying parent_uri hits a `#blockedPost` at parent.parent!
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", parent_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": parent_uri,
                    "author": { "did": "did:plc:target" },
                    "record": { "$type": "app.bsky.feed.post", "text": "\"nuh uh\"" }
                },
                "parent": {
                    "$type": "app.bsky.feed.defs#blockedPost",
                    "uri": blocked_gp_uri,
                    "blocked": true
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Hop 2: querying blocked_gp_uri recovers both the blocked grandparent AND the root post!
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", blocked_gp_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": blocked_gp_uri,
                    "author": { "did": "did:plc:other" },
                    "record": { "$type": "app.bsky.feed.post", "text": "No." }
                },
                "parent": {
                    "$type": "app.bsky.feed.defs#threadViewPost",
                    "post": {
                        "uri": root_uri,
                        "author": { "did": "did:plc:troll" },
                        "record": { "$type": "app.bsky.feed.post", "text": "Bad faith strawman claim" }
                    },
                    "parent": null
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let enricher =
        AppViewContextEnricher::with_endpoint(mock_server.uri()).with_thread_context(true);
    let interaction = Interaction::new(
        "did:plc:other",
        "did:plc:target",
        InteractionType::DirectReply,
        "at://did:plc:other/app.bsky.feed.post/candidate",
        "bafycand",
        "He's arguing a straw man and being stupid on purpose.",
    )
    .with_parent_uri(parent_uri);

    let ctx = enricher.enrich(&interaction).await;
    assert_eq!(ctx.thread_ancestors.len(), 3);
    assert_eq!(ctx.thread_ancestors[0].text, "Bad faith strawman claim");
    assert_eq!(ctx.thread_ancestors[1].text, "No.");
    assert_eq!(ctx.thread_ancestors[2].text, "\"nuh uh\"");

    let role_formatted =
        ctx.format_for_interaction(&interaction.author_did, &interaction.target_did);
    assert!(role_formatted.contains("[1] OtherUser (did:plc:troll): \"Bad faith strawman claim\""));
    assert!(role_formatted.contains("[2] Author (did:plc:other): \"No.\""));
    assert!(role_formatted.contains("[3] Target (did:plc:target): \"\"nuh uh\"\""));
    assert!(role_formatted.contains("[IMMEDIATE PARENT — Author is replying to this post]"));
}

#[test]
fn test_subthread_reply_marks_immediate_other_user_parent_for_interaction() {
    use skybouncer::enricher::{EnrichedContext, ParentPostContext, ThreadPost};

    let target_did = "did:plc:mmtjkssv6jeneahkgfdxuy7p";
    let author_did = "did:plc:qgzzrfoh3fapodvfpeqjbtii";
    let immediate_other_did = "did:plc:kpizu7db55xo3m3vy5alpwaf";
    let third_did = "did:plc:ttabju4hgr5y6abt353dtkbd";

    let mut ctx = EnrichedContext::empty();
    ctx.parent_post = Some(ParentPostContext {
        author_did: immediate_other_did.to_string(),
        text: "AIPAC doesn't necessarily mean Jews...".to_string(),
        cid: Some("bafyparent".to_string()),
    });
    ctx.thread_ancestors = vec![
        ThreadPost {
            author_did: target_did.to_string(),
            text: "Root thread opener".to_string(),
        },
        ThreadPost {
            author_did: third_did.to_string(),
            text: "Intermediate sub-thread reply".to_string(),
        },
        ThreadPost {
            author_did: immediate_other_did.to_string(),
            text: "AIPAC doesn't necessarily mean Jews...".to_string(),
        },
    ];

    // Role-aware formatting marks ONLY the immediate parent post.
    let role_formatted = ctx.format_for_interaction(author_did, target_did);
    assert!(role_formatted.contains(&format!(
        "[3] OtherUser ({immediate_other_did}): \"AIPAC doesn't necessarily mean Jews...\" [IMMEDIATE PARENT — Author is replying to this post]"
    )));
    assert_eq!(
        role_formatted
            .matches("[IMMEDIATE PARENT — Author is replying to this post]")
            .count(),
        1
    );
    assert!(!role_formatted.contains("In Reply To (by"));

    // Role-less format_for_classifier remains compact and unchanged.
    let raw_formatted = ctx.format_for_classifier();
    assert!(!raw_formatted.contains("[IMMEDIATE PARENT"));
    assert!(!raw_formatted.contains("In Reply To"));

    // If parent_post author differs from the last resolved ancestor (e.g. partial thread fetch),
    // In Reply To is emitted explicitly alongside Conversation Thread.
    ctx.parent_post = Some(ParentPostContext {
        author_did: "did:plc:unlisted_parent".to_string(),
        text: "Separate immediate parent".to_string(),
        cid: None,
    });
    let mismatched = ctx.format_for_interaction(author_did, target_did);
    assert!(!mismatched.contains("[IMMEDIATE PARENT"));
    assert!(mismatched.contains(
        "In Reply To (by OtherUser (did:plc:unlisted_parent)): \"Separate immediate parent\""
    ));
}

#[tokio::test]
async fn test_appview_enricher_preserves_ancestor_quote_embeds_for_interaction() {
    let mock_server = MockServer::start().await;
    let target_did = "did:plc:mmtjkssv6jeneahkgfdxuy7p";
    let author_did = "did:plc:lqvsqsm4bjxqeue3bulyhvwl";
    let root_author_did = "did:plc:sailormichael0000000000";
    let quoted_did = "did:plc:7umvpuxe2vbrc3zrzuquzniu";
    let third_did = "did:plc:commenter111111111111111";
    let media_quoted_did = "did:plc:quotedmedia222222222222";
    let parent_uri = "at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/3n27fphhcx22b";

    // Ancestor chain ordered oldest -> newest:
    // [1] root with `app.bsky.embed.record#view`
    // [2] intermediate with `app.bsky.embed.recordWithMedia#view`
    // [3] intermediate with non-quote `app.bsky.embed.images#view` (ignored -> None)
    // [4] immediate parent with blocked quote `#viewBlocked` (ignored -> None)
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", parent_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": parent_uri,
                    "author": { "did": target_did },
                    "record": { "$type": "app.bsky.feed.post", "text": "Charmin really earned that ratio." },
                    "embed": {
                        "$type": "app.bsky.embed.record#view",
                        "record": {
                            "$type": "app.bsky.embed.record#viewBlocked",
                            "uri": "at://did:plc:blocked/app.bsky.feed.post/1",
                            "blocked": true
                        }
                    }
                },
                "parent": {
                    "$type": "app.bsky.feed.defs#threadViewPost",
                    "post": {
                        "uri": "at://did:plc:commenter/app.bsky.feed.post/3",
                        "author": { "did": third_did },
                        "record": { "$type": "app.bsky.feed.post", "text": "Screenshot attached." },
                        "embed": {
                            "$type": "app.bsky.embed.images#view",
                            "images": [{ "fullsize": "https://cdn.bsky.app/img/1.jpg", "alt": "chart" }]
                        }
                    },
                    "parent": {
                        "$type": "app.bsky.feed.defs#threadViewPost",
                        "post": {
                            "uri": "at://did:plc:target/app.bsky.feed.post/2",
                            "author": { "did": target_did },
                            "record": { "$type": "app.bsky.feed.post", "text": "Look at the follow-up too." },
                            "embed": {
                                "$type": "app.bsky.embed.recordWithMedia#view",
                                "record": {
                                    "record": {
                                        "$type": "app.bsky.embed.record#viewRecord",
                                        "author": {
                                            "did": media_quoted_did,
                                            "handle": "mediaquoted.bsky.social"
                                        },
                                        "value": { "text": "Original quoted take with media." }
                                    }
                                },
                                "media": { "$type": "app.bsky.embed.images#view", "images": [] }
                            }
                        },
                        "parent": {
                            "$type": "app.bsky.feed.defs#threadViewPost",
                            "post": {
                                "uri": "at://did:plc:root/app.bsky.feed.post/1",
                                "author": { "did": root_author_did },
                                "record": { "$type": "app.bsky.feed.post", "text": "Unbelievable meltdown." },
                                "embed": {
                                    "$type": "app.bsky.embed.record#view",
                                    "record": {
                                        "$type": "app.bsky.embed.record#viewRecord",
                                        "author": {
                                            "did": quoted_did,
                                            "handle": "@whstancil.bsky.social"
                                        },
                                        "value": { "text": "I am very mad online about being criticized." }
                                    }
                                }
                            },
                            "parent": null
                        }
                    }
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let enricher =
        AppViewContextEnricher::with_endpoint(mock_server.uri()).with_thread_context(true);
    let interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::DirectReply,
        "at://did:plc:lqvsqsm4bjxqeue3bulyhvwl/app.bsky.feed.post/3n27g24tm3s26",
        "bafycand",
        "And now he's super sad this morning.",
    )
    .with_parent_uri(parent_uri);

    let ctx = enricher.enrich(&interaction).await;
    assert_eq!(ctx.thread_ancestors.len(), 4);
    assert_eq!(ctx.thread_ancestor_quotes.len(), 4);
    assert_eq!(
        ctx.thread_ancestor_quotes[0]
            .as_ref()
            .and_then(|q| q.author_handle.as_deref()),
        Some("whstancil.bsky.social")
    );
    assert_eq!(
        ctx.thread_ancestor_quotes[1]
            .as_ref()
            .and_then(|q| q.author_handle.as_deref()),
        Some("mediaquoted.bsky.social")
    );
    assert!(ctx.thread_ancestor_quotes[2].is_none());
    assert!(ctx.thread_ancestor_quotes[3].is_none());

    let role_formatted = ctx.format_for_interaction(author_did, target_did);
    assert!(role_formatted.contains(&format!(
        "[1] OtherUser ({root_author_did}): \"Unbelievable meltdown.\" [quoting OtherUser @whstancil.bsky.social ({quoted_did}): \"I am very mad online about being criticized.\"]"
    )));
    assert!(role_formatted.contains(&format!(
        "[2] Target ({target_did}): \"Look at the follow-up too.\" [quoting OtherUser @mediaquoted.bsky.social ({media_quoted_did}): \"Original quoted take with media.\"]"
    )));
    assert!(role_formatted.contains(&format!(
        "[4] Target ({target_did}): \"Charmin really earned that ratio.\" [IMMEDIATE PARENT — Author is replying to this post]"
    )));

    // `format_for_classifier()` must remain unchanged without role or quote annotations.
    let raw_formatted = ctx.format_for_classifier();
    assert!(!raw_formatted.contains("[quoting"));
    assert!(!raw_formatted.contains("[IMMEDIATE PARENT"));

    // Public `fetch_thread_ancestors` keeps its original signature and returns `Vec<ThreadPost>`.
    let raw_chain = enricher.fetch_thread_ancestors(parent_uri).await;
    assert_eq!(raw_chain.len(), 3);
}

#[tokio::test]
async fn test_quoted_ancestor_target_author_roles_is_empty_and_image_enrich() {
    use skybouncer::enricher::{EnrichedContext, QuotedAncestor, ThreadPost};

    let target_did = "did:plc:target_role";
    let author_did = "did:plc:author_role";

    // `is_empty()` treats all-`None` `thread_ancestor_quotes` as empty, and non-`None` as non-empty.
    let mut ctx = EnrichedContext::empty();
    ctx.thread_ancestor_quotes = vec![None];
    assert!(ctx.is_empty());

    ctx.thread_ancestor_quotes = vec![Some(QuotedAncestor {
        author_did: target_did.to_string(),
        author_handle: None,
        text: "Quoted Target without handle".to_string(),
    })];
    assert!(!ctx.is_empty());

    // Role formatting covers `Target (did)` (no handle) and `Author @handle (did)` quote labels.
    ctx.thread_ancestors = vec![
        ThreadPost {
            author_did: "did:plc:other".to_string(),
            text: "First post".to_string(),
        },
        ThreadPost {
            author_did: target_did.to_string(),
            text: "Second post".to_string(),
        },
    ];
    ctx.thread_ancestor_quotes = vec![
        Some(QuotedAncestor {
            author_did: target_did.to_string(),
            author_handle: None,
            text: "Quoted Target without handle".to_string(),
        }),
        Some(QuotedAncestor {
            author_did: author_did.to_string(),
            author_handle: Some("author.bsky.social".to_string()),
            text: "Quoted Author with handle".to_string(),
        }),
    ];
    let formatted = ctx.format_for_interaction(author_did, target_did);
    assert!(formatted.contains(&format!(
        "[quoting Target ({target_did}): \"Quoted Target without handle\"]"
    )));
    assert!(formatted.contains(&format!(
        "[quoting Author @author.bsky.social ({author_did}): \"Quoted Author with handle\"]"
    )));

    // `AppViewContextEnricher::enrich` exercises image fetching when `interaction.has_images()`.
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/img/feed_thumbnail/plain/{author_did}/bafkreiimg@jpeg"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"IMG".to_vec()))
        .mount(&mock_server)
        .await;

    let enricher = AppViewContextEnricher::with_endpoints(mock_server.uri(), mock_server.uri());
    let mut img_interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::Mention,
        "at://did:plc:author_role/app.bsky.feed.post/1",
        "bafy1",
        "check this image",
    );
    img_interaction.image_cids = vec!["bafkreiimg".to_string()];

    let enriched = enricher.enrich(&img_interaction).await;
    assert_eq!(enriched.images_base64, vec!["SU1H".to_string()]);
}

#[tokio::test]
async fn test_appview_enricher_standalone_quote_resolves_quoted_thread_and_skips_plain_root() {
    let mock_server = MockServer::start().await;
    let target_did = "did:plc:mmtjkssv6jeneahkgfdxuy7p";
    let author_did = "did:plc:qwpty6y2kbyathbxlfcejz2p";
    let interlocutor_did = "did:plc:vasmwozbxda25bah7d6sb3ja";
    let quoted_other_did = "did:plc:otherquoted000000000000";

    // Case 1: Multi-post quoted thread (models 3n264mmxavs2v at bottom of Chuck Schumer debate).
    let thread_quote_uri = "at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/3n264mmxavs2v";
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .and(query_param("uris", thread_quote_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [{
                "uri": thread_quote_uri,
                "cid": "bafyquotedthread",
                "author": { "did": target_did, "handle": "mike10010100.com" },
                "record": { "$type": "app.bsky.feed.post", "text": "So just the two things then.\n\nOr will there inevitably be more?" }
            }]
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", thread_quote_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": thread_quote_uri,
                    "author": { "did": target_did },
                    "record": { "$type": "app.bsky.feed.post", "text": "So just the two things then.\n\nOr will there inevitably be more?" }
                },
                "parent": {
                    "$type": "app.bsky.feed.defs#threadViewPost",
                    "post": {
                        "uri": "at://did:plc:vasmwozbxda25bah7d6sb3ja/app.bsky.feed.post/13",
                        "author": { "did": interlocutor_did },
                        "record": { "$type": "app.bsky.feed.post", "text": "So yes I find Schumer uniquely unsatisfactory for the job" }
                    },
                    "parent": {
                        "$type": "app.bsky.feed.defs#threadViewPost",
                        "post": {
                            "uri": "at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/12",
                            "author": { "did": target_did },
                            "record": { "$type": "app.bsky.feed.post", "text": "How fascinating, your list of reasons to dislike a very particular politician go back decades!" }
                        },
                        "parent": null
                    }
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Case 2: Standalone quote of a single root post that itself embeds a quote (`!quotes.is_empty()`).
    let nested_quote_uri = "at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/nestedroot";
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .and(query_param("uris", nested_quote_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [{
                "uri": nested_quote_uri,
                "cid": "bafynestedroot",
                "author": { "did": target_did, "handle": "mike10010100.com" },
                "record": { "$type": "app.bsky.feed.post", "text": "Charmin." }
            }]
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", nested_quote_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": nested_quote_uri,
                    "author": { "did": target_did },
                    "record": { "$type": "app.bsky.feed.post", "text": "Charmin." },
                    "embed": {
                        "$type": "app.bsky.embed.record#view",
                        "record": {
                            "$type": "app.bsky.embed.record#viewRecord",
                            "author": { "did": quoted_other_did, "handle": "other.bsky.social" },
                            "value": { "text": "People are being mean to me." }
                        }
                    }
                },
                "parent": null
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Case 3: Standalone quote of a plain single root post (no parents, no embedded quote).
    let plain_root_uri = "at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/plainroot";
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .and(query_param("uris", plain_root_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [{
                "uri": plain_root_uri,
                "cid": "bafyplainroot",
                "author": { "did": target_did, "handle": "mike10010100.com" },
                "record": { "$type": "app.bsky.feed.post", "text": "Plain root take." }
            }]
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", plain_root_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": plain_root_uri,
                    "author": { "did": target_did },
                    "record": { "$type": "app.bsky.feed.post", "text": "Plain root take." }
                },
                "parent": null
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let enricher =
        AppViewContextEnricher::with_endpoint(mock_server.uri()).with_thread_context(true);

    // 1. Multi-post quoted thread is retained and tagged `[QUOTED POST]`, NOT `[IMMEDIATE PARENT]`.
    let thread_quote_interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:qwpty6y2kbyathbxlfcejz2p/app.bsky.feed.post/3n27kxiexm22j",
        "bafy3n27",
        "Chuck supporters are the dumbest fucks around.",
    )
    .with_quote_uri(thread_quote_uri);
    let ctx_thread = enricher.enrich(&thread_quote_interaction).await;
    assert_eq!(ctx_thread.thread_ancestors.len(), 3);
    assert!(ctx_thread.parent_post.is_none());
    assert!(ctx_thread.quoted_post.is_some());
    let rendered_thread = ctx_thread.format_for_interaction(author_did, target_did);
    assert!(rendered_thread.contains("Schumer uniquely unsatisfactory"));
    assert!(rendered_thread.contains("[QUOTED POST — Author is quote-posting this post]"));
    assert!(!rendered_thread.contains("[IMMEDIATE PARENT"));
    assert!(rendered_thread.contains(&format!("Quoted Post (by Target ({target_did})):")));

    // 2. Single root post with a nested quote embed preserves `thread_ancestors` and `[quoting OtherUser ...]`.
    let nested_quote_interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:qwpty6y2kbyathbxlfcejz2p/app.bsky.feed.post/qnested",
        "bafyqnested",
        "Look at this guy lol",
    )
    .with_quote_uri(nested_quote_uri);
    let ctx_nested = enricher.enrich(&nested_quote_interaction).await;
    assert_eq!(ctx_nested.thread_ancestors.len(), 1);
    assert_eq!(ctx_nested.thread_ancestor_quotes.len(), 1);
    let rendered_nested = ctx_nested.format_for_interaction(author_did, target_did);
    assert!(rendered_nested.contains("[quoting OtherUser @other.bsky.social"));
    assert!(rendered_nested.contains("[QUOTED POST — Author is quote-posting this post]"));

    // 3. Plain single root post omits redundant `thread_ancestors` while preserving `Quoted Post`.
    let plain_quote_interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:qwpty6y2kbyathbxlfcejz2p/app.bsky.feed.post/qplain",
        "bafyqplain",
        "Worst take ever.",
    )
    .with_quote_uri(plain_root_uri);
    let ctx_plain = enricher.enrich(&plain_quote_interaction).await;
    assert!(ctx_plain.thread_ancestors.is_empty());
    assert!(ctx_plain.thread_ancestor_quotes.is_empty());
    let rendered_plain = ctx_plain.format_for_interaction(author_did, target_did);
    assert!(!rendered_plain.contains("Conversation Thread"));
    assert!(rendered_plain.contains(&format!(
        "Quoted Post (by Target ({target_did})): \"Plain root take.\""
    )));
}

#[tokio::test]
async fn test_appview_enricher_ari_nested_view_record_and_format_preservation() {
    use skybouncer::enricher::ContextImageRef;

    let mock_server = MockServer::start().await;
    let target_did = "did:plc:mmtjkssv6jeneahkgfdxuy7p";
    let author_did = "did:plc:jbbiqk7nyatsivk2mboyqm6t";
    let quoted_did = "did:plc:ktc7mkfqnint7hmviye6wizr";
    let parent_uri = "at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/3n2bnzagrqk2m";
    let screenshot_cid = "bafkreigx7ubyrt2jyulj5e45yb5br3yq4teohelvrm52454gpsnpzto6ti";

    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .and(query_param("uris", parent_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [{
                "uri": parent_uri,
                "cid": "bafyparent3n2b",
                "author": { "did": target_did, "handle": "mike10010100.com" },
                "record": { "$type": "app.bsky.feed.post", "text": "LMAO they're still blaming Buttigieg? Wild." }
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", parent_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": parent_uri,
                    "author": { "did": target_did, "handle": "mike10010100.com" },
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": "LMAO they're still blaming Buttigieg? Wild."
                    },
                    "embed": {
                        "$type": "app.bsky.embed.record#view",
                        "record": {
                            "$type": "app.bsky.embed.record#viewRecord",
                            "uri": "at://did:plc:ktc7mkfqnint7hmviye6wizr/app.bsky.feed.post/3n2asybjkpk2p",
                            "author": {
                                "did": quoted_did,
                                "handle": "pierceah66.bsky.social"
                            },
                            "value": {
                                "$type": "app.bsky.feed.post",
                                "text": "Rahm’s shady bitch of a brother being very loud & wrong.",
                                "embed": {
                                    "$type": "app.bsky.embed.images",
                                    "images": [{
                                        "alt": "",
                                        "image": {
                                            "$type": "blob",
                                            "ref": { "$link": screenshot_cid }
                                        }
                                    }]
                                }
                            },
                            "embeds": [{
                                "$type": "app.bsky.embed.images#view",
                                "images": [{
                                    "thumb": format!("https://cdn.bsky.app/img/feed_thumbnail/plain/{quoted_did}/{screenshot_cid}@jpeg"),
                                    "fullsize": format!("https://cdn.bsky.app/img/feed_fullsize/plain/{quoted_did}/{screenshot_cid}@jpeg"),
                                    "alt": ""
                                }]
                            }]
                        }
                    }
                },
                "parent": null
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let enricher =
        AppViewContextEnricher::with_endpoint(mock_server.uri()).with_thread_context(true);
    let interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::DirectReply,
        "at://did:plc:jbbiqk7nyatsivk2mboyqm6t/app.bsky.feed.post/3n2btnssbrs2s",
        "bafy3n2b",
        "Just for you Ari, you prick.",
    )
    .with_parent_uri(parent_uri);

    let enriched = enricher.enrich(&interaction).await;
    assert_eq!(
        enriched.context_image_refs,
        vec![ContextImageRef {
            author_did: quoted_did.to_string(),
            cid: screenshot_cid.to_string(),
        }]
    );
    assert!(enriched.context_images_base64.is_empty());

    let interaction_fmt = enriched.format_for_interaction(author_did, target_did);
    assert!(interaction_fmt.contains(&format!(
        "[quoting OtherUser @pierceah66.bsky.social ({quoted_did}): \"Rahm’s shady bitch of a brother being very loud & wrong.\"]"
    )));
    assert!(interaction_fmt.contains("[quoted post has 1 attached image(s) (no alt text)]"));
    assert!(interaction_fmt.contains("[IMMEDIATE PARENT — Author is replying to this post]"));

    let raw_fmt = enriched.format_for_classifier();
    assert!(!raw_fmt.contains("[quoted post has"));
    assert!(!raw_fmt.contains("[quoting"));
}

#[tokio::test]
async fn test_appview_enricher_embeds_cards_gallery_cdn_fallback_and_standalone_media_quote() {
    use skybouncer::enricher::{ContextImageRef, MAX_CONTEXT_IMAGES};

    let mock_server = MockServer::start().await;
    let target_did = "did:plc:target_embed";
    let author_did = "did:plc:author_embed";
    let other_did = "did:plc:other_embed";
    let quoted_did = "did:plc:quoted_embed";
    let parent_uri = "at://did:plc:target_embed/app.bsky.feed.post/parent";

    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", parent_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": parent_uri,
                    "author": { "did": target_did },
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": "Look at both screenshots.",
                        "embed": {
                            "$type": "app.bsky.embed.recordWithMedia",
                            "media": {
                                "$type": "app.bsky.embed.images",
                                "images": [
                                    { "alt": "Polling chart showing 60% disapproval", "image": { "ref": { "$link": "bafkreicand1" } } },
                                    { "alt": "", "image": { "ref": { "$link": "bafkreicand2" } } }
                                ]
                            },
                            "record": { "record": { "uri": "at://did:plc:quoted_embed/app.bsky.feed.post/q" } }
                        }
                    },
                    "embed": {
                        "$type": "app.bsky.embed.recordWithMedia#view",
                        "media": {
                            "$type": "app.bsky.embed.images#view",
                            "images": [
                                { "thumb": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:target_embed/bafkreicand1@jpeg", "alt": "Polling chart showing 60% disapproval" },
                                { "thumb": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:target_embed/bafkreicand2@jpeg", "alt": "" }
                            ]
                        },
                        "record": {
                            "record": {
                                "$type": "app.bsky.embed.record#viewRecord",
                                "author": { "did": quoted_did, "handle": "reporter.bsky.social" },
                                "value": {
                                    "text": "Full scoop inside.",
                                    "embed": {
                                        "$type": "app.bsky.embed.external",
                                        "external": {
                                            "title": "Executive Under Fire",
                                            "description": "Inside the boardroom revolt."
                                        }
                                    }
                                },
                                "embeds": [{
                                    "$type": "app.bsky.embed.images#view",
                                    "images": [{
                                        "thumb": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:quoted_embed/bafkreiqimg@jpeg",
                                        "alt": "Ari Emanuel portrait"
                                    }]
                                }]
                            }
                        }
                    }
                },
                "parent": {
                    "$type": "app.bsky.feed.defs#threadViewPost",
                    "post": {
                        "uri": "at://did:plc:other_embed/app.bsky.feed.post/gallery_post",
                        "author": { "did": other_did },
                        "record": {
                            "$type": "app.bsky.feed.post",
                            "text": "Gallery of receipts",
                            "embed": {
                                "$type": "app.bsky.embed.gallery",
                                "items": [{
                                    "alt": "Receipt item 1",
                                    "item": { "ref": { "$link": "bafkreigallery1" } }
                                }]
                            }
                        },
                        "embed": {
                            "$type": "app.bsky.embed.gallery#view",
                            "items": [{
                                "fullsize": format!("https://cdn.bsky.app/img/feed_fullsize/plain/{other_did}/bafkreigallery1@jpeg"),
                                "alt": "Receipt item 1"
                            }]
                        }
                    },
                    "parent": {
                        "$type": "app.bsky.feed.defs#threadViewPost",
                        "post": {
                            "uri": "at://did:plc:other_embed/app.bsky.feed.post/root_card",
                            "author": { "did": other_did },
                            "record": {
                                "$type": "app.bsky.feed.post",
                                "text": "Read this report"
                            },
                            "embed": {
                                "$type": "app.bsky.embed.external#view",
                                "external": {
                                    "title": "Senate Hearing Transcript",
                                    "description": "Verbatim testimony from Tuesday."
                                }
                            }
                        },
                        "parent": null
                    }
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let enricher =
        AppViewContextEnricher::with_endpoint(mock_server.uri()).with_thread_context(true);
    let reply = Interaction::new(
        author_did,
        target_did,
        InteractionType::DirectReply,
        "at://did:plc:author_embed/app.bsky.feed.post/reply1",
        "bafyreply1",
        "What a corrupt disaster",
    )
    .with_parent_uri(parent_uri);

    let ctx = enricher.enrich(&reply).await;
    // Own post has 2 images so MAX_CONTEXT_IMAGES caps before the quoted post's image.
    assert_eq!(ctx.context_image_refs.len(), MAX_CONTEXT_IMAGES);
    assert_eq!(
        ctx.context_image_refs,
        vec![
            ContextImageRef {
                author_did: target_did.to_string(),
                cid: "bafkreicand1".to_string(),
            },
            ContextImageRef {
                author_did: target_did.to_string(),
                cid: "bafkreicand2".to_string(),
            },
        ]
    );
    let formatted = ctx.format_for_interaction(author_did, target_did);
    assert!(formatted.contains(
        "[link card: \"Senate Hearing Transcript\" — \"Verbatim testimony from Tuesday.\"]"
    ));
    assert!(formatted.contains("[attached 1 image(s); alt: \"Receipt item 1\"]"));
    assert!(
        formatted.contains("[attached 2 image(s); alt: \"Polling chart showing 60% disapproval\"]")
    );
    assert!(formatted.contains(
        "[quoted post link card: \"Executive Under Fire\" — \"Inside the boardroom revolt.\"]"
    ));
    assert!(formatted.contains("[quoted post attached 1 image(s); alt: \"Ari Emanuel portrait\"]"));

    // Standalone quote of a single root post that has only an image (`#view`-only `fullsize` CDN fallback,
    // no `record.embed`) retains the thread ancestor, embed summary, and ContextImageRef!
    let view_only_quote_uri = "at://did:plc:target_embed/app.bsky.feed.post/view_only_root";
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPosts"))
        .and(query_param("uris", view_only_quote_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "posts": [{
                "uri": view_only_quote_uri,
                "cid": "bafyviewonlyroot",
                "author": { "did": target_did, "handle": "target.bsky.social" },
                "record": { "$type": "app.bsky.feed.post", "text": "Wild chart." }
            }]
        })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getPostThread"))
        .and(query_param("uri", view_only_quote_uri))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "thread": {
                "$type": "app.bsky.feed.defs#threadViewPost",
                "post": {
                    "uri": view_only_quote_uri,
                    "author": { "did": target_did },
                    "record": { "$type": "app.bsky.feed.post", "text": "Wild chart." },
                    "embed": {
                        "$type": "app.bsky.embed.images#view",
                        "images": [{
                            "fullsize": format!("https://cdn.bsky.app/img/feed_fullsize/plain/{target_did}/bafkreiviewonly@jpeg"),
                            "alt": ""
                        }]
                    }
                },
                "parent": null
            }
        })))
        .mount(&mock_server)
        .await;

    let standalone = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:author_embed/app.bsky.feed.post/sq1",
        "bafysq1",
        "Look at those numbers",
    )
    .with_quote_uri(view_only_quote_uri);
    let ctx_sq = enricher.enrich(&standalone).await;
    assert_eq!(ctx_sq.thread_ancestors.len(), 1);
    assert_eq!(
        ctx_sq.context_image_refs,
        vec![ContextImageRef {
            author_did: target_did.to_string(),
            cid: "bafkreiviewonly".to_string(),
        }]
    );
    let fmt_sq = ctx_sq.format_for_interaction(author_did, target_did);
    assert!(fmt_sq.contains("[attached 1 image(s) (no alt text)]"));
    assert!(fmt_sq.contains("[QUOTED POST — Author is quote-posting this post]"));
}

#[tokio::test]
async fn test_enricher_new_fields_is_empty_mock_and_interaction_formatting() {
    use skybouncer::enricher::{
        ContextImageRef, EnrichedContext, PostEmbedSummary, ThreadPost, MAX_CONTEXT_IMAGES,
    };

    assert!(PostEmbedSummary::default().is_empty());
    let non_empty_summary = PostEmbedSummary {
        external_title: Some("Only Title".to_string()),
        ..Default::default()
    };
    assert!(!non_empty_summary.is_empty());

    // `is_empty()` checks all four new `EnrichedContext` fields accurately.
    let mut ctx = EnrichedContext::empty();
    ctx.image_alts = vec!["   ".to_string()];
    ctx.thread_ancestor_embeds = vec![None];
    assert!(ctx.is_empty());

    ctx.image_alts = vec!["Tweet screenshot".to_string()];
    assert!(!ctx.is_empty());

    let mut ctx_embed = EnrichedContext::empty();
    ctx_embed.thread_ancestors = vec![ThreadPost {
        author_did: "did:plc:t".to_string(),
        text: "Quoted card post".to_string(),
    }];
    ctx_embed.thread_ancestor_embeds = vec![Some(PostEmbedSummary {
        quoted_external_description: Some("Quoted description only".to_string()),
        ..Default::default()
    })];
    assert!(!ctx_embed.is_empty());
    assert!(ctx_embed
        .format_for_interaction("did:plc:a", "did:plc:t")
        .contains("[quoted post link card: \"Quoted description only\"]"));

    let mut ctx_ref = EnrichedContext::empty();
    ctx_ref.context_image_refs = vec![ContextImageRef {
        author_did: "did:plc:x".to_string(),
        cid: "bafkreix".to_string(),
    }];
    assert!(!ctx_ref.is_empty());

    let mut ctx_b64 = EnrichedContext::empty();
    ctx_b64.context_images_base64 = vec!["AQID".to_string()];
    assert!(!ctx_b64.is_empty());

    // `format_for_interaction` renders `Candidate Image Alt Text` and `Context Thread Images`;
    // `format_for_classifier` omits both and omits embed suffixes.
    let mut rich = EnrichedContext::empty();
    rich.thread_ancestors = vec![ThreadPost {
        author_did: "did:plc:t".to_string(),
        text: "Thread root".to_string(),
    }];
    rich.thread_ancestor_embeds = vec![Some(non_empty_summary.clone())];
    rich.image_alts = vec!["  ".to_string(), "Alt description for meme".to_string()];
    rich.context_images_base64 = vec!["AQID".to_string()];

    let inter_fmt = rich.format_for_interaction("did:plc:a", "did:plc:t");
    assert!(inter_fmt.contains("[link card: \"Only Title\"]"));
    assert!(inter_fmt.contains("Candidate Image Alt Text: [2] \"Alt description for meme\""));
    assert!(inter_fmt.contains(
        "Context Thread Images [1 thumbnail(s) from the parent/quoted post decoded for visual context — NOT uploaded by Author]"
    ));
    let raw_fmt = rich.format_for_classifier();
    assert!(!raw_fmt.contains("Candidate Image Alt Text"));
    assert!(!raw_fmt.contains("Context Thread Images"));
    assert!(!raw_fmt.contains("[link card:"));

    // `MockContextEnricher::set_context_image_refs` caps at MAX_CONTEXT_IMAGES and keeps `image_alts`.
    let mock = MockContextEnricher::new();
    let p_uri = "at://did:plc:t/app.bsky.feed.post/p1";
    mock.set_context_image_refs(
        p_uri,
        vec![
            ContextImageRef {
                author_did: "did:plc:q".to_string(),
                cid: "cid1".to_string(),
            },
            ContextImageRef {
                author_did: "did:plc:q".to_string(),
                cid: "cid2".to_string(),
            },
            ContextImageRef {
                author_did: "did:plc:q".to_string(),
                cid: "cid3".to_string(),
            },
        ],
    );
    let mut inter = Interaction::new(
        "did:plc:a",
        "did:plc:t",
        InteractionType::DirectReply,
        "at://did:plc:a/app.bsky.feed.post/r1",
        "bafyr1",
        "Reply text",
    )
    .with_parent_uri(p_uri);
    inter.image_alts = vec![" ".to_string(), "Chart screenshot".to_string()];
    let mocked = mock.enrich(&inter).await;
    assert_eq!(mocked.context_image_refs.len(), MAX_CONTEXT_IMAGES);
    assert_eq!(mocked.image_alts, vec!["Chart screenshot".to_string()]);
    assert!(mocked.context_images_base64.is_empty());
}
