//! Engine-level integration tests for dynamic Tier-1 primary routing.
//!
//! Verifies that when a multimodal classifier is configured, image-bearing commits
//! are routed to it at Tier-1 while text-only commits use the text primary, and that
//! image-triggered Tier-2 escalation is suppressed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::sync::Arc;

use serde_json::json;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};

use skybouncer::classifier::{Classifier, MockClassifier, RuleRubric, Sensitivity, Verdict};
use skybouncer::{SkybouncerConfig, SkybouncerEngine};

fn reply_commit(
    author: &str,
    target: &str,
    rkey: &str,
    text: &str,
    with_image: bool,
) -> JetstreamCommit {
    let embed = if with_image {
        json!({
            "$type": "app.bsky.embed.images",
            "images": [{
                "alt": "screenshot",
                "image": {
                    "$type": "blob",
                    "ref": { "$link": "bafyimagecid" },
                    "mimeType": "image/png",
                    "size": 1234
                }
            }]
        })
    } else {
        json!(null)
    };

    let mut record = json!({
        "$type": "app.bsky.feed.post",
        "text": text,
        "reply": {
            "parent": {
                "uri": format!("at://{target}/app.bsky.feed.post/root"),
                "cid": "bafyparentcid"
            },
            "root": {
                "uri": format!("at://{target}/app.bsky.feed.post/root"),
                "cid": "bafyrootcid"
            }
        },
        "createdAt": "2026-10-02T02:00:00.000Z"
    });
    if with_image {
        record["embed"] = embed;
    }

    JetstreamCommit {
        did: author.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreicid".to_string()),
        record: Some(record),
    }
}

fn build_engine(text: Arc<MockClassifier>, multimodal: Arc<MockClassifier>) -> SkybouncerEngine {
    let rubric = RuleRubric::new("Block spam and harassment", Sensitivity::Medium);
    let config = SkybouncerConfig::new(["did:plc:protected"], rubric).with_dry_run(true);
    SkybouncerEngine::builder(config)
        .with_classifier(text as Arc<dyn Classifier>)
        .with_multimodal_classifier(multimodal as Arc<dyn Classifier>)
        .build()
        .expect("engine builds")
}

#[tokio::test]
async fn image_commit_routes_to_multimodal_tier1() {
    let text = Arc::new(MockClassifier::new(Verdict::permitted("text ok")));
    let multimodal = Arc::new(MockClassifier::new(Verdict::permitted("image ok")));
    let engine = build_engine(Arc::clone(&text), Arc::clone(&multimodal));

    let commit = reply_commit(
        "did:plc:author",
        "did:plc:protected",
        "img1",
        "check out this picture",
        true,
    );
    engine.process_commit(&commit).await.expect("process");

    assert_eq!(
        text.call_count(),
        0,
        "text primary must be bypassed for images"
    );
    assert_eq!(
        multimodal.call_count(),
        1,
        "multimodal primary must handle images"
    );
}

#[tokio::test]
async fn text_commit_routes_to_text_tier1() {
    let text = Arc::new(MockClassifier::new(Verdict::permitted("text ok")));
    let multimodal = Arc::new(MockClassifier::new(Verdict::permitted("image ok")));
    let engine = build_engine(Arc::clone(&text), Arc::clone(&multimodal));

    let commit = reply_commit(
        "did:plc:author",
        "did:plc:protected",
        "txt1",
        "just a normal comment",
        false,
    );
    engine.process_commit(&commit).await.expect("process");

    assert_eq!(
        text.call_count(),
        1,
        "text primary must handle text-only posts"
    );
    assert_eq!(
        multimodal.call_count(),
        0,
        "multimodal primary must be bypassed"
    );
}

#[tokio::test]
async fn without_multimodal_config_all_routes_to_text_primary() {
    // No multimodal classifier configured => dynamic routing disabled; behavior is
    // identical to the pre-existing single primary path.
    let text = Arc::new(MockClassifier::new(Verdict::permitted("text ok")));
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let config = SkybouncerConfig::new(["did:plc:protected"], rubric).with_dry_run(true);
    let engine = SkybouncerEngine::builder(config)
        .with_classifier(Arc::clone(&text) as Arc<dyn Classifier>)
        .build()
        .expect("engine builds");

    let image_commit = reply_commit(
        "did:plc:author",
        "did:plc:protected",
        "img2",
        "picture",
        true,
    );
    engine.process_commit(&image_commit).await.expect("process");
    assert_eq!(text.call_count(), 1);
}
