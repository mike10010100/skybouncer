//! Tests for the daemon's extracted cold-start hydration and PDS provisioning helpers.

#![cfg(all(
    feature = "web",
    feature = "stream",
    feature = "bot",
    feature = "telemetry"
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::MockPdsServer;
use serde_json::json;
use skybouncer::classifier::{MockClassifier, RuleRubric, Sensitivity, Verdict};
use skybouncer::engine::{SkybouncerConfig, SkybouncerEngine};
use skybouncer::enricher::AppViewContextEnricher;
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn build_engine(
    protected: &str,
    pds: &MockPdsServer,
    dry_run: bool,
) -> Arc<SkybouncerEngine> {
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let modlist =
        Arc::new(ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(rubric.clone()));
    let pds_client = Arc::new(pds.pds_client(protected));
    let classifier = Arc::new(MockClassifier::new(Verdict::permitted("ok")));
    let mut dids = HashSet::new();
    dids.insert(protected.to_string());
    let config = SkybouncerConfig::new(dids, rubric).with_dry_run(dry_run);
    Arc::new(
        SkybouncerEngine::builder(config)
            .with_follow_graph(follow_graph)
            .with_gate(gate)
            .with_cache(cache)
            .with_modlist_manager(modlist)
            .with_pds_client(pds_client)
            .with_classifier(classifier)
            .build()
            .expect("engine"),
    )
}

#[tokio::test]
async fn hydrate_cold_start_seeds_follow_records_and_followers() {
    let appview = MockServer::start().await;
    let pds = MockPdsServer::start().await;
    let protected = "did:plc:alice";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [{
                "uri": "at://did:plc:alice/app.bsky.graph.follow/3kabc",
                "value": {"subject": "did:plc:bob"}
            }],
            "cursor": null
        })))
        .mount(&appview)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.graph.getFollowers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "followers": [{"did": "did:plc:carol"}],
            "cursor": null
        })))
        .mount(&appview)
        .await;

    let engine = build_engine(protected, &pds, true).await;
    let enricher = AppViewContextEnricher::with_endpoint(appview.uri());
    let mut dids = HashSet::new();
    dids.insert(protected.to_string());

    let hydrated = skybouncer::daemon::hydrate_cold_start(&engine, &enricher, &dids).await;
    assert!(hydrated >= 2, "expected follow record + follower hydration");
    assert!(engine.is_following(protected, "did:plc:bob"));
}

#[tokio::test]
async fn provision_pds_resources_creates_lists_for_protected_did() {
    let pds = MockPdsServer::start().await;
    let protected = "did:plc:alice";
    let engine = build_engine(protected, &pds, false).await;
    let mut dids = HashSet::new();
    dids.insert(protected.to_string());

    // Ensure the list exists (mock PDS handles createRecord/listRecords dynamically).
    let provisioned = skybouncer::daemon::provision_pds_resources(&engine, &dids).await;
    assert_eq!(provisioned, 1);
}
