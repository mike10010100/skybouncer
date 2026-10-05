//! Integration and unit tests for Sovereign PDS Config Storage (PRD §2.2).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybase::repo::PdsRepoClient;
use skybouncer::classifier::{RuleRubric, Sensitivity};
use skybouncer::modlist::sovereign_config::{
    extract_rubric_from_list_description, fetch_sovereign_config,
    format_list_description_with_rubric, publish_sovereign_config, SovereignConfigRecord,
    SOVEREIGN_CONFIG_COLLECTION, SOVEREIGN_CONFIG_RKEY,
};

#[test]
fn test_sovereign_config_record_roundtrip() {
    let rubric = RuleRubric::new(
        "Strictly block crypto scams, phishing links, and aggressive slurs.",
        Sensitivity::High,
    );
    let record = SovereignConfigRecord::from_rubric(&rubric);

    assert_eq!(record.record_type, SOVEREIGN_CONFIG_COLLECTION);
    assert_eq!(record.rules, rubric.prompt);
    assert_eq!(record.sensitivity, "high");

    let json_bytes = serde_json::to_vec(&record).unwrap();
    let deserialized: SovereignConfigRecord = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(record, deserialized);

    let parsed_rubric = deserialized.to_rubric();
    assert_eq!(parsed_rubric.prompt, rubric.prompt);
    assert_eq!(parsed_rubric.sensitivity, Sensitivity::High);
    assert!(parsed_rubric.bypass_incoming_followers);
}

#[test]
fn test_sovereign_config_bypass_incoming_followers_roundtrip() {
    // Opt-out flag must persist through both the record and list-metadata encodings.
    let rubric =
        RuleRubric::new("Block spam", Sensitivity::Medium).with_bypass_incoming_followers(false);

    let record = SovereignConfigRecord::from_rubric(&rubric);
    assert!(!record.bypass_incoming_followers);
    assert!(!record.to_rubric().bypass_incoming_followers);

    let encoded = format_list_description_with_rubric("My list", &rubric);
    assert!(encoded.contains("\"bypass_incoming_followers\":false"));
    let extracted = extract_rubric_from_list_description(&encoded).unwrap();
    assert!(!extracted.bypass_incoming_followers);

    // Legacy payloads lacking the field default to enabled.
    let legacy = json!({
        "$type": SOVEREIGN_CONFIG_COLLECTION,
        "rules": "Block spam",
        "sensitivity": "medium",
        "updatedAt": "2026-01-01T00:00:00.000Z"
    });
    let legacy_record: SovereignConfigRecord = serde_json::from_value(legacy).unwrap();
    assert!(legacy_record.to_rubric().bypass_incoming_followers);
}

#[test]
fn test_list_description_metadata_embedding_and_extraction() {
    let rubric = RuleRubric::new(
        "Block abusive trolls, sea-lioning, and spam.",
        Sensitivity::Medium,
    );

    // 1. With existing user description
    let base_desc = "My custom personal blocklist curated automatically.";
    let encoded = format_list_description_with_rubric(base_desc, &rubric);
    assert!(encoded.starts_with(base_desc));
    assert!(encoded.contains("[skybouncer:{\"rules\":\"Block abusive trolls"));
    assert!(encoded.contains("\"sensitivity\":\"medium\""));

    let extracted = extract_rubric_from_list_description(&encoded);
    assert!(extracted.is_some());
    let ext = extracted.unwrap();
    assert_eq!(ext.prompt, rubric.prompt);
    assert_eq!(ext.sensitivity, Sensitivity::Medium);

    // 2. Without base description
    let empty_base = "";
    let encoded_empty = format_list_description_with_rubric(empty_base, &rubric);
    assert!(encoded_empty.starts_with("[skybouncer:{\"rules\":"));

    let extracted_empty = extract_rubric_from_list_description(&encoded_empty).unwrap();
    assert_eq!(extracted_empty.prompt, rubric.prompt);
    assert_eq!(extracted_empty.sensitivity, Sensitivity::Medium);

    // 3. Description without skybouncer metadata
    let plain_desc = "Just a regular list with no special tags.";
    assert!(extract_rubric_from_list_description(plain_desc).is_none());

    // 4. Overwriting existing tag preserves human description
    let updated_rubric = RuleRubric::new("New rules prompt", Sensitivity::Low);
    let re_encoded = format_list_description_with_rubric(&encoded, &updated_rubric);
    assert!(re_encoded.starts_with(base_desc));
    assert!(re_encoded.contains("\"sensitivity\":\"low\""));
    let re_extracted = extract_rubric_from_list_description(&re_encoded).unwrap();
    assert_eq!(re_extracted.prompt, "New rules prompt");
    assert_eq!(re_extracted.sensitivity, Sensitivity::Low);
}

#[tokio::test]
async fn test_sovereign_config_pds_publish_and_fetch() {
    let mock_server = MockServer::start().await;
    let repo_did = "did:plc:alice_sovereign";

    let pds_client =
        PdsRepoClient::from_credentials(mock_server.uri(), repo_did, "dummy_token_for_mock_tests")
            .unwrap();

    let rubric = RuleRubric::new("Block harassment and scams immediately.", Sensitivity::High);

    // 1. Mock putRecord
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.repo.putRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": format!("at://{repo_did}/{SOVEREIGN_CONFIG_COLLECTION}/{SOVEREIGN_CONFIG_RKEY}"),
            "cid": "bafyreisovereigncid"
        })))
        .mount(&mock_server)
        .await;

    let published_uri = publish_sovereign_config(&pds_client, repo_did, &rubric)
        .await
        .unwrap();
    assert!(published_uri.contains(SOVEREIGN_CONFIG_COLLECTION));

    // 2. Mock getRecord success
    let record_payload = SovereignConfigRecord::from_rubric(&rubric);
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .and(query_param("repo", repo_did))
        .and(query_param("collection", SOVEREIGN_CONFIG_COLLECTION))
        .and(query_param("rkey", SOVEREIGN_CONFIG_RKEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": published_uri,
            "cid": "bafyreisovereigncid",
            "value": record_payload
        })))
        .mount(&mock_server)
        .await;

    let fetched = fetch_sovereign_config(&pds_client, repo_did).await.unwrap();
    assert!(fetched.is_some());
    let fetched_rubric = fetched.unwrap();
    assert_eq!(fetched_rubric.prompt, rubric.prompt);
    assert_eq!(fetched_rubric.sensitivity, Sensitivity::High);
}

#[tokio::test]
async fn test_sovereign_config_pds_not_found_returns_none() {
    let mock_server = MockServer::start().await;
    let repo_did = "did:plc:bob_new_user";

    let pds_client =
        PdsRepoClient::from_credentials(mock_server.uri(), repo_did, "dummy_token_for_mock_tests")
            .unwrap();

    // Mock 404 RecordNotFound
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "RecordNotFound",
            "message": "Could not find record"
        })))
        .mount(&mock_server)
        .await;

    let fetched = fetch_sovereign_config(&pds_client, repo_did).await.unwrap();
    assert!(fetched.is_none());
}

// =============================================================================
// Autonomous Sovereign Firehose Synchronization Tests (PRD §2.2)
// =============================================================================

use skybase::ingest::{CommitOperation, JetstreamCommit};
use skybouncer::classifier::{MockClassifier, Verdict};
use skybouncer::engine::{
    ProcessCommitResult, SkybouncerConfig, SkybouncerEngine, SovereignConfigSyncEvent,
};
use skybouncer::matcher::{FollowGraph, NonFollowedGate};
use skybouncer::modlist::{DeduplicationCache, ModListManager};
use skybouncer::stream::StreamConfig;
use std::collections::HashSet;
use std::sync::Arc;

async fn setup_sovereign_test_engine(protected_did: &str) -> (Arc<SkybouncerEngine>, MockServer) {
    let mock_server = MockServer::start().await;
    let pds_client = Arc::new(
        PdsRepoClient::from_credentials(mock_server.uri(), protected_did, "mock_token").unwrap(),
    );
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let follow_graph = Arc::new(FollowGraph::new());
    let gate = Arc::new(NonFollowedGate::new(Arc::clone(&follow_graph)));
    let initial_rubric = RuleRubric::new("Initial rules prompt", Sensitivity::Medium);
    let modlist_manager = Arc::new(
        ModListManager::from_shared_cache(Arc::clone(&cache)).with_rubric(initial_rubric.clone()),
    );
    let classifier = Arc::new(MockClassifier::new(Verdict::permitted("benign test")));

    let mut protected_dids = HashSet::new();
    protected_dids.insert(protected_did.to_string());
    let config = SkybouncerConfig::new(protected_dids, initial_rubric);

    let engine = Arc::new(SkybouncerEngine::new(
        config,
        follow_graph,
        gate,
        classifier,
        modlist_manager,
        pds_client,
    ));

    (engine, mock_server)
}

#[test]
fn test_stream_config_default_includes_sovereign_collections() {
    let config = StreamConfig::default();
    assert!(
        config
            .collections
            .contains(&"app.bsky.feed.post".to_string()),
        "Must contain app.bsky.feed.post"
    );
    assert!(
        config
            .collections
            .contains(&"app.bsky.graph.follow".to_string()),
        "Must contain app.bsky.graph.follow"
    );
    assert!(
        config
            .collections
            .contains(&SOVEREIGN_CONFIG_COLLECTION.to_string()),
        "Must contain social.skybouncer.config"
    );
    assert!(
        config
            .collections
            .contains(&"app.bsky.graph.list".to_string()),
        "Must contain app.bsky.graph.list"
    );
}

#[tokio::test]
async fn test_firehose_sovereign_config_create_and_update_hot_reloads_rubric() {
    let protected_did = "did:plc:protected_sovereign_alice";
    let (engine, _server) = setup_sovereign_test_engine(protected_did).await;

    // Verify initial rubric state
    assert_eq!(engine.rubric().prompt, "Initial rules prompt");
    assert_eq!(engine.rubric().sensitivity, Sensitivity::Medium);

    // 1. Simulate incoming CommitOperation::Create on social.skybouncer.config
    let updated_rubric = RuleRubric::new(
        "Strictly block crypto spam, drainers, and phishing attacks.",
        Sensitivity::High,
    );
    let record_payload = json!(SovereignConfigRecord::from_rubric(&updated_rubric));

    let commit = JetstreamCommit {
        did: protected_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreisovereigncommitcid".to_string()),
        record: Some(record_payload),
    };

    let result = engine.process_commit(&commit).await.unwrap();
    assert!(result.is_sovereign_config_synced());

    match result {
        ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Updated {
            did,
            prompt,
            sensitivity,
        }) => {
            assert_eq!(did, protected_did);
            assert_eq!(prompt, updated_rubric.prompt);
            assert_eq!(sensitivity, Sensitivity::High);
        }
        other => panic!("Expected SovereignConfigSynced(Updated), got {other:?}"),
    }

    // Verify engine state was dynamically hot-reloaded
    assert_eq!(engine.rubric().prompt, updated_rubric.prompt);
    assert_eq!(engine.rubric().sensitivity, Sensitivity::High);
    assert_eq!(engine.stats().snapshot().sovereign_configs_synced, 1);

    // 2. Simulate CommitOperation::Update
    let second_rubric =
        RuleRubric::new("Permissive mode: block only direct slurs", Sensitivity::Low);
    let second_payload = json!(SovereignConfigRecord::from_rubric(&second_rubric));

    let update_commit = JetstreamCommit {
        did: protected_did.to_string(),
        time_us: 1_720_000_001_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Update,
        cid: Some("bafyreisovereigncommitcid2".to_string()),
        record: Some(second_payload),
    };

    let result2 = engine.process_commit(&update_commit).await.unwrap();
    assert!(result2.is_sovereign_config_synced());
    assert_eq!(engine.rubric().prompt, second_rubric.prompt);
    assert_eq!(engine.rubric().sensitivity, Sensitivity::Low);
    assert_eq!(engine.stats().snapshot().sovereign_configs_synced, 2);
}

#[tokio::test]
async fn test_firehose_sovereign_config_delete() {
    let protected_did = "did:plc:protected_sovereign_bob";
    let (engine, _server) = setup_sovereign_test_engine(protected_did).await;

    let delete_commit = JetstreamCommit {
        did: protected_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    };

    let result = engine.process_commit(&delete_commit).await.unwrap();
    assert!(result.is_sovereign_config_synced());

    match result {
        ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted { did }) => {
            assert_eq!(did, protected_did);
        }
        other => panic!("Expected SovereignConfigSynced(Deleted), got {other:?}"),
    }
    assert_eq!(engine.stats().snapshot().sovereign_configs_synced, 1);
}

#[tokio::test]
async fn test_firehose_sovereign_config_unprotected_did_ignored() {
    let protected_did = "did:plc:protected_alice";
    let stranger_did = "did:plc:stranger_eve";
    let (engine, _server) = setup_sovereign_test_engine(protected_did).await;

    let stranger_rubric = RuleRubric::new(
        "Malicious attacker trying to tamper rules",
        Sensitivity::Low,
    );
    let commit = JetstreamCommit {
        did: stranger_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreicit".to_string()),
        record: Some(json!(SovereignConfigRecord::from_rubric(&stranger_rubric))),
    };

    let result = engine.process_commit(&commit).await.unwrap();
    assert!(result.is_ignored());

    // Protected user's rubric must remain 100% intact
    assert_eq!(engine.rubric().prompt, "Initial rules prompt");
    assert_eq!(engine.rubric().sensitivity, Sensitivity::Medium);
    assert_eq!(engine.stats().snapshot().sovereign_configs_synced, 0);
}

#[tokio::test]
async fn test_firehose_list_metadata_commit_hot_reloads_rubric() {
    let protected_did = "did:plc:protected_alice";
    let (engine, _server) = setup_sovereign_test_engine(protected_did).await;

    let list_rubric = RuleRubric::new(
        "Extracted from list description: block spam & trolls",
        Sensitivity::High,
    );
    let encoded_desc = format_list_description_with_rubric("My personal blocklist", &list_rubric);

    let list_commit = JetstreamCommit {
        did: protected_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.list".to_string(),
        rkey: "3mwu123list".to_string(),
        operation: CommitOperation::Update,
        cid: Some("bafyreilistcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.graph.list",
            "name": "Skybouncer Auto-Filter",
            "purpose": "app.bsky.graph.defs#modlist",
            "description": encoded_desc,
            "createdAt": "2026-10-01T20:00:00.000Z"
        })),
    };

    let result = engine.process_commit(&list_commit).await.unwrap();
    assert!(result.is_sovereign_config_synced());

    match result {
        ProcessCommitResult::SovereignConfigSynced(
            SovereignConfigSyncEvent::ListMetadataUpdated {
                did,
                prompt,
                sensitivity,
            },
        ) => {
            assert_eq!(did, protected_did);
            assert_eq!(prompt, list_rubric.prompt);
            assert_eq!(sensitivity, Sensitivity::High);
        }
        other => panic!("Expected SovereignConfigSynced(ListMetadataUpdated), got {other:?}"),
    }

    assert_eq!(engine.rubric().prompt, list_rubric.prompt);
    assert_eq!(engine.rubric().sensitivity, Sensitivity::High);
    assert_eq!(engine.stats().snapshot().sovereign_configs_synced, 1);
}

#[tokio::test]
async fn test_process_commit_queued_sovereign_config_sync() {
    let protected_did = "did:plc:protected_alice";
    let (engine, _server) = setup_sovereign_test_engine(protected_did).await;
    let (eval_tx, mut eval_rx) = tokio::sync::mpsc::channel(16);

    let updated_rubric = RuleRubric::new("Queued pipeline dynamic rubric update", Sensitivity::Low);
    let commit = JetstreamCommit {
        did: protected_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: SOVEREIGN_CONFIG_COLLECTION.to_string(),
        rkey: SOVEREIGN_CONFIG_RKEY.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreiqueued".to_string()),
        record: Some(json!(SovereignConfigRecord::from_rubric(&updated_rubric))),
    };

    let result = engine
        .process_commit_queued(&commit, &eval_tx)
        .await
        .unwrap();
    assert!(result.is_sovereign_config_synced());
    assert_eq!(engine.rubric().prompt, updated_rubric.prompt);
    assert_eq!(engine.rubric().sensitivity, Sensitivity::Low);

    // Ensure evaluation queue was NOT polluted with non-post candidates
    assert!(eval_rx.try_recv().is_err());
}
