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
