//! Empirical adversarial, fault-injection, and concurrency verification suite
//! for `ModListManager` and `DeduplicationCache` (Milestone 3 Challenger).
//!
//! Validates:
//! 1. Adversarial PDS network conditions:
//!    - Repeated 500 Internal Server Errors on createRecord, deleteRecord, listRecords.
//!    - Malformed JSON responses from PDS.
//!    - Abrupt TCP socket drops / connection resets.
//! 2. Concurrent bounce races on the SAME violator:
//!    - 10 simultaneous threads bouncing the same violator DID.
//!    - Evaluates whether duplicate PDS mutations occur or deduplication succeeds.
//! 3. Rapid oscillating bounce-pardon-bounce lifecycles:
//!    - Repeated cycles of bounce -> pardon -> bounce -> pardon.
//! 4. Cache consistency & non-corruption under all failure modes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::MockPdsServer;
use skybouncer::classifier::ViolationCategory;
use skybouncer::error::SkybouncerError;
use skybouncer::modlist::{BounceRequest, ModListManager};

// =============================================================================
// 1. Adversarial PDS Network Conditions & Fault Injection
// =============================================================================

#[tokio::test]
async fn test_adversarial_pds_repeated_500_create_record() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // Pre-provision the moderation list so ensure_mod_list succeeds
    let list_uri = manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .unwrap();
    assert!(list_uri.contains("app.bsky.graph.list"));

    // Inject repeated 500 errors on createRecord
    for attempt in 1..=3 {
        pds.mount_create_error_once(500, "InternalServerError", "Database deadlocked")
            .await;

        let res = manager
            .bounce(
                &client,
                BounceRequest::new(
                    "did:plc:alice",
                    "did:plc:resilient_spammer",
                    &ViolationCategory::CryptoSpam,
                    0.95,
                    "Airdrop phishing",
                    &format!("at://did:plc:resilient_spammer/app.bsky.feed.post/{attempt}"),
                ),
            )
            .await;

        assert!(res.is_err(), "Attempt {attempt} should fail on PDS 500");
        match res.unwrap_err() {
            SkybouncerError::Repo(msg) => {
                assert!(msg.contains("Failed to create listitem record"));
            }
            other => panic!("Expected SkybouncerError::Repo, got: {other:?}"),
        }

        // Cache must NOT record this user as bounced
        assert!(
            !manager.is_bounced("did:plc:resilient_spammer").unwrap(),
            "Cache must not contain unconfirmed bounce after attempt {attempt}"
        );
        assert_eq!(manager.cache().count_bounced().unwrap(), 0);
    }

    // Now PDS recovers: bounce should succeed cleanly
    let res = manager
        .bounce(
            &client,
            BounceRequest::new(
                "did:plc:alice",
                "did:plc:resilient_spammer",
                &ViolationCategory::CryptoSpam,
                0.95,
                "Airdrop phishing",
                "at://did:plc:resilient_spammer/app.bsky.feed.post/recovery",
            ),
        )
        .await
        .unwrap();

    assert!(res.is_some());
    assert!(manager.is_bounced("did:plc:resilient_spammer").unwrap());
    assert_eq!(manager.cache().count_bounced().unwrap(), 1);
}

#[tokio::test]
async fn test_adversarial_pds_malformed_json_create_record() {
    let server = MockServer::start().await;

    // Server returns 200 OK but body is malformed / truncated JSON
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.repo.createRecord"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    "{\"uri\": \"at://did:plc:alice/app.bsky.graph.listitem/123\", \"cid",
                )
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let client =
        skybase::repo::PdsRepoClient::from_credentials(server.uri(), "did:plc:alice", "mock_token")
            .unwrap();
    let manager = ModListManager::open_in_memory().unwrap();

    // Cache a fake list config so ensure_mod_list doesn't call PDS
    let config = skybouncer::modlist::ModListConfig {
        user_did: "did:plc:alice".to_string(),
        list_uri: "at://did:plc:alice/app.bsky.graph.list/test_list".to_string(),
        list_cid: "bafytestcid".to_string(),
        created_at: 1_700_000_000,
    };
    manager.cache().set_mod_list(&config).unwrap();

    let res = manager
        .bounce(
            &client,
            BounceRequest::new(
                "did:plc:alice",
                "did:plc:malformed_json_target",
                &ViolationCategory::Spam,
                0.90,
                "Spam test",
                "at://did:plc:malformed_json_target/app.bsky.feed.post/1",
            ),
        )
        .await;

    assert!(res.is_err());
    // Cache must remain pristine
    assert!(!manager.is_bounced("did:plc:malformed_json_target").unwrap());
}

#[tokio::test]
async fn test_adversarial_pds_socket_drop_on_create_record() {
    // Bind a TCP listener that resets the connection immediately upon receiving data
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream.shutdown().await;
            drop(stream);
        }
    });

    let client = skybase::repo::PdsRepoClient::from_credentials(
        format!("http://{local_addr}"),
        "did:plc:alice",
        "mock_token",
    )
    .unwrap();
    let manager = ModListManager::open_in_memory().unwrap();

    // Pre-populate list config in cache so ensure_mod_list doesn't fail before createRecord
    let config = skybouncer::modlist::ModListConfig {
        user_did: "did:plc:alice".to_string(),
        list_uri: "at://did:plc:alice/app.bsky.graph.list/test_list".to_string(),
        list_cid: "bafytestcid".to_string(),
        created_at: 1_700_000_000,
    };
    manager.cache().set_mod_list(&config).unwrap();

    let res = manager
        .bounce(
            &client,
            BounceRequest::new(
                "did:plc:alice",
                "did:plc:socket_drop_user",
                &ViolationCategory::Spam,
                0.90,
                "Spam test",
                "at://did:plc:socket_drop_user/app.bsky.feed.post/1",
            ),
        )
        .await;

    assert!(res.is_err(), "Expected network error on socket drop");
    assert!(!manager.is_bounced("did:plc:socket_drop_user").unwrap());

    let _ = server_task.await;
}

#[tokio::test]
async fn test_adversarial_pds_repeated_500_delete_record() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // Pre-bounce user
    manager
        .bounce(
            &client,
            BounceRequest::new(
                "did:plc:alice",
                "did:plc:pardon_target",
                &ViolationCategory::Harassment,
                0.88,
                "Harassment violation",
                "at://did:plc:pardon_target/app.bsky.feed.post/1",
            ),
        )
        .await
        .unwrap();

    assert!(manager.is_bounced("did:plc:pardon_target").unwrap());

    // Inject repeated 503 Service Unavailable on deleteRecord
    for attempt in 1..=3 {
        pds.mount_delete_error_once(503, "ServiceUnavailable", "Database under heavy load")
            .await;

        let res = manager
            .pardon_user(&client, "did:plc:alice", "did:plc:pardon_target")
            .await;

        assert!(res.is_err(), "Pardon attempt {attempt} should fail");

        // The user MUST remain in the SQLite cache as bounced
        assert!(
            manager.is_bounced("did:plc:pardon_target").unwrap(),
            "Bounced user must remain in cache after failed pardon attempt {attempt}"
        );
    }

    // Now PDS recovers: pardon should succeed and remove from cache
    let res = manager
        .pardon_user(&client, "did:plc:alice", "did:plc:pardon_target")
        .await
        .unwrap();

    assert!(res, "Pardon should return true upon recovery");
    assert!(
        !manager.is_bounced("did:plc:pardon_target").unwrap(),
        "User should be purged from cache after successful pardon"
    );
}

#[tokio::test]
async fn test_adversarial_pds_socket_drop_on_delete_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream.shutdown().await;
            drop(stream);
        }
    });

    let client = skybase::repo::PdsRepoClient::from_credentials(
        format!("http://{local_addr}"),
        "did:plc:alice",
        "mock_token",
    )
    .unwrap();
    let manager = ModListManager::open_in_memory().unwrap();

    // Seed cache with a bounced user
    let bounce = skybouncer::modlist::BouncedUser {
        subject_did: "did:plc:socket_drop_pardon".to_string(),
        protected_did: "did:plc:alice".to_string(),
        listitem_uri: "at://did:plc:alice/app.bsky.graph.listitem/item1".to_string(),
        listitem_rkey: "item1".to_string(),
        listitem_cid: "bafyitemcid".to_string(),
        category: "spam".to_string(),
        confidence: 0.9,
        reason: "spam".to_string(),
        post_uri: "at://did:plc:socket_drop_pardon/app.bsky.feed.post/1".to_string(),
        post_text: "spam message".to_string(),
        bounced_at: 1_700_000_000,
        expires_at: None,
    };
    manager.cache().record_bounce(&bounce).unwrap();
    assert!(manager.is_bounced("did:plc:socket_drop_pardon").unwrap());

    let res = manager
        .pardon_user(&client, "did:plc:alice", "did:plc:socket_drop_pardon")
        .await;

    assert!(res.is_err());
    // Must remain in cache
    assert!(manager.is_bounced("did:plc:socket_drop_pardon").unwrap());

    let _ = server_task.await;
}

#[tokio::test]
async fn test_adversarial_pds_list_records_500_fails_without_duplicate_provisioning() {
    let server = MockServer::start().await;

    // listRecords returns 500 Internal Server Error
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": "InternalServerError",
            "message": "Index temporarily degraded"
        })))
        .mount(&server)
        .await;

    // createRecord succeeds (should never be called)
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.repo.createRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/app.bsky.graph.list/fallback_rkey",
            "cid": "bafyfallbackcid"
        })))
        .mount(&server)
        .await;

    let client =
        skybase::repo::PdsRepoClient::from_credentials(server.uri(), "did:plc:alice", "mock_token")
            .unwrap();
    let manager = ModListManager::open_in_memory().unwrap();

    let res = manager.ensure_mod_list(&client, "did:plc:alice").await;
    assert!(
        res.is_err(),
        "Transient listRecords 500 must fail instead of creating duplicate mod list"
    );

    // Must not be cached locally
    assert!(manager.get_mod_list("did:plc:alice").unwrap().is_none());
}

#[tokio::test]
async fn test_adversarial_pds_list_records_malformed_json() {
    let server = MockServer::start().await;

    // listRecords returns 200 with invalid JSON
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.listRecords"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{\"records\": [{\"uri\": \"broken")
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    // createRecord succeeds (should never be called)
    Mock::given(method("POST"))
        .and(path("/xrpc/com.atproto.repo.createRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uri": "at://did:plc:alice/app.bsky.graph.list/malformed_fallback_rkey",
            "cid": "bafymalformedfallback"
        })))
        .mount(&server)
        .await;

    let client =
        skybase::repo::PdsRepoClient::from_credentials(server.uri(), "did:plc:alice", "mock_token")
            .unwrap();
    let manager = ModListManager::open_in_memory().unwrap();

    // Malformed JSON is not swallowed to avoid provisioning duplicates
    let res = manager.ensure_mod_list(&client, "did:plc:alice").await;
    assert!(
        res.is_err(),
        "Malformed JSON on listRecords must fail instead of creating duplicate mod list"
    );

    assert!(manager.get_mod_list("did:plc:alice").unwrap().is_none());
}

#[tokio::test]
async fn test_adversarial_pds_400_invalid_request_create_record() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // Pre-provision list
    manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .unwrap();

    // Mount 400 InvalidRequest on createRecord
    pds.mount_create_error_once(400, "InvalidRequest", "Record validation failed")
        .await;

    let res = manager
        .bounce(
            &client,
            BounceRequest::new(
                "did:plc:alice",
                "did:plc:bad_request_target",
                &ViolationCategory::Spam,
                0.90,
                "Spam test",
                "at://did:plc:bad_request_target/app.bsky.feed.post/1",
            ),
        )
        .await;

    assert!(res.is_err());
    match res.unwrap_err() {
        SkybouncerError::Repo(msg) => {
            assert!(msg.contains("Record validation failed") || msg.contains("Failed to create"));
        }
        other => panic!("Expected SkybouncerError::Repo, got: {other:?}"),
    }

    // Cache must remain clean
    assert!(!manager.is_bounced("did:plc:bad_request_target").unwrap());
}

// =============================================================================
// 2. Rapid Oscillating Bounce-Pardon-Bounce Lifecycle
// =============================================================================

#[tokio::test]
async fn test_rapid_oscillating_bounce_pardon_bounce_lifecycle() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    let target_did = "did:plc:oscillating_violator";

    for cycle in 1..=5 {
        // 1. Bounce user
        let bounce_res = manager
            .bounce(
                &client,
                BounceRequest::new(
                    "did:plc:alice",
                    target_did,
                    &ViolationCategory::CryptoSpam,
                    0.95,
                    &format!("Cycle {cycle} violation"),
                    &format!("at://{target_did}/app.bsky.feed.post/{cycle}"),
                ),
            )
            .await
            .unwrap();

        assert!(
            bounce_res.is_some(),
            "Cycle {cycle}: bounce should create listitem"
        );
        let listitem_uri = bounce_res.unwrap();
        assert!(listitem_uri.contains("app.bsky.graph.listitem"));

        // Verify cache state
        assert!(
            manager.is_bounced(target_did).unwrap(),
            "Cycle {cycle}: target should be marked as bounced in cache"
        );
        let user_record = manager.get_bounced_user(target_did).unwrap().unwrap();
        assert_eq!(user_record.listitem_uri, listitem_uri);

        // Deduplication check: repeated bounce in same cycle drops with 0 PDS writes
        let dupe_res = manager
            .bounce(
                &client,
                BounceRequest::new(
                    "did:plc:alice",
                    target_did,
                    &ViolationCategory::CryptoSpam,
                    0.99,
                    "Duplicate trigger",
                    &format!("at://{target_did}/app.bsky.feed.post/{cycle}_dupe"),
                ),
            )
            .await
            .unwrap();
        assert!(
            dupe_res.is_none(),
            "Cycle {cycle}: duplicate bounce should return None"
        );

        // 2. Pardon user
        let pardon_res = manager
            .pardon_user(&client, "did:plc:alice", target_did)
            .await
            .unwrap();
        assert!(
            pardon_res,
            "Cycle {cycle}: pardon should succeed and return true"
        );

        // Verify cache state
        assert!(
            !manager.is_bounced(target_did).unwrap(),
            "Cycle {cycle}: target should not be bounced after pardon"
        );
        assert!(
            manager.get_bounced_user(target_did).unwrap().is_none(),
            "Cycle {cycle}: target should be deleted from cache"
        );

        // Repeated pardon returns false immediately
        let dupe_pardon = manager
            .pardon_user(&client, "did:plc:alice", target_did)
            .await
            .unwrap();
        assert!(
            !dupe_pardon,
            "Cycle {cycle}: redundant pardon should return false"
        );
    }

    // Verify total PDS mutations across 5 cycles:
    // 1 list creation (in cycle 1) + 1 listblock auto-subscription + 5 listitem creations + 5 listitem deletions
    let created = pds.created_records.lock();
    assert_eq!(created.len(), 7); // 1 list + 1 listblock + 5 listitems
    assert_eq!(created[0]["collection"], "app.bsky.graph.list");
    assert_eq!(created[1]["collection"], "app.bsky.graph.listblock");
    for item in &created[2..] {
        assert_eq!(item["collection"], "app.bsky.graph.listitem");
        assert_eq!(item["record"]["subject"], target_did);
    }

    let deleted = pds.deleted_records.lock();
    assert_eq!(deleted.len(), 5);
    for item in deleted.iter() {
        assert_eq!(item["collection"], "app.bsky.graph.listitem");
    }
}

// =============================================================================
// 3. Concurrent Bounce Races on the Same Violator
// =============================================================================

#[tokio::test]
async fn test_concurrent_bounce_race_same_violator() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = Arc::new(ModListManager::open_in_memory().unwrap());

    // Pre-provision the moderation list so ensure_mod_list doesn't race
    manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .unwrap();

    let target_did = "did:plc:same_violator_racing";
    let concurrency = 10;
    let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

    let mut handles = Vec::new();
    for i in 0..concurrency {
        let mgr = Arc::clone(&manager);
        let cl = client.clone();
        let b = Arc::clone(&barrier);
        let did = target_did.to_string();

        handles.push(tokio::spawn(async move {
            b.wait().await;
            mgr.bounce(
                &cl,
                BounceRequest::new(
                    "did:plc:alice",
                    &did,
                    &ViolationCategory::CryptoSpam,
                    0.90 + (i as f64 * 0.005),
                    "Concurrent race attack",
                    &format!("at://{did}/app.bsky.feed.post/{i}"),
                ),
            )
            .await
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        let res = h.await.unwrap().unwrap();
        results.push(res);
    }

    let successes: Vec<_> = results.into_iter().flatten().collect();

    // Check how many listitem creations were received by PDS
    let created_listitems: Vec<_> = pds
        .created_records
        .lock()
        .iter()
        .filter(|r| r["collection"] == "app.bsky.graph.listitem")
        .cloned()
        .collect();

    println!(
        "Concurrent race results: {} total tasks returned Ok(Some(uri)), {} listitems created on PDS",
        successes.len(),
        created_listitems.len()
    );

    // In SQLite, exactly 1 bounced user entry exists
    assert_eq!(manager.cache().count_bounced().unwrap(), 1);
    assert!(manager.is_bounced(target_did).unwrap());

    // CRITICAL OBSERVATION ON PDS ORPHANS:
    // If multiple listitems were created on PDS, calling pardon_user will only delete 1,
    // leaving the remaining items orphaned on the PDS moderation list.
    let pardoned = manager
        .pardon_user(&client, "did:plc:alice", target_did)
        .await
        .unwrap();
    assert!(pardoned);

    let deleted_count = pds.deleted_records.lock().len();
    println!(
        "Pardon deleted {} records from PDS (leaving {} orphaned listitems on PDS)",
        deleted_count,
        created_listitems.len().saturating_sub(deleted_count)
    );

    // The dispatch requirement states:
    // "Verify that exactly one PDS write succeeds and all others short-circuit without duplicate list items or database race conditions."
    assert_eq!(
        created_listitems.len(),
        1,
        "DISPATCH VIOLATION: Exactly one PDS write must succeed, but {} listitems were created on PDS!",
        created_listitems.len()
    );
    assert_eq!(
        successes.len(),
        1,
        "DISPATCH VIOLATION: Exactly one bounce call should return Ok(Some), others should short-circuit to Ok(None)"
    );
}

#[tokio::test]
async fn test_concurrent_ensure_mod_list_race() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = Arc::new(ModListManager::open_in_memory().unwrap());

    let concurrency = 10;
    let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let mgr = Arc::clone(&manager);
        let cl = client.clone();
        let b = Arc::clone(&barrier);

        handles.push(tokio::spawn(async move {
            b.wait().await;
            mgr.ensure_mod_list(&cl, "did:plc:alice").await
        }));
    }

    for h in handles {
        let res = h.await.unwrap();
        assert!(res.is_ok());
    }

    let created_lists: Vec<_> = pds
        .created_records
        .lock()
        .iter()
        .filter(|r| r["collection"] == "app.bsky.graph.list")
        .cloned()
        .collect();

    println!(
        "ensure_mod_list race: created {} moderation lists on PDS",
        created_lists.len()
    );

    assert_eq!(
        created_lists.len(),
        1,
        "DISPATCH VIOLATION: Concurrent ensure_mod_list created {} moderation lists on PDS instead of 1!",
        created_lists.len()
    );
}
