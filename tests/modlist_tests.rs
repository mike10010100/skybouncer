//! Comprehensive integration and unit test suite for Milestone 3:
//! Moderation List Manager, PDS mutations, and SQLite deduplication cache.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::MockPdsServer;
use skybouncer::classifier::{BounceDuration, RuleRubric, Sensitivity, Verdict, ViolationCategory};
use skybouncer::modlist::{BouncedUser, DeduplicationCache, ModListConfig, ModListManager};

// ============================================================================
// 1. SQLite Cache Unit Tests
// ============================================================================

#[test]
fn test_sqlite_cache_mod_list_config_roundtrip() {
    let cache = DeduplicationCache::open_in_memory().unwrap();
    let config = ModListConfig {
        user_did: "did:plc:alice".to_string(),
        list_uri: "at://did:plc:alice/app.bsky.graph.list/3k123456789ab".to_string(),
        list_cid: "bafyreitestcid".to_string(),
        created_at: 1_720_000_000_000_000,
    };

    // Initially empty
    assert!(cache.get_mod_list("did:plc:alice").unwrap().is_none());

    // Insert
    cache.set_mod_list(&config).unwrap();
    let retrieved = cache.get_mod_list("did:plc:alice").unwrap().unwrap();
    assert_eq!(config, retrieved);

    // Update on conflict
    let updated = ModListConfig {
        list_cid: "bafyreitestcidv2".to_string(),
        created_at: 1_720_000_000_000_100,
        ..config
    };
    cache.set_mod_list(&updated).unwrap();
    let retrieved_updated = cache.get_mod_list("did:plc:alice").unwrap().unwrap();
    assert_eq!(retrieved_updated.list_cid, "bafyreitestcidv2");
    assert_eq!(retrieved_updated.created_at, 1_720_000_000_000_100);
}

#[test]
fn test_sqlite_cache_bounced_user_deduplication() {
    let cache = DeduplicationCache::open_in_memory().unwrap();
    let entry = BouncedUser {
        subject_did: "did:plc:spammer1".to_string(),
        protected_did: "did:plc:alice".to_string(),
        listitem_uri: "at://did:plc:alice/app.bsky.graph.listitem/item123".to_string(),
        listitem_rkey: "item123".to_string(),
        listitem_cid: "bafyitemcid".to_string(),
        category: "crypto_spam".to_string(),
        confidence: 0.95,
        reason: "Crypto giveaway bot".to_string(),
        post_uri: "at://did:plc:spammer1/app.bsky.feed.post/1".to_string(),
        post_text: "Crypto giveaway link".to_string(),
        bounced_at: 1_720_000_000_000_000,
        expires_at: None,
    };

    assert!(!cache.is_bounced("did:plc:spammer1").unwrap());
    assert_eq!(cache.count_bounced().unwrap(), 0);

    // Record bounce
    cache.record_bounce(&entry).unwrap();
    assert!(cache.is_bounced("did:plc:spammer1").unwrap());
    assert_eq!(cache.count_bounced().unwrap(), 1);

    // Fetch details
    let fetched = cache.get_bounced_user("did:plc:spammer1").unwrap().unwrap();
    assert_eq!(fetched, entry);

    // Remove bounce returns rkey
    let removed_rkey = cache.remove_bounce("did:plc:spammer1").unwrap();
    assert_eq!(removed_rkey.as_deref(), Some("item123"));
    assert!(!cache.is_bounced("did:plc:spammer1").unwrap());
    assert_eq!(cache.count_bounced().unwrap(), 0);

    // Second removal returns None
    assert!(cache.remove_bounce("did:plc:spammer1").unwrap().is_none());
}

#[test]
fn test_sqlite_cache_evaluation_ttl_and_pruning() {
    let cache = DeduplicationCache::open_in_memory().unwrap();
    let verdict = Verdict::Violation {
        category: ViolationCategory::Harassment,
        confidence: 0.88,
        reason: "Persistent target abuse".to_string(),
    };

    // Store evaluation valid for 10 seconds
    cache
        .set_evaluation(
            "cache_key_live",
            "did:plc:author1",
            &verdict,
            Duration::from_secs(10),
        )
        .unwrap();

    let cached = cache.get_evaluation("cache_key_live").unwrap();
    assert_eq!(cached, Some(verdict.clone()));

    // Store evaluation with 0 TTL (already expired)
    cache
        .set_evaluation(
            "cache_key_expired",
            "did:plc:author2",
            &verdict,
            Duration::ZERO,
        )
        .unwrap();

    // get_evaluation deletes expired entry on access
    assert_eq!(cache.get_evaluation("cache_key_expired").unwrap(), None);

    // Store another expired entry and prune it
    cache
        .set_evaluation(
            "cache_key_prunable",
            "did:plc:author3",
            &verdict,
            Duration::ZERO,
        )
        .unwrap();

    assert_eq!(cache.count_evaluations().unwrap(), 2); // 1 live + 1 prunable
    let pruned = cache.prune_expired_evaluations().unwrap();
    assert_eq!(pruned, 1);
    assert_eq!(cache.count_evaluations().unwrap(), 1);
}

// ============================================================================
// 2. ModListManager Provisioning Tests
// ============================================================================

#[tokio::test]
async fn test_ensure_mod_list_cache_hit_zero_network() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // Call 1: Provisions list and caches
    let uri1 = manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .unwrap();
    assert!(uri1.starts_with("at://did:plc:alice/app.bsky.graph.list/"));
    assert_eq!(pds.created_records.lock().len(), 2); // 1 list + 1 listblock

    // Call 2: Cache hit short-circuits with 0 additional PDS requests
    let uri2 = manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .unwrap();
    assert_eq!(uri1, uri2);
    assert_eq!(pds.created_records.lock().len(), 2);
}

#[tokio::test]
async fn test_ensure_mod_list_provisions_when_not_cached() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    let uri = manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .unwrap();
    assert!(uri.starts_with("at://did:plc:alice/app.bsky.graph.list/"));

    let records = pds.created_records.lock();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["collection"], "app.bsky.graph.list");
    assert_eq!(records[1]["collection"], "app.bsky.graph.listblock");
    assert_eq!(records[1]["record"]["subject"], uri);
    assert_eq!(
        records[0]["record"]["purpose"],
        "app.bsky.graph.defs#modlist"
    );
    assert_eq!(records[0]["record"]["name"], "Skybouncer Moderation List");

    // Cache is populated
    let cached = manager.get_mod_list("did:plc:alice").unwrap().unwrap();
    assert_eq!(cached.list_uri, uri);
}

#[tokio::test]
async fn test_ensure_mod_list_discovers_existing_remote_list() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");

    // Mount an existing remote moderation list on PDS
    pds.mount_existing_list(
        "did:plc:alice",
        "existing_modlist_rkey",
        "Pre-existing Mod List",
    )
    .await;

    let manager = ModListManager::open_in_memory().unwrap();

    // ensure_mod_list discovers the existing list via listRecords instead of creating a new one
    let uri = manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .unwrap();
    assert_eq!(
        uri,
        "at://did:plc:alice/app.bsky.graph.list/existing_modlist_rkey"
    );

    // Zero list createRecord requests issued; auto-subscribes listblock
    let created = pds.created_records.lock();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["collection"], "app.bsky.graph.listblock");
    assert_eq!(created[0]["record"]["subject"], uri);

    // Existing list is now cached locally
    let cached = manager.get_mod_list("did:plc:alice").unwrap().unwrap();
    assert_eq!(cached.list_uri, uri);
    assert_eq!(cached.list_cid, "bafyexisting_modlist_rkeyexistingcid");
}

// ============================================================================
// 3. ModListManager Bounce Violator Tests
// ============================================================================

#[tokio::test]
async fn test_bounce_user_success_and_cache_population() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    let res = manager
        .bounce_user(
            &client,
            "did:plc:alice",
            "did:plc:violator_crypto",
            &ViolationCategory::CryptoSpam,
            0.96,
            "Airdrop phishing scam",
            "at://did:plc:violator_crypto/app.bsky.feed.post/123",
        )
        .await
        .unwrap();

    assert!(res.is_some());
    let listitem_uri = res.unwrap();
    assert!(listitem_uri.starts_with("at://did:plc:alice/app.bsky.graph.listitem/"));

    // Verify 3 PDS creations: list + listblock + listitem
    let records = pds.created_records.lock();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["collection"], "app.bsky.graph.list");
    assert_eq!(records[1]["collection"], "app.bsky.graph.listblock");
    assert_eq!(records[2]["collection"], "app.bsky.graph.listitem");
    assert_eq!(records[2]["record"]["subject"], "did:plc:violator_crypto");

    // Verify cache record
    assert!(manager.is_bounced("did:plc:violator_crypto").unwrap());
    let user = manager
        .get_bounced_user("did:plc:violator_crypto")
        .unwrap()
        .unwrap();
    assert_eq!(user.category, "crypto_spam");
    assert_eq!(user.confidence, 0.96);
    assert_eq!(user.reason, "Airdrop phishing scam");
    assert_eq!(user.listitem_uri, listitem_uri);
}

#[tokio::test]
async fn test_bounce_user_deduplication_drops_redundant_writes() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // First bounce
    let res1 = manager
        .bounce_user(
            &client,
            "did:plc:alice",
            "did:plc:repeated_spammer",
            &ViolationCategory::Spam,
            0.92,
            "First spam attack",
            "at://did:plc:repeated_spammer/app.bsky.feed.post/1",
        )
        .await
        .unwrap();
    assert!(res1.is_some());
    assert_eq!(pds.created_records.lock().len(), 3); // 1 list + 1 listblock + 1 listitem

    // Second bounce: same candidate DID drops immediately at zero cost
    let res2 = manager
        .bounce_user(
            &client,
            "did:plc:alice",
            "did:plc:repeated_spammer",
            &ViolationCategory::Spam,
            0.99,
            "Second spam attack",
            "at://did:plc:repeated_spammer/app.bsky.feed.post/2",
        )
        .await
        .unwrap();
    assert!(res2.is_none());
    assert_eq!(pds.created_records.lock().len(), 3); // No new PDS requests
}

#[tokio::test]
async fn test_bounce_user_sensitivity_threshold_filter() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let rubric = RuleRubric::new("Strict moderation rules", Sensitivity::Medium); // threshold 0.75
    let manager = ModListManager::open_in_memory()
        .unwrap()
        .with_rubric(rubric);

    // Below threshold (0.65 < 0.75) -> dropped without network or DB writes
    let res = manager
        .bounce_user(
            &client,
            "did:plc:alice",
            "did:plc:borderline_user",
            &ViolationCategory::Harassment,
            0.65,
            "Mild sarcasm",
            "at://did:plc:borderline_user/app.bsky.feed.post/1",
        )
        .await
        .unwrap();

    assert!(res.is_none());
    assert_eq!(pds.created_records.lock().len(), 0);
    assert!(!manager.is_bounced("did:plc:borderline_user").unwrap());
}

// ============================================================================
// 4. ModListManager Pardon Tests
// ============================================================================

#[tokio::test]
async fn test_pardon_user_deletes_record_and_purges_cache() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // 1. Bounce user
    manager
        .bounce_user(
            &client,
            "did:plc:alice",
            "did:plc:reformed_user",
            &ViolationCategory::SeaLioning,
            0.85,
            "Badgering questions",
            "at://did:plc:reformed_user/app.bsky.feed.post/1",
        )
        .await
        .unwrap();
    assert!(manager.is_bounced("did:plc:reformed_user").unwrap());

    // 2. Pardon user
    let pardoned = manager
        .pardon_user(&client, "did:plc:alice", "did:plc:reformed_user")
        .await
        .unwrap();
    assert!(pardoned);

    // Verify PDS deleteRecord was dispatched
    let deleted = pds.deleted_records.lock();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["collection"], "app.bsky.graph.listitem");

    // Verify user removed from local cache
    assert!(!manager.is_bounced("did:plc:reformed_user").unwrap());
}

#[tokio::test]
async fn test_pardon_unbounced_user_returns_false() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    let pardoned = manager
        .pardon_user(&client, "did:plc:alice", "did:plc:innocent_user")
        .await
        .unwrap();
    assert!(!pardoned);
    assert_eq!(pds.deleted_records.lock().len(), 0);
}

// ============================================================================
// 5. Resilience & Fault Tolerance Tests
// ============================================================================

#[tokio::test]
async fn test_bounce_user_recovers_from_dpop_nonce_challenge() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // Inject one-time 401 DPoP challenge
    pds.mount_nonce_challenge_once("fresh_nonce_challenge_12345")
        .await;

    let res = manager
        .bounce_user(
            &client,
            "did:plc:alice",
            "did:plc:dpop_challenge_violator",
            &ViolationCategory::Phishing,
            0.99,
            "Credential harvester",
            "at://did:plc:dpop_challenge_violator/app.bsky.feed.post/1",
        )
        .await
        .unwrap();

    assert!(res.is_some());
    assert!(manager
        .is_bounced("did:plc:dpop_challenge_violator")
        .unwrap());
}

#[tokio::test]
async fn test_bounce_user_pds_failure_preserves_cache() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // Mount 500 error on createRecord
    pds.mount_create_error_once(500, "InternalServerError", "Database unavailable")
        .await;

    let res = manager
        .bounce_user(
            &client,
            "did:plc:alice",
            "did:plc:failed_bounce_user",
            &ViolationCategory::HateSpeech,
            0.95,
            "Hate speech violation",
            "at://did:plc:failed_bounce_user/app.bsky.feed.post/1",
        )
        .await;

    assert!(res.is_err());
    // Cache must NOT record this bounce
    assert!(!manager.is_bounced("did:plc:failed_bounce_user").unwrap());
}

#[tokio::test]
async fn test_pardon_user_pds_failure_preserves_cache() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();

    // 1. Bounce user
    manager
        .bounce_user(
            &client,
            "did:plc:alice",
            "did:plc:failed_pardon_user",
            &ViolationCategory::Spam,
            0.90,
            "Spam comment",
            "at://did:plc:failed_pardon_user/app.bsky.feed.post/1",
        )
        .await
        .unwrap();
    assert!(manager.is_bounced("did:plc:failed_pardon_user").unwrap());

    // 2. Mount 503 error on deleteRecord
    pds.mount_delete_error_once(503, "ServiceUnavailable", "PDS busy")
        .await;

    let res = manager
        .pardon_user(&client, "did:plc:alice", "did:plc:failed_pardon_user")
        .await;
    assert!(res.is_err());

    // User must remain recorded as bounced in cache
    assert!(manager.is_bounced("did:plc:failed_pardon_user").unwrap());
}

#[tokio::test]
async fn test_concurrent_distinct_violator_bounces() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = Arc::new(ModListManager::open_in_memory().unwrap());

    // Pre-provision list
    manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .unwrap();

    let mut handles = Vec::new();
    for i in 0..10 {
        let mgr = Arc::clone(&manager);
        let cl = client.clone();
        handles.push(tokio::spawn(async move {
            let did = format!("did:plc:concurrent_violator_{i}");
            mgr.bounce_user(
                &cl,
                "did:plc:alice",
                &did,
                &ViolationCategory::CryptoSpam,
                0.90,
                "Mass airdrop spam",
                &format!("at://{did}/app.bsky.feed.post/1"),
            )
            .await
        }));
    }

    for h in handles {
        let res = h.await.unwrap().unwrap();
        assert!(res.is_some());
    }

    assert_eq!(manager.cache().count_bounced().unwrap(), 10);
}

#[tokio::test]
async fn test_file_backed_sqlite_persistence() {
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let db_path = temp_file.path().to_str().unwrap().to_string();

    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");

    // Session 1: Provision and bounce
    {
        let manager = ModListManager::open(&db_path).unwrap();
        manager
            .bounce_user(
                &client,
                "did:plc:alice",
                "did:plc:disk_persisted_user",
                &ViolationCategory::Spam,
                0.95,
                "Disk persistence test spam",
                "at://did:plc:disk_persisted_user/app.bsky.feed.post/1",
            )
            .await
            .unwrap();
        assert!(manager.is_bounced("did:plc:disk_persisted_user").unwrap());
    }

    // Session 2: Reopen from disk path and verify state persisted across restart
    {
        let manager2 = ModListManager::open(&db_path).unwrap();
        assert!(manager2.is_bounced("did:plc:disk_persisted_user").unwrap());
        let list_config = manager2.get_mod_list("did:plc:alice").unwrap().unwrap();
        assert!(list_config.list_uri.contains("app.bsky.graph.list"));
    }
}

#[tokio::test]
async fn test_multi_rkey_tracking_and_pardon_cleanup() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();
    let cache = manager.cache();

    let target_did = "did:plc:multi_rkey_violator";

    // Simulate 3 distinct bounce mutations recorded over time for the same DID
    for i in 1..=3 {
        let entry = BouncedUser {
            subject_did: target_did.to_string(),
            protected_did: "did:plc:alice".to_string(),
            listitem_uri: format!("at://did:plc:alice/app.bsky.graph.listitem/rkey_{i}"),
            listitem_rkey: format!("rkey_{i}"),
            listitem_cid: format!("bafycid_{i}"),
            category: "spam".to_string(),
            confidence: 0.95,
            reason: format!("Repeated attack attempt {i}"),
            post_uri: format!("at://{target_did}/app.bsky.feed.post/{i}"),
            post_text: format!("Attack post {i}"),
            bounced_at: 1_720_000_000_000_000 + (i as u64),
            expires_at: None,
        };
        cache.record_bounce(&entry).unwrap();
    }

    // Verify all 3 rkeys are tracked in SQLite
    let tracked_rkeys = cache.get_all_bounced_rkeys(target_did).unwrap();
    assert_eq!(tracked_rkeys.len(), 3);
    assert!(tracked_rkeys.contains(&"rkey_1".to_string()));
    assert!(tracked_rkeys.contains(&"rkey_2".to_string()));
    assert!(tracked_rkeys.contains(&"rkey_3".to_string()));

    // Pardon user: must delete all 3 rkeys from PDS
    let pardoned = manager
        .pardon_user(&client, "did:plc:alice", target_did)
        .await
        .unwrap();
    assert!(pardoned);

    // Verify all 3 rkeys were sent to PDS deleteRecord
    let deleted = pds.deleted_records.lock();
    assert_eq!(deleted.len(), 3);
    let deleted_rkeys: std::collections::HashSet<_> = deleted
        .iter()
        .filter_map(|r| r["rkey"].as_str().map(String::from))
        .collect();
    assert!(deleted_rkeys.contains("rkey_1"));
    assert!(deleted_rkeys.contains("rkey_2"));
    assert!(deleted_rkeys.contains("rkey_3"));

    // Verify cache is completely clean of all records for this DID
    assert!(!manager.is_bounced(target_did).unwrap());
    assert!(cache.get_all_bounced_rkeys(target_did).unwrap().is_empty());
    assert_eq!(cache.count_bounced().unwrap(), 0);
}

#[tokio::test]
async fn test_temporary_ttl_bounce_expiration_and_cache_pruning() {
    let cache = DeduplicationCache::open_in_memory().unwrap();
    let now_us = 1_720_000_000_000_000;

    // 1. Verify BounceDuration string parsing and roundtrip
    assert_eq!(
        "24h".parse::<BounceDuration>().unwrap(),
        BounceDuration::Cooldown24h
    );
    assert_eq!(
        "7d".parse::<BounceDuration>().unwrap(),
        BounceDuration::Timeout7d
    );
    assert_eq!(
        "30d".parse::<BounceDuration>().unwrap(),
        BounceDuration::Timeout30d
    );
    assert_eq!(
        "permanent".parse::<BounceDuration>().unwrap(),
        BounceDuration::Permanent
    );
    assert_eq!(
        "3600".parse::<BounceDuration>().unwrap(),
        BounceDuration::Custom(3600)
    );

    // 2. Verify RuleRubric directive parsing with timeout/duration
    let rubric =
        RuleRubric::parse("[duration: 24h]\n[sensitivity: high]\nBlock all crypto scams").unwrap();
    assert_eq!(rubric.bounce_duration, BounceDuration::Cooldown24h);
    assert_eq!(rubric.sensitivity, Sensitivity::High);

    // 3. Populate 3 records: expired, unexpired, permanent
    let expired_user = BouncedUser {
        subject_did: "did:plc:expired_violator".to_string(),
        protected_did: "did:plc:alice".to_string(),
        listitem_uri: "at://did:plc:alice/app.bsky.graph.listitem/item_exp".to_string(),
        listitem_rkey: "item_exp".to_string(),
        listitem_cid: "bafyitemexp".to_string(),
        category: "spam".to_string(),
        confidence: 0.95,
        reason: "Temporary spam timeout".to_string(),
        post_uri: "at://did:plc:expired_violator/app.bsky.feed.post/1".to_string(),
        post_text: "Spam text".to_string(),
        bounced_at: now_us - 100_000_000,
        expires_at: Some(now_us - 50_000_000), // Expired in the past
    };

    let active_user = BouncedUser {
        subject_did: "did:plc:active_violator".to_string(),
        protected_did: "did:plc:alice".to_string(),
        listitem_uri: "at://did:plc:alice/app.bsky.graph.listitem/item_act".to_string(),
        listitem_rkey: "item_act".to_string(),
        listitem_cid: "bafyitemact".to_string(),
        category: "harassment".to_string(),
        confidence: 0.98,
        reason: "Active 7-day timeout".to_string(),
        post_uri: "at://did:plc:active_violator/app.bsky.feed.post/1".to_string(),
        post_text: "Harassment text".to_string(),
        bounced_at: now_us,
        expires_at: Some(now_us + 100_000_000), // Active into future
    };

    let perm_user = BouncedUser {
        subject_did: "did:plc:permanent_violator".to_string(),
        protected_did: "did:plc:alice".to_string(),
        listitem_uri: "at://did:plc:alice/app.bsky.graph.listitem/item_perm".to_string(),
        listitem_rkey: "item_perm".to_string(),
        listitem_cid: "bafyitemperm".to_string(),
        category: "crypto_scam".to_string(),
        confidence: 0.99,
        reason: "Permanent ban".to_string(),
        post_uri: "at://did:plc:permanent_violator/app.bsky.feed.post/1".to_string(),
        post_text: "Airdrop link".to_string(),
        bounced_at: now_us,
        expires_at: None,
    };

    assert!(expired_user.is_expired(now_us));
    assert!(!active_user.is_expired(now_us));
    assert!(!perm_user.is_expired(now_us));

    cache.record_bounce(&expired_user).unwrap();
    cache.record_bounce(&active_user).unwrap();
    cache.record_bounce(&perm_user).unwrap();

    // 4. Query list_expired_bounces
    let expired_list = cache.list_expired_bounces(now_us).unwrap();
    assert_eq!(expired_list.len(), 1);
    assert_eq!(expired_list[0].subject_did, "did:plc:expired_violator");
    assert_eq!(expired_list[0].expires_at, Some(now_us - 50_000_000));

    // 5. Test PDS pardon on expired violator
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = ModListManager::open_in_memory().unwrap();
    manager.cache().record_bounce(&expired_user).unwrap();

    let pardoned = manager
        .pardon_user(&client, "did:plc:alice", &expired_user.subject_did)
        .await
        .unwrap();
    assert!(pardoned);
    assert!(!manager.is_bounced(&expired_user.subject_did).unwrap());
}
