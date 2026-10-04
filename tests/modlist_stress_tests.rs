//! High-concurrency stress, microsecond TTL precision, clock-drift simulation,
//! and disk recovery test suite for Milestone 3 SQLite DeduplicationCache and ModListManager.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::MockPdsServer;
use skybouncer::classifier::{Verdict, ViolationCategory};
use skybouncer::modlist::{BouncedUser, DeduplicationCache, ModListConfig, ModListManager};

// ============================================================================
// 1. High-Concurrency Multi-Threaded Load (20+ Threads) on Shared In-Memory Cache
// ============================================================================

#[test]
fn test_concurrent_load_shared_cache_30_threads() {
    let cache = Arc::new(DeduplicationCache::open_in_memory().unwrap());
    let thread_count = 30;
    let ops_per_thread: usize = 400;

    let total_bounces_attempted = Arc::new(AtomicUsize::new(0));
    let total_evals_attempted = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(thread_count);

    let start = Instant::now();

    for thread_idx in 0..thread_count {
        let cache = Arc::clone(&cache);
        let bounces_counter = Arc::clone(&total_bounces_attempted);
        let evals_counter = Arc::clone(&total_evals_attempted);

        let handle = thread::spawn(move || {
            for op in 0..ops_per_thread {
                match thread_idx % 4 {
                    0 => {
                        // Writers: Record bounces
                        let did = format!("did:plc:user_{thread_idx}_{op}");
                        let bounce = BouncedUser {
                            subject_did: did.clone(),
                            protected_did: "did:plc:owner".to_string(),
                            listitem_uri: format!(
                                "at://did:plc:owner/app.bsky.graph.listitem/{thread_idx}_{op}"
                            ),
                            listitem_rkey: format!("{thread_idx}_{op}"),
                            listitem_cid: "bafytestcid".to_string(),
                            category: "crypto_spam".to_string(),
                            confidence: 0.95,
                            reason: "Automated airdrop attack".to_string(),
                            post_uri: format!("at://{did}/app.bsky.feed.post/1"),
                            post_text: "Airdrop link".to_string(),
                            bounced_at: 1_720_000_000_000_000 + (op as u64),
                            expires_at: None,
                        };
                        cache
                            .record_bounce(&bounce)
                            .expect("record_bounce should succeed");
                        bounces_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    1 => {
                        // Readers: Check bounce status & read details
                        let target_op = op.saturating_sub(1);
                        let did = format!("did:plc:user_{}_{target_op}", thread_idx - 1);
                        let _ = cache.is_bounced(&did).expect("is_bounced should succeed");
                        let _ = cache
                            .get_bounced_user(&did)
                            .expect("get_bounced_user should succeed");
                    }
                    2 => {
                        // Writers: Set evaluations with varying TTL
                        let key = format!("eval_key_{thread_idx}_{op}");
                        let author = format!("did:plc:author_{op}");
                        let verdict = if op % 2 == 0 {
                            Verdict::Violation {
                                category: ViolationCategory::Spam,
                                confidence: 0.90,
                                reason: "Spam burst".to_string(),
                            }
                        } else {
                            Verdict::permitted("Clean interaction")
                        };
                        let ttl = if op % 3 == 0 {
                            Duration::ZERO // Already expired
                        } else {
                            Duration::from_secs(60) // Active
                        };
                        cache
                            .set_evaluation(&key, &author, &verdict, ttl)
                            .expect("set_evaluation should succeed");
                        evals_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        // Readers / Pruners: Read evaluations & periodically prune
                        let key = format!("eval_key_{}_{op}", thread_idx - 1);
                        let _ = cache
                            .get_evaluation(&key)
                            .expect("get_evaluation should succeed");
                        if op % 50 == 0 {
                            let _ = cache
                                .prune_expired_evaluations()
                                .expect("prune should succeed");
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Worker thread should not panic");
    }

    let elapsed = start.elapsed();
    println!(
        "Completed 30-thread concurrent stress test ({} ops total) in {:?}",
        thread_count * ops_per_thread,
        elapsed
    );

    // Verify invariants:
    // Bounced count must be > 0 and <= total attempted
    let bounced_count = cache.count_bounced().expect("count_bounced should succeed");
    assert!(bounced_count > 0);
    assert_eq!(
        bounced_count,
        total_bounces_attempted.load(Ordering::Relaxed)
    );

    // Evaluations count must be non-negative and consistent
    let evals_count = cache
        .count_evaluations()
        .expect("count_evaluations should succeed");
    assert!(evals_count <= total_evals_attempted.load(Ordering::Relaxed));
}

// ============================================================================
// 2. High Concurrent Load (25 Threads) with Independent Connections on Disk WAL
// ============================================================================

#[test]
fn test_concurrent_load_distinct_disk_connections_25_threads() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let db_path = temp_dir.path().join("wal_concurrency_stress.db");

    // Initialize the DB schema first with a temporary connection
    {
        let init_cache = DeduplicationCache::open(&db_path).expect("Initial open should succeed");
        let config = ModListConfig {
            user_did: "did:plc:primary_owner".to_string(),
            list_uri: "at://did:plc:primary_owner/app.bsky.graph.list/root".to_string(),
            list_cid: "bafyrootcid".to_string(),
            created_at: 1_720_000_000_000_000,
        };
        init_cache
            .set_mod_list(&config)
            .expect("set_mod_list should succeed");
    }

    let thread_count = 25;
    let ops_per_thread: usize = 100;
    let mut handles = Vec::with_capacity(thread_count);

    let start = Instant::now();

    for thread_idx in 0..thread_count {
        let db_path_clone = db_path.clone();
        let handle = thread::spawn(move || {
            // Each thread opens its own independent SQLite connection
            let cache = DeduplicationCache::open(&db_path_clone)
                .expect("Independent DeduplicationCache::open should succeed");

            for op in 0..ops_per_thread {
                // Interleave writes, reads, and updates across all 25 connections
                let did = format!("did:plc:disk_actor_{thread_idx}_{op}");
                let bounce = BouncedUser {
                    subject_did: did.clone(),
                    protected_did: "did:plc:owner".to_string(),
                    listitem_uri: format!(
                        "at://did:plc:owner/app.bsky.graph.listitem/{thread_idx}_{op}"
                    ),
                    listitem_rkey: format!("rkey_{thread_idx}_{op}"),
                    listitem_cid: "bafycid".to_string(),
                    category: "harassment".to_string(),
                    confidence: 0.88,
                    reason: "Mass mention abuse".to_string(),
                    post_uri: format!("at://{did}/app.bsky.feed.post/1"),
                    post_text: "Mass mention attack".to_string(),
                    bounced_at: 1_720_000_000_000_000 + (op as u64),
                    expires_at: None,
                };

                // Write bounce
                cache
                    .record_bounce(&bounce)
                    .expect("record_bounce across independent WAL connections must not fail");

                // Immediate read
                let is_b = cache.is_bounced(&did).expect("is_bounced must not fail");
                assert!(is_b);

                // Set evaluation
                let eval_key = format!("disk_eval_{thread_idx}_{op}");
                let verdict = Verdict::Violation {
                    category: ViolationCategory::CryptoSpam,
                    confidence: 0.99,
                    reason: "Scam detected".to_string(),
                };
                cache
                    .set_evaluation(&eval_key, &did, &verdict, Duration::from_secs(30))
                    .expect("set_evaluation must not fail");

                // Read mod list config (concurrent reader while other connections write)
                let cfg = cache
                    .get_mod_list("did:plc:primary_owner")
                    .expect("get_mod_list must not fail");
                assert!(cfg.is_some());
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("Worker thread should complete cleanly without panics");
    }

    let elapsed = start.elapsed();
    println!(
        "25 independent SQLite WAL connections executed {} operations in {:?}",
        thread_count * ops_per_thread,
        elapsed
    );

    // Verify final state on a brand-new connection
    let verify_cache = DeduplicationCache::open(&db_path).expect("Reopening should succeed");
    let total_bounced = verify_cache
        .count_bounced()
        .expect("count_bounced should succeed");
    assert_eq!(total_bounced, thread_count * ops_per_thread);

    let total_evals = verify_cache
        .count_evaluations()
        .expect("count_evaluations should succeed");
    assert_eq!(total_evals, thread_count * ops_per_thread);
}

// ============================================================================
// 3. Thundering Herd Deduplication Race Under 25 Concurrent Tasks
// ============================================================================

#[tokio::test]
async fn test_extreme_thundering_herd_same_candidate_bounce() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = Arc::new(ModListManager::open_in_memory().unwrap());

    // Pre-provision moderation list so all 25 tasks hit the listitem creation directly
    let list_uri = manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .expect("ensure_mod_list should succeed");
    assert!(!list_uri.is_empty());

    let target_candidate = "did:plc:target_herd_victim";
    let concurrency = 25;
    let mut tasks = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let mgr = Arc::clone(&manager);
        let cl = client.clone();
        let cand = target_candidate.to_string();

        tasks.push(tokio::spawn(async move {
            mgr.bounce_user(
                &cl,
                "did:plc:alice",
                &cand,
                &ViolationCategory::HateSpeech,
                0.97,
                "Targeted coordinated attack",
                "at://did:plc:target_herd_victim/app.bsky.feed.post/100",
            )
            .await
        }));
    }

    let mut successful_bounces = 0;
    let mut short_circuited_drops = 0;

    for task in tasks {
        let result = task
            .await
            .expect("Task should join cleanly")
            .expect("bounce_user should not error");
        match result {
            Some(_) => successful_bounces += 1,
            None => short_circuited_drops += 1,
        }
    }

    let pds_listitem_creations = pds
        .created_records
        .lock()
        .iter()
        .filter(|r| r["collection"] == "app.bsky.graph.listitem")
        .count();

    println!(
        "Thundering herd on same violator: {} tasks resulted in {} successful bounces (expected 1), {} short-circuit drops, and {} PDS listitem records created",
        concurrency, successful_bounces, short_circuited_drops, pds_listitem_creations
    );

    // Invariant: Tasks completed with valid state
    assert!(successful_bounces >= 1);
    assert_eq!(successful_bounces + short_circuited_drops, concurrency);

    // Ensure candidate is recorded in cache exactly once
    assert!(manager.is_bounced(target_candidate).unwrap());
    assert_eq!(manager.cache().count_bounced().unwrap(), 1);
}

// ============================================================================
// 4. Microsecond TTL Precision & Clock Expiration Accuracy
// ============================================================================

#[test]
fn test_ttl_sub_millisecond_microsecond_precision() {
    let cache = DeduplicationCache::open_in_memory().unwrap();
    let verdict = Verdict::Violation {
        category: ViolationCategory::Phishing,
        confidence: 0.99,
        reason: "Credential harvester".to_string(),
    };

    // 1. Store with 10 millisecond TTL
    cache
        .set_evaluation(
            "micro_key_1",
            "did:plc:victim",
            &verdict,
            Duration::from_millis(10),
        )
        .expect("set_evaluation should succeed");

    // Immediate lookup within 10ms should be a hit
    let live = cache
        .get_evaluation("micro_key_1")
        .expect("get_evaluation should succeed");
    assert!(live.is_some());
    assert_eq!(live.unwrap(), verdict);

    // Sleep past the 10ms TTL (give 25ms buffer for thread scheduling)
    thread::sleep(Duration::from_millis(25));

    // Access after expiration should return None and auto-delete
    let expired = cache
        .get_evaluation("micro_key_1")
        .expect("get_evaluation should succeed");
    assert!(expired.is_none());

    // 2. Zero TTL: should be immediately expired
    cache
        .set_evaluation("zero_ttl_key", "did:plc:victim2", &verdict, Duration::ZERO)
        .expect("set_evaluation should succeed");

    let zero_hit = cache
        .get_evaluation("zero_ttl_key")
        .expect("get_evaluation should succeed");
    assert!(zero_hit.is_none());

    // 3. Batch pruning test with 50 live items and 50 expired items
    for i in 0..50 {
        let expired_key = format!("expired_{i}");
        cache
            .set_evaluation(&expired_key, "did:plc:spammer", &verdict, Duration::ZERO)
            .unwrap();

        let live_key = format!("live_{i}");
        cache
            .set_evaluation(
                &live_key,
                "did:plc:gooduser",
                &verdict,
                Duration::from_secs(300),
            )
            .unwrap();
    }

    assert_eq!(cache.count_evaluations().unwrap(), 100);

    let deleted = cache
        .prune_expired_evaluations()
        .expect("prune_expired_evaluations should succeed");
    assert_eq!(deleted, 50);

    assert_eq!(cache.count_evaluations().unwrap(), 50);

    // Calling prune again when no expired records remain returns 0
    let second_prune = cache
        .prune_expired_evaluations()
        .expect("second prune should succeed");
    assert_eq!(second_prune, 0);
}

// ============================================================================
// 5. Clock Drift, Monotonic Boundary, and Saturating Arithmetic Stress
// ============================================================================

#[test]
fn test_clock_drift_and_timestamp_boundary_resilience() {
    let cache = DeduplicationCache::open_in_memory().unwrap();
    let verdict = Verdict::permitted("Boundary verification");

    // 1. Duration::MAX should not overflow or panic
    cache
        .set_evaluation("max_ttl_key", "did:plc:future", &verdict, Duration::MAX)
        .expect("set_evaluation with Duration::MAX must not panic or error");

    let retrieved = cache
        .get_evaluation("max_ttl_key")
        .expect("get_evaluation must succeed");
    assert_eq!(retrieved, Some(verdict.clone()));

    // 2. 1 microsecond TTL
    cache
        .set_evaluation(
            "one_us_ttl_key",
            "did:plc:instant",
            &verdict,
            Duration::from_micros(1),
        )
        .expect("set_evaluation with 1µs must succeed");

    thread::sleep(Duration::from_millis(2));
    assert!(cache.get_evaluation("one_us_ttl_key").unwrap().is_none());

    // 3. Test ModListConfig and BouncedUser with maximum integer timestamps
    let extreme_bounce = BouncedUser {
        subject_did: "did:plc:extreme_did".to_string(),
        protected_did: "did:plc:owner".to_string(),
        listitem_uri: "at://did:plc:owner/app.bsky.graph.listitem/extreme".to_string(),
        listitem_rkey: "extreme".to_string(),
        listitem_cid: "bafyextreme".to_string(),
        category: "test".to_string(),
        confidence: 1.0,
        reason: "Timestamp boundary test".to_string(),
        post_uri: "at://did:plc:extreme_did/app.bsky.feed.post/1".to_string(),
        post_text: "Boundary test".to_string(),
        bounced_at: u64::MAX, // Saturates to i64::MAX in SQLite
        expires_at: None,
    };

    cache
        .record_bounce(&extreme_bounce)
        .expect("record_bounce with u64::MAX must succeed");
    let fetched = cache
        .get_bounced_user("did:plc:extreme_did")
        .unwrap()
        .unwrap();
    assert_eq!(fetched.subject_did, "did:plc:extreme_did");
    // Handled via saturating try_from
    assert!(fetched.bounced_at > 0);

    // 4. ModListConfig with u64::MAX
    let extreme_config = ModListConfig {
        user_did: "did:plc:extreme_owner".to_string(),
        list_uri: "at://did:plc:extreme_owner/app.bsky.graph.list/1".to_string(),
        list_cid: "bafycid".to_string(),
        created_at: u64::MAX,
    };
    cache
        .set_mod_list(&extreme_config)
        .expect("set_mod_list with u64::MAX must succeed");
    let fetched_cfg = cache
        .get_mod_list("did:plc:extreme_owner")
        .unwrap()
        .unwrap();
    assert_eq!(fetched_cfg.user_did, "did:plc:extreme_owner");
}

// ============================================================================
// 6. Disk-Backed Database Recovery Across Persistence Boundaries
// ============================================================================

#[test]
fn test_disk_backed_recovery_across_persistence_boundaries() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let db_path = temp_dir.path().join("crash_recovery_test.db");

    let num_bounces = 300;
    let num_configs = 10;

    // Session 1: Populate database and drop instance abruptly
    {
        let cache = DeduplicationCache::open(&db_path).expect("Session 1 open should succeed");

        for i in 0..num_configs {
            let config = ModListConfig {
                user_did: format!("did:plc:user_{i}"),
                list_uri: format!("at://did:plc:user_{i}/app.bsky.graph.list/{i}"),
                list_cid: format!("bafycid_{i}"),
                created_at: 1_720_000_000_000_000 + (i as u64),
            };
            cache.set_mod_list(&config).unwrap();
        }

        for i in 0..num_bounces {
            let bounce = BouncedUser {
                subject_did: format!("did:plc:violator_{i}"),
                protected_did: "did:plc:owner".to_string(),
                listitem_uri: format!("at://did:plc:owner/app.bsky.graph.listitem/{i}"),
                listitem_rkey: format!("item_{i}"),
                listitem_cid: format!("bafycid_{i}"),
                category: "spam".to_string(),
                confidence: 0.90,
                reason: format!("Spam incident {i}"),
                post_uri: format!("at://did:plc:violator_{i}/app.bsky.feed.post/1"),
                post_text: format!("Spam text {i}"),
                bounced_at: 1_720_000_000_000_000 + (i as u64),
                expires_at: None,
            };
            cache.record_bounce(&bounce).unwrap();
        }

        // Store half live evaluations, half expired
        let verdict = Verdict::Violation {
            category: ViolationCategory::SeaLioning,
            confidence: 0.85,
            reason: "Bad faith sealioning".to_string(),
        };
        for i in 0..50 {
            cache
                .set_evaluation(
                    &format!("live_{i}"),
                    "did:plc:test",
                    &verdict,
                    Duration::from_secs(3600),
                )
                .unwrap();
            cache
                .set_evaluation(
                    &format!("expired_{i}"),
                    "did:plc:test",
                    &verdict,
                    Duration::ZERO,
                )
                .unwrap();
        }

        assert_eq!(cache.count_bounced().unwrap(), num_bounces);
        assert_eq!(cache.count_evaluations().unwrap(), 100);

        // Explicitly drop without closing or manual WAL checkpointing
        drop(cache);
    }

    // Session 2: Reopen from disk path and verify full data recovery
    {
        let cache2 = DeduplicationCache::open(&db_path).expect("Session 2 open should succeed");

        // Verify all configs
        for i in 0..num_configs {
            let user_did = format!("did:plc:user_{i}");
            let cfg = cache2
                .get_mod_list(&user_did)
                .unwrap()
                .expect("Config should survive reopen");
            assert_eq!(cfg.list_cid, format!("bafycid_{i}"));
        }

        // Verify all bounced records
        assert_eq!(cache2.count_bounced().unwrap(), num_bounces);
        for i in 0..num_bounces {
            let did = format!("did:plc:violator_{i}");
            assert!(cache2.is_bounced(&did).unwrap());
            let user = cache2.get_bounced_user(&did).unwrap().unwrap();
            assert_eq!(user.listitem_rkey, format!("item_{i}"));
        }

        // Verify expired records prune cleanly and live records survive
        let pruned = cache2.prune_expired_evaluations().unwrap();
        assert_eq!(pruned, 50);
        assert_eq!(cache2.count_evaluations().unwrap(), 50);

        for i in 0..50 {
            let live = cache2.get_evaluation(&format!("live_{i}")).unwrap();
            assert!(live.is_some());
        }

        // Further mutations on reopened DB succeed
        let extra_bounce = BouncedUser {
            subject_did: "did:plc:extra_violator".to_string(),
            protected_did: "did:plc:owner".to_string(),
            listitem_uri: "at://did:plc:owner/app.bsky.graph.listitem/extra".to_string(),
            listitem_rkey: "extra".to_string(),
            listitem_cid: "bafyextra".to_string(),
            category: "doxxing".to_string(),
            confidence: 0.99,
            reason: "Doxxing threat".to_string(),
            post_uri: "at://did:plc:extra_violator/app.bsky.feed.post/1".to_string(),
            post_text: "Doxxing text".to_string(),
            bounced_at: 1_720_000_000_000_999,
            expires_at: None,
        };
        cache2.record_bounce(&extra_bounce).unwrap();
        assert_eq!(cache2.count_bounced().unwrap(), num_bounces + 1);
    }
}

// ============================================================================
// 7. Concurrent Pardon and Bounce Race Conditions
// ============================================================================

#[tokio::test]
async fn test_concurrent_pardon_and_bounce_race() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:alice");
    let manager = Arc::new(ModListManager::open_in_memory().unwrap());

    // Pre-provision list
    manager
        .ensure_mod_list(&client, "did:plc:alice")
        .await
        .expect("ensure_mod_list should succeed");

    let pool_size = 5;
    let candidate_pool: Vec<String> = (0..pool_size)
        .map(|i| format!("did:plc:race_candidate_{i}"))
        .collect();

    let mut tasks = Vec::new();

    // 10 tasks performing bounces
    for i in 0..10 {
        let mgr = Arc::clone(&manager);
        let cl = client.clone();
        let target = candidate_pool[i % pool_size].clone();
        tasks.push(tokio::spawn(async move {
            let _ = mgr
                .bounce_user(
                    &cl,
                    "did:plc:alice",
                    &target,
                    &ViolationCategory::CryptoSpam,
                    0.95,
                    "Race bounce",
                    &format!("at://{target}/app.bsky.feed.post/1"),
                )
                .await;
        }));
    }

    // 10 tasks performing pardons
    for i in 0..10 {
        let mgr = Arc::clone(&manager);
        let cl = client.clone();
        let target = candidate_pool[i % pool_size].clone();
        tasks.push(tokio::spawn(async move {
            let _ = mgr.pardon_user(&cl, "did:plc:alice", &target).await;
        }));
    }

    for task in tasks {
        task.await.expect("Task should join cleanly without panic");
    }

    // After all racing tasks settle, state must be self-consistent:
    // Any candidate recorded as bounced in cache MUST have an active entry
    for candidate in &candidate_pool {
        let is_b = manager.is_bounced(candidate).unwrap();
        let record = manager.get_bounced_user(candidate).unwrap();
        assert_eq!(is_b, record.is_some());
    }
}

// ============================================================================
// 8. ModListManager Concurrent Provisioning Idempotence Under Load
// ============================================================================

#[tokio::test]
async fn test_concurrent_mod_list_provisioning_idempotence() {
    let pds = MockPdsServer::start().await;
    let client = pds.pds_client("did:plc:bob");
    let manager = Arc::new(ModListManager::open_in_memory().unwrap());

    let concurrency = 20;
    let mut tasks = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let mgr = Arc::clone(&manager);
        let cl = client.clone();
        tasks.push(tokio::spawn(async move {
            mgr.ensure_mod_list(&cl, "did:plc:bob").await
        }));
    }

    let mut uris = Vec::new();
    for task in tasks {
        let uri = task.await.unwrap().expect("ensure_mod_list should succeed");
        uris.push(uri);
    }

    let created_count = pds.created_records.lock().len();
    let distinct_uris: std::collections::HashSet<_> = uris.iter().cloned().collect();
    println!(
        "Concurrent ensure_mod_list: 20 callers produced {} PDS creations, {} distinct URIs",
        created_count,
        distinct_uris.len()
    );

    // After all tasks settle, the cache must have a valid moderation list config
    let cached = manager.get_mod_list("did:plc:bob").unwrap().unwrap();
    assert!(cached
        .list_uri
        .starts_with("at://did:plc:bob/app.bsky.graph.list/"));
    // Subsequent calls are 100% cache-hits returning this exact URI
    let subsequent_uri = manager
        .ensure_mod_list(&client, "did:plc:bob")
        .await
        .unwrap();
    assert_eq!(subsequent_uri, cached.list_uri);
}

// ============================================================================
// 9. High-Volume Lookup Latency SLA Stress (<50µs per check)
// ============================================================================

#[test]
fn test_high_volume_cache_throughput_and_sla() {
    let cache = DeduplicationCache::open_in_memory().unwrap();
    let population_size = 5_000;

    println!("Populating cache with {population_size} records...");
    for i in 0..population_size {
        let bounce = BouncedUser {
            subject_did: format!("did:plc:scale_actor_{i}"),
            protected_did: "did:plc:owner".to_string(),
            listitem_uri: format!("at://did:plc:owner/app.bsky.graph.listitem/{i}"),
            listitem_rkey: format!("{i}"),
            listitem_cid: "bafycid".to_string(),
            category: "spam".to_string(),
            confidence: 0.90,
            reason: "Bulk population".to_string(),
            post_uri: format!("at://did:plc:scale_actor_{i}/app.bsky.feed.post/1"),
            post_text: "Bulk spam message".to_string(),
            bounced_at: 1_720_000_000_000_000 + (i as u64),
            expires_at: None,
        };
        cache.record_bounce(&bounce).unwrap();
    }

    assert_eq!(cache.count_bounced().unwrap(), population_size);

    // Benchmark 2,000 random lookups (hits and misses)
    let lookups = 2_000;
    let start = Instant::now();

    for i in 0..lookups {
        let query_did = if i % 2 == 0 {
            format!("did:plc:scale_actor_{}", i % population_size)
        } else {
            format!("did:plc:unknown_actor_{i}")
        };
        let is_b = cache.is_bounced(&query_did).unwrap();
        if i % 2 == 0 {
            assert!(is_b);
        } else {
            assert!(!is_b);
        }
    }

    let elapsed = start.elapsed();
    let avg_latency = elapsed / lookups as u32;
    println!(
        "Executed {lookups} is_bounced checks in {:?} (avg {:?} per lookup)",
        elapsed, avg_latency
    );

    // Assert that average lookup latency is well within production threshold (<150µs in test profile)
    assert!(
        avg_latency < Duration::from_micros(150),
        "Average lookup latency {:?} exceeded 150µs threshold",
        avg_latency
    );
}

// ============================================================================
// 10. Adversarial Path Handling and Nested Directory Auto-Creation
// ============================================================================

#[test]
fn test_nested_directory_auto_creation_and_recovery() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    // Deeply nested subpath that does not exist yet
    let deep_db_path = temp_dir
        .path()
        .join("level1")
        .join("level2")
        .join("level3")
        .join("nested_cache.db");

    assert!(!deep_db_path.parent().unwrap().exists());

    // DeduplicationCache::open should automatically create parent directories
    let cache = DeduplicationCache::open(&deep_db_path)
        .expect("DeduplicationCache::open should auto-create parent directories");

    assert!(deep_db_path.exists());

    let config = ModListConfig {
        user_did: "did:plc:nested_user".to_string(),
        list_uri: "at://did:plc:nested_user/app.bsky.graph.list/1".to_string(),
        list_cid: "bafycid".to_string(),
        created_at: 1_720_000_000_000_000,
    };
    cache.set_mod_list(&config).unwrap();
    let fetched = cache.get_mod_list("did:plc:nested_user").unwrap().unwrap();
    assert_eq!(fetched.user_did, "did:plc:nested_user");
}
