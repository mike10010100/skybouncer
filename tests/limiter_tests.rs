//! Integration and unit tests for EvaluationRateLimiter (Tier-4 Anti-Denial-of-Wallet).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use skybouncer::limiter::{EvaluationRateLimiter, RateLimiterConfig};

#[tokio::test]
async fn test_rate_limiter_basic_ceiling() {
    let config = RateLimiterConfig {
        max_evaluations: 5,
        window_duration: Duration::from_secs(60),
    };
    let limiter = EvaluationRateLimiter::new(config);
    let target = "did:plc:alice";

    assert_eq!(limiter.remaining(target), 5);

    // Consume all 5
    for i in 0..5 {
        assert!(
            limiter.check_and_record(target),
            "Evaluation {i} should be allowed"
        );
        assert_eq!(limiter.remaining(target), 4 - i);
    }

    // 6th evaluation should be rejected
    assert!(
        !limiter.check_and_record(target),
        "6th evaluation should be rejected"
    );
    assert_eq!(limiter.remaining(target), 0);
}

#[tokio::test]
async fn test_rate_limiter_target_isolation() {
    let config = RateLimiterConfig {
        max_evaluations: 2,
        window_duration: Duration::from_secs(60),
    };
    let limiter = EvaluationRateLimiter::new(config);
    let alice = "did:plc:alice";
    let bob = "did:plc:bob";

    assert!(limiter.check_and_record(alice));
    assert!(limiter.check_and_record(alice));
    assert!(!limiter.check_and_record(alice));

    // Bob should still have full capacity
    assert_eq!(limiter.remaining(bob), 2);
    assert!(limiter.check_and_record(bob));
    assert!(limiter.check_and_record(bob));
    assert!(!limiter.check_and_record(bob));
}

#[tokio::test]
async fn test_rate_limiter_window_expiry() {
    let config = RateLimiterConfig {
        max_evaluations: 2,
        window_duration: Duration::from_millis(100),
    };
    let limiter = EvaluationRateLimiter::new(config);
    let target = "did:plc:carol";

    assert!(limiter.check_and_record(target));
    assert!(limiter.check_and_record(target));
    assert!(!limiter.check_and_record(target));

    // Wait for rolling window to expire
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Capacity should be refreshed
    assert_eq!(limiter.remaining(target), 2);
    assert!(limiter.check_and_record(target));
}

#[tokio::test]
async fn test_rate_limiter_reset_and_clear_all() {
    let config = RateLimiterConfig {
        max_evaluations: 3,
        window_duration: Duration::from_secs(60),
    };
    let limiter = EvaluationRateLimiter::new(config);
    let user1 = "did:plc:user1";
    let user2 = "did:plc:user2";

    let _ = limiter.check_and_record(user1);
    let _ = limiter.check_and_record(user1);
    let _ = limiter.check_and_record(user2);

    assert_eq!(limiter.remaining(user1), 1);
    assert_eq!(limiter.remaining(user2), 2);

    // Reset user1
    limiter.reset(user1);
    assert_eq!(limiter.remaining(user1), 3);
    assert_eq!(limiter.remaining(user2), 2);

    // Clear all
    let _ = limiter.check_and_record(user1);
    limiter.clear_all();
    assert_eq!(limiter.remaining(user1), 3);
    assert_eq!(limiter.remaining(user2), 3);
}

#[tokio::test]
async fn test_rate_limiter_unlimited() {
    let limiter = EvaluationRateLimiter::new(RateLimiterConfig::unlimited());
    let target = "did:plc:unlimited_target";

    for _ in 0..500 {
        assert!(limiter.check_and_record(target));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_rate_limiter_concurrent_hammer() {
    let config = RateLimiterConfig {
        max_evaluations: 50,
        window_duration: Duration::from_secs(60),
    };
    let limiter = Arc::new(EvaluationRateLimiter::new(config));
    let target = "did:plc:hammer_target";
    let allowed_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..100 {
        let lim = Arc::clone(&limiter);
        let count = Arc::clone(&allowed_count);
        let tgt = target.to_string();
        handles.push(tokio::spawn(async move {
            if lim.check_and_record(&tgt) {
                count.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(
        allowed_count.load(Ordering::SeqCst),
        50,
        "Exactly 50 evaluations should be allowed under concurrent race"
    );
    assert_eq!(limiter.remaining(target), 0);
}
