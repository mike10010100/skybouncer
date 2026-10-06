//! Empirical adversarial, fault-injection, and concurrency verification suite
//! for `JevClassifier` (Milestone 1).
//!
//! Validates client resilience against:
//! 1. Malformed JSON, missing fields, type corruptions, unexpected keys, and empty bodies.
//! 2. Non-UTF8 binary byte streams on both 200 OK and error responses.
//! 3. Strict 4xx client error non-retry policies (400, 401, 403, 404, 422, 429).
//! 4. 5xx server error retry backoff timing and recovery (500, 502, 503, 504).
//! 5. Socket resets, abruptly dropped TCP connections, and network fault injection.
//! 6. High-concurrency load (50+ simultaneous tokio tasks) with connection pool reuse.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybouncer::classifier::{Classifier, JevClassifier, JevConfig, RuleRubric, ViolationCategory};
use skybouncer::matcher::{Interaction, InteractionType};

fn sample_interaction(text: &str) -> Interaction {
    Interaction {
        post_uri: "at://did:plc:adversarial_author/app.bsky.feed.post/3kadversarial".to_string(),
        post_cid: Some("bafyrei_adv_cid".to_string()),
        author_did: "did:plc:adversarial_author".to_string(),
        target_did: "did:plc:protected_target".to_string(),
        text: text.to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: Some("at://did:plc:protected_target/app.bsky.feed.post/root".to_string()),
        root_uri: Some("at://did:plc:protected_target/app.bsky.feed.post/root".to_string()),
        created_at_us: 1_700_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    }
}

// =============================================================================
// 1. Malformed JSON & Payload Corruptions
// =============================================================================

#[tokio::test]
async fn test_adversarial_malformed_json_syntax() {
    let server = MockServer::start().await;

    // Server returns 200 OK but with truncated/corrupted JSON syntax
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{\"violates\": true, \"confidence\": 0.95, \"reaso")
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Check this link");

    let err = classifier.classify(&interaction).await.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("Failed to parse Jev JSON response"),
        "Expected JSON parse error, got: {err_msg}"
    );
}

#[tokio::test]
async fn test_adversarial_missing_required_fields() {
    let server = MockServer::start().await;

    // Missing 'confidence' and 'reason'
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{\"violates\": true}")
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Check this link");

    let err = classifier.classify(&interaction).await.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("Failed to parse Jev JSON response"),
        "Expected missing field parse error, got: {err_msg}"
    );
}

#[tokio::test]
async fn test_adversarial_invalid_field_types() {
    let server = MockServer::start().await;

    // 'confidence' is returned as a string instead of f64
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    "{\"violates\": true, \"confidence\": \"ninety-nine\", \"reason\": \"spam\"}",
                )
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Check this link");

    let err = classifier.classify(&interaction).await.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("Failed to parse Jev JSON response"),
        "Expected type mismatch parse error, got: {err_msg}"
    );
}

#[tokio::test]
async fn test_adversarial_unexpected_unknown_keys_forward_compatibility() {
    let server = MockServer::start().await;

    // Server returns valid response PLUS future unexpected keys & metadata
    let payload_with_extra_keys = json!({
        "violates": true,
        "category": "spam",
        "confidence": 0.92,
        "reason": "Bot spam activity",
        "unexpected_server_version": "3.5.1",
        "trace_id": "018f-abcd-1234",
        "evaluation_metrics": {
            "tokens_consumed": 42,
            "inference_time_ms": 12.4
        }
    });

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload_with_extra_keys))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Bot spam");

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::Spam));
    assert_eq!(verdict.reason(), "Bot spam activity");
}

#[tokio::test]
async fn test_adversarial_empty_response_body() {
    let server = MockServer::start().await;

    // Server returns 200 OK with empty body (0 bytes)
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(vec![])
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("Failed to parse Jev JSON response"),
        "Expected parse failure on empty body, got: {err_msg}"
    );
}

#[tokio::test]
async fn test_adversarial_non_utf8_binary_body_on_200() {
    let server = MockServer::start().await;

    // Server returns 200 OK with completely invalid UTF-8 binary bytes
    let invalid_utf8_bytes = vec![0xFF, 0xFE, 0xFD, 0x80, 0x81, 0x00];

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(invalid_utf8_bytes)
                .insert_header("content-type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    let err_msg = err.to_string();

    assert!(
        err_msg.contains("Failed to parse Jev JSON response"),
        "Expected parse failure for invalid UTF-8, got: {err_msg}"
    );
}

#[tokio::test]
async fn test_adversarial_non_utf8_binary_body_on_error_status() {
    let server = MockServer::start().await;

    // Server returns 400 Bad Request with non-UTF8 binary bytes in error response
    let invalid_utf8_bytes = vec![0x80, 0x81, 0xFF, 0xAA];

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_bytes(invalid_utf8_bytes)
                .insert_header("content-type", "text/plain"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    let err_msg = err.to_string();

    // Client must not panic and must safely surface HTTP 400
    assert!(
        err_msg.contains("client error (HTTP 400)"),
        "Expected HTTP 400 error message, got: {err_msg}"
    );
}

#[tokio::test]
async fn test_adversarial_unknown_violation_category_maps_to_custom() {
    let server = MockServer::start().await;

    // Jev model introduces a novel violation category not hardcoded in enum
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "doxxing_and_pii_leak",
            "confidence": 0.98,
            "reason": "Exposing personal home address"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Personal info leak");

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    match verdict.category() {
        Some(ViolationCategory::Custom(ref cat)) => {
            assert_eq!(cat, "doxxing_and_pii_leak");
        }
        other => panic!("Expected Custom category, got {other:?}"),
    }
}

#[tokio::test]
async fn test_adversarial_null_category_maps_to_unspecified() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": null,
            "confidence": 0.88,
            "reason": "Violation without category"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Offensive comment");

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    assert_eq!(
        verdict.category(),
        Some(&ViolationCategory::Custom("unspecified".to_string()))
    );
}

#[tokio::test]
async fn test_adversarial_confidence_out_of_bounds_clamping() {
    let server = MockServer::start().await;

    // Server returns confidence score > 1.0 (e.g. 1.85 due to upstream scaling bug)
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "spam",
            "confidence": 1.85,
            "reason": "Massive spam score"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Massive spam");

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    // Verdict::violation must clamp to 1.0
    assert_eq!(verdict.confidence(), Some(1.0));
}

// =============================================================================
// 2. HTTP 4xx Non-Retry Invariants
// =============================================================================

#[tokio::test]
async fn test_adversarial_400_bad_request_strictly_no_retry() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Malformed request syntax"))
        .expect(1) // STRICT INVARIANT: Exactly 1 call made!
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 3, // Even with max_retries = 3, 400 must NEVER retry
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("client error (HTTP 400)"));
}

#[tokio::test]
async fn test_adversarial_403_forbidden_strictly_no_retry() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden: Quota Exceeded"))
        .expect(1) // STRICT INVARIANT: Exactly 1 call made!
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 3,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("client error (HTTP 403)"));
}

#[tokio::test]
async fn test_adversarial_404_not_found_strictly_no_retry() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Model endpoint not found"))
        .expect(1) // STRICT INVARIANT: Exactly 1 call made!
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 3,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("client error (HTTP 404)"));
}

#[tokio::test]
async fn test_adversarial_422_unprocessable_entity_strictly_no_retry() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(422).set_body_string("Unprocessable entity"))
        .expect(1) // STRICT INVARIANT: Exactly 1 call made!
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 3,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("client error (HTTP 422)"));
}

#[tokio::test]
async fn test_adversarial_429_too_many_requests_strictly_no_retry() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Rate limit exceeded"))
        .expect(1) // STRICT INVARIANT: 4xx treated as client error, fails immediately
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 3,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("client error (HTTP 429)"));
}

// =============================================================================
// 3. HTTP 5xx Retry Backoff & Timing
// =============================================================================

#[tokio::test]
async fn test_adversarial_502_bad_gateway_exhaustion() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .expect(2) // 1 initial + 1 retry = 2 attempts
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("server error (HTTP 502)"));
}

#[tokio::test]
async fn test_adversarial_503_retry_backoff_timing_assertion() {
    let server = MockServer::start().await;

    // max_retries = 2 -> 3 attempts total.
    // Each retry sleeps 100ms backoff.
    // Total elapsed time must be >= 200ms.
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(3) // 1 initial + 2 retries = 3 calls
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 2,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let start = Instant::now();
    let err = classifier.classify(&interaction).await.unwrap_err();
    let elapsed = start.elapsed();

    assert!(err.to_string().contains("server error (HTTP 503)"));
    assert!(
        elapsed >= Duration::from_millis(190),
        "Expected elapsed backoff >= 190ms, actual: {elapsed:?}"
    );
}

#[tokio::test]
async fn test_adversarial_504_gateway_timeout_recovery_on_second_retry() {
    let server = MockServer::start().await;

    // Attempt 1: 504 Gateway Timeout
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(504).set_body_string("Gateway Timeout"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    // Attempt 2: 503 Service Unavailable
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    // Attempt 3: 200 OK (recovers!)
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.95,
            "reason": "Recovered on attempt 3"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 2,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Crypto link");

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    assert_eq!(verdict.reason(), "Recovered on attempt 3");
}

// =============================================================================
// 4. Socket Resets & Network Fault Injection
// =============================================================================

#[tokio::test]
async fn test_adversarial_socket_drop_recovery_on_retry() {
    // Bind a real TCP listener to simulate a socket drop on attempt 1, followed
    // by a successful HTTP/1.1 response on attempt 2 (retry).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        // Connection 1: Accept and abruptly close connection
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream.shutdown().await;
            drop(stream);
        }

        // Connection 2 (Retry): Accept and return valid HTTP 200 response
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;

            let response_body = serde_json::to_string(&json!({
                "violates": true,
                "category": "spam",
                "confidence": 0.94,
                "reason": "Recovered after abrupt socket drop"
            }))
            .unwrap();

            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(http_response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });

    let config = JevConfig {
        base_url: format!("http://{local_addr}"),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(2000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Spam link");

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    assert_eq!(verdict.reason(), "Recovered after abrupt socket drop");

    let _ = server_task.await;
}

#[tokio::test]
async fn test_adversarial_socket_drop_exhaustion() {
    // Bind a TCP listener that immediately resets every incoming connection
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        // Drop two connections (attempt 0 and attempt 1)
        for _ in 0..2 {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.shutdown().await;
                drop(stream);
            }
        }
    });

    let config = JevConfig {
        base_url: format!("http://{local_addr}"),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("network error") || err_msg.contains("connection"),
        "Expected network error on socket drop exhaustion, got: {err_msg}"
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_adversarial_unreachable_network_endpoint() {
    // Port 1 on 127.0.0.1 is not listening
    let config = JevConfig {
        base_url: "http://127.0.0.1:1".to_string(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(500),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("network error"));
}

// =============================================================================
// 5. Concurrency & Connection Reuse
// =============================================================================

#[tokio::test]
async fn test_adversarial_50_concurrent_requests_shared_client() {
    let server = MockServer::start().await;

    // Mount a mock that handles 50 concurrent requests
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(header("authorization", "Bearer concurrent_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "spam",
            "confidence": 0.90,
            "reason": "Concurrent spam classification"
        })))
        .expect(50)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: Some("concurrent_key".to_string()),
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(5000),
        max_retries: 1,
    };
    let classifier = Arc::new(JevClassifier::new(config, RuleRubric::default()).unwrap());

    let mut join_set = JoinSet::new();

    for i in 0..50 {
        let client = Arc::clone(&classifier);
        join_set.spawn(async move {
            let interaction = sample_interaction(&format!("Spam message number {i}"));
            let verdict = client.classify(&interaction).await.unwrap();
            assert!(verdict.is_violation());
            assert_eq!(verdict.reason(), "Concurrent spam classification");
            i
        });
    }

    let mut completed_indices = Vec::new();
    while let Some(res) = join_set.join_next().await {
        let idx = res.expect("Task must not panic");
        completed_indices.push(idx);
    }

    assert_eq!(completed_indices.len(), 50);
}

#[tokio::test]
async fn test_adversarial_high_concurrency_mixed_outcomes() {
    let server = MockServer::start().await;

    // Route 1: violations (text containing 'action_scam_token')
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(wiremock::matchers::body_string_contains(
            "\"action_scam_token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.95,
            "reason": "Crypto scam detected"
        })))
        .expect(20)
        .mount(&server)
        .await;

    // Route 2: permitted (text containing 'action_benign_post')
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(wiremock::matchers::body_string_contains(
            "\"action_benign_post",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": false,
            "confidence": 0.05,
            "reason": "Benign post"
        })))
        .expect(20)
        .mount(&server)
        .await;

    // Route 3: forbidden (text containing 'action_forbidden_req')
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(wiremock::matchers::body_string_contains(
            "\"action_forbidden_req",
        ))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .expect(10) // Strictly 10 calls, zero retries
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(5000),
        max_retries: 2,
    };
    let classifier = Arc::new(JevClassifier::new(config, RuleRubric::default()).unwrap());

    let mut join_set = JoinSet::new();

    // 20 scam tasks
    for i in 0..20 {
        let client = Arc::clone(&classifier);
        join_set.spawn(async move {
            let interaction = sample_interaction(&format!("action_scam_token {i}"));
            let verdict = client.classify(&interaction).await.unwrap();
            assert!(verdict.is_violation());
            "scam"
        });
    }

    // 20 benign tasks
    for i in 0..20 {
        let client = Arc::clone(&classifier);
        join_set.spawn(async move {
            let interaction = sample_interaction(&format!("action_benign_post {i}"));
            let verdict = client.classify(&interaction).await.unwrap();
            assert!(verdict.is_permitted());
            "benign"
        });
    }

    // 10 forbidden tasks (asserting error returned and no panic)
    for i in 0..10 {
        let client = Arc::clone(&classifier);
        join_set.spawn(async move {
            let interaction = sample_interaction(&format!("action_forbidden_req {i}"));
            let err = client.classify(&interaction).await.unwrap_err();
            assert!(err.to_string().contains("HTTP 403"));
            "forbidden"
        });
    }

    let mut counts = std::collections::HashMap::new();
    while let Some(res) = join_set.join_next().await {
        let outcome = res.expect("Task must not panic");
        *counts.entry(outcome).or_insert(0) += 1;
    }

    assert_eq!(counts.get("scam"), Some(&20));
    assert_eq!(counts.get("benign"), Some(&20));
    assert_eq!(counts.get("forbidden"), Some(&10));
}

// =============================================================================
// 6. Additional Adversarial & Structural Edge Cases
// =============================================================================

#[tokio::test]
async fn test_adversarial_max_retries_zero_no_retry_on_500() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
        .expect(1) // With max_retries = 0, exactly 1 call is made!
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 0,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("server error (HTTP 500)"));
}

#[tokio::test]
async fn test_adversarial_massive_unicode_and_zalgo_payload() {
    let server = MockServer::start().await;

    // 50KB payload with complex Unicode, emojis, RTL, and Zalgo characters
    let mut large_text = String::with_capacity(50_000);
    large_text.push_str("🔥 Crypto airdrop! ");
    large_text.push_str("مرحبا بالعالم שלום עולם 🚀 ");
    for _ in 0..1000 {
        large_text.push_str("Z̵̛̀a̷̋́l̶̐͝ǧ̷̈o̷̎̿ ̶̇͒ẗ̸͘e̴͆͊x̴̎̽t̶͑͊ ̶̒̈ ");
    }

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "spam",
            "confidence": 0.99,
            "reason": "Zalgo spam flood"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(2000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction(&large_text);

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    assert_eq!(verdict.reason(), "Zalgo spam flood");
}

#[test]
fn test_adversarial_url_normalization_variants() {
    let rubric = RuleRubric::default();

    // Case 1: Plain host without trailing slash
    let c1 = JevClassifier::new(
        JevConfig {
            base_url: "https://api.jev.ai".to_string(),
            ..Default::default()
        },
        rubric.clone(),
    )
    .unwrap();
    assert_eq!(c1.classify_url(), "https://api.jev.ai/v1/classify");

    // Case 2: Host with trailing slash
    let c2 = JevClassifier::new(
        JevConfig {
            base_url: "https://api.jev.ai/".to_string(),
            ..Default::default()
        },
        rubric.clone(),
    )
    .unwrap();
    assert_eq!(c2.classify_url(), "https://api.jev.ai/v1/classify");

    // Case 3: Already has /v1
    let c3 = JevClassifier::new(
        JevConfig {
            base_url: "https://api.jev.ai/v1".to_string(),
            ..Default::default()
        },
        rubric.clone(),
    )
    .unwrap();
    assert_eq!(c3.classify_url(), "https://api.jev.ai/v1/classify");

    // Case 4: Already has /v1/classify
    let c4 = JevClassifier::new(
        JevConfig {
            base_url: "https://api.jev.ai/v1/classify/".to_string(),
            ..Default::default()
        },
        rubric.clone(),
    )
    .unwrap();
    assert_eq!(c4.classify_url(), "https://api.jev.ai/v1/classify");

    // Case 5: Custom prefix
    let c5 = JevClassifier::new(
        JevConfig {
            base_url: "https://proxy.example.com/prefix".to_string(),
            ..Default::default()
        },
        rubric,
    )
    .unwrap();
    assert_eq!(
        c5.classify_url(),
        "https://proxy.example.com/prefix/v1/classify"
    );
}

#[test]
fn test_adversarial_invalid_base_url_fails_cleanly() {
    let rubric = RuleRubric::default();
    let config = JevConfig {
        base_url: "not-a-valid-scheme://foo bar".to_string(),
        ..Default::default()
    };
    let res = JevClassifier::new(config, rubric);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.to_string().contains("Invalid Jev endpoint URL"));
}

struct NoAuthHeader;
impl wiremock::Match for NoAuthHeader {
    fn matches(&self, request: &wiremock::Request) -> bool {
        !request
            .headers
            .contains_key(wiremock::http::HeaderName::from_static("authorization"))
    }
}

#[tokio::test]
async fn test_adversarial_empty_vs_bearer_auth_headers() {
    let server = MockServer::start().await;

    // When api_key is None, no Authorization header is sent
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(NoAuthHeader)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": false,
            "confidence": 0.1,
            "reason": "OK without auth"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let classifier = JevClassifier::new(config, RuleRubric::default()).unwrap();
    let interaction = sample_interaction("Hello");

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_permitted());
}

// =============================================================================
// 6. Classifier Accessors, Endpoint Kind Resolution & Category Mapping
// =============================================================================

#[test]
fn test_endpoint_kind_as_str_and_url_resolution() {
    use skybouncer::classifier::JevEndpointKind;
    assert_eq!(JevEndpointKind::StandardJev.as_str(), "standard_jev");
    assert_eq!(JevEndpointKind::Ollama.as_str(), "ollama");
    assert_eq!(JevEndpointKind::SystemOne.as_str(), "system_one");
}

fn classifier_for_url(base_url: &str) -> JevClassifier {
    JevClassifier::new(
        JevConfig {
            base_url: base_url.to_string(),
            api_key: Some("k".to_string()),
            model: "m".to_string(),
            timeout: Duration::from_millis(500),
            max_retries: 0,
        },
        RuleRubric::default(),
    )
    .unwrap()
}

#[test]
fn test_classifier_accessors_and_endpoint_kinds() {
    let c = classifier_for_url("https://api.jev.ai");
    assert_eq!(c.model(), "m");
    assert_eq!(c.config().model, "m");
    assert_eq!(c.rubric().prompt, RuleRubric::default().prompt);
    assert!(!c.classify_url().is_empty());

    // Ollama endpoint detection from base URL.
    let ollama = classifier_for_url("http://localhost:11434");
    assert_eq!(
        ollama.endpoint_kind(),
        skybouncer::classifier::JevEndpointKind::Ollama
    );

    // SystemOne endpoint detection.
    let sysone = classifier_for_url("https://api.example.com/v1/systemone");
    assert_eq!(
        sysone.endpoint_kind(),
        skybouncer::classifier::JevEndpointKind::SystemOne
    );

    // set_rubric swaps the active rubric.
    let new_rubric = RuleRubric::new("Block all spam", skybouncer::classifier::Sensitivity::High);
    c.set_rubric(new_rubric.clone());
    assert_eq!(c.rubric().prompt, "Block all spam");
}

#[tokio::test]
async fn test_standard_jev_category_mapping_matrix() {
    // Each category string maps to the expected ViolationCategory.
    let cases = [
        ("spam", ViolationCategory::Spam),
        ("crypto_spam", ViolationCategory::CryptoSpam),
        ("crypto-spam", ViolationCategory::CryptoSpam),
        ("harassment", ViolationCategory::Harassment),
        ("sea_lioning", ViolationCategory::SeaLioning),
        ("sealioning", ViolationCategory::SeaLioning),
        ("sealioning_or_bad_faith", ViolationCategory::SeaLioning),
        ("bad_faith", ViolationCategory::SeaLioning),
        ("phishing", ViolationCategory::Phishing),
        ("hate_speech", ViolationCategory::HateSpeech),
        ("hatespeech", ViolationCategory::HateSpeech),
    ];
    for (label, expected) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/classify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "violates": true,
                "confidence": 0.99,
                "reason": "test",
                "category": label
            })))
            .mount(&server)
            .await;

        let classifier = classifier_for_url(&server.uri());
        let interaction = sample_interaction("test content");
        let verdict = classifier.classify(&interaction).await.unwrap();
        match verdict {
            skybouncer::classifier::Verdict::Violation { category, .. } => {
                assert_eq!(category, expected, "category mismatch for {label}");
            }
            other => panic!("expected violation for {label}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_unknown_category_maps_to_custom() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "violates": true,
            "confidence": 0.99,
            "reason": "test",
            "category": "totally_novel_category"
        })))
        .mount(&server)
        .await;

    let classifier = classifier_for_url(&server.uri());
    let interaction = sample_interaction("test content");
    match classifier.classify(&interaction).await.unwrap() {
        skybouncer::classifier::Verdict::Violation { category, .. } => {
            assert!(matches!(category, ViolationCategory::Custom(_)));
        }
        other => panic!("expected violation, got {other:?}"),
    }
}

#[tokio::test]
async fn test_all_server_errors_exhaust_retries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    // max_retries=1 => two attempts, both 500, then a classifier error.
    let classifier = classifier_for_url(&server.uri());
    let interaction = sample_interaction("test");
    let err = classifier.classify(&interaction).await.unwrap_err();
    assert!(err.to_string().contains("Jev API server error"));
}

// =============================================================================
// 7. Ollama & SystemOne Endpoint Kinds
// =============================================================================

fn classifier_for(base_url: String, model: &str) -> JevClassifier {
    JevClassifier::new(
        JevConfig {
            base_url,
            api_key: None,
            model: model.to_string(),
            timeout: Duration::from_millis(500),
            max_retries: 0,
        },
        RuleRubric::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn test_ollama_endpoint_parses_wrapped_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {
                "role": "assistant",
                "content": "```json\n{\"violates\": true, \"confidence\": 0.91, \"category\": \"spam\", \"reason\": \"promo\"}\n```"
            }
        })))
        .mount(&server)
        .await;

    let base = format!("{}/api/chat", server.uri());
    let classifier = classifier_for(base, "llama3");
    assert_eq!(
        classifier.endpoint_kind(),
        skybouncer::classifier::JevEndpointKind::Ollama
    );
    let verdict = classifier
        .classify(&sample_interaction("buy now spam"))
        .await
        .unwrap();
    assert!(matches!(
        verdict,
        skybouncer::classifier::Verdict::Violation { .. }
    ));
}

#[tokio::test]
async fn test_systemone_endpoint_parses_choice_and_probabilities() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "crypto_spam",
                    "probabilities": {"permitted": 0.05, "crypto_spam": 0.95}
                }
            }
        })))
        .mount(&server)
        .await;

    let base = format!("{}/v1/systemone", server.uri());
    let classifier = classifier_for(base, "systemone");
    assert_eq!(
        classifier.endpoint_kind(),
        skybouncer::classifier::JevEndpointKind::SystemOne
    );
    let verdict = classifier
        .classify(&sample_interaction("airdrop"))
        .await
        .unwrap();
    assert!(matches!(
        verdict,
        skybouncer::classifier::Verdict::Violation { .. }
    ));
}

#[tokio::test]
async fn test_systemone_permitted_choice_uses_probability() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "permitted",
                    "probabilities": {"permitted": 0.97}
                }
            }
        })))
        .mount(&server)
        .await;

    let base = format!("{}/v1/systemone", server.uri());
    let classifier = classifier_for(base, "systemone");
    let verdict = classifier
        .classify(&sample_interaction("hello friend"))
        .await
        .unwrap();
    assert!(!verdict.is_violation());
}

#[tokio::test]
async fn test_systemone_missing_moderation_answer_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"answers": {}})))
        .mount(&server)
        .await;

    let base = format!("{}/v1/systemone", server.uri());
    let classifier = classifier_for(base, "systemone");
    let err = classifier
        .classify(&sample_interaction("x"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("missing 'moderation' answer"));
}

#[tokio::test]
async fn test_client_error_4xx_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;

    let classifier = classifier_for(server.uri(), "m");
    let err = classifier
        .classify(&sample_interaction("x"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Jev API client error"));
}

#[tokio::test]
async fn test_ollama_bad_wrapper_json_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;

    let base = format!("{}/api/chat", server.uri());
    let classifier = classifier_for(base, "llama3");
    let err = classifier
        .classify(&sample_interaction("x"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Ollama"));
}

#[tokio::test]
async fn test_systemone_violation_uses_choice_probability_when_no_permitted() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "spam",
                    "probabilities": {"spam": 0.8}
                }
            }
        })))
        .mount(&server)
        .await;

    let base = format!("{}/v1/systemone", server.uri());
    let classifier = classifier_for(base, "systemone");
    let v = classifier.classify(&sample_interaction("x")).await.unwrap();
    assert!(v.is_violation());
    assert_eq!(v.confidence(), Some(0.8));
}

#[tokio::test]
async fn test_systemone_uses_scalar_confidence_when_no_probabilities() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "permitted",
                    "confidence": 0.66
                }
            }
        })))
        .mount(&server)
        .await;

    let base = format!("{}/v1/systemone", server.uri());
    let classifier = classifier_for(base, "systemone");
    let v = classifier.classify(&sample_interaction("x")).await.unwrap();
    assert!(!v.is_violation());
    assert_eq!(v.confidence(), Some(0.66));
}

#[tokio::test]
async fn test_systemone_missing_confidence_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {"type": "choice", "choice": "spam"}
            }
        })))
        .mount(&server)
        .await;

    let base = format!("{}/v1/systemone", server.uri());
    let classifier = classifier_for(base, "systemone");
    let err = classifier
        .classify(&sample_interaction("x"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("missing confidence"));
}

#[test]
fn test_jev_accessors_and_from_env() {
    // from_env uses defaults when nothing is set.
    for k in [
        "JEV_API_BASE_URL",
        "JEV_MODEL",
        "JEV_TIMEOUT_MS",
        "JEV_MAX_RETRIES",
    ] {
        std::env::remove_var(k);
    }
    let c = JevClassifier::from_env(RuleRubric::default()).expect("from_env");
    assert!(!c.model().is_empty());
    assert!(!c.classify_url().is_empty());
    c.set_rubric(RuleRubric::new(
        "new rules",
        skybouncer::classifier::Sensitivity::High,
    ));
    assert_eq!(c.rubric().prompt, "new rules");
}

#[tokio::test]
async fn test_jev_evaluate_delegates_and_ollama_parse_error() {
    let server = MockServer::start().await;
    // Ollama wrapper with non-JSON content -> Ollama content parse error.
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"role": "assistant", "content": "not a json object"}
        })))
        .mount(&server)
        .await;

    let base = format!("{}/api/chat", server.uri());
    let classifier = classifier_for(base, "llama3");
    // evaluate() delegates to evaluate_with_rubric(None).
    let err = classifier
        .evaluate(&sample_interaction("x"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Ollama content"));
}

#[test]
fn test_jev_endpoint_url_construction_variants() {
    // /api base -> appends /chat
    let c = JevClassifier::new(
        JevConfig {
            base_url: "http://localhost:11434/api".to_string(),
            api_key: None,
            model: "m".to_string(),
            timeout: Duration::from_millis(100),
            max_retries: 0,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(c.classify_url().ends_with("/api/chat"));

    // /v1 base -> appends /classify
    let c = JevClassifier::new(
        JevConfig {
            base_url: "https://api.jev.ai/v1".to_string(),
            api_key: None,
            model: "m".to_string(),
            timeout: Duration::from_millis(100),
            max_retries: 0,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(c.classify_url().ends_with("/v1/classify"));

    // Invalid base URL -> Config error.
    assert!(JevClassifier::new(
        JevConfig {
            base_url: "not a url".to_string(),
            api_key: None,
            model: "m".to_string(),
            timeout: Duration::from_millis(100),
            max_retries: 0,
        },
        RuleRubric::default(),
    )
    .is_err());
}
