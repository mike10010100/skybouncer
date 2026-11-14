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
        quote_uri: None,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
        supports_images: false,
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
            supports_images: false,
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
            supports_images: false,
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
            supports_images: false,
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
            supports_images: false,
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
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .is_err());
}

#[tokio::test]
async fn test_systemone_fragmented_violation_probabilities_uses_choice_probability_and_house_rules()
{
    let server = MockServer::start().await;

    // Verify that Active House Rules are injected into `state` AND fragmented probabilities
    // across violation buckets use `probabilities[choice]` (0.52) rather than `1 - permitted` (0.88).
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .and(wiremock::matchers::body_string_contains(
            "Active House Rules for Target: \\\"Block Severance spoilers\\\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "harassment",
                    "probabilities": {
                        "harassment": 0.52,
                        "sealioning_or_bad_faith": 0.22,
                        "spam": 0.14,
                        "permitted": 0.12
                    }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: format!("{}/v1/systemone", server.uri()),
        api_key: None,
        model: "nimble".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 0,
        supports_images: false,
    };
    // Sensitivity::High threshold is 0.60. With choice probability 0.52 (< 0.60),
    // it MUST downgrade to Permitted with confidence 0.52 (in uncertainty band [0.40, 0.85))!
    let rubric = RuleRubric::new(
        "Block Severance spoilers",
        skybouncer::classifier::Sensitivity::High,
    );
    let classifier = JevClassifier::new(config, rubric).unwrap();
    let verdict = classifier
        .classify(&sample_interaction("ambiguous snarky reply"))
        .await
        .unwrap();

    assert!(verdict.is_permitted());
    assert!((verdict.confidence().unwrap() - 0.52).abs() < 1e-6);
}

#[tokio::test]
async fn test_subthread_reply_to_other_user_injects_not_target_recipient_framing() {
    use skybouncer::enricher::{EnrichedContext, ParentPostContext, ThreadPost};

    let server = MockServer::start().await;
    let target_did = "did:plc:mmtjkssv6jeneahkgfdxuy7p";
    let author_did = "did:plc:qgzzrfoh3fapodvfpeqjbtii";
    let other_did = "did:plc:kpizu7db55xo3m3vy5alpwaf";

    let expected_replying_to = format!(
        "Replying To: OtherUser ({other_did}) [NOT Target — sub-thread reply to another commenter; second-person 'you'/'your' addresses this OtherUser unless Target is explicitly named or @mentioned]"
    );

    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .and(wiremock::matchers::body_string_contains(
            &expected_replying_to,
        ))
        .and(wiremock::matchers::body_string_contains(
            "[IMMEDIATE PARENT — Author is replying to this post]",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "permitted",
                    "probabilities": { "permitted": 0.96, "harassment": 0.04 }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .and(wiremock::matchers::body_string_contains(
            &expected_replying_to,
        ))
        .and(wiremock::matchers::body_string_contains(
            "[IMMEDIATE PARENT — Author is replying to this post]",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {
                "role": "assistant",
                "content": "{\"violates\":false,\"category\":null,\"confidence\":0.98,\"reason\":\"Sub-thread scolding directed at OtherUser, not Target.\"}"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut ctx = EnrichedContext::empty();
    ctx.parent_post = Some(ParentPostContext {
        author_did: other_did.to_string(),
        text: "AIPAC doesn't necessarily mean Jews...".to_string(),
        cid: Some("bafyparent".to_string()),
    });
    ctx.thread_ancestors = vec![
        ThreadPost {
            author_did: target_did.to_string(),
            text: "Original thread root".to_string(),
        },
        ThreadPost {
            author_did: other_did.to_string(),
            text: "AIPAC doesn't necessarily mean Jews...".to_string(),
        },
    ];

    let subthread_interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::ThreadReply,
        format!("at://{author_did}/app.bsky.feed.post/3n22v76mrj22a"),
        "bafycand",
        "Okay could you actually read what people say instead of immediately doing...this? Because you sound fucking insane.",
    )
    .with_parent_uri(format!("at://{other_did}/app.bsky.feed.post/3n22girgtls24"))
    .with_root_uri(format!("at://{target_did}/app.bsky.feed.post/3n223xnkqqw2m"))
    .with_enriched_context(ctx);

    let sys1 = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(sys1
        .classify(&subthread_interaction)
        .await
        .unwrap()
        .is_permitted());

    let ollama = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/api/chat", server.uri()),
            api_key: None,
            model: "gemma4:26b".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(ollama
        .classify(&subthread_interaction)
        .await
        .unwrap()
        .is_permitted());
}

#[tokio::test]
async fn test_reply_recipient_line_self_reply_mention_and_standalone_quote() {
    let server = MockServer::start().await;
    let target_did = "did:plc:target";
    let author_did = "did:plc:author";
    let other_did = "did:plc:other";

    // 1. Self-reply continuation inside Target's thread
    Mock::given(method("POST"))
        .and(path("/self/v1/systemone"))
        .and(wiremock::matchers::body_string_contains(
            "Replying To: Author (did:plc:author) [self-reply / thread continuation]",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": { "moderation": { "type": "choice", "choice": "permitted", "probabilities": { "permitted": 0.99 } } }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // 2. Mention of Target while replying to OtherUser
    Mock::given(method("POST"))
        .and(path("/mention/v1/systemone"))
        .and(wiremock::matchers::body_string_contains(
            "Replying To: OtherUser (did:plc:other) [NOT Target — replying to another commenter while mentioning/quoting Target]",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": { "moderation": { "type": "choice", "choice": "permitted", "probabilities": { "permitted": 0.99 } } }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // 3. Standalone Quote (no reply parent -> no Replying To line)
    Mock::given(method("POST"))
        .and(path("/quote/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": { "moderation": { "type": "choice", "choice": "permitted", "probabilities": { "permitted": 0.99 } } }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let make = |suffix: &str| {
        JevClassifier::new(
            JevConfig {
                base_url: format!("{}/{suffix}/v1/systemone", server.uri()),
                api_key: None,
                model: "nimble".to_string(),
                timeout: Duration::from_millis(1000),
                max_retries: 0,
                supports_images: false,
            },
            RuleRubric::default(),
        )
        .unwrap()
    };

    let self_reply = Interaction::new(
        author_did,
        target_did,
        InteractionType::ThreadReply,
        "at://did:plc:author/app.bsky.feed.post/2",
        "cid2",
        "adding one more note",
    )
    .with_parent_uri("at://did:plc:author/app.bsky.feed.post/1")
    .with_root_uri("at://did:plc:target/app.bsky.feed.post/root");
    assert!(make("self")
        .classify(&self_reply)
        .await
        .unwrap()
        .is_permitted());

    let mention_in_reply = Interaction::new(
        author_did,
        target_did,
        InteractionType::Mention,
        "at://did:plc:author/app.bsky.feed.post/3",
        "cid3",
        "see what @target posted above",
    )
    .with_parent_uri(format!("at://{other_did}/app.bsky.feed.post/1"));
    assert!(make("mention")
        .classify(&mention_in_reply)
        .await
        .unwrap()
        .is_permitted());

    let standalone_quote = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:author/app.bsky.feed.post/4",
        "cid4",
        "great post",
    );
    assert!(make("quote")
        .classify(&standalone_quote)
        .await
        .unwrap()
        .is_permitted());
    let reqs = server.received_requests().await.unwrap();
    let quote_body = String::from_utf8_lossy(&reqs[2].body);
    assert!(!quote_body.contains("Replying To:"));
    assert!(quote_body.contains("Quoting: Target (did:plc:target)"));
}

#[tokio::test]
async fn test_third_person_commiseration_with_quoted_ancestor_systemone_and_ollama() {
    use skybouncer::enricher::{EnrichedContext, ParentPostContext, QuotedAncestor, ThreadPost};

    let server = MockServer::start().await;
    let target_did = "did:plc:mmtjkssv6jeneahkgfdxuy7p";
    let author_did = "did:plc:lqvsqsm4bjxqeue3bulyhvwl";
    let quoted_did = "did:plc:7umvpuxe2vbrc3zrzuquzniu";

    // Both SystemOne (`nimble`) and Ollama (`gemma4:26b`) receive the `[quoting OtherUser ...]`
    // annotation alongside `Replying To: Target`, plus updated 3p commiseration guidance.
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .and(wiremock::matchers::body_string_contains(
            "Replying To: Target",
        ))
        .and(wiremock::matchers::body_string_contains(
            "[quoting OtherUser @whstancil.bsky.social (did:plc:7umvpuxe2vbrc3zrzuquzniu):",
        ))
        .and(wiremock::matchers::body_string_contains(
            "aimed at a '[quoting OtherUser ...]' subject",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "permitted",
                    "probabilities": { "permitted": 0.96, "harassment": 0.03 }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .and(wiremock::matchers::body_string_contains("Replying To: Target"))
        .and(wiremock::matchers::body_string_contains(
            "[quoting OtherUser @whstancil.bsky.social (did:plc:7umvpuxe2vbrc3zrzuquzniu):",
        ))
        .and(wiremock::matchers::body_string_contains(
            "Third-person commiseration & quoted-subject co-reference",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {
                "role": "assistant",
                "content": r#"{"violates": false, "category": null, "confidence": 0.99, "reason": "Author is commiserating with Target about the quoted third party (@whstancil.bsky.social), not attacking Target."}"#
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut ctx = EnrichedContext::empty();
    ctx.parent_post = Some(ParentPostContext {
        author_did: target_did.to_string(),
        text: "Charmin really made a scene over this.".to_string(),
        cid: Some("bafyparent".to_string()),
    });
    ctx.thread_ancestors = vec![
        ThreadPost {
            author_did: "did:plc:sailormichael0000000000".to_string(),
            text: "Look at this thread.".to_string(),
        },
        ThreadPost {
            author_did: target_did.to_string(),
            text: "Charmin really made a scene over this.".to_string(),
        },
    ];
    ctx.thread_ancestor_quotes = vec![
        Some(QuotedAncestor {
            author_did: quoted_did.to_string(),
            author_handle: Some("whstancil.bsky.social".to_string()),
            text: "Everyone in my mentions is being unfair to me.".to_string(),
        }),
        None,
    ];

    let mut interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::DirectReply,
        "at://did:plc:lqvsqsm4bjxqeue3bulyhvwl/app.bsky.feed.post/3n27g24tm3s26",
        "bafycand",
        "And now he's super sad this morning because there's a bunch of broads in his mentions reminding him how mediocre he is.",
    )
    .with_parent_uri("at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/3n27fphhcx22b");
    interaction.enriched_context = Some(ctx);

    let systemone = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    let res_s1 = systemone.classify(&interaction).await.unwrap();
    assert!(res_s1.is_permitted());

    let ollama = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/api/chat", server.uri()),
            api_key: None,
            model: "gemma4:26b".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    let res_ollama = ollama.classify(&interaction).await.unwrap();
    assert!(res_ollama.is_permitted());
}

#[tokio::test]
async fn test_systemone_and_classifier_edge_branches() {
    use skybouncer::classifier::{Classifier, OllamaChatOptions, Verdict, DEFAULT_OLLAMA_NUM_CTX};

    let opts = OllamaChatOptions::default();
    assert_eq!(opts.num_ctx, DEFAULT_OLLAMA_NUM_CTX);

    let server = MockServer::start().await;

    // 1. SystemOne non-SystemOne JSON body triggers parse error branch.
    Mock::given(method("POST"))
        .and(path("/bad_s1/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"not_answers": 1})))
        .mount(&server)
        .await;

    let bad_s1 = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/bad_s1/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    let sample = Interaction::new(
        "did:plc:a",
        "did:plc:b",
        InteractionType::DirectReply,
        "at://did:plc:a/app.bsky.feed.post/1",
        "cid1",
        "hello",
    );
    assert!(bad_s1.classify(&sample).await.is_err());

    // 2. Violation choice deriving confidence as `1.0 - permitted` when choice probability is absent.
    Mock::given(method("POST"))
        .and(path("/perm_fallback/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "harassment",
                    "probabilities": { "permitted": 0.08 }
                }
            }
        })))
        .mount(&server)
        .await;

    let perm_fallback = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/perm_fallback/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    let v_perm_fb = perm_fallback.classify(&sample).await.unwrap();
    assert!(v_perm_fb.is_violation());
    assert!((v_perm_fb.confidence().unwrap() - 0.92).abs() < 1e-6);

    // 3. Permitted choice with empty probabilities and null confidence returns error.
    Mock::given(method("POST"))
        .and(path("/perm_empty/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "permitted",
                    "probabilities": {}
                }
            }
        })))
        .mount(&server)
        .await;

    let perm_empty = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/perm_empty/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(perm_empty.classify(&sample).await.is_err());

    // 4. `Classifier::set_rubric` trait forwarding and substring `sea-lion` category mapping.
    Mock::given(method("POST"))
        .and(path("/sealion/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "persistent sea-lioning troll",
            "confidence": 0.91,
            "reason": "sealion"
        })))
        .mount(&server)
        .await;

    let sealion_clf = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/sealion", server.uri()),
            api_key: None,
            model: "custom".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    let trait_clf: &dyn Classifier = &sealion_clf;
    let custom_rubric = RuleRubric::new(
        "Strict custom rubric",
        skybouncer::classifier::Sensitivity::High,
    );
    trait_clf.set_rubric(custom_rubric.clone());
    assert_eq!(sealion_clf.rubric().prompt, custom_rubric.prompt);

    let sealion_verdict = trait_clf.classify(&sample).await.unwrap();
    assert!(matches!(
        sealion_verdict,
        Verdict::Violation {
            category: ViolationCategory::SeaLioning,
            ..
        }
    ));
}

#[tokio::test]
async fn test_standalone_quote_group_label_dunk_systemone_and_ollama() {
    use skybouncer::classifier::Verdict;
    use skybouncer::enricher::{EnrichedContext, ParentPostContext, ThreadPost};

    let server = MockServer::start().await;
    let target_did = "did:plc:mmtjkssv6jeneahkgfdxuy7p";
    let author_did = "did:plc:qwpty6y2kbyathbxlfcejz2p";
    let interlocutor_did = "did:plc:vasmwozbxda25bah7d6sb3ja";

    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .and(wiremock::matchers::body_string_contains("Quoting: Target"))
        .and(wiremock::matchers::body_string_contains(
            "[QUOTED POST — Author is quote-posting this post]",
        ))
        .and(wiremock::matchers::body_string_contains(
            "standalone 'Quoting: Target' quote-posts that hurl demeaning intelligence/character insults",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "harassment",
                    "probabilities": { "harassment": 0.91, "permitted": 0.08 }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .and(wiremock::matchers::body_string_contains("Quoting: Target"))
        .and(wiremock::matchers::body_string_contains(
            "[QUOTED POST — Author is quote-posting this post]",
        ))
        .and(wiremock::matchers::body_string_contains(
            "Standalone quote-posts ('Quoting: Target') & group-label quote-dunks",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {
                "role": "assistant",
                "content": r#"{"violates": true, "category": "harassment", "confidence": 0.95, "reason": "Standalone quote-post demeans Target via the 'Chuck supporters' group label representing Target's stance in the thread."}"#
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Also verify `Quoting:` header omission when quoting an OtherUser and resolution from `enriched_context.quoted_post`.
    Mock::given(method("POST"))
        .and(path("/other_quote/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "permitted",
                    "probabilities": { "permitted": 0.95 }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/ctx_quote/v1/systemone"))
        .and(wiremock::matchers::body_string_contains("Quoting: Target"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "harassment",
                    "probabilities": { "harassment": 0.93 }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut ctx = EnrichedContext::empty();
    ctx.quoted_post = Some(ParentPostContext {
        author_did: target_did.to_string(),
        text: "So just the two things then.\n\nOr will there inevitably be more?".to_string(),
        cid: Some("bafyquoted".to_string()),
    });
    ctx.thread_ancestors = vec![
        ThreadPost {
            author_did: interlocutor_did.to_string(),
            text: "So yes I find Schumer uniquely unsatisfactory for the job".to_string(),
        },
        ThreadPost {
            author_did: target_did.to_string(),
            text: "So just the two things then.\n\nOr will there inevitably be more?".to_string(),
        },
    ];

    let mut interaction = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:qwpty6y2kbyathbxlfcejz2p/app.bsky.feed.post/3n27kxiexm22j",
        "bafycand",
        "Chuck supporters are the dumbest fucks around.",
    )
    .with_quote_uri("at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/3n264mmxavs2v");
    interaction.enriched_context = Some(ctx);

    let systemone = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    let res_s1 = systemone.classify(&interaction).await.unwrap();
    assert!(matches!(
        res_s1,
        Verdict::Violation {
            category: ViolationCategory::Harassment,
            ..
        }
    ));

    let ollama = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/api/chat", server.uri()),
            api_key: None,
            model: "gemma4:26b".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    let res_ollama = ollama.classify(&interaction).await.unwrap();
    assert!(matches!(
        res_ollama,
        Verdict::Violation {
            category: ViolationCategory::Harassment,
            ..
        }
    ));

    // Standalone quote without `quote_uri` falls back to `enriched_context.quoted_post.author_did`.
    let mut ctx_only = EnrichedContext::empty();
    ctx_only.quoted_post = Some(ParentPostContext {
        author_did: target_did.to_string(),
        text: "Target take".to_string(),
        cid: None,
    });
    let mut quote_via_ctx = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:qwpty6y2kbyathbxlfcejz2p/app.bsky.feed.post/ctxonly",
        "bafyctx",
        "People like this are morons.",
    );
    quote_via_ctx.enriched_context = Some(ctx_only);
    let ctx_clf = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/ctx_quote/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(ctx_clf
        .classify(&quote_via_ctx)
        .await
        .unwrap()
        .is_violation());

    // Standalone quote whose `quote_uri` points at an OtherUser omits `Quoting: Target`.
    let other_quote = Interaction::new(
        author_did,
        target_did,
        InteractionType::Quote,
        "at://did:plc:qwpty6y2kbyathbxlfcejz2p/app.bsky.feed.post/otherq",
        "bafyother",
        "agree completely",
    )
    .with_quote_uri("at://did:plc:someoneelse/app.bsky.feed.post/1");
    let other_clf = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/other_quote/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(other_clf
        .classify(&other_quote)
        .await
        .unwrap()
        .is_permitted());
    let reqs = server.received_requests().await.unwrap();
    let other_req_body = reqs
        .iter()
        .find(|r| r.url.path() == "/other_quote/v1/systemone")
        .expect("other_quote request recorded");
    assert!(!String::from_utf8_lossy(&other_req_body.body).contains("Quoting: Target ("));
}

#[tokio::test]
async fn test_rhetorical_apostrophe_and_vocative_guardrail_prompts_systemone_and_ollama() {
    use skybouncer::classifier::Verdict;
    use skybouncer::enricher::{EnrichedContext, PostEmbedSummary, QuotedAncestor, ThreadPost};

    let server = MockServer::start().await;
    let target_did = "did:plc:mmtjkssv6jeneahkgfdxuy7p";
    let author_did = "did:plc:jbbiqk7nyatsivk2mboyqm6t";
    let quoted_did = "did:plc:ktc7mkfqnint7hmviye6wizr";
    let parent_uri = "at://did:plc:mmtjkssv6jeneahkgfdxuy7p/app.bsky.feed.post/3n2bnzagrqk2m";

    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .and(wiremock::matchers::body_string_contains(
            "[quoted post has 1 attached image(s) (no alt text)]",
        ))
        .and(wiremock::matchers::body_string_contains(
            "Just for you Ari, you prick",
        ))
        .and(wiremock::matchers::body_string_contains(
            "NEVER slang/insult vocatives like 'Karen', 'Bozo', 'Einstein', 'buddy', or 'pal'",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "permitted",
                    "probabilities": { "permitted": 0.92, "harassment": 0.08 }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .and(wiremock::matchers::body_string_contains(
            "rhetorical second-person apostrophe ('shouting at the screen')",
        ))
        .and(wiremock::matchers::body_string_contains("STRICT GUARDRAILS"))
        .and(wiremock::matchers::body_string_contains("Karen"))
        .and(wiremock::matchers::body_string_contains("Bozo"))
        .and(wiremock::matchers::body_string_contains("buddy"))
        .and(wiremock::matchers::body_string_contains("c3JjX2N0eF9pbWc="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {
                "role": "assistant",
                "content": r#"{"violates": false, "category": null, "confidence": 0.99, "reason": "Rhetorical second-person apostrophe addressed to Ari Emanuel in quoted screenshot, not Target."}"#
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/karen/api/chat"))
        .and(wiremock::matchers::body_string_contains("Okay Karen, you prick."))
        .and(wiremock::matchers::body_string_contains(
            "unqualified second-person attacks on Target",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {
                "role": "assistant",
                "content": r#"{"violates": true, "category": "harassment", "confidence": 0.99, "reason": "Uses generic slang vocative 'Karen' + second-person insult addressing Target."}"#
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut ctx = EnrichedContext::empty();
    ctx.thread_ancestors = vec![ThreadPost {
        author_did: target_did.to_string(),
        text: "LMAO they're still blaming Buttigieg? Wild.".to_string(),
    }];
    ctx.thread_ancestor_quotes = vec![Some(QuotedAncestor {
        author_did: quoted_did.to_string(),
        author_handle: Some("pierceah66.bsky.social".to_string()),
        text: "Rahm’s shady bitch of a brother being very loud & wrong.".to_string(),
    })];
    ctx.thread_ancestor_embeds = vec![Some(PostEmbedSummary {
        quoted_image_count: 1,
        ..Default::default()
    })];
    ctx.context_images_base64 = vec!["c3JjX2N0eF9pbWc=".to_string()];

    let mut ari_reply = Interaction::new(
        author_did,
        target_did,
        InteractionType::DirectReply,
        "at://did:plc:jbbiqk7nyatsivk2mboyqm6t/app.bsky.feed.post/3n2btnssbrs2s",
        "bafyari",
        "Just for you Ari, you prick.",
    )
    .with_parent_uri(parent_uri);
    ari_reply.enriched_context = Some(ctx.clone());

    let systemone = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/v1/systemone", server.uri()),
            api_key: None,
            model: "nimble".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: true,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(systemone.classify(&ari_reply).await.unwrap().is_permitted());

    let ollama = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/api/chat", server.uri()),
            api_key: None,
            model: "gemma4:26b".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    assert!(ollama.classify(&ari_reply).await.unwrap().is_permitted());

    let karen_ollama = JevClassifier::new(
        JevConfig {
            base_url: format!("{}/karen/api/chat", server.uri()),
            api_key: None,
            model: "gemma4:26b".to_string(),
            timeout: Duration::from_millis(1000),
            max_retries: 0,
            supports_images: false,
        },
        RuleRubric::default(),
    )
    .unwrap();
    let mut karen_reply = Interaction::new(
        author_did,
        target_did,
        InteractionType::DirectReply,
        "at://did:plc:jbbiqk7nyatsivk2mboyqm6t/app.bsky.feed.post/karen1",
        "bafykaren",
        "Okay Karen, you prick.",
    )
    .with_parent_uri(parent_uri);
    karen_reply.enriched_context = Some(ctx);
    let karen_verdict = karen_ollama.classify(&karen_reply).await.unwrap();
    assert!(matches!(
        karen_verdict,
        Verdict::Violation {
            category: ViolationCategory::Harassment,
            ..
        }
    ));

    // Confirm SystemOne never receives context_images_base64 even when supports_images=true.
    let reqs = server.received_requests().await.unwrap();
    let s1_req = reqs
        .iter()
        .find(|r| r.url.path() == "/v1/systemone")
        .expect("SystemOne request recorded");
    assert!(!String::from_utf8_lossy(&s1_req.body).contains("c3JjX2N0eF9pbWc="));
}
