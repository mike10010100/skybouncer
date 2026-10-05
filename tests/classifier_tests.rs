//! Hermetic unit and integration tests for Classifier engine.
//!
//! Covers JevClassifier with Wiremock, HeuristicClassifier, MockClassifier,
//! RuleRubric, Sensitivity, and Verdict models. Property tests live in
//! `tests/property_tests.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wiremock::matchers::{body_json, body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skybouncer::classifier::{
    CertaintyConfig, Classifier, HeuristicClassifier, JevClassifier, JevConfig, JevEndpointKind,
    MockClassifier, RuleRubric, Sensitivity, TieredClassifier, Verdict, ViolationCategory,
};
use skybouncer::enricher::EnrichedContext;
use skybouncer::error::SkybouncerError;
use skybouncer::matcher::{extract_did_from_at_uri, Interaction, InteractionType};

fn sample_interaction(text: &str) -> Interaction {
    Interaction {
        post_uri: "at://did:plc:spammer123/app.bsky.feed.post/3kxyz".to_string(),
        post_cid: Some("bafyrei_test_cid".to_string()),
        author_did: "did:plc:spammer123".to_string(),
        target_did: "did:plc:protected456".to_string(),
        text: text.to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: Some("at://did:plc:protected456/app.bsky.feed.post/root".to_string()),
        root_uri: Some("at://did:plc:protected456/app.bsky.feed.post/root".to_string()),
        created_at_us: 1_700_000_000_000_000,
        image_cids: Vec::new(),
        image_alts: Vec::new(),
        enriched_context: None,
        rubric: None,
    }
}

// =============================================================================
// 1. JevClassifier Wiremock Tests
// =============================================================================

#[tokio::test]
async fn test_jev_classifier_violation_success() {
    let server = MockServer::start().await;

    let expected_body = json!({
        "model": "jev-system1-mod-v1",
        "text": "Claim free crypto airdrop at https://evil.scam",
        "rubric": "Block crypto scams",
        "context": {
            "author_did": "did:plc:spammer123",
            "target_did": "did:plc:protected456",
            "interaction_type": "direct_reply"
        },
        "sensitivity": "medium"
    });

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(header("authorization", "Bearer test_secret_key"))
        .and(header("content-type", "application/json"))
        .and(body_json(expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.96,
            "reason": "Unsolicited airdrop link detected"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: Some("test_secret_key".to_string()),
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let rubric = RuleRubric::new("Block crypto scams", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let interaction = sample_interaction("Claim free crypto airdrop at https://evil.scam");
    let verdict = classifier.classify(&interaction).await.unwrap();

    match verdict {
        Verdict::Violation {
            category,
            confidence,
            reason,
        } => {
            assert_eq!(category, ViolationCategory::CryptoSpam);
            assert!((confidence - 0.96).abs() < 1e-6);
            assert_eq!(reason, "Unsolicited airdrop link detected");
        }
        Verdict::Permitted { .. } => panic!("Expected Violation verdict"),
    }
}

#[tokio::test]
async fn test_jev_classifier_permitted_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": false,
            "category": null,
            "confidence": 0.10,
            "reason": "Friendly greeting"
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
    let rubric = RuleRubric::new("Block crypto scams", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let interaction = sample_interaction("Hello! How are you doing today?");
    let verdict = classifier.classify(&interaction).await.unwrap();

    match verdict {
        Verdict::Permitted { reason, .. } => {
            assert_eq!(reason, "Friendly greeting");
        }
        Verdict::Violation { .. } => panic!("Expected Permitted verdict"),
    }
}

#[tokio::test]
async fn test_jev_classifier_confidence_below_threshold_downgrades_to_permitted() {
    let server = MockServer::start().await;

    // Sensitivity::Medium requires threshold >= 0.75.
    // Server returns confidence 0.65.
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "harassment",
            "confidence": 0.65,
            "reason": "Borderline negative comment"
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
    let rubric = RuleRubric::new("Block harassment", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let interaction = sample_interaction("I disagree with your take.");
    let verdict = classifier.classify(&interaction).await.unwrap();

    // Must downgrade to Permitted because confidence 0.65 < 0.75 threshold!
    assert!(!verdict.is_violation());
    assert_eq!(verdict.reason(), "Borderline negative comment");
}

#[tokio::test]
async fn test_jev_classifier_single_retry_on_500() {
    let server = MockServer::start().await;

    // Attempt 1: 500 Internal Server Error
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal server error"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    // Attempt 2 (Retry): 200 OK
    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "spam",
            "confidence": 0.90,
            "reason": "Spam after retry"
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
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let interaction = sample_interaction("Spam link");
    let verdict = classifier.classify(&interaction).await.unwrap();

    assert!(verdict.is_violation());
    assert_eq!(verdict.reason(), "Spam after retry");
}

#[tokio::test]
async fn test_jev_classifier_never_retries_401_client_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized: Invalid API Key"))
        .expect(1) // STRICT INVARIANT: Exactly 1 call, NEVER retries 4xx!
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: Some("bad_key".to_string()),
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let interaction = sample_interaction("Hello");
    let err = classifier.classify(&interaction).await.unwrap_err();

    assert!(err.to_string().contains("client error (HTTP 401)"));
}

#[tokio::test]
async fn test_jev_classifier_exhausts_retries_on_persistent_503() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(2) // 1 initial + 1 retry = 2 attempts total
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let interaction = sample_interaction("Hello");
    let err = classifier.classify(&interaction).await.unwrap_err();

    assert!(err.to_string().contains("server error (HTTP 503)"));
}

#[tokio::test]
async fn test_jev_classifier_timeout() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(300)))
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: server.uri(),
        api_key: None,
        model: "jev-system1-mod-v1".to_string(),
        timeout: Duration::from_millis(50), // 50ms timeout
        max_retries: 0,
    };
    let rubric = RuleRubric::new("Block spam", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let interaction = sample_interaction("Hello");
    let err = classifier.classify(&interaction).await.unwrap_err();

    assert!(err.to_string().contains("network error") || err.to_string().contains("timed out"));
}

#[test]
fn test_jev_config_defaults_and_env() {
    let default_config = JevConfig::default();
    assert_eq!(default_config.base_url, "https://api.jev.ai");
    assert_eq!(default_config.model, "jev-system1-mod-v1");
    assert_eq!(default_config.timeout, Duration::from_millis(15000));
    assert_eq!(default_config.max_retries, 1);
    assert!(default_config.api_key.is_none());

    // Test environment variable parsing
    std::env::set_var("JEV_API_BASE_URL", "https://custom.jev.domain");
    std::env::set_var("JEV_API_KEY", "secret_key_123");
    std::env::set_var("JEV_MODEL", "custom-model");
    std::env::set_var("JEV_TIMEOUT_MS", "5000");
    std::env::set_var("JEV_MAX_RETRIES", "2");

    let env_config = JevConfig::from_env().unwrap();
    assert_eq!(env_config.base_url, "https://custom.jev.domain");
    assert_eq!(env_config.api_key.as_deref(), Some("secret_key_123"));
    assert_eq!(env_config.model, "custom-model");
    assert_eq!(env_config.timeout, Duration::from_millis(5000));
    assert_eq!(env_config.max_retries, 2);

    std::env::remove_var("JEV_API_BASE_URL");
    std::env::remove_var("JEV_API_KEY");
    std::env::remove_var("JEV_MODEL");
    std::env::remove_var("JEV_TIMEOUT_MS");
    std::env::remove_var("JEV_MAX_RETRIES");
}

#[tokio::test]
async fn test_jev_classifier_endpoint_kind_detection() {
    let rubric = RuleRubric::default();

    // Standard Jev
    let c_std = JevClassifier::new(
        JevConfig {
            base_url: "https://example.com/api".to_string(),
            ..Default::default()
        },
        rubric.clone(),
    )
    .unwrap();
    assert_eq!(c_std.endpoint_kind(), JevEndpointKind::StandardJev);
    assert_eq!(c_std.classify_url(), "https://example.com/api/v1/classify");

    // Ollama port 11434
    let c_ollama = JevClassifier::new(
        JevConfig {
            base_url: "http://localhost:11434".to_string(),
            ..Default::default()
        },
        rubric.clone(),
    )
    .unwrap();
    assert_eq!(c_ollama.endpoint_kind(), JevEndpointKind::Ollama);
    assert_eq!(c_ollama.classify_url(), "http://localhost:11434/api/chat");

    // System-One port 8000
    let c_sysone = JevClassifier::new(
        JevConfig {
            base_url: "http://localhost:8000".to_string(),
            ..Default::default()
        },
        rubric,
    )
    .unwrap();
    assert_eq!(c_sysone.endpoint_kind(), JevEndpointKind::SystemOne);
    assert_eq!(
        c_sysone.classify_url(),
        "http://localhost:8000/v1/systemone"
    );
}

#[tokio::test]
async fn test_jev_classifier_ollama_dialect_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "tev1:latest",
            "message": {
                "role": "assistant",
                "content": "{\"violates\": true, \"category\": \"crypto_spam\", \"confidence\": 0.95, \"reason\": \"Airdrop scam link detected\"}"
            },
            "done": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: format!("{}/api/chat", server.uri()),
        api_key: None,
        model: "tev1:latest".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let rubric = RuleRubric::new("Block crypto scams", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();
    assert_eq!(classifier.endpoint_kind(), JevEndpointKind::Ollama);

    let interaction = sample_interaction("Claim free airdrop now");
    let verdict = classifier.classify(&interaction).await.unwrap();

    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::CryptoSpam));
    assert_eq!(verdict.confidence(), Some(0.95));
}

#[tokio::test]
async fn test_jev_classifier_systemone_dialect_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "tev1",
            "answers": {
                "moderation": {
                    "type": "choice",
                    "choice": "crypto_spam",
                    "probabilities": {
                        "crypto_spam": 0.985,
                        "permitted": 0.015
                    },
                    "confidence": 0.94
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: format!("{}/v1/systemone", server.uri()),
        api_key: None,
        model: "tev1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let rubric = RuleRubric::new("Block crypto scams", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();
    assert_eq!(classifier.endpoint_kind(), JevEndpointKind::SystemOne);

    let interaction = sample_interaction("Claim free airdrop now");
    let verdict = classifier.classify(&interaction).await.unwrap();

    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::CryptoSpam));
    assert!((verdict.confidence().unwrap() - 0.985).abs() < 1e-4);
}

// =============================================================================
// 2. HeuristicClassifier Unit & Property Tests
// =============================================================================

#[test]
fn test_heuristic_crypto_airdrop_patterns() {
    let classifier = HeuristicClassifier::new().unwrap();
    let triggers = [
        "Check out this huge airdrop opportunity!",
        "Claim free tokens at our site now",
        "Presale live! Connect wallet immediately",
        "Whitelist now open for minting",
        "DM for crypto signals and VIP access",
        "Send eth to this address and get 2x back",
        "Congratulations giveaway winner! Claim reward",
        "FREE MINT IS LIVE RIGHT NOW",
        "Claim your allocation before it expires",
    ];

    for text in triggers {
        let verdict = classifier.evaluate_text(text);
        assert!(verdict.is_violation(), "Expected violation for: {text}");
        assert_eq!(verdict.confidence(), Some(1.0));
        if let Verdict::Violation { category, .. } = verdict {
            assert_eq!(category, ViolationCategory::CryptoSpam);
        }
    }
}

#[test]
fn test_heuristic_messaging_lures() {
    let classifier = HeuristicClassifier::new().unwrap();
    let triggers = [
        "Join our trading community: t.me/cryptopumps",
        "https://telegram.me/spambot",
        "Message support on WhatsApp: wa.me/+14155552671",
        "Join my Discord server: discord.gg/freecrypto",
        "Visit https://discord.com/invite/exclusive_airdrop",
    ];

    for text in triggers {
        let verdict = classifier.evaluate_text(text);
        assert!(verdict.is_violation(), "Expected violation for: {text}");
        if let Verdict::Violation { category, .. } = verdict {
            assert_eq!(category, ViolationCategory::Spam);
        }
    }
}

#[test]
fn test_heuristic_suspicious_tlds() {
    let classifier = HeuristicClassifier::new().unwrap();
    let triggers = [
        "Check this out at https://scam-site.xyz/login",
        "Go to http://free-download.top/browse",
        "Visit https://latest-promo.buzz/",
        "Click https://phishing.click/auth",
        "Get funds at https://fast-money.loan",
        "https://malicious.gq/app",
    ];

    for text in triggers {
        let verdict = classifier.evaluate_text(text);
        assert!(verdict.is_violation(), "Expected violation for: {text}");
        if let Verdict::Violation { category, .. } = verdict {
            assert_eq!(category, ViolationCategory::Phishing);
        }
    }
}

#[test]
fn test_heuristic_benign_negative_cases() {
    let classifier = HeuristicClassifier::new().unwrap();
    let benign_texts = [
        "I'm studying the history of cryptography and modern protocols.",
        "There was a noticeable drop in temperature last night.",
        "Did you pick up your wallet from the lost and found?",
        "I need to claim my baggage at terminal 2.",
        "Check out my open-source code at https://github.com/rust-lang/rust",
        "Top stories of the day: https://nytimes.com/top-stories",
        "Let's meet at 3:00pm today.",
        "This is a totally normal, friendly post about gardening.",
    ];

    for text in benign_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(!verdict.is_violation(), "Expected permitted for: {text}");
    }
}

#[test]
fn test_heuristic_custom_rule_addition() {
    let mut classifier = HeuristicClassifier::new().unwrap();
    classifier
        .add_rule(
            r"(?i)\bbadpattern123\b",
            ViolationCategory::Custom("test_rule".to_string()),
            "test custom rule",
        )
        .unwrap();

    let verdict = classifier.evaluate_text("Here is some text with badpattern123 included.");
    assert!(verdict.is_violation());
    if let Verdict::Violation {
        category, reason, ..
    } = verdict
    {
        assert_eq!(category, ViolationCategory::Custom("test_rule".to_string()));
        assert!(reason.contains("test custom rule"));
    }
}

#[test]
fn test_heuristic_sub_microsecond_execution() {
    let classifier = HeuristicClassifier::new().unwrap();
    let benign = "A typical Bluesky post with some text discussing programming and everyday life.";

    // Warm up
    for _ in 0..1_000 {
        let _ = classifier.evaluate_text(benign);
    }

    let iterations = 10_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = classifier.evaluate_text(benign);
    }
    let elapsed = start.elapsed();
    let nanos_per_call = elapsed.as_nanos() / iterations as u128;

    // Sub-microsecond requirement in release mode (< 1000 ns); unoptimized debug builds allow up to 10us
    let threshold = if cfg!(debug_assertions) {
        10_000
    } else {
        1_000
    };
    assert!(
        nanos_per_call < threshold,
        "Classification took {nanos_per_call} ns/call, exceeding {threshold} ns threshold!"
    );
}

// =============================================================================
// 3. MockClassifier Tests
// =============================================================================

#[tokio::test]
async fn test_mock_classifier_call_counting_and_delays() {
    let mock = MockClassifier::permitted();
    assert_eq!(mock.call_count(), 0);

    let interaction = sample_interaction("Hello there!");
    let verdict = mock.classify(&interaction).await.unwrap();
    assert!(!verdict.is_violation());
    assert_eq!(mock.call_count(), 1);

    // Keyword verdict override
    mock.set_keyword_verdict(
        "scam",
        Verdict::Violation {
            category: ViolationCategory::Spam,
            confidence: 0.99,
            reason: "Keyword hit".to_string(),
        },
    );

    let scam_interaction = sample_interaction("This is a scam post");
    let scam_verdict = mock.classify(&scam_interaction).await.unwrap();
    assert!(scam_verdict.is_violation());
    assert_eq!(mock.call_count(), 2);

    // Simulated delay
    mock.set_simulated_delay(Some(Duration::from_millis(25)));
    let start = Instant::now();
    let _ = mock.classify(&interaction).await.unwrap();
    assert!(start.elapsed() >= Duration::from_millis(20));
    assert_eq!(mock.call_count(), 3);

    // Simulated error
    mock.set_error(Some("upstream timeout"));
    let err = mock.classify(&interaction).await.unwrap_err();
    assert!(matches!(err, SkybouncerError::Classifier(_)));
    assert_eq!(mock.call_count(), 4);

    // Reset
    mock.reset_call_count();
    assert_eq!(mock.call_count(), 0);
}

// =============================================================================
// 4. Models: Verdict, ViolationCategory, Sensitivity, Rubric & Matcher
// =============================================================================

#[test]
fn test_verdict_helpers_and_clamping() {
    // Normal violation
    let v1 = Verdict::violation(ViolationCategory::Spam, 0.85, "Spam detected");
    assert!(v1.is_violation());
    assert!(!v1.is_permitted());
    assert_eq!(v1.confidence(), Some(0.85));
    assert_eq!(v1.reason(), "Spam detected");
    assert_eq!(v1.category(), Some(&ViolationCategory::Spam));

    // Clamping > 1.0
    let v2 = Verdict::violation(ViolationCategory::CryptoSpam, 1.5, "Out of bounds");
    assert_eq!(v2.confidence(), Some(1.0));

    // Clamping < 0.0
    let v3 = Verdict::violation(ViolationCategory::CryptoSpam, -0.5, "Negative bounds");
    assert_eq!(v3.confidence(), Some(0.0));

    // NaN sanitized to 0.0
    let v4 = Verdict::violation(ViolationCategory::CryptoSpam, f64::NAN, "NaN bounds");
    assert_eq!(v4.confidence(), Some(0.0));

    // Permitted
    let p = Verdict::permitted("Looks benign");
    assert!(!p.is_violation());
    assert!(p.is_permitted());
    assert_eq!(p.confidence(), None);
    assert_eq!(p.category(), None);
    assert_eq!(p.reason(), "Looks benign");
}

#[test]
fn test_verdict_serde_json_roundtrip() {
    let violation = Verdict::violation(ViolationCategory::Harassment, 0.92, "Abusive text");
    let json_str = serde_json::to_string(&violation).unwrap();
    assert!(json_str.contains(r#""status":"violation""#));
    assert!(json_str.contains(r#""category":"harassment""#));

    let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(violation, deserialized);

    let permitted = Verdict::permitted("All clear");
    let json_p = serde_json::to_string(&permitted).unwrap();
    assert!(json_p.contains(r#""status":"permitted""#));

    let deserialized_p: Verdict = serde_json::from_str(&json_p).unwrap();
    assert_eq!(permitted, deserialized_p);
}

#[test]
fn test_violation_category_custom_slug() {
    let cat = ViolationCategory::from_slug("doxxing");
    assert_eq!(cat, ViolationCategory::Custom("doxxing".to_string()));
    assert_eq!(cat.as_str(), "doxxing");

    // Serde roundtrip for custom
    let json_val = serde_json::to_string(&cat).unwrap();
    assert_eq!(json_val, r#""doxxing""#);
    let parsed: ViolationCategory = serde_json::from_str(&json_val).unwrap();
    assert_eq!(parsed, cat);
}

#[test]
fn test_sensitivity_thresholds_and_parsing() {
    assert!((Sensitivity::Low.threshold() - 0.90).abs() < 1e-6);
    assert!((Sensitivity::Medium.threshold() - 0.75).abs() < 1e-6);
    assert!((Sensitivity::High.threshold() - 0.60).abs() < 1e-6);

    assert_eq!("low".parse::<Sensitivity>().unwrap(), Sensitivity::Low);
    assert_eq!(
        "medium".parse::<Sensitivity>().unwrap(),
        Sensitivity::Medium
    );
    assert_eq!("med".parse::<Sensitivity>().unwrap(), Sensitivity::Medium);
    assert_eq!("high".parse::<Sensitivity>().unwrap(), Sensitivity::High);
    assert!("invalid".parse::<Sensitivity>().is_err());
}

#[test]
fn test_rubric_actionability_and_downgrade() {
    let rubric = RuleRubric::new("Block hate speech", Sensitivity::Medium);
    assert!(!rubric.is_actionable(0.70));
    assert!(rubric.is_actionable(0.75));
    assert!(rubric.is_actionable(0.95));

    // Violation below threshold gets downgraded to Permitted
    let borderline = Verdict::violation(ViolationCategory::HateSpeech, 0.70, "Mildly offensive");
    let evaluated = rubric.evaluate_verdict(borderline);
    assert!(evaluated.is_permitted());
    assert!(evaluated
        .reason()
        .contains("below the medium sensitivity threshold"));

    // Violation above threshold remains Violation
    let severe = Verdict::violation(ViolationCategory::HateSpeech, 0.85, "Severe slurs");
    let evaluated_severe = rubric.evaluate_verdict(severe);
    assert!(evaluated_severe.is_violation());
}

#[test]
fn test_rubric_parser_directives() {
    let raw = "sensitivity: high\nBlock all crypto promotion and airdrops.";
    let rubric = RuleRubric::parse(raw).unwrap();
    assert_eq!(rubric.sensitivity, Sensitivity::High);
    assert_eq!(rubric.prompt, "Block all crypto promotion and airdrops.");

    // Bracketed directive
    let raw_bracketed = "[sensitivity: low]\nBlock toxic behavior.";
    let rubric_b = RuleRubric::parse(raw_bracketed).unwrap();
    assert_eq!(rubric_b.sensitivity, Sensitivity::Low);
    assert_eq!(rubric_b.prompt, "Block toxic behavior.");

    // Empty prompt error
    assert!(RuleRubric::parse("   ").is_err());
    assert!(RuleRubric::parse("sensitivity: low\n   ").is_err());
}

#[test]
fn test_extract_did_from_at_uri() {
    let uri = "at://did:plc:spammer123/app.bsky.feed.post/3kxyz";
    assert_eq!(extract_did_from_at_uri(uri), Some("did:plc:spammer123"));

    assert_eq!(
        extract_did_from_at_uri("https://bsky.app/profile/foo"),
        None
    );
    assert_eq!(
        extract_did_from_at_uri("at://not_a_did/app.bsky.feed.post/1"),
        None
    );
}

#[test]
fn test_interaction_self_interaction() {
    let mut interaction = sample_interaction("Self talk");
    assert!(!interaction.is_self_interaction());

    interaction.author_did = interaction.target_did.clone();
    assert!(interaction.is_self_interaction());
}

#[tokio::test]
async fn test_jev_classifier_multimodal_images_injected_standard_jev() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/classify"))
        .and(body_string_contains("c3RhbmRhcmRfamV2X2ltYWdl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "violates": true,
            "category": "crypto_spam",
            "confidence": 0.99,
            "reason": "Multimodal visual wallet drainer QR detected"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: format!("{}/v1/classify", server.uri()),
        api_key: None,
        model: "jev-multimodal-v1".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let rubric = RuleRubric::new("Block crypto scams", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let mut interaction = sample_interaction("Check this image");
    let mut enriched = EnrichedContext::default();
    enriched
        .images_base64
        .push("c3RhbmRhcmRfamV2X2ltYWdl".to_string());
    interaction.enriched_context = Some(enriched);

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::CryptoSpam));
    assert_eq!(verdict.confidence(), Some(0.99));
}

#[tokio::test]
async fn test_jev_classifier_multimodal_images_injected_ollama() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .and(body_string_contains("b2xsYW1hX3Zpc2lvbl9pbWFnZQ=="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "gemma4:12b",
            "message": {
                "role": "assistant",
                "content": "{\"violates\": true, \"category\": \"harassment\", \"confidence\": 0.94, \"reason\": \"Abusive visual meme detected\"}"
            },
            "done": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = JevConfig {
        base_url: format!("{}/api/chat", server.uri()),
        api_key: None,
        model: "gemma4:12b".to_string(),
        timeout: Duration::from_millis(1000),
        max_retries: 1,
    };
    let rubric = RuleRubric::new("Block harassment", Sensitivity::Medium);
    let classifier = JevClassifier::new(config, rubric).unwrap();

    let mut interaction = sample_interaction("Look at this");
    let mut enriched = EnrichedContext::default();
    enriched
        .images_base64
        .push("b2xsYW1hX3Zpc2lvbl9pbWFnZQ==".to_string());
    interaction.enriched_context = Some(enriched);

    let verdict = classifier.classify(&interaction).await.unwrap();
    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::Harassment));
    assert_eq!(verdict.confidence(), Some(0.94));
}

#[tokio::test]
async fn test_tiered_classifier_integration_escalation() {
    // Primary classifier returns borderline/uncertain score (0.60, within [0.40, 0.85))
    let primary = Arc::new(MockClassifier::new(Verdict::permitted_with_confidence(
        "Borderline text",
        0.60,
    )));
    // Fallback classifier (e.g. gemma4:12b) returns confident violation
    let fallback = Arc::new(MockClassifier::new(Verdict::violation(
        ViolationCategory::Harassment,
        0.92,
        "System-2 confirmed violation",
    )));

    let config = CertaintyConfig::new(0.40, 0.85, true);
    let tiered = TieredClassifier::new(primary.clone(), fallback.clone(), config);

    let interaction = sample_interaction("borderline statement");
    let verdict = tiered.classify(&interaction).await.unwrap();

    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::Harassment));
    assert_eq!(verdict.confidence(), Some(0.92));
    assert_eq!(primary.call_count(), 1);
    assert_eq!(fallback.call_count(), 1);
    assert_eq!(tiered.stats().fallback_escalated.load(Ordering::Relaxed), 1);
    assert_eq!(
        tiered
            .stats()
            .uncertainty_escalations
            .load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn test_tiered_classifier_image_escalation() {
    // Primary classifier allows text
    let primary = Arc::new(MockClassifier::permitted());
    // Fallback classifier detects violation in image
    let fallback = Arc::new(MockClassifier::violation(
        ViolationCategory::Phishing,
        0.95,
        "Visual phishing credential harvest in image",
    ));

    let config = CertaintyConfig::new(0.40, 0.85, true);
    let tiered = TieredClassifier::new(primary.clone(), fallback.clone(), config);

    let mut interaction = sample_interaction("Please review attachment");
    interaction
        .image_cids
        .push("bafkreitestimagecid".to_string());
    interaction.image_alts.push("attachment.png".to_string());

    let verdict = tiered.classify(&interaction).await.unwrap();

    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::Phishing));
    assert_eq!(primary.call_count(), 1);
    assert_eq!(fallback.call_count(), 1);
    assert_eq!(tiered.stats().image_escalations.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_tiered_classifier_integration_decisive_violation_bypass() {
    // Primary classifier returns high confidence violation (0.95 >= 0.85)
    let primary = Arc::new(MockClassifier::new(Verdict::violation(
        ViolationCategory::CryptoSpam,
        0.95,
        "Unambiguous crypto drainer link in text",
    )));
    // Fallback classifier should NEVER be called
    let fallback = Arc::new(MockClassifier::permitted());

    let config = CertaintyConfig::new(0.40, 0.85, true);
    let tiered = TieredClassifier::new(primary.clone(), fallback.clone(), config);

    let mut interaction = sample_interaction("Claim free ETH now: https://scam.eth");
    // Even if interaction has images attached, decisive text violation skips fallback
    interaction.image_cids.push("bafkreiblob".to_string());

    let verdict = tiered.classify(&interaction).await.unwrap();

    assert!(verdict.is_violation());
    assert_eq!(verdict.category(), Some(&ViolationCategory::CryptoSpam));
    assert_eq!(primary.call_count(), 1);
    assert_eq!(fallback.call_count(), 0);
    assert_eq!(tiered.stats().primary_resolved.load(Ordering::Relaxed), 1);
    assert_eq!(tiered.stats().fallback_escalated.load(Ordering::Relaxed), 0);
}

// Property tests for the heuristic classifier now live in the canonical
// `tests/property_tests.rs` (see `rust-best-practices` blueprint).
