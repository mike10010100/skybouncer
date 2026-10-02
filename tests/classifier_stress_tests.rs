//! Empirical stress-testing, adversarial challenge, and concurrency harness
//! for `HeuristicClassifier` and `MockClassifier`.
//!
//! Evaluates regex patterns against adversarial payloads (zero-width spaces, homoglyphs,
//! case variations, ReDoS / large payloads), false positive boundaries, sub-microsecond
//! latency profiles, and high-concurrency safety (50 tasks, atomic counter, zero deadlocks).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use skybouncer::classifier::{
    Classifier, HeuristicClassifier, MockClassifier, Verdict, ViolationCategory,
};
use skybouncer::matcher::{Interaction, InteractionType};

fn make_test_interaction(text: &str) -> Interaction {
    Interaction {
        post_uri: "at://did:plc:stress_test/app.bsky.feed.post/stress_rkey".to_string(),
        post_cid: Some("bafyrei_stress_cid".to_string()),
        author_did: "did:plc:attacker_or_user".to_string(),
        target_did: "did:plc:protected_target".to_string(),
        text: text.to_string(),
        interaction_type: InteractionType::DirectReply,
        parent_uri: None,
        root_uri: None,
        created_at_us: 1_700_000_000_000_000,
        enriched_context: None,
    }
}

// =============================================================================
// 1. Adversarial Payloads & Regex Evasion
// =============================================================================

#[test]
fn test_adversarial_case_variations() {
    let classifier = HeuristicClassifier::new().unwrap();

    let case_variations = [
        ("AiRdRoP now", ViolationCategory::CryptoSpam),
        ("cLaIm FrEe ToKeNs", ViolationCategory::CryptoSpam),
        ("CoNnEcT wAlLeT iMmEdIaTeLy", ViolationCategory::CryptoSpam),
        ("SeNd EtH to double your bag", ViolationCategory::CryptoSpam),
        ("dIsCoRd.Gg/CrYpToPuMpS", ViolationCategory::Spam),
        ("t.Me/ScAmChAt", ViolationCategory::Spam),
        ("wA.mE/+1234567890", ViolationCategory::Spam),
        ("hTtPs://EvIl-SiTe.XyZ/LoGiN", ViolationCategory::Phishing),
        (
            "HtTp://FrEe-MoNeY.tOp/DoWnLoAd",
            ViolationCategory::Phishing,
        ),
    ];

    for (payload, expected_category) in case_variations {
        let verdict = classifier.evaluate_text(payload);
        assert!(
            verdict.is_violation(),
            "Case variation failed to match: '{payload}'"
        );
        if let Verdict::Violation { category, .. } = verdict {
            assert_eq!(
                category, expected_category,
                "Category mismatch for '{payload}'"
            );
        }
    }
}

#[test]
fn test_adversarial_zero_width_spaces_evasion_observation() {
    let classifier = HeuristicClassifier::new().unwrap();

    // Adversarial injection of zero-width spaces (\u{200B}, \u{200C}, \u{200D}, \u{FEFF})
    // into standard triggers.
    let zws_payloads = [
        "c\u{200B}o\u{200B}n\u{200B}n\u{200B}e\u{200B}c\u{200B}t w\u{200B}a\u{200B}l\u{200B}l\u{200B}e\u{200B}t",
        "a\u{200C}i\u{200C}r\u{200C}d\u{200C}r\u{200C}o\u{200C}p",
        "c\u{200D}l\u{200D}a\u{200D}i\u{200D}m f\u{200D}r\u{200D}e\u{200D}e",
        "s\u{FEFF}e\u{FEFF}n\u{FEFF}d e\u{FEFF}t\u{FEFF}h",
        "t\u{200B}.\u{200B}m\u{200B}e/scam",
    ];

    for payload in zws_payloads {
        // Empirical observation: HeuristicClassifier uses standard ASCII regex without
        // zero-width normalization. The regex evaluates safely without panics or crashes,
        // and returns Permitted, which allows the System-2 (JevClassifier) semantic layer
        // to handle the evasive interaction.
        let verdict = classifier.evaluate_text(payload);
        assert!(
            !verdict.is_violation(),
            "Empirical observation: zero-width space broke simple regex as expected"
        );
    }
}

#[test]
fn test_adversarial_homoglyphs_evasion_observation() {
    let classifier = HeuristicClassifier::new().unwrap();

    // Cyrillic homoglyphs: 'а' (U+0430), 'і' (U+0456), 'о' (U+043E), 'р' (U+0440)
    let cyrillic_airdrop = "\u{0430}\u{0456}\u{0440}dr\u{043E}\u{0440}";
    // Fullwidth Latin: 'ａｉｒｄｒｏｐ' (U+FF41 ..)
    let fullwidth_airdrop = "\u{FF41}\u{FF49}\u{FF52}\u{FF44}\u{FF52}\u{FF4F}\u{FF50}";
    // Mathematical bold: '𝐚𝐢𝐫𝐝𝐫𝐨𝐩'
    let math_bold_airdrop = "𝐚𝐢𝐫𝐝𝐫𝐨𝐩";

    let homoglyphs = [cyrillic_airdrop, fullwidth_airdrop, math_bold_airdrop];

    for payload in homoglyphs {
        let verdict = classifier.evaluate_text(payload);
        // Does not panic, returns Permitted for System-2 delegation.
        assert!(
            !verdict.is_violation(),
            "Empirical observation: homoglyph bypasses ASCII regex pre-filter"
        );
    }
}

#[test]
fn test_adversarial_redos_and_extreme_payloads() {
    let classifier = HeuristicClassifier::new().unwrap();

    // 1. Catastrophic backtracking attempt: repeating partial match prefixes
    let repeating_claim = "claim ".repeat(5_000);
    let start = Instant::now();
    let verdict = classifier.evaluate_text(&repeating_claim);
    let elapsed = start.elapsed();
    assert!(!verdict.is_violation());
    assert!(
        elapsed < Duration::from_millis(50),
        "ReDoS vulnerability detected! 5000 repeating claims took {elapsed:?}"
    );

    // 2. Extreme whitespace between words
    let spaced_claim = format!("claim{}free", " ".repeat(50_000));
    let start = Instant::now();
    let verdict = classifier.evaluate_text(&spaced_claim);
    let elapsed = start.elapsed();
    // \s+ should match even 50,000 spaces linearly in Rust regex
    assert!(verdict.is_violation());
    assert!(
        elapsed < Duration::from_millis(50),
        "Extreme whitespace took {elapsed:?}"
    );

    // 3. 1 Megabyte string without match
    let large_non_match = "The quick brown fox jumps over the lazy dog. ".repeat(25_000); // ~1.1 MB
    let start = Instant::now();
    let verdict = classifier.evaluate_text(&large_non_match);
    let elapsed = start.elapsed();
    assert!(!verdict.is_violation());
    // In Rust DFA regex, scanning 1MB of text typically takes < 25ms
    assert!(
        elapsed < Duration::from_millis(150),
        "1MB payload scan exceeded 150ms: {elapsed:?}"
    );

    // 4. 1 Megabyte string with trigger at the very end
    let large_with_trigger_at_end = format!("{large_non_match} connect wallet");
    let start = Instant::now();
    let verdict = classifier.evaluate_text(&large_with_trigger_at_end);
    let elapsed = start.elapsed();
    assert!(verdict.is_violation());
    assert!(
        elapsed < Duration::from_millis(150),
        "1MB payload with tail trigger took {elapsed:?}"
    );
}

// =============================================================================
// 2. False Positive Boundaries
// =============================================================================

#[test]
fn test_false_positive_boundaries_wallet() {
    let classifier = HeuristicClassifier::new().unwrap();

    let benign_wallet_texts = [
        "I lost my physical wallet on the subway today.",
        "Check your back pocket for your wallet.",
        "A leather wallet makes a great gift for Father's Day.",
        "The cold storage wallet is completely air-gapped and disconnected.",
        "How do I disconnect wallet access in settings?",
        "My hardware wallet arrived in the mail this morning.",
        "I need a slim minimalist wallet for travel.",
    ];

    for text in benign_wallet_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(
            !verdict.is_violation(),
            "False positive triggered for legitimate wallet text: '{text}'"
        );
    }

    // Positive triggers must still be caught
    let scam_wallet_texts = [
        "Please connect wallet to claim rewards",
        "Connect your wallet to verify eligibility",
        "Connect   wallet immediately",
    ];

    for text in scam_wallet_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(
            verdict.is_violation(),
            "Expected violation for scam text: '{text}'"
        );
    }
}

#[test]
fn test_false_positive_boundaries_drop() {
    let classifier = HeuristicClassifier::new().unwrap();

    let benign_drop_texts = [
        "There was a noticeable drop in temperatures yesterday.",
        "Please drop off the keys at the reception desk.",
        "Did you drop your phone on the pavement?",
        "Rain drops kept falling throughout the afternoon.",
        "I saw a huge drop in GPU prices recently.",
        "A huge air drop of relief supplies landed in the valley.", // "air drop" with space
    ];

    for text in benign_drop_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(
            !verdict.is_violation(),
            "False positive triggered for legitimate drop text: '{text}'"
        );
    }

    // Boundary observation: Apple's "AirDrop" matches `\bairdrop\b`.
    // In automated bouncer systems, single-word matches like "airdrop" have this known boundary.
    let apple_airdrop = "Can you send me that video via AirDrop?";
    let verdict = classifier.evaluate_text(apple_airdrop);
    assert!(
        verdict.is_violation(),
        "Empirical observation: 'AirDrop' alone triggers CRYPTO_AIRDROP_PATTERN"
    );
}

#[test]
fn test_false_positive_boundaries_telegram() {
    let classifier = HeuristicClassifier::new().unwrap();

    let benign_telegram_texts = [
        "In the 19th century, people communicated across continents via telegram.",
        "Telegram is a popular cloud-based instant messaging platform.",
        "Have you read the latest news about Telegram's CEO?",
        "You can find documentation on https://telegram.org/faq",
        "I uninstalled Telegram to reduce screen time.",
        "Visit telegram.me without any path", // no path after domain
        "Check t.me",                         // no path
    ];

    for text in benign_telegram_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(
            !verdict.is_violation(),
            "False positive triggered for legitimate telegram text: '{text}'"
        );
    }

    // Positive spam lures must trigger
    let scam_telegram_texts = [
        "Join our VIP signals channel: https://t.me/cryptoleaks",
        "Reach out directly at telegram.me/fast_support_247",
        "t.me/free_btc_airdrop",
    ];

    for text in scam_telegram_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(
            verdict.is_violation(),
            "Expected violation for telegram lure: '{text}'"
        );
    }
}

#[test]
fn test_false_positive_boundaries_discord() {
    let classifier = HeuristicClassifier::new().unwrap();

    let benign_discord_texts = [
        "There was widespread discord among the political factions.",
        "Discord released a new audio codec today.",
        "You can check their status page at https://discord.com",
        "Discord is my preferred platform for chatting while gaming.",
        "Visit discord.gg without an invite code", // no invite code path
    ];

    for text in benign_discord_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(
            !verdict.is_violation(),
            "False positive triggered for legitimate discord text: '{text}'"
        );
    }

    // Positive invite lures must trigger
    let scam_discord_texts = [
        "Join our exclusive community: discord.gg/cryptoalpha",
        "Claim rewards on https://discord.com/invite/giveaway2026",
    ];

    for text in scam_discord_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(
            verdict.is_violation(),
            "Expected violation for discord lure: '{text}'"
        );
    }
}

#[test]
fn test_false_positive_boundaries_token_names_and_words() {
    let classifier = HeuristicClassifier::new().unwrap();

    // Verify word boundaries prevent matching partial names
    let benign_word_texts = [
        "Send Ethan our warmest birthday wishes.", // 'Ethan' contains 'eth'
        "Please send Solomon the latest financial report.", // 'Solomon' contains 'sol'
        "Can you send Bethel the package?",        // 'Bethel' contains 'eth'
        "The top ten movies of 2025: https://nytimes.com/top-ten", // path contains 'top'
        "Click here to read the article: https://example.com/click", // path contains 'click'
    ];

    for text in benign_word_texts {
        let verdict = classifier.evaluate_text(text);
        assert!(
            !verdict.is_violation(),
            "False positive triggered for word boundary text: '{text}'"
        );
    }

    // Genuine scams must match
    assert!(classifier
        .evaluate_text("send eth to my address")
        .is_violation());
    assert!(classifier.evaluate_text("send sol fast").is_violation());
    assert!(classifier.evaluate_text("send btc now").is_violation());
}

// =============================================================================
// 3. Empirical Latency Benchmarks
// =============================================================================

#[test]
fn test_empirical_latency_benchmark_multi_profile() {
    let classifier = HeuristicClassifier::new().unwrap();

    let short_benign = "Hey, did you read that article about compiler optimizations?";
    let spam_match = "Claim free tokens and airdrop at https://scam-airdrop.xyz/connect";
    let long_benign = "The architecture of distributed ledger technology requires deep understanding of consensus mechanisms, cryptographic hashing algorithms, and peer-to-peer gossip networking protocols. In modern federated systems, sovereign identities are anchored using decentralized identifiers.".repeat(3); // ~800 chars

    // Warm-up
    for _ in 0..1_000 {
        let _ = classifier.evaluate_text(short_benign);
        let _ = classifier.evaluate_text(spam_match);
        let _ = classifier.evaluate_text(&long_benign);
    }

    let iterations = 20_000;

    // Benchmark 1: Short Benign Post
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = classifier.evaluate_text(short_benign);
    }
    let elapsed_short = start.elapsed();
    let nanos_short = elapsed_short.as_nanos() / iterations as u128;

    // Benchmark 2: Spam Match (early exit on first regex)
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = classifier.evaluate_text(spam_match);
    }
    let elapsed_spam = start.elapsed();
    let nanos_spam = elapsed_spam.as_nanos() / iterations as u128;

    // Benchmark 3: Long Benign Post (~800 chars scanning all 3 regexes)
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = classifier.evaluate_text(&long_benign);
    }
    let elapsed_long = start.elapsed();
    let nanos_long = elapsed_long.as_nanos() / iterations as u128;

    println!(
        "\n--- HeuristicClassifier Empirical Latency Benchmark --- \n\
         - Short Benign (~60 chars):  {nanos_short} ns/call\n\
         - Spam Match (~60 chars):    {nanos_spam} ns/call\n\
         - Long Benign (~800 chars):  {nanos_long} ns/call\n"
    );

    let threshold_short = if cfg!(debug_assertions) {
        10_000
    } else {
        1_000
    };
    assert!(
        nanos_short < threshold_short,
        "Short benign latency {nanos_short} ns exceeded threshold {threshold_short} ns"
    );
}

// =============================================================================
// 4. MockClassifier Concurrency & Safety
// =============================================================================

#[tokio::test]
async fn test_mock_classifier_50_tasks_concurrency_and_atomicity() {
    let mock = Arc::new(MockClassifier::permitted());

    // Pre-populate some keyword rules
    mock.set_keyword_verdict(
        "spam_keyword",
        Verdict::violation(ViolationCategory::Spam, 0.99, "Keyword hit"),
    );

    let task_count = 50;
    let ops_per_task = 200;
    let mut handles = Vec::with_capacity(task_count);

    let total_expected_invocations = task_count * ops_per_task;
    let actual_violations = Arc::new(AtomicUsize::new(0));

    let start_time = Instant::now();

    for task_idx in 0..task_count {
        let mock_clone = Arc::clone(&mock);
        let violations_counter = Arc::clone(&actual_violations);

        let handle = tokio::spawn(async move {
            for i in 0..ops_per_task {
                let text = if i % 2 == 0 {
                    format!("Task {task_idx} harmless post #{i}")
                } else {
                    format!("Task {task_idx} contains spam_keyword #{i}")
                };

                let interaction = make_test_interaction(&text);
                let verdict = mock_clone.classify(&interaction).await.unwrap();

                if verdict.is_violation() {
                    violations_counter.fetch_add(1, Ordering::SeqCst);
                }

                // Periodic dynamic mutation to test concurrent readers and writers
                if i == 50 && task_idx == 0 {
                    mock_clone.set_keyword_verdict(
                        "dynamic_keyword",
                        Verdict::violation(ViolationCategory::Phishing, 0.90, "Dynamic rule"),
                    );
                }

                if i == 100 && task_idx == 1 {
                    mock_clone.set_simulated_delay(Some(Duration::from_micros(10)));
                }

                if i == 150 && task_idx == 1 {
                    mock_clone.set_simulated_delay(None);
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all 50 tasks to complete without deadlock
    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start_time.elapsed();
    let final_call_count = mock.call_count();

    // Verify atomic invocation counter strictly matches total task operations
    assert_eq!(
        final_call_count, total_expected_invocations,
        "Atomic call count mismatch: expected {total_expected_invocations}, got {final_call_count}"
    );

    // Verify that approximately half of the operations returned violations
    let total_violations = actual_violations.load(Ordering::SeqCst);
    assert_eq!(total_violations, total_expected_invocations / 2);

    println!(
        "\n--- MockClassifier Concurrency Verification --- \n\
         - Tasks: {task_count}\n\
         - Total Invocations: {final_call_count}\n\
         - Total Violations:  {total_violations}\n\
         - Wall Time:         {elapsed:?}\n\
         - Deadlocks:         0 (Clean join)\n"
    );
}

#[tokio::test]
async fn test_mock_classifier_concurrency_error_injection_lifecycle() {
    let mock = Arc::new(MockClassifier::permitted());

    let task_count = 20;
    let mut handles = Vec::with_capacity(task_count);

    // Concurrently trigger classify while an injector toggles error states
    for task_idx in 0..task_count {
        let mock_clone = Arc::clone(&mock);
        handles.push(tokio::spawn(async move {
            let interaction = make_test_interaction(&format!("task_{task_idx}"));
            // Attempt 10 classifications per task
            for _ in 0..10 {
                let _ = mock_clone.classify(&interaction).await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }));
    }

    // Controller task toggles error state on and off
    let mock_controller = Arc::clone(&mock);
    let controller = tokio::spawn(async move {
        for _ in 0..5 {
            mock_controller.set_error(Some("injected synthetic outage"));
            tokio::time::sleep(Duration::from_millis(2)).await;
            mock_controller.set_error(None::<String>);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    for handle in handles {
        handle.await.unwrap();
    }
    controller.await.unwrap();

    // After clearing error, verify normal classification succeeds
    mock.set_error(None::<String>);
    let interaction = make_test_interaction("post-test verification");
    let result = mock.classify(&interaction).await;
    assert!(result.is_ok());
}
