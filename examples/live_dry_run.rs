//! Live Dry-Run Demonstration evaluating real Bluesky posts via live Jev Decision Gateway.

use std::sync::Arc;
use std::time::Instant;

use skybouncer::classifier::{
    Classifier, HeuristicClassifier, JevClassifier, JevConfig, RuleRubric, Sensitivity, Verdict,
};
use skybouncer::enricher::{AppViewContextEnricher, ContextEnricher};
use skybouncer::matcher::{Interaction, InteractionType};

struct TestCase {
    name: &'static str,
    author_did: &'static str,
    target_did: &'static str,
    interaction_type: InteractionType,
    post_uri: &'static str,
    parent_uri: Option<&'static str>,
    text: &'static str,
    expected_violation: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║   🛡️  SKYBOUNCER LIVE DRY-RUN BENCHMARK (Real Bluesky Posts & Live Jev)      ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    let jev_endpoint = std::env::var("JEV_API_BASE_URL")
        .unwrap_or_else(|_| "http://nmo.purdlauski.net:8000".to_string());
    let jev_model = std::env::var("JEV_MODEL").unwrap_or_else(|_| "tev1".to_string());

    println!("📡 Connecting to Live Evaluator:");
    println!("   • Endpoint: {jev_endpoint}");
    println!("   • Model:    {jev_model}");

    let rubric = RuleRubric::new(
        "Block crypto airdrop spam, scam bots, phishing, targeted harassment, and bad-faith sea-lioning.",
        Sensitivity::Medium,
    );
    println!("   • Rubric:   \"{}\"", rubric.prompt);
    println!(
        "   • Sensitivity: {} (Threshold: {:.2})\n",
        rubric.sensitivity,
        rubric.sensitivity.threshold()
    );

    let jev_config = JevConfig {
        base_url: jev_endpoint,
        api_key: None,
        model: jev_model,
        timeout: std::time::Duration::from_secs(10),
        max_retries: 1,
    };

    let heuristic = HeuristicClassifier::default();
    let jev = JevClassifier::new(jev_config, rubric.clone())?;
    let enricher = Arc::new(AppViewContextEnricher::new());

    let test_cases = [
        TestCase {
            name: "Live Crypto / Telegram Airdrop Spam",
            author_did: "did:plc:j6e4fasbotyd47igvri32w4m", // @financehit.bsky.social
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:j6e4fasbotyd47igvri32w4m/app.bsky.feed.post/3mwvi4essppvv",
            parent_uri: None,
            text: "Retik Finance has a total supply of 100 million tokens. The distribution strategy includes a public sale, a presale, and an airdrop of pre-mined tokens. https://t.me/simpledb",
            expected_violation: true,
        },
        TestCase {
            name: "Benign Homonym: Military Defense Airdrop",
            author_did: "did:plc:e3adubyxy7pfj44s3dyyrv5x", // @sambendett.bsky.social
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:e3adubyxy7pfj44s3dyyrv5x/app.bsky.feed.post/3mwvyojctz22g",
            parent_uri: None,
            text: "The airdrop was carried out from 600 m. Upon landing, the UGVs began executing combat training missions, including delivering ammunition and supplies, evacuating the wounded...",
            expected_violation: false,
        },
        TestCase {
            name: "Benign Homonym: Apple Tech AirDrop Settings",
            author_did: "did:plc:fd4sw7sbdl7vdkdgynujpmgx", // @chriswalker.scot
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:fd4sw7sbdl7vdkdgynujpmgx/app.bsky.feed.post/3mwvqrjck5ucb",
            parent_uri: None,
            text: "It would be nice to be able to configure the secure link defaults. It already takes so many taps to airdrop a secure link, it would be great to reduce it a bit.",
            expected_violation: false,
        },
        TestCase {
            name: "Spam Link / Discord Quiz Airdrop",
            author_did: "did:plc:abbgh6wiuz6aad32mdzjbllx", // @questgecko.bsky.social
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:abbgh6wiuz6aad32mdzjbllx/app.bsky.feed.post/3mww6wjp4722q",
            parent_uri: None,
            text: "Join ACI Airdrop Quiz💲 Explore: https://discord.gg/PSs8QzM7JU ➞ Accept Invite ➞ Unverified ➞( Verify )",
            expected_violation: true,
        },
        TestCase {
            name: "Hostile Political Reply (Third-Party Target Context)",
            author_did: "did:plc:ztnfoowoyrujkme7p5jy5fyi", // @leftaz.bsky.social
            target_did: "did:plc:4llrhdclvdlmmynkwsmg5tdc",  // @atrupar.com
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:ztnfoowoyrujkme7p5jy5fyi/app.bsky.feed.post/3mwrhhecgpk2h",
            parent_uri: Some("at://did:plc:4llrhdclvdlmmynkwsmg5tdc/app.bsky.feed.post/3mwr4mvz23y23"),
            text: "WTF is he going on about? A severely mentally ill individual who is dangerously insane and an audience for delirium!",
            expected_violation: false, // Political criticism of clip subject, not harassment of author
        },
        TestCase {
            name: "Direct Hostile Personal Attack on User",
            author_did: "did:plc:vs3kdkoqu4tznuvirws7smpf", // @katwalably.bsky.social
            target_did: "did:plc:6imm5sbdbablknpzu4xgq4xd",  // @ruralfreedomnet.bsky.social
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:vs3kdkoqu4tznuvirws7smpf/app.bsky.feed.post/3mwva4puog22y",
            parent_uri: Some("at://did:plc:6imm5sbdbablknpzu4xgq4xd/app.bsky.feed.post/3mwv7zlld722t"),
            text: "Shut up, you idiot, I would say that about you",
            expected_violation: true,
        },
        TestCase {
            name: "Benign Welcoming Reply to Pete Buttigieg",
            author_did: "did:plc:zzwwkmywxcg7q6ybegvirmad", // @wendymichelle.bsky.social
            target_did: "did:plc:2q2hs5o42jhbd23pp6lkiauh",  // @petebuttigieg.bsky.social
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:zzwwkmywxcg7q6ybegvirmad/app.bsky.feed.post/3lhtin47oqs2r",
            parent_uri: Some("at://did:plc:2q2hs5o42jhbd23pp6lkiauh/app.bsky.feed.post/3lhtdtw23m22m"),
            text: "Welcome Pete! The sky just got a little bluer here!",
            expected_violation: false,
        },
    ];

    println!("{:-<80}", "");
    for (i, tc) in test_cases.iter().enumerate() {
        println!("Test #{}: {}", i + 1, tc.name);
        println!("  Text: \"{}\"", tc.text);

        let mut interaction = Interaction::new(
            tc.author_did,
            tc.target_did,
            tc.interaction_type,
            tc.post_uri,
            "bafy_test_cid",
            tc.text,
        );

        if let Some(parent) = tc.parent_uri {
            interaction = interaction.with_parent_uri(parent);
        }

        // 1. Context Enrichment
        let t0 = Instant::now();
        let enriched = enricher.enrich(&interaction).await;
        let enrich_ms = t0.elapsed().as_millis();
        if !enriched.is_empty() {
            println!(
                "  [Context Enricher ({}ms)]: {}",
                enrich_ms,
                enriched.format_for_classifier().replace('\n', " | ")
            );
            interaction = interaction.with_enriched_context(enriched);
        }

        // 2. Heuristic Pre-Filter
        let t1 = Instant::now();
        let heuristic_verdict = heuristic.evaluate(&interaction);
        let heuristic_us = t1.elapsed().as_micros();

        // 3. Live Model Evaluation (System-One Jev)
        let t2 = Instant::now();
        let model_verdict = jev.classify(&interaction).await?;
        let model_ms = t2.elapsed().as_millis();

        // Display Heuristic Result
        match &heuristic_verdict {
            Verdict::Violation {
                category, reason, ..
            } => {
                println!("  [Heuristic ({heuristic_us}µs)]: ⚠️ VIOLATION [{category}] -> {reason}");
            }
            Verdict::Permitted { .. } => {
                println!("  [Heuristic ({heuristic_us}µs)]: 🟢 PERMITTED (Pass to LLM)");
            }
        }

        // Display Model Result
        match &model_verdict {
            Verdict::Violation {
                category,
                confidence,
                reason,
            } => {
                let meets = rubric.meets_threshold(category, *confidence);
                let flag = if meets {
                    "🚨 VIOLATION"
                } else {
                    "⚠️ BELOW THRESHOLD"
                };
                println!(
                    "  [Live Jev   ({model_ms}ms)]: {flag} [{category}] ({:.1}%) -> {reason}",
                    confidence * 100.0
                );
            }
            Verdict::Permitted { reason } => {
                println!("  [Live Jev   ({model_ms}ms)]: 🟢 PERMITTED -> {reason}");
            }
        }

        // Combined Pipeline Verdict: Heuristic fast-path short-circuits to Bounce, else Model verdict
        let (pipeline_verdict, evaluator_name) = if heuristic_verdict.is_violation() {
            (heuristic_verdict, "Heuristic Fast-Path")
        } else {
            (model_verdict.clone(), "Live Jev Gateway")
        };

        match pipeline_verdict {
            Verdict::Violation {
                category,
                confidence,
                reason: _,
            } => {
                let action = if rubric.meets_threshold(&category, confidence) {
                    "🚨 BOUNCE (Add to PDS Modlist)"
                } else {
                    "⚠️ BELOW THRESHOLD (Tolerated)"
                };
                println!("  => Pipeline Verdict: VIOLATION [{category}] via {evaluator_name} -> {action}");
                if tc.expected_violation {
                    println!("     Score: ✅ ACCURATE DETECTION");
                } else {
                    println!("     Score: ❌ FALSE POSITIVE (Caught by {evaluator_name})");
                }
            }
            Verdict::Permitted { reason: _ } => {
                println!(
                    "  => Pipeline Verdict: PERMITTED via {evaluator_name} -> ALLOW (Zero Action)"
                );
                if !tc.expected_violation {
                    println!("     Score: ✅ ACCURATE BENIGN PASS");
                } else {
                    println!("     Score: ❌ MISSED VIOLATION");
                }
            }
        }

        println!("{:-<80}", "");
    }

    println!("\n🎉 Dry-run evaluation completed successfully against live infrastructure!");
    Ok(())
}
