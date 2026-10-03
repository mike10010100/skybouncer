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

    let enable_heuristic = std::env::var("ENABLE_HEURISTIC_PREFILTER")
        .or_else(|_| std::env::var("SKYBOUNCER_ENABLE_HEURISTIC_PREFILTER"))
        .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
        .unwrap_or(false);

    let heuristic = if enable_heuristic {
        println!("   • Heuristic: ENABLED (Regex fast-path)");
        HeuristicClassifier::default()
    } else {
        println!("   • Heuristic: DISABLED by default (Routing all candidates to Jev model to prevent homonym false positives)");
        HeuristicClassifier::empty()
    };
    println!();

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
            name: "Live Crypto Wallet Drainer Scam",
            author_did: "did:plc:c76k5igcucs5dmqzcr76l4uo", // @bonksol.bsky.social
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:c76k5igcucs5dmqzcr76l4uo/app.bsky.feed.post/3mufmzl5tc52g",
            parent_uri: None,
            text: "Stop scrolling. Start claiming! 🪂✨ Claim your free #$BONK Airdrop before snapshot. 🚀 Open site 🔗 http://dropsol.solstudio.cc Connect wallet & claim! Repost = +100 luck 🔁 #Airdrop #Crypto #Web3",
            expected_violation: true,
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
            name: "WhatsApp Off-Platform Funnel Lure",
            author_did: "did:plc:ti6i4s7vumeom5jf7mfqfaam", // @nourishworkplce.bsky.social
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:ti6i4s7vumeom5jf7mfqfaam/app.bsky.feed.post/3mfqq3adtbk26",
            parent_uri: None,
            text: "Please let them know that they can get free advice from me in my WhatApp community https://chat.whatsapp.com/DhR3PkAmbSP6akJv7qoUHe and free resources through this link https://wa.me/+441634479932?text=resource",
            expected_violation: true,
        },
        TestCase {
            name: "Mass-Mention Livestream Promo Spam",
            author_did: "did:plc:jn3dh5dtzbjjeppzjy4zeiam", // @bobby-slacks.bsky.social
            target_did: "did:plc:4llrhdclvdlmmynkwsmg5tdc",  // @atrupar.com
            interaction_type: InteractionType::Mention,
            post_uri: "at://did:plc:jn3dh5dtzbjjeppzjy4zeiam/app.bsky.feed.post/3mwvyjumdkc27",
            parent_uri: None,
            text: "https://www.youtube.com/live/4R5WH95ceQo ❤️💙💛 @halsparks.com @mariamilito.bsky.social @bostonbrian.com @mrtommycampbell.bsky.social @aoc.bsky.social @atrupar.com @adamkinzinger.substack.com",
            expected_violation: true,
        },
        TestCase {
            name: "Self-Promotional Plug on Viral Post",
            author_did: "did:plc:zzyx3v5srvxzmhldfc2zeff2", // @motochop.bsky.social
            target_did: "did:plc:2q2hs5o42jhbd23pp6lkiauh",  // @petebuttigieg.bsky.social
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:zzyx3v5srvxzmhldfc2zeff2/app.bsky.feed.post/3lhtmtl2zsc25",
            parent_uri: Some("at://did:plc:2q2hs5o42jhbd23pp6lkiauh/app.bsky.feed.post/3lhtdtw23m22m"),
            text: "Hey Pete! Check out my new sound! https://www.soundclick.com/share.cfm?id=14940959",
            expected_violation: true,
        },
        TestCase {
            name: "Follower-Begging Churn Spam",
            author_did: "did:plc:zymhvskkinx462d3jjulfnt3", // @putmygamefaceon.bsky.social
            target_did: "did:plc:2q2hs5o42jhbd23pp6lkiauh",  // @petebuttigieg.bsky.social
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:zymhvskkinx462d3jjulfnt3/app.bsky.feed.post/3li33ryxbkc22",
            parent_uri: Some("at://did:plc:2q2hs5o42jhbd23pp6lkiauh/app.bsky.feed.post/3lhtdtw23m22m"),
            text: "Can I get a follow back please",
            expected_violation: false, // Low quality, but permitted unless strict rules configured
        },
        TestCase {
            name: "Direct Hostile Attack with Profanity",
            author_did: "did:plc:pvpvu47y3dcx7ufwil6wfacy", // @daggerwashere.bsky.social
            target_did: "did:plc:zwpu5frtr4ieumbbxwt2l2cr",  // @veleda-k.bsky.social
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:pvpvu47y3dcx7ufwil6wfacy/app.bsky.feed.post/3mwwi7xgu622y",
            parent_uri: Some("at://did:plc:zwpu5frtr4ieumbbxwt2l2cr/app.bsky.feed.post/3mwwhrqtz5d2z"),
            text: "Your bigotry 'Only woman can ever be victims' Your dumbass 'I meant my bigotry to sound like everyone else's' Me: 'You're a dumbass. Now fuck off idiot.' Accuracy is important dumbass.",
            expected_violation: true,
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
            name: "Hostile Account Deletion Demand",
            author_did: "did:plc:6q7cexqwvzlmerjccgsaaipx", // @floopjack.com
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:6q7cexqwvzlmerjccgsaaipx/app.bsky.feed.post/3mwwam2bjwk2x",
            parent_uri: None,
            text: "You have absolutely no idea what you're talking about. None. Zero. Delete your account.",
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
            name: "Benign Homonym: Linux Mint OS Discussion",
            author_did: "did:plc:73suvu2txuufcjgpj747lhgi", // @vinylwreckers.com
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:73suvu2txuufcjgpj747lhgi/app.bsky.feed.post/3mwwji77hx226",
            parent_uri: None,
            text: "everything is so slow. going back to Win 10 straight from Linux Mint its like molasses.",
            expected_violation: false,
        },
        TestCase {
            name: "Benign Homonym: Token of Appreciation",
            author_did: "did:plc:ufsoflgrapyqjq7utgb7mni2", // @miaterasu.bsky.social
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:ufsoflgrapyqjq7utgb7mni2/app.bsky.feed.post/3mwppfovn7k23",
            parent_uri: None,
            text: "Thankies and I hope you like my token of appreciation nyaa. Thankies for being my friend nyan",
            expected_violation: false,
        },
        TestCase {
            name: "Benign Homonym: Gas Prices & Inflation",
            author_did: "did:plc:qagpkz53gjkmfgpi3j2wiz2d", // @jjlynch81.bsky.social
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:qagpkz53gjkmfgpi3j2wiz2d/app.bsky.feed.post/3mwwjthxuts22",
            parent_uri: None,
            text: "Midterms are coming: Gas prices, food prices, rent, mortgage rates ALL have risen under GOP. Inflation, unemployment & farm bankruptcies ALL up.",
            expected_violation: false,
        },
        TestCase {
            name: "Benign False Positive Trap: Connect Wallet Critique",
            author_did: "did:plc:mgb3easmxdv452quq7rr2cib", // @perly-io.bsky.social
            target_did: "did:plc:alice_protected",
            interaction_type: InteractionType::DirectReply,
            post_uri: "at://did:plc:mgb3easmxdv452quq7rr2cib/app.bsky.feed.post/3mwuwpwzvdg2e",
            parent_uri: None,
            text: "\"Connect wallet\" asks for two things: the one you wanted, and the one you did not. Paste an address instead. We read the public key, and that is the whole of what we can do.",
            expected_violation: false,
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
    let mut total_count = 0;
    let mut accurate_detections = 0;
    let mut accurate_passes = 0;
    let mut false_positives = 0;
    let mut below_threshold_tolerated = 0;

    for (i, tc) in test_cases.iter().enumerate() {
        total_count += 1;
        println!("Test Vector #{:02}: {}", i + 1, tc.name);
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

        // Display Heuristic Result (if enabled)
        if enable_heuristic {
            match &heuristic_verdict {
                Verdict::Violation {
                    category, reason, ..
                } => {
                    println!(
                        "  [Heuristic ({heuristic_us}µs)]: ⚠️ VIOLATION [{category}] -> {reason}"
                    );
                }
                Verdict::Permitted { .. } => {
                    println!("  [Heuristic ({heuristic_us}µs)]: 🟢 PERMITTED (Pass to LLM)");
                }
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
            Verdict::Permitted { reason, .. } => {
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
                    accurate_detections += 1;
                    println!("     Score: ✅ ACCURATE DETECTION");
                } else {
                    false_positives += 1;
                    println!("     Score: ❌ FALSE POSITIVE (Caught by {evaluator_name})");
                }
            }
            Verdict::Permitted { .. } => {
                println!(
                    "  => Pipeline Verdict: PERMITTED via {evaluator_name} -> ALLOW (Zero Action)"
                );
                if !tc.expected_violation {
                    accurate_passes += 1;
                    println!("     Score: ✅ ACCURATE BENIGN PASS");
                } else {
                    below_threshold_tolerated += 1;
                    println!(
                        "     Score: ℹ️ TOLERATED / MISSED (Below Medium Sensitivity Threshold)"
                    );
                }
            }
        }

        println!("{:-<80}", "");
    }

    println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                       BENCHMARK SCORECARD SUMMARY                            ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Total Real Vectors Tested:      {total_count:<43} ║");
    println!("║  Accurate Spam/Abuse Bounces:    {accurate_detections:<43} ║");
    println!("║  Accurate Benign Passes:         {accurate_passes:<43} ║");
    println!("║  Borderline / Tolerated:         {below_threshold_tolerated:<43} ║");
    println!("║  False Positives:                {false_positives:<43} ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    Ok(())
}
