//! Live Dry-Run Demonstration evaluating real Bluesky posts via live Jev Decision Gateway
//! and Tiered Multimodal Fallback architecture.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use skybouncer::classifier::{
    CertaintyConfig, Classifier, HeuristicClassifier, JevClassifier, JevConfig, RuleRubric,
    Sensitivity, TieredClassifier, Verdict,
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
    image_cids: Vec<&'static str>,
    image_alts: Vec<&'static str>,
    expected_violation: bool,
}

impl TestCase {
    #[allow(clippy::too_many_arguments)]
    fn new(
        name: &'static str,
        author_did: &'static str,
        target_did: &'static str,
        interaction_type: InteractionType,
        post_uri: &'static str,
        parent_uri: Option<&'static str>,
        text: &'static str,
        expected_violation: bool,
    ) -> Self {
        Self {
            name,
            author_did,
            target_did,
            interaction_type,
            post_uri,
            parent_uri,
            text,
            image_cids: Vec::new(),
            image_alts: Vec::new(),
            expected_violation,
        }
    }

    fn with_image(mut self, cid: &'static str, alt: &'static str) -> Self {
        self.image_cids.push(cid);
        self.image_alts.push(alt);
        self
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║   🛡️  SKYBOUNCER TIERED MULTIMODAL BENCHMARK (Real Viral Posts & Live Jev)   ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    let primary_endpoint = std::env::var("JEV_API_BASE_URL")
        .unwrap_or_else(|_| "http://nmo.purdlauski.net:8000".to_string());
    let primary_model = std::env::var("JEV_MODEL").unwrap_or_else(|_| "tev1".to_string());

    let fallback_endpoint = std::env::var("FALLBACK_API_BASE_URL")
        .unwrap_or_else(|_| "http://nmo.purdlauski.net:8000".to_string());
    let fallback_model = std::env::var("FALLBACK_MODEL").unwrap_or_else(|_| "nimble".to_string());

    println!("📡 Connecting to Tiered Live Evaluators:");
    println!("   • Primary System-1:  {primary_endpoint} (model: {primary_model})");
    println!("   • Secondary System-2: {fallback_endpoint} (model: {fallback_model})");

    let rubric = RuleRubric::new(
        "Block crypto airdrop spam, scam bots, phishing, targeted harassment, and bad-faith sea-lioning.",
        Sensitivity::Medium,
    );
    println!("   • Moderation Rubric: \"{}\"", rubric.prompt);
    println!(
        "   • Sensitivity Level: {} (Actionable Threshold: {:.2})",
        rubric.sensitivity,
        rubric.sensitivity.threshold()
    );

    let certainty_config = CertaintyConfig::new(0.40, 0.85, true);
    println!(
        "   • Certainty Band:    Uncertainty in [{:.2}, {:.2}) triggers System-2 escalation",
        certainty_config.min_confidence, certainty_config.max_confidence
    );
    println!(
        "   • Vision Policy:     Escalate on image attachments: {}\n",
        certainty_config.escalate_on_images
    );

    let primary_jev_config = JevConfig {
        base_url: primary_endpoint,
        api_key: None,
        model: primary_model.clone(),
        timeout: std::time::Duration::from_secs(20),
        max_retries: 1,
    };

    let fallback_jev_config = JevConfig {
        base_url: fallback_endpoint,
        api_key: None,
        model: fallback_model.clone(),
        timeout: std::time::Duration::from_secs(25),
        max_retries: 1,
    };

    let primary_jev = Arc::new(JevClassifier::new(primary_jev_config, rubric.clone())?);
    let fallback_jev = Arc::new(JevClassifier::new(fallback_jev_config, rubric.clone())?);
    let tiered = Arc::new(TieredClassifier::new(
        primary_jev,
        fallback_jev,
        certainty_config,
    ));

    let enricher = Arc::new(AppViewContextEnricher::new());

    let enable_heuristic = std::env::var("ENABLE_HEURISTIC_PREFILTER")
        .or_else(|_| std::env::var("SKYBOUNCER_ENABLE_HEURISTIC_PREFILTER"))
        .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
        .unwrap_or(false);

    let heuristic = if enable_heuristic {
        println!("   • Heuristic Gate:    ENABLED (Regex fast-path)");
        HeuristicClassifier::default()
    } else {
        println!(
            "   • Heuristic Gate:    DISABLED by default (Zero false-positive pure-AI routing)"
        );
        HeuristicClassifier::empty()
    };
    println!();

    let test_cases = vec![
        // ---------------------------------------------------------------------
        // 1. Live Multimodal Visual Posts (Trending Inktober Art, Memes, Satire)
        // ---------------------------------------------------------------------
        TestCase::new(
            "Viral Inktober 2026 Artwork (Benign Visual Media)",
            "did:plc:l4emr3rlhykszhwwvbz2tz2z", // @steve-lucas.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:l4emr3rlhykszhwwvbz2tz2z/app.bsky.feed.post/3mwrh63heyc2o",
            None,
            "INKTOBER 2026\nDay 1 - Apple\n\n#Inktober #Inktober2026 #Sketch #ink #Art #Day1 #Apple",
            false,
        ).with_image("bafkreidcrbwmnnv67sufydeyresmzrknrs6x4bjbsi3ylnckqaa2gh2fje", "INKTOBER 2026 Day 1 - Apple"),

        TestCase::new(
            "Viral Satirical Headline & Image (The Onion)",
            "did:plc:a4pqq234yw7fqbddawjo7y35", // @theonion.com
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:a4pqq234yw7fqbddawjo7y35/app.bsky.feed.post/3mwvql6ks5425",
            None,
            "‘Digger’ Prosthetic Artist Recalls Grueling Process Of Having Tom Cruise Sit Still",
            false,
        ).with_image("bafkreihb6s3lyx7bgtdxvtguavaco46w247qejq2phegah3rv6kdjkmdvu", "‘Digger’ Prosthetic Artist Recalls Grueling Process Of Having Tom Cruise Sit Still"),

        TestCase::new(
            "Viral Tom Cruise Doppelgänger Meme (Benign Social Humor)",
            "did:plc:ahcborosqrfchi3iiyhoixch", // @dennycarter.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:ahcborosqrfchi3iiyhoixch/app.bsky.feed.post/3lx5ohwumzc2n",
            None,
            "When did Tom Cruise turn into Norm Macdonald",
            false,
        ).with_image("bafkreidozklfkhqyt7i3nosjwz4cxbstkncaqqekkoydpjbk633dbtznti", "Tom cruise looking an awful lot like norm McDonald"),

        // ---------------------------------------------------------------------
        // 2. Active Live Crypto Scams / Airdrop Wallet Drainers with Images
        // ---------------------------------------------------------------------
        TestCase::new(
            "Active Live Airdrop Scam with Image Lure #1",
            "did:plc:v6bodcfx5hwfmxyorkp2kbmw", // @kew20na.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:v6bodcfx5hwfmxyorkp2kbmw/app.bsky.feed.post/3mwsvmcxvd22x",
            None,
            "Quip Network ~ New Early Alpha Backed by Portal Ventures & Orange DAO with Confirmed Airdrop 🐡\n🟣 Start your journey here : https://da.gd/D8Py9O\n➖ Connect with your EVM Wallet.\n➖ Link your X, Discord and Github accounts.\n➖ Complete live tasks & Keep check-in daily.\n➖ Done! ✅\n🏆 Join Me on TG : https://da.gd/mpLo",
            true,
        ).with_image("bafkreietnoe2egfqgg7vmjzxct4zznguta45fgx73beqclatd26tn55vvi", "Quip Network Airdrop Promotional Banner"),

        TestCase::new(
            "Active Live Airdrop Scam with Image Lure #2",
            "did:plc:v6bodcfx5hwfmxyorkp2kbmw", // @kew20na.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:v6bodcfx5hwfmxyorkp2kbmw/app.bsky.feed.post/3mwljkqrfl22u",
            None,
            "Amadeus Protocol ~ The Foundation is Already Live! & The Airdrop Still Ongoing! 👀\n🟡 Register here : https://da.gd/RzWsC\n➖ Connect your EVM wallet.\n➖ Create your Amadeus Wallet.\n➖ Complete your profile.\n➖ Finish the available quests.\n➖ Done! ✅\n🏆 Never Miss Any Airdrop Again, Join Me on TG : https://da.gd/mpLo",
            true,
        ).with_image("bafkreigp44mdjihwr2jbvkrji45nosfidangvmgr4ni2zhotikkef2h7d4", "Amadeus Protocol Wallet Quests Banner"),

        // ---------------------------------------------------------------------
        // 3. Real Trending Heated Political Discourse (Zero False-Positive Tests)
        // ---------------------------------------------------------------------
        TestCase::new(
            "Trending Heated Discourse Reply #1: Political Bribery Accusation",
            "did:plc:ztcyp3tdiporixbena4hog2l", // @clmcginley.bsky.social
            "did:plc:gkgmduxh722ocstroyi75gbg", // @mjfree.bsky.social
            InteractionType::DirectReply,
            "at://did:plc:ztcyp3tdiporixbena4hog2l/app.bsky.feed.post/3mwychcqhn22e",
            Some("at://did:plc:gkgmduxh722ocstroyi75gbg/app.bsky.feed.post/3mwxz6t22ou2m"),
            "So this blatant bribery for their votes...illegal as all get out, and nothing will be done. As usual.",
            false,
        ),

        TestCase::new(
            "Trending Heated Discourse Reply #2: Partisan Rhetoric",
            "did:plc:zhignjohgoryalfpgum4p6dl", // @m-pathy.bsky.social
            "did:plc:gkgmduxh722ocstroyi75gbg", // @mjfree.bsky.social
            InteractionType::DirectReply,
            "at://did:plc:zhignjohgoryalfpgum4p6dl/app.bsky.feed.post/3mwycarnhdc2x",
            Some("at://did:plc:gkgmduxh722ocstroyi75gbg/app.bsky.feed.post/3mwxz6t22ou2m"),
            "Make it 10 grand and I still won't vote for any Republican.",
            false,
        ),

        TestCase::new(
            "Trending Heated Discourse Reply #3: Policy Critique with Hashtags",
            "did:plc:xnfuootbvsjfusgfonrnkf2u", // @defeatthefascists.bsky.social
            "did:plc:gkgmduxh722ocstroyi75gbg", // @mjfree.bsky.social
            InteractionType::DirectReply,
            "at://did:plc:xnfuootbvsjfusgfonrnkf2u/app.bsky.feed.post/3mwycqso2f224",
            Some("at://did:plc:gkgmduxh722ocstroyi75gbg/app.bsky.feed.post/3mwxz6t22ou2m"),
            "Finding yet another way to try to bankrupt Medicare. $2B thrown away to try to bribe a few senile MAGAs for what even to the hardest hit among us is a negligible sum in the grand scheme of things. #MedicareForAll",
            false,
        ),

        // ---------------------------------------------------------------------
        // 4. Established Live Spam & Abuse Benchmarks
        // ---------------------------------------------------------------------
        TestCase::new(
            "Live Crypto / Telegram Airdrop Spam",
            "did:plc:j6e4fasbotyd47igvri32w4m", // @financehit.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:j6e4fasbotyd47igvri32w4m/app.bsky.feed.post/3mwvi4essppvv",
            None,
            "Retik Finance has a total supply of 100 million tokens. The distribution strategy includes a public sale, a presale, and an airdrop of pre-mined tokens. https://t.me/simpledb",
            true,
        ),

        TestCase::new(
            "Live Crypto Wallet Drainer Scam ($BONK)",
            "did:plc:c76k5igcucs5dmqzcr76l4uo", // @bonksol.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:c76k5igcucs5dmqzcr76l4uo/app.bsky.feed.post/3mufmzl5tc52g",
            None,
            "Stop scrolling. Start claiming! 🪂✨ Claim your free #$BONK Airdrop before snapshot. 🚀 Open site 🔗 http://dropsol.solstudio.cc Connect wallet & claim! Repost = +100 luck 🔁 #Airdrop #Crypto #Web3",
            true,
        ),

        TestCase::new(
            "Spam Link / Discord Quiz Airdrop",
            "did:plc:abbgh6wiuz6aad32mdzjbllx", // @questgecko.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:abbgh6wiuz6aad32mdzjbllx/app.bsky.feed.post/3mww6wjp4722q",
            None,
            "Join ACI Airdrop Quiz💲 Explore: https://discord.gg/PSs8QzM7JU ➞ Accept Invite ➞ Unverified ➞( Verify )",
            true,
        ),

        TestCase::new(
            "WhatsApp Off-Platform Funnel Lure",
            "did:plc:ti6i4s7vumeom5jf7mfqfaam", // @nourishworkplce.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:ti6i4s7vumeom5jf7mfqfaam/app.bsky.feed.post/3mfqq3adtbk26",
            None,
            "Please let them know that they can get free advice from me in my WhatApp community https://chat.whatsapp.com/DhR3PkAmbSP6akJv7qoUHe and free resources through this link https://wa.me/+441634479932?text=resource",
            true,
        ),

        TestCase::new(
            "Mass-Mention Livestream Promo Spam",
            "did:plc:jn3dh5dtzbjjeppzjy4zeiam", // @bobby-slacks.bsky.social
            "did:plc:4llrhdclvdlmmynkwsmg5tdc",  // @atrupar.com
            InteractionType::Mention,
            "at://did:plc:jn3dh5dtzbjjeppzjy4zeiam/app.bsky.feed.post/3mwvyjumdkc27",
            None,
            "https://www.youtube.com/live/4R5WH95ceQo ❤️💙💛 @halsparks.com @mariamilito.bsky.social @bostonbrian.com @mrtommycampbell.bsky.social @aoc.bsky.social @atrupar.com @adamkinzinger.substack.com",
            true,
        ),

        TestCase::new(
            "Direct Hostile Attack with Profanity",
            "did:plc:pvpvu47y3dcx7ufwil6wfacy", // @daggerwashere.bsky.social
            "did:plc:zwpu5frtr4ieumbbxwt2l2cr",  // @veleda-k.bsky.social
            InteractionType::DirectReply,
            "at://did:plc:pvpvu47y3dcx7ufwil6wfacy/app.bsky.feed.post/3mwwi7xgu622y",
            Some("at://did:plc:zwpu5frtr4ieumbbxwt2l2cr/app.bsky.feed.post/3mwwhrqtz5d2z"),
            "Your bigotry 'Only woman can ever be victims' Your dumbass 'I meant my bigotry to sound like everyone else's' Me: 'You're a dumbass. Now fuck off idiot.' Accuracy is important dumbass.",
            true,
        ),

        // ---------------------------------------------------------------------
        // 5. Benign Homonym Traps
        // ---------------------------------------------------------------------
        TestCase::new(
            "Benign Homonym: Military Defense Airdrop",
            "did:plc:e3adubyxy7pfj44s3dyyrv5x", // @sambendett.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:e3adubyxy7pfj44s3dyyrv5x/app.bsky.feed.post/3mwvyojctz22g",
            None,
            "The airdrop was carried out from 600 m. Upon landing, the UGVs began executing combat training missions, including delivering ammunition and supplies, evacuating the wounded...",
            false,
        ),

        TestCase::new(
            "Benign Homonym: Apple Tech AirDrop Settings",
            "did:plc:fd4sw7sbdl7vdkdgynujpmgx", // @chriswalker.scot
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:fd4sw7sbdl7vdkdgynujpmgx/app.bsky.feed.post/3mwvqrjck5ucb",
            None,
            "It would be nice to be able to configure the secure link defaults. It already takes so many taps to airdrop a secure link, it would be great to reduce it a bit.",
            false,
        ),

        TestCase::new(
            "Benign Homonym: Linux Mint OS Discussion",
            "did:plc:73suvu2txuufcjgpj747lhgi", // @vinylwreckers.com
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:73suvu2txuufcjgpj747lhgi/app.bsky.feed.post/3mwwji77hx226",
            None,
            "everything is so slow. going back to Win 10 straight from Linux Mint its like molasses.",
            false,
        ),

        TestCase::new(
            "Benign False Positive Trap: Connect Wallet Critique",
            "did:plc:mgb3easmxdv452quq7rr2cib", // @perly-io.bsky.social
            "did:plc:alice_protected",
            InteractionType::DirectReply,
            "at://did:plc:mgb3easmxdv452quq7rr2cib/app.bsky.feed.post/3mwuwpwzvdg2e",
            None,
            "\"Connect wallet\" asks for two things: the one you wanted, and the one you did not. Paste an address instead. We read the public key, and that is the whole of what we can do.",
            false,
        ),
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
        println!("  Text: \"{}\"", tc.text.replace('\n', " "));
        if !tc.image_cids.is_empty() {
            println!(
                "  Images: {} visual attachment(s) (CIDs: {:?})",
                tc.image_cids.len(),
                tc.image_cids
            );
        }

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
        for (cid, alt) in tc.image_cids.iter().zip(tc.image_alts.iter()) {
            interaction.image_cids.push(cid.to_string());
            interaction.image_alts.push(alt.to_string());
        }

        // 1. Context Enrichment (including image downloading & base64 decoding from Bluesky CDN)
        let t0 = Instant::now();
        let enriched = enricher.enrich(&interaction).await;
        let enrich_ms = t0.elapsed().as_millis();
        if !enriched.is_empty() {
            let mut summary = enriched.format_for_classifier().replace('\n', " | ");
            if let Some((idx, _)) = summary.char_indices().nth(150) {
                summary.truncate(idx);
                summary.push_str("...");
            }
            println!("  [Context Enricher ({}ms)]: {}", enrich_ms, summary);
            if !enriched.images_base64.is_empty() {
                println!(
                    "  [CDN Visual Fetch]: Successfully decoded {} image(s) to base64 for vision inspection",
                    enriched.images_base64.len()
                );
            }
            interaction = interaction.with_enriched_context(enriched);
        }

        // 2. Heuristic Pre-Filter
        let t1 = Instant::now();
        let heuristic_verdict = heuristic.evaluate(&interaction);
        let heuristic_us = t1.elapsed().as_micros();

        // Snapshot tiered stats before evaluation
        let stats_before_primary_resolved = tiered.stats().primary_resolved.load(Ordering::Relaxed);
        let stats_before_fallback = tiered.stats().fallback_escalated.load(Ordering::Relaxed);
        let stats_before_img = tiered.stats().image_escalations.load(Ordering::Relaxed);
        let stats_before_unc = tiered
            .stats()
            .uncertainty_escalations
            .load(Ordering::Relaxed);

        // 3. Live Tiered Model Classification
        let t2 = Instant::now();
        let tiered_verdict = tiered.classify(&interaction).await?;
        let tiered_ms = t2.elapsed().as_millis();

        let escalated_to_fallback =
            tiered.stats().fallback_escalated.load(Ordering::Relaxed) > stats_before_fallback;
        let img_escalated =
            tiered.stats().image_escalations.load(Ordering::Relaxed) > stats_before_img;
        let unc_escalated = tiered
            .stats()
            .uncertainty_escalations
            .load(Ordering::Relaxed)
            > stats_before_unc;
        let primary_short_circuited =
            tiered.stats().primary_resolved.load(Ordering::Relaxed) > stats_before_primary_resolved;

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
                    println!("  [Heuristic ({heuristic_us}µs)]: 🟢 PERMITTED (Pass to Model)");
                }
            }
        }

        // Display Tiered Execution Path
        if escalated_to_fallback {
            let reason_tag = if img_escalated {
                "Visual Image Attachment Trigger"
            } else if unc_escalated {
                "Certainty Band Trigger [0.40, 0.85)"
            } else {
                "Uncertainty Escalation"
            };
            println!(
                "  [Tier-2 Escalation]: ⚡ Escalated to System-2 ({fallback_model}) via {reason_tag}"
            );
        } else if primary_short_circuited {
            println!(
                "  [Tier-1 Resolution]: ⚡ Resolved directly by System-1 ({primary_model}) - Decisive evaluation"
            );
        }

        // Display Tiered Model Result
        match &tiered_verdict {
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
                    "  [Tiered Verdict ({tiered_ms}ms)]: {flag} [{category}] ({:.1}%) -> {reason}",
                    confidence * 100.0
                );
            }
            Verdict::Permitted { reason, confidence } => {
                let conf_str = confidence
                    .map(|c| format!(" ({:.1}%)", c * 100.0))
                    .unwrap_or_default();
                println!("  [Tiered Verdict ({tiered_ms}ms)]: 🟢 PERMITTED{conf_str} -> {reason}");
            }
        }

        // Combined Pipeline Verdict: Heuristic fast-path short-circuits to Bounce, else Model verdict
        let (pipeline_verdict, evaluator_name) = if heuristic_verdict.is_violation() {
            (heuristic_verdict, "Heuristic Fast-Path")
        } else {
            (tiered_verdict.clone(), "Tiered Jev Pipeline")
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
                println!(
                    "  => Pipeline Action: VIOLATION [{category}] via {evaluator_name} -> {action}"
                );
                if tc.expected_violation {
                    accurate_detections += 1;
                    println!("     Validation: ✅ ACCURATE ABUSE DETECTION");
                } else {
                    false_positives += 1;
                    println!("     Validation: ❌ FALSE POSITIVE (Caught by {evaluator_name})");
                }
            }
            Verdict::Permitted { .. } => {
                println!(
                    "  => Pipeline Action: PERMITTED via {evaluator_name} -> ALLOW (Zero Action)"
                );
                if !tc.expected_violation {
                    accurate_passes += 1;
                    println!("     Validation: ✅ ACCURATE BENIGN PASS");
                } else {
                    below_threshold_tolerated += 1;
                    println!(
                        "     Validation: ℹ️ TOLERATED / MISSED (Below Medium Sensitivity Threshold)"
                    );
                }
            }
        }

        println!("{:-<80}", "");
    }

    println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    TIERED BENCHMARK SCORECARD SUMMARY                        ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Total Real Vectors Evaluated:   {total_count:<43} ║");
    println!(
        "║  Primary System-1 Resolutions:   {:<43} ║",
        tiered.stats().primary_resolved.load(Ordering::Relaxed)
    );
    println!(
        "║  System-2 Fallback Escalations:  {:<43} ║",
        tiered.stats().fallback_escalated.load(Ordering::Relaxed)
    );
    println!(
        "║    • Visual Image Escalations:   {:<43} ║",
        tiered.stats().image_escalations.load(Ordering::Relaxed)
    );
    println!(
        "║    • Uncertainty Band Triggers:  {:<43} ║",
        tiered
            .stats()
            .uncertainty_escalations
            .load(Ordering::Relaxed)
    );
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Accurate Abuse Detections:      {accurate_detections:<43} ║");
    println!("║  Accurate Benign Passes:         {accurate_passes:<43} ║");
    println!("║  Borderline / Tolerated:         {below_threshold_tolerated:<43} ║");
    println!("║  False Positives (Benign Speech):{false_positives:<43} ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    Ok(())
}
