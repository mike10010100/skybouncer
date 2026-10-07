//! Live/experimental benchmark: does thread context or a dynamic multimodal Tier-1
//! primary improve bouncer decisions?
//!
//! Replays the curated proven vectors in `examples/fixtures/curated_vectors.json`
//! (with real AT-URIs) and the captured live logs in
//! `examples/fixtures/context_replay.json`.
//!
//! Part 1 (context): re-fetches each candidate's full ancestor chain via the public
//! AppView and compares a `nimble` System-1 pass with immediate-parent-only context
//! against the full conversation thread.
//!
//! Part 2 (dynamic primary): for image-bearing vectors, compares the production
//! tiered path (`nimble` text primary + `gemma4:12b` vision fallback) with a
//! `clef-flash` multimodal Tier-1 primary.
//!
//! Run with live endpoints (default) or replay-only via `EXPERIMENT_OFFLINE=1`.

use std::sync::Arc;
use std::time::Instant;

use skybouncer::classifier::{
    CertaintyConfig, Classifier, DynamicModelPolicy, DynamicPrimaryClassifier, JevClassifier,
    JevConfig, RuleRubric, Sensitivity, TieredClassifier, Verdict,
};
use skybouncer::enricher::{AppViewContextEnricher, EnrichedContext, ParentPostContext};
use skybouncer::matcher::{Interaction, InteractionType};

const CURATED_FIXTURE: &str = include_str!("fixtures/curated_vectors.json");
const REPLAY_FIXTURE: &str = include_str!("fixtures/context_replay.json");
const HARD_FIXTURE: &str = include_str!("fixtures/hard_threads.json");
const HARD_IMAGES_FIXTURE: &str = include_str!("fixtures/hard_images.json");

#[derive(serde::Deserialize)]
struct HardImages {
    cases: Vec<ImageCase>,
}

#[derive(serde::Deserialize)]
struct ImageCase {
    name: String,
    text: String,
    image: String,
    expected_violation: bool,
    note: String,
}

#[derive(serde::Deserialize)]
struct HardThreads {
    cases: Vec<HardCase>,
}

#[derive(serde::Deserialize)]
struct HardCase {
    name: String,
    author_did: String,
    target_did: String,
    #[serde(default)]
    ancestors: Vec<HardPost>,
    candidate_text: String,
    expected_violation: bool,
    note: String,
}

#[derive(serde::Deserialize)]
struct HardPost {
    author_did: String,
    text: String,
}

#[derive(serde::Deserialize)]
struct CuratedVectors {
    vectors: Vec<CuratedVector>,
}

#[derive(serde::Deserialize)]
struct CuratedVector {
    name: String,
    author_did: String,
    target_did: String,
    post_uri: String,
    text: String,
    #[serde(default)]
    image_cids: Vec<String>,
    expected_violation: bool,
}

#[derive(serde::Deserialize)]
struct ReplayFixture {
    count: usize,
    cases: Vec<ReplayCase>,
}

#[derive(serde::Deserialize)]
struct ReplayCase {
    source: String,
    has_images: bool,
    baseline: ReplayBaseline,
}

#[derive(serde::Deserialize)]
struct ReplayBaseline {
    final_action: String,
}

fn primary_config(model: &str) -> JevConfig {
    JevConfig {
        base_url: std::env::var("JEV_API_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string()),
        api_key: None,
        model: model.to_string(),
        timeout: std::time::Duration::from_secs(30),
        max_retries: 1,
        supports_images: false,
    }
}

fn multimodal_config(model: &str) -> JevConfig {
    JevConfig {
        supports_images: true,
        ..primary_config(model)
    }
}

fn ollama_config(model: &str) -> JevConfig {
    JevConfig {
        base_url: std::env::var("FALLBACK_API_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:11434".to_string()),
        model: model.to_string(),
        // Generous timeout so heavyweight Level-2 models can cold-load under churn.
        timeout: std::time::Duration::from_secs(300),
        supports_images: false,
        ..primary_config(model)
    }
}

fn is_violation(v: &Verdict) -> bool {
    v.is_violation()
}

fn base_interaction(v: &CuratedVector) -> Interaction {
    let mut i = Interaction::new(
        &v.author_did,
        &v.target_did,
        InteractionType::DirectReply,
        &v.post_uri,
        "bafyexperimentcid",
        &v.text,
    );
    let cids = v.image_cids.clone();
    i.image_cids = cids.clone();
    i.image_alts = cids.iter().map(|_| String::new()).collect();
    i
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let offline = std::env::var("EXPERIMENT_OFFLINE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let curated: CuratedVectors = serde_json::from_str(CURATED_FIXTURE)?;
    let replay: ReplayFixture = serde_json::from_str(REPLAY_FIXTURE)?;
    let hard: HardThreads = serde_json::from_str(HARD_FIXTURE)?;
    let hard_images: HardImages = serde_json::from_str(HARD_IMAGES_FIXTURE)?;

    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║  SKYBOUNCER EXPERIMENT: THREAD CONTEXT & DYNAMIC MULTIMODAL TIER-1 PRIMARY   ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!("  Curated labeled vectors: {}", curated.vectors.len());
    let live = replay.cases.iter().filter(|c| c.source == "live").count();
    let violations = replay
        .cases
        .iter()
        .filter(|c| c.baseline.final_action == "violation")
        .count();
    println!(
        "  Captured live replay cases: {} ({} live, {} baseline violations, {} with images)",
        replay.count,
        live,
        violations,
        replay.cases.iter().filter(|c| c.has_images).count()
    );

    if offline {
        println!("\n[OFFLINE] Fixtures loaded; skipping live endpoint calls.");
        return Ok(());
    }

    let enricher = AppViewContextEnricher::new();
    let rubric = RuleRubric::new(
        "Block crypto airdrop spam, scam bots, phishing, targeted harassment, and bad-faith sea-lioning.",
        Sensitivity::Medium,
    );

    let part = std::env::var("EXPERIMENT_PART").unwrap_or_else(|_| "both".to_string());
    let run = |name: &str| part == "both" || part == name;
    if run("1") {
        run_context_experiment(&curated, &enricher, &rubric).await?;
    }
    if run("hard") {
        run_hard_thread_experiment(&hard, &rubric).await?;
    }
    if run("2") {
        run_dynamic_primary_experiment(&curated, &enricher, &rubric).await?;
    }
    if run("l2") {
        run_hard_thread_l2_experiment(&hard, &rubric).await?;
    }
    if run("images") {
        run_hard_image_experiment(&hard_images, &rubric).await?;
    }

    Ok(())
}

/// Hard image corpus: image-borne violations with innocuous captions, plus
/// regression guards (benign images with alarming text, benign/benign control).
/// Compares text-only L1 (`nimble`, images invisible) against multimodal L1
/// (`clef-flash`) and the heavyweight L2 fallback (`gemma4:12b`).
async fn run_hard_image_experiment(
    hard: &HardImages,
    rubric: &RuleRubric,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{:=<80}", "");
    println!("PART 4  HARD IMAGES: text-only L1 vs multimodal L1 vs L2 fallback");
    println!("{:=<80}", "");

    let text_l1 = JevClassifier::new(primary_config("nimble"), rubric.clone())?;
    let mm_model = std::env::var("MULTIMODAL_MODEL").unwrap_or_else(|_| "clef-flash".to_string());
    let mm_l1 = JevClassifier::new(multimodal_config(&mm_model), rubric.clone())?;
    let l2_model =
        std::env::var("EXPERIMENT_L2_MODEL").unwrap_or_else(|_| "gemma4:12b".to_string());
    let l2 = JevClassifier::new(ollama_config(&l2_model), rubric.clone())?;

    println!("  Text-only L1: nimble | Multimodal L1: {mm_model} | L2: {l2_model}");
    println!(
        "  {:<32} {:<5} {:<18} {:<18} {:<18}",
        "case", "want", "text-only(nimble)", "multimodal L1", "L2 reasoner"
    );
    println!("  {:-<95}", "");

    let mut text_correct = 0usize;
    let mut mm_correct = 0usize;
    let mut l2_correct = 0usize;
    let mut total = 0usize;
    let mut text_missed_violations = 0usize;
    let mut mm_latency = 0u128;
    let mut l2_latency = 0u128;

    for c in &hard.cases {
        total += 1;
        let path = format!("examples/fixtures/images/{}", c.image);
        let raw = std::fs::read(&path)?;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);

        let mut interaction = Interaction::new(
            "did:plc:img-author",
            "did:plc:img-target",
            InteractionType::DirectReply,
            format!("at://did:plc:img-author/app.bsky.feed.post/{}", c.name),
            "bafyimgcid",
            &c.text,
        );
        interaction.image_cids = vec!["imgcid".to_string()];

        // Text-only L1: images are not forwarded (nimble can't accept them).
        let text_v = text_l1.classify(&interaction).await?;

        // Multimodal L1 and L2 both receive the decoded image.
        let mut ctx = EnrichedContext::empty();
        ctx.images_base64 = vec![b64.clone()];
        let with_img = interaction.clone().with_enriched_context(ctx);

        let t0 = Instant::now();
        let mm_v = mm_l1.classify(&with_img).await?;
        mm_latency += t0.elapsed().as_millis();

        let t1 = Instant::now();
        let l2_v = match l2.classify(&with_img).await {
            Ok(v) => v,
            Err(e) => {
                println!("  {:<32} L2 ERROR: {e}", truncate(&c.name, 32));
                continue;
            }
        };
        l2_latency += t1.elapsed().as_millis();

        let tv = is_violation(&text_v);
        let mv = is_violation(&mm_v);
        let lv = is_violation(&l2_v);
        if tv == c.expected_violation {
            text_correct += 1;
        } else if c.expected_violation && !tv {
            text_missed_violations += 1;
        }
        if mv == c.expected_violation {
            mm_correct += 1;
        }
        if lv == c.expected_violation {
            l2_correct += 1;
        }

        println!(
            "  {:<32} {:<5} {:<18} {:<18} {:<18}",
            truncate(&c.name, 32),
            c.expected_violation,
            format!("{tv} ({:.2})", text_v.confidence().unwrap_or(0.0)),
            format!("{mv} ({:.2})", mm_v.confidence().unwrap_or(0.0)),
            format!("{lv} ({:.2})", l2_v.confidence().unwrap_or(0.0)),
        );
        if tv != c.expected_violation || mv != c.expected_violation || lv != c.expected_violation {
            println!("       note: {}", c.note);
        }
    }

    println!("  {:-<95}", "");
    println!("  Hard image cases:                 {total}");
    println!("  Text-only L1 (nimble) correct:    {text_correct}/{total}  (missed {text_missed_violations} violations)");
    println!("  Multimodal L1 ({mm_model}) correct: {mm_correct}/{total}");
    println!("  L2 ({l2_model}) correct:           {l2_correct}/{total}");
    println!(
        "  Mean latency: multimodal L1 {:.0}ms | L2 {:.0}ms",
        safe_mean(mm_latency, total),
        safe_mean(l2_latency, total)
    );
    Ok(())
}

/// Level-2 (System-2) test: run the hard corpus through a heavyweight reasoning
/// LLM via the Ollama chat endpoint, comparing no-context, parent-only, and full
/// ancestor chains. Hypothesis: larger/thinking models exploit thread context
/// better than the Tier-1 decision classifiers.
async fn run_hard_thread_l2_experiment(
    hard: &HardThreads,
    rubric: &RuleRubric,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{:=<80}", "");
    println!("PART 3  LEVEL-2 SYSTEM-2 (reasoning LLM): no-context vs parent-only vs full chain");
    println!("{:=<80}", "");

    let model = std::env::var("EXPERIMENT_L2_MODEL").unwrap_or_else(|_| "gemma4:12b".to_string());
    println!("  Level-2 model: {model} (Ollama chat)");
    let classifier = JevClassifier::new(ollama_config(&model), rubric.clone())?;

    let mut no_ctx_correct = 0usize;
    let mut parent_correct = 0usize;
    let mut thread_correct = 0usize;
    let mut flips_to_correct = 0usize;
    let mut flips_to_wrong = 0usize;
    let mut total = 0usize;

    for c in &hard.cases {
        total += 1;
        let interaction = Interaction::new(
            &c.author_did,
            &c.target_did,
            InteractionType::DirectReply,
            format!("at://{}/app.bsky.feed.post/l2exp{}", c.author_did, total),
            "bafyl2cid",
            &c.candidate_text,
        );

        let no_ctx = match classifier.classify(&interaction).await {
            Ok(v) => v,
            Err(e) => {
                println!("  {:<30} no-ctx ERROR: {e}", truncate(&c.name, 30));
                continue;
            }
        };

        let parent_ctx = c.ancestors.last().map(|a| {
            let mut ctx = EnrichedContext::empty();
            ctx.parent_post = Some(ParentPostContext {
                author_did: a.author_did.clone(),
                text: a.text.clone(),
                cid: None,
            });
            ctx
        });
        let parent_input = interaction.clone().with_enriched_context_opt(parent_ctx);
        let parent = match classifier.classify(&parent_input).await {
            Ok(v) => v,
            Err(e) => {
                println!("  {:<30} parent ERROR: {e}", truncate(&c.name, 30));
                continue;
            }
        };

        let mut thread_ctx = EnrichedContext::empty();
        thread_ctx.thread_ancestors = c
            .ancestors
            .iter()
            .map(|a| skybouncer::enricher::ThreadPost {
                author_did: a.author_did.clone(),
                text: a.text.clone(),
            })
            .collect();
        let threaded = interaction.with_enriched_context(thread_ctx);
        let thread = match classifier.classify(&threaded).await {
            Ok(v) => v,
            Err(e) => {
                println!("  {:<30} thread ERROR: {e}", truncate(&c.name, 30));
                continue;
            }
        };

        let n = is_violation(&no_ctx);
        let p = is_violation(&parent);
        let t = is_violation(&thread);
        if n == c.expected_violation {
            no_ctx_correct += 1;
        }
        if p == c.expected_violation {
            parent_correct += 1;
        }
        if t == c.expected_violation {
            thread_correct += 1;
        }
        if t != p {
            if t == c.expected_violation {
                flips_to_correct += 1;
            } else {
                flips_to_wrong += 1;
            }
        }

        println!(
            "  {:<30} depth={} expect={:<5} none={:<5} parent={:<5} thread={:<5} {}",
            truncate(&c.name, 30),
            c.ancestors.len(),
            c.expected_violation,
            n,
            p,
            t,
            if t != p { "THREAD-CHANGED" } else { "" }
        );
    }

    println!("  {:-<78}", "");
    println!("  Level-2 hard cases:               {total}");
    println!("  No-context correct:               {no_ctx_correct}/{total}");
    println!("  Parent-only correct:              {parent_correct}/{total}");
    println!("  Full-thread correct:              {thread_correct}/{total}");
    println!("  Thread flips vs parent:");
    println!("    -> correct:                     {flips_to_correct}");
    println!("    -> wrong:                       {flips_to_wrong}");
    Ok(())
}

/// Hard corpus: candidate text that is ambiguous/benign in isolation but requires
/// thread context to classify correctly. Compares no-context, parent-only, and
/// full-chain inputs for the primary System-1 model.
async fn run_hard_thread_experiment(
    hard: &HardThreads,
    rubric: &RuleRubric,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{:=<80}", "");
    println!("PART 1B  HARD THREADS: no-context vs parent-only vs full ancestor chain");
    println!("{:=<80}", "");

    let model = std::env::var("EXPERIMENT_MODEL").unwrap_or_else(|_| "nimble".to_string());
    println!("  Primary model: {model}");
    let classifier = JevClassifier::new(primary_config(&model), rubric.clone())?;

    let mut no_ctx_correct = 0usize;
    let mut parent_correct = 0usize;
    let mut thread_correct = 0usize;
    let mut flips_to_correct = 0usize;
    let mut flips_to_wrong = 0usize;
    let mut total = 0usize;

    for c in &hard.cases {
        total += 1;
        let mut interaction = Interaction::new(
            &c.author_did,
            &c.target_did,
            InteractionType::DirectReply,
            format!("at://{}/app.bsky.feed.post/exp{}", c.author_did, total),
            "bafyhardcid",
            &c.candidate_text,
        );

        // (a) No context.
        let no_ctx = classifier.classify(&interaction).await?;

        // (b) Parent-only context.
        let parent_ctx = c.ancestors.last().map(|a| {
            let mut ctx = EnrichedContext::empty();
            ctx.parent_post = Some(ParentPostContext {
                author_did: a.author_did.clone(),
                text: a.text.clone(),
                cid: None,
            });
            ctx
        });
        let parent_input = interaction.clone().with_enriched_context_opt(parent_ctx);
        let parent = classifier.classify(&parent_input).await?;

        // (c) Full ancestor chain.
        let mut thread_ctx = EnrichedContext::empty();
        thread_ctx.thread_ancestors = c
            .ancestors
            .iter()
            .map(|a| skybouncer::enricher::ThreadPost {
                author_did: a.author_did.clone(),
                text: a.text.clone(),
            })
            .collect();
        interaction = interaction.with_enriched_context(thread_ctx);
        let thread = classifier.classify(&interaction).await?;

        let n = is_violation(&no_ctx);
        let p = is_violation(&parent);
        let t = is_violation(&thread);
        if n == c.expected_violation {
            no_ctx_correct += 1;
        }
        if p == c.expected_violation {
            parent_correct += 1;
        }
        if t == c.expected_violation {
            thread_correct += 1;
        }
        if t != p {
            if t == c.expected_violation {
                flips_to_correct += 1;
            } else {
                flips_to_wrong += 1;
            }
        }

        println!(
            "  {:<30} depth={} expect={:<5} none={:<5} parent={:<5} thread={:<5} {}",
            truncate(&c.name, 30),
            c.ancestors.len(),
            c.expected_violation,
            n,
            p,
            t,
            if t != p { "THREAD-CHANGED" } else { "" }
        );
        println!("       note: {}", c.note);
    }

    println!("  {:-<78}", "");
    println!("  Hard cases:                       {total}");
    println!("  No-context correct:               {no_ctx_correct}/{total}");
    println!("  Parent-only correct:              {parent_correct}/{total}");
    println!("  Full-thread correct:              {thread_correct}/{total}");
    println!("  Thread flips vs parent:");
    println!("    -> correct:                     {flips_to_correct}");
    println!("    -> wrong:                       {flips_to_wrong}");
    Ok(())
}

async fn run_context_experiment(
    curated: &CuratedVectors,
    enricher: &AppViewContextEnricher,
    rubric: &RuleRubric,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{:=<80}", "");
    println!("PART 1  THREAD CONTEXT: parent-only (baseline) vs full ancestor chain");
    println!("{:=<80}", "");

    let classifier = JevClassifier::new(primary_config("nimble"), rubric.clone())?;

    let mut agree = 0usize;
    let mut changed_to_correct = 0usize;
    let mut changed_to_wrong = 0usize;
    let mut base_correct = 0usize;
    let mut thread_correct = 0usize;
    let mut total = 0usize;
    let mut base_latency = 0u128;
    let mut thread_latency = 0u128;
    let mut ancestor_posts = 0usize;

    for v in curated.vectors.iter().filter(|v| v.image_cids.is_empty()) {
        total += 1;
        let chain = enricher.fetch_thread_ancestors(&v.post_uri).await;
        ancestor_posts += chain.len();
        let depth = chain.len();

        let interaction = base_interaction(v);

        let baseline_ctx = chain.last().map(|a| {
            let mut ctx = EnrichedContext::empty();
            ctx.parent_post = Some(ParentPostContext {
                author_did: a.author_did.clone(),
                text: a.text.clone(),
                cid: None,
            });
            ctx
        });
        let baseline = interaction.clone().with_enriched_context_opt(baseline_ctx);
        let t0 = Instant::now();
        let base_verdict = match classifier.classify(&baseline).await {
            Ok(v) => v,
            Err(e) => {
                println!("  {:<34} baseline ERROR: {e}", truncate(&v.name, 34));
                continue;
            }
        };
        base_latency += t0.elapsed().as_millis();

        let mut thread_ctx = EnrichedContext::empty();
        thread_ctx.thread_ancestors = chain.clone();
        let threaded = interaction.with_enriched_context(thread_ctx);
        let t1 = Instant::now();
        let thread_verdict = match classifier.classify(&threaded).await {
            Ok(v) => v,
            Err(e) => {
                println!("  {:<34} thread ERROR: {e}", truncate(&v.name, 34));
                continue;
            }
        };
        thread_latency += t1.elapsed().as_millis();

        let b = is_violation(&base_verdict);
        let t = is_violation(&thread_verdict);
        if b == v.expected_violation {
            base_correct += 1;
        }
        if t == v.expected_violation {
            thread_correct += 1;
        }
        if b == t {
            agree += 1;
        } else if t == v.expected_violation {
            changed_to_correct += 1;
        } else {
            changed_to_wrong += 1;
        }

        println!(
            "  {:<34} depth={depth} expected={:<5} base={:<5}({:.2}) thread={:<5}({:.2}) {}",
            truncate(&v.name, 34),
            v.expected_violation,
            b,
            base_verdict.confidence().unwrap_or(0.0),
            t,
            thread_verdict.confidence().unwrap_or(0.0),
            if b == t { "same" } else { "CHANGED" }
        );
    }

    println!("  {:-<78}", "");
    println!("  Text vectors compared:        {total}");
    println!("  Ancestor posts fetched:       {ancestor_posts}");
    println!("  Baseline (parent-only) correct: {base_correct}/{total}");
    println!("  Thread-context correct:         {thread_correct}/{total}");
    println!("  Verdict agreement:              {agree}/{total}");
    println!("    changed -> correct:           {changed_to_correct}");
    println!("    changed -> wrong:             {changed_to_wrong}");
    println!(
        "  Mean latency: baseline {:.0}ms | thread {:.0}ms",
        safe_mean(base_latency, total),
        safe_mean(thread_latency, total)
    );
    Ok(())
}

async fn run_dynamic_primary_experiment(
    curated: &CuratedVectors,
    enricher: &AppViewContextEnricher,
    rubric: &RuleRubric,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{:=<80}", "");
    println!("PART 2  DYNAMIC TIER-1: nimble+gemma fallback (baseline) vs clef-flash primary");
    println!("{:=<80}", "");

    let tiered = TieredClassifier::new(
        Arc::new(JevClassifier::new(
            primary_config("nimble"),
            rubric.clone(),
        )?),
        Arc::new(JevClassifier::new(
            ollama_config(&std::env::var("FALLBACK_MODEL").unwrap_or_else(|_| "gemma4:12b".into())),
            rubric.clone(),
        )?),
        CertaintyConfig::default(),
    );

    let dynamic = DynamicPrimaryClassifier::new(
        Arc::new(JevClassifier::new(
            primary_config("nimble"),
            rubric.clone(),
        )?),
        Arc::new(JevClassifier::new(
            multimodal_config(
                &std::env::var("MULTIMODAL_MODEL").unwrap_or_else(|_| "clef-flash".into()),
            ),
            rubric.clone(),
        )?),
        DynamicModelPolicy::default(),
    );

    let mut total = 0usize;
    let mut base_correct = 0usize;
    let mut dyn_correct = 0usize;
    let mut base_latency = 0u128;
    let mut dyn_latency = 0u128;

    for v in curated.vectors.iter().filter(|v| !v.image_cids.is_empty()) {
        total += 1;
        let images = enricher
            .fetch_images_base64(&v.author_did, &v.image_cids)
            .await;
        let mut ctx = EnrichedContext::empty();
        ctx.images_base64 = images;
        let interaction = base_interaction(v).with_enriched_context(ctx);

        let t0 = Instant::now();
        let base = match tiered.classify(&interaction).await {
            Ok(v) => v,
            Err(e) => {
                println!("  {:<34} baseline ERROR: {e}", truncate(&v.name, 34));
                continue;
            }
        };
        base_latency += t0.elapsed().as_millis();

        let t1 = Instant::now();
        let dynv = match dynamic.classify(&interaction).await {
            Ok(v) => v,
            Err(e) => {
                println!("  {:<34} dynamic ERROR: {e}", truncate(&v.name, 34));
                continue;
            }
        };
        dyn_latency += t1.elapsed().as_millis();

        let b = is_violation(&base);
        let d = is_violation(&dynv);
        if b == v.expected_violation {
            base_correct += 1;
        }
        if d == v.expected_violation {
            dyn_correct += 1;
        }

        println!(
            "  {:<34} expected={:<5} baseline={:<5}({:.2}) dynamic={:<5}({:.2})",
            truncate(&v.name, 34),
            v.expected_violation,
            b,
            base.confidence().unwrap_or(0.0),
            d,
            dynv.confidence().unwrap_or(0.0),
        );
    }

    println!("  {:-<78}", "");
    println!("  Image vectors compared:            {total}");
    println!("  Baseline (tiered nimble+gemma):    {base_correct}/{total} correct");
    println!("  Dynamic (clef-flash Tier-1):       {dyn_correct}/{total} correct");
    println!(
        "  Mean latency: baseline {:.0}ms | dynamic {:.0}ms",
        safe_mean(base_latency, total),
        safe_mean(dyn_latency, total)
    );
    println!(
        "  Dynamic routing: {} text, {} multimodal",
        dynamic.stats().snapshot().text_routed,
        dynamic.stats().snapshot().multimodal_routed
    );
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn safe_mean(total_ms: u128, count: usize) -> f64 {
    if count == 0 {
        0.0
    } else {
        total_ms as f64 / count as f64
    }
}
