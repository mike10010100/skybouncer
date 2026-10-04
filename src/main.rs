#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    missing_docs,
    rust_2018_idioms
)]

//! `skybouncer` CLI entrypoint and operational command suite.
//!
//! Orchestrates the live Jetstream firehose streamer, non-followed account bypass gate,
//! pluggable Jev System-1 classifier, and sovereign PDS moderation list mutator with graceful
//! shutdown, structured telemetry, and operational subcommands (`status`, `pardon`, `simulate`, `daemon`).

use std::path::Path;
use std::time::Duration;

use skybouncer::engine::{SkybouncerConfig, SkybouncerEngine, DEFAULT_MAINTENANCE_INTERVAL};
use skybouncer::error::SkybouncerError;
use skybouncer::stream::{run_jetstream_streamer, StreamConfig, DEFAULT_JETSTREAM_ENDPOINT};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// Loads environment variables from a `.env` file if it exists on disk.
fn load_dotenv_file(path: &Path) {
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');
                if std::env::var_os(key).is_none() {
                    std::env::set_var(key, val);
                }
            }
        }
    }
}

/// Formats an integer with thousands separator commas (e.g. 1000000 -> "1,000,000").
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (count, c) in s.chars().rev().enumerate() {
        if count > 0 && count % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Resolves the target daemon base URL from CLI arguments, environment, or default fallback.
fn resolve_daemon_url(args: &[String]) -> String {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--url" && i + 1 < args.len() {
            return args[i + 1].trim_end_matches('/').to_string();
        }
        i += 1;
    }
    if let Ok(url) =
        std::env::var("SKYBOUNCER_URL").or_else(|_| std::env::var("SKYBOUNCER_STATUS_URL"))
    {
        return url.trim_end_matches('/').to_string();
    }
    let port = std::env::var("PORT")
        .or_else(|_| std::env::var("SKYBOUNCER_PORT"))
        .unwrap_or_else(|_| "3000".to_string());
    format!("http://127.0.0.1:{port}")
}

/// Prints general command-line usage information.
fn print_help() {
    println!(
        "🛡️ Skybouncer v{} - Sovereign Automated Moderation Service for Bluesky",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("USAGE:");
    println!("  skybouncer [COMMAND] [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!(
        "  daemon                    Run 24/7 firehose streamer and moderation engine (default)"
    );
    println!("  status                    Query local or remote daemon status, rates, and health");
    println!("  simulate <TEXT>           Test post text and optional images against house rules");
    println!("  pardon <DID_OR_HANDLE>    Pardon/unban account and remove list item from PDS");
    println!();
    println!("DAEMON OPTIONS:");
    println!("  --dry-run, --shadow-mode  Run in shadow mode: stream real-time firehose, evaluate");
    println!(
        "                            with live model, but simulate PDS list mutations (0 writes)"
    );
    println!("  --did <DID>               Add protected DID to shield (can be repeated)");
    println!("  --admin <DID>             Designate instance administrator DID (fleet oversight & shielded)");
    println!("  --rules <RULES>           Override natural-language moderation rules prompt");
    println!("  -h, --help                Print help information");
    println!();
    println!("STATUS OPTIONS:");
    println!("  --url <URL>               Daemon base URL (default: http://127.0.0.1:3000)");
    println!("  --json                    Output status as structured JSON");
    println!();
    println!("SIMULATE OPTIONS:");
    println!("  --image <PATH_OR_URL>     Attach image file or URL for multimodal evaluation");
    println!("  --url <URL>               Daemon base URL (default: http://127.0.0.1:3000)");
    println!(
        "  --offline                 Force local offline evaluation without contacting daemon"
    );
    println!();
    println!("PARDON OPTIONS:");
    println!("  --url <URL>               Daemon base URL (default: http://127.0.0.1:3000)");
    println!("  --target <DID>            Protected user DID whose modlist to pardon from");
}

/// Executes the `skybouncer status` operational subcommand.
async fn run_cli_status(args: &[String]) -> Result<(), SkybouncerError> {
    let daemon_url = resolve_daemon_url(args);
    let json_output = args.iter().any(|a| a == "--json");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| SkybouncerError::Config(format!("HTTP client error: {e}")))?;

    let status_endpoint = format!("{daemon_url}/api/status");
    let resp = match client.get(&status_endpoint).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("❌ Could not connect to Skybouncer daemon at {daemon_url}: {e}");
            eprintln!(
                "   Ensure the daemon is running with 'skybouncer daemon' or pass '--url <URL>'."
            );
            return Err(SkybouncerError::Config(format!(
                "Daemon unreachable at {status_endpoint}: {e}"
            )));
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        eprintln!("❌ Daemon returned HTTP {status}: {body}");
        return Err(SkybouncerError::Config(format!(
            "Daemon returned HTTP {status}"
        )));
    }

    if json_output {
        let val: serde_json::Value = resp.json().await.map_err(|e| {
            SkybouncerError::Config(format!("Failed to parse status response JSON: {e}"))
        })?;
        println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
        return Ok(());
    }

    let status: skybouncer::web::api::StatusResponse = resp
        .json()
        .await
        .map_err(|e| SkybouncerError::Config(format!("Failed to parse status response: {e}")))?;

    let s = &status.stats;
    let total_bypassed = s.gate_bypassed_self + s.gate_bypassed_followed;
    let bypass_rate = if s.interactions_matched > 0 {
        format!(
            "{:.1}%",
            (total_bypassed as f64 / s.interactions_matched as f64) * 100.0
        )
    } else {
        "0.0%".to_string()
    };

    let mode_str = if status.dry_run {
        "🛡️ SHADOW MODE (Zero PDS Writes)"
    } else {
        "⚡ LIVE PRODUCTION (Enforcing PDS ModList Mutations)"
    };

    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║                     🛡️  SKYBOUNCER DAEMON STATUS                         ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Daemon URL:                 {daemon_url}");
    println!("  Daemon Version:             v{}", status.version);
    println!("  Operating Mode:             {mode_str}");
    println!(
        "  Protected Accounts:         {}",
        status.protected_dids.len()
    );
    for did in &status.protected_dids {
        println!("    • {did}");
    }
    println!();
    println!("── FIREHOSE & INGESTION ──────────────────────────────────────────────────");
    println!(
        "  Commits Ingested:           {}",
        format_number(s.commits_received)
    );
    println!(
        "  Follows Hydrated/Synced:    {}",
        format_number(s.follows_synced)
    );
    println!(
        "  Sovereign Configs Synced:   {}",
        format_number(s.sovereign_configs_synced)
    );
    println!();
    println!("── COST-CONTROL GATE ($0) ────────────────────────────────────────────────");
    println!(
        "  Target Interactions Matched:{}",
        format_number(s.interactions_matched)
    );
    println!(
        "  Gate Bypassed (Self):       {}",
        format_number(s.gate_bypassed_self)
    );
    println!(
        "  Gate Bypassed (Followed):   {}",
        format_number(s.gate_bypassed_followed)
    );
    println!(
        "  Total Bypassed ($0 / <1µs): {} ({bypass_rate} saved before model)",
        format_number(total_bypassed)
    );
    println!();
    println!("── EVALUATION & QUEUE ────────────────────────────────────────────────────");
    println!(
        "  Candidates Evaluated:       {}",
        format_number(s.candidates_evaluated)
    );
    println!(
        "  Model Evaluations:          {}",
        format_number(s.model_evaluations)
    );
    println!(
        "  Dedup Cache Hits:           {}",
        format_number(s.dedup_cache_hits)
    );
    let queue_backlog = s.eval_queue_enqueued.saturating_sub(s.eval_queue_processed);
    println!(
        "  Queue Backlog:              {}",
        format_number(queue_backlog)
    );
    println!(
        "  Queue Processed:            {}",
        format_number(s.eval_queue_processed)
    );
    println!(
        "  Queue Overflows (Shed):     {}",
        format_number(s.eval_queue_overflows)
    );
    println!();
    println!("── MODERATION ACTION & ENFORCEMENT ───────────────────────────────────────");
    println!(
        "  Violations Detected:        {}",
        format_number(s.violations_detected)
    );
    println!(
        "  Bounces Executed (PDS):     {}",
        format_number(s.bounces_executed)
    );
    println!(
        "  Permitted Interactions:     {}",
        format_number(s.permitted)
    );
    println!();
    println!("── ACTIVE MODERATION RUBRIC ──────────────────────────────────────────────");
    println!(
        "  Sensitivity Level:          {} (Threshold: {:.0}%)",
        status.rubric.sensitivity,
        status.rubric.threshold * 100.0
    );
    println!("  Moderation Prompt:          {}", status.rubric.prompt);
    println!();

    Ok(())
}

/// Executes the `skybouncer pardon` operational subcommand.
async fn run_cli_pardon(args: &[String]) -> Result<(), SkybouncerError> {
    let daemon_url = resolve_daemon_url(args);
    let mut subject = None;
    let mut protected_did = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--url" && i + 1 < args.len() {
            i += 2;
            continue;
        }
        if args[i] == "--target" && i + 1 < args.len() {
            protected_did = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if !args[i].starts_with("--") && subject.is_none() {
            subject = Some(args[i].clone());
        }
        i += 1;
    }

    let raw_subject = match subject {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            eprintln!("❌ Missing required account identifier.");
            eprintln!(
                "   Usage: skybouncer pardon <DID_OR_HANDLE> [--url <URL>] [--target <PROTECTED_DID>]"
            );
            return Err(SkybouncerError::Config(
                "Missing DID or handle to pardon".into(),
            ));
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| SkybouncerError::Config(format!("HTTP client error: {e}")))?;

    // Resolve handle if needed
    let subject_did = if raw_subject.starts_with("did:") {
        raw_subject
    } else {
        let clean_handle = raw_subject.trim_start_matches('@');
        println!("🔍 Resolving handle @{clean_handle} via ATProto identity directory...");
        let resolve_url = format!(
            "https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle={clean_handle}"
        );
        match client.get(&resolve_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let json: serde_json::Value = resp.json().await.map_err(|e| {
                    SkybouncerError::Config(format!("Failed to parse resolveHandle JSON: {e}"))
                })?;
                if let Some(did) = json.get("did").and_then(|v| v.as_str()) {
                    println!("   Resolved: @{clean_handle} -> {did}");
                    did.to_string()
                } else {
                    eprintln!("❌ Handle @{clean_handle} could not be resolved to a DID.");
                    return Err(SkybouncerError::Config(format!(
                        "Cannot resolve handle: @{clean_handle}"
                    )));
                }
            }
            Ok(resp) => {
                eprintln!(
                    "❌ Handle resolution failed with HTTP {}: verify handle spelling.",
                    resp.status()
                );
                return Err(SkybouncerError::Config(format!(
                    "Handle resolution HTTP {}",
                    resp.status()
                )));
            }
            Err(e) => {
                eprintln!("❌ Network error resolving handle @{clean_handle}: {e}");
                return Err(SkybouncerError::Config(format!(
                    "Network error resolving handle: {e}"
                )));
            }
        }
    };

    println!("🔓 Issuing pardon for '{subject_did}' on daemon at {daemon_url}...");
    let pardon_url = format!("{daemon_url}/api/pardon");
    let req_payload = skybouncer::web::api::PardonRequest {
        subject_did: subject_did.clone(),
        protected_did,
        allowlist: false,
        reason: None,
    };

    let resp = match client.post(&pardon_url).json(&req_payload).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("❌ Could not connect to Skybouncer daemon at {daemon_url}: {e}");
            return Err(SkybouncerError::Config(format!(
                "Daemon unreachable at {pardon_url}: {e}"
            )));
        }
    };

    if resp.status().is_success() {
        let pardon_res: skybouncer::web::api::PardonResponse = resp.json().await.map_err(|e| {
            SkybouncerError::Config(format!("Failed to parse pardon response: {e}"))
        })?;
        println!("✅ Account successfully pardoned!");
        println!("   Subject DID:   {}", pardon_res.subject_did);
        println!("   Pardoned:      {}", pardon_res.pardoned);
        println!("   Status:        {}", pardon_res.message);
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        eprintln!("❌ Pardon failed (HTTP {status}): {body}");
        Err(SkybouncerError::Config(format!(
            "Pardon failed with HTTP {status}: {body}"
        )))
    }
}

/// Formats and prints a simulation evaluation result banner.
fn print_simulation_result(
    text: &str,
    res: &skybouncer::web::api::SimulateResponse,
    image_arg: &Option<String>,
) {
    let eval_badge = if res.evaluator.contains("fallback") || res.evaluator.contains("vision") {
        "👁️  Vision Fallback (Tier 2 Multimodal)"
    } else if res.evaluator.contains("heuristic") {
        "⚡ Heuristic Pre-Filter"
    } else if res.images_evaluated > 0 || res.evaluator.contains("multimodal") {
        "🧠 Primary Model (Multimodal)"
    } else {
        "🧠 Primary Model (Text)"
    };

    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║                   🧪  SKYBOUNCER SIMULATION RESULT                       ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Input Text:       \"{text}\"");
    if let Some(ref img) = image_arg {
        println!("  Attached Image:   {img}");
    }
    println!("  Images Evaluated: {}", res.images_evaluated);
    println!("  Evaluator:        {eval_badge}");
    println!();
    if res.violates {
        let cat = res.category.as_deref().unwrap_or("Unspecified");
        println!("  Verdict:          🚨 VIOLATION [{cat}]");
        println!(
            "  Confidence:       {:.1}% (Threshold: {:.1}%)",
            res.confidence * 100.0,
            res.threshold * 100.0
        );
        println!(
            "  Threshold Met:    {}",
            if res.meets_threshold {
                "YES (Will Bounce)"
            } else {
                "NO (Borderline, Permitted)"
            }
        );
        println!("  Reason:           {}", res.reason);
        println!();
        if res.meets_threshold {
            println!(
                "  Action (Live):    💥 Author would be BOUNCED to sovereign PDS moderation list"
            );
        } else {
            println!("  Action (Live):    ⚠️ Confidence below sensitivity threshold; interaction permitted");
        }
    } else {
        println!("  Verdict:          ✅ PERMITTED");
        println!(
            "  Confidence:       {:.1}% (Threshold: {:.1}%)",
            res.confidence * 100.0,
            res.threshold * 100.0
        );
        println!("  Reason:           {}", res.reason);
        println!();
        println!("  Action (Live):    🛡️ Permitted through gate (zero PDS listitem mutations)");
    }
    println!();
}

/// Executes the `skybouncer simulate` operational subcommand.
async fn run_cli_simulate(args: &[String]) -> Result<(), SkybouncerError> {
    let daemon_url = resolve_daemon_url(args);
    let offline_flag = args.iter().any(|a| a == "--offline");
    let mut image_arg = None;
    let mut text_parts = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--url" && i + 1 < args.len() {
            i += 2;
            continue;
        }
        if args[i] == "--image" && i + 1 < args.len() {
            image_arg = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if args[i] == "--offline" {
            i += 1;
            continue;
        }
        if !args[i].starts_with("--") {
            text_parts.push(args[i].clone());
        }
        i += 1;
    }

    let text = text_parts.join(" ");
    let text = text.trim();
    if text.is_empty() {
        eprintln!("❌ Missing text to simulate.");
        eprintln!(
            "   Usage: skybouncer simulate <TEXT...> [--image <PATH_OR_URL>] [--url <URL>] [--offline]"
        );
        return Err(SkybouncerError::Config(
            "Missing text for simulation".into(),
        ));
    }

    let mut image_base64 = None;
    let mut image_url = None;

    if let Some(ref img) = image_arg {
        if img.starts_with("http://") || img.starts_with("https://") {
            image_url = Some(img.clone());
        } else {
            let path = Path::new(img);
            if !path.exists() {
                eprintln!("❌ Image file does not exist: '{img}'");
                return Err(SkybouncerError::Config(format!(
                    "Image file not found: {img}"
                )));
            }
            let bytes = std::fs::read(path).map_err(|e| {
                SkybouncerError::Config(format!("Failed to read image file '{img}': {e}"))
            })?;
            use base64::Engine;
            image_base64 = Some(base64::engine::general_purpose::STANDARD.encode(&bytes));
        }
    }

    // 1. Attempt evaluation against running daemon if not --offline
    if !offline_flag {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| SkybouncerError::Config(format!("HTTP client error: {e}")))?;

        let sim_endpoint = format!("{daemon_url}/api/simulate");
        let payload = skybouncer::web::api::SimulateRequest {
            text: text.to_string(),
            author_did: None,
            target_did: None,
            image_base64: image_base64.clone(),
            image_url: image_url.clone(),
        };

        if let Ok(resp) = client.post(&sim_endpoint).json(&payload).send().await {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<skybouncer::web::api::SimulateResponse>().await {
                    print_simulation_result(text, &data, &image_arg);
                    return Ok(());
                }
            }
        }
    }

    // 2. Fallback: Local offline simulation
    println!("ℹ️ Running local offline simulation...");
    let config = SkybouncerConfig::from_env()?;
    let heuristic = skybouncer::classifier::HeuristicClassifier::default();
    let rubric = config.rubric.clone();

    let mut images_base64 = Vec::new();
    let mut image_cids = Vec::new();
    if let Some(b64) = image_base64 {
        images_base64.push(b64);
        image_cids.push("local-file-image".to_string());
    }

    let enriched_context = if !images_base64.is_empty() {
        let mut ctx = skybouncer::enricher::EnrichedContext::empty();
        ctx.images_base64 = images_base64;
        Some(ctx)
    } else {
        None
    };

    let interaction = skybouncer::matcher::Interaction {
        post_uri: "at://did:plc:cli-sim/app.bsky.feed.post/sample".to_string(),
        post_cid: Some("bafyclisim".to_string()),
        author_did: "did:plc:candidate-author".to_string(),
        target_did: "did:plc:protected-user".to_string(),
        text: text.to_string(),
        interaction_type: skybouncer::matcher::InteractionType::DirectReply,
        parent_uri: None,
        root_uri: None,
        created_at_us: 0,
        image_cids,
        image_alts: Vec::new(),
        enriched_context,
    };

    let heuristic_verdict = heuristic.evaluate(&interaction);
    let sim_response = match heuristic_verdict {
        skybouncer::classifier::Verdict::Violation {
            category,
            confidence,
            reason,
        } => {
            let meets_threshold = rubric.meets_threshold(&category, confidence);
            skybouncer::web::api::SimulateResponse {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                threshold: rubric.sensitivity.threshold(),
                reason,
                evaluator: "heuristic_prefilter".to_string(),
                meets_threshold,
                images_evaluated: if interaction.enriched_context.is_some() {
                    1
                } else {
                    0
                },
                tier1: None,
                tier2: None,
            }
        }
        skybouncer::classifier::Verdict::Permitted { .. } => {
            if let Some(ref jev_cfg) = config.jev_config {
                let classifier =
                    skybouncer::classifier::JevClassifier::new(jev_cfg.clone(), rubric.clone())?;
                use skybouncer::classifier::Classifier;
                match classifier.classify(&interaction).await {
                    Ok(skybouncer::classifier::Verdict::Violation {
                        category,
                        confidence,
                        reason,
                    }) => {
                        let meets_threshold = rubric.meets_threshold(&category, confidence);
                        skybouncer::web::api::SimulateResponse {
                            violates: true,
                            category: Some(category.to_string()),
                            confidence,
                            threshold: rubric.sensitivity.threshold(),
                            reason,
                            evaluator: "primary_classifier".to_string(),
                            meets_threshold,
                            images_evaluated: if interaction.enriched_context.is_some() {
                                1
                            } else {
                                0
                            },
                            tier1: None,
                            tier2: None,
                        }
                    }
                    Ok(skybouncer::classifier::Verdict::Permitted { reason, confidence }) => {
                        skybouncer::web::api::SimulateResponse {
                            violates: false,
                            category: None,
                            confidence: confidence.unwrap_or(0.0),
                            threshold: rubric.sensitivity.threshold(),
                            reason,
                            evaluator: "primary_classifier".to_string(),
                            meets_threshold: false,
                            images_evaluated: if interaction.enriched_context.is_some() {
                                1
                            } else {
                                0
                            },
                            tier1: None,
                            tier2: None,
                        }
                    }
                    Err(e) => skybouncer::web::api::SimulateResponse {
                        violates: false,
                        category: None,
                        confidence: 0.0,
                        threshold: rubric.sensitivity.threshold(),
                        reason: format!("Primary model error: {e}"),
                        evaluator: "offline_fallback".to_string(),
                        meets_threshold: false,
                        images_evaluated: 0,
                        tier1: None,
                        tier2: None,
                    },
                }
            } else {
                skybouncer::web::api::SimulateResponse {
                    violates: false,
                    category: None,
                    confidence: 0.0,
                    threshold: rubric.sensitivity.threshold(),
                    reason: "Passed heuristic filter (primary model not configured)".to_string(),
                    evaluator: "heuristic_only".to_string(),
                    meets_threshold: false,
                    images_evaluated: 0,
                    tier1: None,
                    tier2: None,
                }
            }
        }
    };

    print_simulation_result(text, &sim_response, &image_arg);
    Ok(())
}

/// Executes the live 24/7 firehose streamer and moderation daemon.
async fn run_daemon(args: &[String]) -> Result<(), SkybouncerError> {
    // Initialize structured tracing subscriber
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("skybouncer=info,skybase=info,info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();

    info!("🛡️ Starting Skybouncer v{}", env!("CARGO_PKG_VERSION"));
    info!("   Sovereign, Rule-Driven Auto-Moderation & Bouncer Service for ATProto & Bluesky");

    // Load engine configuration from environment variables
    let mut config = match SkybouncerConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(
                error = %e,
                "Failed to load Skybouncer configuration from environment"
            );
            return Err(e);
        }
    };

    // Override or augment from CLI arguments
    if args
        .iter()
        .any(|a| a == "--dry-run" || a == "--shadow-mode")
    {
        config.dry_run = true;
    }
    let mut i = 0;
    while i < args.len() {
        if (args[i] == "--did" || args[i] == "--protected-did") && i + 1 < args.len() {
            config.protected_dids.insert(args[i + 1].clone());
            i += 1;
        } else if (args[i] == "--admin" || args[i] == "--admin-did") && i + 1 < args.len() {
            let admin = args[i + 1].clone();
            config.protected_dids.insert(admin.clone());
            config.admin_did = Some(admin);
            i += 1;
        } else if args[i] == "--rules" && i + 1 < args.len() {
            config.rubric = skybouncer::classifier::RuleRubric::parse(&args[i + 1])?;
            i += 1;
        }
        i += 1;
    }

    if config.dry_run {
        info!("╔══════════════════════════════════════════════════════════════════════════════╗");
        info!("║  🛡️  SHADOW MODE ACTIVE (--dry-run)                                         ║");
        info!("║  Streaming real-time Jetstream firehose and running live AI evaluations.    ║");
        info!("║  All remote PDS modlist mutations will be simulated with ZERO writes!       ║");
        info!("╚══════════════════════════════════════════════════════════════════════════════╝");
    }

    if config.protected_dids.is_empty() {
        warn!("No PROTECTED_DIDS configured! Set PROTECTED_DIDS in .env or pass --did <DID>.");
        warn!("Running in monitoring mode — no accounts will be actively protected.");
    } else {
        info!(
            count = config.protected_dids.len(),
            "Loaded protected user DIDs"
        );
        for did in &config.protected_dids {
            info!("   Protected: {}", did);
        }
    }

    if let Some(ref admin) = config.admin_did {
        info!("👑 System administrator: {}", admin);
    }

    info!(
        sensitivity = %config.rubric.sensitivity,
        threshold = %config.rubric.sensitivity.threshold(),
        "Active moderation rubric configured"
    );

    if let Some(ref jev) = config.jev_config {
        info!(
            endpoint = %jev.base_url,
            model = %jev.model,
            "Jev System-1 classifier configured"
        );
    } else {
        warn!("No JEV_API_BASE_URL configured; primary classifier fallback disabled");
    }

    if let Some(ref fb) = config.fallback_jev_config {
        info!(
            endpoint = %fb.base_url,
            model = %fb.model,
            timeout_ms = fb.timeout.as_millis(),
            "Multimodal System-2 fallback classifier configured (escalating on images/uncertainty)"
        );
    }

    if config.enable_heuristic_prefilter {
        info!(
            "⚡ Zero-cost heuristic regex pre-filter: ENABLED (short-circuiting common patterns)"
        );
    } else {
        info!("🧠 Heuristic regex pre-filter: DISABLED by default (all candidate speech routed to primary model to eliminate false positives)");
    }

    // Build the unified Skybouncer engine with context enricher
    let appview_endpoint = std::env::var("APPVIEW_ENDPOINT")
        .or_else(|_| std::env::var("SKYBOUNCER_APPVIEW_ENDPOINT"))
        .unwrap_or_else(|_| skybouncer::enricher::DEFAULT_APPVIEW_ENDPOINT.to_string());
    let enricher = std::sync::Arc::new(
        skybouncer::enricher::AppViewContextEnricher::with_endpoint(appview_endpoint),
    );

    // Initialize Web / OAuth configuration early for background token auto-refreshes
    let web_config = skybouncer::web::WebServerConfig::from_env();
    let (oauth_client, _) = skybouncer::web::build_oauth_client(&web_config);

    let mut engine_builder =
        SkybouncerEngine::builder(config.clone()).with_enricher(enricher.clone());
    if let Some(ref oc) = oauth_client {
        info!(
            "🔑 ATProto OAuth client initialized for automatic background session token refreshes"
        );
        engine_builder = engine_builder.with_oauth_client(std::sync::Arc::clone(oc));
    }

    let engine = match engine_builder.build() {
        Ok(eng) => eng,
        Err(e) => {
            error!(error = %e, "Failed to initialize Skybouncer engine");
            return Err(e);
        }
    };

    // Setup cancellation and background task supervision
    let cancel = CancellationToken::new();
    let mut join_set = JoinSet::new();

    // Start Sovereign Web Dashboard early so OAuth endpoints (e.g. client-metadata.json)
    // are actively reachable when PDS authorization servers verify OAuth client metadata
    let web_enabled = std::env::var("WEB_ENABLED")
        .or_else(|_| std::env::var("SKYBOUNCER_WEB_ENABLED"))
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    let port_configured = std::env::var("PORT").is_ok() || std::env::var("SKYBOUNCER_PORT").is_ok();

    if web_enabled || port_configured {
        let web_port = web_config.port;
        let engine_web = std::sync::Arc::new(engine.clone());
        let cancel_web = cancel.clone();
        let web_cfg = web_config.clone();

        join_set.spawn(async move {
            if let Err(e) = skybouncer::web::run_web_server(web_cfg, engine_web, cancel_web).await {
                error!(
                    error = %e,
                    "Sovereign web dashboard server encountered error"
                );
            }
            Ok(Default::default())
        });
        info!(
            port = web_port,
            "🌐 Sovereign Web Dashboard server activated"
        );
        // Allow TCP listener to bind before performing remote PDS verifications
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    } else {
        info!("ℹ️ Sovereign Web Dashboard disabled (WEB_ENABLED / PORT not configured)");
    }

    // Cold-start follow graph hydration via public AppView
    for did in &config.protected_dids {
        let follow_records = enricher.fetch_follow_records(did, 100).await;
        if !follow_records.is_empty() {
            let count = engine.hydrate_follow_records(did, follow_records);
            info!(
                did = %did,
                count = count,
                "Hydrated initial follow graph with real rkeys from AppView (cold start)"
            );
        } else {
            let follows = enricher.fetch_follows(did, 100).await;
            if !follows.is_empty() {
                let count = engine.hydrate_follows(did, follows);
                info!(
                    did = %did,
                    count = count,
                    "Hydrated initial follow graph from AppView (fallback)"
                );
            }
        }
    }

    // Ensure moderation list and listblock exist on PDS for configured protected DIDs and enrolled tenants
    if !config.dry_run {
        let mut all_dids = config.protected_dids.clone();
        if let Ok(tenants) = engine.tenant_registry().list_all() {
            for t in tenants {
                if t.session.is_some() {
                    all_dids.insert(t.did);
                }
            }
        }

        for did in &all_dids {
            match engine.ensure_mod_list(did).await {
                Ok(list_uri) => {
                    info!(
                        did = %did,
                        list_uri = %list_uri,
                        "Moderation list verified on sovereign PDS"
                    );
                    if let Err(e) = engine.ensure_list_blocked(did, &list_uri).await {
                        warn!(
                            did = %did,
                            error = %e,
                            "Could not verify auto-blocking listblock on PDS"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        did = %did,
                        error = %e,
                        "Could not verify moderation list on PDS"
                    );
                }
            }

            // Synchronize sovereign moderation rubric from user's PDS repository
            match engine.sync_sovereign_config(did).await {
                Ok(Some(pds_rubric)) => {
                    info!(
                        did = %did,
                        prompt = %pds_rubric.prompt,
                        "Synchronized sovereign rules from PDS repo (social.skybouncer.config)"
                    );
                }
                Ok(None) => {
                    // No sovereign config on PDS yet: publish initial configured rubric to PDS
                    match engine.publish_sovereign_config(did).await {
                        Ok(uri) => {
                            info!(
                                did = %did,
                                uri = %uri,
                                "Published initial sovereign rules to PDS repo (social.skybouncer.config)"
                            );
                        }
                        Err(e) => {
                            warn!(
                                did = %did,
                                error = %e,
                                "Could not publish initial sovereign rules to PDS"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        did = %did,
                        error = %e,
                        "Could not sync sovereign config from PDS"
                    );
                }
            }
        }
    } else if config.dry_run {
        info!("🛡️ Shadow mode active: skipping remote PDS moderation list verification");
    }

    // Event channel connecting Jetstream streamer to engine pipeline
    let (tx, rx) = mpsc::channel(config.channel_capacity);

    // Spawn engine processing loop
    let engine_clone = engine.clone();
    let cancel_engine = cancel.clone();
    join_set.spawn(async move {
        match engine_clone.run(rx, cancel_engine).await {
            Ok(stats) => Ok(stats),
            Err(e) => {
                error!(error = %e, "Engine processing loop error");
                Err(e)
            }
        }
    });

    // Spawn Jetstream firehose streamer
    let jetstream_url = std::env::var("JETSTREAM_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_JETSTREAM_ENDPOINT.to_string());
    let stream_config = StreamConfig::new(jetstream_url);
    let cancel_stream = cancel.clone();
    join_set.spawn(async move {
        if let Err(e) = run_jetstream_streamer(stream_config, tx, cancel_stream).await {
            error!(error = %e, "Jetstream streamer error");
        }
        Ok(Default::default())
    });

    // Spawn periodic cache maintenance
    let engine_maint = engine.clone();
    let cancel_maint = cancel.clone();
    join_set.spawn(async move {
        let _ = engine_maint
            .run_maintenance(DEFAULT_MAINTENANCE_INTERVAL, cancel_maint)
            .await;
        Ok(Default::default())
    });

    // Optional ATProto DM Bot worker
    let bot_handle = std::env::var("BOT_HANDLE")
        .or_else(|_| std::env::var("BOT_IDENTIFIER"))
        .ok()
        .filter(|h| !h.trim().is_empty());
    let bot_password = std::env::var("BOT_APP_PASSWORD")
        .or_else(|_| std::env::var("BLUESKY_APP_PASSWORD"))
        .ok()
        .filter(|p| !p.trim().is_empty() && !p.contains("xxxx"));
    let pds_endpoint =
        std::env::var("PDS_ENDPOINT").unwrap_or_else(|_| "https://bsky.social".to_string());

    let chat_endpoint = std::env::var("CHAT_ENDPOINT")
        .unwrap_or_else(|_| skybouncer::DEFAULT_CHAT_ENDPOINT.to_string());
    let chat_token = std::env::var("CHAT_ACCESS_TOKEN")
        .ok()
        .or_else(|| std::env::var("PDS_ACCESS_TOKEN").ok())
        .filter(|t| !t.trim().is_empty() && !t.contains("xxxx"));
    let bot_did = std::env::var("BOT_DID")
        .ok()
        .filter(|d| {
            !d.trim().is_empty() && !d.contains("example") && !d.contains("skybouncerbotdid")
        })
        .or_else(|| config.protected_dids.iter().next().cloned());

    let bot_client_and_did = if let (Some(handle), Some(pass)) = (bot_handle, bot_password) {
        info!(handle = %handle, "Authenticating ATProto DM bot via App Password...");
        match skybouncer::ChatClient::login_with_app_password(
            &pds_endpoint,
            &chat_endpoint,
            &handle,
            &pass,
        )
        .await
        {
            Ok((client, resolved_did)) => {
                info!(did = %resolved_did, "ATProto DM bot authenticated successfully");
                Some((client, resolved_did))
            }
            Err(e) => {
                error!(error = %e, "Failed to authenticate bot with App Password");
                None
            }
        }
    } else if let (Some(token), Some(did)) = (chat_token, bot_did) {
        match skybouncer::ChatClient::new(chat_endpoint, token) {
            Ok(c) => Some((c, did)),
            Err(e) => {
                error!(error = %e, "Failed to initialize ChatClient from token");
                None
            }
        }
    } else {
        None
    };

    if let Some((chat_client, did)) = bot_client_and_did {
        let web_config = skybouncer::web::WebServerConfig::from_env();
        let handler = skybouncer::BotCommandHandler::new(std::sync::Arc::new(engine.clone()), did)
            .with_public_url(web_config.public_url);
        let poller_client = chat_client.clone();
        let cancel_bot = cancel.clone();
        join_set.spawn(async move {
            if let Err(e) = skybouncer::run_bot_poller(
                poller_client,
                handler,
                skybouncer::DEFAULT_BOT_POLL_INTERVAL,
                cancel_bot,
            )
            .await
            {
                error!(error = %e, "ATProto DM bot worker encountered error");
            }
            Ok(Default::default())
        });
        info!("🤖 ATProto DM bot poller activated");

        // Spawn proactive ATProto DM bounce alert dispatcher
        let bounce_rx = engine.subscribe_bounces();
        let alert_client = chat_client;
        let cancel_alerts = cancel.clone();
        join_set.spawn(async move {
            if let Err(e) =
                skybouncer::run_bounce_alert_dispatcher(alert_client, bounce_rx, cancel_alerts)
                    .await
            {
                error!(
                    error = %e,
                    "ATProto DM bounce alert dispatcher encountered error"
                );
            }
            Ok(Default::default())
        });
        info!("📢 Proactive ATProto DM bounce alert dispatcher activated");
    } else {
        info!("ℹ️ ATProto DM bot disabled (BOT_APP_PASSWORD / CHAT_ACCESS_TOKEN not configured)");
    }

    info!("🚀 Skybouncer is running! Press Ctrl+C to stop.");

    // Await shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C); initiating graceful shutdown...");
        }
        _ = cancel.cancelled() => {
            info!("Cancellation token triggered; initiating graceful shutdown...");
        }
    }

    // Graceful drain and shutdown
    cancel.cancel();
    let shutdown_timeout = Duration::from_secs(5);
    let _ = SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, shutdown_timeout).await;

    // Output final operational telemetry
    let stats = engine.stats().snapshot();
    info!("📊 Final Skybouncer Operational Telemetry:");
    info!(
        "   Incoming Commits Received:    {}",
        stats.commits_received
    );
    info!("   Follows Synced:               {}", stats.follows_synced);
    info!(
        "   Sovereign Configs Synced:     {}",
        stats.sovereign_configs_synced
    );
    info!(
        "   Interactions Matched:         {}",
        stats.interactions_matched
    );
    info!(
        "   Gate Bypassed (Self):         {}",
        stats.gate_bypassed_self
    );
    info!(
        "   Gate Bypassed (Followed):     {}",
        stats.gate_bypassed_followed
    );
    info!(
        "   Dedup Cache Hits:             {}",
        stats.dedup_cache_hits
    );
    info!("   Evaluation Cache Hits:        {}", stats.eval_cache_hits);
    info!(
        "   Heuristic Violations:         {}",
        stats.heuristic_violations
    );
    info!(
        "   Model Evaluations:            {}",
        stats.model_evaluations
    );
    info!(
        "   Eval Queue Enqueued:          {}",
        stats.eval_queue_enqueued
    );
    info!(
        "   Eval Queue Processed:         {}",
        stats.eval_queue_processed
    );
    info!(
        "   Eval Queue Overflows:         {}",
        stats.eval_queue_overflows
    );
    info!(
        "   Violations Detected:          {}",
        stats.violations_detected
    );
    info!(
        "   Bounces Executed on PDS:      {}",
        stats.bounces_executed
    );
    info!("   Permitted Interactions:       {}", stats.permitted);

    info!("🛡️ Skybouncer daemon exited cleanly.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), SkybouncerError> {
    // 1. Load .env file from current working directory if present
    load_dotenv_file(Path::new(".env"));

    let args: Vec<String> = std::env::args().collect();
    let subcmd = args.get(1).map(|s| s.as_str()).unwrap_or("daemon");

    if args.iter().any(|a| a == "--help" || a == "-h") || subcmd == "help" {
        print_help();
        return Ok(());
    }

    match subcmd {
        "status" => run_cli_status(&args[2..]).await,
        "pardon" => run_cli_pardon(&args[2..]).await,
        "simulate" => run_cli_simulate(&args[2..]).await,
        "daemon" => {
            let daemon_args = if args.len() > 2 {
                &args[2..]
            } else {
                &args[0..0]
            };
            run_daemon(daemon_args).await
        }
        arg if arg.starts_with("--") => {
            // Backward-compatible invocation where flags are passed directly without "daemon" keyword:
            // e.g. `skybouncer --dry-run`
            run_daemon(&args[1..]).await
        }
        other => {
            eprintln!("❌ Unknown command: '{other}'");
            println!();
            print_help();
            Err(SkybouncerError::Config(format!(
                "Unknown command: '{other}'"
            )))
        }
    }
}
