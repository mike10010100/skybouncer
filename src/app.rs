//! Operational CLI command implementations (`status`, `pardon`, `simulate`).
//!
//! Factored out of `src/main.rs` so the command logic can be exercised against a
//! mock HTTP daemon in tests. `main.rs` wires the subcommand dispatch to these.

use std::time::Duration;

use crate::cli;
use crate::engine::{SkybouncerConfig, SkybouncerEngine};
use crate::error::SkybouncerError;

/// Executes the `skybouncer status` operational subcommand.
pub async fn run_cli_status(args: &[String]) -> Result<(), SkybouncerError> {
    let daemon_url = cli::resolve_daemon_url(args);
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

    let status: crate::web::api::StatusResponse = resp
        .json()
        .await
        .map_err(|e| SkybouncerError::Config(format!("Failed to parse status response: {e}")))?;

    let s = &status.stats;
    let total_bypassed = s.gate_bypassed_self + s.gate_bypassed_followed + s.gate_bypassed_follower;
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
        cli::format_number(s.commits_received)
    );
    println!(
        "  Follows Hydrated/Synced:    {}",
        cli::format_number(s.follows_synced)
    );
    println!(
        "  Sovereign Configs Synced:   {}",
        cli::format_number(s.sovereign_configs_synced)
    );
    println!();
    println!("── COST-CONTROL GATE ($0) ────────────────────────────────────────────────");
    println!(
        "  Target Interactions Matched:{}",
        cli::format_number(s.interactions_matched)
    );
    println!(
        "  Gate Bypassed (Self):       {}",
        cli::format_number(s.gate_bypassed_self)
    );
    println!(
        "  Gate Bypassed (Followed):   {}",
        cli::format_number(s.gate_bypassed_followed)
    );
    println!(
        "  Gate Bypassed (Followers):  {}",
        cli::format_number(s.gate_bypassed_follower)
    );
    println!(
        "  Total Bypassed ($0 / <1µs): {} ({bypass_rate} saved before model)",
        cli::format_number(total_bypassed)
    );
    println!();
    println!("── EVALUATION & QUEUE ────────────────────────────────────────────────────");
    println!(
        "  Candidates Evaluated:       {}",
        cli::format_number(s.candidates_evaluated)
    );
    println!(
        "  Model Evaluations:          {}",
        cli::format_number(s.model_evaluations)
    );
    println!(
        "  Dedup Cache Hits:           {}",
        cli::format_number(s.dedup_cache_hits)
    );
    let queue_backlog = s.eval_queue_enqueued.saturating_sub(s.eval_queue_processed);
    println!(
        "  Queue Backlog:              {}",
        cli::format_number(queue_backlog)
    );
    println!(
        "  Queue Processed:            {}",
        cli::format_number(s.eval_queue_processed)
    );
    println!(
        "  Queue Overflows (Shed):     {}",
        cli::format_number(s.eval_queue_overflows)
    );
    println!();
    println!("── MODERATION ACTION & ENFORCEMENT ───────────────────────────────────────");
    println!(
        "  Violations Detected:        {}",
        cli::format_number(s.violations_detected)
    );
    println!(
        "  Bounces Executed (PDS):     {}",
        cli::format_number(s.bounces_executed)
    );
    println!(
        "  Permitted Interactions:     {}",
        cli::format_number(s.permitted)
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
pub async fn run_cli_pardon(args: &[String]) -> Result<(), SkybouncerError> {
    let daemon_url = cli::resolve_daemon_url(args);
    let mut subject = None;
    let protected_did = cli::arg_value(args, "--target").map(str::to_string);

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--url" && i + 1 < args.len() {
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
        let clean_handle = crate::util::normalize_handle(&raw_subject);
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
    let req_payload = crate::web::api::PardonRequest {
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
        let pardon_res: crate::web::api::PardonResponse = resp.json().await.map_err(|e| {
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

/// Prints a simulation evaluation result banner to stdout.
pub fn print_simulation_result(
    text: &str,
    res: &crate::web::api::SimulateResponse,
    image_arg: &Option<String>,
) {
    print!("{}", cli::format_simulation_report(text, res, image_arg));
}

/// Executes the `skybouncer simulate` operational subcommand.
pub async fn run_cli_simulate(args: &[String]) -> Result<(), SkybouncerError> {
    let daemon_url = cli::resolve_daemon_url(args);
    let parsed = cli::parse_simulate_args(args)?;
    let cli::SimulateArgs {
        text,
        image_arg,
        image_base64,
        image_url,
        offline,
    } = parsed;

    // 1. Attempt evaluation against running daemon if not --offline
    if !offline {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| SkybouncerError::Config(format!("HTTP client error: {e}")))?;

        let sim_endpoint = format!("{daemon_url}/api/simulate");
        let payload = crate::web::api::SimulateRequest {
            text: text.clone(),
            author_did: None,
            target_did: None,
            image_base64: image_base64.clone(),
            image_url: image_url.clone(),
        };

        if let Ok(resp) = client.post(&sim_endpoint).json(&payload).send().await {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<crate::web::api::SimulateResponse>().await {
                    print_simulation_result(&text, &data, &image_arg);
                    return Ok(());
                }
            }
        }
    }

    // 2. Fallback: Local offline simulation via a dry-run engine.
    println!("ℹ️ Running local offline simulation...");
    let config = SkybouncerConfig::from_env()?.with_dry_run(true);
    let engine = match SkybouncerEngine::builder(config).build() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("❌ Failed to initialize offline simulation engine: {e}");
            return Err(e);
        }
    };

    let inputs = crate::engine::simulate::SimulationInputs::new(
        &text,
        "did:plc:candidate-author",
        "did:plc:protected-user",
    )
    .with_image(image_base64, false);

    let sim_result = engine.run_simulation(inputs).await?;
    let sim_response = crate::web::api::SimulateResponse {
        violates: sim_result.violates,
        category: sim_result.category,
        confidence: sim_result.confidence,
        reason: sim_result.reason,
        evaluator: sim_result.evaluator,
        meets_threshold: sim_result.meets_threshold,
        threshold: sim_result.threshold,
        images_evaluated: sim_result.images_evaluated,
        tier1: sim_result.tier1.map(|t| crate::web::api::TierStageDetail {
            stage_name: t.stage_name,
            model: t.model,
            status: t.status,
            violates: t.violates,
            category: t.category,
            confidence: t.confidence,
            reason: t.reason,
        }),
        tier2: sim_result.tier2.map(|t| crate::web::api::TierStageDetail {
            stage_name: t.stage_name,
            model: t.model,
            status: t.status,
            violates: t.violates,
            category: t.category,
            confidence: t.confidence,
            reason: t.reason,
        }),
    };

    print_simulation_result(&text, &sim_response, &image_arg);
    Ok(())
}
