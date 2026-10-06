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

/// Loads environment variables from a `.env` file if it exists on disk.
fn load_dotenv_file(path: &Path) {
    skybouncer::env::load_dotenv_file(path);
}

/// Prints general command-line usage information.
fn print_help() {
    println!(
        "🛡️ Skybouncer v{} - Sovereign Automated Moderation Service for Bluesky",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    print!("{}", skybouncer::cli::help_text());
}

/// Executes the live 24/7 firehose streamer and moderation daemon.
async fn run_daemon(args: &[String]) -> Result<(), SkybouncerError> {
    // Initialize structured tracing subscriber
    skybouncer::env::init_tracing();

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

    // Override or augment from CLI arguments (logic tested in `cli::apply_daemon_overrides`).
    skybouncer::cli::apply_daemon_overrides(&mut config, args)?;

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
    let enricher = std::sync::Arc::new(skybouncer::enricher::AppViewContextEnricher::from_env());

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
    let web_enabled = skybouncer::env::bool_or(&["WEB_ENABLED", "SKYBOUNCER_WEB_ENABLED"], false);
    // Mirror the historical check: a set-but-empty PORT still counts as configured.
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

        let followers = enricher.fetch_followers(did, 100).await;
        if !followers.is_empty() {
            let count = engine.hydrate_followers(did, followers);
            info!(
                did = %did,
                count = count,
                "Hydrated initial incoming followers from AppView (cold start)"
            );
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
    let jetstream_url =
        skybouncer::env::var_or(&["JETSTREAM_ENDPOINT"], DEFAULT_JETSTREAM_ENDPOINT);
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
    let bot_handle = skybouncer::env::var(&["BOT_HANDLE", "BOT_IDENTIFIER"]);
    let bot_password = skybouncer::env::var(&["BOT_APP_PASSWORD", "BLUESKY_APP_PASSWORD"])
        .filter(|p| !p.contains("xxxx"));
    let pds_endpoint = skybouncer::env::var_or(&["PDS_ENDPOINT"], "https://bsky.social");

    let chat_endpoint =
        skybouncer::env::var_or(&["CHAT_ENDPOINT"], skybouncer::DEFAULT_CHAT_ENDPOINT);
    let chat_token = skybouncer::env::var(&["CHAT_ACCESS_TOKEN", "PDS_ACCESS_TOKEN"])
        .filter(|t| !t.contains("xxxx"));
    let bot_did = skybouncer::env::var(&["BOT_DID"])
        .filter(|d| !d.contains("example") && !d.contains("skybouncerbotdid"))
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

    // Persist cumulative telemetry counters so dashboard KPIs survive restarts
    if let Err(e) = engine.persist_stats() {
        warn!(error = %e, "Failed to persist dashboard telemetry counters during shutdown");
    }

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
        "   Gate Bypassed (Followers):    {}",
        stats.gate_bypassed_follower
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
        "status" => skybouncer::app::run_cli_status(&args[2..]).await,
        "pardon" => skybouncer::app::run_cli_pardon(&args[2..]).await,
        "simulate" => skybouncer::app::run_cli_simulate(&args[2..]).await,
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
