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

//! `skybouncer` daemon entrypoint.
//!
//! Orchestrates the live Jetstream firehose streamer, non-followed account bypass gate,
//! pluggable Jev System-1 classifier, and sovereign PDS moderation list mutator with graceful
//! shutdown and structured telemetry.

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

#[tokio::main]
async fn main() -> Result<(), SkybouncerError> {
    // 1. Load .env file from current working directory if present
    load_dotenv_file(Path::new(".env"));

    // 2. Initialize structured tracing subscriber
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("skybouncer=info,skybase=info,info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("🛡️ Starting Skybouncer v{}", env!("CARGO_PKG_VERSION"));
    info!("   Sovereign, Rule-Driven Auto-Moderation & Bouncer Service for ATProto & Bluesky");

    // 3. Load engine configuration from environment variables
    let config = match SkybouncerConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(error = %e, "Failed to load Skybouncer configuration from environment");
            return Err(e);
        }
    };

    if config.protected_dids.is_empty() {
        warn!("No PROTECTED_DIDS configured! Set PROTECTED_DIDS in .env (comma-separated).");
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

    if config.enable_heuristic_prefilter {
        info!(
            "⚡ Zero-cost heuristic regex pre-filter: ENABLED (short-circuiting common patterns)"
        );
    } else {
        info!("🧠 Heuristic regex pre-filter: DISABLED by default (all candidate speech routed to primary model to eliminate false positives)");
    }

    // 4. Build the unified Skybouncer engine with context enricher
    let appview_endpoint = std::env::var("APPVIEW_ENDPOINT")
        .or_else(|_| std::env::var("SKYBOUNCER_APPVIEW_ENDPOINT"))
        .unwrap_or_else(|_| skybouncer::enricher::DEFAULT_APPVIEW_ENDPOINT.to_string());
    let enricher = std::sync::Arc::new(
        skybouncer::enricher::AppViewContextEnricher::with_endpoint(appview_endpoint),
    );

    let engine = match SkybouncerEngine::builder(config.clone())
        .with_enricher(enricher)
        .build()
    {
        Ok(eng) => eng,
        Err(e) => {
            error!(error = %e, "Failed to initialize Skybouncer engine");
            return Err(e);
        }
    };

    // 5. Ensure moderation list exists on PDS for configured protected DIDs
    if config.pds_endpoint.is_some() && config.pds_access_token.is_some() {
        for did in &config.protected_dids {
            match engine.ensure_mod_list(did).await {
                Ok(list_uri) => {
                    info!(did = %did, list_uri = %list_uri, "Moderation list verified on sovereign PDS");
                }
                Err(e) => {
                    warn!(did = %did, error = %e, "Could not verify moderation list on PDS");
                }
            }
        }
    }

    // 6. Setup cancellation and background task supervision
    let cancel = CancellationToken::new();
    let mut join_set = JoinSet::new();

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
    let chat_endpoint = std::env::var("CHAT_ENDPOINT")
        .unwrap_or_else(|_| skybouncer::DEFAULT_CHAT_ENDPOINT.to_string());
    let chat_token = std::env::var("CHAT_ACCESS_TOKEN")
        .ok()
        .or_else(|| std::env::var("PDS_ACCESS_TOKEN").ok());
    let bot_did = std::env::var("BOT_DID")
        .ok()
        .or_else(|| config.protected_dids.iter().next().cloned());

    if let (Some(token), Some(did)) = (chat_token, bot_did) {
        match skybouncer::ChatClient::new(chat_endpoint, token) {
            Ok(chat_client) => {
                let handler =
                    skybouncer::BotCommandHandler::new(std::sync::Arc::new(engine.clone()), did);
                let cancel_bot = cancel.clone();
                join_set.spawn(async move {
                    if let Err(e) = skybouncer::run_bot_poller(
                        chat_client,
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
            }
            Err(e) => {
                warn!(error = %e, "Could not initialize ATProto DM chat client");
            }
        }
    } else {
        info!("ℹ️ ATProto DM bot disabled (CHAT_ACCESS_TOKEN / BOT_DID not configured)");
    }

    // Optional Sovereign Web Dashboard
    let web_enabled = std::env::var("WEB_ENABLED")
        .or_else(|_| std::env::var("SKYBOUNCER_WEB_ENABLED"))
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    let port_configured = std::env::var("PORT").is_ok() || std::env::var("SKYBOUNCER_PORT").is_ok();

    if web_enabled || port_configured {
        let web_config = skybouncer::web::WebServerConfig::from_env();
        let web_port = web_config.port;
        let engine_web = std::sync::Arc::new(engine.clone());
        let cancel_web = cancel.clone();

        join_set.spawn(async move {
            if let Err(e) =
                skybouncer::web::run_web_server(web_config, engine_web, cancel_web).await
            {
                error!(error = %e, "Sovereign web dashboard server encountered error");
            }
            Ok(Default::default())
        });
        info!(
            port = web_port,
            "🌐 Sovereign Web Dashboard server activated"
        );
    } else {
        info!("ℹ️ Sovereign Web Dashboard disabled (WEB_ENABLED / PORT not configured)");
    }

    info!("🚀 Skybouncer is running! Press Ctrl+C to stop.");

    // 7. Await shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C); initiating graceful shutdown...");
        }
        _ = cancel.cancelled() => {
            info!("Cancellation token triggered; initiating graceful shutdown...");
        }
    }

    // 8. Graceful drain and shutdown
    cancel.cancel();
    let shutdown_timeout = Duration::from_secs(5);
    let _ = SkybouncerEngine::drain_and_shutdown(&mut join_set, &cancel, shutdown_timeout).await;

    // 9. Output final operational telemetry
    let stats = engine.stats().snapshot();
    info!("📊 Final Skybouncer Operational Telemetry:");
    info!(
        "   Incoming Commits Received:    {}",
        stats.commits_received
    );
    info!("   Follows Synced:               {}", stats.follows_synced);
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
