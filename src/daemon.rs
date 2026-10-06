//! Live 24/7 firehose daemon orchestration.
//!
//! Extracted from `src/main.rs` so the daemon startup/telemetry logic is exercised by
//! tests. The public [`run`] takes an external [`CancellationToken`] so callers (and
//! tests) can drive graceful shutdown deterministically.

use std::time::Duration;

use crate::engine::{SkybouncerConfig, SkybouncerEngine, DEFAULT_MAINTENANCE_INTERVAL};
use crate::error::SkybouncerError;
use crate::stream::{run_jetstream_streamer, StreamConfig, DEFAULT_JETSTREAM_ENDPOINT};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Executes the live 24/7 firehose streamer and moderation daemon.
pub async fn run(args: &[String], cancel: CancellationToken) -> Result<(), SkybouncerError> {
    // Initialize structured tracing subscriber
    crate::env::init_tracing();

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
    crate::cli::apply_daemon_overrides(&mut config, args)?;

    if config.dry_run {
        info!("╔══════════════════════════════════════════════════════════════════════════════╗");
        info!("║  🛡️  SHADOW MODE ACTIVE (--dry-run)                                         ║");
        info!("║  Streaming real-time Jetstream firehose and running live AI evaluations.    ║");
        info!("║  All remote PDS modlist mutations will be simulated with ZERO writes!       ║");
        info!("╚══════════════════════════════════════════════════════════════════════════════╝");
    }

    for line in crate::cli::format_startup_summary(&config).lines() {
        if line.starts_with('⚠') {
            warn!("{line}");
        } else {
            info!("{line}");
        }
    }

    // Build the unified Skybouncer engine with context enricher
    let enricher = std::sync::Arc::new(crate::enricher::AppViewContextEnricher::from_env());

    // Initialize Web / OAuth configuration early for background token auto-refreshes
    let web_config = crate::web::WebServerConfig::from_env();
    let (oauth_client, _) = crate::web::build_oauth_client(&web_config);

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

    // Background task supervision (cancellation token supplied by the caller).
    let mut join_set = JoinSet::new();

    // Start Sovereign Web Dashboard early so OAuth endpoints (e.g. client-metadata.json)
    // are actively reachable when PDS authorization servers verify OAuth client metadata
    let web_enabled = crate::env::bool_or(&["WEB_ENABLED", "SKYBOUNCER_WEB_ENABLED"], false);
    // Mirror the historical check: a set-but-empty PORT still counts as configured.
    let port_configured = std::env::var("PORT").is_ok() || std::env::var("SKYBOUNCER_PORT").is_ok();

    if web_enabled || port_configured {
        let web_port = web_config.port;
        let engine_web = std::sync::Arc::new(engine.clone());
        let cancel_web = cancel.clone();
        let web_cfg = web_config.clone();

        join_set.spawn(async move {
            if let Err(e) = crate::web::run_web_server(web_cfg, engine_web, cancel_web).await {
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
    let jetstream_url = crate::env::var_or(&["JETSTREAM_ENDPOINT"], DEFAULT_JETSTREAM_ENDPOINT);
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
    let bot_handle = crate::env::var(&["BOT_HANDLE", "BOT_IDENTIFIER"]);
    let bot_password = crate::env::var(&["BOT_APP_PASSWORD", "BLUESKY_APP_PASSWORD"])
        .filter(|p| !p.contains("xxxx"));
    let pds_endpoint = crate::env::var_or(&["PDS_ENDPOINT"], "https://bsky.social");

    let chat_endpoint = crate::env::var_or(&["CHAT_ENDPOINT"], crate::DEFAULT_CHAT_ENDPOINT);
    let chat_token =
        crate::env::var(&["CHAT_ACCESS_TOKEN", "PDS_ACCESS_TOKEN"]).filter(|t| !t.contains("xxxx"));
    let bot_did = crate::env::var(&["BOT_DID"])
        .filter(|d| !d.contains("example") && !d.contains("skybouncerbotdid"))
        .or_else(|| config.protected_dids.iter().next().cloned());

    let bot_client_and_did = if let (Some(handle), Some(pass)) = (bot_handle, bot_password) {
        info!(handle = %handle, "Authenticating ATProto DM bot via App Password...");
        match crate::ChatClient::login_with_app_password(
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
        match crate::ChatClient::new(chat_endpoint, token) {
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
        let handler = crate::BotCommandHandler::new(std::sync::Arc::new(engine.clone()), did)
            .with_public_url(web_config.public_url);
        let poller_client = chat_client.clone();
        let cancel_bot = cancel.clone();
        join_set.spawn(async move {
            if let Err(e) = crate::run_bot_poller(
                poller_client,
                handler,
                crate::DEFAULT_BOT_POLL_INTERVAL,
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
                crate::run_bounce_alert_dispatcher(alert_client, bounce_rx, cancel_alerts).await
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
    info!("{}", crate::cli::format_final_telemetry(&stats));

    info!("🛡️ Skybouncer daemon exited cleanly.");
    Ok(())
}
