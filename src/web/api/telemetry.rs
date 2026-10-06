use super::*;

/// Handler for `GET /api/status`: returns engine operational telemetry.
pub async fn get_status(State(state): State<ApiState>, headers: HeaderMap) -> Json<StatusResponse> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine);
    let is_admin = caller_did
        .as_deref()
        .is_some_and(|did| state.engine.is_admin(did));

    let stats = if caller_did.is_some() || is_admin {
        state.engine.stats().snapshot()
    } else {
        EngineStatsSnapshot::default()
    };

    let protected_dids = if is_admin {
        let mut dids: Vec<String> = state.engine.protected_dids().into_iter().collect();
        dids.sort();
        dids
    } else if let Some(ref did) = caller_did {
        if state.engine.is_protected(did) {
            vec![did.clone()]
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let rubric = if let Some(ref did) = caller_did {
        state.engine.rubric_for(did)
    } else {
        RuleRubric {
            prompt: "[Protected sovereign rubric - sign in to view]".to_string(),
            sensitivity: state.engine.rubric().sensitivity,
            bounce_duration: state.engine.rubric().bounce_duration,
            bypass_incoming_followers: state.engine.rubric().bypass_incoming_followers,
        }
    };

    let monitored_users_count = if is_admin {
        Some(state.engine.protected_dids().len())
    } else {
        None
    };

    Json(StatusResponse {
        stats,
        protected_dids,
        rubric: RulesResponse {
            prompt: rubric.prompt,
            sensitivity: rubric.sensitivity,
            threshold: rubric.sensitivity.threshold(),
            bounce_duration: rubric.bounce_duration,
            bypass_incoming_followers: rubric.bypass_incoming_followers,
        },
        dry_run: state.engine.is_dry_run(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        monitored_users_count,
    })
}

/// Handler for `GET /healthz` and `GET /api/health`: service liveness and readiness probe.
pub async fn health_check() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
}

/// Handler for `GET /metrics` and `GET /api/metrics`: exports telemetry counters and gauges in Prometheus text exposition format.
pub async fn get_prometheus_metrics(State(state): State<ApiState>) -> Response {
    let stats = state.engine.stats().snapshot();
    let protected_count = state.engine.protected_dids().len();
    let tenant_count = state.engine.tenant_registry().count().unwrap_or(0);
    let dry_run = if state.engine.is_dry_run() { 1 } else { 0 };
    let queue_depth = stats
        .eval_queue_enqueued
        .saturating_sub(stats.eval_queue_processed);

    let mut out = String::with_capacity(4096);
    use std::fmt::Write;

    let _ = writeln!(
        out,
        "# HELP skybouncer_commits_received_total Total incoming Jetstream commits processed."
    );
    let _ = writeln!(out, "# TYPE skybouncer_commits_received_total counter");
    let _ = writeln!(
        out,
        "skybouncer_commits_received_total {}",
        stats.commits_received
    );

    let _ = writeln!(out, "\n# HELP skybouncer_follow_sync_events_total Total follow/unfollow events synchronized to the follow graph.");
    let _ = writeln!(out, "# TYPE skybouncer_follow_sync_events_total counter");
    let _ = writeln!(
        out,
        "skybouncer_follow_sync_events_total {}",
        stats.follow_sync_events
    );

    let _ = writeln!(out, "\n# HELP skybouncer_interactions_matched_total Total candidate interactions extracted targeting protected users.");
    let _ = writeln!(out, "# TYPE skybouncer_interactions_matched_total counter");
    let _ = writeln!(
        out,
        "skybouncer_interactions_matched_total {}",
        stats.interactions_matched
    );

    let _ = writeln!(out, "\n# HELP skybouncer_gate_bypassed_total Interactions dropped by zero-cost pre-evaluation gates.");
    let _ = writeln!(out, "# TYPE skybouncer_gate_bypassed_total counter");
    let _ = writeln!(
        out,
        "skybouncer_gate_bypassed_total{{reason=\"self\"}} {}",
        stats.gate_bypassed_self
    );
    let _ = writeln!(
        out,
        "skybouncer_gate_bypassed_total{{reason=\"followed\"}} {}",
        stats.gate_bypassed_followed
    );
    let _ = writeln!(
        out,
        "skybouncer_gate_bypassed_total{{reason=\"follower\"}} {}",
        stats.gate_bypassed_follower
    );
    let _ = writeln!(
        out,
        "skybouncer_gate_bypassed_total{{reason=\"allowlist\"}} {}",
        stats.gate_bypassed_allowlist
    );

    let _ = writeln!(out, "\n# HELP skybouncer_candidates_evaluated_total Interactions that passed all gates and were evaluated.");
    let _ = writeln!(out, "# TYPE skybouncer_candidates_evaluated_total counter");
    let _ = writeln!(
        out,
        "skybouncer_candidates_evaluated_total {}",
        stats.candidates_evaluated
    );

    let _ = writeln!(out, "\n# HELP skybouncer_dedup_cache_hits_total Interactions dropped because author was already recorded as bounced.");
    let _ = writeln!(out, "# TYPE skybouncer_dedup_cache_hits_total counter");
    let _ = writeln!(
        out,
        "skybouncer_dedup_cache_hits_total {}",
        stats.dedup_cache_hits
    );

    let _ = writeln!(out, "\n# HELP skybouncer_eval_cache_hits_total Candidate evaluations served from SQLite TTL evaluation cache.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_cache_hits_total counter");
    let _ = writeln!(
        out,
        "skybouncer_eval_cache_hits_total {}",
        stats.eval_cache_hits
    );

    let _ = writeln!(out, "\n# HELP skybouncer_heuristic_violations_total High-confidence violations matched instantly by heuristic regex rules.");
    let _ = writeln!(out, "# TYPE skybouncer_heuristic_violations_total counter");
    let _ = writeln!(
        out,
        "skybouncer_heuristic_violations_total {}",
        stats.heuristic_violations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_model_evaluations_total Candidate interactions evaluated by primary and secondary classifiers.");
    let _ = writeln!(out, "# TYPE skybouncer_model_evaluations_total counter");
    let _ = writeln!(
        out,
        "skybouncer_model_evaluations_total {}",
        stats.model_evaluations
    );

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_tier1_evaluations_total Tier-1 primary model evaluations."
    );
    let _ = writeln!(out, "# TYPE skybouncer_tier1_evaluations_total counter");
    let _ = writeln!(
        out,
        "skybouncer_tier1_evaluations_total {}",
        stats.tier1_evaluations
    );

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_tier2_evaluations_total Tier-2 fallback model escalations."
    );
    let _ = writeln!(out, "# TYPE skybouncer_tier2_evaluations_total counter");
    let _ = writeln!(
        out,
        "skybouncer_tier2_evaluations_total {}",
        stats.tier2_evaluations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_tier2_image_escalations_total Tier-2 escalations triggered by attached images.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_tier2_image_escalations_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_tier2_image_escalations_total {}",
        stats.tier2_image_escalations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_tier2_uncertainty_escalations_total Tier-2 escalations triggered by confidence uncertainty band.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_tier2_uncertainty_escalations_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_tier2_uncertainty_escalations_total {}",
        stats.tier2_uncertainty_escalations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_eval_queue_enqueued_total Candidate interactions enqueued to background evaluation queue.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_queue_enqueued_total counter");
    let _ = writeln!(
        out,
        "skybouncer_eval_queue_enqueued_total {}",
        stats.eval_queue_enqueued
    );

    let _ = writeln!(out, "\n# HELP skybouncer_eval_queue_processed_total Candidate interactions processed by background evaluation worker.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_queue_processed_total counter");
    let _ = writeln!(
        out,
        "skybouncer_eval_queue_processed_total {}",
        stats.eval_queue_processed
    );

    let _ = writeln!(out, "\n# HELP skybouncer_eval_queue_overflows_total Candidate interactions dropped due to evaluation queue capacity saturation.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_queue_overflows_total counter");
    let _ = writeln!(
        out,
        "skybouncer_eval_queue_overflows_total {}",
        stats.eval_queue_overflows
    );

    let _ = writeln!(out, "\n# HELP skybouncer_rate_limited_evaluations_total Evaluations dropped due to per-user evaluation rate limits.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_rate_limited_evaluations_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_rate_limited_evaluations_total {}",
        stats.rate_limited_evaluations
    );

    let _ = writeln!(out, "\n# HELP skybouncer_context_enrichments_total Candidates enriched with author profile and parent post context.");
    let _ = writeln!(out, "# TYPE skybouncer_context_enrichments_total counter");
    let _ = writeln!(
        out,
        "skybouncer_context_enrichments_total {}",
        stats.context_enrichments
    );

    let _ = writeln!(out, "\n# HELP skybouncer_violations_detected_total Total violations confirmed across heuristic and model classifiers.");
    let _ = writeln!(out, "# TYPE skybouncer_violations_detected_total counter");
    let _ = writeln!(
        out,
        "skybouncer_violations_detected_total {}",
        stats.violations_detected
    );

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_bounces_total Successful listitem mutations created on sovereign PDS."
    );
    let _ = writeln!(out, "# TYPE skybouncer_bounces_total counter");
    let _ = writeln!(out, "skybouncer_bounces_total {}", stats.bounces_executed);

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_permitted_total Total interactions classified as permitted or benign."
    );
    let _ = writeln!(out, "# TYPE skybouncer_permitted_total counter");
    let _ = writeln!(out, "skybouncer_permitted_total {}", stats.permitted);

    let _ = writeln!(out, "\n# HELP skybouncer_bounces_skipped_rubric_total Violations dropped because confidence fell below rubric sensitivity threshold.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_bounces_skipped_rubric_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_bounces_skipped_rubric_total {}",
        stats.bounces_skipped_rubric
    );

    let _ = writeln!(out, "\n# HELP skybouncer_errors_total Total operational or network errors encountered during pipeline execution.");
    let _ = writeln!(out, "# TYPE skybouncer_errors_total counter");
    let _ = writeln!(out, "skybouncer_errors_total {}", stats.errors_encountered);

    let _ = writeln!(out, "\n# HELP skybouncer_sovereign_configs_synced_total Sovereign configuration hot-reload events synchronized from the firehose.");
    let _ = writeln!(
        out,
        "# TYPE skybouncer_sovereign_configs_synced_total counter"
    );
    let _ = writeln!(
        out,
        "skybouncer_sovereign_configs_synced_total {}",
        stats.sovereign_configs_synced
    );

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_protected_users Number of protected accounts currently monitored."
    );
    let _ = writeln!(out, "# TYPE skybouncer_protected_users gauge");
    let _ = writeln!(out, "skybouncer_protected_users {protected_count}");

    let _ = writeln!(out, "\n# HELP skybouncer_eval_queue_depth Current number of candidate interactions queued awaiting evaluation.");
    let _ = writeln!(out, "# TYPE skybouncer_eval_queue_depth gauge");
    let _ = writeln!(out, "skybouncer_eval_queue_depth {queue_depth}");

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_enrolled_tenants Number of sovereign multi-tenant users registered."
    );
    let _ = writeln!(out, "# TYPE skybouncer_enrolled_tenants gauge");
    let _ = writeln!(out, "skybouncer_enrolled_tenants {tenant_count}");

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_dry_run Whether dry-run shadow mode is active (1) or disabled (0)."
    );
    let _ = writeln!(out, "# TYPE skybouncer_dry_run gauge");
    let _ = writeln!(out, "skybouncer_dry_run {dry_run}");

    let _ = writeln!(
        out,
        "\n# HELP skybouncer_build_info Build and version metadata."
    );
    let _ = writeln!(out, "# TYPE skybouncer_build_info gauge");
    let _ = writeln!(
        out,
        "skybouncer_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}
