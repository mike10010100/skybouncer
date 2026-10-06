use super::*;

/// Fetches a simulation image through `skyauth`'s SSRF-hardened HTTP client, which
/// enforces scheme/host/IP validation, DNS pinning, redirect bounds, and a body size cap.
async fn fetch_simulation_image(url_str: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    skyauth::ssrf::SsrfFilter::default()
        .safe_get(url_str, MAX_SIMULATION_IMAGE_BYTES)
        .await
        .map_err(|e| map_ssrf_error(&e))
}

/// Maps an [`skyauth::SsrfError`] to an HTTP status and client-facing message.
fn map_ssrf_error(err: &skyauth::SsrfError) -> (StatusCode, String) {
    use skyauth::SsrfError;
    match err {
        SsrfError::InsecureScheme(_) | SsrfError::InvalidUrl(_) => {
            (StatusCode::BAD_REQUEST, format!("Invalid image URL: {err}"))
        }
        SsrfError::BlockedIp(_) | SsrfError::BlockedHost(_) => {
            (StatusCode::BAD_REQUEST, format!("SSRF protection: {err}"))
        }
        SsrfError::ResponseTooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("Simulation image exceeds limit: {err}"),
        ),
        SsrfError::DnsResolutionFailed(_)
        | SsrfError::TooManyRedirects
        | SsrfError::HttpStatus(_, _)
        | SsrfError::Http(_)
        | SsrfError::Io(_)
        | SsrfError::Json(_) => (
            StatusCode::BAD_GATEWAY,
            format!("Failed to fetch simulation image: {err}"),
        ),
    }
}

/// Handler for `POST /api/simulate`: runs a dry-run evaluation on sample text and optional images.
pub async fn simulate_interaction(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to run evaluation simulation".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);

    let text = payload.text.trim();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Text cannot be empty".to_string()));
    }

    let author_did = payload
        .author_did
        .unwrap_or_else(|| "did:plc:sample-author".to_string());
    let target_did = if is_admin {
        payload.target_did.unwrap_or_else(|| caller_did.clone())
    } else {
        caller_did.clone()
    };

    let mut image_cids = Vec::new();
    let mut images_base64 = Vec::new();

    if let Some(b64) = payload.image_base64.filter(|s| !s.trim().is_empty()) {
        images_base64.push(b64);
        image_cids.push("simulate-base64-image".to_string());
    } else if let Some(url) = payload.image_url.filter(|s| !s.trim().is_empty()) {
        let bytes = fetch_simulation_image(&url).await?;
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        images_base64.push(encoded);
        image_cids.push("simulate-url-image".to_string());
    }

    let images_evaluated = images_base64.len();
    let enriched_context = if !images_base64.is_empty() {
        let mut ctx = crate::enricher::EnrichedContext::empty();
        ctx.images_base64 = images_base64;
        Some(ctx)
    } else {
        None
    };

    let rubric = state.engine.rubric_for(&target_did);
    let threshold = rubric.sensitivity.threshold();

    let synthetic_interaction =
        Interaction::synthetic(&author_did, &target_did, text, InteractionType::DirectReply)
            .with_post_uri("at://did:plc:sample/app.bsky.feed.post/sample123")
            .with_post_cid("bafysample123")
            .with_images(image_cids, Vec::new())
            .with_enriched_context_opt(enriched_context)
            .with_rubric(rubric.clone());

    // 1. Check zero-cost heuristic pre-filter
    let heuristic_verdict = state
        .engine
        .heuristic_classifier()
        .evaluate(&synthetic_interaction);

    if heuristic_verdict.is_violation() {
        if let Verdict::Violation {
            category,
            confidence,
            reason,
        } = heuristic_verdict
        {
            let meets_threshold = rubric.meets_threshold(&category, confidence);
            let tier1 = TierStageDetail {
                stage_name: "Tier 1 • System-1 Fast Text".to_string(),
                model: "nimble".to_string(),
                status: "bypassed".to_string(),
                violates: false,
                category: None,
                confidence: 0.0,
                reason: "Bypassed: Heuristic regex pre-filter matched instantly (0ms)".to_string(),
            };
            let tier2 = TierStageDetail {
                stage_name: "Tier 2 • System-2 Fallback".to_string(),
                model: "gemma4:12b".to_string(),
                status: "bypassed".to_string(),
                violates: false,
                category: None,
                confidence: 0.0,
                reason: "Bypassed: Heuristic regex pre-filter matched instantly (0ms)".to_string(),
            };
            let target_handle = state.engine.target_handle(&target_did);

            if let Err(e) =
                state
                    .engine
                    .cache()
                    .record_evaluation_log(&NewEvaluationLog::heuristic(
                        &synthetic_interaction,
                        &format!("at://{author_did}/app.bsky.feed.post/simulated"),
                        &Verdict::Violation {
                            category: category.clone(),
                            confidence: 1.0,
                            reason: reason.clone(),
                        },
                        EvaluationLogContext {
                            source: "simulation",
                            outcome: "Simulated: Would Bounce (Regex Pre-filter)",
                        },
                        "simulated-test.bsky.social".to_string(),
                        target_handle,
                    ))
            {
                tracing::warn!(error = %e, "Failed to record simulated evaluation log");
            }

            return Ok(Json(SimulateResponse {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                reason,
                evaluator: "heuristic_prefilter".to_string(),
                meets_threshold,
                threshold,
                images_evaluated,
                tier1: Some(tier1),
                tier2: Some(tier2),
            }));
        }
    }

    // 2. Primary classifier evaluation (Tiered Jev / Multimodal Fallback)
    let detailed = match state
        .engine
        .primary_classifier()
        .classify_detailed(&synthetic_interaction)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Classification failed: {e}"),
            ));
        }
    };

    let tier1_violates = detailed.primary_verdict.is_violation();
    let tier1_cat = detailed.primary_verdict.category().map(|c| c.to_string());
    let tier1_conf = detailed.primary_verdict.confidence().unwrap_or(0.0);
    let tier1_reason = detailed.primary_verdict.reason().to_string();
    let tier1_status = if detailed.escalated {
        "escalated".to_string()
    } else {
        "resolved".to_string()
    };

    let tier1 = TierStageDetail {
        stage_name: "Tier 1 • System-1 Fast Text".to_string(),
        model: detailed.primary_model.clone(),
        status: tier1_status,
        violates: tier1_violates,
        category: tier1_cat.clone(),
        confidence: tier1_conf,
        reason: tier1_reason.clone(),
    };

    let tier2 = if detailed.escalated {
        if let Some(ref fb) = detailed.fallback_verdict {
            TierStageDetail {
                stage_name: "Tier 2 • System-2 Fallback".to_string(),
                model: detailed
                    .fallback_model
                    .clone()
                    .unwrap_or_else(|| "fallback".to_string()),
                status: "resolved".to_string(),
                violates: fb.is_violation(),
                category: fb.category().map(|c| c.to_string()),
                confidence: fb.confidence().unwrap_or(0.0),
                reason: fb.reason().to_string(),
            }
        } else {
            TierStageDetail {
                stage_name: "Tier 2 • System-2 Fallback".to_string(),
                model: detailed
                    .fallback_model
                    .clone()
                    .unwrap_or_else(|| "fallback".to_string()),
                status: "escalated".to_string(),
                violates: false,
                category: None,
                confidence: 0.0,
                reason: detailed.escalation_reason.clone().unwrap_or_default(),
            }
        }
    } else {
        TierStageDetail {
            stage_name: "Tier 2 • System-2 Fallback".to_string(),
            model: detailed
                .fallback_model
                .clone()
                .unwrap_or_else(|| "fallback".to_string()),
            status: "bypassed".to_string(),
            violates: false,
            category: None,
            confidence: 0.0,
            reason: detailed.escalation_reason.clone().unwrap_or_else(|| {
                "Bypassed: Tier 1 resolved decisively (System-2 GPU inference spared)".to_string()
            }),
        }
    };

    let target_handle = state.engine.target_handle(&target_did);

    let sim_outcome_str = match &detailed.final_verdict {
        Verdict::Violation {
            category,
            confidence,
            ..
        } => {
            if rubric.meets_threshold(category, *confidence) {
                "Simulated: Would Bounce"
            } else {
                "Simulated: Below Rubric Threshold"
            }
        }
        Verdict::Permitted { .. } => "Simulated: Permitted",
    };

    if let Err(e) = state
        .engine
        .cache()
        .record_evaluation_log(&NewEvaluationLog::from_tiered(
            &synthetic_interaction,
            &format!("at://{author_did}/app.bsky.feed.post/simulated"),
            &detailed,
            &detailed.final_verdict,
            EvaluationLogContext {
                source: "simulation",
                outcome: sim_outcome_str,
            },
            "simulated-test.bsky.social".to_string(),
            target_handle,
        ))
    {
        tracing::warn!(error = %e, "Failed to record simulated evaluation log");
    }

    match detailed.final_verdict {
        Verdict::Violation {
            category,
            confidence,
            reason,
        } => {
            let meets_threshold = rubric.meets_threshold(&category, confidence);
            let evaluator = if reason.contains("uncertainty escalation") {
                "fallback_uncertainty_classifier".to_string()
            } else if reason.contains("Fallback") || reason.contains("Tiered") {
                "fallback_vision_classifier".to_string()
            } else if images_evaluated > 0 {
                "primary_classifier (multimodal)".to_string()
            } else {
                "primary_classifier".to_string()
            };
            Ok(Json(SimulateResponse {
                violates: true,
                category: Some(category.to_string()),
                confidence,
                reason,
                evaluator,
                meets_threshold,
                threshold,
                images_evaluated,
                tier1: Some(tier1),
                tier2: Some(tier2),
            }))
        }
        Verdict::Permitted { reason, confidence } => {
            let evaluator = if reason.contains("uncertainty escalation") {
                "fallback_uncertainty_classifier".to_string()
            } else if reason.contains("Fallback") || reason.contains("Tiered") {
                "fallback_vision_classifier".to_string()
            } else if images_evaluated > 0 {
                "primary_classifier (multimodal)".to_string()
            } else {
                "primary_classifier".to_string()
            };
            Ok(Json(SimulateResponse {
                violates: false,
                category: None,
                confidence: confidence.unwrap_or(0.05),
                reason,
                evaluator,
                meets_threshold: false,
                threshold,
                images_evaluated,
                tier1: Some(tier1),
                tier2: Some(tier2),
            }))
        }
    }
}
