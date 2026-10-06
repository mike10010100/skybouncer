use super::*;

/// Maximum size of a URL-fetched simulation image (2 MiB).
const MAX_SIMULATION_IMAGE_BYTES: usize = 2 * 1024 * 1024;

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

/// Converts an engine [`crate::engine::simulate::SimulateTierStage`] into the wire [`TierStageDetail`].
fn into_tier_detail(
    stage: Option<crate::engine::simulate::SimulateTierStage>,
) -> Option<TierStageDetail> {
    stage.map(|s| TierStageDetail {
        stage_name: s.stage_name,
        model: s.model,
        status: s.status,
        violates: s.violates,
        category: s.category,
        confidence: s.confidence,
        reason: s.reason,
    })
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

    let text = payload.text.trim().to_string();
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

    // Resolve an optional image. A URL is fetched through the SSRF filter and
    // re-encoded; a provided base64 payload is used as-is.
    let (image_base64, fetched_url_image) =
        if let Some(b64) = payload.image_base64.filter(|s| !s.trim().is_empty()) {
            (Some(b64), false)
        } else if let Some(url) = payload.image_url.filter(|s| !s.trim().is_empty()) {
            let bytes = fetch_simulation_image(&url).await?;
            use base64::Engine;
            (
                Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
                true,
            )
        } else {
            (None, false)
        };

    let inputs = crate::engine::simulate::SimulationInputs::new(text, author_did, target_did)
        .with_image(image_base64, fetched_url_image)
        .with_persist_log(true);

    let result = state.engine.run_simulation(inputs).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Classification failed: {e}"),
        )
    })?;

    Ok(Json(SimulateResponse {
        violates: result.violates,
        category: result.category,
        confidence: result.confidence,
        reason: result.reason,
        evaluator: result.evaluator,
        meets_threshold: result.meets_threshold,
        threshold: result.threshold,
        images_evaluated: result.images_evaluated,
        tier1: into_tier_detail(result.tier1),
        tier2: into_tier_detail(result.tier2),
    }))
}
