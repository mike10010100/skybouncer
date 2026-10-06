use super::*;

/// Extracts the verified authenticated caller DID strictly from a valid session token in Cookie or Authorization header.
///
/// Unsigned `x-skybouncer-did` headers and unverified cookie DIDs are strictly rejected.
pub fn extract_authenticated_caller(
    headers: &HeaderMap,
    engine: &SkybouncerEngine,
) -> Option<String> {
    // 1. Check Authorization: Bearer <session_token>
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(s) = auth_header.to_str() {
            let trimmed = s.trim();
            if let Some(token) = trimmed.strip_prefix("Bearer ") {
                let token = token.trim();
                if !token.is_empty() {
                    if let Ok(Some(did)) = engine.tenant_registry().validate_web_session(token) {
                        return Some(did);
                    }
                }
            }
        }
    }

    // 2. Check Cookie: skybouncer_session=<session_token>
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(s) = cookie_header.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("skybouncer_session=") {
                    let token = val.trim();
                    if !token.is_empty() {
                        if let Ok(Some(did)) = engine.tenant_registry().validate_web_session(token)
                        {
                            return Some(did);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Resolves the authenticated caller identity and enforces authorization on the target DID for rules endpoints.
///
/// # Errors
/// Returns `StatusCode::UNAUTHORIZED` if caller is not authenticated,
/// or `StatusCode::FORBIDDEN` if caller attempts to access another user's rules without admin privileges.
pub fn resolve_rules_target_did(
    engine: &SkybouncerEngine,
    headers: &HeaderMap,
    query_did: Option<&str>,
    action_desc: &str,
) -> Result<String, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(headers, engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            format!("Authentication required to {action_desc}. Please sign in with Bluesky."),
        )
    })?;

    let is_admin = engine.is_admin(&caller_did);
    let is_enrolled = engine.is_enrolled(&caller_did);
    let is_protected = engine.is_protected(&caller_did);

    if !is_admin && !is_enrolled && !is_protected {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("Account {caller_did} is not enrolled or recognized. Please sign in."),
        ));
    }

    // Target DID: if caller requests a different target, must be admin
    if let Some(target) = query_did.map(str::trim).filter(|s| !s.is_empty()) {
        if target != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Access denied: you may only {action_desc} for your own account."),
            ));
        }
        Ok(target.to_string())
    } else {
        Ok(caller_did)
    }
}

/// Handler for `GET /api/rules`: returns active moderation rubric for authenticated caller.
pub async fn get_rules(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SessionQuery>,
) -> Result<Json<RulesResponse>, (StatusCode, String)> {
    let target_did = resolve_rules_target_did(
        &state.engine,
        &headers,
        query.did.as_deref(),
        "view moderation rules",
    )?;

    let rubric = state.engine.rubric_for(&target_did);
    Ok(Json(RulesResponse {
        prompt: rubric.prompt,
        sensitivity: rubric.sensitivity,
        threshold: rubric.sensitivity.threshold(),
        bounce_duration: rubric.bounce_duration,
        bypass_incoming_followers: rubric.bypass_incoming_followers,
    }))
}

/// Handler for `POST /api/rules`: updates the active moderation rubric for authenticated caller and persists to sovereign PDS.
pub async fn update_rules(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SessionQuery>,
    Json(payload): Json<UpdateRulesRequest>,
) -> Result<Json<RulesResponse>, (StatusCode, String)> {
    let target_did = resolve_rules_target_did(
        &state.engine,
        &headers,
        query.did.as_deref(),
        "modify moderation rules",
    )?;

    let mut rubric = state.engine.rubric_for(&target_did);

    if let Some(prompt) = payload.prompt {
        let trimmed = prompt.trim();
        if trimmed.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Prompt cannot be empty".to_string(),
            ));
        }
        let parsed = RuleRubric::parse(trimmed)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid rubric: {e}")))?;
        rubric.prompt = parsed.prompt;
    }

    if let Some(sens) = payload.sensitivity {
        rubric.sensitivity = sens;
    }

    if let Some(dur) = payload.bounce_duration {
        rubric.bounce_duration = dur;
    }

    if let Some(bypass) = payload.bypass_incoming_followers {
        rubric.bypass_incoming_followers = bypass;
    }

    // Apply the incoming-follower bypass toggle to the in-memory gate immediately so the
    // change takes effect without a restart (and regardless of enrollment state).
    state
        .engine
        .set_bypass_incoming_followers(&target_did, rubric.bypass_incoming_followers);

    let is_enrolled = state
        .engine
        .tenant_registry()
        .is_enrolled(&target_did)
        .unwrap_or(false);
    if is_enrolled {
        state
            .engine
            .tenant_registry()
            .update_rubric(&target_did, &rubric)
            .map_err(|e| {
                tracing::error!(did = %target_did, error = %e, "Failed to persist updated rubric");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to persist rubric: {e}"),
                )
            })?;
    } else if state.engine.is_protected(&target_did) {
        // Only non-enrolled protected accounts update the default engine rubric
        state.engine.set_rubric(rubric.clone());
    }

    // Asynchronously persist updated rubric to user's sovereign PDS repository
    let eng = state.engine.clone();
    let publish_did = target_did.clone();
    tokio::spawn(async move {
        if let Err(e) = eng.publish_sovereign_config(&publish_did).await {
            tracing::warn!(did = %publish_did, error = %e, "Failed to publish sovereign config to PDS in background task");
        }
    });

    Ok(Json(RulesResponse {
        prompt: rubric.prompt,
        sensitivity: rubric.sensitivity,
        threshold: rubric.sensitivity.threshold(),
        bounce_duration: rubric.bounce_duration,
        bypass_incoming_followers: rubric.bypass_incoming_followers,
    }))
}
