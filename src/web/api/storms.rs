use super::*;
use std::str::FromStr;

use crate::dogpile::ThreadgatePolicy;
use crate::SkybouncerError;

fn resolve_storm_target_did(
    engine: &SkybouncerEngine,
    caller_did: &str,
    requested_did: Option<&str>,
    action: &str,
) -> Result<String, (StatusCode, String)> {
    let is_admin = engine.is_admin(caller_did);
    if let Some(req) = requested_did.map(str::trim).filter(|s| !s.is_empty()) {
        if req != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Access denied: you may only {action} for your own account."),
            ));
        }
        Ok(req.to_string())
    } else {
        Ok(caller_did.to_string())
    }
}

fn map_shield_error(err: SkybouncerError) -> (StatusCode, String) {
    match err {
        SkybouncerError::Config(msg) => (StatusCode::BAD_REQUEST, msg),
        SkybouncerError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// Handler for `GET /api/storms`: returns dogpile storms and current Storm Mode status.
///
/// Authentication is strictly required. Non-admin users are scoped to their own DID.
pub async fn get_storms(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<StormsQuery>,
) -> Result<Json<StormsResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to view dogpile storms. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let active_only = query.active_only.unwrap_or(false);

    let filter_did = if is_admin {
        query
            .user_did
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    } else {
        if let Some(requested) = query
            .user_did
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if requested != caller_did {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Access denied: you may only view storms for your own account.".to_string(),
                ));
            }
        }
        Some(caller_did.as_str())
    };

    let storms = state
        .engine
        .list_storms_for(filter_did, active_only, limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let storm_mode_did = filter_did.unwrap_or(&caller_did);
    let storm_mode_active = state.engine.is_storm_mode_active(storm_mode_did);

    Ok(Json(StormsResponse {
        storm_mode_active,
        storms,
    }))
}

/// Handler for `POST /api/storms/mode`: enables or disables Storm Mode for a protected account.
pub async fn toggle_storm_mode(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<StormModeRequest>,
) -> Result<Json<StormModeResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to toggle Storm Mode. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    let target_did = resolve_storm_target_did(
        &state.engine,
        &caller_did,
        payload.target_did.as_deref(),
        "toggle Storm Mode",
    )?;

    state.engine.set_storm_mode(&target_did, payload.enabled);

    Ok(Json(StormModeResponse {
        target_did: target_did.clone(),
        storm_mode_active: state.engine.is_storm_mode_active(&target_did),
    }))
}

/// Handler for `POST /api/storms/dismiss`: dismisses a storm event by database identifier.
pub async fn dismiss_storm(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<DismissStormRequest>,
) -> Result<Json<DismissStormResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to dismiss storms. Please sign in with Bluesky.".to_string(),
        )
    })?;

    if payload.storm_id <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "storm_id must be a positive integer".to_string(),
        ));
    }

    let owner_filter = if state.engine.is_admin(&caller_did) {
        None
    } else {
        Some(caller_did.as_str())
    };

    let dismissed = state
        .engine
        .dismiss_storm(owner_filter, payload.storm_id)
        .map_err(|e| match e {
            SkybouncerError::Config(msg) => (StatusCode::FORBIDDEN, msg),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    Ok(Json(DismissStormResponse {
        storm_id: payload.storm_id,
        dismissed,
    }))
}

/// Handler for `POST /api/storms/lock`: applies an `app.bsky.feed.threadgate` reply lock on PDS.
pub async fn lock_thread_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<LockThreadRequest>,
) -> Result<Json<ShieldActionResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to lock threads. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let post_uri = payload.post_uri.trim();
    if post_uri.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "post_uri cannot be empty".to_string(),
        ));
    }

    let policy = match payload
        .policy
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            ThreadgatePolicy::from_str(raw).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        }
        None => ThreadgatePolicy::FollowingOnly,
    };

    let protected_did = resolve_storm_target_did(
        &state.engine,
        &caller_did,
        payload.protected_did.as_deref(),
        "lock threads",
    )?;

    let (record_uri, canonical_post_uri) = state
        .engine
        .lock_thread(&protected_did, post_uri, policy)
        .await
        .map_err(map_shield_error)?;

    Ok(Json(ShieldActionResponse {
        success: true,
        action: "lock".to_string(),
        post_uri: canonical_post_uri,
        record_uri: Some(record_uri),
        detached_count: None,
        dry_run: state.engine.is_dry_run(),
    }))
}

/// Handler for `POST /api/storms/unlock`: removes an `app.bsky.feed.threadgate` lock from PDS.
pub async fn unlock_thread_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<UnlockThreadRequest>,
) -> Result<Json<ShieldActionResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to unlock threads. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let post_uri = payload.post_uri.trim();
    if post_uri.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "post_uri cannot be empty".to_string(),
        ));
    }

    let protected_did = resolve_storm_target_did(
        &state.engine,
        &caller_did,
        payload.protected_did.as_deref(),
        "unlock threads",
    )?;

    let canonical_post_uri = state
        .engine
        .unlock_thread(&protected_did, post_uri)
        .await
        .map_err(map_shield_error)?;

    Ok(Json(ShieldActionResponse {
        success: true,
        action: "unlock".to_string(),
        post_uri: canonical_post_uri,
        record_uri: None,
        detached_count: None,
        dry_run: state.engine.is_dry_run(),
    }))
}

/// Handler for `POST /api/storms/detach`: detaches quote-posts or disables quotes via `app.bsky.feed.postgate`.
pub async fn detach_quotes_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<DetachQuotesRequest>,
) -> Result<Json<ShieldActionResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to detach quote-posts. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    let post_uri = payload.post_uri.trim();
    if post_uri.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "post_uri cannot be empty".to_string(),
        ));
    }

    let protected_did = resolve_storm_target_did(
        &state.engine,
        &caller_did,
        payload.protected_did.as_deref(),
        "detach quote-posts",
    )?;

    let disable_all = payload.disable_all_quotes.unwrap_or(false);
    let (record_uri, canonical_post_uri, detached_count) = state
        .engine
        .detach_quotes(
            &protected_did,
            post_uri,
            payload.qt_uris.as_deref(),
            disable_all,
        )
        .await
        .map_err(map_shield_error)?;

    Ok(Json(ShieldActionResponse {
        success: true,
        action: "detach".to_string(),
        post_uri: canonical_post_uri,
        record_uri: Some(record_uri),
        detached_count: Some(detached_count),
        dry_run: state.engine.is_dry_run(),
    }))
}
