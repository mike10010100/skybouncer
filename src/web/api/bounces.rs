use super::*;

/// Handler for `GET /api/bounces`: returns recent bounced violators.
///
/// Authentication is strictly required. Non-admin users are restricted to viewing
/// only bounces on their own posts; admins may view fleet-wide or specify a target DID.
pub async fn get_bounces(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<BouncesQuery>,
) -> Result<Json<Vec<BouncedUserWithHandle>>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to view bounces. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let is_admin = state.engine.is_admin(&caller_did);

    let filter_did = if is_admin {
        query.user_did.as_deref().filter(|s| !s.trim().is_empty())
    } else {
        if let Some(requested_did) = query.user_did.as_deref().filter(|s| !s.trim().is_empty()) {
            if requested_did != caller_did {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Access denied: you may only view bounces for your own account.".to_string(),
                ));
            }
        }
        Some(caller_did.as_str())
    };

    let bounces = state
        .engine
        .list_recent_bounces_for(filter_did, limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let enriched = bounces
        .into_iter()
        .map(|b| {
            let handle = state.engine.cached_handle_for_did(&b.subject_did);
            let protected_handle = if b.protected_did.trim().is_empty() {
                None
            } else {
                let th = state.engine.target_handle(&b.protected_did);
                if !th.is_empty() {
                    Some(th)
                } else {
                    state.engine.cached_handle_for_did(&b.protected_did)
                }
            };
            BouncedUserWithHandle {
                user: b,
                handle,
                protected_handle,
            }
        })
        .collect();
    Ok(Json(enriched))
}

/// Handler for `POST /api/pardon`: unbans a user and removes their listitem from PDS.
///
/// Authentication is strictly required. Non-admin callers may only pardon accounts
/// from their own sovereign moderation list.
pub async fn pardon_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<PardonRequest>,
) -> Result<Json<PardonResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to pardon accounts. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let subject_did = payload.subject_did.trim().to_string();
    if subject_did.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "subject_did cannot be empty".to_string(),
        ));
    }

    let is_admin = state.engine.is_admin(&caller_did);
    let protected_did = if let Some(ref pd) = payload.protected_did {
        let requested = pd.trim();
        if requested != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                "Access denied: you may only pardon users from your own moderation list."
                    .to_string(),
            ));
        }
        requested.to_string()
    } else {
        caller_did.clone()
    };

    if payload.allowlist {
        match state
            .engine
            .pardon_and_allowlist(
                &protected_did,
                &subject_did,
                payload
                    .reason
                    .as_deref()
                    .or(Some("Immunized via web API pardon")),
            )
            .await
        {
            Ok(pardoned) => Ok(Json(PardonResponse {
                pardoned,
                allowlisted: true,
                subject_did: subject_did.clone(),
                message: format!(
                    "Account {subject_did} was pardoned and immunized on the allowlist."
                ),
            })),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to pardon and allowlist: {e}"),
            )),
        }
    } else {
        match state.engine.pardon_user(&protected_did, &subject_did).await {
            Ok(true) => Ok(Json(PardonResponse {
                pardoned: true,
                allowlisted: false,
                subject_did: subject_did.clone(),
                message: format!(
                    "Account {subject_did} was pardoned and removed from moderation list."
                ),
            })),
            Ok(false) => Ok(Json(PardonResponse {
                pardoned: false,
                allowlisted: false,
                subject_did: subject_did.clone(),
                message: format!("Account {subject_did} was not found in the bounced cache."),
            })),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to pardon: {e}"),
            )),
        }
    }
}

/// Handler for `GET /api/allowlist`: lists allowlisted accounts for the authenticated user or target user (admin).
pub async fn get_allowlist(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AllowlistQuery>,
) -> Result<Json<Vec<crate::modlist::AllowlistEntry>>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to view allowlist. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let target_did = if let Some(ref ud) = query.user_did {
        let requested = ud.trim();
        if requested != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                "Access denied: you may only view your own allowlist.".to_string(),
            ));
        }
        requested
    } else {
        &caller_did
    };

    match state.engine.list_allowlist(target_did) {
        Ok(mut entries) => {
            for entry in &mut entries {
                if entry.handle.is_none() {
                    entry.handle = state.engine.cached_handle_for_did(&entry.subject_did);
                }
            }
            Ok(Json(entries))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to list allowlist: {e}"),
        )),
    }
}

/// Handler for `POST /api/allowlist`: adds an account to the moderation allowlist.
pub async fn add_to_allowlist(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<AddAllowlistRequest>,
) -> Result<Json<AddAllowlistResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to update allowlist. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let protected_did = if let Some(ref pd) = payload.protected_did {
        let requested = pd.trim();
        if requested != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                "Access denied: you may only update your own allowlist.".to_string(),
            ));
        }
        requested.to_string()
    } else {
        caller_did.clone()
    };

    let raw_subject = payload.subject.trim();
    if raw_subject.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "subject cannot be empty".to_string(),
        ));
    }

    let clean = crate::util::normalize_handle(raw_subject);
    let (subject_did, resolved_handle) = if clean.starts_with("did:") {
        let handle = state.engine.resolve_did_to_handle(clean).await;
        (clean.to_string(), handle)
    } else {
        match state.engine.resolve_handle(clean).await {
            Some(did) => {
                let _ = state.engine.cache().set_handle_for_did(&did, clean);
                (did, Some(clean.to_string()))
            }
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Could not resolve handle `@{clean}` to a DID."),
                ));
            }
        }
    };

    match state.engine.add_to_allowlist(
        &protected_did,
        &subject_did,
        payload.reason.as_deref().or(Some("Added via web API")),
    ) {
        Ok(()) => Ok(Json(AddAllowlistResponse {
            subject_did: subject_did.clone(),
            handle: resolved_handle,
            message: format!("Account {subject_did} was added to the allowlist."),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to add to allowlist: {e}"),
        )),
    }
}

/// Handler for `DELETE /api/allowlist/:did`: removes an account from the moderation allowlist.
pub async fn remove_from_allowlist(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(subject_did): Path<String>,
    Query(query): Query<AllowlistQuery>,
) -> Result<Json<RemoveAllowlistResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to update allowlist. Please sign in with Bluesky.".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let protected_did = if let Some(ref ud) = query.user_did {
        let requested = ud.trim();
        if requested != caller_did && !is_admin {
            return Err((
                StatusCode::FORBIDDEN,
                "Access denied: you may only update your own allowlist.".to_string(),
            ));
        }
        requested
    } else {
        &caller_did
    };

    let clean_did = subject_did.trim();
    if clean_did.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "DID path parameter cannot be empty".to_string(),
        ));
    }

    match state.engine.remove_from_allowlist(protected_did, clean_did) {
        Ok(removed) => Ok(Json(RemoveAllowlistResponse {
            removed,
            subject_did: clean_did.to_string(),
            message: if removed {
                format!("Account {clean_did} was removed from the allowlist.")
            } else {
                format!("Account {clean_did} was not found on the allowlist.")
            },
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to remove from allowlist: {e}"),
        )),
    }
}
