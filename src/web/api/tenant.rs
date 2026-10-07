use super::*;

/// Handler for `GET /api/me`: returns authenticated session info and permissions.
pub async fn get_current_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Json<UserSessionResponse> {
    let did_opt = extract_authenticated_caller(&headers, &state.engine);

    if let Some(did) = did_opt {
        let is_admin = state.engine.is_admin(&did);
        let mod_list_uri = state
            .engine
            .cache()
            .get_mod_list(&did)
            .ok()
            .flatten()
            .map(|c| c.list_uri);
        let is_list_blocked = state.engine.cache().is_list_blocked(&did).unwrap_or(false);

        // Dynamically resolve handle if missing or empty
        let resolved_handle = state.engine.resolve_did_to_handle(&did).await;

        let monitored_users_count = if is_admin {
            Some(state.engine.protected_dids().len())
        } else {
            None
        };

        if let Ok(Some(tenant)) = state.engine.tenant_registry().get(&did) {
            let rubric = tenant.rubric.unwrap_or_else(|| state.engine.rubric());
            let handle = tenant.handle.or(resolved_handle);
            return Json(UserSessionResponse {
                authenticated: true,
                did: Some(tenant.did),
                handle,
                is_admin,
                is_active: tenant.is_active,
                mod_list_uri,
                rubric: Some(RulesResponse {
                    prompt: rubric.prompt,
                    sensitivity: rubric.sensitivity,
                    threshold: rubric.sensitivity.threshold(),
                    bounce_duration: rubric.bounce_duration,
                    bypass_incoming_followers: rubric.bypass_incoming_followers,
                }),
                is_list_blocked,
                monitored_users_count,
            });
        }

        if state.engine.is_protected(&did) || is_admin {
            let rubric = state.engine.rubric();
            return Json(UserSessionResponse {
                authenticated: true,
                did: Some(did.clone()),
                handle: resolved_handle,
                is_admin,
                is_active: !state.engine.is_tenant_paused(&did),
                mod_list_uri,
                rubric: Some(RulesResponse {
                    prompt: rubric.prompt,
                    sensitivity: rubric.sensitivity,
                    threshold: rubric.sensitivity.threshold(),
                    bounce_duration: rubric.bounce_duration,
                    bypass_incoming_followers: rubric.bypass_incoming_followers,
                }),
                is_list_blocked,
                monitored_users_count,
            });
        }
    }

    Json(UserSessionResponse {
        authenticated: false,
        did: None,
        handle: None,
        is_admin: false,
        is_active: false,
        mod_list_uri: None,
        rubric: None,
        is_list_blocked: false,
        monitored_users_count: None,
    })
}

/// Handler for `GET /api/admin/tenants`: returns multi-tenant fleet overview (admin only).
pub async fn get_admin_tenants(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<AdminTenantsResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to access tenant fleet. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    if !state.engine.is_admin(&caller_did) {
        return Err((
            StatusCode::FORBIDDEN,
            "Administrator privileges required to access tenant fleet".to_string(),
        ));
    }

    let all_tenants = state
        .engine
        .tenant_registry()
        .list_all()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut active_count = 0;
    let mut paused_count = 0;
    let mut summaries = Vec::with_capacity(all_tenants.len());

    for t in all_tenants {
        if t.is_active {
            active_count += 1;
        } else {
            paused_count += 1;
        }

        let mod_list_uri = state
            .engine
            .cache()
            .get_mod_list(&t.did)
            .ok()
            .flatten()
            .map(|c| c.list_uri);

        let handle = t
            .handle
            .or_else(|| state.engine.cached_handle_for_did(&t.did));

        summaries.push(TenantSummary {
            did: t.did,
            handle,
            is_active: t.is_active,
            has_session: t.session.is_some(),
            mod_list_uri,
            created_at: t.created_at,
            updated_at: t.updated_at,
        });
    }

    let monitored_count = state.engine.protected_dids().len();

    Ok(Json(AdminTenantsResponse {
        total: summaries.len(),
        active_count,
        paused_count,
        monitored_count,
        tenants: summaries,
    }))
}

/// Handler for `GET /api/evaluations`: returns evaluation audit logs scoped to the authenticated caller
/// (or target DID for admins) adhering to PRD §7.1 Item 3.
pub async fn get_evaluations(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<EvaluationsQuery>,
) -> Result<Json<EvaluationsResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to access evaluation audit logs. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);
    let target_filter = if is_admin {
        query.target_did.as_deref().filter(|s| !s.trim().is_empty())
    } else {
        if let Some(requested_did) = query.target_did.as_deref().filter(|s| !s.trim().is_empty()) {
            if requested_did != caller_did {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Access denied: you may only view evaluation logs for your own account."
                        .to_string(),
                ));
            }
        }
        Some(caller_did.as_str())
    };

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let source_filter = query.source.as_deref();

    let total = state
        .engine
        .cache()
        .count_evaluation_logs(target_filter, source_filter)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let evaluations = state
        .engine
        .cache()
        .list_evaluation_logs(target_filter, source_filter, limit, offset)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(EvaluationsResponse { total, evaluations }))
}

/// Handler for `GET /api/admin/evaluations`: returns comprehensive Tier 1 & Tier 2 evaluation log (admin only).
pub async fn get_admin_evaluations(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AdminEvaluationsQuery>,
) -> Result<Json<AdminEvaluationsResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Administrator privileges required to access evaluation audit logs. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    if !state.engine.is_admin(&caller_did) {
        return Err((
            StatusCode::FORBIDDEN,
            "Administrator privileges required to access evaluation audit logs".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let target_filter = query.target_did.as_deref();
    let source_filter = query.source.as_deref();

    let total = state
        .engine
        .cache()
        .count_evaluation_logs(target_filter, source_filter)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let evaluations = state
        .engine
        .cache()
        .list_evaluation_logs(target_filter, source_filter, limit, offset)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AdminEvaluationsResponse { total, evaluations }))
}

/// Handler for `POST /api/tenant/toggle`: toggles defense active/paused state for a tenant.
pub async fn toggle_tenant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<ToggleTenantRequest>,
) -> Result<Json<ToggleTenantResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to change defense status. Please sign in with Bluesky."
                .to_string(),
        )
    })?;
    let is_admin = state.engine.is_admin(&caller_did);

    let target_did = payload.did.unwrap_or_else(|| caller_did.clone());

    if !is_admin && caller_did != target_did {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot modify other tenant status without admin privileges".to_string(),
        ));
    }

    let current_tenant = state
        .engine
        .tenant_registry()
        .get(&target_did)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let new_active = match payload.is_active {
        Some(explicit) => explicit,
        None => match current_tenant {
            Some(ref t) => !t.is_active,
            None => false,
        },
    };

    state
        .engine
        .tenant_registry()
        .set_active(&target_did, new_active)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update tenant status: {e}"),
            )
        })?;

    if (state.engine.is_admin(&target_did) || state.engine.is_single_tenant())
        && state.engine.is_protected(&target_did)
    {
        if new_active {
            state.engine.resume();
        } else {
            state.engine.pause();
        }
    }

    let status_str = if new_active { "resumed" } else { "paused" };
    Ok(Json(ToggleTenantResponse {
        success: true,
        did: target_did.clone(),
        is_active: new_active,
        message: format!("Automated defense {status_str} for {target_did}"),
    }))
}

/// Handler for `POST /api/auth/logout`: clears session cookie and returns unauthenticated state.
pub async fn logout(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(s) = cookie_header.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("skybouncer_session=") {
                    let token = val.trim();
                    if !token.is_empty() {
                        let _ = state.engine.tenant_registry().delete_web_session(token);
                    }
                }
            }
        }
    }

    let mut resp = Json(serde_json::json!({ "logged_out": true })).into_response();
    if let Ok(cookie_val) = HeaderValue::from_str(
        "skybouncer_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure",
    ) {
        resp.headers_mut().insert(header::SET_COOKIE, cookie_val);
    }
    resp
}
