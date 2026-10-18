use super::*;

fn appview_client_from_env() -> skybase::appview::AppViewClient {
    let endpoint = crate::env::var_or(
        &["APPVIEW_ENDPOINT", "SKYBOUNCER_APPVIEW_ENDPOINT"],
        crate::enricher::DEFAULT_APPVIEW_ENDPOINT,
    );
    skybase::appview::AppViewClient::with_endpoint(endpoint)
}

/// Handler for `GET /api/resolve`: resolves a DID to a handle, or a handle to a DID.
///
/// Authentication is strictly required, as resolution may perform outbound AppView/PLC
/// lookups for cache misses.
pub async fn resolve_identity(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ResolveQuery>,
) -> Result<Json<ResolveResponse>, (StatusCode, String)> {
    extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to resolve identities. Please sign in with Bluesky."
                .to_string(),
        )
    })?;

    let raw_did = query.did.as_deref().or_else(|| {
        query
            .actor
            .as_deref()
            .filter(|s| s.trim().starts_with("did:"))
    });
    if let Some(did) = raw_did {
        let clean_did = did.trim();
        let handle = state.engine.resolve_did_to_handle(clean_did).await;
        return Ok(Json(ResolveResponse {
            did: Some(clean_did.to_string()),
            handle,
        }));
    }

    let raw_handle = query.handle.as_deref().or_else(|| {
        query
            .actor
            .as_deref()
            .filter(|s| !s.trim().starts_with("did:"))
    });
    if let Some(handle) = raw_handle.filter(|s| !s.trim().is_empty()) {
        let normalized_handle = crate::util::normalize_handle_or_default(handle);
        let did = state.engine.resolve_handle(&normalized_handle).await;
        return Ok(Json(ResolveResponse {
            did,
            handle: Some(normalized_handle),
        }));
    }

    Err((
        StatusCode::BAD_REQUEST,
        "Query parameter 'did', 'handle', or 'actor' is required".to_string(),
    ))
}

/// Handler for `GET /api/auth/typeahead`: returns live actor suggestions for the Sign-In modal.
///
/// Queries the configured AppView's `app.bsky.actor.searchActorsTypeahead` endpoint and
/// degrades gracefully to an empty list on transport or upstream errors.
pub async fn auth_typeahead(
    Query(query): Query<AuthTypeaheadQuery>,
) -> Result<Json<AuthTypeaheadResponse>, (StatusCode, String)> {
    let raw_q = query.q.as_deref().unwrap_or("").trim();
    let clean_q = crate::util::normalize_handle(raw_q).trim();
    if clean_q.len() < 2 || clean_q.len() > 128 {
        return Ok(Json(AuthTypeaheadResponse { actors: Vec::new() }));
    }

    let limit = query.limit.unwrap_or(6).clamp(1, 15);
    let client = appview_client_from_env();

    let actors = client
        .search_actors_typeahead(clean_q, limit)
        .await
        .into_iter()
        .map(|a| AuthActorSuggestion {
            did: a.did,
            handle: a.handle,
            display_name: a.display_name,
            avatar: a.avatar,
        })
        .collect();

    Ok(Json(AuthTypeaheadResponse { actors }))
}

/// Handler for `GET /api/auth/preview`: resolves a handle or DID prior to OAuth redirect
/// so the user can confirm their account and see which PDS / provider host they will be
/// redirected to ("Is this you? Continue to `<pds_host>`").
pub async fn auth_preview(
    State(state): State<ApiState>,
    Query(query): Query<AuthPreviewQuery>,
) -> Result<Json<AuthPreviewResponse>, (StatusCode, String)> {
    let stripped = query
        .handle
        .as_deref()
        .map(crate::util::normalize_handle)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Query parameter 'handle' is required".to_string(),
            )
        })?;

    let normalized = crate::util::normalize_handle_or_default(stripped);
    let assumed_bsky_social =
        !stripped.starts_with("did:") && !stripped.contains('.') && normalized != stripped;

    let resolver = state.engine.oauth_client().map_or_else(
        || skyauth::identity::IdentityResolver::new(skyauth::ssrf::SsrfFilter::default()),
        |client| client.resolver().clone(),
    );
    let mut discovered = resolver.discover_oauth_endpoints(&normalized).await.ok();
    if discovered.is_none() && !normalized.starts_with("did:") {
        if let Some(fallback_did) = state.engine.resolve_handle(&normalized).await {
            if let Ok(mut ep) = resolver.discover_oauth_endpoints(&fallback_did).await {
                if ep.handle.is_none() {
                    ep.handle = Some(normalized.clone());
                }
                discovered = Some(ep);
            }
        }
    }

    let Some(ep) = discovered else {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Could not resolve handle or PDS for '{normalized}'"),
        ));
    };
    let Some(pds_host) = ep.pds_host() else {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Could not determine PDS host for '{normalized}'"),
        ));
    };
    let auth_server_host = ep.auth_server_host().unwrap_or_else(|| pds_host.clone());
    let did = ep.did;
    let resolved_handle = ep.handle;
    let pds_endpoint = ep.pds_endpoint;

    #[derive(Deserialize)]
    struct RawProfile {
        #[serde(default)]
        handle: Option<String>,
        #[serde(default, rename = "displayName")]
        display_name: Option<String>,
        #[serde(default)]
        avatar: Option<String>,
    }

    let profile = appview_client_from_env()
        .get::<RawProfile>("app.bsky.actor.getProfile", &[("actor", did.clone())])
        .await
        .ok();

    let canonical_handle = if let Some(h) = resolved_handle {
        h
    } else if let Some(h) = profile.as_ref().and_then(|p| p.handle.clone()) {
        h
    } else if let Some(h) = state.engine.resolve_did_to_handle(&did).await {
        h
    } else {
        normalized
    };
    let _ = state
        .engine
        .cache()
        .set_handle_for_did(&did, &canonical_handle);

    Ok(Json(AuthPreviewResponse {
        did,
        handle: canonical_handle,
        display_name: profile.as_ref().and_then(|p| p.display_name.clone()),
        avatar: profile.and_then(|p| p.avatar),
        pds_endpoint,
        pds_host,
        auth_server_host,
        assumed_bsky_social,
    }))
}
