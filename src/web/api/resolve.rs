use super::*;

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
        let clean_handle = crate::util::normalize_handle(handle);
        let did = state.engine.resolve_handle(clean_handle).await;
        return Ok(Json(ResolveResponse {
            did,
            handle: Some(clean_handle.to_string()),
        }));
    }

    Err((
        StatusCode::BAD_REQUEST,
        "Query parameter 'did', 'handle', or 'actor' is required".to_string(),
    ))
}
