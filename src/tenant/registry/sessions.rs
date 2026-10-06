use super::*;

impl TenantRegistry {
    /// Registers a new tenant or updates an existing tenant's credentials and settings.
    ///
    /// Invalidates any cached [`PdsRepoClient`] for this tenant so new session tokens take effect.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if database persistence or JSON serialization fails.
    pub fn register_or_update(&self, tenant: &Tenant) -> Result<(), SkybouncerError> {
        let session_json = match tenant.session {
            Some(ref s) => {
                let json = serde_json::to_string(s).map_err(|e| {
                    SkybouncerError::Config(format!("Failed to serialize tenant session: {e}"))
                })?;
                Some(
                    self.cipher
                        .encrypt_with_aad(json.as_bytes(), tenant.did.as_bytes())?,
                )
            }
            None => None,
        };

        let (rubric_prompt, sensitivity, bounce_duration, bypass_followers) = match tenant.rubric {
            Some(ref r) => (
                Some(r.prompt.clone()),
                Some(r.sensitivity.to_string()),
                Some(r.bounce_duration.to_db_string()),
                Some(i64::from(r.bypass_incoming_followers)),
            ),
            None => (None, None, None, None),
        };

        let is_active_int: i64 = if tenant.is_active { 1 } else { 0 };
        let created_at_i64 = us_to_i64(tenant.created_at);
        let updated_at_i64 = us_to_i64(tenant.updated_at);
        // Only advance handle freshness when a non-empty handle is being written;
        // `None` leaves the existing mapping (and its freshness) untouched.
        let handle_updated_at_i64 = tenant
            .handle
            .as_ref()
            .filter(|h| !h.trim().is_empty())
            .map(|_| updated_at_i64);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO tenants (
                did, handle, session_json, rubric_prompt, sensitivity, bounce_duration, bypass_followers, is_active, created_at, updated_at, handle_updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(did) DO UPDATE SET
                 handle = COALESCE(excluded.handle, tenants.handle),
                 session_json = COALESCE(excluded.session_json, tenants.session_json),
                 rubric_prompt = COALESCE(excluded.rubric_prompt, tenants.rubric_prompt),
                 sensitivity = COALESCE(excluded.sensitivity, tenants.sensitivity),
                 bounce_duration = COALESCE(excluded.bounce_duration, tenants.bounce_duration),
                 bypass_followers = COALESCE(excluded.bypass_followers, tenants.bypass_followers),
                 is_active = excluded.is_active,
                 updated_at = excluded.updated_at,
                 handle_updated_at = COALESCE(excluded.handle_updated_at, tenants.handle_updated_at);",
        )?;

        stmt.execute(params![
            tenant.did,
            tenant.handle,
            session_json,
            rubric_prompt,
            sensitivity,
            bounce_duration,
            bypass_followers,
            is_active_int,
            created_at_i64,
            updated_at_i64,
            handle_updated_at_i64,
        ])?;

        // Invalidate cached PDS client on credential update
        self.pds_clients.write().remove(&tenant.did);

        Ok(())
    }

    /// Retrieves an enrolled tenant by DID.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite lookup fails.
    pub fn get(&self, did: &str) -> Result<Option<Tenant>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT did, handle, session_json, rubric_prompt, sensitivity, bounce_duration, bypass_followers, is_active, created_at, updated_at
             FROM tenants WHERE did = ?1;",
        )?;

        let res = stmt
            .query_row(params![did], |row| {
                let did: String = row.get(0)?;
                let handle: Option<String> = row.get(1)?;
                let session_json: Option<String> = row.get(2)?;
                let rubric_prompt: Option<String> = row.get(3)?;
                let sensitivity_str: Option<String> = row.get(4)?;
                let bounce_duration_str: Option<String> = row.get(5)?;
                let bypass_followers_int: Option<i64> = row.get(6)?;
                let is_active_int: i64 = row.get(7)?;
                let created_at_i64: i64 = row.get(8)?;
                let updated_at_i64: i64 = row.get(9)?;

                Ok((
                    did,
                    handle,
                    session_json,
                    rubric_prompt,
                    sensitivity_str,
                    bounce_duration_str,
                    bypass_followers_int,
                    is_active_int,
                    created_at_i64,
                    updated_at_i64,
                ))
            })
            .optional()?;

        match res {
            Some((
                did,
                handle,
                session_json,
                rubric_prompt,
                sensitivity_str,
                bounce_duration_str,
                bypass_followers_int,
                is_active_int,
                created_at_i64,
                updated_at_i64,
            )) => {
                let session: Option<OAuthSession> = match session_json {
                    Some(ref raw) if !raw.trim().is_empty() => {
                        let decrypted = self
                            .cipher
                            .decrypt_or_passthrough_with_aad(raw, did.as_bytes())
                            .map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    2,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })?;
                        let session: OAuthSession =
                            serde_json::from_str(&decrypted).map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    2,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })?;
                        Some(session)
                    }
                    _ => None,
                };

                let bounce_duration =
                    crate::classifier::bounce_duration_from_db(bounce_duration_str.as_deref());

                let bypass_incoming_followers = bypass_followers_int.is_none_or(|v| v != 0);

                let rubric: Option<RuleRubric> = match (rubric_prompt, sensitivity_str) {
                    (Some(prompt), Some(sens_str)) => {
                        let sens = crate::classifier::sensitivity_from_db(Some(&sens_str));
                        Some(RuleRubric {
                            prompt,
                            sensitivity: sens,
                            bounce_duration,
                            bypass_incoming_followers,
                        })
                    }
                    (Some(prompt), None) => Some(
                        RuleRubric::parse(&prompt)
                            .map(|mut r| {
                                r.bounce_duration = bounce_duration;
                                r.bypass_incoming_followers = bypass_incoming_followers;
                                r
                            })
                            .unwrap_or(RuleRubric {
                                prompt,
                                sensitivity: crate::classifier::Sensitivity::Medium,
                                bounce_duration,
                                bypass_incoming_followers,
                            }),
                    ),
                    _ => None,
                };

                let created_at = i64_to_us(created_at_i64);
                let updated_at = i64_to_us(updated_at_i64);

                Ok(Some(Tenant {
                    did,
                    handle,
                    session,
                    rubric,
                    is_active: is_active_int != 0,
                    created_at,
                    updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// Attaches an [`AtprotoOAuthClient`] for background session token refreshes.
    pub fn set_oauth_client(&self, client: Arc<AtprotoOAuthClient>) {
        *self.oauth_client.write() = Some(client);
        self.pds_clients.write().clear();
    }

    /// Returns a clone of the configured [`AtprotoOAuthClient`], if set.
    #[must_use]
    pub fn oauth_client(&self) -> Option<Arc<AtprotoOAuthClient>> {
        self.oauth_client.read().clone()
    }

    /// Updates the stored [`OAuthSession`] for an enrolled tenant in SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if serialization or SQLite execution fails.
    pub fn update_session(
        &self,
        did: &str,
        session: &OAuthSession,
    ) -> Result<bool, SkybouncerError> {
        let serialized = serde_json::to_string(session).map_err(|e| {
            SkybouncerError::Database(format!("Failed to serialize OAuthSession for {did}: {e}"))
        })?;
        let encrypted = self
            .cipher
            .encrypt_with_aad(serialized.as_bytes(), did.as_bytes())?;
        let now_us = current_time_us();
        let conn = self.conn.lock();
        let rows = conn
            .execute(
                "UPDATE tenants SET session_json = ?1, updated_at = ?2 WHERE did = ?3",
                params![encrypted, now_us, did],
            )
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to update session for {did}: {e}"))
            })?;
        self.pds_clients.write().remove(did);
        Ok(rows > 0)
    }

    /// Creates a cryptographically secure web session token for an authenticated user.
    ///
    /// The token is 256 bits of high-entropy randomness generated via CSPRNG.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] or [`SkybouncerError::Config`] if parameters or storage fail.
    pub fn create_web_session(&self, did: &str, ttl: Duration) -> Result<String, SkybouncerError> {
        let clean_did = did.trim();
        if clean_did.is_empty() {
            return Err(SkybouncerError::Config(
                "DID cannot be empty for web session".to_string(),
            ));
        }

        // Generate 256 bits of cryptographic entropy (43-char URL-safe base64 string)
        let token = skyauth::pkce::PkcePair::generate().verifier;
        let token_hash = hash_session_token(&token);
        let now_us = current_time_us();
        let ttl_us = u64::try_from(ttl.as_micros()).unwrap_or(u64::MAX / 2);
        let expires_at_us = now_us.saturating_add(ttl_us);

        let created_at_i64 = us_to_i64(now_us);
        let expires_at_i64 = i64::try_from(expires_at_us).unwrap_or(i64::MAX);

        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO web_sessions (token, did, created_at, expires_at) VALUES (?1, ?2, ?3, ?4);",
            params![token_hash, clean_did, created_at_i64, expires_at_i64],
        )
        .map_err(|e| SkybouncerError::Database(format!("Failed to store web session: {e}")))?;

        Ok(token)
    }

    /// Validates a web session token and returns the authenticated DID if valid.
    ///
    /// If the token is expired, it is deleted and `None` is returned.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn validate_web_session(&self, token: &str) -> Result<Option<String>, SkybouncerError> {
        let clean_token = token.trim();
        if clean_token.is_empty() {
            return Ok(None);
        }

        let token_hash = hash_session_token(clean_token);
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT did, expires_at FROM web_sessions WHERE token = ?1 OR token = ?2;",
        )?;

        let row = stmt
            .query_row(params![token_hash, clean_token], |row| {
                let did: String = row.get(0)?;
                let expires_at: i64 = row.get(1)?;
                Ok((did, expires_at))
            })
            .optional()?;

        match row {
            Some((did, expires_at)) => {
                if now_i64 > expires_at {
                    // Expired, purge token
                    let _ = conn.execute(
                        "DELETE FROM web_sessions WHERE token = ?1 OR token = ?2;",
                        params![token_hash, clean_token],
                    );
                    Ok(None)
                } else {
                    Ok(Some(did))
                }
            }
            None => Ok(None),
        }
    }

    /// Invalidates a web session token on logout.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if deletion fails.
    pub fn delete_web_session(&self, token: &str) -> Result<bool, SkybouncerError> {
        let clean_token = token.trim();
        if clean_token.is_empty() {
            return Ok(false);
        }

        let token_hash = hash_session_token(clean_token);
        let conn = self.conn.lock();
        let rows = conn
            .execute(
                "DELETE FROM web_sessions WHERE token = ?1 OR token = ?2;",
                params![token_hash, clean_token],
            )
            .map_err(|e| SkybouncerError::Database(format!("Failed to delete web session: {e}")))?;

        Ok(rows > 0)
    }

    /// Prunes expired web sessions from the database.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if prune fails.
    pub fn prune_expired_web_sessions(&self) -> Result<usize, SkybouncerError> {
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let conn = self.conn.lock();
        let rows = conn
            .execute(
                "DELETE FROM web_sessions WHERE expires_at < ?1;",
                params![now_i64],
            )
            .map_err(|e| SkybouncerError::Database(format!("Failed to prune web sessions: {e}")))?;

        Ok(rows)
    }

    /// Resolves or initializes a dedicated [`PdsRepoClient`] for an enrolled tenant using their DPoP session.
    ///
    /// If a client was already constructed for this DID and its session is still valid, it is returned from cache immediately (<50ns).
    /// If the session is expired or expiring within 60 seconds, it is automatically refreshed using the configured [`AtprotoOAuthClient`].
    /// If the tenant has no stored session, returns `Ok(None)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if client creation or database lookup fails.
    pub async fn get_pds_client(
        &self,
        did: &str,
        oauth_client: Option<&Arc<AtprotoOAuthClient>>,
    ) -> Result<Option<Arc<PdsRepoClient>>, SkybouncerError> {
        // 1. Fast path: check in-memory cache if the cached client session is still valid
        {
            let guard = self.pds_clients.read();
            if let Some(client) = guard.get(did) {
                if !client
                    .session()
                    .is_expired_with_leeway(Duration::from_secs(60))
                {
                    return Ok(Some(Arc::clone(client)));
                }
            }
        }

        // 2. Acquire per-DID serialization lock to eliminate concurrent refresh races (single-flight)
        let _refresh_guard = self.refresh_locks.shard_for(did).lock().await;

        // 3. Double-check cache under the lock: another task may have refreshed while we waited
        {
            let guard = self.pds_clients.read();
            if let Some(client) = guard.get(did) {
                if !client
                    .session()
                    .is_expired_with_leeway(Duration::from_secs(60))
                {
                    return Ok(Some(Arc::clone(client)));
                }
            }
        }

        // 4. Load tenant from database
        let tenant = match self.get(did)? {
            Some(t) => t,
            None => return Ok(None),
        };

        let mut session = match tenant.session {
            Some(s) => s,
            None => return Ok(None),
        };

        // 3. Resolve OAuth client
        let resolved_oauth_client = oauth_client
            .cloned()
            .or_else(|| self.oauth_client.read().clone());

        // 4. If session is expired or close to expiring, auto-refresh via OAuth
        if session.is_expired_with_leeway(Duration::from_secs(60)) {
            let oc = match resolved_oauth_client.as_ref() {
                Some(oc) => oc,
                None => {
                    self.pds_clients.write().remove(did);
                    return Err(SkybouncerError::Auth(format!(
                        "OAuth session for tenant {did} is expired and no OAuth client is configured"
                    )));
                }
            };

            if session.refresh_token().is_none() {
                self.pds_clients.write().remove(did);
                return Err(SkybouncerError::Auth(format!(
                    "OAuth session for tenant {did} is expired and has no refresh token"
                )));
            }

            tracing::info!(
                did = %did,
                "Refreshing expired ATProto OAuth session for tenant PDS client"
            );
            match oc.refresh_session(&mut session).await {
                Ok(()) => {
                    tracing::info!(
                        did = %did,
                        "Successfully refreshed ATProto OAuth session for tenant"
                    );
                    if let Err(e) = self.update_session(did, &session) {
                        tracing::warn!(
                            did = %did,
                            error = %e,
                            "Failed to persist refreshed session to SQLite database"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        "Failed to refresh ATProto OAuth session using refresh token"
                    );
                    self.pds_clients.write().remove(did);
                    return Err(SkybouncerError::Auth(format!(
                        "Failed to refresh expired OAuth session for tenant {did}: {e}"
                    )));
                }
            }
        }

        if session.is_expired() {
            self.pds_clients.write().remove(did);
            return Err(SkybouncerError::Auth(format!(
                "OAuth session for tenant {did} remains expired"
            )));
        }

        // 5. Construct PdsRepoClient
        let session_arc = Arc::new(session);
        let client = match resolved_oauth_client {
            Some(ref oc) => PdsRepoClient::new(session_arc, Arc::clone(oc)).map_err(|e| {
                SkybouncerError::Config(format!(
                    "Failed to create PDS client with OAuth client for {did}: {e}"
                ))
            })?,
            None => PdsRepoClient::from_session(session_arc).map_err(|e| {
                SkybouncerError::Config(format!(
                    "Failed to create PDS client from session for {did}: {e}"
                ))
            })?,
        };

        let client_arc = Arc::new(client);
        self.pds_clients
            .write()
            .insert(did.to_string(), Arc::clone(&client_arc));

        Ok(Some(client_arc))
    }
}
