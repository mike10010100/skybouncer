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
                 handle_updated_at = COALESCE(excluded.handle_updated_at, tenants.handle_updated_at),
                 reauth_required = CASE WHEN excluded.session_json IS NOT NULL THEN 0 ELSE tenants.reauth_required END,
                 reauth_notified_at = CASE WHEN excluded.session_json IS NOT NULL THEN NULL ELSE tenants.reauth_notified_at END,
                 reauth_notify_count = CASE WHEN excluded.session_json IS NOT NULL THEN 0 ELSE tenants.reauth_notify_count END;",
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
        let now_us = us_to_i64(current_time_us());
        let conn = self.conn.lock();
        let rows = conn
            .execute(
                "UPDATE tenants SET session_json = ?1, updated_at = ?2, reauth_required = 0, reauth_notified_at = NULL, reauth_notify_count = 0 WHERE did = ?3",
                params![encrypted, now_us, did],
            )
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to update session for {did}: {e}"))
            })?;
        self.pds_clients.write().remove(did);
        Ok(rows > 0)
    }

    /// Loads the persistent confidential-client ES256 signing key (`private_key_jwt`) from
    /// environment or SQLite (`oauth_client_keys`), generating and encrypting a fresh key
    /// if none is persisted yet.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if key parsing, encryption, or database persistence fails.
    pub fn load_or_create_oauth_client_key(
        &self,
    ) -> Result<skyauth::dpop::DPoPKey, SkybouncerError> {
        if let Some(raw_env) = crate::env::var(&[
            "OAUTH_CLIENT_PRIVATE_KEY",
            "SKYBOUNCER_OAUTH_CLIENT_PRIVATE_KEY",
        ]) {
            let trimmed = raw_env.trim();
            let parsed = if trimmed.starts_with("-----BEGIN") {
                skyauth::dpop::DPoPKey::from_pkcs8_pem(trimmed)
            } else {
                skyauth::dpop::DPoPKey::from_bytes_b64(trimmed)
            };
            return parsed.map_err(|e| {
                SkybouncerError::Config(format!("Invalid OAUTH_CLIENT_PRIVATE_KEY: {e}"))
            });
        }

        const PRIMARY_KEY_ID: &str = "primary";
        const PRIMARY_KEY_AAD: &[u8] = b"oauth_client_key:primary";

        let conn = self.conn.lock();
        let existing: Option<String> = conn
            .query_row(
                "SELECT encrypted_key FROM oauth_client_keys WHERE key_id = ?1 LIMIT 1;",
                params![PRIMARY_KEY_ID],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(raw) = existing {
            let decrypted = self
                .cipher
                .decrypt_or_passthrough_with_aad(&raw, PRIMARY_KEY_AAD)?;
            return skyauth::dpop::DPoPKey::from_bytes_b64(decrypted.trim()).map_err(|e| {
                SkybouncerError::Auth(format!("Failed to parse stored OAuth client key: {e}"))
            });
        }

        let generated = skyauth::dpop::DPoPKey::generate();
        let b64_key = generated.to_bytes_b64();
        let encrypted = self
            .cipher
            .encrypt_with_aad(b64_key.as_bytes(), PRIMARY_KEY_AAD)?;
        let now_i64 = us_to_i64(current_time_us());

        conn.execute(
            "INSERT INTO oauth_client_keys (key_id, encrypted_key, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key_id) DO NOTHING;",
            params![PRIMARY_KEY_ID, encrypted, now_i64],
        )?;

        Ok(generated)
    }

    /// Returns `true` if a token refresh error represents a permanent credential revocation or
    /// expiration (`invalid_grant`, `unauthorized_client`, `invalid_client`, or missing refresh token)
    /// that requires user re-authentication, as opposed to a transient network or 5xx error.
    #[must_use]
    pub fn is_permanent_oauth_refresh_error(err: &skyauth::error::AtprotoOAuthError) -> bool {
        use skyauth::error::{AtprotoOAuthError, TokenError};
        match err {
            AtprotoOAuthError::Token(TokenError::MissingRefreshToken) => true,
            AtprotoOAuthError::Token(TokenError::RequestFailed { error, .. }) => matches!(
                error.to_ascii_lowercase().as_str(),
                "invalid_grant" | "unauthorized_client" | "invalid_client"
            ),
            _ => false,
        }
    }

    /// Marks an enrolled tenant as requiring OAuth re-authentication (`reauth_required = 1`).
    ///
    /// Returns `Ok(true)` if the tenant is active and has not yet been sent a re-authentication DM
    /// (`reauth_notified_at IS NULL`), or `Ok(false)` if already notified or inactive.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite update fails.
    pub fn mark_reauth_required(&self, did: &str) -> Result<bool, SkybouncerError> {
        let now_i64 = us_to_i64(current_time_us());
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE tenants SET reauth_required = 1, updated_at = ?1 WHERE did = ?2;",
            params![now_i64, did],
        )?;

        let row: Option<(i64, Option<i64>)> = conn
            .query_row(
                "SELECT is_active, reauth_notified_at FROM tenants WHERE did = ?1 LIMIT 1;",
                params![did],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        Ok(matches!(row, Some((active, None)) if active != 0))
    }

    /// Records that a proactive re-authentication DM alert was delivered to `did`,
    /// advancing `reauth_notified_at` and incrementing `reauth_notify_count`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite update fails.
    pub fn mark_reauth_notified(&self, did: &str) -> Result<bool, SkybouncerError> {
        self.mark_reauth_notified_at(did, current_time_us())
    }

    /// Records that a proactive re-authentication DM alert was delivered to `did` at `now_us`,
    /// advancing `reauth_notified_at` and incrementing `reauth_notify_count`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite update fails.
    pub fn mark_reauth_notified_at(&self, did: &str, now_us: u64) -> Result<bool, SkybouncerError> {
        let now_i64 = us_to_i64(now_us);
        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE tenants
             SET reauth_notified_at = ?1,
                 reauth_notify_count = reauth_notify_count + 1,
                 updated_at = ?1
             WHERE did = ?2 AND reauth_required = 1;",
            params![now_i64, did],
        )?;
        Ok(rows > 0)
    }

    /// Returns the number of proactive re-authentication DM alerts delivered to `did`
    /// during the current expiration cycle (`0` before the initial alert, up to [`MAX_REAUTH_NOTIFICATIONS`]).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn reauth_notify_count(&self, did: &str) -> Result<u32, SkybouncerError> {
        let conn = self.conn.lock();
        let count: Option<i64> = conn
            .query_row(
                "SELECT reauth_notify_count FROM tenants WHERE did = ?1 LIMIT 1;",
                params![did],
                |r| r.get(0),
            )
            .optional()?;
        Ok(u32::try_from(count.unwrap_or(0).max(0)).unwrap_or(0))
    }

    /// Checks whether a tenant is currently marked as requiring OAuth re-authentication.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_reauth_required(&self, did: &str) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let flag: Option<i64> = conn
            .query_row(
                "SELECT reauth_required FROM tenants WHERE did = ?1 LIMIT 1;",
                params![did],
                |r| r.get(0),
            )
            .optional()?;
        Ok(flag.unwrap_or(0) != 0)
    }

    /// Checks whether an active tenant requires OAuth re-authentication and is due for either
    /// an initial DM alert (`reauth_notified_at IS NULL`) or a weekly follow-up reminder
    /// (up to [`MAX_REAUTH_NOTIFICATIONS`] total alerts, spaced by [`DEFAULT_REAUTH_REMINDER_INTERVAL`]).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_reauth_notification_pending(&self, did: &str) -> Result<bool, SkybouncerError> {
        self.is_reauth_notification_pending_at(
            did,
            current_time_us(),
            DEFAULT_REAUTH_REMINDER_INTERVAL,
        )
    }

    /// Checks whether an active tenant requires OAuth re-authentication and is due for an alert
    /// at `now_us` given `reminder_interval` and [`MAX_REAUTH_NOTIFICATIONS`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_reauth_notification_pending_at(
        &self,
        did: &str,
        now_us: u64,
        reminder_interval: Duration,
    ) -> Result<bool, SkybouncerError> {
        let interval_us = u64::try_from(reminder_interval.as_micros()).unwrap_or(u64::MAX);
        let cutoff_i64 = us_to_i64(now_us.saturating_sub(interval_us));
        let max_count = i64::from(MAX_REAUTH_NOTIFICATIONS);
        let conn = self.conn.lock();
        let pending: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM tenants
                 WHERE did = ?1
                   AND is_active = 1
                   AND reauth_required = 1
                   AND reauth_notify_count < ?2
                   AND (reauth_notified_at IS NULL OR reauth_notified_at <= ?3)
                 LIMIT 1;",
                params![did, max_count, cutoff_i64],
                |r| r.get(0),
            )
            .optional()?;
        Ok(pending.is_some())
    }

    /// Lists all active tenants whose OAuth session requires re-authentication and who are due
    /// for either an initial DM alert or a weekly follow-up reminder (up to [`MAX_REAUTH_NOTIFICATIONS`]
    /// total alerts, spaced by [`DEFAULT_REAUTH_REMINDER_INTERVAL`]).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_pending_reauth_notifications(
        &self,
    ) -> Result<Vec<(String, Option<String>)>, SkybouncerError> {
        self.list_pending_reauth_notifications_at(
            current_time_us(),
            DEFAULT_REAUTH_REMINDER_INTERVAL,
        )
    }

    /// Lists all active tenants whose OAuth session requires re-authentication and who are due
    /// for an alert at `now_us` given `reminder_interval` and [`MAX_REAUTH_NOTIFICATIONS`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_pending_reauth_notifications_at(
        &self,
        now_us: u64,
        reminder_interval: Duration,
    ) -> Result<Vec<(String, Option<String>)>, SkybouncerError> {
        let interval_us = u64::try_from(reminder_interval.as_micros()).unwrap_or(u64::MAX);
        let cutoff_i64 = us_to_i64(now_us.saturating_sub(interval_us));
        let max_count = i64::from(MAX_REAUTH_NOTIFICATIONS);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT did, handle FROM tenants
             WHERE is_active = 1
               AND reauth_required = 1
               AND reauth_notify_count < ?1
               AND (reauth_notified_at IS NULL OR reauth_notified_at <= ?2)
             ORDER BY created_at ASC;",
        )?;
        let rows = stmt.query_map(params![max_count, cutoff_i64], |row| {
            let did: String = row.get(0)?;
            let handle: Option<String> = row.get(1)?;
            Ok((did, handle))
        })?;
        let mut pending = Vec::new();
        for row in rows {
            pending.push(row?);
        }
        Ok(pending)
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
                let _ = self.mark_reauth_required(did);
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
                    if Self::is_permanent_oauth_refresh_error(&e) {
                        let _ = self.mark_reauth_required(did);
                    }
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
            Some(ref oc) => PdsRepoClient::new(session_arc, Arc::clone(oc)).inspect_err(|e| {
                tracing::warn!(did = %did, error = %e, "Failed to create PDS client with OAuth client");
            })?,
            None => PdsRepoClient::from_session(session_arc).inspect_err(|e| {
                tracing::warn!(did = %did, error = %e, "Failed to create PDS client from session");
            })?,
        };

        let client_arc = Arc::new(client);
        self.pds_clients
            .write()
            .insert(did.to_string(), Arc::clone(&client_arc));

        Ok(Some(client_arc))
    }
}
