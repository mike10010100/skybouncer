use super::*;

impl TenantRegistry {
    pub(super) fn bump_epoch_and_evict(&self, did: &str) {
        {
            let mut epochs = self.client_epochs.write();
            let entry = epochs.entry(did.to_string()).or_insert(0);
            *entry = entry.wrapping_add(1);
        }
        self.pds_clients.write().remove(did);
    }

    /// Migrates legacy encrypted or unencrypted `tenants.session_json` and
    /// `oauth_client_keys.encrypted_key` rows to strict AES-256-GCM envelopes with
    /// tenant-DID / key-ID AAD under the active cipher.
    ///
    /// Rows that cannot be decrypted by either the active cipher or `legacy_cipher`
    /// (for example, rows encrypted with an explicit test cipher prior to `.with_cipher()`)
    /// are logged and left untouched so runtime decryption continues to fail closed.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the migration transaction fails.
    pub fn migrate_encrypted_secrets(
        &self,
        legacy_cipher: Option<&SessionCipher>,
    ) -> Result<(), SkybouncerError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let tenant_rows: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT did, session_json FROM tenants
                 WHERE session_json IS NOT NULL AND TRIM(session_json) != '';",
            )?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };

        for (did, raw) in tenant_rows {
            if let Ok(strict_plain) = self.cipher.decrypt_strict_with_aad(&raw, did.as_bytes()) {
                if let Ok(session) = serde_json::from_str::<OAuthSession>(&strict_plain) {
                    if session.sub() != did {
                        tracing::warn!(
                            did = %did,
                            sub = %session.sub(),
                            "Detected tenant session_json with mismatched sub during startup check"
                        );
                    }
                }
                continue;
            }

            let maybe_plain = self
                .cipher
                .decrypt_or_passthrough_with_aad(&raw, did.as_bytes())
                .map(Zeroizing::new)
                .ok()
                .or_else(|| {
                    legacy_cipher.and_then(|lc| {
                        lc.decrypt_or_passthrough_with_aad(&raw, did.as_bytes())
                            .map(Zeroizing::new)
                            .ok()
                    })
                });

            let Some(plain) = maybe_plain else {
                tracing::warn!(
                    did = %did,
                    "Skipping undecryptable tenant session_json during startup secret migration"
                );
                continue;
            };

            let session: OAuthSession = match serde_json::from_str(&plain) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        "Skipping malformed tenant session_json during startup secret migration"
                    );
                    continue;
                }
            };
            if session.sub() != did {
                tracing::error!(
                    did = %did,
                    sub = %session.sub(),
                    "Refusing to migrate tenant session_json whose sub does not match tenant DID"
                );
                continue;
            }

            let resealed = self
                .cipher
                .encrypt_with_aad(plain.as_bytes(), did.as_bytes())?;
            tx.execute(
                "UPDATE tenants SET session_json = ?1 WHERE did = ?2;",
                params![resealed, did],
            )?;
        }

        let key_rows: Vec<(String, String)> = {
            let mut stmt = tx.prepare("SELECT key_id, encrypted_key FROM oauth_client_keys;")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };

        for (key_id, raw) in key_rows {
            let aad = format!("oauth_client_key:{key_id}");
            if self
                .cipher
                .decrypt_strict_with_aad(&raw, aad.as_bytes())
                .is_ok()
            {
                continue;
            }

            let maybe_plain = self
                .cipher
                .decrypt_or_passthrough_with_aad(&raw, aad.as_bytes())
                .map(Zeroizing::new)
                .ok()
                .or_else(|| {
                    legacy_cipher.and_then(|lc| {
                        lc.decrypt_or_passthrough_with_aad(&raw, aad.as_bytes())
                            .map(Zeroizing::new)
                            .ok()
                    })
                });

            let Some(plain) = maybe_plain else {
                tracing::warn!(
                    key_id = %key_id,
                    "Skipping undecryptable oauth_client_keys row during startup secret migration"
                );
                continue;
            };

            if skyauth::dpop::DPoPKey::from_bytes_b64(plain.trim()).is_err() {
                tracing::warn!(
                    key_id = %key_id,
                    "Skipping invalid oauth_client_keys payload during startup secret migration"
                );
                continue;
            }

            let resealed = self
                .cipher
                .encrypt_with_aad(plain.trim().as_bytes(), aad.as_bytes())?;
            tx.execute(
                "UPDATE oauth_client_keys SET encrypted_key = ?1 WHERE key_id = ?2;",
                params![resealed, key_id],
            )?;
        }

        tx.commit()?;
        drop(conn);
        let _ = self.list_summaries();
        Ok(())
    }

    /// Registers a new tenant or updates an existing tenant's credentials and settings.
    ///
    /// Invalidates any cached [`PdsRepoClient`] for this tenant so new session tokens take effect.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if session subject validation, encryption, or database persistence fails.
    pub fn register_or_update(&self, tenant: &Tenant) -> Result<(), SkybouncerError> {
        let session_json = match tenant.session {
            Some(ref s) => {
                if s.sub() != tenant.did {
                    return Err(SkybouncerError::Auth(format!(
                        "OAuth session subject '{}' does not match tenant DID '{}'",
                        s.sub(),
                        tenant.did
                    )));
                }
                let json = Zeroizing::new(serde_json::to_string(s).map_err(|e| {
                    SkybouncerError::Config(format!("Failed to serialize tenant session: {e}"))
                })?);
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

        let committed_meta = {
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
            Self::query_meta_locked(&conn, &tenant.did)?
        };

        if let Some(meta) = committed_meta {
            self.meta_cache.write().insert(meta.did.clone(), meta);
        } else {
            self.meta_cache.write().remove(&tenant.did);
        }

        // Invalidate cached PDS client and advance epoch after commit
        self.bump_epoch_and_evict(&tenant.did);

        Ok(())
    }

    /// Atomically inserts or updates an OAuth session from `/oauth/callback` without
    /// overwriting concurrent `rubric_prompt`, `sensitivity`, `bounce_duration`,
    /// `bypass_followers`, or `is_active` updates.
    ///
    /// Returns the persisted `is_active` state and optional custom rubric so callers can
    /// synchronize runtime state (`protected_dids`, `gate`) from the committed DB row.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if `session.sub() != did`, encryption fails, or SQLite fails.
    pub fn upsert_oauth_session(
        &self,
        did: &str,
        handle: Option<&str>,
        session: &OAuthSession,
    ) -> Result<(bool, Option<RuleRubric>), SkybouncerError> {
        if session.sub() != did {
            return Err(SkybouncerError::Auth(format!(
                "OAuth session subject '{}' does not match tenant DID '{}'",
                session.sub(),
                did
            )));
        }

        let json = Zeroizing::new(serde_json::to_string(session).map_err(|e| {
            SkybouncerError::Config(format!("Failed to serialize tenant session: {e}"))
        })?);
        let encrypted = self
            .cipher
            .encrypt_with_aad(json.as_bytes(), did.as_bytes())?;

        let clean_handle = handle
            .map(|h| crate::util::normalize_handle(h).to_ascii_lowercase())
            .filter(|h| !h.is_empty() && h != "handle.invalid");
        let now_i64 = us_to_i64(current_time_us());
        let handle_updated_at_i64 = clean_handle.as_ref().map(|_| now_i64);

        let committed_meta: TenantMeta = {
            let mut conn = self.conn.lock();
            let tx = conn.transaction()?;
            if let Some(ref h) = clean_handle {
                tx.execute(
                    "UPDATE tenants SET handle = NULL, handle_updated_at = ?1, updated_at = ?1
                     WHERE (LOWER(handle) = LOWER(?2) OR LOWER(handle) = LOWER(?3)) AND did != ?4;",
                    params![now_i64, h, format!("@{h}"), did],
                )?;
            }
            tx.execute(
                "INSERT INTO tenants (
                    did, handle, session_json, is_active, created_at, updated_at, handle_updated_at,
                    reauth_required, reauth_notified_at, reauth_notify_count
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?4, ?5, 0, NULL, 0)
                 ON CONFLICT(did) DO UPDATE SET
                     session_json = excluded.session_json,
                     handle = COALESCE(excluded.handle, tenants.handle),
                     updated_at = excluded.updated_at,
                     handle_updated_at = COALESCE(excluded.handle_updated_at, tenants.handle_updated_at),
                     reauth_required = 0,
                     reauth_notified_at = NULL,
                     reauth_notify_count = 0;",
                params![did, clean_handle, encrypted, now_i64, handle_updated_at_i64],
            )?;
            let meta = tx.query_row(
                "SELECT did, handle,
                        (session_json IS NOT NULL AND TRIM(session_json) != '') AS has_session,
                        reauth_required, rubric_prompt, sensitivity, bounce_duration,
                        bypass_followers, is_active, created_at, updated_at
                 FROM tenants WHERE did = ?1;",
                params![did],
                Self::map_tenant_meta_row,
            )?;
            tx.commit()?;
            meta
        };

        {
            let mut cache = self.meta_cache.write();
            if let Some(ref h) = clean_handle {
                let at_h = format!("@{h}");
                for (entry_did, entry) in cache.iter_mut() {
                    if entry_did != did
                        && entry.handle.as_deref().is_some_and(|existing| {
                            existing.eq_ignore_ascii_case(h) || existing.eq_ignore_ascii_case(&at_h)
                        })
                    {
                        entry.handle = None;
                        entry.updated_at = i64_to_us(now_i64);
                    }
                }
            }
            cache.insert(committed_meta.did.clone(), committed_meta.clone());
        }

        self.bump_epoch_and_evict(did);

        Ok((committed_meta.is_active, committed_meta.rubric))
    }

    pub(super) fn decode_rubric_fields(
        rubric_prompt: Option<String>,
        sensitivity_str: Option<String>,
        bounce_duration_str: Option<String>,
        bypass_followers_int: Option<i64>,
    ) -> Option<RuleRubric> {
        let bounce_duration =
            crate::classifier::bounce_duration_from_db(bounce_duration_str.as_deref());
        let bypass_incoming_followers = bypass_followers_int.is_none_or(|v| v != 0);

        match (rubric_prompt, sensitivity_str) {
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
        }
    }

    /// Retrieves an enrolled tenant by DID.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite lookup fails, or [`SkybouncerError::Auth`]
    /// if strict decryption or `session.sub() == did` verification fails.
    pub fn get(&self, did: &str) -> Result<Option<Tenant>, SkybouncerError> {
        let res = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT did, handle, session_json, rubric_prompt, sensitivity, bounce_duration, bypass_followers, is_active, created_at, updated_at
                 FROM tenants WHERE did = ?1;",
            )?;

            stmt.query_row(params![did], |row| {
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
            .optional()?
        };

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
                        let decrypted = self.cipher.decrypt_strict_with_aad(raw, did.as_bytes())?;
                        let session: OAuthSession =
                            serde_json::from_str(&decrypted).map_err(|e| {
                                SkybouncerError::Auth(format!(
                                    "Failed to deserialize tenant session for {did}: {e}"
                                ))
                            })?;
                        if session.sub() != did {
                            return Err(SkybouncerError::Auth(format!(
                                "Decrypted OAuth session subject '{}' does not match tenant DID '{did}'",
                                session.sub()
                            )));
                        }
                        Some(session)
                    }
                    _ => None,
                };

                let rubric = Self::decode_rubric_fields(
                    rubric_prompt,
                    sensitivity_str,
                    bounce_duration_str,
                    bypass_followers_int,
                );

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
    /// Returns [`SkybouncerError::Auth`] if `session.sub() != did` or encryption fails, or
    /// [`SkybouncerError::Database`] if serialization or SQLite execution fails.
    pub fn update_session(
        &self,
        did: &str,
        session: &OAuthSession,
    ) -> Result<bool, SkybouncerError> {
        if session.sub() != did {
            return Err(SkybouncerError::Auth(format!(
                "OAuth session subject '{}' does not match tenant DID '{did}'",
                session.sub()
            )));
        }
        let serialized = Zeroizing::new(serde_json::to_string(session).map_err(|e| {
            SkybouncerError::Database(format!("Failed to serialize OAuthSession for {did}: {e}"))
        })?);
        let encrypted = self
            .cipher
            .encrypt_with_aad(serialized.as_bytes(), did.as_bytes())?;
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);
        let rows = {
            let conn = self.conn.lock();
            conn.execute(
                "UPDATE tenants SET session_json = ?1, updated_at = ?2, reauth_required = 0, reauth_notified_at = NULL, reauth_notify_count = 0 WHERE did = ?3",
                params![encrypted, now_i64, did],
            )
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to update session for {did}: {e}"))
            })?
        };
        if rows > 0 {
            if let Some(entry) = self.meta_cache.write().get_mut(did) {
                entry.has_session = true;
                entry.reauth_required = false;
                entry.updated_at = now_us;
            }
        }
        self.bump_epoch_and_evict(did);
        Ok(rows > 0)
    }

    /// Atomically updates `session_json` only if the stored ciphertext still matches
    /// `expected_raw_session_json` (SQL Compare-And-Swap).
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] on subject mismatch, encryption failure, or SQLite failure.
    pub fn update_session_cas(
        &self,
        did: &str,
        session: &OAuthSession,
        expected_raw_session_json: &str,
    ) -> Result<CasUpdateOutcome, SkybouncerError> {
        if session.sub() != did {
            return Err(SkybouncerError::Auth(format!(
                "OAuth session subject '{}' does not match tenant DID '{did}'",
                session.sub()
            )));
        }
        let serialized = Zeroizing::new(serde_json::to_string(session).map_err(|e| {
            SkybouncerError::Database(format!("Failed to serialize OAuthSession for {did}: {e}"))
        })?);
        let encrypted = self
            .cipher
            .encrypt_with_aad(serialized.as_bytes(), did.as_bytes())?;
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let (rows, exists) = {
            let conn = self.conn.lock();
            let rows = conn
                .execute(
                    "UPDATE tenants
                     SET session_json = ?1,
                         updated_at = ?2,
                         reauth_required = 0,
                         reauth_notified_at = NULL,
                         reauth_notify_count = 0
                     WHERE did = ?3 AND session_json = ?4;",
                    params![encrypted, now_i64, did, expected_raw_session_json],
                )
                .map_err(|e| {
                    SkybouncerError::Database(format!(
                        "Failed to CAS-update session for {did}: {e}"
                    ))
                })?;
            if rows > 0 {
                (rows, true)
            } else {
                let exists = conn
                    .query_row(
                        "SELECT 1 FROM tenants WHERE did = ?1 LIMIT 1;",
                        params![did],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                (0, exists)
            }
        };

        if rows > 0 {
            if let Some(entry) = self.meta_cache.write().get_mut(did) {
                entry.has_session = true;
                entry.reauth_required = false;
                entry.updated_at = now_us;
            }
            self.bump_epoch_and_evict(did);
            Ok(CasUpdateOutcome::Updated)
        } else if exists {
            Ok(CasUpdateOutcome::Conflict)
        } else {
            self.meta_cache.write().remove(did);
            self.bump_epoch_and_evict(did);
            Ok(CasUpdateOutcome::NotFound)
        }
    }

    /// Loads the persistent confidential-client ES256 signing key (`private_key_jwt`) from
    /// environment or SQLite (`oauth_client_keys`), generating and encrypting a fresh key
    /// inside an `IMMEDIATE` transaction if none is persisted yet.
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

        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<String> = tx
            .query_row(
                "SELECT encrypted_key FROM oauth_client_keys WHERE key_id = ?1 LIMIT 1;",
                params![PRIMARY_KEY_ID],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(raw) = existing {
            let decrypted = self.cipher.decrypt_strict_with_aad(&raw, PRIMARY_KEY_AAD)?;
            tx.commit()?;
            return skyauth::dpop::DPoPKey::from_bytes_b64(decrypted.trim()).map_err(|e| {
                SkybouncerError::Auth(format!("Failed to parse stored OAuth client key: {e}"))
            });
        }

        let generated = skyauth::dpop::DPoPKey::generate();
        let b64_key = Zeroizing::new(generated.to_bytes_b64());
        let encrypted = self
            .cipher
            .encrypt_with_aad(b64_key.as_bytes(), PRIMARY_KEY_AAD)?;
        let now_i64 = us_to_i64(current_time_us());

        let inserted = tx.execute(
            "INSERT INTO oauth_client_keys (key_id, encrypted_key, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key_id) DO NOTHING;",
            params![PRIMARY_KEY_ID, encrypted, now_i64],
        )?;

        if inserted == 0 {
            let winner_raw: String = tx.query_row(
                "SELECT encrypted_key FROM oauth_client_keys WHERE key_id = ?1 LIMIT 1;",
                params![PRIMARY_KEY_ID],
                |row| row.get(0),
            )?;
            let decrypted = self
                .cipher
                .decrypt_strict_with_aad(&winner_raw, PRIMARY_KEY_AAD)?;
            tx.commit()?;
            return skyauth::dpop::DPoPKey::from_bytes_b64(decrypted.trim()).map_err(|e| {
                SkybouncerError::Auth(format!("Failed to parse stored OAuth client key: {e}"))
            });
        }

        tx.commit()?;
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
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);
        let (rows, row) = {
            let conn = self.conn.lock();
            let rows = conn.execute(
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
            (rows, row)
        };
        if rows > 0 {
            if let Some(entry) = self.meta_cache.write().get_mut(did) {
                entry.reauth_required = true;
                entry.updated_at = now_us;
            }
        }

        Ok(matches!(row, Some((active, None)) if active != 0))
    }

    /// Atomically marks an enrolled tenant as requiring OAuth re-authentication only if the
    /// stored `session_json` ciphertext still matches `expected_raw_session_json`.
    ///
    /// Prevents a stale failed refresh from marking a concurrent fresh `/oauth/callback` login
    /// as `reauth_required = 1`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite update fails.
    pub fn mark_reauth_required_cas(
        &self,
        did: &str,
        expected_raw_session_json: &str,
    ) -> Result<bool, SkybouncerError> {
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);
        let (rows, row) = {
            let conn = self.conn.lock();
            let rows = conn.execute(
                "UPDATE tenants SET reauth_required = 1, updated_at = ?1
                 WHERE did = ?2 AND session_json = ?3;",
                params![now_i64, did, expected_raw_session_json],
            )?;
            if rows == 0 {
                return Ok(false);
            }

            let row: Option<(i64, Option<i64>)> = conn
                .query_row(
                    "SELECT is_active, reauth_notified_at FROM tenants WHERE did = ?1 LIMIT 1;",
                    params![did],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            (rows, row)
        };
        if rows > 0 {
            if let Some(entry) = self.meta_cache.write().get_mut(did) {
                entry.reauth_required = true;
                entry.updated_at = now_us;
            }
        }

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
    /// Uses `meta_cache` / lightweight SQL projection without decrypting `session_json`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_reauth_required(&self, did: &str) -> Result<bool, SkybouncerError> {
        Ok(self.get_meta(did)?.is_some_and(|m| m.reauth_required))
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
        let stored_token = format!("{WEB_SESSION_HASH_PREFIX}{}", hash_session_token(&token));
        let now_us = current_time_us();
        let ttl_us = u64::try_from(ttl.as_micros()).unwrap_or(u64::MAX / 2);
        let expires_at_us = now_us.saturating_add(ttl_us);

        let created_at_i64 = us_to_i64(now_us);
        let expires_at_i64 = i64::try_from(expires_at_us).unwrap_or(i64::MAX);

        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO web_sessions (token, did, created_at, expires_at) VALUES (?1, ?2, ?3, ?4);",
            params![stored_token, clean_did, created_at_i64, expires_at_i64],
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

        let stored_token = format!(
            "{WEB_SESSION_HASH_PREFIX}{}",
            hash_session_token(clean_token)
        );
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT did, expires_at FROM web_sessions WHERE token = ?1;")?;

        let row = stmt
            .query_row(params![stored_token], |row| {
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
                        "DELETE FROM web_sessions WHERE token = ?1;",
                        params![stored_token],
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

        let stored_token = format!(
            "{WEB_SESSION_HASH_PREFIX}{}",
            hash_session_token(clean_token)
        );
        let conn = self.conn.lock();
        let rows = conn
            .execute(
                "DELETE FROM web_sessions WHERE token = ?1;",
                params![stored_token],
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

    fn load_session_snapshot(
        &self,
        did: &str,
    ) -> Result<Option<(String, OAuthSession)>, SkybouncerError> {
        let raw_opt: Option<String> = {
            let conn = self.conn.lock();
            conn.query_row(
                "SELECT session_json FROM tenants WHERE did = ?1 LIMIT 1;",
                params![did],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
        };

        let Some(raw) = raw_opt.filter(|r| !r.trim().is_empty()) else {
            return Ok(None);
        };

        let decrypted = self.cipher.decrypt_strict_with_aad(&raw, did.as_bytes())?;
        let session: OAuthSession = serde_json::from_str(&decrypted).map_err(|e| {
            SkybouncerError::Auth(format!(
                "Failed to deserialize tenant session for {did}: {e}"
            ))
        })?;
        if session.sub() != did {
            return Err(SkybouncerError::Auth(format!(
                "Decrypted OAuth session subject '{}' does not match tenant DID '{did}'",
                session.sub()
            )));
        }

        Ok(Some((raw, session)))
    }

    async fn persist_refreshed_session_with_retry(
        &self,
        did: &str,
        session: &OAuthSession,
        expected_raw: &str,
    ) -> Result<CasUpdateOutcome, SkybouncerError> {
        const BACKOFFS_MS: [u64; 4] = [25, 50, 100, 200];
        let mut attempt = 0usize;
        loop {
            match self.update_session_cas(did, session, expected_raw) {
                Ok(outcome) => return Ok(outcome),
                Err(e) if attempt < BACKOFFS_MS.len() && Self::is_transient_db_error(&e) => {
                    tracing::warn!(
                        did = %did,
                        attempt = attempt + 1,
                        error = %e,
                        "Transient database error persisting refreshed OAuth session; retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(BACKOFFS_MS[attempt])).await;
                    attempt += 1;
                }
                Err(e) => {
                    self.pds_clients.write().remove(did);
                    return Err(e);
                }
            }
        }
    }

    pub(super) fn is_transient_db_error(err: &SkybouncerError) -> bool {
        match err {
            SkybouncerError::Database(msg) => {
                let lower = msg.to_ascii_lowercase();
                lower.contains("locked") || lower.contains("busy") || lower.contains("sqlite_busy")
            }
            _ => false,
        }
    }

    fn build_pds_client(
        did: &str,
        session: OAuthSession,
        resolved_oauth_client: Option<&Arc<AtprotoOAuthClient>>,
    ) -> Result<Arc<PdsRepoClient>, SkybouncerError> {
        let session_arc = Arc::new(session);
        let client = match resolved_oauth_client {
            Some(oc) => {
                let c = PdsRepoClient::new(session_arc, Arc::clone(oc)).inspect_err(|e| {
                    tracing::warn!(did = %did, error = %e, "Failed to create PDS client with OAuth client");
                })?;
                if oc.ssrf_filter().allow_insecure_localhost {
                    c.with_ssrf_filter(*oc.ssrf_filter())
                } else {
                    c
                }
            }
            None => PdsRepoClient::from_session(session_arc).inspect_err(|e| {
                tracing::warn!(did = %did, error = %e, "Failed to create PDS client from session");
            })?,
        };
        Ok(Arc::new(client))
    }

    pub(super) fn insert_pds_client_if_epoch_matches(
        &self,
        did: &str,
        expected_epoch: u64,
        client: &Arc<PdsRepoClient>,
    ) {
        let epochs = self.client_epochs.read();
        let current_epoch = epochs.get(did).copied().unwrap_or(0);
        if current_epoch == expected_epoch {
            self.pds_clients
                .write()
                .insert(did.to_string(), Arc::clone(client));
        }
    }

    async fn refresh_and_build_client(
        &self,
        did: &str,
        expected_epoch: &mut u64,
        raw_session_json: &str,
        mut session: OAuthSession,
        resolved_oauth_client: Option<&Arc<AtprotoOAuthClient>>,
    ) -> Result<Option<Arc<PdsRepoClient>>, SkybouncerError> {
        let oc = match resolved_oauth_client {
            Some(oc) => oc,
            None => {
                self.pds_clients.write().remove(did);
                return Err(SkybouncerError::Auth(format!(
                    "OAuth session for tenant {did} is expired and no OAuth client is configured"
                )));
            }
        };

        if session.refresh_token().is_none() {
            let _ = self.mark_reauth_required_cas(did, raw_session_json);
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
                match self
                    .persist_refreshed_session_with_retry(did, &session, raw_session_json)
                    .await?
                {
                    CasUpdateOutcome::Updated => {
                        *expected_epoch = self.client_epochs.read().get(did).copied().unwrap_or(0);
                    }
                    CasUpdateOutcome::Conflict => {
                        *expected_epoch = self.client_epochs.read().get(did).copied().unwrap_or(0);
                        match self.load_session_snapshot(did)? {
                            Some((_, newer_session)) => {
                                session = newer_session;
                            }
                            None => return Ok(None),
                        }
                    }
                    CasUpdateOutcome::NotFound => return Ok(None),
                }
            }
            Err(e) => {
                tracing::warn!(
                    did = %did,
                    error = %e,
                    "Failed to refresh ATProto OAuth session using refresh token"
                );
                if Self::is_permanent_oauth_refresh_error(&e) {
                    let _ = self.mark_reauth_required_cas(did, raw_session_json);
                }
                self.pds_clients.write().remove(did);
                return Err(SkybouncerError::Auth(format!(
                    "Failed to refresh expired OAuth session for tenant {did}: {e}"
                )));
            }
        }

        if session.is_expired() {
            self.pds_clients.write().remove(did);
            return Err(SkybouncerError::Auth(format!(
                "OAuth session for tenant {did} remains expired"
            )));
        }

        let client_arc = Self::build_pds_client(did, session, resolved_oauth_client)?;
        self.insert_pds_client_if_epoch_matches(did, *expected_epoch, &client_arc);
        Ok(Some(client_arc))
    }

    /// Resolves or initializes a dedicated [`PdsRepoClient`] for an enrolled tenant using their DPoP session.
    ///
    /// If a client was already constructed for this DID and its session is still valid, it is returned from cache immediately (<50ns).
    /// If the session is expired or expiring within 60 seconds, it is automatically refreshed using the configured [`AtprotoOAuthClient`].
    /// If the tenant has no stored session, returns `Ok(None)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if client creation, OAuth refresh, or database persistence fails.
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

        // 3.5. Short-circuit tenants already marked reauth_required without decrypting session_json
        if self.is_reauth_required(did)? {
            self.pds_clients.write().remove(did);
            return Err(SkybouncerError::Auth(format!(
                "OAuth session for tenant {did} requires re-authentication"
            )));
        }

        let mut expected_epoch = self.client_epochs.read().get(did).copied().unwrap_or(0);

        // 4. Load raw ciphertext + strict decrypted session from database
        let Some((raw_session_json, session)) = self.load_session_snapshot(did)? else {
            return Ok(None);
        };

        let resolved_oauth_client = oauth_client
            .cloned()
            .or_else(|| self.oauth_client.read().clone());

        if session.is_expired_with_leeway(Duration::from_secs(60)) {
            return self
                .refresh_and_build_client(
                    did,
                    &mut expected_epoch,
                    &raw_session_json,
                    session,
                    resolved_oauth_client.as_ref(),
                )
                .await;
        }

        if session.is_expired() {
            self.pds_clients.write().remove(did);
            return Err(SkybouncerError::Auth(format!(
                "OAuth session for tenant {did} remains expired"
            )));
        }

        let client_arc = Self::build_pds_client(did, session, resolved_oauth_client.as_ref())?;
        self.insert_pds_client_if_epoch_matches(did, expected_epoch, &client_arc);
        Ok(Some(client_arc))
    }

    /// Evicts `failed_client` from the per-DID cache and performs a single-flight OAuth token
    /// refresh after a PDS HTTP 401 (`ExpiredToken`/`InvalidToken`) error.
    ///
    /// If another task already replaced `failed_client` in `pds_clients` with a valid client,
    /// that fresh client is returned without triggering a redundant refresh.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if OAuth refresh or database persistence fails.
    pub async fn force_refresh_pds_client(
        &self,
        did: &str,
        failed_client: &Arc<PdsRepoClient>,
        oauth_client: Option<&Arc<AtprotoOAuthClient>>,
    ) -> Result<Option<Arc<PdsRepoClient>>, SkybouncerError> {
        let _refresh_guard = self.refresh_locks.shard_for(did).lock().await;

        {
            let guard = self.pds_clients.read();
            if let Some(cached) = guard.get(did) {
                if !Arc::ptr_eq(cached, failed_client)
                    && !cached
                        .session()
                        .is_expired_with_leeway(Duration::from_secs(60))
                {
                    return Ok(Some(Arc::clone(cached)));
                }
            }
        }

        self.pds_clients.write().remove(did);
        let mut expected_epoch = self.client_epochs.read().get(did).copied().unwrap_or(0);

        let Some((raw_session_json, session)) = self.load_session_snapshot(did)? else {
            return Ok(None);
        };

        let resolved_oauth_client = oauth_client
            .cloned()
            .or_else(|| self.oauth_client.read().clone());

        self.refresh_and_build_client(
            did,
            &mut expected_epoch,
            &raw_session_json,
            session,
            resolved_oauth_client.as_ref(),
        )
        .await
    }
}
