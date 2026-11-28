use super::*;

const TENANT_SCHEMA_VERSION: u16 = 1;

struct ImmediateTxGuard<'a> {
    conn: &'a Connection,
    committed: bool,
}

impl<'a> ImmediateTxGuard<'a> {
    fn begin(conn: &'a Connection) -> Result<Self, SkybouncerError> {
        conn.execute_batch("BEGIN IMMEDIATE;").map_err(|e| {
            SkybouncerError::Database(format!("Failed to start tenant migration tx: {e}"))
        })?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    fn commit(mut self) -> Result<(), SkybouncerError> {
        self.conn.execute_batch("COMMIT;").map_err(|e| {
            SkybouncerError::Database(format!("Failed to commit tenant migration tx: {e}"))
        })?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for ImmediateTxGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch("ROLLBACK;");
        }
    }
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, SkybouncerError> {
    let sql = format!("PRAGMA table_info({table});");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

impl TenantRegistry {
    /// Opens or creates a persistent SQLite tenant registry at the given filesystem path.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] or [`SkybouncerError::Config`] if directory creation,
    /// `.skybouncer.key` resolution, SQLite initialization, or startup secret migration fails.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SkybouncerError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    SkybouncerError::Database(format!(
                        "Failed to create tenant registry directory: {e}"
                    ))
                })?;
            }
        }

        let (cipher, legacy_cipher) = SessionCipher::resolve_for_db_path(Some(path))?;

        let conn = Connection::open(path).map_err(|e| {
            SkybouncerError::Database(format!("Failed to open SQLite database: {e}"))
        })?;

        Self::apply_pragmas(&conn)?;
        Self::init_schema(&conn)?;
        crate::crypto::set_sqlite_file_permissions(path);

        let registry = Self {
            conn: Arc::new(Mutex::new(conn)),
            pds_clients: Arc::new(RwLock::new(HashMap::new())),
            client_epochs: Arc::new(RwLock::new(HashMap::new())),
            meta_cache: Arc::new(RwLock::new(HashMap::new())),
            oauth_client: Arc::new(RwLock::new(None)),
            cipher,
            refresh_locks: Arc::new(crate::modlist::manager::StripedAsyncLocks::new()),
        };
        registry.migrate_encrypted_secrets(legacy_cipher.as_ref())?;
        let _ = registry.list_summaries();
        Ok(registry)
    }

    /// Opens an isolated in-memory tenant registry (ideal for testing).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if in-memory SQLite initialization fails.
    pub fn open_in_memory() -> Result<Self, SkybouncerError> {
        let (cipher, legacy_cipher) = SessionCipher::resolve_for_db_path(None)?;
        let conn = Connection::open_in_memory().map_err(|e| {
            SkybouncerError::Database(format!("Failed to open in-memory SQLite: {e}"))
        })?;

        Self::apply_pragmas(&conn)?;
        Self::init_schema(&conn)?;

        let registry = Self {
            conn: Arc::new(Mutex::new(conn)),
            pds_clients: Arc::new(RwLock::new(HashMap::new())),
            client_epochs: Arc::new(RwLock::new(HashMap::new())),
            meta_cache: Arc::new(RwLock::new(HashMap::new())),
            oauth_client: Arc::new(RwLock::new(None)),
            cipher,
            refresh_locks: Arc::new(crate::modlist::manager::StripedAsyncLocks::new()),
        };
        registry.migrate_encrypted_secrets(legacy_cipher.as_ref())?;
        let _ = registry.list_summaries();
        Ok(registry)
    }

    /// Creates a fallback in-memory tenant registry without aborting the process.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if in-memory SQLite initialization fails.
    pub fn fallback() -> Result<Self, SkybouncerError> {
        Self::open_in_memory()
    }

    /// Initializes a `TenantRegistry` reusing an existing shared SQLite connection.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] or [`SkybouncerError::Config`] if schema migration,
    /// key resolution, or startup secret migration fails.
    pub fn from_connection(conn: Arc<Mutex<Connection>>) -> Result<Self, SkybouncerError> {
        let db_path: Option<PathBuf> = {
            let guard = conn.lock();
            guard
                .path()
                .filter(|p| !p.is_empty() && *p != ":memory:")
                .map(PathBuf::from)
        };
        let (cipher, legacy_cipher) = SessionCipher::resolve_for_db_path(db_path.as_deref())?;

        {
            let guard = conn.lock();
            Self::init_schema(&guard)?;
        }
        if let Some(ref p) = db_path {
            crate::crypto::set_sqlite_file_permissions(p);
        }

        let registry = Self {
            conn,
            pds_clients: Arc::new(RwLock::new(HashMap::new())),
            client_epochs: Arc::new(RwLock::new(HashMap::new())),
            meta_cache: Arc::new(RwLock::new(HashMap::new())),
            oauth_client: Arc::new(RwLock::new(None)),
            cipher,
            refresh_locks: Arc::new(crate::modlist::manager::StripedAsyncLocks::new()),
        };
        registry.migrate_encrypted_secrets(legacy_cipher.as_ref())?;
        let _ = registry.list_summaries();
        Ok(registry)
    }

    /// Configures a custom [`SessionCipher`] for encrypting and decrypting OAuth session tokens at rest.
    #[must_use]
    pub fn with_cipher(mut self, cipher: SessionCipher) -> Self {
        self.cipher = cipher;
        self
    }

    /// Returns a reference to the active [`SessionCipher`].
    #[must_use]
    pub fn cipher(&self) -> &SessionCipher {
        &self.cipher
    }

    pub(super) fn apply_pragmas(conn: &Connection) -> Result<(), SkybouncerError> {
        crate::util::apply_common_pragmas(conn, 5000)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set foreign_keys ON: {e}"))
            })?;
        Ok(())
    }

    pub(super) fn init_schema(conn: &Connection) -> Result<(), SkybouncerError> {
        let uv: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let (tenant_ver, cache_ver) = crate::util::unpack_schema_versions(uv);

        if tenant_ver >= TENANT_SCHEMA_VERSION {
            // Fast read-only check so repeated opens don't acquire unnecessary write locks,
            // while still upgrading any legacy prompt rows if present.
            for &(legacy, upgraded) in crate::classifier::rubric::LEGACY_PROMPT_UPGRADES {
                let has_legacy: bool = conn
                    .query_row(
                        "SELECT 1 FROM tenants WHERE rubric_prompt = ?1 LIMIT 1;",
                        params![legacy],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if has_legacy {
                    conn.execute(
                        "UPDATE tenants SET rubric_prompt = ?1 WHERE rubric_prompt = ?2;",
                        params![upgraded, legacy],
                    )?;
                }
            }
            return Ok(());
        }

        let tx = ImmediateTxGuard::begin(conn)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS tenants (
                did TEXT PRIMARY KEY,
                handle TEXT,
                session_json TEXT,
                rubric_prompt TEXT,
                sensitivity TEXT,
                bounce_duration TEXT,
                bypass_followers INTEGER,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                handle_updated_at INTEGER,
                reauth_required INTEGER NOT NULL DEFAULT 0,
                reauth_notified_at INTEGER,
                reauth_notify_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS web_sessions (
                token TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_web_sessions_did
                ON web_sessions(did);

            CREATE INDEX IF NOT EXISTS idx_web_sessions_expires
                ON web_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS oauth_client_keys (
                key_id TEXT PRIMARY KEY,
                encrypted_key TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            ",
        )
        .map_err(|e| {
            SkybouncerError::Database(format!("Failed to initialize tenants schema: {e}"))
        })?;

        // Idempotent column migrations for existing databases via PRAGMA table_info
        let alter_migrations: &[(&str, &str)] = &[
            (
                "bounce_duration",
                "ALTER TABLE tenants ADD COLUMN bounce_duration TEXT;",
            ),
            (
                "bypass_followers",
                "ALTER TABLE tenants ADD COLUMN bypass_followers INTEGER;",
            ),
            (
                "handle_updated_at",
                "ALTER TABLE tenants ADD COLUMN handle_updated_at INTEGER;",
            ),
            (
                "reauth_required",
                "ALTER TABLE tenants ADD COLUMN reauth_required INTEGER NOT NULL DEFAULT 0;",
            ),
            (
                "reauth_notified_at",
                "ALTER TABLE tenants ADD COLUMN reauth_notified_at INTEGER;",
            ),
            (
                "reauth_notify_count",
                "ALTER TABLE tenants ADD COLUMN reauth_notify_count INTEGER NOT NULL DEFAULT 0;",
            ),
        ];
        for &(col, sql) in alter_migrations {
            if !column_exists(conn, "tenants", col)? {
                conn.execute(sql, [])?;
            }
        }

        conn.execute_batch(
            "
            CREATE INDEX IF NOT EXISTS idx_tenants_handle
                ON tenants(handle);

            CREATE INDEX IF NOT EXISTS idx_tenants_handle_lower
                ON tenants(LOWER(handle));

            CREATE INDEX IF NOT EXISTS idx_tenants_active
                ON tenants(is_active);
            ",
        )
        .map_err(|e| SkybouncerError::Database(format!("Failed to create tenant indexes: {e}")))?;

        // Backfill notification count for rows that already received their initial re-auth DM
        // prior to the weekly reminder counter column.
        conn.execute(
            "UPDATE tenants SET reauth_notify_count = 1 WHERE reauth_notified_at IS NOT NULL AND reauth_notify_count = 0;",
            [],
        )?;
        // Backfill handle freshness for rows predating the column so TTL lookups
        // do not treat existing handle mappings as permanently stale.
        conn.execute(
            "UPDATE tenants SET handle_updated_at = updated_at WHERE handle_updated_at IS NULL;",
            [],
        )?;
        // Upgrade unmodified legacy default and preset rubric strings to target-scoped
        // wording while preserving any customized tenant rubric prompts verbatim.
        for &(legacy, upgraded) in crate::classifier::rubric::LEGACY_PROMPT_UPGRADES {
            conn.execute(
                "UPDATE tenants SET rubric_prompt = ?1 WHERE rubric_prompt = ?2;",
                params![upgraded, legacy],
            )?;
        }

        // Zero-logout web_sessions migration:
        // 1. Prefix existing 64-char lowercase hex SHA-256 digests with `sha256:`.
        // 2. Purge expired unprefixed rows, then hash any remaining legacy plaintext tokens in place.
        conn.execute(
            "UPDATE web_sessions
             SET token = 'sha256:' || token
             WHERE token NOT LIKE 'sha256:%'
               AND length(token) = 64
               AND token NOT GLOB '*[^0-9a-f]*';",
            [],
        )?;
        let now_i64 = us_to_i64(current_time_us());
        conn.execute(
            "DELETE FROM web_sessions WHERE token NOT LIKE 'sha256:%' AND expires_at < ?1;",
            params![now_i64],
        )?;
        let legacy_tokens: Vec<String> = {
            let mut stmt =
                conn.prepare("SELECT token FROM web_sessions WHERE token NOT LIKE 'sha256:%';")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut tokens = Vec::new();
            for row in rows {
                tokens.push(row?);
            }
            tokens
        };
        for raw_token in legacy_tokens {
            let prefixed = format!(
                "{WEB_SESSION_HASH_PREFIX}{}",
                hash_session_token(&raw_token)
            );
            conn.execute(
                "UPDATE web_sessions SET token = ?1 WHERE token = ?2;",
                params![prefixed, raw_token],
            )?;
        }

        let new_uv = crate::util::pack_schema_versions(TENANT_SCHEMA_VERSION, cache_ver);
        conn.pragma_update(None, "user_version", new_uv)
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to update user_version: {e}"))
            })?;

        tx.commit()?;
        Ok(())
    }

    /// Returns the total count of registered tenants.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if query fails.
    pub fn count(&self) -> Result<usize, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT COUNT(*) FROM tenants;")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(usize::try_from(count.max(0)).unwrap_or(0))
    }
}
