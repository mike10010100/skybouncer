use super::*;

impl TenantRegistry {
    /// Opens or creates a persistent SQLite tenant registry at the given filesystem path.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if directory creation or SQLite initialization fails.
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

        let conn = Connection::open(path).map_err(|e| {
            SkybouncerError::Database(format!("Failed to open SQLite database: {e}"))
        })?;

        Self::apply_pragmas(&conn)?;
        Self::init_schema(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            pds_clients: Arc::new(RwLock::new(HashMap::new())),
            oauth_client: Arc::new(RwLock::new(None)),
            cipher: SessionCipher::from_env(),
            refresh_locks: Arc::new(crate::modlist::manager::StripedAsyncLocks::new()),
        })
    }

    /// Opens an isolated in-memory tenant registry (ideal for testing).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if in-memory SQLite initialization fails.
    pub fn open_in_memory() -> Result<Self, SkybouncerError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            SkybouncerError::Database(format!("Failed to open in-memory SQLite: {e}"))
        })?;

        Self::apply_pragmas(&conn)?;
        Self::init_schema(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            pds_clients: Arc::new(RwLock::new(HashMap::new())),
            oauth_client: Arc::new(RwLock::new(None)),
            cipher: SessionCipher::from_env(),
            refresh_locks: Arc::new(crate::modlist::manager::StripedAsyncLocks::new()),
        })
    }

    /// Creates a fallback in-memory tenant registry with zero panics.
    #[must_use]
    pub fn fallback() -> Self {
        if let Ok(reg) = Self::open_in_memory() {
            return reg;
        }
        let conn = Connection::open_in_memory()
            .or_else(|_| Connection::open(":memory:"))
            .or_else(|_| Connection::open(""))
            .or_else(|_| {
                Connection::open(std::env::temp_dir().join(format!(
                    "skybouncer_fallback_{}.db",
                    current_time_us()
                )))
            })
            .unwrap_or_else(|e| {
                tracing::error!(
                    error = %e,
                    "Could not open SQLite connection for fallback; opening in-memory database with default flags"
                );
                Connection::open_with_flags(
                    ":memory:",
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
                )
                .unwrap_or_else(|e2| {
                    tracing::error!(error = %e2, "Emergency: opening private temp SQLite database");
                    Connection::open_with_flags(
                        "",
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                            | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
                    )
                    .unwrap_or_else(|_| std::process::exit(1))
                })
            });
        Self {
            conn: Arc::new(Mutex::new(conn)),
            pds_clients: Arc::new(RwLock::new(HashMap::new())),
            oauth_client: Arc::new(RwLock::new(None)),
            cipher: SessionCipher::from_env(),
            refresh_locks: Arc::new(crate::modlist::manager::StripedAsyncLocks::new()),
        }
    }

    /// Initializes a `TenantRegistry` reusing an existing shared SQLite connection.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if schema migration fails.
    pub fn from_connection(conn: Arc<Mutex<Connection>>) -> Result<Self, SkybouncerError> {
        {
            let guard = conn.lock();
            Self::init_schema(&guard)?;
        }

        Ok(Self {
            conn,
            pds_clients: Arc::new(RwLock::new(HashMap::new())),
            oauth_client: Arc::new(RwLock::new(None)),
            cipher: SessionCipher::from_env(),
            refresh_locks: Arc::new(crate::modlist::manager::StripedAsyncLocks::new()),
        })
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
                handle_updated_at INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_tenants_handle
                ON tenants(handle);

            CREATE INDEX IF NOT EXISTS idx_tenants_active
                ON tenants(is_active);

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
            ",
        )
        .map_err(|e| {
            SkybouncerError::Database(format!("Failed to initialize tenants schema: {e}"))
        })?;

        // Idempotent column migrations for existing databases
        let _ = conn.execute("ALTER TABLE tenants ADD COLUMN bounce_duration TEXT;", []);
        let _ = conn.execute(
            "ALTER TABLE tenants ADD COLUMN bypass_followers INTEGER;",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE tenants ADD COLUMN handle_updated_at INTEGER;",
            [],
        );
        // Backfill handle freshness for rows predating the column so TTL lookups
        // do not treat existing handle mappings as permanently stale.
        let _ = conn.execute(
            "UPDATE tenants SET handle_updated_at = updated_at WHERE handle_updated_at IS NULL;",
            [],
        );

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
