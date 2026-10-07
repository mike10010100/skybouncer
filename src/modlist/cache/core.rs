use super::*;

impl DeduplicationCache {
    /// Opens or creates a persistent SQLite cache database at the specified filesystem path.
    ///
    /// Configures WAL mode, normal synchronous durability, a 5000ms busy timeout,
    /// in-memory temporary storage, and foreign key constraints.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if directory creation or SQLite initialization fails.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SkybouncerError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    SkybouncerError::Database(format!("Failed to create database directory: {e}"))
                })?;
            }
        }

        let conn = Connection::open(path).map_err(|e| {
            SkybouncerError::Database(format!("Failed to open SQLite database: {e}"))
        })?;

        Self::apply_pragmas(&conn, 5000)?;
        Self::init_schema(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Opens an isolated in-memory SQLite cache database (ideal for unit testing).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite initialization fails.
    pub fn open_in_memory() -> Result<Self, SkybouncerError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            SkybouncerError::Database(format!("Failed to open in-memory SQLite: {e}"))
        })?;

        Self::apply_pragmas(&conn, 5000)?;
        Self::init_schema(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Returns a shared reference to the underlying SQLite connection mutex.
    #[must_use]
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    pub(super) fn apply_pragmas(
        conn: &Connection,
        busy_timeout_ms: u32,
    ) -> Result<(), SkybouncerError> {
        crate::util::apply_common_pragmas(conn, busy_timeout_ms)?;
        conn.pragma_update(None, "temp_store", "MEMORY")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set temp_store MEMORY: {e}"))
            })?;
        conn.pragma_update(None, "mmap_size", 268_435_456_i64)
            .map_err(|e| SkybouncerError::Database(format!("Failed to set mmap_size: {e}")))?;
        conn.pragma_update(None, "foreign_keys", "OFF")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set foreign_keys OFF: {e}"))
            })?;
        Ok(())
    }

    pub(super) fn init_schema(conn: &Connection) -> Result<(), SkybouncerError> {
        // 1. Base tables
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS mod_list_config (
                user_did TEXT PRIMARY KEY,
                list_uri TEXT NOT NULL,
                list_cid TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bounced_users (
                subject_did TEXT NOT NULL,
                listitem_uri TEXT NOT NULL,
                listitem_rkey TEXT NOT NULL,
                listitem_cid TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT NOT NULL,
                post_uri TEXT NOT NULL,
                bounced_at INTEGER NOT NULL,
                protected_did TEXT NOT NULL DEFAULT '',
                post_text TEXT NOT NULL DEFAULT '',
                expires_at INTEGER,
                PRIMARY KEY (protected_did, subject_did)
            );

            CREATE TABLE IF NOT EXISTS bounced_user_rkeys (
                protected_did TEXT NOT NULL DEFAULT '',
                subject_did TEXT NOT NULL,
                listitem_rkey TEXT NOT NULL PRIMARY KEY,
                listitem_uri TEXT NOT NULL,
                listitem_cid TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evaluation_cache (
                cache_key TEXT PRIMARY KEY,
                author_did TEXT NOT NULL,
                verdict_json TEXT NOT NULL,
                evaluated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS listblock_cache (
                user_did TEXT PRIMARY KEY,
                list_uri TEXT NOT NULL,
                blocked_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evaluation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_us INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'live',
                post_uri TEXT NOT NULL,
                post_text TEXT NOT NULL DEFAULT '',
                author_did TEXT NOT NULL,
                author_handle TEXT NOT NULL DEFAULT '',
                target_did TEXT NOT NULL,
                target_handle TEXT NOT NULL DEFAULT '',
                has_images INTEGER NOT NULL DEFAULT 0,
                primary_model TEXT NOT NULL,
                primary_action TEXT NOT NULL,
                primary_confidence REAL NOT NULL,
                primary_category TEXT NOT NULL DEFAULT '',
                primary_reason TEXT NOT NULL DEFAULT '',
                escalated INTEGER NOT NULL DEFAULT 0,
                escalation_reason TEXT,
                fallback_model TEXT,
                fallback_action TEXT,
                fallback_confidence REAL,
                fallback_category TEXT,
                fallback_reason TEXT,
                final_action TEXT NOT NULL,
                final_confidence REAL NOT NULL,
                outcome TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS allowlist (
                protected_did TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                reason TEXT,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (protected_did, subject_did)
            );

            CREATE TABLE IF NOT EXISTS did_handles (
                did TEXT PRIMARY KEY,
                handle TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dashboard_stats (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                snapshot_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            ",
        )
        .map_err(|e| {
            SkybouncerError::Database(format!("Failed to initialize base cache schema: {e}"))
        })?;

        // 2. Ensure backward-compatible columns exist on legacy tables BEFORE creating indexes on them
        let _ = conn.execute(
            "ALTER TABLE bounced_users ADD COLUMN protected_did TEXT NOT NULL DEFAULT '';",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE bounced_users ADD COLUMN post_text TEXT NOT NULL DEFAULT '';",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE bounced_user_rkeys ADD COLUMN protected_did TEXT NOT NULL DEFAULT '';",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE evaluation_log ADD COLUMN source TEXT NOT NULL DEFAULT 'live';",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE bounced_users ADD COLUMN expires_at INTEGER;",
            [],
        );

        // 3. Migrate legacy bounced_users table from single-column PK (subject_did) to composite PK (protected_did, subject_did)
        let needs_pk_migration: bool = {
            let mut stmt = conn.prepare("PRAGMA table_info(bounced_users);")?;
            let mut pk_count = 0;
            let mut subject_is_pk = false;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                let pk: i64 = row.get(5)?;
                if pk > 0 {
                    pk_count += 1;
                    if name == "subject_did" {
                        subject_is_pk = true;
                    }
                }
            }
            pk_count == 1 && subject_is_pk
        };

        if needs_pk_migration {
            conn.execute_batch(
                "
                CREATE TABLE bounced_users_v2 (
                    subject_did TEXT NOT NULL,
                    listitem_uri TEXT NOT NULL,
                    listitem_rkey TEXT NOT NULL,
                    listitem_cid TEXT NOT NULL,
                    category TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reason TEXT NOT NULL,
                    post_uri TEXT NOT NULL,
                    bounced_at INTEGER NOT NULL,
                    protected_did TEXT NOT NULL DEFAULT '',
                    post_text TEXT NOT NULL DEFAULT '',
                    expires_at INTEGER,
                    PRIMARY KEY (protected_did, subject_did)
                );
                INSERT OR IGNORE INTO bounced_users_v2
                    SELECT subject_did, listitem_uri, listitem_rkey, listitem_cid,
                           category, confidence, reason, post_uri, bounced_at,
                           COALESCE(protected_did, ''), COALESCE(post_text, ''), expires_at
                    FROM bounced_users;
                DROP TABLE bounced_users;
                ALTER TABLE bounced_users_v2 RENAME TO bounced_users;
                ",
            )
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to migrate bounced_users PK: {e}"))
            })?;
        }

        // 3.5. Migrate legacy bounced_user_rkeys table if it has a foreign key referencing bounced_users
        let has_legacy_rkeys_fk: bool = {
            let mut stmt = conn.prepare("PRAGMA foreign_key_list(bounced_user_rkeys);")?;
            let mut rows = stmt.query([])?;
            let mut found = false;
            while let Some(row) = rows.next()? {
                let table: String = row.get(2)?;
                if table == "bounced_users" {
                    found = true;
                    break;
                }
            }
            found
        };

        if has_legacy_rkeys_fk {
            conn.execute_batch(
                "
                CREATE TABLE bounced_user_rkeys_v2 (
                    protected_did TEXT NOT NULL DEFAULT '',
                    subject_did TEXT NOT NULL,
                    listitem_rkey TEXT NOT NULL PRIMARY KEY,
                    listitem_uri TEXT NOT NULL,
                    listitem_cid TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO bounced_user_rkeys_v2 (protected_did, subject_did, listitem_rkey, listitem_uri, listitem_cid, created_at)
                    SELECT COALESCE(protected_did, ''), subject_did, listitem_rkey, listitem_uri, listitem_cid, created_at FROM bounced_user_rkeys;
                DROP TABLE bounced_user_rkeys;
                ALTER TABLE bounced_user_rkeys_v2 RENAME TO bounced_user_rkeys;
                ",
            )
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to migrate bounced_user_rkeys FK: {e}"))
            })?;
        }

        // 4. Dependent indexes
        conn.execute_batch(
            "
            CREATE INDEX IF NOT EXISTS idx_bounced_users_bounced_at
                ON bounced_users(bounced_at);

            CREATE INDEX IF NOT EXISTS idx_bounced_users_subject
                ON bounced_users(subject_did);

            CREATE INDEX IF NOT EXISTS idx_bounced_users_protected
                ON bounced_users(protected_did);

            CREATE INDEX IF NOT EXISTS idx_bounced_users_expires
                ON bounced_users(expires_at) WHERE expires_at IS NOT NULL;

            CREATE INDEX IF NOT EXISTS idx_bounced_user_rkeys_subject
                ON bounced_user_rkeys(subject_did);

            CREATE INDEX IF NOT EXISTS idx_bounced_user_rkeys_protected
                ON bounced_user_rkeys(protected_did, subject_did);

            INSERT OR IGNORE INTO bounced_user_rkeys (protected_did, subject_did, listitem_rkey, listitem_uri, listitem_cid, created_at)
                SELECT protected_did, subject_did, listitem_rkey, listitem_uri, listitem_cid, bounced_at FROM bounced_users;

            CREATE TABLE IF NOT EXISTS evaluation_cache (
                cache_key TEXT PRIMARY KEY,
                author_did TEXT NOT NULL,
                verdict_json TEXT NOT NULL,
                evaluated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_evaluation_cache_expires_at
                ON evaluation_cache(expires_at);

            CREATE INDEX IF NOT EXISTS idx_evaluation_cache_author
                ON evaluation_cache(author_did);

            CREATE TABLE IF NOT EXISTS listblock_cache (
                user_did TEXT PRIMARY KEY,
                list_uri TEXT NOT NULL,
                blocked_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_evaluation_log_timestamp
                ON evaluation_log(timestamp_us DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_evaluation_log_target
                ON evaluation_log(target_did);

            CREATE INDEX IF NOT EXISTS idx_evaluation_log_source
                ON evaluation_log(source);

            CREATE INDEX IF NOT EXISTS idx_allowlist_protected
                ON allowlist(protected_did);

            CREATE INDEX IF NOT EXISTS idx_did_handles_updated
                ON did_handles(updated_at);
            ",
        )
        .map_err(|e| {
            SkybouncerError::Database(format!("Failed to initialize cache schema indexes: {e}"))
        })?;

        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set foreign_keys ON: {e}"))
            })?;

        Ok(())
    }
}
