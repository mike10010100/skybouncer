//! Thread-safe embedded SQLite deduplication and evaluation TTL cache.
//!
//! Provides a 3-table persistence engine:
//! - `mod_list_config`: stores provisioned moderation list metadata per protected user.
//! - `bounced_users`: records bounced violator DIDs and corresponding PDS listitem rkeys.
//! - `evaluation_cache`: caches classifier verdicts with configurable microsecond TTLs.
//!
//! Enforces zero lock holding across `.await` points by wrapping connections in
//! synchronous locks that are acquired and released exclusively inside method calls.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::classifier::Verdict;
use crate::error::SkybouncerError;

/// Persisted configuration of a provisioned ATProto moderation list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModListConfig {
    /// DID of the protected user owning this moderation list.
    pub user_did: String,
    /// Canonical AT-URI of the moderation list (`at://{did}/app.bsky.graph.list/{rkey}`).
    pub list_uri: String,
    /// Content identifier (CID) of the list record.
    pub list_cid: String,
    /// Microsecond Unix timestamp when the list was provisioned or discovered.
    pub created_at: u64,
}

/// Detailed record of a bounced violator persisted in SQLite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BouncedUser {
    /// Decentralized identifier (DID) of the bounced violator.
    pub subject_did: String,
    /// Protected user DID whose moderation list the violator was added to.
    #[serde(default)]
    pub protected_did: String,
    /// Canonical AT-URI of the created listitem record.
    pub listitem_uri: String,
    /// Record key (`rkey`) of the created listitem record on the PDS.
    pub listitem_rkey: String,
    /// Content identifier (CID) of the listitem record.
    pub listitem_cid: String,
    /// Category of the moderation violation.
    pub category: String,
    /// Classifier confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Human-readable or model-generated reason for the bounce.
    pub reason: String,
    /// AT-URI of the offending post that triggered the bounce.
    pub post_uri: String,
    /// Snippet or plaintext of the offending post that triggered the bounce.
    #[serde(default)]
    pub post_text: String,
    /// Microsecond Unix timestamp when the bounce was recorded.
    pub bounced_at: u64,
}

/// Thread-safe embedded SQLite deduplication and evaluation TTL cache.
#[derive(Clone)]
pub struct DeduplicationCache {
    conn: Arc<Mutex<Connection>>,
}

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

    fn apply_pragmas(conn: &Connection, busy_timeout_ms: u32) -> Result<(), SkybouncerError> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set journal_mode WAL: {e}"))
            })?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set synchronous NORMAL: {e}"))
            })?;
        conn.pragma_update(None, "busy_timeout", busy_timeout_ms)
            .map_err(|e| SkybouncerError::Database(format!("Failed to set busy_timeout: {e}")))?;
        conn.pragma_update(None, "temp_store", "MEMORY")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set temp_store MEMORY: {e}"))
            })?;
        conn.pragma_update(None, "mmap_size", 268_435_456_i64)
            .map_err(|e| SkybouncerError::Database(format!("Failed to set mmap_size: {e}")))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set foreign_keys ON: {e}"))
            })?;
        Ok(())
    }

    fn init_schema(conn: &Connection) -> Result<(), SkybouncerError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS mod_list_config (
                user_did TEXT PRIMARY KEY,
                list_uri TEXT NOT NULL,
                list_cid TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bounced_users (
                subject_did TEXT PRIMARY KEY,
                listitem_uri TEXT NOT NULL,
                listitem_rkey TEXT NOT NULL,
                listitem_cid TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT NOT NULL,
                post_uri TEXT NOT NULL,
                bounced_at INTEGER NOT NULL,
                protected_did TEXT NOT NULL DEFAULT '',
                post_text TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_bounced_users_bounced_at
                ON bounced_users(bounced_at);

            CREATE INDEX IF NOT EXISTS idx_bounced_users_protected
                ON bounced_users(protected_did);

            CREATE TABLE IF NOT EXISTS bounced_user_rkeys (
                subject_did TEXT NOT NULL,
                listitem_rkey TEXT NOT NULL PRIMARY KEY,
                listitem_uri TEXT NOT NULL,
                listitem_cid TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(subject_did) REFERENCES bounced_users(subject_did) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_bounced_user_rkeys_subject
                ON bounced_user_rkeys(subject_did);

            INSERT OR IGNORE INTO bounced_user_rkeys (subject_did, listitem_rkey, listitem_uri, listitem_cid, created_at)
                SELECT subject_did, listitem_rkey, listitem_uri, listitem_cid, bounced_at FROM bounced_users;

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
            ",
        )
        .map_err(|e| {
            SkybouncerError::Database(format!("Failed to initialize cache schema: {e}"))
        })?;

        // Forward-compatible migrations for existing databases
        let _ = conn.execute(
            "ALTER TABLE bounced_users ADD COLUMN protected_did TEXT NOT NULL DEFAULT '';",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE bounced_users ADD COLUMN post_text TEXT NOT NULL DEFAULT '';",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_bounced_users_protected ON bounced_users(protected_did);",
            [],
        );

        Ok(())
    }

    /// Retrieves the provisioned moderation list configuration for the given protected user DID.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn get_mod_list(&self, user_did: &str) -> Result<Option<ModListConfig>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT user_did, list_uri, list_cid, created_at
                 FROM mod_list_config
                 WHERE user_did = ?1;",
        )?;

        let res = stmt
            .query_row(params![user_did], |row| {
                let created_at_i64: i64 = row.get(3)?;
                let created_at = u64::try_from(created_at_i64.max(0)).unwrap_or_default();
                Ok(ModListConfig {
                    user_did: row.get(0)?,
                    list_uri: row.get(1)?,
                    list_cid: row.get(2)?,
                    created_at,
                })
            })
            .optional()?;

        Ok(res)
    }

    /// Persists or updates the moderation list configuration for a protected user DID.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the insert fails.
    pub fn set_mod_list(&self, config: &ModListConfig) -> Result<(), SkybouncerError> {
        let created_at_i64 = i64::try_from(config.created_at).unwrap_or(i64::MAX);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO mod_list_config (user_did, list_uri, list_cid, created_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(user_did) DO UPDATE SET
                     list_uri = excluded.list_uri,
                     list_cid = excluded.list_cid,
                     created_at = excluded.created_at;",
        )?;

        stmt.execute(params![
            config.user_did,
            config.list_uri,
            config.list_cid,
            created_at_i64,
        ])?;

        Ok(())
    }

    /// Checks whether an automatic `app.bsky.graph.listblock` subscription is cached for the user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn is_list_blocked(&self, user_did: &str) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM listblock_cache WHERE user_did = ?1 LIMIT 1;")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to prepare listblock query: {e}"))
            })?;

        let exists = stmt
            .query_row(params![user_did], |_| Ok(()))
            .optional()
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to check listblock cache: {e}"))
            })?
            .is_some();

        Ok(exists)
    }

    /// Records an active `app.bsky.graph.listblock` subscription for the user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite execution fails.
    pub fn set_list_blocked(&self, user_did: &str, list_uri: &str) -> Result<(), SkybouncerError> {
        let now_us = current_time_us();
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO listblock_cache (user_did, list_uri, blocked_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(user_did) DO UPDATE SET
                 list_uri = excluded.list_uri,
                 blocked_at = excluded.blocked_at;",
        )?;

        stmt.execute(params![user_did, list_uri, now_us])?;
        Ok(())
    }

    /// Checks whether the subject DID is already recorded as bounced.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn is_bounced(&self, subject_did: &str) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT 1 FROM bounced_users WHERE subject_did = ?1 LIMIT 1;")?;

        let exists = stmt
            .query_row(params![subject_did], |_| Ok(()))
            .optional()?
            .is_some();

        Ok(exists)
    }

    /// Checks whether a subject DID is recorded as bounced for a specific protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn is_bounced_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM bounced_users
             WHERE subject_did = ?1 AND (protected_did = ?2 OR protected_did = '') LIMIT 1;",
        )?;

        let exists = stmt
            .query_row(params![subject_did, protected_did], |_| Ok(()))
            .optional()?
            .is_some();

        Ok(exists)
    }

    /// Retrieves detailed record of a bounced violator if present.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_bounced_user(
        &self,
        subject_did: &str,
    ) -> Result<Option<BouncedUser>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT subject_did, listitem_uri, listitem_rkey, listitem_cid,
                        category, confidence, reason, post_uri, bounced_at,
                        protected_did, post_text
                 FROM bounced_users
                 WHERE subject_did = ?1;",
        )?;

        let res = stmt
            .query_row(params![subject_did], |row| {
                let bounced_at_i64: i64 = row.get(8)?;
                let bounced_at = u64::try_from(bounced_at_i64.max(0)).unwrap_or_default();
                Ok(BouncedUser {
                    subject_did: row.get(0)?,
                    listitem_uri: row.get(1)?,
                    listitem_rkey: row.get(2)?,
                    listitem_cid: row.get(3)?,
                    category: row.get(4)?,
                    confidence: row.get(5)?,
                    reason: row.get(6)?,
                    post_uri: row.get(7)?,
                    bounced_at,
                    protected_did: row.get(9)?,
                    post_text: row.get(10)?,
                })
            })
            .optional()?;

        Ok(res)
    }

    /// Records a bounced violator and their corresponding PDS listitem record into the cache.
    ///
    /// Preserves all historical and concurrent `listitem_rkey` values in `bounced_user_rkeys`
    /// while maintaining the canonical latest bounce state in `bounced_users`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the insert fails.
    pub fn record_bounce(&self, entry: &BouncedUser) -> Result<(), SkybouncerError> {
        let bounced_at_i64 = i64::try_from(entry.bounced_at).unwrap_or(i64::MAX);

        let conn = self.conn.lock();

        // 1. Insert or update the canonical bounced_users record
        let mut user_stmt = conn.prepare_cached(
            "INSERT INTO bounced_users (
                    subject_did, listitem_uri, listitem_rkey, listitem_cid,
                    category, confidence, reason, post_uri, bounced_at,
                    protected_did, post_text
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(subject_did) DO UPDATE SET
                     listitem_uri = excluded.listitem_uri,
                     listitem_rkey = excluded.listitem_rkey,
                     listitem_cid = excluded.listitem_cid,
                     category = excluded.category,
                     confidence = excluded.confidence,
                     reason = excluded.reason,
                     post_uri = excluded.post_uri,
                     bounced_at = excluded.bounced_at,
                     protected_did = excluded.protected_did,
                     post_text = excluded.post_text;",
        )?;

        user_stmt.execute(params![
            entry.subject_did,
            entry.listitem_uri,
            entry.listitem_rkey,
            entry.listitem_cid,
            entry.category,
            entry.confidence,
            entry.reason,
            entry.post_uri,
            bounced_at_i64,
            entry.protected_did,
            entry.post_text,
        ])?;

        // 2. Record in historical rkeys table (never overwrites or erases existing rkeys)
        let mut rkey_stmt = conn.prepare_cached(
            "INSERT INTO bounced_user_rkeys (
                subject_did, listitem_rkey, listitem_uri, listitem_cid, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(listitem_rkey) DO NOTHING;",
        )?;

        rkey_stmt.execute(params![
            entry.subject_did,
            entry.listitem_rkey,
            entry.listitem_uri,
            entry.listitem_cid,
            bounced_at_i64,
        ])?;

        Ok(())
    }

    /// Retrieves all known listitem `rkey` values associated with the given subject DID.
    ///
    /// Returns both the primary rkey and any historical or concurrent duplicate rkeys recorded.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_all_bounced_rkeys(&self, subject_did: &str) -> Result<Vec<String>, SkybouncerError> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare_cached(
            "SELECT listitem_rkey FROM bounced_user_rkeys
             WHERE subject_did = ?1
             ORDER BY created_at ASC;",
        )?;

        let rows = stmt.query_map(params![subject_did], |row| row.get::<_, String>(0))?;
        let mut rkeys = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for r in rows {
            let rk = r?;
            if seen.insert(rk.clone()) {
                rkeys.push(rk);
            }
        }

        // Defensive fallback: if bounced_user_rkeys had no entries, check bounced_users
        if rkeys.is_empty() {
            let mut fallback_stmt = conn.prepare_cached(
                "SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1;",
            )?;
            let fallback_rkey: Option<String> = fallback_stmt
                .query_row(params![subject_did], |row| row.get(0))
                .optional()?;
            if let Some(rk) = fallback_rkey {
                rkeys.push(rk);
            }
        }

        Ok(rkeys)
    }

    /// Retrieves all known listitem `rkey` values associated with the given subject DID.
    ///
    /// Alias for [`Self::get_all_bounced_rkeys`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_bounced_rkeys(&self, subject_did: &str) -> Result<Vec<String>, SkybouncerError> {
        self.get_all_bounced_rkeys(subject_did)
    }

    /// Lists recently bounced users ordered by most recent bounce timestamp descending.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn list_recent_bounces(&self, limit: usize) -> Result<Vec<BouncedUser>, SkybouncerError> {
        self.list_recent_bounces_for(None, limit)
    }

    /// Lists recently bounced users filtered by an optional protected user DID,
    /// ordered by most recent bounce timestamp descending.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn list_recent_bounces_for(
        &self,
        protected_did: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BouncedUser>, SkybouncerError> {
        let limit_i64 = i64::try_from(limit).unwrap_or(50);
        let conn = self.conn.lock();
        let mut list = Vec::new();

        if let Some(target) = protected_did.filter(|s| !s.trim().is_empty()) {
            let mut stmt = conn.prepare_cached(
                "SELECT subject_did, listitem_uri, listitem_rkey, listitem_cid,
                        category, confidence, reason, post_uri, bounced_at,
                        protected_did, post_text
                 FROM bounced_users
                 WHERE protected_did = ?1 OR protected_did = ''
                 ORDER BY bounced_at DESC
                 LIMIT ?2;",
            )?;

            let rows = stmt.query_map(params![target, limit_i64], |row| {
                let bounced_at_i64: i64 = row.get(8)?;
                let bounced_at = u64::try_from(bounced_at_i64.max(0)).unwrap_or_default();
                Ok(BouncedUser {
                    subject_did: row.get(0)?,
                    listitem_uri: row.get(1)?,
                    listitem_rkey: row.get(2)?,
                    listitem_cid: row.get(3)?,
                    category: row.get(4)?,
                    confidence: row.get(5)?,
                    reason: row.get(6)?,
                    post_uri: row.get(7)?,
                    bounced_at,
                    protected_did: row.get(9)?,
                    post_text: row.get(10)?,
                })
            })?;

            for r in rows {
                list.push(r?);
            }
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT subject_did, listitem_uri, listitem_rkey, listitem_cid,
                        category, confidence, reason, post_uri, bounced_at,
                        protected_did, post_text
                 FROM bounced_users
                 ORDER BY bounced_at DESC
                 LIMIT ?1;",
            )?;

            let rows = stmt.query_map(params![limit_i64], |row| {
                let bounced_at_i64: i64 = row.get(8)?;
                let bounced_at = u64::try_from(bounced_at_i64.max(0)).unwrap_or_default();
                Ok(BouncedUser {
                    subject_did: row.get(0)?,
                    listitem_uri: row.get(1)?,
                    listitem_rkey: row.get(2)?,
                    listitem_cid: row.get(3)?,
                    category: row.get(4)?,
                    confidence: row.get(5)?,
                    reason: row.get(6)?,
                    post_uri: row.get(7)?,
                    bounced_at,
                    protected_did: row.get(9)?,
                    post_text: row.get(10)?,
                })
            })?;

            for r in rows {
                list.push(r?);
            }
        }

        Ok(list)
    }

    /// Removes a bounced user from the cache, returning the primary listitem `rkey`.
    ///
    /// Cleans up both `bounced_users` and all associated entries in `bounced_user_rkeys`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_bounce(&self, subject_did: &str) -> Result<Option<String>, SkybouncerError> {
        let conn = self.conn.lock();

        let mut select_stmt =
            conn.prepare_cached("SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1;")?;

        let rkey: Option<String> = select_stmt
            .query_row(params![subject_did], |row| row.get(0))
            .optional()?;

        if rkey.is_some() {
            let mut delete_rkeys =
                conn.prepare_cached("DELETE FROM bounced_user_rkeys WHERE subject_did = ?1;")?;
            let _ = delete_rkeys.execute(params![subject_did]);

            let mut delete_stmt =
                conn.prepare_cached("DELETE FROM bounced_users WHERE subject_did = ?1;")?;

            delete_stmt.execute(params![subject_did])?;
        }

        Ok(rkey)
    }

    /// Removes a bounced user from the cache, returning all known listitem `rkey` values.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_all_bounces(&self, subject_did: &str) -> Result<Vec<String>, SkybouncerError> {
        let rkeys = self.get_all_bounced_rkeys(subject_did)?;
        if !rkeys.is_empty() {
            let conn = self.conn.lock();
            let mut delete_rkeys =
                conn.prepare_cached("DELETE FROM bounced_user_rkeys WHERE subject_did = ?1;")?;
            let _ = delete_rkeys.execute(params![subject_did]);

            let mut delete_stmt =
                conn.prepare_cached("DELETE FROM bounced_users WHERE subject_did = ?1;")?;
            delete_stmt.execute(params![subject_did])?;
        }
        Ok(rkeys)
    }

    /// Counts the total number of bounced users recorded in the cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn count_bounced(&self) -> Result<usize, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT COUNT(*) FROM bounced_users;")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(usize::try_from(count.max(0)).unwrap_or(0))
    }

    /// Retrieves a cached evaluation verdict for the given cache key.
    ///
    /// If the evaluation has expired, it is deleted from the cache and `Ok(None)` is returned.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] or [`SkybouncerError::Serialization`] on error.
    pub fn get_evaluation(&self, cache_key: &str) -> Result<Option<Verdict>, SkybouncerError> {
        let now_us = current_time_us();
        let conn = self.conn.lock();

        let mut stmt = conn.prepare_cached(
            "SELECT verdict_json, expires_at
                 FROM evaluation_cache
                 WHERE cache_key = ?1;",
        )?;

        let row: Option<(String, i64)> = stmt
            .query_row(params![cache_key], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;

        match row {
            Some((verdict_json, expires_at_i64)) => {
                let expires_at_u64 = u64::try_from(expires_at_i64.max(0)).unwrap_or_default();

                if now_us >= expires_at_u64 {
                    let mut del_stmt =
                        conn.prepare_cached("DELETE FROM evaluation_cache WHERE cache_key = ?1;")?;
                    let _ = del_stmt.execute(params![cache_key]);
                    Ok(None)
                } else {
                    let verdict: Verdict = serde_json::from_str(&verdict_json)?;
                    Ok(Some(verdict))
                }
            }
            None => Ok(None),
        }
    }

    /// Stores a classifier verdict in the evaluation cache with the specified TTL.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] or [`SkybouncerError::Serialization`] on error.
    pub fn set_evaluation(
        &self,
        cache_key: &str,
        author_did: &str,
        verdict: &Verdict,
        ttl: Duration,
    ) -> Result<(), SkybouncerError> {
        let verdict_json = serde_json::to_string(verdict)?;
        let now_us = current_time_us();
        let ttl_us = u64::try_from(ttl.as_micros()).unwrap_or(u64::MAX);
        let expires_us = now_us.saturating_add(ttl_us);

        let evaluated_at_i64 = i64::try_from(now_us).unwrap_or(i64::MAX);
        let expires_at_i64 = i64::try_from(expires_us).unwrap_or(i64::MAX);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO evaluation_cache (
                    cache_key, author_did, verdict_json, evaluated_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(cache_key) DO UPDATE SET
                     author_did = excluded.author_did,
                     verdict_json = excluded.verdict_json,
                     evaluated_at = excluded.evaluated_at,
                     expires_at = excluded.expires_at;",
        )?;

        stmt.execute(params![
            cache_key,
            author_did,
            verdict_json,
            evaluated_at_i64,
            expires_at_i64,
        ])?;

        Ok(())
    }

    /// Purges all expired evaluation records from the cache, returning the count of deleted rows.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the delete query fails.
    pub fn prune_expired_evaluations(&self) -> Result<usize, SkybouncerError> {
        let now_us = current_time_us();
        let now_i64 = i64::try_from(now_us).unwrap_or(i64::MAX);

        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("DELETE FROM evaluation_cache WHERE expires_at <= ?1;")?;
        let deleted = stmt.execute(params![now_i64])?;
        Ok(deleted)
    }

    /// Counts the total number of evaluation cache entries (including unexpired ones).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn count_evaluations(&self) -> Result<usize, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT COUNT(*) FROM evaluation_cache;")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(usize::try_from(count.max(0)).unwrap_or(0))
    }
}

/// Computes clock-warp safe microsecond timestamp since Unix epoch.
fn current_time_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or_default())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::classifier::ViolationCategory;

    #[test]
    fn test_mod_list_config_roundtrip() {
        let cache = DeduplicationCache::open_in_memory().unwrap();
        let config = ModListConfig {
            user_did: "did:plc:alice".to_string(),
            list_uri: "at://did:plc:alice/app.bsky.graph.list/123".to_string(),
            list_cid: "bafytestcid".to_string(),
            created_at: 1_700_000_000,
        };

        assert!(cache.get_mod_list("did:plc:alice").unwrap().is_none());
        cache.set_mod_list(&config).unwrap();

        let retrieved = cache.get_mod_list("did:plc:alice").unwrap().unwrap();
        assert_eq!(config, retrieved);

        // Update list_cid
        let updated = ModListConfig {
            list_cid: "bafyupdatedcid".to_string(),
            ..config
        };
        cache.set_mod_list(&updated).unwrap();
        let retrieved_updated = cache.get_mod_list("did:plc:alice").unwrap().unwrap();
        assert_eq!(retrieved_updated.list_cid, "bafyupdatedcid");
    }

    #[test]
    fn test_bounced_user_crud() {
        let cache = DeduplicationCache::open_in_memory().unwrap();
        let bounce = BouncedUser {
            subject_did: "did:plc:badactor".to_string(),
            protected_did: "did:plc:alice".to_string(),
            listitem_uri: "at://did:plc:alice/app.bsky.graph.listitem/item1".to_string(),
            listitem_rkey: "item1".to_string(),
            listitem_cid: "bafyitemcid".to_string(),
            category: "crypto_spam".to_string(),
            confidence: 0.98,
            reason: "Airdrop scam link".to_string(),
            post_uri: "at://did:plc:badactor/app.bsky.feed.post/post1".to_string(),
            post_text: "Free airdrop at scam link".to_string(),
            bounced_at: 1_700_000_100,
        };

        assert!(!cache.is_bounced("did:plc:badactor").unwrap());
        assert!(!cache
            .is_bounced_for("did:plc:alice", "did:plc:badactor")
            .unwrap());
        assert_eq!(cache.count_bounced().unwrap(), 0);

        cache.record_bounce(&bounce).unwrap();
        assert!(cache.is_bounced("did:plc:badactor").unwrap());
        assert!(cache
            .is_bounced_for("did:plc:alice", "did:plc:badactor")
            .unwrap());
        assert_eq!(cache.count_bounced().unwrap(), 1);

        let fetched = cache.get_bounced_user("did:plc:badactor").unwrap().unwrap();
        assert_eq!(fetched, bounce);

        let recent_alice = cache
            .list_recent_bounces_for(Some("did:plc:alice"), 10)
            .unwrap();
        assert_eq!(recent_alice.len(), 1);
        assert_eq!(recent_alice[0].post_text, "Free airdrop at scam link");

        // Remove bounce
        let rkey = cache.remove_bounce("did:plc:badactor").unwrap();
        assert_eq!(rkey.as_deref(), Some("item1"));
        assert!(!cache.is_bounced("did:plc:badactor").unwrap());
        assert!(!cache
            .is_bounced_for("did:plc:alice", "did:plc:badactor")
            .unwrap());
        assert_eq!(cache.count_bounced().unwrap(), 0);

        // Removing non-existent returns None
        assert!(cache.remove_bounce("did:plc:badactor").unwrap().is_none());
    }

    #[test]
    fn test_evaluation_ttl_and_pruning() {
        let cache = DeduplicationCache::open_in_memory().unwrap();
        let verdict = Verdict::Violation {
            category: ViolationCategory::Spam,
            confidence: 0.85,
            reason: "Automated mention spam".to_string(),
        };

        // Cache for 100ms
        cache
            .set_evaluation(
                "key1",
                "did:plc:spammer",
                &verdict,
                Duration::from_millis(100),
            )
            .unwrap();

        let cached = cache.get_evaluation("key1").unwrap();
        assert_eq!(cached, Some(verdict.clone()));

        // Expired evaluation (with 0ms TTL)
        cache
            .set_evaluation("key2", "did:plc:spammer2", &verdict, Duration::ZERO)
            .unwrap();

        // get_evaluation on expired item returns None and purges it
        let expired = cache.get_evaluation("key2").unwrap();
        assert_eq!(expired, None);

        // Pruning removes expired entries
        let pruned = cache.prune_expired_evaluations().unwrap();
        let _ = pruned;
    }
}
