//! Thread-safe embedded SQLite deduplication and evaluation TTL cache.
//!
//! Provides a 3-table persistence engine:
//! - `mod_list_config`: stores provisioned moderation list metadata per protected user.
//! - `bounced_users`: records bounced violator DIDs and corresponding PDS listitem rkeys.
//! - `evaluation_cache`: caches classifier verdicts with configurable microsecond TTLs.
//!
//! Enforces zero lock holding across `.await` points by wrapping connections in
//! synchronous locks that are acquired and released exclusively inside method calls.

use std::collections::{HashMap, HashSet};
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
    /// Optional microsecond Unix timestamp when the temporary bounce expires (or `None` for permanent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl BouncedUser {
    /// Returns true if this bounce has an expiration timestamp and it has expired relative to `now_us`.
    #[must_use]
    pub fn is_expired(&self, now_us: u64) -> bool {
        self.expires_at.is_some_and(|exp| exp <= now_us)
    }
}

/// An account immunized on a protected user's moderation allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    /// Decentralized identifier (DID) of the protected user owning this allowlist.
    pub protected_did: String,
    /// Decentralized identifier (DID) of the allowed/immunized subject.
    #[serde(alias = "allowed_did")]
    pub subject_did: String,
    /// ATProto handle of the allowed subject, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Optional rationale explaining why the account was allowlisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Microsecond Unix timestamp when the entry was created.
    pub created_at: u64,
}

/// Comprehensive audit record of an AI evaluation (Tier 1 & Tier 2 breakdown) persisted in SQLite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationLogEntry {
    /// Auto-incrementing primary key ID.
    pub id: i64,
    /// Evaluation timestamp in microseconds since Unix epoch.
    pub timestamp_us: u64,
    /// Origin of this evaluation: "live" (Jetstream firehose) or "simulation" (test harness).
    pub source: String,
    /// Canonical AT-URI of the evaluated post.
    pub post_uri: String,
    /// Plaintext snippet or full text of the post.
    pub post_text: String,
    /// Decentralized identifier (DID) of the post author.
    pub author_did: String,
    /// ATProto handle of the author, if resolved.
    pub author_handle: String,
    /// Protected user DID targeted by this interaction.
    pub target_did: String,
    /// ATProto handle of the protected user, if resolved.
    pub target_handle: String,
    /// Whether the interaction included attached images.
    pub has_images: bool,
    /// Model name of the primary Tier-1 System-1 classifier.
    pub primary_model: String,
    /// Action emitted by Tier 1 ("allow" or "violation").
    pub primary_action: String,
    /// Confidence score from Tier 1 (0.0 to 1.0).
    pub primary_confidence: f64,
    /// Moderation category from Tier 1, if any.
    pub primary_category: String,
    /// Rationale emitted by Tier 1.
    pub primary_reason: String,
    /// Whether evaluation escalated to the Tier-2 fallback classifier.
    pub escalated: bool,
    /// Rationale explaining why escalation occurred or was bypassed.
    pub escalation_reason: Option<String>,
    /// Model name of the secondary Tier-2 fallback classifier, if escalated.
    pub fallback_model: Option<String>,
    /// Action emitted by Tier 2 ("allow" or "violation"), if escalated.
    pub fallback_action: Option<String>,
    /// Confidence score from Tier 2 (0.0 to 1.0), if escalated.
    pub fallback_confidence: Option<f64>,
    /// Moderation category from Tier 2, if escalated.
    pub fallback_category: Option<String>,
    /// Rationale emitted by Tier 2, if escalated.
    pub fallback_reason: Option<String>,
    /// Final verdict action adopted by the engine ("allow" or "violation").
    pub final_action: String,
    /// Final confidence score adopted by the engine.
    pub final_confidence: f64,
    /// Final operational outcome (e.g. "Bounced", "Permitted", "Below Rubric Threshold", "Rate Limited", etc.).
    pub outcome: String,
}

/// Unpersisted evaluation log record prepared for database insertion.
#[derive(Debug, Clone, PartialEq)]
pub struct NewEvaluationLog {
    /// Evaluation timestamp in microseconds since Unix epoch.
    pub timestamp_us: u64,
    /// Origin of this evaluation: "live" or "simulation".
    pub source: String,
    /// Canonical AT-URI of the evaluated post.
    pub post_uri: String,
    /// Plaintext snippet or full text of the post.
    pub post_text: String,
    /// Decentralized identifier (DID) of the post author.
    pub author_did: String,
    /// ATProto handle of the author, if resolved.
    pub author_handle: String,
    /// Protected user DID targeted by this interaction.
    pub target_did: String,
    /// ATProto handle of the protected user, if resolved.
    pub target_handle: String,
    /// Whether the interaction included attached images.
    pub has_images: bool,
    /// Model name of the primary Tier-1 System-1 classifier.
    pub primary_model: String,
    /// Action emitted by Tier 1 ("allow" or "violation").
    pub primary_action: String,
    /// Confidence score from Tier 1 (0.0 to 1.0).
    pub primary_confidence: f64,
    /// Moderation category from Tier 1, if any.
    pub primary_category: String,
    /// Rationale emitted by Tier 1.
    pub primary_reason: String,
    /// Whether evaluation escalated to the Tier-2 fallback classifier.
    pub escalated: bool,
    /// Rationale explaining why escalation occurred or was bypassed.
    pub escalation_reason: Option<String>,
    /// Model name of the secondary Tier-2 fallback classifier, if escalated.
    pub fallback_model: Option<String>,
    /// Action emitted by Tier 2 ("allow" or "violation"), if escalated.
    pub fallback_action: Option<String>,
    /// Confidence score from Tier 2 (0.0 to 1.0), if escalated.
    pub fallback_confidence: Option<f64>,
    /// Moderation category from Tier 2, if escalated.
    pub fallback_category: Option<String>,
    /// Rationale emitted by Tier 2, if escalated.
    pub fallback_reason: Option<String>,
    /// Final verdict action adopted by the engine.
    pub final_action: String,
    /// Final confidence score adopted by the engine.
    pub final_confidence: f64,
    /// Final operational outcome.
    pub outcome: String,
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
        conn.pragma_update(None, "foreign_keys", "OFF")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set foreign_keys OFF: {e}"))
            })?;
        Ok(())
    }

    fn init_schema(conn: &Connection) -> Result<(), SkybouncerError> {
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
             WHERE subject_did = ?1 AND protected_did = ?2 LIMIT 1;",
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
                        protected_did, post_text, expires_at
                 FROM bounced_users
                 WHERE subject_did = ?1
                 LIMIT 1;",
        )?;

        let res = stmt
            .query_row(params![subject_did], |row| {
                let bounced_at_i64: i64 = row.get(8)?;
                let bounced_at = u64::try_from(bounced_at_i64.max(0)).unwrap_or_default();
                let expires_at = row
                    .get::<_, Option<i64>>(11)?
                    .map(|v| u64::try_from(v.max(0)).unwrap_or_default());
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
                    expires_at,
                })
            })
            .optional()?;

        Ok(res)
    }

    /// Retrieves detailed record of a bounced violator for a specific protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_bounced_user_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Option<BouncedUser>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT subject_did, listitem_uri, listitem_rkey, listitem_cid,
                        category, confidence, reason, post_uri, bounced_at,
                        protected_did, post_text, expires_at
                 FROM bounced_users
                 WHERE subject_did = ?1 AND protected_did = ?2;",
        )?;

        let res = stmt
            .query_row(params![subject_did, protected_did], |row| {
                let bounced_at_i64: i64 = row.get(8)?;
                let bounced_at = u64::try_from(bounced_at_i64.max(0)).unwrap_or_default();
                let expires_at = row
                    .get::<_, Option<i64>>(11)?
                    .map(|v| u64::try_from(v.max(0)).unwrap_or_default());
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
                    expires_at,
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
    /// Uses a single SQLite transaction to guarantee atomicity.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the insert fails.
    pub fn record_bounce(&self, entry: &BouncedUser) -> Result<(), SkybouncerError> {
        let bounced_at_i64 = i64::try_from(entry.bounced_at).unwrap_or(i64::MAX);
        let expires_at_i64 = entry
            .expires_at
            .map(|v| i64::try_from(v).unwrap_or(i64::MAX));

        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(|e| {
            SkybouncerError::Database(format!(
                "Failed to start transaction for bounce record: {e}"
            ))
        })?;

        // 1. Insert or update the canonical bounced_users record
        {
            let mut user_stmt = tx.prepare_cached(
                "INSERT INTO bounced_users (
                        subject_did, listitem_uri, listitem_rkey, listitem_cid,
                        category, confidence, reason, post_uri, bounced_at,
                        protected_did, post_text, expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(protected_did, subject_did) DO UPDATE SET
                         listitem_uri = excluded.listitem_uri,
                         listitem_rkey = excluded.listitem_rkey,
                         listitem_cid = excluded.listitem_cid,
                         category = excluded.category,
                         confidence = excluded.confidence,
                         reason = excluded.reason,
                         post_uri = excluded.post_uri,
                         bounced_at = excluded.bounced_at,
                         post_text = excluded.post_text,
                         expires_at = excluded.expires_at;",
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
                expires_at_i64,
            ])?;
        }

        // 2. Record in historical rkeys table (never overwrites or erases existing rkeys)
        {
            let mut rkey_stmt = tx.prepare_cached(
                "INSERT INTO bounced_user_rkeys (
                    protected_did, subject_did, listitem_rkey, listitem_uri, listitem_cid, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(listitem_rkey) DO NOTHING;",
            )?;

            rkey_stmt.execute(params![
                entry.protected_did,
                entry.subject_did,
                entry.listitem_rkey,
                entry.listitem_uri,
                entry.listitem_cid,
                bounced_at_i64,
            ])?;
        }

        tx.commit().map_err(|e| {
            SkybouncerError::Database(format!("Failed to commit bounce record transaction: {e}"))
        })?;

        Ok(())
    }

    /// Retrieves all known listitem `rkey` values associated with the given subject DID for a protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_all_bounced_rkeys_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Vec<String>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut rkeys = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if protected_did.is_empty() {
            let mut stmt = conn.prepare_cached(
                "SELECT listitem_rkey FROM bounced_user_rkeys
                 WHERE subject_did = ?1
                 ORDER BY created_at ASC;",
            )?;

            let rows = stmt.query_map(params![subject_did], |row| row.get::<_, String>(0))?;
            for r in rows {
                let rk = r?;
                if seen.insert(rk.clone()) {
                    rkeys.push(rk);
                }
            }

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
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT listitem_rkey FROM bounced_user_rkeys
                 WHERE subject_did = ?1 AND protected_did = ?2
                 ORDER BY created_at ASC;",
            )?;

            let rows = stmt.query_map(params![subject_did, protected_did], |row| {
                row.get::<_, String>(0)
            })?;
            for r in rows {
                let rk = r?;
                if seen.insert(rk.clone()) {
                    rkeys.push(rk);
                }
            }

            if rkeys.is_empty() {
                let mut fallback_stmt = conn.prepare_cached(
                    "SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1 AND protected_did = ?2;",
                )?;
                let fallback_rkey: Option<String> = fallback_stmt
                    .query_row(params![subject_did, protected_did], |row| row.get(0))
                    .optional()?;
                if let Some(rk) = fallback_rkey {
                    rkeys.push(rk);
                }
            }
        }

        Ok(rkeys)
    }

    /// Retrieves all known listitem `rkey` values associated with the given subject DID across all lists.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn get_all_bounced_rkeys(&self, subject_did: &str) -> Result<Vec<String>, SkybouncerError> {
        self.get_all_bounced_rkeys_for("", subject_did)
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
    /// Strictly isolates tenant moderation data: when `protected_did` is provided,
    /// only bounces for that exact tenant are returned.
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
                        protected_did, post_text, expires_at
                 FROM bounced_users
                 WHERE protected_did = ?1
                 ORDER BY bounced_at DESC
                 LIMIT ?2;",
            )?;

            let rows = stmt.query_map(params![target, limit_i64], |row| {
                let bounced_at_i64: i64 = row.get(8)?;
                let bounced_at = u64::try_from(bounced_at_i64.max(0)).unwrap_or_default();
                let expires_at = row
                    .get::<_, Option<i64>>(11)?
                    .map(|v| u64::try_from(v.max(0)).unwrap_or_default());
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
                    expires_at,
                })
            })?;

            for r in rows {
                list.push(r?);
            }
        } else {
            let mut stmt = conn.prepare_cached(
                "SELECT subject_did, listitem_uri, listitem_rkey, listitem_cid,
                        category, confidence, reason, post_uri, bounced_at,
                        protected_did, post_text, expires_at
                 FROM bounced_users
                 ORDER BY bounced_at DESC
                 LIMIT ?1;",
            )?;

            let rows = stmt.query_map(params![limit_i64], |row| {
                let bounced_at_i64: i64 = row.get(8)?;
                let bounced_at = u64::try_from(bounced_at_i64.max(0)).unwrap_or_default();
                let expires_at = row
                    .get::<_, Option<i64>>(11)?
                    .map(|v| u64::try_from(v.max(0)).unwrap_or_default());
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
                    expires_at,
                })
            })?;

            for r in rows {
                list.push(r?);
            }
        }

        Ok(list)
    }

    /// Lists all temporary bounces that have expired relative to `now_us`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the SQLite query fails.
    pub fn list_expired_bounces(&self, now_us: u64) -> Result<Vec<BouncedUser>, SkybouncerError> {
        let now_i64 = i64::try_from(now_us).unwrap_or(i64::MAX);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT subject_did, listitem_uri, listitem_rkey, listitem_cid,
                    category, confidence, reason, post_uri, bounced_at,
                    protected_did, post_text, expires_at
             FROM bounced_users
             WHERE expires_at IS NOT NULL AND expires_at <= ?1
             ORDER BY expires_at ASC;",
        )?;

        let rows = stmt.query_map(params![now_i64], |row| {
            let bounced_at_i64: i64 = row.get(8)?;
            let bounced_at = u64::try_from(bounced_at_i64.max(0)).unwrap_or_default();
            let expires_at = row
                .get::<_, Option<i64>>(11)?
                .map(|v| u64::try_from(v.max(0)).unwrap_or_default());
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
                expires_at,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Removes a bounced user from the cache for a specific protected user, returning the listitem `rkey`.
    ///
    /// Cleans up both `bounced_users` and all associated entries in `bounced_user_rkeys`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_bounce_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Option<String>, SkybouncerError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(|e| {
            SkybouncerError::Database(format!(
                "Failed to start transaction for remove_bounce: {e}"
            ))
        })?;

        let rkey: Option<String> = {
            if protected_did.is_empty() {
                let mut select_stmt = tx.prepare_cached(
                    "SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1 LIMIT 1;",
                )?;
                select_stmt
                    .query_row(params![subject_did], |row| row.get(0))
                    .optional()?
            } else {
                let mut select_stmt = tx.prepare_cached(
                    "SELECT listitem_rkey FROM bounced_users WHERE subject_did = ?1 AND protected_did = ?2 LIMIT 1;",
                )?;
                select_stmt
                    .query_row(params![subject_did, protected_did], |row| row.get(0))
                    .optional()?
            }
        };

        if rkey.is_some() {
            if protected_did.is_empty() {
                let mut delete_rkeys =
                    tx.prepare_cached("DELETE FROM bounced_user_rkeys WHERE subject_did = ?1;")?;
                let _ = delete_rkeys.execute(params![subject_did]);

                let mut delete_stmt =
                    tx.prepare_cached("DELETE FROM bounced_users WHERE subject_did = ?1;")?;
                delete_stmt.execute(params![subject_did])?;
            } else {
                let mut delete_rkeys = tx.prepare_cached(
                    "DELETE FROM bounced_user_rkeys WHERE subject_did = ?1 AND protected_did = ?2;",
                )?;
                let _ = delete_rkeys.execute(params![subject_did, protected_did]);

                let mut delete_stmt = tx.prepare_cached(
                    "DELETE FROM bounced_users WHERE subject_did = ?1 AND protected_did = ?2;",
                )?;
                delete_stmt.execute(params![subject_did, protected_did])?;
            }
        }

        tx.commit().map_err(|e| {
            SkybouncerError::Database(format!("Failed to commit remove_bounce transaction: {e}"))
        })?;

        Ok(rkey)
    }

    /// Removes a bounced user from the cache across all lists, returning the primary listitem `rkey`.
    ///
    /// Cleans up both `bounced_users` and all associated entries in `bounced_user_rkeys`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_bounce(&self, subject_did: &str) -> Result<Option<String>, SkybouncerError> {
        self.remove_bounce_for("", subject_did)
    }

    /// Removes a bounced user from the cache for a specific protected user, returning all known listitem `rkey` values.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_all_bounces_for(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Vec<String>, SkybouncerError> {
        let rkeys = self.get_all_bounced_rkeys_for(protected_did, subject_did)?;
        if !rkeys.is_empty() {
            let mut conn = self.conn.lock();
            let tx = conn.transaction().map_err(|e| {
                SkybouncerError::Database(format!(
                    "Failed to start transaction for remove_all_bounces: {e}"
                ))
            })?;

            if protected_did.is_empty() {
                let mut delete_rkeys =
                    tx.prepare_cached("DELETE FROM bounced_user_rkeys WHERE subject_did = ?1;")?;
                let _ = delete_rkeys.execute(params![subject_did]);

                let mut delete_stmt =
                    tx.prepare_cached("DELETE FROM bounced_users WHERE subject_did = ?1;")?;
                delete_stmt.execute(params![subject_did])?;
            } else {
                let mut delete_rkeys = tx.prepare_cached(
                    "DELETE FROM bounced_user_rkeys WHERE subject_did = ?1 AND protected_did = ?2;",
                )?;
                let _ = delete_rkeys.execute(params![subject_did, protected_did]);

                let mut delete_stmt = tx.prepare_cached(
                    "DELETE FROM bounced_users WHERE subject_did = ?1 AND protected_did = ?2;",
                )?;
                delete_stmt.execute(params![subject_did, protected_did])?;
            }

            tx.commit().map_err(|e| {
                SkybouncerError::Database(format!(
                    "Failed to commit remove_all_bounces transaction: {e}"
                ))
            })?;
        }
        Ok(rkeys)
    }

    /// Removes a bounced user from the cache across all lists, returning all known listitem `rkey` values.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query or deletion fails.
    pub fn remove_all_bounces(&self, subject_did: &str) -> Result<Vec<String>, SkybouncerError> {
        self.remove_all_bounces_for("", subject_did)
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
    /// Also prunes the historical evaluation audit log to prevent unbounded database growth.
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

        // Prune evaluation log table to retain at most 5,000 recent evaluations
        let mut prune_logs_stmt = conn.prepare_cached(
            "DELETE FROM evaluation_log WHERE id NOT IN (
                SELECT id FROM evaluation_log ORDER BY timestamp_us DESC, id DESC LIMIT 5000
             );",
        )?;
        let _ = prune_logs_stmt.execute([]);

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

    /// Records a comprehensive AI evaluation log entry (Tier 1 & Tier 2 breakdown).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite insertion fails.
    pub fn record_evaluation_log(&self, entry: &NewEvaluationLog) -> Result<i64, SkybouncerError> {
        let timestamp_i64 = i64::try_from(entry.timestamp_us).unwrap_or(i64::MAX);
        let has_images_i64 = if entry.has_images { 1 } else { 0 };
        let escalated_i64 = if entry.escalated { 1 } else { 0 };
        let primary_conf_f64 = entry.primary_confidence;
        let fallback_conf_f64 = entry.fallback_confidence;
        let final_conf_f64 = entry.final_confidence;

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO evaluation_log (
                timestamp_us, source, post_uri, post_text,
                author_did, author_handle, target_did, target_handle,
                has_images, primary_model, primary_action, primary_confidence,
                primary_category, primary_reason, escalated, escalation_reason,
                fallback_model, fallback_action, fallback_confidence,
                fallback_category, fallback_reason, final_action, final_confidence,
                outcome
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
             );",
        )?;

        stmt.execute(params![
            timestamp_i64,
            entry.source,
            entry.post_uri,
            entry.post_text,
            entry.author_did,
            entry.author_handle,
            entry.target_did,
            entry.target_handle,
            has_images_i64,
            entry.primary_model,
            entry.primary_action,
            primary_conf_f64,
            entry.primary_category,
            entry.primary_reason,
            escalated_i64,
            entry.escalation_reason,
            entry.fallback_model,
            entry.fallback_action,
            fallback_conf_f64,
            entry.fallback_category,
            entry.fallback_reason,
            entry.final_action,
            final_conf_f64,
            entry.outcome,
        ])?;

        Ok(conn.last_insert_rowid())
    }

    /// Lists evaluation log entries ordered by timestamp descending, with optional filtering.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_evaluation_logs(
        &self,
        target_did: Option<&str>,
        source: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<EvaluationLogEntry>, SkybouncerError> {
        let limit_i64 = i64::try_from(limit.clamp(1, 200)).unwrap_or(50);
        let offset_i64 = i64::try_from(offset).unwrap_or(0);
        let clean_target = target_did.filter(|s| !s.trim().is_empty());
        let clean_source = source.filter(|s| !s.trim().is_empty() && *s != "all");
        let conn = self.conn.lock();

        let mut query = String::from(
            "SELECT id, timestamp_us, source, post_uri, post_text,
                    author_did, author_handle, target_did, target_handle,
                    has_images, primary_model, primary_action, primary_confidence,
                    primary_category, primary_reason, escalated, escalation_reason,
                    fallback_model, fallback_action, fallback_confidence,
                    fallback_category, fallback_reason, final_action, final_confidence,
                    outcome
             FROM evaluation_log WHERE 1=1",
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(t) = clean_target {
            query.push_str(" AND target_did = ?");
            params_vec.push(Box::new(t.to_string()));
        }
        if let Some(s) = clean_source {
            query.push_str(" AND source = ?");
            params_vec.push(Box::new(s.to_string()));
        }
        query.push_str(" ORDER BY timestamp_us DESC, id DESC LIMIT ? OFFSET ?;");
        params_vec.push(Box::new(limit_i64));
        params_vec.push(Box::new(offset_i64));

        let param_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(AsRef::as_ref).collect();
        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            let id: i64 = row.get(0)?;
            let ts_i64: i64 = row.get(1)?;
            let timestamp_us = u64::try_from(ts_i64.max(0)).unwrap_or_default();
            let source: String = row.get(2)?;
            let post_uri: String = row.get(3)?;
            let post_text: String = row.get(4)?;
            let author_did: String = row.get(5)?;
            let author_handle: String = row.get(6)?;
            let target_did: String = row.get(7)?;
            let target_handle: String = row.get(8)?;
            let has_images: bool = row.get::<_, i64>(9)? != 0;
            let primary_model: String = row.get(10)?;
            let primary_action: String = row.get(11)?;
            let primary_confidence: f64 = row.get(12)?;
            let primary_category: String = row.get(13)?;
            let primary_reason: String = row.get(14)?;
            let escalated: bool = row.get::<_, i64>(15)? != 0;
            let escalation_reason: Option<String> = row.get(16)?;
            let fallback_model: Option<String> = row.get(17)?;
            let fallback_action: Option<String> = row.get(18)?;
            let fallback_confidence: Option<f64> = row.get(19)?;
            let fallback_category: Option<String> = row.get(20)?;
            let fallback_reason: Option<String> = row.get(21)?;
            let final_action: String = row.get(22)?;
            let final_confidence: f64 = row.get(23)?;
            let outcome: String = row.get(24)?;

            Ok(EvaluationLogEntry {
                id,
                timestamp_us,
                source,
                post_uri,
                post_text,
                author_did,
                author_handle,
                target_did,
                target_handle,
                has_images,
                primary_model,
                primary_action,
                primary_confidence,
                primary_category,
                primary_reason,
                escalated,
                escalation_reason,
                fallback_model,
                fallback_action,
                fallback_confidence,
                fallback_category,
                fallback_reason,
                final_action,
                final_confidence,
                outcome,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Counts evaluation logs matching optional target DID and source filters.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn count_evaluation_logs(
        &self,
        target_did: Option<&str>,
        source: Option<&str>,
    ) -> Result<usize, SkybouncerError> {
        let clean_target = target_did.filter(|s| !s.trim().is_empty());
        let clean_source = source.filter(|s| !s.trim().is_empty() && *s != "all");
        let conn = self.conn.lock();

        let mut query = String::from("SELECT COUNT(*) FROM evaluation_log WHERE 1=1");
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(t) = clean_target {
            query.push_str(" AND target_did = ?");
            params_vec.push(Box::new(t.to_string()));
        }
        if let Some(s) = clean_source {
            query.push_str(" AND source = ?");
            params_vec.push(Box::new(s.to_string()));
        }

        let param_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(AsRef::as_ref).collect();
        let mut stmt = conn.prepare(&query)?;
        let count: i64 = stmt.query_row(param_refs.as_slice(), |row| row.get(0))?;
        Ok(usize::try_from(count.max(0)).unwrap_or(0))
    }

    /// Prunes evaluation logs to prevent unbounded growth, retaining at most `max_retained` newest rows.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite execution fails.
    pub fn prune_evaluation_logs(&self, max_retained: usize) -> Result<usize, SkybouncerError> {
        let max_i64 = i64::try_from(max_retained.max(1)).unwrap_or(5000);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "DELETE FROM evaluation_log WHERE id NOT IN (
                SELECT id FROM evaluation_log ORDER BY timestamp_us DESC, id DESC LIMIT ?1
             );",
        )?;
        let deleted = stmt.execute(params![max_i64])?;
        Ok(deleted)
    }

    /// Adds an account to the protected user's moderation allowlist.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite persistence fails.
    pub fn add_to_allowlist(
        &self,
        protected_did: &str,
        subject_did: &str,
        reason: Option<&str>,
    ) -> Result<(), SkybouncerError> {
        let conn = self.conn.lock();
        let now_us = current_time_us();
        let now_i64 = i64::try_from(now_us).unwrap_or(i64::MAX);

        let mut stmt = conn.prepare_cached(
            "INSERT INTO allowlist (protected_did, subject_did, reason, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(protected_did, subject_did) DO UPDATE SET
                 reason = excluded.reason,
                 created_at = excluded.created_at;",
        )?;

        stmt.execute(params![protected_did, subject_did, reason, now_i64])?;
        Ok(())
    }

    /// Removes an account from the protected user's moderation allowlist.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite delete fails.
    pub fn remove_from_allowlist(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "DELETE FROM allowlist WHERE protected_did = ?1 AND subject_did = ?2;",
        )?;
        let affected = stmt.execute(params![protected_did, subject_did])?;
        Ok(affected > 0)
    }

    /// Checks whether an account is currently on the protected user's moderation allowlist in SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_allowlisted(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM allowlist WHERE protected_did = ?1 AND subject_did = ?2 LIMIT 1;",
        )?;
        let exists = stmt
            .query_row(params![protected_did, subject_did], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    /// Lists all accounts on the protected user's moderation allowlist.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_allowlist(
        &self,
        protected_did: &str,
    ) -> Result<Vec<AllowlistEntry>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT a.protected_did, a.subject_did, a.reason, a.created_at, h.handle
             FROM allowlist a
             LEFT JOIN did_handles h ON a.subject_did = h.did
             WHERE a.protected_did = ?1
             ORDER BY a.created_at DESC;",
        )?;
        let rows = stmt.query_map(params![protected_did], |row| {
            let p_did: String = row.get(0)?;
            let s_did: String = row.get(1)?;
            let reason: Option<String> = row.get(2)?;
            let created_at_i64: i64 = row.get(3)?;
            let created_at = u64::try_from(created_at_i64.max(0)).unwrap_or_default();
            let handle: Option<String> = row.get(4)?;
            Ok(AllowlistEntry {
                protected_did: p_did,
                subject_did: s_did,
                handle,
                reason,
                created_at,
            })
        })?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r?);
        }
        Ok(entries)
    }

    /// Loads all allowlist records across all protected users into a nested HashMap.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn load_all_allowlists(&self) -> Result<HashMap<String, HashSet<String>>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT protected_did, subject_did FROM allowlist;")?;
        let rows = stmt.query_map([], |row| {
            let p_did: String = row.get(0)?;
            let s_did: String = row.get(1)?;
            Ok((p_did, s_did))
        })?;

        let mut map: HashMap<String, HashSet<String>> = HashMap::new();
        for r in rows {
            let (p, s) = r?;
            map.entry(p).or_default().insert(s);
        }
        Ok(map)
    }

    /// Looks up the cached handle for a given DID from SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_handle_for_did(&self, did: &str) -> Result<Option<String>, SkybouncerError> {
        let conn = self.conn.lock();
        let clean = did.trim();
        let mut stmt =
            conn.prepare_cached("SELECT handle FROM did_handles WHERE did = ?1 LIMIT 1;")?;
        let handle = stmt
            .query_row(params![clean], |row| row.get(0))
            .optional()?;
        Ok(handle)
    }

    /// Looks up the cached DID for a given handle from SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_did_for_handle(&self, handle: &str) -> Result<Option<String>, SkybouncerError> {
        let clean = handle.trim().trim_start_matches('@');
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT did FROM did_handles WHERE handle = ?1 COLLATE NOCASE LIMIT 1;",
        )?;
        let did = stmt
            .query_row(params![clean], |row| row.get(0))
            .optional()?;
        Ok(did)
    }

    /// Looks up the cached DID for a handle, ignoring mappings older than `max_age_us`
    /// microseconds.
    ///
    /// This prevents a stale persisted mapping from shadowing a handle that has since
    /// rotated to a new owner on the network.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_did_for_handle_with_ttl(
        &self,
        handle: &str,
        max_age_us: u64,
    ) -> Result<Option<String>, SkybouncerError> {
        let clean = handle.trim().trim_start_matches('@');
        let cutoff_i64 =
            i64::try_from(current_time_us().saturating_sub(max_age_us)).unwrap_or(i64::MAX);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT did FROM did_handles WHERE handle = ?1 COLLATE NOCASE AND updated_at >= ?2 LIMIT 1;",
        )?;
        let did = stmt
            .query_row(params![clean, cutoff_i64], |row| row.get(0))
            .optional()?;
        Ok(did)
    }

    /// Caches a DID to handle mapping in SQLite.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite execution fails.
    pub fn set_handle_for_did(&self, did: &str, handle: &str) -> Result<(), SkybouncerError> {
        let clean_did = did.trim();
        let clean_handle = handle.trim().trim_start_matches('@');
        if clean_did.is_empty() || clean_handle.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock();
        let now_us = current_time_us();
        let now_i64 = i64::try_from(now_us).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare_cached(
            "INSERT INTO did_handles (did, handle, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(did) DO UPDATE SET handle = excluded.handle, updated_at = excluded.updated_at;",
        )?;
        stmt.execute(params![clean_did, clean_handle, now_i64])?;
        Ok(())
    }

    /// Removes the cached DID-to-handle mapping for a given handle.
    ///
    /// Used to invalidate a rotated or stale handle so subsequent lookups
    /// re-resolve it from the authoritative source.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite execution fails.
    pub fn remove_handle_for_handle(&self, handle: &str) -> Result<usize, SkybouncerError> {
        let clean = handle.trim().trim_start_matches('@');
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("DELETE FROM did_handles WHERE handle = ?1 COLLATE NOCASE;")?;
        let deleted = stmt.execute(params![clean])?;
        Ok(deleted)
    }

    /// Prunes stale DID-to-handle cache entries and bounds the table size.
    ///
    /// First deletes mappings whose `updated_at` is strictly older than `older_than_us`,
    /// then, if more than `max_retained` rows remain, deletes the oldest mappings until
    /// only the `max_retained` most recently updated entries survive.
    ///
    /// Returns the total number of deleted rows.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite execution fails.
    pub fn prune_did_handles(
        &self,
        older_than_us: u64,
        max_retained: usize,
    ) -> Result<usize, SkybouncerError> {
        let conn = self.conn.lock();
        let cutoff_i64 = i64::try_from(older_than_us).unwrap_or(i64::MAX);
        let mut expire_stmt =
            conn.prepare_cached("DELETE FROM did_handles WHERE updated_at < ?1;")?;
        let mut deleted = expire_stmt.execute(params![cutoff_i64])?;

        let max_i64 = i64::try_from(max_retained.max(1)).unwrap_or(i64::MAX);
        let mut cap_stmt = conn.prepare_cached(
            "DELETE FROM did_handles WHERE did NOT IN (
                SELECT did FROM did_handles ORDER BY updated_at DESC LIMIT ?1
             );",
        )?;
        deleted = deleted.saturating_add(cap_stmt.execute(params![max_i64])?);
        Ok(deleted)
    }
}

/// Computes clock-warp safe microsecond timestamp since Unix epoch.
#[must_use]
pub fn current_time_us() -> u64 {
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
            expires_at: None,
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

    #[test]
    fn test_legacy_schema_migration_order() {
        let conn = Connection::open_in_memory().unwrap();
        // Create the legacy table without protected_did or post_text
        conn.execute_batch(
            "
            CREATE TABLE bounced_users (
                subject_did TEXT PRIMARY KEY,
                listitem_uri TEXT NOT NULL,
                listitem_rkey TEXT NOT NULL,
                listitem_cid TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT NOT NULL,
                post_uri TEXT NOT NULL,
                bounced_at INTEGER NOT NULL
            );
            ",
        )
        .unwrap();

        // init_schema must smoothly migrate the legacy table and create the index without erroring
        DeduplicationCache::init_schema(&conn).unwrap();

        // Verify columns and index now exist
        let cache = DeduplicationCache {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
        };
        let bounce = BouncedUser {
            subject_did: "did:plc:migrated_user".to_string(),
            protected_did: "did:plc:legacy_owner".to_string(),
            listitem_uri: "at://did:plc:legacy_owner/app.bsky.graph.listitem/item1".to_string(),
            listitem_rkey: "item1".to_string(),
            listitem_cid: "bafyitemcid".to_string(),
            category: "spam".to_string(),
            confidence: 0.95,
            reason: "Legacy migration test".to_string(),
            post_uri: "at://did:plc:migrated_user/app.bsky.feed.post/1".to_string(),
            post_text: "Migrated text".to_string(),
            bounced_at: 1_700_000_000,
            expires_at: None,
        };
        cache.record_bounce(&bounce).unwrap();
        let fetched = cache
            .get_bounced_user("did:plc:migrated_user")
            .unwrap()
            .unwrap();
        assert_eq!(fetched.protected_did, "did:plc:legacy_owner");
        assert_eq!(fetched.post_text, "Migrated text");
    }

    #[test]
    fn test_evaluation_log_persistence_and_pruning() {
        let cache = DeduplicationCache::open_in_memory().unwrap();

        // 1. Record several evaluation log entries
        let entry1 = NewEvaluationLog {
            timestamp_us: 1_000_000,
            source: "live".to_string(),
            post_uri: "at://did:plc:author1/app.bsky.feed.post/1".to_string(),
            post_text: "Hey idiot".to_string(),
            author_did: "did:plc:author1".to_string(),
            author_handle: "author1.bsky.social".to_string(),
            target_did: "did:plc:target1".to_string(),
            target_handle: "target1.bsky.social".to_string(),
            has_images: false,
            primary_model: "gemini-2.5-flash".to_string(),
            primary_action: "violation".to_string(),
            primary_confidence: 0.92,
            primary_category: "harassment".to_string(),
            primary_reason: "Personal insult".to_string(),
            escalated: false,
            escalation_reason: Some("High primary confidence".to_string()),
            fallback_model: None,
            fallback_action: None,
            fallback_confidence: None,
            fallback_category: None,
            fallback_reason: None,
            final_action: "violation".to_string(),
            final_confidence: 0.92,
            outcome: "Bounced".to_string(),
        };

        let entry2 = NewEvaluationLog {
            timestamp_us: 2_000_000,
            source: "live".to_string(),
            post_uri: "at://did:plc:author2/app.bsky.feed.post/2".to_string(),
            post_text: "Look at this image".to_string(),
            author_did: "did:plc:author2".to_string(),
            author_handle: "author2.bsky.social".to_string(),
            target_did: "did:plc:target1".to_string(),
            target_handle: "target1.bsky.social".to_string(),
            has_images: true,
            primary_model: "gemini-2.5-flash".to_string(),
            primary_action: "allow".to_string(),
            primary_confidence: 0.45,
            primary_category: String::new(),
            primary_reason: "Text benign, requires vision inspection".to_string(),
            escalated: true,
            escalation_reason: Some("Attached visual image".to_string()),
            fallback_model: Some("gemini-2.5-pro".to_string()),
            fallback_action: Some("violation".to_string()),
            fallback_confidence: Some(0.88),
            fallback_category: Some("hate_speech".to_string()),
            fallback_reason: Some("Offensive imagery detected".to_string()),
            final_action: "violation".to_string(),
            final_confidence: 0.88,
            outcome: "Bounced".to_string(),
        };

        let entry3 = NewEvaluationLog {
            timestamp_us: 3_000_000,
            source: "simulation".to_string(),
            post_uri: "at://did:plc:sim/app.bsky.feed.post/sim".to_string(),
            post_text: "Synthetic test".to_string(),
            author_did: "did:plc:sim".to_string(),
            author_handle: "sim.bsky.social".to_string(),
            target_did: "did:plc:target2".to_string(),
            target_handle: "target2.bsky.social".to_string(),
            has_images: false,
            primary_model: "gemini-2.5-flash".to_string(),
            primary_action: "allow".to_string(),
            primary_confidence: 0.99,
            primary_category: String::new(),
            primary_reason: "Benign question".to_string(),
            escalated: false,
            escalation_reason: None,
            fallback_model: None,
            fallback_action: None,
            fallback_confidence: None,
            fallback_category: None,
            fallback_reason: None,
            final_action: "allow".to_string(),
            final_confidence: 0.99,
            outcome: "Permitted".to_string(),
        };

        let id1 = cache.record_evaluation_log(&entry1).unwrap();
        let id2 = cache.record_evaluation_log(&entry2).unwrap();
        let id3 = cache.record_evaluation_log(&entry3).unwrap();
        assert!(id1 > 0 && id2 > id1 && id3 > id2);

        // 2. Count verification
        assert_eq!(cache.count_evaluation_logs(None, None).unwrap(), 3);
        assert_eq!(
            cache
                .count_evaluation_logs(Some("did:plc:target1"), None)
                .unwrap(),
            2
        );
        assert_eq!(
            cache
                .count_evaluation_logs(None, Some("simulation"))
                .unwrap(),
            1
        );
        assert_eq!(cache.count_evaluation_logs(None, Some("live")).unwrap(), 2);

        // 3. List verification (ordered descending by timestamp)
        let all_logs = cache.list_evaluation_logs(None, None, 10, 0).unwrap();
        assert_eq!(all_logs.len(), 3);
        assert_eq!(all_logs[0].id, id3); // timestamp 3_000_000
        assert_eq!(all_logs[1].id, id2); // timestamp 2_000_000
        assert_eq!(all_logs[2].id, id1); // timestamp 1_000_000

        // Detailed field checks on escalated entry
        assert!(all_logs[1].escalated);
        assert_eq!(
            all_logs[1].fallback_model.as_deref(),
            Some("gemini-2.5-pro")
        );
        assert_eq!(
            all_logs[1].fallback_category.as_deref(),
            Some("hate_speech")
        );
        assert!(all_logs[1].has_images);

        // Filter by target
        let target1_logs = cache
            .list_evaluation_logs(Some("did:plc:target1"), None, 10, 0)
            .unwrap();
        assert_eq!(target1_logs.len(), 2);
        assert_eq!(target1_logs[0].author_did, "did:plc:author2");

        // 4. Pruning verification
        // Pruning retaining max 2 removes the oldest record (id1)
        let deleted = cache.prune_evaluation_logs(2).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(cache.count_evaluation_logs(None, None).unwrap(), 2);
        let remaining = cache.list_evaluation_logs(None, None, 10, 0).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].id, id3);
        assert_eq!(remaining[1].id, id2);
    }

    #[test]
    fn test_multitenant_bounce_isolation() {
        let cache = DeduplicationCache::open_in_memory().unwrap();

        let bounce_a = BouncedUser {
            subject_did: "did:plc:spammer".to_string(),
            protected_did: "did:plc:tenant_a".to_string(),
            listitem_uri: "at://did:plc:tenant_a/app.bsky.graph.listitem/item_a".to_string(),
            listitem_rkey: "item_a".to_string(),
            listitem_cid: "bafyitema".to_string(),
            category: "spam".to_string(),
            confidence: 0.99,
            reason: "Spam for A".to_string(),
            post_uri: "at://did:plc:spammer/app.bsky.feed.post/1".to_string(),
            post_text: "Spam text".to_string(),
            bounced_at: 1_700_000_000,
            expires_at: None,
        };

        let bounce_b = BouncedUser {
            subject_did: "did:plc:spammer".to_string(),
            protected_did: "did:plc:tenant_b".to_string(),
            listitem_uri: "at://did:plc:tenant_b/app.bsky.graph.listitem/item_b".to_string(),
            listitem_rkey: "item_b".to_string(),
            listitem_cid: "bafyitemb".to_string(),
            category: "harassment".to_string(),
            confidence: 0.95,
            reason: "Harassment for B".to_string(),
            post_uri: "at://did:plc:spammer/app.bsky.feed.post/2".to_string(),
            post_text: "Harassment text".to_string(),
            bounced_at: 1_700_000_100,
            expires_at: None,
        };

        // Record bounces for both tenants
        cache.record_bounce(&bounce_a).unwrap();
        cache.record_bounce(&bounce_b).unwrap();

        // Both are bounced in their respective tenant contexts
        assert!(cache
            .is_bounced_for("did:plc:tenant_a", "did:plc:spammer")
            .unwrap());
        assert!(cache
            .is_bounced_for("did:plc:tenant_b", "did:plc:spammer")
            .unwrap());
        assert!(!cache
            .is_bounced_for("did:plc:tenant_c", "did:plc:spammer")
            .unwrap());

        // Recent bounces list isolates records
        let list_a = cache
            .list_recent_bounces_for(Some("did:plc:tenant_a"), 10)
            .unwrap();
        assert_eq!(list_a.len(), 1);
        assert_eq!(list_a[0].listitem_rkey, "item_a");

        let list_b = cache
            .list_recent_bounces_for(Some("did:plc:tenant_b"), 10)
            .unwrap();
        assert_eq!(list_b.len(), 1);
        assert_eq!(list_b[0].listitem_rkey, "item_b");

        let list_c = cache
            .list_recent_bounces_for(Some("did:plc:tenant_c"), 10)
            .unwrap();
        assert_eq!(list_c.len(), 0);

        // Tenant A pardons spammer
        let removed = cache
            .remove_bounce_for("did:plc:tenant_a", "did:plc:spammer")
            .unwrap();
        assert_eq!(removed.as_deref(), Some("item_a"));

        // Tenant A no longer has spammer bounced, but Tenant B STILL DOES!
        assert!(!cache
            .is_bounced_for("did:plc:tenant_a", "did:plc:spammer")
            .unwrap());
        assert!(cache
            .is_bounced_for("did:plc:tenant_b", "did:plc:spammer")
            .unwrap());

        let list_b_after = cache
            .list_recent_bounces_for(Some("did:plc:tenant_b"), 10)
            .unwrap();
        assert_eq!(list_b_after.len(), 1);
        assert_eq!(list_b_after[0].listitem_rkey, "item_b");
    }

    #[test]
    fn test_allowlist_crud_and_loading() {
        let cache = DeduplicationCache::open_in_memory().unwrap();

        assert!(!cache
            .is_allowlisted("did:plc:alice", "did:plc:friend")
            .unwrap());

        cache
            .add_to_allowlist("did:plc:alice", "did:plc:friend", Some("Friend of mine"))
            .unwrap();
        cache
            .add_to_allowlist("did:plc:alice", "did:plc:colleague", None)
            .unwrap();
        cache
            .add_to_allowlist("did:plc:bob", "did:plc:partner", Some("Work partner"))
            .unwrap();

        assert!(cache
            .is_allowlisted("did:plc:alice", "did:plc:friend")
            .unwrap());
        assert!(cache
            .is_allowlisted("did:plc:alice", "did:plc:colleague")
            .unwrap());
        assert!(!cache
            .is_allowlisted("did:plc:alice", "did:plc:partner")
            .unwrap());
        assert!(cache
            .is_allowlisted("did:plc:bob", "did:plc:partner")
            .unwrap());

        let alice_list = cache.list_allowlist("did:plc:alice").unwrap();
        assert_eq!(alice_list.len(), 2);
        assert!(alice_list
            .iter()
            .any(|e| e.subject_did == "did:plc:friend"
                && e.reason.as_deref() == Some("Friend of mine")));

        let all_map = cache.load_all_allowlists().unwrap();
        assert_eq!(all_map.get("did:plc:alice").unwrap().len(), 2);
        assert_eq!(all_map.get("did:plc:bob").unwrap().len(), 1);

        let removed = cache
            .remove_from_allowlist("did:plc:alice", "did:plc:friend")
            .unwrap();
        assert!(removed);
        assert!(!cache
            .is_allowlisted("did:plc:alice", "did:plc:friend")
            .unwrap());

        let removed_again = cache
            .remove_from_allowlist("did:plc:alice", "did:plc:friend")
            .unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn test_did_handle_cache_roundtrip_and_normalization() {
        let cache = DeduplicationCache::open_in_memory().unwrap();

        let did = "did:plc:7nf3vqbvea5gpbet3kmibxpm";
        let handle = "valoisdubins.bsky.social";

        // Unresolved lookups return None
        assert_eq!(cache.get_handle_for_did(did).unwrap(), None);
        assert_eq!(cache.get_did_for_handle(handle).unwrap(), None);

        // Store with surrounding whitespace and leading '@' to verify normalization
        cache
            .set_handle_for_did(&format!("  {did}  "), &format!("@{handle}"))
            .unwrap();

        assert_eq!(
            cache.get_handle_for_did(did).unwrap().as_deref(),
            Some(handle)
        );
        // get_did_for_handle trims '@' and is case-insensitive
        assert_eq!(
            cache.get_did_for_handle(handle).unwrap().as_deref(),
            Some(did)
        );
        assert_eq!(
            cache
                .get_did_for_handle(&format!("  @{}  ", handle.to_uppercase()))
                .unwrap()
                .as_deref(),
            Some(did)
        );

        // Upsert updates the existing mapping in place
        let updated = "newhandle.bsky.social";
        cache.set_handle_for_did(did, updated).unwrap();
        assert_eq!(
            cache.get_handle_for_did(did).unwrap().as_deref(),
            Some(updated)
        );
        assert_eq!(cache.get_did_for_handle(handle).unwrap(), None);
        assert_eq!(
            cache.get_did_for_handle(updated).unwrap().as_deref(),
            Some(did)
        );

        // Empty inputs are a no-op and never persisted
        cache.set_handle_for_did("   ", "some.handle").unwrap();
        cache.set_handle_for_did(did, "   ").unwrap();
        assert_eq!(cache.get_handle_for_did("").unwrap(), None);
    }

    #[test]
    fn test_get_did_for_handle_with_ttl() {
        let cache = DeduplicationCache::open_in_memory().unwrap();
        let did = "did:plc:ttluser";
        let handle = "ttluser.bsky.social";

        // Missing mapping returns None.
        assert_eq!(
            cache.get_did_for_handle_with_ttl(handle, u64::MAX).unwrap(),
            None
        );

        cache.set_handle_for_did(did, handle).unwrap();

        // A generous TTL returns the freshly written mapping.
        assert_eq!(
            cache
                .get_did_for_handle_with_ttl(handle, u64::MAX)
                .unwrap()
                .as_deref(),
            Some(did)
        );

        // A zero TTL treats the mapping as stale (cutoff == now), excluding it.
        assert_eq!(cache.get_did_for_handle_with_ttl(handle, 0).unwrap(), None);

        // The non-TTL lookup still sees the mapping regardless of age.
        assert_eq!(
            cache.get_did_for_handle(handle).unwrap().as_deref(),
            Some(did)
        );

        // remove_handle_for_handle clears it from all lookups.
        let removed = cache.remove_handle_for_handle(handle).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            cache.get_did_for_handle_with_ttl(handle, u64::MAX).unwrap(),
            None
        );
    }

    #[test]
    fn test_prune_did_handles_by_age_and_capacity() {
        let cache = DeduplicationCache::open_in_memory().unwrap();

        // All inserted with "now"; a zero cutoff ages out nothing, so only the
        // capacity bound should apply.
        for i in 0..10 {
            cache
                .set_handle_for_did(&format!("did:plc:user{i}"), &format!("user{i}.bsky.social"))
                .unwrap();
        }

        // Capacity bound retains the 3 most recently updated entries.
        let deleted = cache.prune_did_handles(0, 3).unwrap();
        assert_eq!(deleted, 7);
        let remaining = (0..10)
            .filter(|i| {
                cache
                    .get_handle_for_did(&format!("did:plc:user{i}"))
                    .unwrap()
                    .is_some()
            })
            .count();
        assert_eq!(remaining, 3);

        // A cutoff in the future expires all remaining rows regardless of capacity.
        let all_deleted = cache.prune_did_handles(u64::MAX, 1000).unwrap();
        assert_eq!(all_deleted, 3);

        // Zero cutoff with max_retained=0 still keeps at least one row (max(1)).
        cache
            .set_handle_for_did("did:plc:only", "only.bsky.social")
            .unwrap();
        assert_eq!(cache.prune_did_handles(0, 0).unwrap(), 0);
        assert!(cache.get_handle_for_did("did:plc:only").unwrap().is_some());
    }

    #[test]
    fn test_allowlist_handle_enrichment_via_join() {
        let cache = DeduplicationCache::open_in_memory().unwrap();

        let protected = "did:plc:alice";
        let friend_did = "did:plc:friend";
        let stranger_did = "did:plc:stranger";

        cache
            .add_to_allowlist(protected, friend_did, Some("Friend of mine"))
            .unwrap();
        cache
            .add_to_allowlist(protected, stranger_did, None)
            .unwrap();

        // Only the friend has a cached handle; the stranger resolves to None.
        cache
            .set_handle_for_did(friend_did, "friend.bsky.social")
            .unwrap();

        let entries = cache.list_allowlist(protected).unwrap();
        assert_eq!(entries.len(), 2);

        let friend = entries
            .iter()
            .find(|e| e.subject_did == friend_did)
            .expect("friend entry present");
        assert_eq!(friend.handle.as_deref(), Some("friend.bsky.social"));

        let stranger = entries
            .iter()
            .find(|e| e.subject_did == stranger_did)
            .expect("stranger entry present");
        assert_eq!(stranger.handle, None);
    }
}
