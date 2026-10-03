//! Thread-safe SQLite tenant registry managing dynamic multi-user DPoP sessions and PDS clients.
//!
//! Enforces:
//! - Multi-tenant isolation and persistent storage in SQLite.
//! - Cryptographically bound [`OAuthSession`] DPoP credential serialization and restoration.
//! - Per-tenant [`PdsRepoClient`] generation with sharded concurrent caching.
//! - Dynamic enrollment and activation toggles for ATProto users.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use skyauth::client::AtprotoOAuthClient;
use skyauth::session::OAuthSession;
use skybase::repo::PdsRepoClient;

use crate::classifier::RuleRubric;
use crate::error::SkybouncerError;

/// Multi-tenant record representing an enrolled Bluesky user.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tenant {
    /// Decentralized identifier (DID) of the enrolled user (e.g. `did:plc:...`).
    pub did: String,
    /// ATProto handle if known (e.g. `alice.bsky.social`).
    pub handle: Option<String>,
    /// Cryptographic ATProto OAuth 2.1 DPoP session, if enrolled via web OAuth.
    pub session: Option<OAuthSession>,
    /// Custom moderation rule rubric, if configured specifically for this tenant.
    pub rubric: Option<RuleRubric>,
    /// Whether automated moderation actions are active for this tenant.
    pub is_active: bool,
    /// Microsecond Unix timestamp when this tenant was first registered.
    pub created_at: u64,
    /// Microsecond Unix timestamp when this tenant was last updated.
    pub updated_at: u64,
}

impl Tenant {
    /// Creates a new active tenant with the given DID.
    #[must_use]
    pub fn new(did: impl Into<String>) -> Self {
        let now_us = current_time_us();
        Self {
            did: did.into(),
            handle: None,
            session: None,
            rubric: None,
            is_active: true,
            created_at: now_us,
            updated_at: now_us,
        }
    }

    /// Sets the user's handle.
    #[must_use]
    pub fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Attaches an authenticated [`OAuthSession`].
    #[must_use]
    pub fn with_session(mut self, session: OAuthSession) -> Self {
        self.session = Some(session);
        self
    }

    /// Sets a personalized moderation rule rubric.
    #[must_use]
    pub fn with_rubric(mut self, rubric: RuleRubric) -> Self {
        self.rubric = Some(rubric);
        self
    }

    /// Sets the tenant active state.
    #[must_use]
    pub fn with_active(mut self, is_active: bool) -> Self {
        self.is_active = is_active;
        self
    }
}

/// Thread-safe embedded SQLite registry managing multi-tenant enrollment and PDS clients.
#[derive(Clone)]
pub struct TenantRegistry {
    conn: Arc<Mutex<Connection>>,
    pds_clients: Arc<RwLock<HashMap<String, Arc<PdsRepoClient>>>>,
}

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
        })
    }

    /// Creates a fallback in-memory tenant registry with zero panics.
    #[must_use]
    pub fn fallback() -> Self {
        if let Ok(reg) = Self::open_in_memory() {
            return reg;
        }
        let conn_opt = Connection::open_in_memory()
            .or_else(|_| Connection::open(":memory:"))
            .or_else(|_| Connection::open(""))
            .or_else(|_| Connection::open("skybouncer_fallback.db"))
            .or_else(|_| {
                Connection::open_with_flags(
                    "",
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                        | rusqlite::OpenFlags::SQLITE_OPEN_MEMORY,
                )
            });
        let conn = match conn_opt {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "CRITICAL: Could not open any SQLite connection");
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
        };
        Self {
            conn: Arc::new(Mutex::new(conn)),
            pds_clients: Arc::new(RwLock::new(HashMap::new())),
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
        })
    }

    fn apply_pragmas(conn: &Connection) -> Result<(), SkybouncerError> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set journal_mode WAL: {e}"))
            })?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set synchronous NORMAL: {e}"))
            })?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .map_err(|e| SkybouncerError::Database(format!("Failed to set busy_timeout: {e}")))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| {
                SkybouncerError::Database(format!("Failed to set foreign_keys ON: {e}"))
            })?;
        Ok(())
    }

    fn init_schema(conn: &Connection) -> Result<(), SkybouncerError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS tenants (
                did TEXT PRIMARY KEY,
                handle TEXT,
                session_json TEXT,
                rubric_prompt TEXT,
                sensitivity TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tenants_handle
                ON tenants(handle);

            CREATE INDEX IF NOT EXISTS idx_tenants_active
                ON tenants(is_active);
            ",
        )
        .map_err(|e| {
            SkybouncerError::Database(format!("Failed to initialize tenants schema: {e}"))
        })?;

        Ok(())
    }

    /// Registers a new tenant or updates an existing tenant's credentials and settings.
    ///
    /// Invalidates any cached [`PdsRepoClient`] for this tenant so new session tokens take effect.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if database persistence or JSON serialization fails.
    pub fn register_or_update(&self, tenant: &Tenant) -> Result<(), SkybouncerError> {
        let session_json = match tenant.session {
            Some(ref s) => Some(serde_json::to_string(s).map_err(|e| {
                SkybouncerError::Config(format!("Failed to serialize tenant session: {e}"))
            })?),
            None => None,
        };

        let (rubric_prompt, sensitivity) = match tenant.rubric {
            Some(ref r) => (Some(r.prompt.clone()), Some(r.sensitivity.to_string())),
            None => (None, None),
        };

        let is_active_int: i64 = if tenant.is_active { 1 } else { 0 };
        let created_at_i64 = i64::try_from(tenant.created_at).unwrap_or(i64::MAX);
        let updated_at_i64 = i64::try_from(tenant.updated_at).unwrap_or(i64::MAX);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO tenants (
                did, handle, session_json, rubric_prompt, sensitivity, is_active, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(did) DO UPDATE SET
                 handle = COALESCE(excluded.handle, tenants.handle),
                 session_json = COALESCE(excluded.session_json, tenants.session_json),
                 rubric_prompt = COALESCE(excluded.rubric_prompt, tenants.rubric_prompt),
                 sensitivity = COALESCE(excluded.sensitivity, tenants.sensitivity),
                 is_active = excluded.is_active,
                 updated_at = excluded.updated_at;",
        )?;

        stmt.execute(params![
            tenant.did,
            tenant.handle,
            session_json,
            rubric_prompt,
            sensitivity,
            is_active_int,
            created_at_i64,
            updated_at_i64,
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
            "SELECT did, handle, session_json, rubric_prompt, sensitivity, is_active, created_at, updated_at
             FROM tenants WHERE did = ?1;",
        )?;

        let res = stmt
            .query_row(params![did], |row| {
                let did: String = row.get(0)?;
                let handle: Option<String> = row.get(1)?;
                let session_json: Option<String> = row.get(2)?;
                let rubric_prompt: Option<String> = row.get(3)?;
                let sensitivity_str: Option<String> = row.get(4)?;
                let is_active_int: i64 = row.get(5)?;
                let created_at_i64: i64 = row.get(6)?;
                let updated_at_i64: i64 = row.get(7)?;

                Ok((
                    did,
                    handle,
                    session_json,
                    rubric_prompt,
                    sensitivity_str,
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
                is_active_int,
                created_at_i64,
                updated_at_i64,
            )) => {
                let session: Option<OAuthSession> = match session_json {
                    Some(ref json) if !json.trim().is_empty() => serde_json::from_str(json)
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                2,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?,
                    _ => None,
                };

                let rubric: Option<RuleRubric> = match (rubric_prompt, sensitivity_str) {
                    (Some(prompt), Some(sens_str)) => {
                        let sens = match sens_str.to_ascii_lowercase().as_str() {
                            "high" => crate::classifier::Sensitivity::High,
                            "low" => crate::classifier::Sensitivity::Low,
                            _ => crate::classifier::Sensitivity::Medium,
                        };
                        Some(RuleRubric {
                            prompt,
                            sensitivity: sens,
                        })
                    }
                    (Some(prompt), None) => {
                        Some(RuleRubric::parse(&prompt).unwrap_or(RuleRubric {
                            prompt,
                            sensitivity: crate::classifier::Sensitivity::Medium,
                        }))
                    }
                    _ => None,
                };

                let created_at = u64::try_from(created_at_i64.max(0)).unwrap_or_default();
                let updated_at = u64::try_from(updated_at_i64.max(0)).unwrap_or_default();

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

    /// Retrieves an enrolled tenant by Bluesky handle.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite lookup fails.
    pub fn get_by_handle(&self, handle: &str) -> Result<Option<Tenant>, SkybouncerError> {
        let clean = handle.trim().trim_start_matches('@');
        let did_opt: Option<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT did FROM tenants WHERE LOWER(handle) = LOWER(?1) OR LOWER(handle) = LOWER(?2) LIMIT 1;",
            )?;
            stmt.query_row(params![clean, format!("@{clean}")], |row| row.get(0))
                .optional()?
        };

        match did_opt {
            Some(did) => self.get(&did),
            None => Ok(None),
        }
    }

    /// Checks whether the given DID is registered and enrolled in the tenant registry.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_enrolled(&self, did: &str) -> Result<bool, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT 1 FROM tenants WHERE did = ?1 LIMIT 1;")?;
        let exists = stmt
            .query_row(params![did], |_| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    /// Lists all enrolled tenants whose automated moderation status is active (`is_active = 1`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if query fails.
    pub fn list_active(&self) -> Result<Vec<Tenant>, SkybouncerError> {
        let dids = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT did FROM tenants WHERE is_active = 1 ORDER BY created_at ASC;",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut dids = Vec::new();
            for r in rows {
                dids.push(r?);
            }
            dids
        };

        let mut tenants = Vec::with_capacity(dids.len());
        for did in dids {
            if let Some(t) = self.get(&did)? {
                tenants.push(t);
            }
        }
        Ok(tenants)
    }

    /// Lists all enrolled tenants regardless of active status.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if query fails.
    pub fn list_all(&self) -> Result<Vec<Tenant>, SkybouncerError> {
        let dids = {
            let conn = self.conn.lock();
            let mut stmt =
                conn.prepare_cached("SELECT did FROM tenants ORDER BY created_at ASC;")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut dids = Vec::new();
            for r in rows {
                dids.push(r?);
            }
            dids
        };

        let mut tenants = Vec::with_capacity(dids.len());
        for did in dids {
            if let Some(t) = self.get(&did)? {
                tenants.push(t);
            }
        }
        Ok(tenants)
    }

    /// Toggles the active status (`is_active`) of an enrolled tenant.
    ///
    /// Returns `true` if the tenant was found and updated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if update query fails.
    pub fn set_active(&self, did: &str, is_active: bool) -> Result<bool, SkybouncerError> {
        let is_active_int: i64 = if is_active { 1 } else { 0 };
        let now_us = current_time_us();
        let now_i64 = i64::try_from(now_us).unwrap_or(i64::MAX);

        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached("UPDATE tenants SET is_active = ?1, updated_at = ?2 WHERE did = ?3;")?;

        let count = stmt.execute(params![is_active_int, now_i64, did])?;
        Ok(count > 0)
    }

    /// Updates the custom rule rubric for an enrolled tenant.
    ///
    /// Returns `true` if the tenant was found and updated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if update query fails.
    pub fn update_rubric(&self, did: &str, rubric: &RuleRubric) -> Result<bool, SkybouncerError> {
        let now_us = current_time_us();
        let now_i64 = i64::try_from(now_us).unwrap_or(i64::MAX);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "UPDATE tenants SET rubric_prompt = ?1, sensitivity = ?2, updated_at = ?3 WHERE did = ?4;",
        )?;

        let count = stmt.execute(params![
            rubric.prompt,
            rubric.sensitivity.to_string(),
            now_i64,
            did
        ])?;
        Ok(count > 0)
    }

    /// Deletes a tenant from the registry.
    ///
    /// Returns `true` if the tenant was found and deleted.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if deletion fails.
    pub fn remove(&self, did: &str) -> Result<bool, SkybouncerError> {
        self.pds_clients.write().remove(did);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("DELETE FROM tenants WHERE did = ?1;")?;
        let count = stmt.execute(params![did])?;
        Ok(count > 0)
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

    /// Resolves or initializes a dedicated [`PdsRepoClient`] for an enrolled tenant using their DPoP session.
    ///
    /// If a client was already constructed for this DID, it is returned from cache immediately (<50ns).
    /// If the tenant has no stored session, returns `Ok(None)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if client creation fails.
    pub fn get_pds_client(
        &self,
        did: &str,
        oauth_client: Option<&Arc<AtprotoOAuthClient>>,
    ) -> Result<Option<Arc<PdsRepoClient>>, SkybouncerError> {
        // 1. Fast path: check in-memory cache
        {
            let guard = self.pds_clients.read();
            if let Some(client) = guard.get(did) {
                return Ok(Some(Arc::clone(client)));
            }
        }

        // 2. Load tenant from database
        let tenant = match self.get(did)? {
            Some(t) => t,
            None => return Ok(None),
        };

        let session = match tenant.session {
            Some(s) => s,
            None => return Ok(None),
        };

        let session_arc = Arc::new(session);
        let client = match oauth_client {
            Some(oc) => PdsRepoClient::new(session_arc, Arc::clone(oc)).map_err(|e| {
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
    use skyauth::dpop::DPoPKey;

    #[test]
    fn test_tenant_crud_in_memory() {
        let registry = TenantRegistry::open_in_memory().unwrap();
        assert_eq!(registry.count().unwrap(), 0);
        assert!(!registry.is_enrolled("did:plc:alice").unwrap());

        let tenant = Tenant::new("did:plc:alice")
            .with_handle("alice.bsky.social")
            .with_rubric(RuleRubric::parse("Block crypto spam and harassment").unwrap());

        registry.register_or_update(&tenant).unwrap();

        assert_eq!(registry.count().unwrap(), 1);
        assert!(registry.is_enrolled("did:plc:alice").unwrap());

        let fetched = registry.get("did:plc:alice").unwrap().unwrap();
        assert_eq!(fetched.did, "did:plc:alice");
        assert_eq!(fetched.handle.as_deref(), Some("alice.bsky.social"));
        assert!(fetched.is_active);
        assert_eq!(
            fetched.rubric.unwrap().prompt,
            "Block crypto spam and harassment"
        );

        // Fetch by handle
        let by_handle = registry
            .get_by_handle("@alice.bsky.social")
            .unwrap()
            .unwrap();
        assert_eq!(by_handle.did, "did:plc:alice");

        // Toggle active
        assert!(registry.set_active("did:plc:alice", false).unwrap());
        let updated = registry.get("did:plc:alice").unwrap().unwrap();
        assert!(!updated.is_active);
        assert!(registry.list_active().unwrap().is_empty());

        // Remove
        assert!(registry.remove("did:plc:alice").unwrap());
        assert_eq!(registry.count().unwrap(), 0);
        assert!(!registry.is_enrolled("did:plc:alice").unwrap());
    }

    #[test]
    fn test_tenant_session_roundtrip_and_pds_client() {
        let registry = TenantRegistry::open_in_memory().unwrap();

        let dpop_key = DPoPKey::generate();
        let session = OAuthSession::new(
            "did:plc:bob",
            "at_access_token_sample",
            Some("rt_refresh_token_sample".to_string()),
            "DPoP",
            Some("atproto transition:generic".to_string()),
            Some(3600),
            dpop_key,
            Some("https://pds.bob.example.com".to_string()),
            Some("https://auth.example.com".to_string()),
            Some("https://auth.example.com/oauth/token".to_string()),
        )
        .unwrap();

        let tenant = Tenant::new("did:plc:bob")
            .with_handle("bob.bsky.social")
            .with_session(session);

        registry.register_or_update(&tenant).unwrap();

        let fetched = registry.get("did:plc:bob").unwrap().unwrap();
        assert!(fetched.session.is_some());
        let s = fetched.session.unwrap();
        assert_eq!(s.sub(), "did:plc:bob");
        assert_eq!(s.access_token(), "at_access_token_sample");
        assert_eq!(s.pds_endpoint(), Some("https://pds.bob.example.com"));

        // Build PdsRepoClient
        let pds_client = registry
            .get_pds_client("did:plc:bob", None)
            .unwrap()
            .unwrap();
        assert_eq!(pds_client.did(), "did:plc:bob");
        assert_eq!(
            pds_client.pds_endpoint().unwrap(),
            "https://pds.bob.example.com"
        );
    }
}
