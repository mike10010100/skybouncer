//! Thread-safe SQLite tenant registry managing dynamic multi-user DPoP sessions and PDS clients.
//!
//! Enforces:
//! - Multi-tenant isolation and persistent storage in SQLite.
//! - Cryptographically bound [`OAuthSession`] DPoP credential serialization and restoration.
//! - Per-tenant [`PdsRepoClient`] generation with sharded concurrent caching.
//! - Dynamic enrollment and activation toggles for ATProto users.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use skyauth::client::AtprotoOAuthClient;
use skyauth::session::OAuthSession;
use skybase::repo::PdsRepoClient;
use zeroize::Zeroizing;

use crate::classifier::RuleRubric;
use crate::crypto::SessionCipher;
use crate::error::SkybouncerError;
use crate::time::{current_time_us, i64_to_us, us_to_i64};

/// Prefix applied to SHA-256 hashed web session tokens stored in SQLite.
pub const WEB_SESSION_HASH_PREFIX: &str = "sha256:";

/// Outcome of a Compare-And-Swap (`WHERE did = ? AND session_json = ?`) OAuth session update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasUpdateOutcome {
    /// The stored ciphertext matched `expected_raw_session_json` and was atomically replaced.
    Updated,
    /// The row still exists, but its ciphertext was concurrently modified by another operation.
    Conflict,
    /// No tenant row exists for the given DID.
    NotFound,
}

/// Default time-to-live for handle resolution caching (1 hour).
pub const DEFAULT_HANDLE_TTL: Duration = Duration::from_secs(3600);

/// Default interval between proactive OAuth re-authentication reminder DMs (7 days).
pub const DEFAULT_REAUTH_REMINDER_INTERVAL: Duration = Duration::from_secs(7 * 24 * 3600);

/// Maximum number of re-authentication DMs sent per expiration cycle (1 initial alert + 2 weekly reminders).
pub const MAX_REAUTH_NOTIFICATIONS: u32 = 3;

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
    /// In-memory cache of authenticated [`PdsRepoClient`] instances indexed by tenant DID.
    pub pds_clients: Arc<RwLock<HashMap<String, Arc<PdsRepoClient>>>>,
    client_epochs: Arc<RwLock<HashMap<String, u64>>>,
    oauth_client: Arc<RwLock<Option<Arc<AtprotoOAuthClient>>>>,
    cipher: SessionCipher,
    refresh_locks: Arc<crate::modlist::manager::StripedAsyncLocks>,
}

mod admin;
mod core;
mod handles;
mod sessions;

/// Hashes a web session token using SHA-256 for secure database storage at rest.
fn hash_session_token(token: &str) -> String {
    let digest = skyauth::crypto::sha256_digest(token.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use skyauth::dpop::DPoPKey;

    /// Opens a fresh in-memory tenant registry for tests.
    pub(super) fn test_registry() -> TenantRegistry {
        TenantRegistry::open_in_memory().expect("open in-memory registry")
    }

    #[test]
    fn test_registry_open_persistent_path_creates_file() {
        let dir = std::env::temp_dir().join(format!(
            "skybouncer_reg_test_{}",
            crate::time::current_time_us()
        ));
        let db = dir.join("nested").join("tenants.db");
        let registry = TenantRegistry::open(&db).expect("open persistent registry");
        assert_eq!(registry.count().unwrap(), 0);
        assert!(db.exists(), "database file must be created");
        drop(registry);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_registry_from_connection_reuses_schema() {
        let conn = std::sync::Arc::new(parking_lot::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        ));
        let a = TenantRegistry::from_connection(std::sync::Arc::clone(&conn)).unwrap();
        a.register_or_update(&Tenant::new("did:plc:shared"))
            .unwrap();

        // A second registry over the same connection sees the persisted row.
        let b = TenantRegistry::from_connection(std::sync::Arc::clone(&conn)).unwrap();
        assert_eq!(b.count().unwrap(), 1);
        assert!(b.is_enrolled("did:plc:shared").unwrap());
    }

    #[test]
    fn test_init_schema_upgrades_unmodified_legacy_default_and_presets_preserving_custom() {
        let conn = std::sync::Arc::new(parking_lot::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        ));
        let a = TenantRegistry::from_connection(std::sync::Arc::clone(&conn)).unwrap();
        for (idx, &(legacy, _)) in crate::classifier::rubric::LEGACY_PROMPT_UPGRADES
            .iter()
            .enumerate()
        {
            a.register_or_update(
                &Tenant::new(format!("did:plc:legacy{idx}"))
                    .with_rubric(RuleRubric::with_default_sensitivity(legacy)),
            )
            .unwrap();
        }
        a.register_or_update(
            &Tenant::new("did:plc:custom")
                .with_rubric(RuleRubric::with_default_sensitivity("Block all spoilers.")),
        )
        .unwrap();

        let b = TenantRegistry::from_connection(std::sync::Arc::clone(&conn)).unwrap();
        for (idx, &(_, expected)) in crate::classifier::rubric::LEGACY_PROMPT_UPGRADES
            .iter()
            .enumerate()
        {
            let tenant = b
                .get(&format!("did:plc:legacy{idx}"))
                .unwrap()
                .expect("legacy tenant present");
            assert_eq!(tenant.rubric.unwrap().prompt, expected);
        }
        let custom_tenant = b.get("did:plc:custom").unwrap().unwrap();
        assert_eq!(custom_tenant.rubric.unwrap().prompt, "Block all spoilers.");
    }

    #[test]
    fn test_registry_fallback_constructs_usable_registry() {
        let registry = TenantRegistry::fallback().unwrap();
        assert_eq!(registry.count().unwrap(), 0);
        registry
            .register_or_update(&Tenant::new("did:plc:fb"))
            .unwrap();
        assert!(registry.is_enrolled("did:plc:fb").unwrap());
    }

    #[test]
    fn test_registry_with_cipher_and_accessor() {
        let cipher = crate::crypto::SessionCipher::from_secret_passphrase("unit-test-key");
        let registry = test_registry().with_cipher(cipher);
        // Accessor returns the configured cipher (no panic / borrow issue).
        let _ = registry.cipher();
        assert_eq!(registry.count().unwrap(), 0);
    }

    #[test]
    fn test_registry_open_creates_parent_dir_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("nested").join("tenants.sqlite");
        let reg = TenantRegistry::open(&db_path).unwrap();
        reg.register_or_update(&Tenant::new("did:plc:file1"))
            .unwrap();
        assert_eq!(reg.count().unwrap(), 1);
    }

    #[test]
    pub(super) fn test_tenant_crud_in_memory() {
        let registry = test_registry();
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
    pub(super) fn test_tenant_bypass_followers_persistence() {
        let registry = test_registry();

        // Opt-out is persisted and reloaded.
        let tenant = Tenant::new("did:plc:carol").with_rubric(
            RuleRubric::parse("Block spam")
                .unwrap()
                .with_bypass_incoming_followers(false),
        );
        registry.register_or_update(&tenant).unwrap();
        let fetched = registry.get("did:plc:carol").unwrap().unwrap();
        assert!(!fetched.rubric.unwrap().bypass_incoming_followers);

        // update_rubric overwrites the flag.
        let updated = RuleRubric::parse("Block spam")
            .unwrap()
            .with_bypass_incoming_followers(true);
        assert!(registry.update_rubric("did:plc:carol", &updated).unwrap());
        let fetched = registry.get("did:plc:carol").unwrap().unwrap();
        assert!(fetched.rubric.unwrap().bypass_incoming_followers);
    }

    #[tokio::test]
    async fn test_tenant_session_roundtrip_and_pds_client() {
        let registry = test_registry();

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
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pds_client.did(), "did:plc:bob");
        assert_eq!(
            pds_client.pds_endpoint().unwrap(),
            "https://pds.bob.example.com"
        );

        // Test update_session
        let new_dpop_key = DPoPKey::generate();
        let updated_session = OAuthSession::new(
            "did:plc:bob",
            "at_fresh_access_token",
            Some("rt_fresh_refresh_token".to_string()),
            "DPoP",
            Some("atproto transition:generic".to_string()),
            Some(7200),
            new_dpop_key,
            Some("https://pds.bob.example.com".to_string()),
            Some("https://auth.example.com".to_string()),
            Some("https://auth.example.com/oauth/token".to_string()),
        )
        .unwrap();

        assert!(registry
            .update_session("did:plc:bob", &updated_session)
            .unwrap());
        let refetched = registry.get("did:plc:bob").unwrap().unwrap();
        assert_eq!(
            refetched.session.unwrap().access_token(),
            "at_fresh_access_token"
        );
    }

    #[tokio::test]
    async fn test_tenant_session_auto_refresh_on_expired_token() {
        use serde_json::json;
        use skyauth::client::OAuthClientMetadata;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let token_endpoint = format!("{}/oauth/token", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .insert_header("dpop-nonce", "fresh-dpop-nonce-123")
                    .set_body_json(json!({
                        "access_token": "at-auto-refreshed-token",
                        "token_type": "DPoP",
                        "expires_in": 3600,
                        "refresh_token": "rt-auto-refreshed-token",
                        "scope": "atproto",
                        "sub": "did:plc:alice"
                    })),
            )
            .mount(&mock_server)
            .await;

        let oauth_client = Arc::new(
            AtprotoOAuthClient::builder()
                .client_metadata(OAuthClientMetadata::new(
                    "https://skybouncer.example.com/client-metadata.json",
                    "https://skybouncer.example.com/oauth/callback",
                ))
                .allow_insecure_localhost(true)
                .build()
                .unwrap(),
        );

        let registry = test_registry();
        registry.set_oauth_client(Arc::clone(&oauth_client));

        // Create an expired session (expires_in = Some(0))
        let dpop_key = DPoPKey::generate();
        let expired_session = OAuthSession::new(
            "did:plc:alice",
            "at-expired-token",
            Some("rt-initial-refresh-token".to_string()),
            "DPoP",
            Some("atproto".to_string()),
            Some(0),
            dpop_key,
            Some("https://pds.example.com".to_string()),
            Some(mock_server.uri()),
            Some(token_endpoint),
        )
        .unwrap();

        assert!(expired_session.is_expired());

        let tenant = Tenant::new("did:plc:alice")
            .with_handle("alice.bsky.social")
            .with_session(expired_session);
        registry.register_or_update(&tenant).unwrap();

        // Calling get_pds_client should detect the expired session, invoke OAuth refresh, and succeed
        let pds_client = registry
            .get_pds_client("did:plc:alice", None)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            pds_client.session().access_token(),
            "at-auto-refreshed-token"
        );
        assert!(!pds_client.session().is_expired());

        // Verify that the refreshed session was persisted to the SQLite database
        let refetched = registry.get("did:plc:alice").unwrap().unwrap();
        assert_eq!(
            refetched.session.unwrap().access_token(),
            "at-auto-refreshed-token"
        );

        // Subsequent call returns the cached PdsRepoClient immediately
        let cached_client = registry
            .get_pds_client("did:plc:alice", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            cached_client.session().access_token(),
            "at-auto-refreshed-token"
        );
    }

    #[test]
    fn test_get_rubric_field_branch_combinations() {
        use rusqlite::params;
        let registry = test_registry();
        let conn = registry.conn.lock();
        let now: i64 = 1_700_000_000_000_000;

        // rub: prompt + sensitivity (explicit sensitivity path)
        conn.execute(
            "INSERT INTO tenants (did, handle, session_json, rubric_prompt, sensitivity, bounce_duration, bypass_followers, is_active, created_at, updated_at)
             VALUES (?1, NULL, NULL, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
            params!["did:plc:a", "rules A", "high", "7d", 0i64, now],
        )
        .unwrap();
        // rub2: prompt only (RuleRubric::parse fallback path)
        conn.execute(
            "INSERT INTO tenants (did, handle, session_json, rubric_prompt, sensitivity, bounce_duration, bypass_followers, is_active, created_at, updated_at)
             VALUES (?1, NULL, NULL, ?2, NULL, NULL, NULL, 1, ?3, ?3)",
            params!["did:plc:b", "parse me rules", now],
        )
        .unwrap();
        // rub3: neither prompt nor sensitivity (None rubric) + inactive
        conn.execute(
            "INSERT INTO tenants (did, handle, session_json, rubric_prompt, sensitivity, bounce_duration, bypass_followers, is_active, created_at, updated_at)
             VALUES (?1, NULL, NULL, NULL, NULL, NULL, NULL, 0, ?2, ?2)",
            params!["did:plc:c", now],
        )
        .unwrap();
        drop(conn);

        let a = registry.get("did:plc:a").unwrap().unwrap();
        let ra = a.rubric.unwrap();
        assert_eq!(ra.sensitivity, crate::classifier::Sensitivity::High);
        assert_eq!(
            ra.bounce_duration,
            crate::classifier::BounceDuration::Timeout7d
        );
        assert!(!ra.bypass_incoming_followers, "0 => false");

        let b = registry.get("did:plc:b").unwrap().unwrap();
        assert_eq!(b.rubric.unwrap().prompt, "parse me rules");

        let c = registry.get("did:plc:c").unwrap().unwrap();
        assert!(c.rubric.is_none());
        assert!(!c.is_active);

        // Missing DID returns None.
        assert!(registry.get("did:plc:missing").unwrap().is_none());
    }

    #[test]
    fn test_update_session_and_empty_web_session_did() {
        let registry = test_registry();
        let dpop = DPoPKey::generate();
        let session = OAuthSession::new(
            "did:plc:upd",
            "at-token-1",
            Some("rt-1".to_string()),
            "DPoP",
            None,
            None,
            dpop,
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        registry
            .register_or_update(&Tenant::new("did:plc:upd").with_session(session.clone()))
            .unwrap();

        // update_session on an existing tenant returns true and evicts any cached client.
        assert!(registry.update_session("did:plc:upd", &session).unwrap());
        // update_session rejects a mismatched subject DID.
        assert!(registry
            .update_session("did:plc:missing", &session)
            .is_err());
        // update_session on an unknown tenant with matching subject returns false.
        let missing_session = OAuthSession::new(
            "did:plc:missing",
            "at-missing",
            Some("rt-missing".to_string()),
            "DPoP",
            None,
            None,
            DPoPKey::generate(),
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        assert!(!registry
            .update_session("did:plc:missing", &missing_session)
            .unwrap());

        // Empty DID for a web session is a config error.
        assert!(registry
            .create_web_session("   ", Duration::from_secs(60))
            .is_err());
        assert!(registry.oauth_client().is_none());
    }

    #[test]
    pub(super) fn test_web_session_empty_token_and_expired_purge_and_prune() {
        let registry = test_registry();
        // Empty tokens short-circuit.
        assert!(registry.validate_web_session("   ").unwrap().is_none());
        assert!(!registry.delete_web_session("").unwrap());

        // Expired session is purged on validation (returns None) and prune removes leftovers.
        let expired = registry
            .create_web_session("did:plc:exp", Duration::from_micros(1))
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(registry.validate_web_session(&expired).unwrap().is_none());

        let live = registry
            .create_web_session("did:plc:live", Duration::from_secs(600))
            .unwrap();
        assert_eq!(
            registry.validate_web_session(&live).unwrap().as_deref(),
            Some("did:plc:live")
        );
        // prune returns >= 0 and keeps the live session valid.
        let _ = registry.prune_expired_web_sessions().unwrap();
        assert!(registry.validate_web_session(&live).unwrap().is_some());
    }

    #[test]
    pub(super) fn test_web_session_lifecycle() {
        let registry = test_registry();
        let did = "did:plc:alice";

        // 1. Create a session token
        let token = registry
            .create_web_session(did, Duration::from_secs(3600))
            .unwrap();
        assert!(!token.is_empty());

        // 2. Validate token
        let validated = registry.validate_web_session(&token).unwrap();
        assert_eq!(validated, Some(did.to_string()));

        // 3. Unknown token returns None
        assert_eq!(
            registry.validate_web_session("invalid-token").unwrap(),
            None
        );

        // 4. Invalidate / delete token on logout
        let deleted = registry.delete_web_session(&token).unwrap();
        assert!(deleted);

        // 5. Subsequent validation fails
        assert_eq!(registry.validate_web_session(&token).unwrap(), None);

        // 6. Expired token validation
        let expired_token = registry
            .create_web_session(did, Duration::from_micros(1))
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(registry.validate_web_session(&expired_token).unwrap(), None);
    }

    #[test]
    pub(super) fn test_tenant_session_encrypted_at_rest_in_sqlite() {
        use crate::crypto::ENCRYPTION_V1_PREFIX;

        let registry = test_registry();
        let dpop_key = DPoPKey::generate();
        let session = OAuthSession::new(
            "did:plc:encrypted-user",
            "super_secret_access_token_xyz",
            Some("super_secret_refresh_token_abc".to_string()),
            "DPoP",
            Some("atproto".to_string()),
            Some(3600),
            dpop_key,
            Some("https://pds.encrypted.example.com".to_string()),
            Some("https://auth.example.com".to_string()),
            Some("https://auth.example.com/oauth/token".to_string()),
        )
        .unwrap();

        let tenant = Tenant::new("did:plc:encrypted-user").with_session(session);
        registry.register_or_update(&tenant).unwrap();

        // 1. Raw SQLite inspection: Must NOT contain plaintext secrets and must have enc:v1: prefix
        let raw_json: String = {
            let conn = registry.conn.lock();
            conn.query_row(
                "SELECT session_json FROM tenants WHERE did = 'did:plc:encrypted-user';",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };

        assert!(raw_json.starts_with(ENCRYPTION_V1_PREFIX));
        assert!(!raw_json.contains("super_secret_access_token_xyz"));
        assert!(!raw_json.contains("super_secret_refresh_token_abc"));

        // 2. Normal registry retrieval transparently decrypts
        let fetched = registry
            .get("did:plc:encrypted-user")
            .unwrap()
            .expect("tenant should exist");
        let fetched_session = fetched.session.expect("session must be decrypted");
        assert_eq!(
            fetched_session.access_token(),
            "super_secret_access_token_xyz"
        );
        assert_eq!(
            fetched_session.refresh_token(),
            Some("super_secret_refresh_token_abc")
        );
    }

    #[test]
    pub(super) fn test_tenant_session_legacy_unencrypted_passthrough_and_migration() {
        use crate::crypto::ENCRYPTION_V1_PREFIX;

        let registry = test_registry();
        let dpop_key = DPoPKey::generate();
        let session = OAuthSession::new(
            "did:plc:legacy-user",
            "legacy_plain_access_token",
            Some("legacy_plain_refresh_token".to_string()),
            "DPoP",
            Some("atproto".to_string()),
            Some(3600),
            dpop_key,
            Some("https://pds.legacy.example.com".to_string()),
            Some("https://auth.example.com".to_string()),
            Some("https://auth.example.com/oauth/token".to_string()),
        )
        .unwrap();

        let legacy_json = serde_json::to_string(&session).unwrap();

        // Manually inject raw unencrypted JSON into SQLite as if created by an older version
        {
            let conn = registry.conn.lock();
            conn.execute(
                "INSERT INTO tenants (did, handle, session_json, is_active, created_at, updated_at)
                 VALUES ('did:plc:legacy-user', 'legacy.bsky.social', ?1, 1, 1000, 1000);",
                params![legacy_json],
            )
            .unwrap();
        }

        // 1. Runtime get() strictly rejects unmigrated plaintext (no silent downgrade)
        assert!(matches!(
            registry.get("did:plc:legacy-user"),
            Err(SkybouncerError::Auth(_))
        ));

        // 2. Startup migrate_encrypted_secrets transparently re-seals legacy plaintext with tenant AAD
        registry.migrate_encrypted_secrets(None).unwrap();

        let fetched = registry
            .get("did:plc:legacy-user")
            .unwrap()
            .expect("legacy tenant exists");
        let loaded_session = fetched.session.expect("legacy session migrated");
        assert_eq!(loaded_session.access_token(), "legacy_plain_access_token");

        // 3. Raw SQLite inspection now verifies strict encryption at rest
        let raw_json_after_migration: String = {
            let conn = registry.conn.lock();
            conn.query_row(
                "SELECT session_json FROM tenants WHERE did = 'did:plc:legacy-user';",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };

        assert!(raw_json_after_migration.starts_with(ENCRYPTION_V1_PREFIX));
        assert!(!raw_json_after_migration.contains("legacy_plain_access_token"));
    }

    #[test]
    pub(super) fn test_tenant_session_wrong_key_fails_cleanly() {
        let cipher_a = SessionCipher::from_secret_passphrase("correct-encryption-key-123");
        let cipher_b = SessionCipher::from_secret_passphrase("wrong-encryption-key-999");

        let registry_a = TenantRegistry::open_in_memory()
            .unwrap()
            .with_cipher(cipher_a);

        let dpop_key = DPoPKey::generate();
        let session = OAuthSession::new(
            "did:plc:protected-key-test",
            "classified_token_data",
            None,
            "DPoP",
            None,
            None,
            dpop_key,
            None,
            None,
            None,
        )
        .unwrap();

        let tenant = Tenant::new("did:plc:protected-key-test").with_session(session);
        registry_a.register_or_update(&tenant).unwrap();

        // registry_b connects to same SQLite DB but with wrong key
        let registry_b = TenantRegistry::from_connection(Arc::clone(&registry_a.conn))
            .unwrap()
            .with_cipher(cipher_b);

        // Attempting to retrieve tenant fails authentication tag check
        let fetch_result = registry_b.get("did:plc:protected-key-test");
        assert!(fetch_result.is_err());
    }

    #[test]
    pub(super) fn test_tenant_handle_ttl_and_invalidation() {
        let registry = test_registry();
        let tenant = Tenant::new("did:plc:alice").with_handle("alice.bsky.social");
        registry.register_or_update(&tenant).unwrap();

        // Standard retrieval with default TTL
        let fetched = registry.get_by_handle("alice.bsky.social").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().did, "did:plc:alice");

        // Prefix '@' works
        let with_at = registry.get_by_handle("@alice.bsky.social").unwrap();
        assert!(with_at.is_some());

        // Zero TTL treats it as expired
        let expired = registry
            .get_by_handle_with_ttl("alice.bsky.social", Duration::ZERO)
            .unwrap();
        assert!(expired.is_none());

        // Invalidation clears handle
        let invalidated = registry.invalidate_handle("alice.bsky.social").unwrap();
        assert!(invalidated);

        // After invalidation, lookup returns None
        let after = registry.get_by_handle("alice.bsky.social").unwrap();
        assert!(after.is_none());

        // Re-invalidating non-existent handle returns false
        let second_inv = registry.invalidate_handle("alice.bsky.social").unwrap();
        assert!(!second_inv);
    }

    #[test]
    pub(super) fn test_handle_freshness_not_refreshed_by_session_update() {
        let registry = test_registry();

        // Register with a handle, backdating the handle-freshness timestamp so it is
        // already older than a 1-second TTL window.
        let mut tenant = Tenant::new("did:plc:alice").with_handle("alice.bsky.social");
        let old = crate::time::current_time_us().saturating_sub(5_000_000);
        tenant.created_at = old;
        tenant.updated_at = old;
        registry.register_or_update(&tenant).unwrap();

        // Backdate handle_updated_at directly to simulate an old mapping.
        {
            let conn = registry.conn.lock();
            conn.execute(
                "UPDATE tenants SET handle_updated_at = ?1 WHERE did = 'did:plc:alice';",
                rusqlite::params![i64::try_from(old).unwrap()],
            )
            .unwrap();
        }

        // With a 1-second TTL, the 5-second-old mapping is considered stale.
        let stale = registry
            .get_by_handle_with_ttl("alice.bsky.social", Duration::from_secs(1))
            .unwrap();
        assert!(
            stale.is_none(),
            "old handle mapping must be treated as stale"
        );

        // Simulate unrelated activity: update_handle is not called, but other tenant
        // writes (e.g. rubric/session) bump `updated_at`. Use invalidate-free update via
        // register_or_update with an unset handle to ensure handle freshness is preserved.
        let mut unrelated = Tenant::new("did:plc:alice");
        unrelated.updated_at = crate::time::current_time_us();
        registry.register_or_update(&unrelated).unwrap();

        // The handle mapping is still considered stale: session/tenant activity must not
        // resurrect freshness.
        let still_stale = registry
            .get_by_handle_with_ttl("alice.bsky.social", Duration::from_secs(1))
            .unwrap();
        assert!(
            still_stale.is_none(),
            "unrelated tenant updates must not refresh handle freshness"
        );

        // An explicit handle update does refresh freshness.
        assert!(registry
            .update_handle("did:plc:alice", "alice.bsky.social")
            .unwrap());
        let fresh = registry
            .get_by_handle_with_ttl("alice.bsky.social", Duration::from_secs(3600))
            .unwrap();
        assert!(
            fresh.is_some(),
            "explicit handle update must refresh freshness"
        );
    }

    #[tokio::test]
    async fn test_expired_session_without_oauth_client_or_refresh_token_errors() {
        let registry = test_registry();
        let dpop_key = DPoPKey::generate();

        // Expired session without refresh token
        let session_no_rt = OAuthSession::new(
            "did:plc:no-rt",
            "at_expired",
            None,
            "DPoP",
            None,
            Some(0),
            dpop_key,
            None,
            None,
            None,
        )
        .unwrap();

        let tenant = Tenant::new("did:plc:no-rt").with_session(session_no_rt);
        registry.register_or_update(&tenant).unwrap();

        // Calling get_pds_client without OAuth client errors
        let res_no_oc = registry.get_pds_client("did:plc:no-rt", None).await;
        assert!(res_no_oc.is_err());
        assert!(
            matches!(res_no_oc, Err(SkybouncerError::Auth(msg)) if msg.contains("no OAuth client"))
        );
        assert!(registry.pds_clients.read().get("did:plc:no-rt").is_none());
    }

    #[test]
    fn test_load_or_create_oauth_client_key_persists_and_reloads() {
        let registry = test_registry();
        let k1 = registry.load_or_create_oauth_client_key().unwrap();
        let k2 = registry.load_or_create_oauth_client_key().unwrap();
        assert_eq!(k1.jwk_thumbprint(), k2.jwk_thumbprint());
        assert_eq!(k1.public_jwk(), k2.public_jwk());
    }

    #[tokio::test]
    async fn test_reauth_required_and_notified_lifecycle_and_permanent_errors() {
        use serde_json::json;
        use skyauth::client::OAuthClientMetadata;
        use skyauth::error::{AtprotoOAuthError, TokenError};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        assert!(TenantRegistry::is_permanent_oauth_refresh_error(
            &AtprotoOAuthError::Token(TokenError::MissingRefreshToken)
        ));
        assert!(TenantRegistry::is_permanent_oauth_refresh_error(
            &AtprotoOAuthError::Token(TokenError::RequestFailed {
                status: 400,
                error: "invalid_grant".to_string(),
                description: Some("Invalid refresh token".to_string()),
            })
        ));
        assert!(!TenantRegistry::is_permanent_oauth_refresh_error(
            &AtprotoOAuthError::Token(TokenError::RequestFailed {
                status: 502,
                error: "server_error".to_string(),
                description: None,
            })
        ));
        assert!(!TenantRegistry::is_permanent_oauth_refresh_error(
            &AtprotoOAuthError::Token(TokenError::Http("connection reset".to_string()))
        ));

        let mock_server = MockServer::start().await;
        let token_endpoint = format!("{}/oauth/token", mock_server.uri());
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "error": "invalid_grant",
                        "error_description": "Invalid refresh token"
                    })),
            )
            .mount(&mock_server)
            .await;

        let oauth_client = Arc::new(
            AtprotoOAuthClient::builder()
                .client_metadata(OAuthClientMetadata::new(
                    "https://skybouncer.example.com/client-metadata.json",
                    "https://skybouncer.example.com/oauth/callback",
                ))
                .allow_insecure_localhost(true)
                .build()
                .unwrap(),
        );

        let registry = test_registry();
        registry.set_oauth_client(Arc::clone(&oauth_client));

        let dpop_key = DPoPKey::generate();
        let expired_session = OAuthSession::new(
            "did:plc:expired-grant",
            "at-expired",
            Some("rt-revoked".to_string()),
            "DPoP",
            Some("atproto".to_string()),
            Some(0),
            dpop_key.clone(),
            Some("https://pds.example.com".to_string()),
            Some(mock_server.uri()),
            Some(token_endpoint.clone()),
        )
        .unwrap();

        let tenant = Tenant::new("did:plc:expired-grant")
            .with_handle("expired.bsky.social")
            .with_session(expired_session);
        registry.register_or_update(&tenant).unwrap();

        assert!(!registry
            .is_reauth_required("did:plc:expired-grant")
            .unwrap());
        assert!(!registry
            .is_reauth_notification_pending("did:plc:expired-grant")
            .unwrap());

        // Refresh fails with invalid_grant -> marks reauth_required = 1
        let err = registry
            .get_pds_client("did:plc:expired-grant", None)
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("invalid_grant"));
        assert!(registry
            .is_reauth_required("did:plc:expired-grant")
            .unwrap());
        assert!(registry
            .is_reauth_notification_pending("did:plc:expired-grant")
            .unwrap());
        let pending = registry.list_pending_reauth_notifications().unwrap();
        assert_eq!(
            pending,
            vec![(
                "did:plc:expired-grant".to_string(),
                Some("expired.bsky.social".to_string())
            )]
        );

        // Once mark_reauth_notified is called, it is no longer immediately pending notification
        let t0: u64 = 1_700_000_000_000_000;
        let seven_days_us: u64 = 7 * 24 * 3600 * 1_000_000;
        assert_eq!(
            registry
                .reauth_notify_count("did:plc:expired-grant")
                .unwrap(),
            0
        );
        assert!(registry
            .mark_reauth_notified_at("did:plc:expired-grant", t0)
            .unwrap());
        assert_eq!(
            registry
                .reauth_notify_count("did:plc:expired-grant")
                .unwrap(),
            1
        );
        assert!(registry
            .is_reauth_required("did:plc:expired-grant")
            .unwrap());
        assert!(!registry
            .is_reauth_notification_pending_at(
                "did:plc:expired-grant",
                t0 + seven_days_us - 1,
                DEFAULT_REAUTH_REMINDER_INTERVAL,
            )
            .unwrap());
        assert!(registry
            .list_pending_reauth_notifications_at(
                t0 + seven_days_us - 1,
                DEFAULT_REAUTH_REMINDER_INTERVAL,
            )
            .unwrap()
            .is_empty());

        // At t0 + 7d, the 1st weekly reminder (2nd total DM) becomes pending
        let t1 = t0 + seven_days_us;
        assert!(registry
            .is_reauth_notification_pending_at(
                "did:plc:expired-grant",
                t1,
                DEFAULT_REAUTH_REMINDER_INTERVAL,
            )
            .unwrap());
        assert_eq!(
            registry
                .list_pending_reauth_notifications_at(t1, DEFAULT_REAUTH_REMINDER_INTERVAL)
                .unwrap()
                .len(),
            1
        );
        assert!(registry
            .mark_reauth_notified_at("did:plc:expired-grant", t1)
            .unwrap());
        assert_eq!(
            registry
                .reauth_notify_count("did:plc:expired-grant")
                .unwrap(),
            2
        );

        // At t1 + 7d (t0 + 14d), the 2nd/final weekly reminder (3rd total DM) becomes pending
        let t2 = t1 + seven_days_us;
        assert!(registry
            .is_reauth_notification_pending_at(
                "did:plc:expired-grant",
                t2,
                DEFAULT_REAUTH_REMINDER_INTERVAL,
            )
            .unwrap());
        assert!(registry
            .mark_reauth_notified_at("did:plc:expired-grant", t2)
            .unwrap());
        assert_eq!(
            registry
                .reauth_notify_count("did:plc:expired-grant")
                .unwrap(),
            MAX_REAUTH_NOTIFICATIONS
        );

        // At t2 + 7d (t0 + 21d) and beyond, no further reminders are pending (capped at 3 total DMs)
        let t3 = t2 + seven_days_us;
        assert!(!registry
            .is_reauth_notification_pending_at(
                "did:plc:expired-grant",
                t3,
                DEFAULT_REAUTH_REMINDER_INTERVAL,
            )
            .unwrap());
        assert!(registry
            .list_pending_reauth_notifications_at(t3, DEFAULT_REAUTH_REMINDER_INTERVAL)
            .unwrap()
            .is_empty());

        // Re-authentication via update_session resets reauth_required, reauth_notified_at, and reauth_notify_count
        let fresh_session = OAuthSession::new(
            "did:plc:expired-grant",
            "at-fresh",
            Some("rt-fresh".to_string()),
            "DPoP",
            Some("atproto".to_string()),
            Some(3600),
            dpop_key,
            Some("https://pds.example.com".to_string()),
            Some(mock_server.uri()),
            Some(token_endpoint),
        )
        .unwrap();
        assert!(registry
            .update_session("did:plc:expired-grant", &fresh_session)
            .unwrap());
        assert!(!registry
            .is_reauth_required("did:plc:expired-grant")
            .unwrap());
        assert_eq!(
            registry
                .reauth_notify_count("did:plc:expired-grant")
                .unwrap(),
            0
        );
    }

    #[test]
    fn test_fallback_and_cipher_accessor() {
        let reg = TenantRegistry::fallback().unwrap();
        assert_eq!(reg.count().unwrap(), 0);
        let enc = reg.cipher().encrypt(b"check").unwrap();
        assert_eq!(reg.cipher().decrypt_or_passthrough(&enc).unwrap(), "check");
    }

    #[test]
    fn test_web_session_pass_the_hash_rejected() {
        let registry = test_registry();
        let token = registry
            .create_web_session("did:plc:alice", Duration::from_secs(3600))
            .unwrap();
        let stored_hash = {
            let d = skyauth::crypto::sha256_digest(token.as_bytes());
            let mut h = String::with_capacity(WEB_SESSION_HASH_PREFIX.len() + 64);
            h.push_str(WEB_SESSION_HASH_PREFIX);
            for b in d {
                use std::fmt::Write;
                let _ = write!(&mut h, "{b:02x}");
            }
            h
        };
        assert!(stored_hash.starts_with(WEB_SESSION_HASH_PREFIX));

        // Presenting the stored `sha256:<hex>` digest or raw `<hex>` must NOT validate.
        assert_eq!(registry.validate_web_session(&stored_hash).unwrap(), None);
        let raw_hex = stored_hash.strip_prefix(WEB_SESSION_HASH_PREFIX).unwrap();
        assert_eq!(registry.validate_web_session(raw_hex).unwrap(), None);
        assert!(!registry.delete_web_session(&stored_hash).unwrap());

        // Real token still validates cleanly.
        assert_eq!(
            registry.validate_web_session(&token).unwrap().as_deref(),
            Some("did:plc:alice")
        );
    }

    #[test]
    fn test_web_session_zero_logout_migration_from_64hex_and_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("legacy_web_sessions.db");
        let now = current_time_us();
        let future = now + 3_600_000_000;

        let raw_hex_tok = "tok-prehashed-v033";
        let legacy_64hex = {
            let d = skyauth::crypto::sha256_digest(raw_hex_tok.as_bytes());
            let mut h = String::with_capacity(64);
            for b in d {
                use std::fmt::Write;
                let _ = write!(&mut h, "{b:02x}");
            }
            h
        };
        let legacy_plaintext_tok = "legacy-plaintext-session-token";

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE web_sessions (
                    token TEXT PRIMARY KEY,
                    did TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO web_sessions (token, did, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![legacy_64hex, "did:plc:hexuser", us_to_i64(now), us_to_i64(future)],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO web_sessions (token, did, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![legacy_plaintext_tok, "did:plc:plainuser", us_to_i64(now), us_to_i64(future)],
            )
            .unwrap();
            // Expired legacy row should be purged on migration.
            conn.execute(
                "INSERT INTO web_sessions (token, did, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params!["expired-legacy-tok", "did:plc:exp", us_to_i64(now), us_to_i64(now - 10)],
            )
            .unwrap();
        }

        let _env_guard = crate::crypto::test_env_lock().lock().unwrap();
        std::env::remove_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY");
        let registry = TenantRegistry::open(&db_path).unwrap();

        // Zero-logout: both pre-existing tokens STILL validate.
        assert_eq!(
            registry
                .validate_web_session(raw_hex_tok)
                .unwrap()
                .as_deref(),
            Some("did:plc:hexuser")
        );
        assert_eq!(
            registry
                .validate_web_session(legacy_plaintext_tok)
                .unwrap()
                .as_deref(),
            Some("did:plc:plainuser")
        );
        assert_eq!(
            registry.validate_web_session("expired-legacy-tok").unwrap(),
            None
        );

        // Pass-the-hash on migrated rows is rejected.
        let stored_tokens: Vec<String> = {
            let conn = registry.conn.lock();
            let mut stmt = conn.prepare("SELECT token FROM web_sessions").unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        assert_eq!(stored_tokens.len(), 2);
        for tok in stored_tokens {
            assert!(tok.starts_with(WEB_SESSION_HASH_PREFIX), "tok={tok}");
            assert_eq!(registry.validate_web_session(&tok).unwrap(), None);
        }
    }

    #[test]
    fn test_zero_logout_secret_migration_and_db_file_permissions() {
        let _env_guard = crate::crypto::test_env_lock().lock().unwrap();
        std::env::remove_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY");

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("migrate_secrets.db");
        let legacy_cipher = SessionCipher::legacy_host_fallback();
        let did = "did:plc:legacy_migrated";
        let dpop = DPoPKey::generate();
        let session = OAuthSession::new(
            did,
            "at-legacy-tok",
            Some("rt-legacy-tok".to_string()),
            "DPoP",
            Some("atproto".to_string()),
            Some(3600),
            dpop,
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        let raw_session_json = serde_json::to_string(&session).unwrap();
        let legacy_session_enc = legacy_cipher.encrypt(raw_session_json.as_bytes()).unwrap();
        let legacy_client_dpop = DPoPKey::generate();
        let legacy_oauth_key_enc = legacy_cipher
            .encrypt(legacy_client_dpop.to_bytes_b64().as_bytes())
            .unwrap();

        {
            let reg = TenantRegistry::from_connection(Arc::new(Mutex::new(
                Connection::open(&db_path).unwrap(),
            )))
            .unwrap();
            let now = us_to_i64(current_time_us());
            let conn = reg.conn.lock();
            conn.execute(
                "INSERT INTO tenants (did, session_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params![did, legacy_session_enc, now, now],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO oauth_client_keys (key_id, encrypted_key, created_at) VALUES ('primary', ?1, ?2)",
                params![legacy_oauth_key_enc, now],
            )
            .unwrap();
        }

        // Reopen with TenantRegistry::open -> generates .skybouncer.key + migrates legacy rows atomically.
        let migrated_reg = TenantRegistry::open(&db_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let db_mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(db_mode, 0o600);
            let key_mode = std::fs::metadata(dir.path().join(crate::crypto::KEY_FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(key_mode, 0o600);
        }

        // Tenant session decrypts seamlessly under the new cipher + strict AAD.
        let tenant = migrated_reg.get(did).unwrap().expect("migrated tenant");
        assert_eq!(
            tenant.session.as_ref().unwrap().access_token,
            "at-legacy-tok"
        );

        // Stored DB ciphertext was actually re-sealed under the new key with AAD (not legacy cipher).
        let (stored_sess, stored_key): (String, String) = {
            let conn = migrated_reg.conn.lock();
            let s: String = conn
                .query_row(
                    "SELECT session_json FROM tenants WHERE did = ?1",
                    params![did],
                    |r| r.get(0),
                )
                .unwrap();
            let k: String = conn
                .query_row(
                    "SELECT encrypted_key FROM oauth_client_keys WHERE key_id = 'primary'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            (s, k)
        };
        assert!(legacy_cipher
            .decrypt_strict_with_aad(&stored_sess, did.as_bytes())
            .is_err());
        assert!(migrated_reg
            .cipher()
            .decrypt_strict_with_aad(&stored_sess, did.as_bytes())
            .is_ok());
        assert!(migrated_reg
            .cipher()
            .decrypt_strict_with_aad(&stored_key, b"oauth_client_key:primary")
            .is_ok());
    }

    #[test]
    fn test_tenant_session_sub_mismatch_rejected_on_write_and_read() {
        let registry = test_registry();
        let wrong_session = OAuthSession::new(
            "did:plc:attacker",
            "at-1",
            None,
            "DPoP",
            None,
            None,
            DPoPKey::generate(),
            None,
            None,
            None,
        )
        .unwrap();

        // Write checks reject mismatched sub.
        assert!(registry
            .register_or_update(&Tenant::new("did:plc:victim").with_session(wrong_session.clone()))
            .is_err());
        assert!(registry
            .upsert_oauth_session("did:plc:victim", None, &wrong_session)
            .is_err());

        // Read check rejects tampered DB row whose decrypted session.sub != row.did.
        let tampered_enc = registry
            .cipher()
            .encrypt_with_aad(
                serde_json::to_string(&wrong_session).unwrap().as_bytes(),
                b"did:plc:victim",
            )
            .unwrap();
        let now = us_to_i64(current_time_us());
        {
            let conn = registry.conn.lock();
            conn.execute(
                "INSERT INTO tenants (did, session_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params!["did:plc:victim", tampered_enc, now, now],
            )
            .unwrap();
        }
        assert!(registry.get("did:plc:victim").is_err());
    }

    #[test]
    fn test_load_or_create_oauth_client_key_concurrent_cold_start_race() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cold_start_race.db");
        let _env_guard = crate::crypto::test_env_lock().lock().unwrap();
        std::env::remove_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY");

        let reg = Arc::new(TenantRegistry::open(&db_path).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(6));
        let mut handles = Vec::new();
        for _ in 0..6 {
            let r = Arc::clone(&reg);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                r.load_or_create_oauth_client_key()
                    .map(|k| serde_json::to_string(&k).unwrap())
            }));
        }

        let keys: Vec<String> = handles
            .into_iter()
            .map(|h| h.join().unwrap().expect("cold-start key"))
            .collect();
        for k in &keys[1..] {
            assert_eq!(k, &keys[0], "all racing threads must observe identical JWK");
        }
    }

    #[test]
    fn test_remove_tenant_purges_web_sessions_and_evicts_pds_client() {
        let registry = test_registry();
        let did = "did:plc:remove_me";
        let session = OAuthSession::new(
            did,
            "at-rem",
            None,
            "DPoP",
            None,
            None,
            DPoPKey::generate(),
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        registry
            .register_or_update(&Tenant::new(did).with_session(session))
            .unwrap();
        let web_tok = registry
            .create_web_session(did, Duration::from_secs(3600))
            .unwrap();
        let other_tok = registry
            .create_web_session("did:plc:other", Duration::from_secs(3600))
            .unwrap();

        let pds_client =
            Arc::new(PdsRepoClient::from_credentials("https://pds.example", did, "tok").unwrap());
        {
            let mut map = registry.pds_clients.write();
            map.insert(did.to_string(), pds_client);
        }

        assert!(registry.remove(did).unwrap());
        assert!(registry.get(did).unwrap().is_none());
        assert_eq!(registry.validate_web_session(&web_tok).unwrap(), None);
        assert_eq!(
            registry
                .validate_web_session(&other_tok)
                .unwrap()
                .as_deref(),
            Some("did:plc:other")
        );
        assert!(!registry.pds_clients.read().contains_key(did));
    }

    #[test]
    fn test_upsert_oauth_session_preserves_concurrent_rubric_and_pause_edits() {
        let registry = test_registry();
        let did = "did:plc:upsert_preserve";
        let rubric = RuleRubric::new(
            "Custom sovereign prompt",
            crate::classifier::Sensitivity::High,
        );
        let tenant = Tenant::new(did)
            .with_handle("old.bsky.social")
            .with_rubric(rubric.clone())
            .with_active(false);
        registry.register_or_update(&tenant).unwrap();

        let fresh_session = OAuthSession::new(
            did,
            "at-fresh-upsert",
            Some("rt-fresh-upsert".to_string()),
            "DPoP",
            Some("atproto".to_string()),
            Some(3600),
            DPoPKey::generate(),
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        registry
            .upsert_oauth_session(did, Some("new.bsky.social"), &fresh_session)
            .unwrap();

        let updated = registry.get(did).unwrap().unwrap();
        assert_eq!(updated.handle.as_deref(), Some("new.bsky.social"));
        assert!(
            !updated.is_active,
            "inactive/paused state must be preserved on OAuth upsert"
        );
        assert_eq!(
            updated.rubric.as_ref().map(|r| r.prompt.as_str()),
            Some("Custom sovereign prompt")
        );
        assert_eq!(
            updated.session.as_ref().unwrap().access_token,
            "at-fresh-upsert"
        );
    }

    #[test]
    fn test_update_session_cas_conflict_detection_and_missing_row() {
        let registry = test_registry();
        let did = "did:plc:cas_user";
        let s1 = OAuthSession::new(
            did,
            "at-1",
            Some("rt-1".to_string()),
            "DPoP",
            None,
            Some(3600),
            DPoPKey::generate(),
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        registry
            .register_or_update(&Tenant::new(did).with_session(s1))
            .unwrap();

        let original_raw: String = {
            let conn = registry.conn.lock();
            conn.query_row(
                "SELECT session_json FROM tenants WHERE did = ?1",
                params![did],
                |r| r.get(0),
            )
            .unwrap()
        };

        // Simulate concurrent fresh login replacing s1 with s2.
        let s2 = OAuthSession::new(
            did,
            "at-2-fresh-login",
            Some("rt-2".to_string()),
            "DPoP",
            None,
            Some(3600),
            DPoPKey::generate(),
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        registry.upsert_oauth_session(did, None, &s2).unwrap();

        // Stale refresh CAS using old expected ciphertext must detect Conflict and NOT overwrite s2.
        let s_stale_refresh = OAuthSession::new(
            did,
            "at-stale",
            None,
            "DPoP",
            None,
            Some(3600),
            DPoPKey::generate(),
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        let outcome = registry
            .update_session_cas(did, &s_stale_refresh, &original_raw)
            .unwrap();
        assert_eq!(outcome, CasUpdateOutcome::Conflict);
        assert_eq!(
            registry
                .get(did)
                .unwrap()
                .unwrap()
                .session
                .unwrap()
                .access_token,
            "at-2-fresh-login"
        );

        // Missing row returns NotFound.
        let missing_s = OAuthSession::new(
            "did:plc:missing_cas",
            "at-m",
            None,
            "DPoP",
            None,
            None,
            DPoPKey::generate(),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            registry
                .update_session_cas("did:plc:missing_cas", &missing_s, "raw")
                .unwrap(),
            CasUpdateOutcome::NotFound
        );
    }

    #[test]
    fn test_migrate_encrypted_secrets_skips_corrupt_mismatched_and_non_strict_rows() {
        let _env_guard = crate::crypto::test_env_lock().lock().unwrap();
        std::env::remove_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY");

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("corrupt_migration.db");
        let now = us_to_i64(current_time_us());

        let wrong_sub_session = OAuthSession::new(
            "did:plc:wrong_sub",
            "at-wrong",
            None,
            "DPoP",
            None,
            None,
            DPoPKey::generate(),
            None,
            None,
            None,
        )
        .unwrap();
        let wrong_sub_plain = serde_json::to_string(&wrong_sub_session).unwrap();

        {
            let conn = Connection::open(&db_path).unwrap();
            let reg = TenantRegistry::from_connection(Arc::new(Mutex::new(conn))).unwrap();
            let c = reg.conn.lock();
            // 1. Undecryptable tenant session_json
            c.execute(
                "INSERT INTO tenants (did, session_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params!["did:plc:bad_cipher", "enc:v1:bm90LXZhbGlkLWJhc2U2NA==", now, now],
            )
            .unwrap();
            // 2. Non-JSON plaintext tenant session_json
            c.execute(
                "INSERT INTO tenants (did, session_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params!["did:plc:bad_json", "{not-json", now, now],
            )
            .unwrap();
            // 3. Plaintext JSON whose sub != row.did
            c.execute(
                "INSERT INTO tenants (did, session_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params!["did:plc:victim_mig", wrong_sub_plain, now, now],
            )
            .unwrap();
            // 4. Undecryptable oauth_client_keys row
            c.execute(
                "INSERT INTO oauth_client_keys (key_id, encrypted_key, created_at) VALUES ('bad1', ?1, ?2)",
                params!["enc:v1:invalid==", now],
            )
            .unwrap();
            // 5. Invalid DPoPKey payload in oauth_client_keys row
            c.execute(
                "INSERT INTO oauth_client_keys (key_id, encrypted_key, created_at) VALUES ('bad2', ?1, ?2)",
                params!["not-a-dpop-key", now],
            )
            .unwrap();
        }

        // Reopen triggers migration: corrupt rows are safely skipped without aborting startup.
        let reopened = TenantRegistry::open(&db_path).unwrap();
        assert!(reopened.get("did:plc:bad_cipher").is_err());
        assert!(reopened.get("did:plc:victim_mig").is_err());
    }

    #[test]
    fn test_load_or_create_oauth_client_key_env_override_valid_and_invalid() {
        let _env_guard = crate::crypto::test_env_lock().lock().unwrap();
        let reg = test_registry();
        let generated = DPoPKey::generate();
        let b64 = generated.to_bytes_b64();

        std::env::set_var("OAUTH_CLIENT_PRIVATE_KEY", &b64);
        let loaded = reg.load_or_create_oauth_client_key().unwrap();
        assert_eq!(loaded.to_bytes_b64(), b64);

        std::env::set_var(
            "OAUTH_CLIENT_PRIVATE_KEY",
            "-----BEGIN PRIVATE KEY-----\ninvalid",
        );
        assert!(reg.load_or_create_oauth_client_key().is_err());

        std::env::set_var("OAUTH_CLIENT_PRIVATE_KEY", "not-base64-key");
        assert!(reg.load_or_create_oauth_client_key().is_err());

        std::env::remove_var("OAUTH_CLIENT_PRIVATE_KEY");
    }

    #[test]
    fn test_mark_reauth_required_cas_epoch_guard_and_transient_db_detection() {
        assert!(TenantRegistry::is_transient_db_error(
            &SkybouncerError::Database("database is locked".to_string())
        ));
        assert!(TenantRegistry::is_transient_db_error(
            &SkybouncerError::Database("SQLITE_BUSY".to_string())
        ));
        assert!(!TenantRegistry::is_transient_db_error(
            &SkybouncerError::Auth("token expired".to_string())
        ));

        let registry = test_registry();
        let did = "did:plc:reauth_cas_user";
        let s1 = OAuthSession::new(
            did,
            "at-1",
            Some("rt-1".to_string()),
            "DPoP",
            None,
            Some(3600),
            DPoPKey::generate(),
            Some("https://pds.example".to_string()),
            None,
            None,
        )
        .unwrap();
        registry
            .register_or_update(&Tenant::new(did).with_session(s1))
            .unwrap();

        let raw1: String = {
            let conn = registry.conn.lock();
            conn.query_row(
                "SELECT session_json FROM tenants WHERE did = ?1",
                params![did],
                |r| r.get(0),
            )
            .unwrap()
        };

        // CAS mismatch returns false and does NOT mark reauth_required.
        assert!(!registry.mark_reauth_required_cas(did, "stale-raw").unwrap());
        assert!(!registry.is_reauth_required(did).unwrap());

        // Matching CAS marks reauth_required = true and evicts client.
        assert!(registry.mark_reauth_required_cas(did, &raw1).unwrap());
        assert!(registry.is_reauth_required(did).unwrap());

        // Missing DID returns false.
        assert!(!registry
            .mark_reauth_required_cas("did:plc:no_such", &raw1)
            .unwrap());

        // Epoch mismatch prevents stale pds_client insertion.
        let pds_client =
            Arc::new(PdsRepoClient::from_credentials("https://pds.example", did, "tok").unwrap());
        let old_epoch = registry.client_epochs.read().get(did).copied().unwrap_or(0);
        registry.bump_epoch_and_evict(did);
        registry.insert_pds_client_if_epoch_matches(did, old_epoch, &pds_client);
        assert!(!registry.pds_clients.read().contains_key(did));
        let cur_epoch = registry.client_epochs.read().get(did).copied().unwrap_or(0);
        registry.insert_pds_client_if_epoch_matches(did, cur_epoch, &pds_client);
        assert!(registry.pds_clients.read().contains_key(did));
    }
}
