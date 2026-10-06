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
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use skyauth::client::AtprotoOAuthClient;
use skyauth::session::OAuthSession;
use skybase::repo::PdsRepoClient;

use crate::classifier::RuleRubric;
use crate::crypto::SessionCipher;
use crate::error::SkybouncerError;
use crate::time::{current_time_us, i64_to_us, us_to_i64};

/// Default time-to-live for handle resolution caching (1 hour).
pub const DEFAULT_HANDLE_TTL: Duration = Duration::from_secs(3600);

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
    fn test_registry_fallback_constructs_usable_registry() {
        let registry = TenantRegistry::fallback();
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
        // update_session on an unknown tenant returns false.
        assert!(!registry
            .update_session("did:plc:missing", &session)
            .unwrap());

        // Empty DID for a web session is a config error.
        assert!(registry
            .create_web_session("   ", Duration::from_secs(60))
            .is_err());
        assert!(registry.oauth_client().is_none());
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

        // 1. Transparent backward compatibility: get() loads and parses plain JSON seamlessly
        let fetched = registry
            .get("did:plc:legacy-user")
            .unwrap()
            .expect("legacy tenant exists");
        let loaded_session = fetched.session.expect("legacy session parsed");
        assert_eq!(loaded_session.access_token(), "legacy_plain_access_token");

        // 2. On update_session (e.g. token refresh or update), session is encrypted
        let updated = registry
            .update_session("did:plc:legacy-user", &loaded_session)
            .unwrap();
        assert!(updated);

        // 3. Raw SQLite inspection now verifies encryption
        let raw_json_after_update: String = {
            let conn = registry.conn.lock();
            conn.query_row(
                "SELECT session_json FROM tenants WHERE did = 'did:plc:legacy-user';",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };

        assert!(raw_json_after_update.starts_with(ENCRYPTION_V1_PREFIX));
        assert!(!raw_json_after_update.contains("legacy_plain_access_token"));
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
}
