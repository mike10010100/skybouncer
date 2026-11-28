//! Cryptographic helpers for authenticated encryption at rest.
//!
//! Protects sensitive OAuth session tokens, refresh tokens, and private DPoP keys
//! stored in the embedded SQLite database. The AES-256-GCM envelope implementation
//! lives in [`skyauth::sealed::SealedBox`]; this module adapts it to
//! [`SkybouncerError`] and resolves the key from the process environment.

use std::io::{ErrorKind, Write};
use std::path::Path;

use crate::error::SkybouncerError;
use skyauth::sealed::{SealedBox, SEALED_ENVELOPE_PREFIX};
use zeroize::Zeroizing;

/// Prefix identifying encrypted session blobs stored at rest.
pub const ENCRYPTION_V1_PREFIX: &str = SEALED_ENVELOPE_PREFIX;

/// Filename used to persist an auto-generated 256-bit key beside a file-backed SQLite database.
pub const KEY_FILE_NAME: &str = ".skybouncer.key";

/// Authenticated cipher for encrypting and decrypting data at rest using AES-256-GCM.
#[derive(Clone)]
pub struct SessionCipher {
    inner: SealedBox,
}

impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCipher")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Default for SessionCipher {
    fn default() -> Self {
        Self::from_env()
    }
}

impl SessionCipher {
    /// Creates a new [`SessionCipher`] from a 32-byte secret key.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            inner: SealedBox::new(key),
        }
    }

    /// Derives a 32-byte key from an arbitrary secret string using SHA-256.
    #[must_use]
    pub fn from_secret_passphrase(secret: &str) -> Self {
        Self {
            inner: SealedBox::from_secret_passphrase(secret),
        }
    }

    /// Derives the legacy hostname-based fallback cipher used before `.skybouncer.key`
    /// auto-generation was introduced.
    ///
    /// Used exclusively to migrate existing databases at startup without logging users out.
    #[must_use]
    pub fn legacy_host_fallback() -> Self {
        let host = crate::env::var_or(
            &["HOSTNAME", "SERVICE_DID"],
            "skybouncer-default-storage-key",
        );
        Self::from_secret_passphrase(&format!("skybouncer:session:salt:{host}"))
    }

    /// Loads the cipher key from `SKYBOUNCER_SESSION_ENCRYPTION_KEY` or derives a machine-stable key.
    #[must_use]
    pub fn from_env() -> Self {
        if let Some(trimmed) = crate::env::var(&["SKYBOUNCER_SESSION_ENCRYPTION_KEY"]) {
            if let Ok(inner) = SealedBox::from_hex(&trimmed) {
                return Self { inner };
            }
            tracing::warn!(
                "SKYBOUNCER_SESSION_ENCRYPTION_KEY is not a 64-character hex string; deriving key via passphrase KDF"
            );
            return Self::from_secret_passphrase(&trimmed);
        }

        // Fallback: derive a stable default machine key based on hostname/hostname salt
        tracing::warn!(
            "SECURITY WARNING: SKYBOUNCER_SESSION_ENCRYPTION_KEY is not set! \
             Session OAuth tokens at rest are being protected by a host-derived fallback key. \
             Please configure SKYBOUNCER_SESSION_ENCRYPTION_KEY with a 64-char hex key in production."
        );
        Self::legacy_host_fallback()
    }

    /// Resolves the active [`SessionCipher`] and optional legacy migration cipher for `db_path`.
    ///
    /// Precedence:
    /// 1. `SKYBOUNCER_SESSION_ENCRYPTION_KEY` environment variable (64-hex or passphrase KDF).
    /// 2. `<db_dir>/.skybouncer.key` for file-backed SQLite databases: loaded and validated if
    ///    present, or generated atomically with mode `0600` on Unix if absent.
    /// 3. Ephemeral CSPRNG key for in-memory databases (`db_path == None` or `:memory:`).
    ///
    /// Returns `(active_cipher, Some(legacy_host_fallback))` so startup migrations can
    /// transparently re-seal rows encrypted under the legacy hostname fallback key.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if an existing `.skybouncer.key` is malformed or
    /// the key file cannot be read/created (failing closed rather than silently downgrading).
    pub fn resolve_for_db_path(
        db_path: Option<&Path>,
    ) -> Result<(Self, Option<Self>), SkybouncerError> {
        let legacy = Some(Self::legacy_host_fallback());

        if let Some(trimmed) = crate::env::var(&["SKYBOUNCER_SESSION_ENCRYPTION_KEY"]) {
            if let Ok(inner) = SealedBox::from_hex(&trimmed) {
                return Ok((Self { inner }, legacy));
            }
            tracing::warn!(
                "SKYBOUNCER_SESSION_ENCRYPTION_KEY is not a 64-character hex string; deriving key via passphrase KDF"
            );
            return Ok((Self::from_secret_passphrase(&trimmed), legacy));
        }

        let Some(path) =
            db_path.filter(|p| !p.as_os_str().is_empty() && *p != Path::new(":memory:"))
        else {
            return Ok((
                Self {
                    inner: SealedBox::generate(),
                },
                legacy,
            ));
        };

        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| {
            SkybouncerError::Config(format!(
                "Failed to create database key directory {}: {e}",
                dir.display()
            ))
        })?;

        let key_path = dir.join(KEY_FILE_NAME);
        if key_path.exists() {
            let cipher = Self::load_key_file(&key_path)?;
            return Ok((cipher, legacy));
        }

        let inner = SealedBox::generate();
        let hex = inner.to_hex();

        let created = Self::write_key_file_atomically(dir, &key_path, &hex)?;
        if !created {
            // Another concurrent starter placed `.skybouncer.key` first; load its key.
            let cipher = Self::load_key_file(&key_path)?;
            return Ok((cipher, legacy));
        }

        tracing::info!(
            "Generated random 256-bit session encryption key at {} (mode 0600)",
            key_path.display()
        );
        Ok((Self { inner }, legacy))
    }

    fn load_key_file(key_path: &Path) -> Result<Self, SkybouncerError> {
        let raw = Zeroizing::new(std::fs::read_to_string(key_path).map_err(|e| {
            SkybouncerError::Config(format!(
                "Failed to read session encryption key file {}: {e}",
                key_path.display()
            ))
        })?);
        let inner = SealedBox::from_hex(raw.trim()).map_err(|e| {
            SkybouncerError::Config(format!(
                "Invalid session encryption key in {}: {e}",
                key_path.display()
            ))
        })?;
        enforce_owner_rw_permissions(key_path).map_err(|e| {
            SkybouncerError::Config(format!(
                "Failed to enforce 0600 permissions on {}: {e}",
                key_path.display()
            ))
        })?;
        Ok(Self { inner })
    }

    fn write_key_file_atomically(
        dir: &Path,
        key_path: &Path,
        hex: &Zeroizing<String>,
    ) -> Result<bool, SkybouncerError> {
        let pid = std::process::id();
        let mut attempt = 0u32;
        let (tmp_path, mut file) = loop {
            let nonce = crate::time::current_time_us();
            let candidate = dir.join(format!("{KEY_FILE_NAME}.tmp.{pid}.{nonce}.{attempt}"));
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(&candidate) {
                Ok(f) => break (candidate, f),
                Err(e) if e.kind() == ErrorKind::AlreadyExists && attempt < 16 => {
                    attempt += 1;
                }
                Err(e) => {
                    return Err(SkybouncerError::Config(format!(
                        "Failed to create temporary session key file {}: {e}",
                        candidate.display()
                    )));
                }
            }
        };

        let write_res = (|| -> std::io::Result<()> {
            file.write_all(hex.as_bytes())?;
            file.sync_all()?;
            enforce_owner_rw_permissions(&tmp_path)?;
            Ok(())
        })();
        drop(file);

        if let Err(e) = write_res {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(SkybouncerError::Config(format!(
                "Failed to write session encryption key file {}: {e}",
                key_path.display()
            )));
        }

        // Prefer atomic non-clobbering link so concurrent startups never overwrite a winner.
        match std::fs::hard_link(&tmp_path, key_path) {
            Ok(()) => {
                let _ = std::fs::remove_file(&tmp_path);
                let _ = enforce_owner_rw_permissions(key_path);
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&tmp_path);
                Ok(false)
            }
            Err(e) if e.kind() == ErrorKind::Unsupported => {
                let res = std::fs::rename(&tmp_path, key_path);
                if let Err(rename_err) = res {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(SkybouncerError::Config(format!(
                        "Failed to install session key file {}: {rename_err}",
                        key_path.display()
                    )));
                }
                let _ = enforce_owner_rw_permissions(key_path);
                Ok(true)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                Err(SkybouncerError::Config(format!(
                    "Failed to install session key file {}: {e}",
                    key_path.display()
                )))
            }
        }
    }

    /// Encrypts plaintext bytes into a versioned Base64 envelope (`enc:v1:<base64>`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Auth`] if CSPRNG nonce generation or AES-256-GCM sealing fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, SkybouncerError> {
        self.encrypt_with_aad(plaintext, &[])
    }

    /// Encrypts plaintext bytes with additional authenticated data (AAD) into a versioned Base64 envelope (`enc:v1:<base64>`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Auth`] if CSPRNG nonce generation or AES-256-GCM sealing fails.
    pub fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad_bytes: &[u8],
    ) -> Result<String, SkybouncerError> {
        self.inner
            .seal_with_aad(plaintext, aad_bytes)
            .map_err(|e| SkybouncerError::Auth(format!("Failed to encrypt session payload: {e}")))
    }

    /// Strictly decrypts a versioned Base64 envelope with required AAD into a [`Zeroizing<String>`].
    ///
    /// Unlike [`Self::decrypt_or_passthrough_with_aad`], this rejects unencrypted plaintext and
    /// refuses empty-AAD fallback.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Auth`] if the `enc:v1:` prefix is missing, decoding fails, or
    /// AES-256-GCM authentication with `aad_bytes` fails.
    pub fn decrypt_strict_with_aad(
        &self,
        raw: &str,
        aad_bytes: &[u8],
    ) -> Result<Zeroizing<String>, SkybouncerError> {
        self.inner
            .open_string_strict_with_aad(raw, aad_bytes)
            .map_err(|e| SkybouncerError::Auth(format!("Failed to decrypt session: {e}")))
    }

    /// Decrypts a versioned Base64 envelope or passes through legacy unencrypted plaintext.
    ///
    /// Intended solely for startup secret migrations and legacy compatibility unit tests.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Auth`] if Base64 decoding, nonce extraction, or AES-256-GCM tag verification fails.
    pub fn decrypt_or_passthrough(&self, raw: &str) -> Result<String, SkybouncerError> {
        self.decrypt_or_passthrough_with_aad(raw, &[])
    }

    /// Decrypts a versioned Base64 envelope with additional authenticated data (AAD) or passes through legacy unencrypted plaintext.
    ///
    /// Intended solely for startup secret migrations and legacy compatibility unit tests.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Auth`] if Base64 decoding, nonce extraction, or AES-256-GCM tag verification fails.
    pub fn decrypt_or_passthrough_with_aad(
        &self,
        raw: &str,
        aad_bytes: &[u8],
    ) -> Result<String, SkybouncerError> {
        self.inner
            .open_string_with_aad(raw, aad_bytes)
            .map_err(|e| SkybouncerError::Auth(format!("Failed to decrypt session: {e}")))
    }
}

fn enforce_owner_rw_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Best-effort enforcement of owner-only `0600` permissions on a SQLite database file and its
/// `-wal` / `-shm` sidecar files on Unix.
pub(crate) fn set_sqlite_file_permissions(db_path: &Path) {
    if db_path.as_os_str().is_empty() || db_path == Path::new(":memory:") {
        return;
    }
    let sidecars = [
        db_path.to_path_buf(),
        Path::new(&format!("{}-wal", db_path.display())).to_path_buf(),
        Path::new(&format!("{}-shm", db_path.display())).to_path_buf(),
    ];
    for candidate in sidecars {
        if candidate.exists() {
            if let Err(e) = enforce_owner_rw_permissions(&candidate) {
                tracing::warn!(
                    path = %candidate.display(),
                    error = %e,
                    "Failed to enforce 0600 permissions on SQLite file"
                );
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    &tests::ENV_LOCK
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_session_cipher_encrypt_decrypt_roundtrip() {
        let cipher = SessionCipher::from_secret_passphrase("test-secret-passphrase-12345");
        let original_json = r#"{"access_token":"secret123","refresh_token":"refresh456"}"#;

        let encrypted = cipher.encrypt(original_json.as_bytes()).expect("encrypt");
        assert!(encrypted.starts_with(ENCRYPTION_V1_PREFIX));
        assert_ne!(encrypted, original_json);

        let decrypted = cipher.decrypt_or_passthrough(&encrypted).expect("decrypt");
        assert_eq!(decrypted, original_json);
    }

    #[test]
    fn test_session_cipher_passthrough_legacy_unencrypted() {
        let cipher = SessionCipher::from_secret_passphrase("test-secret-passphrase-12345");
        let legacy_json = r#"{"access_token":"plain123","refresh_token":"plain456"}"#;

        let result = cipher
            .decrypt_or_passthrough(legacy_json)
            .expect("passthrough");
        assert_eq!(result, legacy_json);
    }

    #[test]
    fn test_session_cipher_wrong_key_fails_authentication() {
        let cipher1 = SessionCipher::from_secret_passphrase("correct-key");
        let cipher2 = SessionCipher::from_secret_passphrase("wrong-key");

        let original = r#"{"secret":"top-secret-tokens"}"#;
        let encrypted = cipher1.encrypt(original.as_bytes()).expect("encrypt");

        let err = cipher2
            .decrypt_or_passthrough(&encrypted)
            .expect_err("should fail with wrong key");
        assert!(err.to_string().contains("Failed to decrypt session"));
    }

    #[test]
    fn test_session_cipher_aad_roundtrip_and_binding() {
        let cipher = SessionCipher::from_secret_passphrase("aad-key");
        let encrypted = cipher
            .encrypt_with_aad(b"session-json", b"did:plc:alice")
            .expect("encrypt");

        let decrypted = cipher
            .decrypt_or_passthrough_with_aad(&encrypted, b"did:plc:alice")
            .expect("decrypt");
        assert_eq!(decrypted, "session-json");

        let wrong = cipher.decrypt_or_passthrough_with_aad(&encrypted, b"did:plc:mallory");
        assert!(wrong.is_err());
    }

    #[test]
    fn test_session_cipher_new_default_debug_and_env_branches() {
        let _env_guard = ENV_LOCK.lock().unwrap();
        let cipher = SessionCipher::new([7u8; 32]);
        let dbg = format!("{cipher:?}");
        assert!(dbg.contains("REDACTED"));

        std::env::set_var(
            "SKYBOUNCER_SESSION_ENCRYPTION_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let hex_cipher = SessionCipher::default();
        let enc = hex_cipher.encrypt(b"payload").expect("encrypt");
        assert_eq!(
            hex_cipher.decrypt_or_passthrough(&enc).expect("decrypt"),
            "payload"
        );

        std::env::set_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY", "short-passphrase");
        let pass_cipher = SessionCipher::from_env();
        let enc2 = pass_cipher.encrypt(b"payload2").expect("encrypt2");
        assert_eq!(
            pass_cipher.decrypt_or_passthrough(&enc2).expect("decrypt2"),
            "payload2"
        );
        std::env::remove_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY");
    }

    pub(super) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_decrypt_strict_with_aad_rejects_plaintext_and_empty_aad() {
        let cipher = SessionCipher::from_secret_passphrase("strict-test-key");
        assert!(cipher
            .decrypt_strict_with_aad(r#"{"access_token":"raw"}"#, b"did:plc:alice")
            .is_err());

        let legacy_empty_aad = cipher.encrypt(b"secret").expect("encrypt");
        assert!(cipher
            .decrypt_strict_with_aad(&legacy_empty_aad, b"did:plc:alice")
            .is_err());

        let strict_enc = cipher
            .encrypt_with_aad(b"secret", b"did:plc:alice")
            .expect("encrypt with aad");
        let dec = cipher
            .decrypt_strict_with_aad(&strict_enc, b"did:plc:alice")
            .expect("strict decrypt");
        assert_eq!(&*dec, "secret");
    }

    #[test]
    fn test_resolve_for_db_path_creates_0600_key_reloads_and_fails_closed() {
        let _env_guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY");

        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("skybouncer.db");
        let key_path = dir.path().join(KEY_FILE_NAME);

        let (c1, legacy) = SessionCipher::resolve_for_db_path(Some(&db_path)).expect("create key");
        assert!(legacy.is_some());
        assert!(key_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path)
                .expect("meta")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let sealed = c1
            .encrypt_with_aad(b"hello", b"did:plc:alice")
            .expect("seal");
        let (c2, _) = SessionCipher::resolve_for_db_path(Some(&db_path)).expect("reload key");
        assert_eq!(
            &*c2.decrypt_strict_with_aad(&sealed, b"did:plc:alice")
                .expect("decrypt"),
            "hello"
        );

        // Malformed key file fails closed with Config error.
        std::fs::write(&key_path, "not-valid-hex\n").expect("write bad key");
        let err = SessionCipher::resolve_for_db_path(Some(&db_path)).expect_err("malformed key");
        assert!(matches!(err, SkybouncerError::Config(_)));

        // Unwritable directory fails closed with Config error (when not running as root).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let ro_dir = tempfile::tempdir().expect("ro tempdir");
            std::fs::set_permissions(ro_dir.path(), std::fs::Permissions::from_mode(0o500))
                .expect("chmod 500");
            let ro_db = ro_dir.path().join("skybouncer.db");
            let res = SessionCipher::resolve_for_db_path(Some(&ro_db));
            std::fs::set_permissions(ro_dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restore chmod");
            if unsafe_euid_is_nonzero() {
                assert!(matches!(res, Err(SkybouncerError::Config(_))));
            }
        }

        // In-memory resolves ephemeral cipher without touching disk.
        let (mem1, mem_legacy) = SessionCipher::resolve_for_db_path(None).expect("mem1");
        assert!(mem_legacy.is_some());
        let (mem2, _) =
            SessionCipher::resolve_for_db_path(Some(Path::new(":memory:"))).expect("mem2");
        let m_enc = mem1.encrypt_with_aad(b"x", b"aad").expect("enc");
        assert!(mem2.decrypt_strict_with_aad(&m_enc, b"aad").is_err());
    }

    #[cfg(unix)]
    fn unsafe_euid_is_nonzero() -> bool {
        // Avoid libc/unsafe: check via `/proc/self/status` or `id -u`
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(2))
                    .map(|euid| euid != "0")
            })
            .unwrap_or(true)
    }

    #[test]
    fn test_resolve_for_db_path_env_variants_and_sqlite_permissions() {
        let _env_guard = ENV_LOCK.lock().unwrap();

        // 1. Unset env triggers from_env() fallback path.
        std::env::remove_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY");
        let legacy_from_env = SessionCipher::from_env();
        let l_enc = legacy_from_env.encrypt(b"env-fallback").unwrap();
        assert_eq!(
            legacy_from_env.decrypt_or_passthrough(&l_enc).unwrap(),
            "env-fallback"
        );

        // 2. 64-hex env var overrides file key in resolve_for_db_path.
        std::env::set_var(
            "SKYBOUNCER_SESSION_ENCRYPTION_KEY",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("env_override.db");
        let (hex_c, legacy1) = SessionCipher::resolve_for_db_path(Some(&db_path)).unwrap();
        assert!(legacy1.is_some());
        let enc_hex = hex_c.encrypt_with_aad(b"v1", b"did:plc:x").unwrap();
        assert_eq!(
            &*hex_c
                .decrypt_strict_with_aad(&enc_hex, b"did:plc:x")
                .unwrap(),
            "v1"
        );

        // 3. Non-hex passphrase env var in resolve_for_db_path derives KDF key.
        std::env::set_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY", "my-passphrase-secret");
        let (pass_c, legacy2) = SessionCipher::resolve_for_db_path(Some(&db_path)).unwrap();
        assert!(legacy2.is_some());
        let enc_pass = pass_c.encrypt_with_aad(b"v2", b"did:plc:y").unwrap();
        assert_eq!(
            &*pass_c
                .decrypt_strict_with_aad(&enc_pass, b"did:plc:y")
                .unwrap(),
            "v2"
        );
        std::env::remove_var("SKYBOUNCER_SESSION_ENCRYPTION_KEY");

        // 4. set_sqlite_file_permissions tightens .db, -wal, and -shm to 0600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let wal = std::path::PathBuf::from(format!("{}-wal", db_path.display()));
            let shm = std::path::PathBuf::from(format!("{}-shm", db_path.display()));
            for p in [&db_path, &wal, &shm] {
                std::fs::write(p, b"sqlite").unwrap();
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            set_sqlite_file_permissions(&db_path);
            for p in [&db_path, &wal, &shm] {
                let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "path={}", p.display());
            }
        }
    }
}
