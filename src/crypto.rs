//! Cryptographic helpers for authenticated encryption at rest.
//!
//! Protects sensitive OAuth session tokens, refresh tokens, and private DPoP keys
//! stored in the embedded SQLite database. The AES-256-GCM envelope implementation
//! lives in [`skyauth::sealed::SealedBox`]; this module adapts it to
//! [`SkybouncerError`] and resolves the key from the process environment.

use crate::error::SkybouncerError;
use skyauth::sealed::{SealedBox, SEALED_ENVELOPE_PREFIX};

/// Prefix identifying encrypted session blobs stored at rest.
pub const ENCRYPTION_V1_PREFIX: &str = SEALED_ENVELOPE_PREFIX;

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
        let host = crate::env::var_or(
            &["HOSTNAME", "SERVICE_DID"],
            "skybouncer-default-storage-key",
        );
        Self::from_secret_passphrase(&format!("skybouncer:session:salt:{host}"))
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

    /// Decrypts a versioned Base64 envelope or passes through legacy unencrypted plaintext.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Auth`] if Base64 decoding, nonce extraction, or AES-256-GCM tag verification fails.
    pub fn decrypt_or_passthrough(&self, raw: &str) -> Result<String, SkybouncerError> {
        self.decrypt_or_passthrough_with_aad(raw, &[])
    }

    /// Decrypts a versioned Base64 envelope with additional authenticated data (AAD) or passes through legacy unencrypted plaintext.
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
}
