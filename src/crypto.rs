//! Cryptographic helpers for AES-256-GCM authenticated encryption at rest.
//!
//! Protects sensitive OAuth session tokens, refresh tokens, and private DPoP keys
//! stored in the embedded SQLite database.

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};
use ring::digest::{digest, SHA256};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::SkybouncerError;

/// Prefix identifying encrypted session blobs stored at rest.
pub const ENCRYPTION_V1_PREFIX: &str = "enc:v1:";

/// Nonce sequence adapter for single-operation encryption or decryption.
struct SingleNonce(Option<[u8; 12]>);

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let bytes = self.0.take().ok_or(Unspecified)?;
        Nonce::try_assume_unique_for_key(&bytes)
    }
}

/// Authenticated cipher for encrypting and decrypting data at rest using AES-256-GCM.
#[derive(Clone)]
pub struct SessionCipher {
    key_bytes: [u8; 32],
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
        Self { key_bytes: key }
    }

    /// Derives a 32-byte key from an arbitrary secret string using SHA-256.
    #[must_use]
    pub fn from_secret_passphrase(secret: &str) -> Self {
        let digest_val = digest(&SHA256, secret.as_bytes());
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(digest_val.as_ref());
        Self::new(key_bytes)
    }

    /// Loads the cipher key from `SKYBOUNCER_SESSION_ENCRYPTION_KEY` or derives a machine-stable key.
    #[must_use]
    pub fn from_env() -> Self {
        if let Ok(key_str) = std::env::var("SKYBOUNCER_SESSION_ENCRYPTION_KEY") {
            let trimmed = key_str.trim();
            if !trimmed.is_empty() {
                if let Some(key_bytes) = parse_hex_32(trimmed) {
                    return Self::new(key_bytes);
                }
                tracing::warn!(
                    "SKYBOUNCER_SESSION_ENCRYPTION_KEY is not a 64-character hex string; deriving key via passphrase KDF"
                );
                return Self::from_secret_passphrase(trimmed);
            }
        }

        // Fallback: derive a stable default machine key based on hostname/hostname salt
        tracing::warn!(
            "SECURITY WARNING: SKYBOUNCER_SESSION_ENCRYPTION_KEY is not set! \
             Session OAuth tokens at rest are being protected by a host-derived fallback key. \
             Please configure SKYBOUNCER_SESSION_ENCRYPTION_KEY with a 64-char hex key in production."
        );
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("SERVICE_DID"))
            .unwrap_or_else(|_| "skybouncer-default-storage-key".to_string());
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
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| SkybouncerError::Auth("Failed to generate random nonce".to_string()))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| SkybouncerError::Auth("Invalid AES-256-GCM key".to_string()))?;

        let mut sealing_key = SealingKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::from(aad_bytes), &mut in_out)
            .map_err(|_| SkybouncerError::Auth("Failed to encrypt session payload".to_string()))?;

        // Format payload: 12-byte nonce followed by ciphertext + 16-byte tag
        let mut combined = Vec::with_capacity(12 + in_out.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&in_out);

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&combined);
        Ok(format!("{ENCRYPTION_V1_PREFIX}{b64}"))
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
        let raw = raw.trim();
        if !raw.starts_with(ENCRYPTION_V1_PREFIX) {
            // Legacy unencrypted JSON payload; pass through directly
            return Ok(raw.to_string());
        }

        let encoded = &raw[ENCRYPTION_V1_PREFIX.len()..];
        use base64::Engine;
        let combined = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| {
                SkybouncerError::Auth(format!("Base64 decoding failed for session payload: {e}"))
            })?;

        // 12-byte nonce + 16-byte authentication tag = minimum 28 bytes
        if combined.len() < 28 {
            return Err(SkybouncerError::Auth(
                "Encrypted session payload is truncated".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext_and_tag) = combined.split_at(12);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| SkybouncerError::Auth("Invalid AES-256-GCM key".to_string()))?;

        let mut opening_key = OpeningKey::new(unbound_key, SingleNonce(Some(nonce_arr)));

        let mut in_out = ciphertext_and_tag.to_vec();
        // Try opening with specified AAD; if non-empty and fails, try empty AAD for backwards-compatibility
        let plaintext_slice = match opening_key.open_in_place(Aad::from(aad_bytes), &mut in_out) {
            Ok(slice) => slice,
            Err(_) if !aad_bytes.is_empty() => {
                let unbound_key_retry = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
                    .map_err(|_| SkybouncerError::Auth("Invalid AES-256-GCM key".to_string()))?;
                let mut retry_key =
                    OpeningKey::new(unbound_key_retry, SingleNonce(Some(nonce_arr)));
                let mut retry_buf = ciphertext_and_tag.to_vec();
                retry_key
                    .open_in_place(Aad::empty(), &mut retry_buf)
                    .map_err(|_| {
                        SkybouncerError::Auth(
                            "Failed to decrypt session: authentication tag mismatch or invalid key"
                                .to_string(),
                        )
                    })?;
                return String::from_utf8(retry_buf[..retry_buf.len() - 16].to_vec()).map_err(
                    |e| {
                        SkybouncerError::Auth(format!(
                            "Decrypted session payload is not valid UTF-8: {e}"
                        ))
                    },
                );
            }
            Err(_) => {
                return Err(SkybouncerError::Auth(
                    "Failed to decrypt session: authentication tag mismatch or invalid key"
                        .to_string(),
                ));
            }
        };

        String::from_utf8(plaintext_slice.to_vec()).map_err(|e| {
            SkybouncerError::Auth(format!("Decrypted session payload is not valid UTF-8: {e}"))
        })
    }
}

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        let byte = u8::from_str_radix(hex_str, 16).ok()?;
        out[i] = byte;
    }
    Some(out)
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
}
