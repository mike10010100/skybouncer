//! Strongly-typed errors for the `skybouncer` crate.

use thiserror::Error;

/// Core error type representing all failure modes within `skybouncer`.
#[derive(Debug, Error)]
pub enum SkybouncerError {
    /// Failure during Jetstream firehose ingestion or event stream processing.
    #[error("Ingestion error: {0}")]
    Ingestion(String),

    /// Failure interacting with or querying the embedded database.
    #[error("Database error: {0}")]
    Database(String),

    /// Failure executing classifier evaluation (e.g. Jev API or LLM).
    #[error("Classifier evaluation error: {0}")]
    Classifier(String),

    /// Failure authenticating or managing OAuth sessions.
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Failure issuing PDS repository mutations (createRecord, deleteRecord).
    #[error("PDS repository mutation error: {0}")]
    Repo(String),

    /// Failure communicating with ATProto Chat / DM service.
    #[error("Chat/DM service error: {0}")]
    Chat(String),

    /// Invalid configuration, parameter, or rule rubric.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Serialization or JSON parsing error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Underlying HTTP network transport error.
    #[error("Network HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

impl From<rusqlite::Error> for SkybouncerError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<skybase::SkybaseError> for SkybouncerError {
    fn from(err: skybase::SkybaseError) -> Self {
        use skybase::SkybaseError;
        match err {
            SkybaseError::Chat(msg) => Self::Chat(msg),
            SkybaseError::Repo(msg) => Self::Repo(msg),
            SkybaseError::Config(msg) => Self::Config(msg),
            SkybaseError::Auth(e) => Self::Auth(e.to_string()),
            SkybaseError::Index(msg) => Self::Database(msg),
            SkybaseError::Storage(msg) => Self::Database(msg),
            SkybaseError::Event(msg) => Self::Ingestion(msg),
            SkybaseError::Network(e) => Self::Http(e),
            SkybaseError::Serialization(e) => Self::Serialization(e),
            SkybaseError::Internal(msg) => Self::Config(msg),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use skybase::SkybaseError;

    #[test]
    fn rusqlite_error_maps_to_database() {
        let err = SkybouncerError::from(rusqlite::Error::ExecuteReturnedResults);
        assert!(matches!(err, SkybouncerError::Database(_)));
    }

    #[test]
    fn skybase_variant_mapping_preserves_messages() {
        assert!(matches!(
            SkybouncerError::from(SkybaseError::Chat("c".into())),
            SkybouncerError::Chat(m) if m == "c"
        ));
        assert!(matches!(
            SkybouncerError::from(SkybaseError::Repo("r".into())),
            SkybouncerError::Repo(m) if m == "r"
        ));
        assert!(matches!(
            SkybouncerError::from(SkybaseError::Config("cfg".into())),
            SkybouncerError::Config(m) if m == "cfg"
        ));
        assert!(matches!(
            SkybouncerError::from(SkybaseError::Index("i".into())),
            SkybouncerError::Database(m) if m == "i"
        ));
        assert!(matches!(
            SkybouncerError::from(SkybaseError::Storage("s".into())),
            SkybouncerError::Database(m) if m == "s"
        ));
        assert!(matches!(
            SkybouncerError::from(SkybaseError::Event("e".into())),
            SkybouncerError::Ingestion(m) if m == "e"
        ));
        assert!(matches!(
            SkybouncerError::from(SkybaseError::Internal("int".into())),
            SkybouncerError::Config(m) if m == "int"
        ));
    }

    #[test]
    fn skybase_serialization_error_maps_to_serialization() {
        let serde_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let err = SkybouncerError::from(SkybaseError::Serialization(serde_err));
        assert!(matches!(err, SkybouncerError::Serialization(_)));
    }

    #[test]
    fn skybase_auth_error_maps_to_auth_string() {
        let oauth_err = skyauth::error::AtprotoOAuthError::Crypto(
            skyauth::error::CryptoError::InvalidKey("bad".into()),
        );
        let err = SkybouncerError::from(SkybaseError::Auth(oauth_err));
        match err {
            SkybouncerError::Auth(msg) => assert!(msg.contains("bad")),
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[test]
    fn display_prefixes_are_stable() {
        assert_eq!(
            SkybouncerError::Ingestion("x".into()).to_string(),
            "Ingestion error: x"
        );
        assert_eq!(
            SkybouncerError::Database("x".into()).to_string(),
            "Database error: x"
        );
        assert_eq!(
            SkybouncerError::Classifier("x".into()).to_string(),
            "Classifier evaluation error: x"
        );
        assert_eq!(
            SkybouncerError::Auth("x".into()).to_string(),
            "Authentication error: x"
        );
        assert_eq!(
            SkybouncerError::Repo("x".into()).to_string(),
            "PDS repository mutation error: x"
        );
        assert_eq!(
            SkybouncerError::Chat("x".into()).to_string(),
            "Chat/DM service error: x"
        );
        assert_eq!(
            SkybouncerError::Config("x".into()).to_string(),
            "Configuration error: x"
        );
    }
}
