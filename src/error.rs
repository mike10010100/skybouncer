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
