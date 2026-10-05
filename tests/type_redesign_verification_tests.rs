//! Challenger 2: Empirical Verification & Adversarial Stress Suite for Section 5 Type Redesign Proposals.
//!
//! Validates compile-time invariants, zero panics, typed errors, and edge case resilience
//! for all 4 proposals in `docs/ONTOLOGY_REVIEW.md`:
//! - Proposal 1: Validated Protocol Newtypes (`AtDid`, `RecordKey`, `AtUri`)
//! - Proposal 2: Pipeline Typestate Pattern (`Interaction<Stage>`, `InteractionVector`, `AttachedImage`)
//! - Proposal 3: Sovereign Multi-Tenant State Machine (`SovereignTenant`, `TenantLifecycle`)
//! - Proposal 4: Structured Error Hierarchy & Bounded Invariant Types (`Confidence`, `SkybouncerError`)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unused_imports
)]

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use proptest::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use skyauth::session::OAuthSession;
use skybase::repo::PdsRepoClient;
use skybouncer::classifier::{RuleRubric, Sensitivity, Verdict, ViolationCategory};
use skybouncer::error::SkybouncerError;
use skybouncer::matcher::BypassReason;

// =============================================================================
// PROPOSAL 1 IMPLEMENTATION (From Section 5.1)
// =============================================================================

/// Validated ATProto Decentralized Identifier (`did:plc:...`, `did:web:...`).
/// Invariant: Must begin with `did:` and contain at least 2 colon-separated segments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AtDid(String);

impl AtDid {
    /// Validates and constructs an [`AtDid`].
    pub fn parse(s: impl AsRef<str>) -> Result<Self, SkybouncerError> {
        let s_ref = s.as_ref().trim();
        if !s_ref.starts_with("did:") {
            return Err(SkybouncerError::Config(format!(
                "Invalid DID '{s_ref}': must begin with 'did:'"
            )));
        }
        let parts: Vec<&str> = s_ref.split(':').collect();
        if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
            return Err(SkybouncerError::Config(format!(
                "Invalid DID '{s_ref}': must contain method and identifier (did:method:id)"
            )));
        }
        if s_ref.len() > 2048 || s_ref.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err(SkybouncerError::Config(format!(
                "Invalid DID '{s_ref}': illegal characters or exceeds length limit"
            )));
        }
        Ok(Self(s_ref.to_string()))
    }

    /// Returns a borrowed string slice of the canonical DID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the DID method segment (e.g. "plc" or "web").
    #[must_use]
    pub fn method(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or("unknown")
    }
}

impl Deref for AtDid {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for AtDid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for AtDid {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AtDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for AtDid {
    type Err = SkybouncerError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for AtDid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AtDid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Validated ATProto record key (`rkey`).
/// Invariant: 1 to 512 characters matching `[a-zA-Z0-9_.~-]`. Cannot be '.' or '..'.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey(String);

impl RecordKey {
    /// Validates and constructs a [`RecordKey`].
    pub fn parse(s: impl AsRef<str>) -> Result<Self, SkybouncerError> {
        let s_ref = s.as_ref().trim();
        if s_ref.is_empty() || s_ref.len() > 512 {
            return Err(SkybouncerError::Config(
                "Record key length must be between 1 and 512 characters".to_string(),
            ));
        }
        if s_ref == "." || s_ref == ".." {
            return Err(SkybouncerError::Config(
                "Record key cannot be '.' or '..'".to_string(),
            ));
        }
        let valid = s_ref
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '~' || c == '-');
        if !valid {
            return Err(SkybouncerError::Config(format!(
                "Invalid record key '{s_ref}': illegal characters"
            )));
        }
        Ok(Self(s_ref.to_string()))
    }

    /// Returns a borrowed string slice of the record key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for RecordKey {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for RecordKey {
    type Err = SkybouncerError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for RecordKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RecordKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Strongly-typed canonical AT-URI (`at://{authority}/{collection}/{rkey}`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AtUri {
    authority: AtDid,
    collection: String,
    rkey: RecordKey,
    canonical: String,
}

impl AtUri {
    /// Constructs a strongly-typed [`AtUri`].
    #[must_use]
    pub fn new(authority: AtDid, collection: impl Into<String>, rkey: RecordKey) -> Self {
        let coll = collection.into();
        let canonical = format!("at://{}/{}/{}", authority.as_str(), coll, rkey.as_str());
        Self {
            authority,
            collection: coll,
            rkey,
            canonical,
        }
    }

    /// Parses a canonical AT-URI string.
    pub fn parse(uri: impl AsRef<str>) -> Result<Self, SkybouncerError> {
        let raw = uri.as_ref().trim();
        let stripped = raw.strip_prefix("at://").ok_or_else(|| {
            SkybouncerError::Config(format!("AT-URI '{raw}' must start with 'at://'"))
        })?;

        let mut parts = stripped.split('/');
        let authority_str = parts
            .next()
            .ok_or_else(|| SkybouncerError::Config(format!("AT-URI '{raw}' missing authority")))?;
        let collection = parts
            .next()
            .ok_or_else(|| SkybouncerError::Config(format!("AT-URI '{raw}' missing collection")))?;
        let rkey_str = parts
            .next()
            .ok_or_else(|| SkybouncerError::Config(format!("AT-URI '{raw}' missing record key")))?;

        if parts.next().is_some() {
            return Err(SkybouncerError::Config(format!(
                "AT-URI '{raw}' contains unexpected trailing segments"
            )));
        }

        let authority = AtDid::parse(authority_str)?;
        let rkey = RecordKey::parse(rkey_str)?;

        Ok(Self::new(authority, collection, rkey))
    }

    /// Returns the authority DID.
    #[must_use]
    pub fn authority(&self) -> &AtDid {
        &self.authority
    }

    /// Returns the collection NSID.
    #[must_use]
    pub fn collection(&self) -> &str {
        &self.collection
    }

    /// Returns the record key.
    #[must_use]
    pub fn rkey(&self) -> &RecordKey {
        &self.rkey
    }

    /// Returns the canonical string representation (`at://did:plc:.../coll/rkey`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl Deref for AtUri {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AtUri {
    type Err = SkybouncerError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for AtUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AtUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// =============================================================================
// PROPOSAL 2 IMPLEMENTATION (From Section 5.2)
// =============================================================================

/// Interaction vector variants guaranteeing required reference URIs exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InteractionVector {
    /// Direct reply to a post. Must have parent URI and thread root URI.
    DirectReply { parent: AtUri, root: AtUri },
    /// Reply deeper in a thread where immediate parent is not the protected user,
    /// but the thread root was authored by the protected user.
    ThreadReply { parent: AtUri, root: AtUri },
    /// Explicit user mention in richtext facets.
    Mention,
    /// Quote post embedding a protected user's post.
    Quote { quoted_post: AtUri },
}

/// Attached image with guaranteed paired CID and alt text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttachedImage {
    pub cid: String,
    pub alt: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ungated;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gated;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluated;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionableViolation;

#[derive(Debug, Clone)]
pub struct Interaction<Stage> {
    post_uri: AtUri,
    post_cid: Option<String>,
    author_did: AtDid,
    target_did: AtDid,
    text: String,
    vector: InteractionVector,
    created_at_us: u64,
    images: Vec<AttachedImage>,
    _stage: PhantomData<Stage>,
}

impl Interaction<Ungated> {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_ungated(
        post_uri: AtUri,
        post_cid: Option<String>,
        author_did: AtDid,
        target_did: AtDid,
        text: String,
        vector: InteractionVector,
        created_at_us: u64,
        images: Vec<AttachedImage>,
    ) -> Self {
        Self {
            post_uri,
            post_cid,
            author_did,
            target_did,
            text,
            vector,
            created_at_us,
            images,
            _stage: PhantomData,
        }
    }

    #[must_use]
    pub fn is_self_interaction(&self) -> bool {
        self.author_did == self.target_did
    }
}

impl<Stage> Interaction<Stage> {
    #[must_use]
    pub fn author_did(&self) -> &AtDid {
        &self.author_did
    }

    #[must_use]
    pub fn target_did(&self) -> &AtDid {
        &self.target_did
    }

    #[must_use]
    pub fn post_uri(&self) -> &AtUri {
        &self.post_uri
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn vector(&self) -> &InteractionVector {
        &self.vector
    }

    #[must_use]
    pub fn images(&self) -> &[AttachedImage] {
        &self.images
    }

    #[must_use]
    pub fn created_at_us(&self) -> u64 {
        self.created_at_us
    }
}

pub enum TypeSafeGateDecision {
    Candidate(Interaction<Gated>),
    Bypassed {
        reason: BypassReason,
        interaction: Interaction<Ungated>,
    },
}

#[async_trait::async_trait]
pub trait TypeSafeClassifier: Send + Sync {
    async fn classify(&self, candidate: &Interaction<Gated>) -> Result<Verdict, SkybouncerError>;
}

pub struct EvaluatedInteraction {
    pub interaction: Interaction<Evaluated>,
    pub verdict: Verdict,
}

impl Interaction<Gated> {
    #[must_use]
    pub fn with_verdict(self, verdict: Verdict) -> EvaluatedInteraction {
        let interaction = Interaction {
            post_uri: self.post_uri,
            post_cid: self.post_cid,
            author_did: self.author_did,
            target_did: self.target_did,
            text: self.text,
            vector: self.vector,
            created_at_us: self.created_at_us,
            images: self.images,
            _stage: PhantomData,
        };
        EvaluatedInteraction {
            interaction,
            verdict,
        }
    }
}

pub struct ConfirmedViolation {
    pub interaction: Interaction<ActionableViolation>,
    pub category: ViolationCategory,
    pub confidence: f64,
    pub reason: String,
}

impl EvaluatedInteraction {
    #[must_use]
    pub fn filter_actionable(self, rubric: &RuleRubric) -> Option<ConfirmedViolation> {
        match self.verdict {
            Verdict::Violation {
                category,
                confidence,
                reason,
            } => {
                if rubric.meets_threshold(&category, confidence) {
                    Some(ConfirmedViolation {
                        interaction: Interaction {
                            post_uri: self.interaction.post_uri,
                            post_cid: self.interaction.post_cid,
                            author_did: self.interaction.author_did,
                            target_did: self.interaction.target_did,
                            text: self.interaction.text,
                            vector: self.interaction.vector,
                            created_at_us: self.interaction.created_at_us,
                            images: self.interaction.images,
                            _stage: PhantomData,
                        },
                        category,
                        confidence,
                        reason,
                    })
                } else {
                    None
                }
            }
            Verdict::Permitted { .. } => None,
        }
    }
}

// =============================================================================
// PROPOSAL 3 IMPLEMENTATION (From Section 5.3)
// =============================================================================

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    inner: OAuthSession,
}

impl AuthenticatedSession {
    pub fn new(session: OAuthSession) -> Result<Self, SkybouncerError> {
        if session.is_expired() && session.refresh_token().is_none() {
            return Err(SkybouncerError::Auth(
                "Cannot construct AuthenticatedSession: token is expired and has no refresh token"
                    .to_string(),
            ));
        }
        Ok(Self { inner: session })
    }

    #[must_use]
    pub fn is_fresh(&self) -> bool {
        !self.inner.is_expired_with_leeway(Duration::from_secs(60))
    }

    #[must_use]
    pub fn session(&self) -> &OAuthSession {
        &self.inner
    }

    pub fn session_mut(&mut self) -> &mut OAuthSession {
        &mut self.inner
    }
}

#[derive(Debug, Clone)]
pub enum TenantLifecycle {
    EnrolledAwaitingAuth {
        handle: Option<String>,
        registered_at: u64,
    },
    Active {
        session: AuthenticatedSession,
        rubric: RuleRubric,
    },
    Paused {
        session: AuthenticatedSession,
        rubric: RuleRubric,
        paused_at: u64,
    },
    AuthenticationExpired {
        last_session: OAuthSession,
        rubric: RuleRubric,
        failed_at: u64,
    },
    Revoked {
        revoked_at: u64,
    },
}

#[derive(Debug, Clone)]
pub struct SovereignTenant {
    did: AtDid,
    handle: Option<String>,
    lifecycle: TenantLifecycle,
    created_at: u64,
    updated_at: u64,
}

impl SovereignTenant {
    #[must_use]
    pub fn new_onboarding(did: AtDid, handle: Option<String>, now_us: u64) -> Self {
        Self {
            did,
            handle: handle.clone(),
            lifecycle: TenantLifecycle::EnrolledAwaitingAuth {
                handle,
                registered_at: now_us,
            },
            created_at: now_us,
            updated_at: now_us,
        }
    }

    #[must_use]
    pub fn did(&self) -> &AtDid {
        &self.did
    }

    #[must_use]
    pub fn handle(&self) -> Option<&str> {
        self.handle.as_deref()
    }

    #[must_use]
    pub fn lifecycle(&self) -> &TenantLifecycle {
        &self.lifecycle
    }

    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    #[must_use]
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    pub fn activate(&mut self, session: AuthenticatedSession, rubric: RuleRubric, now_us: u64) {
        self.lifecycle = TenantLifecycle::Active { session, rubric };
        self.updated_at = now_us;
    }

    pub fn pause(&mut self, now_us: u64) -> Result<(), SkybouncerError> {
        match std::mem::replace(
            &mut self.lifecycle,
            TenantLifecycle::Revoked { revoked_at: now_us },
        ) {
            TenantLifecycle::Active { session, rubric } => {
                self.lifecycle = TenantLifecycle::Paused {
                    session,
                    rubric,
                    paused_at: now_us,
                };
                self.updated_at = now_us;
                Ok(())
            }
            other => {
                self.lifecycle = other;
                Err(SkybouncerError::Config(
                    "Only Active tenants can be paused".to_string(),
                ))
            }
        }
    }

    pub fn resume(&mut self, now_us: u64) -> Result<(), SkybouncerError> {
        match std::mem::replace(
            &mut self.lifecycle,
            TenantLifecycle::Revoked { revoked_at: now_us },
        ) {
            TenantLifecycle::Paused {
                session, rubric, ..
            } => {
                self.lifecycle = TenantLifecycle::Active { session, rubric };
                self.updated_at = now_us;
                Ok(())
            }
            other => {
                self.lifecycle = other;
                Err(SkybouncerError::Config(
                    "Only Paused tenants can be resumed".to_string(),
                ))
            }
        }
    }

    pub fn resolve_pds_client(
        &self,
        oauth_client: Option<&Arc<skyauth::client::AtprotoOAuthClient>>,
    ) -> Result<Arc<PdsRepoClient>, SkybouncerError> {
        let auth_session = match &self.lifecycle {
            TenantLifecycle::Active { session, .. } | TenantLifecycle::Paused { session, .. } => {
                session
            }
            TenantLifecycle::EnrolledAwaitingAuth { .. } => {
                return Err(SkybouncerError::Auth(format!(
                    "Tenant {} is awaiting OAuth authorization; cannot mutate PDS",
                    self.did
                )));
            }
            TenantLifecycle::AuthenticationExpired { .. } => {
                return Err(SkybouncerError::Auth(format!(
                    "Tenant {} session has expired; re-authorization required",
                    self.did
                )));
            }
            TenantLifecycle::Revoked { .. } => {
                return Err(SkybouncerError::Auth(format!(
                    "Tenant {} has revoked access; cannot mutate PDS",
                    self.did
                )));
            }
        };

        let session_arc = Arc::new(auth_session.session().clone());
        let client = match oauth_client {
            Some(oc) => PdsRepoClient::new(session_arc, Arc::clone(oc)).map_err(|e| {
                SkybouncerError::Config(format!(
                    "Failed to create PdsRepoClient with OAuthClient for {}: {e}",
                    self.did
                ))
            })?,
            None => PdsRepoClient::from_session(session_arc).map_err(|e| {
                SkybouncerError::Config(format!(
                    "Failed to create PdsRepoClient from session for {}: {e}",
                    self.did
                ))
            })?,
        };

        Ok(Arc::new(client))
    }
}

// =============================================================================
// PROPOSAL 4 IMPLEMENTATION (From Section 5.4)
// =============================================================================

/// Normalized confidence score strictly bounded in `[0.0, 1.0]`.
/// Invariant: Cannot be NaN, negative, or greater than 1.0.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Confidence(f64);

impl Confidence {
    pub fn new(val: f64) -> Result<Self, SkybouncerError> {
        if val.is_nan() || !(0.0..=1.0).contains(&val) {
            return Err(SkybouncerError::Config(format!(
                "Confidence score must be finite and between 0.0 and 1.0, got: {val}"
            )));
        }
        Ok(Self(val))
    }

    #[must_use]
    pub fn clamped(val: f64) -> Self {
        if val.is_nan() {
            Self(0.0)
        } else {
            Self(val.clamp(0.0, 1.0))
        }
    }

    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

impl Serialize for Confidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = f64::deserialize(deserializer)?;
        Self::new(val).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Malformed DID: {0}")]
    InvalidDid(String),

    #[error("Malformed AT-URI: {0}")]
    InvalidAtUri(String),

    #[error("Malformed Record Key: {0}")]
    InvalidRecordKey(String),

    #[error("Unexpected collection: expected {expected}, found {found}")]
    CollectionMismatch { expected: String, found: String },
}

#[derive(Debug, Error)]
pub enum TenantError {
    #[error("Tenant '{0}' not found in registry")]
    NotFound(AtDid),

    #[error("Tenant '{0}' is awaiting authorization")]
    Unauthenticated(AtDid),

    #[error("Tenant '{0}' OAuth session has expired")]
    SessionExpired(AtDid),

    #[error(
        "Cross-tenant boundary violation: requested {requested}, authenticated as {authenticated}"
    )]
    IsolationViolation {
        requested: AtDid,
        authenticated: AtDid,
    },
}

#[derive(Debug, Error)]
pub enum ClassifierError {
    #[error("Classifier request timed out after {0:?}")]
    Timeout(Duration),

    #[error("Upstream model HTTP error: status {status}, message: {message}")]
    UpstreamHttp { status: u16, message: String },

    #[error("Model response could not be parsed: {0}")]
    ParseError(String),

    #[error("Tier-4 rate limit exceeded for user '{did}'; retry after {retry_after:?}")]
    RateLimited { did: AtDid, retry_after: Duration },
}

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("PDS mutation rejected with status {status}: {message}")]
    MutationRejected { status: u16, message: String },

    #[error("PDS DPoP nonce challenge retry failed")]
    DPoPNonceFailure,

    #[error("Repository record not found: {0}")]
    RecordNotFound(String),
}

// =============================================================================
// EMPIRICAL TESTS & ADVERSARIAL CHALLENGE SUITE
// =============================================================================

#[test]
fn test_at_did_valid_constructors_and_methods() {
    let plc = AtDid::parse("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
    assert_eq!(plc.as_str(), "did:plc:z72i7hdynmk6r22z27h6tvur");
    assert_eq!(plc.method(), "plc");
    assert_eq!(&*plc, "did:plc:z72i7hdynmk6r22z27h6tvur");
    assert_eq!(plc.to_string(), "did:plc:z72i7hdynmk6r22z27h6tvur");

    let web = AtDid::parse("did:web:api.bsky.chat").unwrap();
    assert_eq!(web.method(), "web");

    let custom = AtDid::parse("did:key:zQ3shokFTS3vFcHc").unwrap();
    assert_eq!(custom.method(), "key");

    // Borrow<str> test with HashMap lookup
    let mut map = HashMap::new();
    map.insert(plc.clone(), 42);
    assert_eq!(map.get("did:plc:z72i7hdynmk6r22z27h6tvur"), Some(&42));
    assert_eq!(map.get("did:web:api.bsky.chat"), None);
}

#[test]
fn test_at_did_invalid_edge_cases() {
    let invalid_cases = [
        "",
        "not_a_did",
        "did:",
        "did:plc",
        "did::123",
        "did:plc:",
        "did:plc: ",
        "did:plc:123\n456",
        "did:plc:123\t456",
        "did:plc:123\x00456",
        "  ",
    ];

    for case in invalid_cases {
        assert!(
            AtDid::parse(case).is_err(),
            "Expected DID rejection for: {case:?}"
        );
    }

    // Exceeds 2048 chars
    let huge = format!("did:plc:{}", "a".repeat(2045));
    assert!(AtDid::parse(huge).is_err());
}

#[test]
fn test_at_did_serde_json_roundtrip() {
    let did = AtDid::parse("did:plc:alice").unwrap();
    let json_str = serde_json::to_string(&did).unwrap();
    assert_eq!(json_str, "\"did:plc:alice\"");

    let deserialized: AtDid = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized, did);

    let err: Result<AtDid, _> = serde_json::from_str("\"invalid_did\"");
    assert!(err.is_err());
}

#[test]
fn test_record_key_valid_and_invalid() {
    assert!(RecordKey::parse("self").is_ok());
    assert!(RecordKey::parse("3k234234").is_ok());
    assert!(RecordKey::parse("valid.key_123~-").is_ok());

    // Invalid edge cases
    assert!(RecordKey::parse("").is_err());
    assert!(RecordKey::parse(".").is_err());
    assert!(RecordKey::parse("..").is_err());
    assert!(RecordKey::parse("invalid/char").is_err());
    assert!(RecordKey::parse("invalid@char").is_err());
    assert!(RecordKey::parse("invalid char").is_err());
    assert!(RecordKey::parse("a".repeat(513)).is_err());

    let rkey = RecordKey::parse("valid-key").unwrap();
    assert_eq!(&*rkey, "valid-key");
    assert_eq!(rkey.as_str(), "valid-key");
    assert_eq!(rkey.to_string(), "valid-key");

    // Serde roundtrip
    let json_str = serde_json::to_string(&rkey).unwrap();
    assert_eq!(json_str, "\"valid-key\"");
    let deserialized: RecordKey = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized, rkey);
}

#[test]
fn test_at_uri_valid_and_invalid() {
    let uri_str = "at://did:plc:alice/app.bsky.feed.post/3k234234";
    let uri = AtUri::parse(uri_str).unwrap();

    assert_eq!(uri.authority().as_str(), "did:plc:alice");
    assert_eq!(uri.collection(), "app.bsky.feed.post");
    assert_eq!(uri.rkey().as_str(), "3k234234");
    assert_eq!(uri.as_str(), uri_str);
    assert_eq!(&*uri, uri_str);
    assert_eq!(uri.to_string(), uri_str);

    // Serde roundtrip
    let json_str = serde_json::to_string(&uri).unwrap();
    let deserialized: AtUri = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized, uri);

    // Invalid cases
    assert!(AtUri::parse("https://bsky.app/profile/alice/post/123").is_err());
    assert!(AtUri::parse("at://did:plc:alice").is_err());
    assert!(AtUri::parse("at://did:plc:alice/app.bsky.feed.post").is_err());
    assert!(AtUri::parse("at://did:plc:alice/app.bsky.feed.post/3k/extra").is_err());
    assert!(AtUri::parse("at://not_a_did/app.bsky.feed.post/3k").is_err());
    assert!(AtUri::parse("at://did:plc:alice/app.bsky.feed.post/.").is_err());
}

#[tokio::test]
async fn test_pipeline_typestate_compile_and_transition_invariants() {
    let author_did = AtDid::parse("did:plc:author").unwrap();
    let target_did = AtDid::parse("did:plc:target").unwrap();
    let post_uri = AtUri::parse("at://did:plc:author/app.bsky.feed.post/123").unwrap();
    let parent_uri = AtUri::parse("at://did:plc:target/app.bsky.feed.post/root1").unwrap();

    let ungated = Interaction::new_ungated(
        post_uri.clone(),
        Some("cid123".to_string()),
        author_did.clone(),
        target_did.clone(),
        "Hello target!".to_string(),
        InteractionVector::DirectReply {
            parent: parent_uri.clone(),
            root: parent_uri.clone(),
        },
        1_000_000,
        vec![AttachedImage {
            cid: "bafkreibxyz".to_string(),
            alt: "A diagram".to_string(),
        }],
    );

    assert!(!ungated.is_self_interaction());
    assert_eq!(ungated.author_did().as_str(), "did:plc:author");
    assert_eq!(ungated.images().len(), 1);
    assert_eq!(ungated.images()[0].alt, "A diagram");

    // Pass through gate to promote to Interaction<Gated>
    let gated: Interaction<Gated> = Interaction {
        post_uri: ungated.post_uri.clone(),
        post_cid: ungated.post_cid.clone(),
        author_did: ungated.author_did.clone(),
        target_did: ungated.target_did.clone(),
        text: ungated.text.clone(),
        vector: ungated.vector.clone(),
        created_at_us: ungated.created_at_us,
        images: ungated.images.clone(),
        _stage: PhantomData,
    };

    // Mock classifier implementing TypeSafeClassifier
    struct MockTypeSafeClassifier;
    #[async_trait::async_trait]
    impl TypeSafeClassifier for MockTypeSafeClassifier {
        async fn classify(
            &self,
            candidate: &Interaction<Gated>,
        ) -> Result<Verdict, SkybouncerError> {
            Ok(Verdict::Violation {
                category: ViolationCategory::Spam,
                confidence: 0.95,
                reason: format!("Spam detected in: {}", candidate.text()),
            })
        }
    }

    let classifier = MockTypeSafeClassifier;
    let verdict = classifier.classify(&gated).await.unwrap();

    // Transition to Evaluated
    let evaluated = gated.with_verdict(verdict);
    assert_eq!(
        evaluated.interaction.author_did().as_str(),
        "did:plc:author"
    );

    // Filter actionable against rubric
    let rubric = RuleRubric {
        prompt: "Block spam".to_string(),
        sensitivity: Sensitivity::Medium, // 0.75 threshold
        bounce_duration: skybouncer::classifier::BounceDuration::Permanent,
        bypass_incoming_followers: true,
    };

    let actionable = evaluated.filter_actionable(&rubric);
    assert!(actionable.is_some());
    let confirmed = actionable.unwrap();
    assert_eq!(confirmed.category, ViolationCategory::Spam);
    assert_eq!(confirmed.confidence, 0.95);
    assert_eq!(
        confirmed.interaction.author_did().as_str(),
        "did:plc:author"
    );

    // Below threshold test
    let gated_low: Interaction<Gated> = Interaction {
        post_uri,
        post_cid: None,
        author_did,
        target_did,
        text: "Low confidence".to_string(),
        vector: InteractionVector::Mention,
        created_at_us: 1_000_000,
        images: vec![],
        _stage: PhantomData,
    };

    let low_verdict = Verdict::Violation {
        category: ViolationCategory::Spam,
        confidence: 0.50, // below 0.75
        reason: "Maybe spam".to_string(),
    };

    let evaluated_low = gated_low.with_verdict(low_verdict);
    let actionable_low = evaluated_low.filter_actionable(&rubric);
    assert!(actionable_low.is_none());
}

#[test]
fn test_sovereign_tenant_lifecycle_transitions() {
    let did = AtDid::parse("did:plc:tenant1").unwrap();
    let mut tenant =
        SovereignTenant::new_onboarding(did.clone(), Some("alice.bsky.social".to_string()), 100);

    assert_eq!(tenant.did().as_str(), "did:plc:tenant1");
    assert_eq!(tenant.handle(), Some("alice.bsky.social"));

    // In EnrolledAwaitingAuth, resolve_pds_client MUST fail
    match tenant.resolve_pds_client(None) {
        Err(SkybouncerError::Auth(msg)) => assert!(msg.contains("awaiting OAuth authorization")),
        Err(other) => panic!("Unexpected error variant: {other:?}"),
        Ok(_) => panic!("Expected error in EnrolledAwaitingAuth, but got Ok"),
    }

    // Attempting to pause in EnrolledAwaitingAuth fails
    assert!(tenant.pause(150).is_err());

    // Create a mock active session
    let dpop_key = skyauth::dpop::DPoPKey::generate();
    let oauth_session = OAuthSession::new(
        "did:plc:tenant1",
        "access_token_123",
        Some("refresh_token_456".to_string()),
        "DPoP",
        Some("atproto transition:generic".to_string()),
        Some(3600),
        dpop_key,
        Some("https://pds.example.com".to_string()),
        None,
        None,
    )
    .unwrap();

    let auth_session = AuthenticatedSession::new(oauth_session).unwrap();
    assert!(auth_session.is_fresh());

    let rubric = RuleRubric {
        prompt: "No spam".to_string(),
        sensitivity: Sensitivity::Medium,
        bounce_duration: skybouncer::classifier::BounceDuration::Permanent,
        bypass_incoming_followers: true,
    };

    // Activate tenant
    tenant.activate(auth_session, rubric, 200);
    assert!(matches!(tenant.lifecycle(), TenantLifecycle::Active { .. }));

    // In Active, client resolution succeeds
    let client_res = tenant.resolve_pds_client(None);
    assert!(client_res.is_ok());

    // Pause tenant
    tenant.pause(300).unwrap();
    assert!(matches!(tenant.lifecycle(), TenantLifecycle::Paused { .. }));

    // Cannot pause already paused tenant
    assert!(tenant.pause(350).is_err());

    // Resume tenant
    tenant.resume(400).unwrap();
    assert!(matches!(tenant.lifecycle(), TenantLifecycle::Active { .. }));

    // Cannot resume already active tenant
    assert!(tenant.resume(450).is_err());
}

#[test]
fn test_confidence_bounded_invariants() {
    // Valid values
    assert!(Confidence::new(0.0).is_ok());
    assert!(Confidence::new(0.5).is_ok());
    assert!(Confidence::new(1.0).is_ok());

    let c = Confidence::new(0.754).unwrap();
    assert_eq!(c.get(), 0.754);
    assert_eq!(c.to_string(), "0.75");

    // Out of bounds / NaN rejected
    assert!(Confidence::new(-0.0001).is_err());
    assert!(Confidence::new(1.0001).is_err());
    assert!(Confidence::new(f64::NAN).is_err());
    assert!(Confidence::new(f64::INFINITY).is_err());
    assert!(Confidence::new(f64::NEG_INFINITY).is_err());

    // Clamped behavior
    assert_eq!(Confidence::clamped(-10.0).get(), 0.0);
    assert_eq!(Confidence::clamped(10.0).get(), 1.0);
    assert_eq!(Confidence::clamped(f64::NAN).get(), 0.0);
    assert_eq!(Confidence::clamped(0.42).get(), 0.42);

    // Serde roundtrip
    let json_str = serde_json::to_string(&c).unwrap();
    assert_eq!(json_str, "0.754");
    let deserialized: Confidence = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized, c);

    // Serde deserialization rejects invalid values
    assert!(serde_json::from_str::<Confidence>("-0.5").is_err());
    assert!(serde_json::from_str::<Confidence>("1.5").is_err());
    assert!(serde_json::from_str::<Confidence>("\"not_a_num\"").is_err());
}

#[test]
fn test_structured_error_sub_enums_and_display() {
    let did = AtDid::parse("did:plc:alice").unwrap();

    let proto_err = ProtocolError::InvalidDid("malformed_did".to_string());
    assert_eq!(proto_err.to_string(), "Malformed DID: malformed_did");

    let tenant_err = TenantError::NotFound(did.clone());
    assert_eq!(
        tenant_err.to_string(),
        "Tenant 'did:plc:alice' not found in registry"
    );

    let classifier_err = ClassifierError::Timeout(Duration::from_millis(500));
    assert_eq!(
        classifier_err.to_string(),
        "Classifier request timed out after 500ms"
    );

    let repo_err = RepoError::MutationRejected {
        status: 400,
        message: "Bad record".to_string(),
    };
    assert_eq!(
        repo_err.to_string(),
        "PDS mutation rejected with status 400: Bad record"
    );
}

// =============================================================================
// ADVERSARIAL CHALLENGE FINDINGS & BUG REPRODUCTIONS
// =============================================================================

/// CHALLENGE FINDING 1:
/// `AtUri::parse` accepts empty collection segments (`at://did:plc:alice//rkey`),
/// which violates ATProto NSID specification.
#[test]
fn test_adversarial_at_uri_empty_collection_gap() {
    let malformed_double_slash = "at://did:plc:alice//3k234";
    let parsed = AtUri::parse(malformed_double_slash);

    // VULNERABILITY REPRODUCTION:
    // In Proposal 1 as written in docs/ONTOLOGY_REVIEW.md:1186,
    // this malformed URI is accepted because `parts.next()` returns `Some("")`,
    // and no non-empty check is performed on collection!
    assert!(
        parsed.is_ok(),
        "Empirical proof: Proposal 1 AtUri::parse accepts empty collection string"
    );
    let uri = parsed.unwrap();
    assert_eq!(uri.collection(), "");
    assert_eq!(uri.as_str(), "at://did:plc:alice//3k234");
}

/// CHALLENGE FINDING 2:
/// `Interaction<Stage>` private fields prevent cross-module typestate transitions.
/// If `Interaction<Stage>` fields are private and no `into_gated` method exists,
/// `NonFollowedGate` in `src/matcher/gate.rs` cannot construct `Interaction<Gated>`.
mod gate_module_boundary_simulation {
    use super::*;

    pub struct SimulatedGate;

    impl SimulatedGate {
        // To construct Interaction<Gated>, either the struct fields must be `pub(crate)`
        // or a dedicated transition method must be provided on `Interaction<Ungated>`.
        pub fn evaluate_ungated(interaction: Interaction<Ungated>) -> TypeSafeGateDecision {
            if interaction.is_self_interaction() {
                TypeSafeGateDecision::Bypassed {
                    reason: BypassReason::SelfInteraction,
                    interaction,
                }
            } else {
                // Here is the fix needed: `into_gated` method
                // Without it, private fields cannot be accessed from another module!
                TypeSafeGateDecision::Candidate(interaction.into_gated_transition())
            }
        }
    }
}

// Add the missing transition method needed by Proposal 2
impl Interaction<Ungated> {
    /// Required transition method to promote Ungated to Gated across module boundaries.
    pub fn into_gated_transition(self) -> Interaction<Gated> {
        Interaction {
            post_uri: self.post_uri,
            post_cid: self.post_cid,
            author_did: self.author_did,
            target_did: self.target_did,
            text: self.text,
            vector: self.vector,
            created_at_us: self.created_at_us,
            images: self.images,
            _stage: PhantomData,
        }
    }
}

#[test]
fn test_adversarial_module_boundary_typestate_transition() {
    let author_did = AtDid::parse("did:plc:alice").unwrap();
    let target_did = AtDid::parse("did:plc:bob").unwrap();
    let post_uri = AtUri::parse("at://did:plc:alice/app.bsky.feed.post/1").unwrap();

    let ungated = Interaction::new_ungated(
        post_uri,
        None,
        author_did,
        target_did,
        "Hello".to_string(),
        InteractionVector::Mention,
        100,
        vec![],
    );

    let decision = gate_module_boundary_simulation::SimulatedGate::evaluate_ungated(ungated);
    assert!(matches!(decision, TypeSafeGateDecision::Candidate(_)));
}

/// CHALLENGE FINDING 3:
/// `SovereignTenant::resolve_pds_client` returns `Ok(Arc<PdsRepoClient>)` even when
/// the tenant is in `TenantLifecycle::Paused`.
/// This permits PDS mutations for paused tenants unless callers remember to check `is_paused()`.
#[test]
fn test_adversarial_paused_tenant_pds_client_resolution() {
    let did = AtDid::parse("did:plc:tenant_paused").unwrap();
    let mut tenant = SovereignTenant::new_onboarding(did, None, 100);

    let dpop_key = skyauth::dpop::DPoPKey::generate();
    let oauth_session = OAuthSession::new(
        "did:plc:tenant_paused",
        "access_token_123",
        Some("refresh_token_456".to_string()),
        "DPoP",
        Some("atproto transition:generic".to_string()),
        Some(3600),
        dpop_key,
        Some("https://pds.example.com".to_string()),
        None,
        None,
    )
    .unwrap();

    let auth_session = AuthenticatedSession::new(oauth_session).unwrap();
    let rubric = RuleRubric {
        prompt: "No spam".to_string(),
        sensitivity: Sensitivity::Medium,
        bounce_duration: skybouncer::classifier::BounceDuration::Permanent,
        bypass_incoming_followers: true,
    };

    tenant.activate(auth_session, rubric, 200);
    tenant.pause(300).unwrap();

    // In Paused state, resolve_pds_client SUCCEEDS in Proposal 3!
    let client_res = tenant.resolve_pds_client(None);
    assert!(
        client_res.is_ok(),
        "Empirical proof: Proposal 3 allows Paused tenants to resolve mutable PdsRepoClient"
    );
}

/// CHALLENGE FINDING 4:
/// Confidence handles IEEE 754 negative zero `-0.0`:
/// In IEEE 754, `-0.0 < 0.0` is false, so `Confidence::new(-0.0)` succeeds.
#[test]
fn test_adversarial_confidence_negative_zero() {
    let neg_zero = -0.0f64;
    let conf = Confidence::new(neg_zero);
    assert!(conf.is_ok());
    assert_eq!(conf.unwrap().get(), 0.0);
}

// =============================================================================
// ADVERSARIAL PROPTEST GENERATORS (Stress Testing)
// =============================================================================

proptest! {
    #[test]
    fn proptest_arbitrary_strings_never_panic_at_did(s in ".*") {
        let _ = AtDid::parse(&s);
    }

    #[test]
    fn proptest_arbitrary_strings_never_panic_record_key(s in ".*") {
        let _ = RecordKey::parse(&s);
    }

    #[test]
    fn proptest_arbitrary_strings_never_panic_at_uri(s in ".*") {
        let _ = AtUri::parse(&s);
    }

    #[test]
    fn proptest_arbitrary_floats_never_panic_confidence(f in any::<f64>()) {
        let _ = Confidence::new(f);
        let clamped = Confidence::clamped(f);
        prop_assert!(clamped.get() >= 0.0);
        prop_assert!(clamped.get() <= 1.0);
        prop_assert!(!clamped.get().is_nan());
    }
}
