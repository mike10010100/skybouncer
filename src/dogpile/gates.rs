//! Sovereign ATProto interaction shields (`app.bsky.feed.threadgate` and `app.bsky.feed.postgate`).
//!
//! Provides ownership-verified helpers for locking replies on a user's post and detaching
//! quote-post catalysts (or disabling quotes) on their sovereign PDS, with full `--dry-run`
//! shadow-mode support.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use skybase::repo::PdsRepoClient;
use tracing::info;

use crate::error::SkybouncerError;
use crate::types::now_iso8601;

/// ATProto collection NSID for thread reply gates.
pub const THREADGATE_COLLECTION: &str = "app.bsky.feed.threadgate";

/// ATProto collection NSID for quote/embedding gates.
pub const POSTGATE_COLLECTION: &str = "app.bsky.feed.postgate";

/// ATProto lexicon ceiling on `detachedEmbeddingUris` per `app.bsky.feed.postgate` record.
pub const MAX_DETACHED_EMBEDDING_URIS: usize = 50;

/// Reply restriction policy written into `app.bsky.feed.threadgate.allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadgatePolicy {
    /// Allow replies only from accounts the post author follows (`#followingRule`).
    #[default]
    FollowingOnly,
    /// Allow replies from accounts the author follows (`#followingRule`) or followers (`#followerRule`).
    FollowingAndFollowers,
    /// Allow replies only from accounts mentioned in the post (`#mentionRule`).
    MentionsOnly,
    /// Disable all replies (`allow: []`).
    Nobody,
}

impl ThreadgatePolicy {
    /// Returns the static string slug for this policy.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FollowingOnly => "following",
            Self::FollowingAndFollowers => "following_and_followers",
            Self::MentionsOnly => "mentions",
            Self::Nobody => "nobody",
        }
    }

    /// Returns a human-readable summary label.
    #[must_use]
    pub const fn display_label(&self) -> &'static str {
        match self {
            Self::FollowingOnly => "People you follow",
            Self::FollowingAndFollowers => "Followers & people you follow",
            Self::MentionsOnly => "Mentioned accounts only",
            Self::Nobody => "Nobody (replies locked)",
        }
    }

    /// Converts this policy into the ATProto `app.bsky.feed.threadgate.allow` rule objects.
    #[must_use]
    pub fn to_allow_rules(&self) -> Vec<serde_json::Value> {
        match self {
            Self::FollowingOnly => vec![serde_json::json!({
                "$type": "app.bsky.feed.threadgate#followingRule"
            })],
            Self::FollowingAndFollowers => vec![
                serde_json::json!({ "$type": "app.bsky.feed.threadgate#followingRule" }),
                serde_json::json!({ "$type": "app.bsky.feed.threadgate#followerRule" }),
            ],
            Self::MentionsOnly => vec![serde_json::json!({
                "$type": "app.bsky.feed.threadgate#mentionRule"
            })],
            Self::Nobody => Vec::new(),
        }
    }
}

impl fmt::Display for ThreadgatePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ThreadgatePolicy {
    type Err = SkybouncerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "following" | "following_only" | "followed" | "friends" => Ok(Self::FollowingOnly),
            "followers" | "following_and_followers" | "following+followers" | "mutuals" => {
                Ok(Self::FollowingAndFollowers)
            }
            "mentions" | "mentions_only" | "mention" => Ok(Self::MentionsOnly),
            "nobody" | "none" | "off" | "closed" | "all" => Ok(Self::Nobody),
            other => Err(SkybouncerError::Config(format!(
                "Invalid threadgate policy '{other}'; expected 'following', 'followers', 'mentions', or 'nobody'"
            ))),
        }
    }
}

/// ATProto `app.bsky.feed.threadgate` repository record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadgateRecord {
    /// Lexicon record type (`"app.bsky.feed.threadgate"`).
    #[serde(rename = "$type")]
    pub record_type: String,
    /// Canonical AT-URI of the root post governed by this threadgate.
    pub post: String,
    /// List of allow-rules (`#followingRule`, `#followerRule`, `#mentionRule`). Empty = nobody.
    #[serde(default)]
    pub allow: Vec<serde_json::Value>,
    /// ISO 8601 timestamp when the gate was created.
    pub created_at: String,
}

impl ThreadgateRecord {
    /// Constructs a new [`ThreadgateRecord`] for `post_uri` enforcing `policy`.
    #[must_use]
    pub fn new(post_uri: impl Into<String>, policy: ThreadgatePolicy) -> Self {
        Self {
            record_type: THREADGATE_COLLECTION.to_string(),
            post: post_uri.into(),
            allow: policy.to_allow_rules(),
            created_at: now_iso8601(),
        }
    }
}

/// ATProto `app.bsky.feed.postgate` repository record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostgateRecord {
    /// Lexicon record type (`"app.bsky.feed.postgate"`).
    #[serde(rename = "$type")]
    pub record_type: String,
    /// Canonical AT-URI of the post governed by this postgate.
    pub post: String,
    /// Quote/embedding rules (e.g. `app.bsky.feed.postgate#disableRule`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedding_rules: Vec<serde_json::Value>,
    /// AT-URIs of quote/embedding posts detached by the original author (max 50).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detached_embedding_uris: Vec<String>,
    /// ISO 8601 timestamp when the postgate was created.
    pub created_at: String,
}

impl PostgateRecord {
    /// Constructs a fresh [`PostgateRecord`] for `post_uri`.
    #[must_use]
    pub fn new(post_uri: impl Into<String>) -> Self {
        Self {
            record_type: POSTGATE_COLLECTION.to_string(),
            post: post_uri.into(),
            embedding_rules: Vec::new(),
            detached_embedding_uris: Vec::new(),
            created_at: now_iso8601(),
        }
    }

    /// Appends quote-post URIs to `detached_embedding_uris` without duplicates, capped at
    /// [`MAX_DETACHED_EMBEDDING_URIS`], and optionally adds `#disableRule`.
    pub fn merge_detaches<I, S>(&mut self, qt_uris: I, disable_all_quotes: bool)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for raw in qt_uris {
            let trimmed = raw.as_ref().trim();
            if !trimmed.starts_with("at://") {
                continue;
            }
            if !self.detached_embedding_uris.iter().any(|u| u == trimmed) {
                if self.detached_embedding_uris.len() >= MAX_DETACHED_EMBEDDING_URIS {
                    break;
                }
                self.detached_embedding_uris.push(trimmed.to_string());
            }
        }
        if disable_all_quotes {
            let already_disabled = self.embedding_rules.iter().any(|r| {
                r.get("$type").and_then(|v| v.as_str())
                    == Some("app.bsky.feed.postgate#disableRule")
            });
            if !already_disabled {
                self.embedding_rules.push(serde_json::json!({
                    "$type": "app.bsky.feed.postgate#disableRule"
                }));
            }
        }
    }
}

fn is_valid_rkey(rkey: &str) -> bool {
    !rkey.is_empty()
        && rkey.len() <= 512
        && rkey
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))
}

/// Parses an AT-URI, Bluesky post URL (when actor is `protected_did`), or bare `rkey`,
/// verifying strict ownership by `protected_did`.
///
/// Returns `(canonical_post_uri, rkey)`.
///
/// # Errors
/// Returns [`SkybouncerError::Config`] if the input is malformed, empty, or owned by a different DID.
pub fn parse_owned_post_uri(
    protected_did: &str,
    post_uri_or_rkey: &str,
) -> Result<(String, String), SkybouncerError> {
    let trimmed = post_uri_or_rkey.trim();
    if trimmed.is_empty() {
        return Err(SkybouncerError::Config(
            "Post URI or rkey cannot be empty".to_string(),
        ));
    }

    if let Some(rest) = trimmed.strip_prefix("at://") {
        let mut parts = rest.split('/');
        let did = parts.next().unwrap_or("");
        let collection = parts.next().unwrap_or("");
        let rkey = parts.next().unwrap_or("");
        if parts.next().is_some()
            || collection != "app.bsky.feed.post"
            || !is_valid_rkey(rkey)
            || !did.starts_with("did:")
        {
            return Err(SkybouncerError::Config(format!(
                "Invalid Bluesky post AT-URI: '{trimmed}'"
            )));
        }
        if did != protected_did {
            return Err(SkybouncerError::Config(format!(
                "Refusing gate mutation: post '{trimmed}' is owned by '{did}', not '{protected_did}'"
            )));
        }
        return Ok((
            format!("at://{protected_did}/app.bsky.feed.post/{rkey}"),
            rkey.to_string(),
        ));
    }

    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        let parsed = url::Url::parse(trimmed).map_err(|e| {
            SkybouncerError::Config(format!("Invalid Bluesky post URL '{trimmed}': {e}"))
        })?;
        let segments: Vec<&str> = parsed
            .path_segments()
            .map(|s| s.filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        // Expect /profile/{actor}/post/{rkey}
        if segments.len() == 4 && segments[0] == "profile" && segments[2] == "post" {
            let actor = segments[1];
            let rkey = segments[3];
            if !is_valid_rkey(rkey) {
                return Err(SkybouncerError::Config(format!(
                    "Invalid post rkey in URL: '{trimmed}'"
                )));
            }
            if actor.starts_with("did:") && actor != protected_did {
                return Err(SkybouncerError::Config(format!(
                    "Refusing gate mutation: post URL '{trimmed}' is owned by '{actor}', not '{protected_did}'"
                )));
            }
            if !actor.starts_with("did:") {
                return Err(SkybouncerError::Config(format!(
                    "Unresolved handle '{actor}' in post URL; resolve handle to DID first"
                )));
            }
            return Ok((
                format!("at://{protected_did}/app.bsky.feed.post/{rkey}"),
                rkey.to_string(),
            ));
        }
        return Err(SkybouncerError::Config(format!(
            "Unsupported Bluesky post URL format: '{trimmed}'"
        )));
    }

    if !is_valid_rkey(trimmed) {
        return Err(SkybouncerError::Config(format!(
            "Invalid post record key '{trimmed}'"
        )));
    }
    Ok((
        format!("at://{protected_did}/app.bsky.feed.post/{trimmed}"),
        trimmed.to_string(),
    ))
}

/// Applies or updates an `app.bsky.feed.threadgate` record on the protected user's PDS.
///
/// # Errors
/// Returns [`SkybouncerError::Config`] if ownership validation fails or [`SkybouncerError::Repo`]
/// if PDS `putRecord` fails.
pub async fn apply_threadgate(
    pds_client: &PdsRepoClient,
    protected_did: &str,
    post_uri_or_rkey: &str,
    policy: ThreadgatePolicy,
    dry_run: bool,
) -> Result<String, SkybouncerError> {
    let (canonical_post_uri, rkey) = parse_owned_post_uri(protected_did, post_uri_or_rkey)?;
    if dry_run {
        let simulated_uri = format!("at://{protected_did}/{THREADGATE_COLLECTION}/{rkey}");
        info!(
            protected_did = %protected_did,
            post_uri = %canonical_post_uri,
            policy = %policy,
            threadgate_uri = %simulated_uri,
            "🛡️ [SHADOW MODE] Simulated threadgate on sovereign PDS"
        );
        return Ok(simulated_uri);
    }

    let record = ThreadgateRecord::new(&canonical_post_uri, policy);
    let res = pds_client
        .put_record(THREADGATE_COLLECTION, &rkey, &record, true)
        .await
        .map_err(|e| SkybouncerError::Repo(format!("Failed to write threadgate on PDS: {e}")))?;

    info!(
        protected_did = %protected_did,
        post_uri = %canonical_post_uri,
        policy = %policy,
        threadgate_uri = %res.uri,
        "Applied threadgate on sovereign PDS"
    );
    Ok(res.uri)
}

/// Removes an `app.bsky.feed.threadgate` record from the protected user's PDS, reopening replies.
///
/// # Errors
/// Returns [`SkybouncerError::Config`] if ownership validation fails or [`SkybouncerError::Repo`]
/// if PDS `deleteRecord` fails.
pub async fn remove_threadgate(
    pds_client: &PdsRepoClient,
    protected_did: &str,
    post_uri_or_rkey: &str,
    dry_run: bool,
) -> Result<(), SkybouncerError> {
    let (canonical_post_uri, rkey) = parse_owned_post_uri(protected_did, post_uri_or_rkey)?;
    if dry_run {
        info!(
            protected_did = %protected_did,
            post_uri = %canonical_post_uri,
            "🛡️ [SHADOW MODE] Simulated threadgate removal on sovereign PDS"
        );
        return Ok(());
    }

    pds_client
        .delete_record(THREADGATE_COLLECTION, &rkey)
        .await
        .map_err(|e| SkybouncerError::Repo(format!("Failed to remove threadgate from PDS: {e}")))?;

    info!(
        protected_did = %protected_did,
        post_uri = %canonical_post_uri,
        "Removed threadgate from sovereign PDS"
    );
    Ok(())
}

/// Fetches any existing `app.bsky.feed.postgate` on the PDS, merges newly detached
/// quote-post URIs (up to [`MAX_DETACHED_EMBEDDING_URIS`]) and optional `#disableRule`,
/// and writes the updated record via `putRecord`.
///
/// Returns `(postgate_uri, total_detached_count)`.
///
/// # Errors
/// Returns [`SkybouncerError::Config`] if ownership validation fails or [`SkybouncerError::Repo`]
/// if PDS queries/mutations fail.
pub async fn apply_postgate_detach(
    pds_client: &PdsRepoClient,
    protected_did: &str,
    post_uri_or_rkey: &str,
    qt_uris: &[String],
    disable_all_quotes: bool,
    dry_run: bool,
) -> Result<(String, usize), SkybouncerError> {
    let (canonical_post_uri, rkey) = parse_owned_post_uri(protected_did, post_uri_or_rkey)?;
    if dry_run {
        let mut sim = PostgateRecord::new(&canonical_post_uri);
        sim.merge_detaches(qt_uris, disable_all_quotes);
        let simulated_uri = format!("at://{protected_did}/{POSTGATE_COLLECTION}/{rkey}");
        info!(
            protected_did = %protected_did,
            post_uri = %canonical_post_uri,
            detached = sim.detached_embedding_uris.len(),
            disable_all_quotes,
            postgate_uri = %simulated_uri,
            "🛡️ [SHADOW MODE] Simulated postgate detach on sovereign PDS"
        );
        return Ok((simulated_uri, sim.detached_embedding_uris.len()));
    }

    let mut record = match pds_client
        .get_record(protected_did, POSTGATE_COLLECTION, &rkey)
        .await
    {
        Ok(view) => serde_json::from_value::<PostgateRecord>(view.value)
            .unwrap_or_else(|_| PostgateRecord::new(&canonical_post_uri)),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("CouldNotFindRecord")
                || msg.contains("RecordNotFound")
                || msg.contains("Could not locate record")
                || msg.contains("404")
                || msg.contains("HTTP 400")
            {
                PostgateRecord::new(&canonical_post_uri)
            } else {
                return Err(SkybouncerError::Repo(format!(
                    "Failed to inspect existing postgate on PDS: {e}"
                )));
            }
        }
    };

    record.post = canonical_post_uri.clone();
    record.merge_detaches(qt_uris, disable_all_quotes);
    let total_detached = record.detached_embedding_uris.len();

    let res = pds_client
        .put_record(POSTGATE_COLLECTION, &rkey, &record, true)
        .await
        .map_err(|e| SkybouncerError::Repo(format!("Failed to write postgate on PDS: {e}")))?;

    info!(
        protected_did = %protected_did,
        post_uri = %canonical_post_uri,
        detached = total_detached,
        disable_all_quotes,
        postgate_uri = %res.uri,
        "Updated postgate on sovereign PDS"
    );
    Ok((res.uri, total_detached))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_owned_post_uri_enforces_ownership_and_formats() {
        let did = "did:plc:alice";
        assert_eq!(
            parse_owned_post_uri(did, "at://did:plc:alice/app.bsky.feed.post/3abc").unwrap(),
            (
                "at://did:plc:alice/app.bsky.feed.post/3abc".to_string(),
                "3abc".to_string()
            )
        );
        assert_eq!(
            parse_owned_post_uri(did, "https://bsky.app/profile/did:plc:alice/post/3abc").unwrap(),
            (
                "at://did:plc:alice/app.bsky.feed.post/3abc".to_string(),
                "3abc".to_string()
            )
        );
        assert_eq!(
            parse_owned_post_uri(did, "3abc").unwrap(),
            (
                "at://did:plc:alice/app.bsky.feed.post/3abc".to_string(),
                "3abc".to_string()
            )
        );

        // Reject foreign DID or invalid inputs
        assert!(parse_owned_post_uri(did, "at://did:plc:eve/app.bsky.feed.post/3abc").is_err());
        assert!(
            parse_owned_post_uri(did, "https://bsky.app/profile/did:plc:eve/post/3abc").is_err()
        );
        assert!(
            parse_owned_post_uri(did, "https://bsky.app/profile/alice.bsky.social/post/3abc")
                .is_err()
        );
        assert!(parse_owned_post_uri(did, "https://not a valid url").is_err());
        assert!(parse_owned_post_uri(did, "https://bsky.app/profile/did:plc:alice").is_err());
        assert!(
            parse_owned_post_uri(did, "https://bsky.app/profile/did:plc:alice/post/bad!rkey")
                .is_err()
        );
        assert!(parse_owned_post_uri(did, "at://did:plc:alice/app.bsky.graph.list/3abc").is_err());
        assert!(parse_owned_post_uri(did, "bad/rkey").is_err());
        assert!(parse_owned_post_uri(did, "   ").is_err());
    }

    #[test]
    fn threadgate_policy_parse_and_rules() {
        assert_eq!(
            "following".parse::<ThreadgatePolicy>().unwrap(),
            ThreadgatePolicy::FollowingOnly
        );
        assert_eq!(
            "followers".parse::<ThreadgatePolicy>().unwrap(),
            ThreadgatePolicy::FollowingAndFollowers
        );
        assert_eq!(
            "mentions".parse::<ThreadgatePolicy>().unwrap(),
            ThreadgatePolicy::MentionsOnly
        );
        assert_eq!(
            "nobody".parse::<ThreadgatePolicy>().unwrap(),
            ThreadgatePolicy::Nobody
        );
        assert!("bogus".parse::<ThreadgatePolicy>().is_err());

        for pol in [
            ThreadgatePolicy::FollowingOnly,
            ThreadgatePolicy::FollowingAndFollowers,
            ThreadgatePolicy::MentionsOnly,
            ThreadgatePolicy::Nobody,
        ] {
            assert!(!pol.as_str().is_empty());
            assert!(!pol.display_label().is_empty());
            assert_eq!(pol.to_string(), pol.as_str());
        }

        assert_eq!(ThreadgatePolicy::FollowingOnly.to_allow_rules().len(), 1);
        assert_eq!(
            ThreadgatePolicy::FollowingAndFollowers
                .to_allow_rules()
                .len(),
            2
        );
        assert_eq!(ThreadgatePolicy::MentionsOnly.to_allow_rules().len(), 1);
        assert!(ThreadgatePolicy::Nobody.to_allow_rules().is_empty());
    }

    #[tokio::test]
    async fn dry_run_gates_make_zero_pds_requests() {
        let pds = MockServer::start().await;
        let client = PdsRepoClient::from_credentials(pds.uri(), "did:plc:alice", "tok")
            .unwrap()
            .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true));

        let tg_uri = apply_threadgate(
            &client,
            "did:plc:alice",
            "3post1",
            ThreadgatePolicy::FollowingOnly,
            true,
        )
        .await
        .unwrap();
        assert_eq!(tg_uri, "at://did:plc:alice/app.bsky.feed.threadgate/3post1");

        remove_threadgate(&client, "did:plc:alice", "3post1", true)
            .await
            .unwrap();

        let (pg_uri, count) = apply_postgate_detach(
            &client,
            "did:plc:alice",
            "3post1",
            &[
                "at://did:plc:troll/app.bsky.feed.post/qt1".to_string(),
                "at://did:plc:troll/app.bsky.feed.post/qt1".to_string(),
            ],
            true,
            true,
        )
        .await
        .unwrap();
        assert_eq!(pg_uri, "at://did:plc:alice/app.bsky.feed.postgate/3post1");
        assert_eq!(count, 1);

        assert!(pds.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn live_threadgate_and_postgate_merge_preserves_existing_and_caps_at_50() {
        let pds = MockServer::start().await;
        let client = PdsRepoClient::from_credentials(pds.uri(), "did:plc:alice", "tok")
            .unwrap()
            .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true));

        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.putRecord"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": "at://did:plc:alice/app.bsky.feed.postgate/3post1",
                "cid": "bafyput"
            })))
            .mount(&pds)
            .await;

        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.deleteRecord"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&pds)
            .await;

        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .and(query_param("collection", "app.bsky.feed.postgate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": "at://did:plc:alice/app.bsky.feed.postgate/3post1",
                "cid": "bafyold",
                "value": {
                    "$type": "app.bsky.feed.postgate",
                    "post": "at://did:plc:alice/app.bsky.feed.post/3post1",
                    "createdAt": "2026-10-01T00:00:00Z",
                    "detachedEmbeddingUris": ["at://did:plc:old/app.bsky.feed.post/qt0"],
                    "embeddingRules": []
                }
            })))
            .mount(&pds)
            .await;

        let mut many_qts = Vec::new();
        for i in 1..=60 {
            many_qts.push(format!("at://did:plc:q{i}/app.bsky.feed.post/qt{i}"));
        }

        let (_pg_uri, count) = apply_postgate_detach(
            &client,
            "did:plc:alice",
            "at://did:plc:alice/app.bsky.feed.post/3post1",
            &many_qts,
            true,
            false,
        )
        .await
        .unwrap();
        assert_eq!(count, MAX_DETACHED_EMBEDDING_URIS);

        let tg_uri = apply_threadgate(
            &client,
            "did:plc:alice",
            "3post1",
            ThreadgatePolicy::Nobody,
            false,
        )
        .await
        .unwrap();
        assert!(tg_uri.contains("did:plc:alice"));

        remove_threadgate(&client, "did:plc:alice", "3post1", false)
            .await
            .unwrap();

        let requests = pds.received_requests().await.unwrap();
        let put_pg = requests
            .iter()
            .find(|r| {
                r.url.path().ends_with("putRecord")
                    && String::from_utf8_lossy(&r.body).contains("app.bsky.feed.postgate")
            })
            .expect("putRecord for postgate");
        let body: serde_json::Value = serde_json::from_slice(&put_pg.body).unwrap();
        assert_eq!(body["record"]["createdAt"], "2026-10-01T00:00:00Z");
        let detached = body["record"]["detachedEmbeddingUris"].as_array().unwrap();
        assert_eq!(detached.len(), MAX_DETACHED_EMBEDDING_URIS);
        assert_eq!(detached[0], "at://did:plc:old/app.bsky.feed.post/qt0");
        let mut pg_dup = PostgateRecord::new("at://did:plc:alice/app.bsky.feed.post/3x");
        pg_dup.merge_detaches(
            &[
                "https://not-at-uri".to_string(),
                "at://did:plc:q1/app.bsky.feed.post/1".to_string(),
            ],
            true,
        );
        pg_dup.merge_detaches(&["at://did:plc:q1/app.bsky.feed.post/1".to_string()], true);
        assert_eq!(pg_dup.detached_embedding_uris.len(), 1);
        assert_eq!(pg_dup.embedding_rules.len(), 1);

        // Fresh postgate (getRecord returns RecordNotFound) + error propagation on 500
        let err_pds = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "RecordNotFound",
                "message": "Record does not exist"
            })))
            .mount(&err_pds)
            .await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.putRecord"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": "at://did:plc:alice/app.bsky.feed.postgate/3fresh",
                "cid": "bafyfresh"
            })))
            .mount(&err_pds)
            .await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.deleteRecord"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "RecordNotFound",
                "message": "Could not locate record"
            })))
            .mount(&err_pds)
            .await;

        let err_client = PdsRepoClient::from_credentials(err_pds.uri(), "did:plc:alice", "tok")
            .unwrap()
            .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true));
        let (fresh_uri, fresh_cnt) = apply_postgate_detach(
            &err_client,
            "did:plc:alice",
            "3fresh",
            &["at://did:plc:q/app.bsky.feed.post/1".to_string()],
            false,
            false,
        )
        .await
        .unwrap();
        assert!(fresh_uri.contains("3fresh"));
        assert_eq!(fresh_cnt, 1);

        // Propagates deleteRecord failure cleanly as SkybouncerError::Repo
        assert!(
            remove_threadgate(&err_client, "did:plc:alice", "3fresh", false)
                .await
                .is_err()
        );

        // 500 errors propagate cleanly as SkybouncerError::Repo
        let fail_pds = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&fail_pds)
            .await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.putRecord"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&fail_pds)
            .await;
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.deleteRecord"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&fail_pds)
            .await;
        let fail_client = PdsRepoClient::from_credentials(fail_pds.uri(), "did:plc:alice", "tok")
            .unwrap()
            .with_ssrf_filter(skyauth::ssrf::SsrfFilter::new(true));
        assert!(
            apply_postgate_detach(&fail_client, "did:plc:alice", "3x", &[], true, false)
                .await
                .is_err()
        );
        assert!(apply_threadgate(
            &fail_client,
            "did:plc:alice",
            "3x",
            ThreadgatePolicy::Nobody,
            false
        )
        .await
        .is_err());
        assert!(
            remove_threadgate(&fail_client, "did:plc:alice", "3x", false)
                .await
                .is_err()
        );
    }
}
