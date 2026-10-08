//! Shared rendering helpers for human-friendly, hotlinkable ATProto DM output.
//!
//! ATProto Chat renders plain text with rich-text facets rather than Markdown, so
//! accounts and posts are made navigable by embedding literal `https://bsky.app/...`
//! URLs (which [`ChatClient::send_message`](skybase::chat::ChatClient::send_message)
//! automatically converts into link facets). These helpers centralize the URL and
//! display-label formatting used by both the command handler and the bounce-alert
//! dispatcher.

/// Public Bluesky web origin used for profile and post deep links.
pub const BSKY_WEB_ORIGIN: &str = "https://bsky.app";

/// Sanitizes an ATProto handle or DID for safe inclusion in a URL path segment.
///
/// DIDs require literal colons (`did:plc:...`), so percent-encoding is intentionally
/// avoided; only characters valid in handles/DIDs are retained.
fn sanitize_actor(actor: &str) -> String {
    let clean = actor.trim().trim_start_matches('@');
    clean
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-' | '%'))
        .collect()
}

/// Returns the canonical Bluesky profile URL for a handle or DID.
///
/// Returns an empty string when the input contains no usable characters.
#[must_use]
pub fn bsky_profile_url(actor_or_did: &str) -> String {
    let actor = sanitize_actor(actor_or_did);
    if actor.is_empty() {
        String::new()
    } else {
        format!("{BSKY_WEB_ORIGIN}/profile/{actor}")
    }
}

/// Returns the canonical Bluesky post URL for an actor and record key.
#[must_use]
pub fn bsky_post_url(actor_or_did: &str, rkey: &str) -> String {
    let profile = bsky_profile_url(actor_or_did);
    let clean_rkey: String = rkey
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))
        .collect();
    if profile.is_empty() || clean_rkey.is_empty() {
        String::new()
    } else {
        format!("{profile}/post/{clean_rkey}")
    }
}

/// Converts an `at://{authority}/app.bsky.feed.post/{rkey}` URI into a Bluesky web URL.
///
/// Returns `None` when the URI is not a well-formed feed-post AT-URI.
#[must_use]
pub fn bsky_post_url_from_at_uri(at_uri: &str) -> Option<String> {
    let (prefix, rest) = at_uri.trim().split_once("/app.bsky.feed.post/")?;
    let authority = prefix.strip_prefix("at://")?;
    let rkey = rest.split('/').next().unwrap_or_default();
    let url = bsky_post_url(authority, rkey);
    if url.is_empty() {
        None
    } else {
        Some(url)
    }
}

/// Formats a human-readable account label, preferring the handle over the raw DID.
///
/// Unknown or blank handles fall back to the DID so callers never render an empty label.
#[must_use]
pub fn account_label(did: &str, handle: Option<&str>) -> String {
    match handle.map(str::trim).filter(|h| !h.is_empty()) {
        Some(handle) => format!("@{}", handle.trim_start_matches('@')),
        None => did.trim().to_string(),
    }
}

/// Returns the command target to embed in a `pardon`/`allow` reply, preferring the
/// handle (which the parser accepts) and falling back to the DID.
#[must_use]
pub fn command_target(did: &str, handle: Option<&str>) -> String {
    match handle.map(str::trim).filter(|h| !h.is_empty()) {
        Some(handle) => handle.trim_start_matches('@').to_string(),
        None => did.trim().to_string(),
    }
}

/// Renders a human-readable account label annotated with a clickable Bluesky profile URL.
///
/// Falls back to the bare label when no valid URL can be constructed.
#[must_use]
pub fn account_label_with_url(did: &str, handle: Option<&str>) -> String {
    let label = account_label(did, handle);
    let url = bsky_profile_url(handle.unwrap_or(did));
    if url.is_empty() {
        label
    } else {
        format!("{label} ({url})")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn profile_url_handles_and_dids() {
        assert_eq!(
            bsky_profile_url("@alice.bsky.social"),
            "https://bsky.app/profile/alice.bsky.social"
        );
        assert_eq!(
            bsky_profile_url("did:plc:abc123"),
            "https://bsky.app/profile/did:plc:abc123"
        );
        assert_eq!(bsky_profile_url("   "), "");
        // Unsafe characters are stripped rather than percent-encoded.
        assert_eq!(
            bsky_profile_url("bad?actor#frag"),
            "https://bsky.app/profile/badactorfrag"
        );
    }

    #[test]
    fn post_url_from_at_uri() {
        assert_eq!(
            bsky_post_url_from_at_uri("at://did:plc:abc/app.bsky.feed.post/3la7xyz"),
            Some("https://bsky.app/profile/did:plc:abc/post/3la7xyz".to_string())
        );
        assert_eq!(
            bsky_post_url_from_at_uri("at://alice.bsky.social/app.bsky.feed.post/abc"),
            Some("https://bsky.app/profile/alice.bsky.social/post/abc".to_string())
        );
        assert_eq!(
            bsky_post_url_from_at_uri("https://example.com/post/1"),
            None
        );
        assert_eq!(
            bsky_post_url_from_at_uri("at://did:plc:abc/app.bsky.graph.list/x"),
            None
        );
        assert_eq!(
            bsky_post_url_from_at_uri("at://did:plc:abc/app.bsky.feed.post/"),
            None
        );
    }

    #[test]
    fn account_label_and_command_target() {
        assert_eq!(
            account_label("did:plc:abc", Some("alice.bsky.social")),
            "@alice.bsky.social"
        );
        assert_eq!(account_label("did:plc:abc", Some("@alice")), "@alice");
        assert_eq!(account_label("did:plc:abc", None), "did:plc:abc");
        assert_eq!(account_label("did:plc:abc", Some("  ")), "did:plc:abc");

        assert_eq!(
            command_target("did:plc:abc", Some("@alice.bsky.social")),
            "alice.bsky.social"
        );
        assert_eq!(command_target("did:plc:abc", None), "did:plc:abc");
    }
}
