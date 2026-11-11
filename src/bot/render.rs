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

/// Maximum Unicode scalar characters per outbound ATProto Chat DM chunk (stays safely within
/// `chat.bsky.convo.defs#messageInput`'s 1,000-grapheme lexicon ceiling).
pub(crate) const MAX_DM_CHARS: usize = 980;

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

/// Converts a feed-post AT-URI (`at://{authority}/app.bsky.feed.post/{rkey}`) or an
/// already-resolved `http(s)://` URL into a navigable web link.
///
/// Returns `None` when the input is blank or neither a feed-post AT-URI nor an HTTP(S) URL.
#[must_use]
pub fn bsky_post_or_web_url(uri_or_url: &str) -> Option<String> {
    let trimmed = uri_or_url.trim();
    if trimmed.is_empty() {
        return None;
    }
    bsky_post_url_from_at_uri(trimmed).or_else(|| {
        if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
            Some(trimmed.to_string())
        } else {
            None
        }
    })
}

/// Truncates `text` to at most `max_chars` Unicode scalar values, appending `…` when truncated.
#[must_use]
pub(crate) fn truncate_chars(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    out.push('…');
    out
}

/// Splits an outbound DM body on newline boundaries into chunks of at most `max_chars`
/// Unicode scalar values so URLs and link facets are never split mid-line and each
/// message obeys `chat.bsky.convo.defs#messageInput` (`maxGraphemes: 1000`).
#[must_use]
pub(crate) fn split_dm_chunks(text: &str, max_chars: usize) -> Vec<String> {
    let cap = max_chars.max(64);
    if text.chars().count() <= cap {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_chars = 0usize;

    for line in text.split('\n') {
        let line_chars = line.chars().count();
        let needed = if current.is_empty() {
            line_chars
        } else {
            line_chars.saturating_add(1)
        };

        if !current.is_empty() && current_chars.saturating_add(needed) > cap {
            chunks.push(std::mem::take(&mut current));
            current_chars = 0;
        }

        if line_chars > cap {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
                current_chars = 0;
            }
            let mut buf = String::new();
            let mut buf_len = 0usize;
            for ch in line.chars() {
                if buf_len >= cap {
                    chunks.push(std::mem::take(&mut buf));
                    buf_len = 0;
                }
                buf.push(ch);
                buf_len += 1;
            }
            if !buf.is_empty() {
                current = buf;
                current_chars = buf_len;
            }
        } else {
            if !current.is_empty() {
                current.push('\n');
                current_chars += 1;
            }
            current.push_str(line);
            current_chars += line_chars;
        }
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

/// Sends a DM via [`skybase::chat::ChatClient::send_message`], automatically splitting into
/// line-aligned chunks only if `text` exceeds [`MAX_DM_CHARS`].
pub(crate) async fn send_dm_chunked(
    client: &skybase::chat::ChatClient,
    convo_id: &str,
    text: &str,
) -> Result<(), skybase::error::SkybaseError> {
    if text.chars().count() <= MAX_DM_CHARS {
        let _ = client.send_message(convo_id, text).await?;
        return Ok(());
    }
    for chunk in split_dm_chunks(text, MAX_DM_CHARS) {
        if !chunk.trim().is_empty() {
            let _ = client.send_message(convo_id, &chunk).await?;
        }
    }
    Ok(())
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

    #[test]
    fn post_or_web_url_and_dm_chunking() {
        assert_eq!(
            bsky_post_or_web_url("at://did:plc:abc/app.bsky.feed.post/3la7xyz"),
            Some("https://bsky.app/profile/did:plc:abc/post/3la7xyz".to_string())
        );
        assert_eq!(
            bsky_post_or_web_url("https://bsky.app/profile/alice.bsky.social/post/abc"),
            Some("https://bsky.app/profile/alice.bsky.social/post/abc".to_string())
        );
        assert_eq!(bsky_post_or_web_url("   "), None);
        assert_eq!(
            bsky_post_or_web_url("at://did:plc:abc/app.bsky.graph.list/x"),
            None
        );

        assert_eq!(truncate_chars("short", 10), "short");
        assert_eq!(truncate_chars("abcdefghij", 5), "abcd…");
        assert_eq!(truncate_chars("abc", 0), "");

        let long_text = (1..=30)
            .map(|i| format!("Line {i}: https://bsky.app/profile/did:plc:actor{i}/post/rkey{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let chunks = split_dm_chunks(&long_text, 200);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(chunk.chars().count() <= 200);
            assert!(!chunk.ends_with("https://bsky.app/profile/did:"));
        }
        assert_eq!(chunks.join("\n"), long_text);
    }
}
