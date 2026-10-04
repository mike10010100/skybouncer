//! Strongly typed data structures for ATProto Chat (`chat.bsky.convo.*`).

use serde::{Deserialize, Serialize};

/// Member within an ATProto Chat conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvoMember {
    /// Decentralized identifier (DID) of the member.
    pub did: String,
    /// Handle of the member if available.
    #[serde(default)]
    pub handle: Option<String>,
    /// Display name of the member if available.
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
}

/// Sender details for an individual chat message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSender {
    /// DID of the message sender.
    pub did: String,
}

/// Individual message representation in `chat.bsky.convo.defs#messageView`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageView {
    /// Unique message identifier string.
    pub id: String,
    /// Revision identifier.
    #[serde(default)]
    pub rev: String,
    /// Text payload of the message.
    pub text: String,
    /// Rich text facets associated with the message text if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facets: Option<Vec<Facet>>,
    /// Sender metadata.
    pub sender: MessageSender,
    /// ISO 8601 timestamp string when the message was sent.
    #[serde(rename = "sentAt")]
    pub sent_at: String,
}

/// Conversation representation in `chat.bsky.convo.defs#convoView`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvoView {
    /// Unique conversation identifier string.
    pub id: String,
    /// Revision identifier.
    #[serde(default)]
    pub rev: String,
    /// Members participating in the conversation.
    #[serde(default)]
    pub members: Vec<ConvoMember>,
    /// Most recent message in the conversation, if any.
    #[serde(rename = "lastMessage", default)]
    pub last_message: Option<MessageView>,
    /// Number of unread messages for the authenticated caller.
    #[serde(rename = "unreadCount", default)]
    pub unread_count: u64,
    /// Status of the conversation for the caller ("request" | "accepted").
    #[serde(default)]
    pub status: Option<String>,
}

/// Response payload from `chat.bsky.convo.listConvos`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListConvosResponse {
    /// Conversations returned in the current page.
    #[serde(default)]
    pub convos: Vec<ConvoView>,
    /// Pagination cursor string if more conversations exist.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Response payload from `chat.bsky.convo.listConvoRequests`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListConvoRequestsResponse {
    /// Conversation requests returned in the current page.
    #[serde(default)]
    pub requests: Vec<ConvoView>,
    /// Pagination cursor string if more conversation requests exist.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Request body for `chat.bsky.convo.acceptConvo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptConvoRequest {
    /// Target conversation ID to accept.
    #[serde(rename = "convoId")]
    pub convo_id: String,
}

/// Response payload from `chat.bsky.convo.acceptConvo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptConvoResponse {
    /// Revision identifier when accepted, or None if already accepted.
    #[serde(default)]
    pub rev: Option<String>,
}

/// Response payload from `chat.bsky.convo.getMessages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetMessagesResponse {
    /// Messages returned in the current page.
    #[serde(default)]
    pub messages: Vec<MessageView>,
    /// Pagination cursor string if more messages exist.
    #[serde(default)]
    pub cursor: Option<String>,
}

pub use crate::types::{ByteSlice, Facet, FacetFeature};

/// Alias for [`ByteSlice`] conforming to ATProto rich text byte index terminology.
pub type FacetIndex = ByteSlice;

/// Extracts all HTTP and HTTPS link facets from `text` with accurate UTF-8 byte slice offsets.
///
/// Strips trailing punctuation (such as `.`, `,`, `!`, `?`, `:`, `;`, quotes, backticks, or unbalanced parentheses)
/// and accounts for preceding multi-byte UTF-8 sequences (emojis, CJK characters).
#[must_use]
pub fn extract_link_facets(text: &str) -> Vec<Facet> {
    static URL_REGEX: std::sync::LazyLock<Option<regex::Regex>> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"(?-u:\b)(?i:https?)://[\x21-\x7E]+").ok());

    let mut facets = Vec::new();
    let Some(ref re) = *URL_REGEX else {
        return facets;
    };
    for mat in re.find_iter(text) {
        let raw = mat.as_str();
        let trimmed = trim_trailing_url_punctuation(raw);
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(parsed) = url::Url::parse(trimmed) {
            if (parsed.scheme() == "http" || parsed.scheme() == "https") && parsed.has_host() {
                let start = mat.start();
                let end = start + trimmed.len();
                facets.push(Facet::link(start, end, trimmed));
            }
        }
    }
    facets
}

fn trim_trailing_url_punctuation(raw_url: &str) -> &str {
    let mut url = raw_url;
    loop {
        if url.is_empty() {
            break;
        }

        let last_char = match url.chars().next_back() {
            Some(c) => c,
            None => break,
        };

        match last_char {
            // Standard sentence and delimiter punctuation
            '.' | ',' | ';' | ':' | '!' | '?' | '"' | '\'' | '`' | '>' | '<' | '*' | '~'
            // Typographic quotes and brackets
            | '”' | '“' | '’' | '‘' | '»' | '«' | '›' | '‹' | '„' | '‟' | '‚'
            // Ellipses and dashes
            | '…' | '⋯' | '‥' | '—' | '–'
            // Fullwidth & CJK punctuation
            | '。' | '、' | '！' | '？' | '：' | '；' | '，' | '．'
            // Invisible, zero-width, and directional formatting characters
            | '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' | '\u{FEFF}' => {
                url = &url[..url.len() - last_char.len_utf8()];
            }
            // ASCII paired delimiters (strip if unbalanced)
            ')' if is_unbalanced_closing(url, '(', ')') => {
                url = &url[..url.len() - 1];
            }
            ']' if is_unbalanced_closing(url, '[', ']') => {
                url = &url[..url.len() - 1];
            }
            '}' if is_unbalanced_closing(url, '{', '}') => {
                url = &url[..url.len() - 1];
            }
            // CJK / Fullwidth paired delimiters (strip if unbalanced)
            '）' if is_unbalanced_closing(url, '（', '）') => {
                url = &url[..url.len() - '）'.len_utf8()];
            }
            '］' if is_unbalanced_closing(url, '［', '］') => {
                url = &url[..url.len() - '］'.len_utf8()];
            }
            '｝' if is_unbalanced_closing(url, '｛', '｝') => {
                url = &url[..url.len() - '｝'.len_utf8()];
            }
            '》' if is_unbalanced_closing(url, '《', '》') => {
                url = &url[..url.len() - '》'.len_utf8()];
            }
            '〉' if is_unbalanced_closing(url, '〈', '〉') => {
                url = &url[..url.len() - '〉'.len_utf8()];
            }
            '」' if is_unbalanced_closing(url, '「', '」') => {
                url = &url[..url.len() - '」'.len_utf8()];
            }
            '』' if is_unbalanced_closing(url, '『', '』') => {
                url = &url[..url.len() - '』'.len_utf8()];
            }
            '】' if is_unbalanced_closing(url, '【', '】') => {
                url = &url[..url.len() - '】'.len_utf8()];
            }
            '〕' if is_unbalanced_closing(url, '〔', '〕') => {
                url = &url[..url.len() - '〕'.len_utf8()];
            }
            '〗' if is_unbalanced_closing(url, '〖', '〗') => {
                url = &url[..url.len() - '〗'.len_utf8()];
            }
            '〙' if is_unbalanced_closing(url, '〘', '〙') => {
                url = &url[..url.len() - '〙'.len_utf8()];
            }
            _ => break,
        }
    }
    url
}

fn is_unbalanced_closing(url: &str, open: char, close: char) -> bool {
    let open_count = url.chars().filter(|&c| c == open).count();
    let close_count = url.chars().filter(|&c| c == close).count();
    close_count > open_count
}

/// Request payload to send a message via `chat.bsky.convo.sendMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessagePayload {
    /// Content of the message.
    pub text: String,
    /// Rich text facets (links, mentions, tags) associated with the message text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facets: Option<Vec<Facet>>,
}

impl SendMessagePayload {
    /// Creates a new message payload, automatically extracting link facets from `text`.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let facets = extract_link_facets(&text);
        Self {
            text,
            facets: if facets.is_empty() {
                None
            } else {
                Some(facets)
            },
        }
    }

    /// Creates a new message payload with explicitly provided facets.
    #[must_use]
    pub fn with_facets(text: impl Into<String>, facets: Option<Vec<Facet>>) -> Self {
        Self {
            text: text.into(),
            facets,
        }
    }
}

/// Request body for `chat.bsky.convo.sendMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Target conversation ID.
    #[serde(rename = "convoId")]
    pub convo_id: String,
    /// Message details.
    pub message: SendMessagePayload,
}

/// Request body for `chat.bsky.convo.updateRead`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateReadRequest {
    /// Target conversation ID.
    #[serde(rename = "convoId")]
    pub convo_id: String,
    /// Message ID marked as read.
    #[serde(rename = "messageId")]
    pub message_id: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_link_facets_empty_and_no_links() {
        assert!(extract_link_facets("").is_empty());
        assert!(extract_link_facets("   ").is_empty());
        assert!(extract_link_facets("Hello world! No links here.").is_empty());
        assert!(extract_link_facets("Just http:// or https:// with no host").is_empty());
        assert!(extract_link_facets("ftp://example.com is not http/https").is_empty());
    }

    #[test]
    fn test_extract_link_facets_simple() {
        let text = "Visit https://skybouncer.mike10010100.com/auth to activate";
        let facets = extract_link_facets(text);
        assert_eq!(facets.len(), 1);

        let facet = &facets[0];
        assert_eq!(
            &text[facet.index.byte_start..facet.index.byte_end],
            "https://skybouncer.mike10010100.com/auth"
        );
        match &facet.features[0] {
            FacetFeature::Link { uri } => {
                assert_eq!(uri, "https://skybouncer.mike10010100.com/auth");
            }
            _ => panic!("expected Link feature"),
        }
    }

    #[test]
    fn test_extract_link_facets_emojis_and_multibyte() {
        let text =
            "👋 Welcome to Skybouncer! Auth: https://skybouncer.mike10010100.com/auth 🎉 Enjoy!";
        let facets = extract_link_facets(text);
        assert_eq!(facets.len(), 1);

        let facet = &facets[0];
        // Confirm UTF-8 byte slice matches URL text exactly
        assert_eq!(
            &text[facet.index.byte_start..facet.index.byte_end],
            "https://skybouncer.mike10010100.com/auth"
        );
        // UTF-8 byte start offset is strictly greater than character count due to multi-byte emojis
        let char_count_before = text
            .chars()
            .take_while(|c| *c != 'h' || !text.contains("https://"))
            .count();
        assert!(facet.index.byte_start > char_count_before);

        // Immediately adjacent emoji without whitespace
        let text_adjacent = "Auth: 🔗https://skybouncer.mike10010100.com/auth";
        let facets_adjacent = extract_link_facets(text_adjacent);
        assert_eq!(facets_adjacent.len(), 1);
        assert_eq!(
            &text_adjacent[facets_adjacent[0].index.byte_start..facets_adjacent[0].index.byte_end],
            "https://skybouncer.mike10010100.com/auth"
        );

        // Skin-tone modifier and ZWJ sequence preceding URL
        let text_zwj = "Leader 👨‍💻: https://skybouncer.mike10010100.com/auth";
        let facets_zwj = extract_link_facets(text_zwj);
        assert_eq!(facets_zwj.len(), 1);
        assert_eq!(
            &text_zwj[facets_zwj[0].index.byte_start..facets_zwj[0].index.byte_end],
            "https://skybouncer.mike10010100.com/auth"
        );

        // RTL mark preceding URL
        let text_rtl = "مرحبا \u{200F}https://skybouncer.mike10010100.com/auth";
        let facets_rtl = extract_link_facets(text_rtl);
        assert_eq!(facets_rtl.len(), 1);
        assert_eq!(
            &text_rtl[facets_rtl[0].index.byte_start..facets_rtl[0].index.byte_end],
            "https://skybouncer.mike10010100.com/auth"
        );

        // Immediately adjacent CJK characters without whitespace or punctuation
        let text_cjk_direct = "请访问https://skybouncer.mike10010100.com/auth进行授权";
        let facets_cjk_direct = extract_link_facets(text_cjk_direct);
        assert_eq!(facets_cjk_direct.len(), 1);
        assert_eq!(
            &text_cjk_direct
                [facets_cjk_direct[0].index.byte_start..facets_cjk_direct[0].index.byte_end],
            "https://skybouncer.mike10010100.com/auth"
        );

        let text_jp_direct = "詳細はhttps://skybouncer.mike10010100.com/authです";
        let facets_jp_direct = extract_link_facets(text_jp_direct);
        assert_eq!(facets_jp_direct.len(), 1);
        assert_eq!(
            &text_jp_direct
                [facets_jp_direct[0].index.byte_start..facets_jp_direct[0].index.byte_end],
            "https://skybouncer.mike10010100.com/auth"
        );

        // Uppercase and mixed-case schemes (RFC 3986 case-insensitive scheme matching)
        let text_upper = "Visit HTTPS://skybouncer.mike10010100.com/auth now";
        let facets_upper = extract_link_facets(text_upper);
        assert_eq!(facets_upper.len(), 1);
        assert_eq!(
            &text_upper[facets_upper[0].index.byte_start..facets_upper[0].index.byte_end],
            "HTTPS://skybouncer.mike10010100.com/auth"
        );

        let text_mixed = "Visit Http://skybouncer.mike10010100.com/auth now";
        let facets_mixed = extract_link_facets(text_mixed);
        assert_eq!(facets_mixed.len(), 1);
        assert_eq!(
            &text_mixed[facets_mixed[0].index.byte_start..facets_mixed[0].index.byte_end],
            "Http://skybouncer.mike10010100.com/auth"
        );

        // Immediately trailing emoji without whitespace
        let text_trailing_emoji = "Visit https://skybouncer.mike10010100.com/auth🚀 immediately!";
        let facets_trailing_emoji = extract_link_facets(text_trailing_emoji);
        assert_eq!(facets_trailing_emoji.len(), 1);
        assert_eq!(
            &text_trailing_emoji[facets_trailing_emoji[0].index.byte_start
                ..facets_trailing_emoji[0].index.byte_end],
            "https://skybouncer.mike10010100.com/auth"
        );

        // Rejection of invalid word prefix (not a URL)
        let text_invalid_prefix = "badprefixhttps://skybouncer.mike10010100.com/auth and 123https://skybouncer.mike10010100.com/auth";
        assert!(extract_link_facets(text_invalid_prefix).is_empty());
    }

    #[test]
    fn test_extract_link_facets_trailing_punctuation() {
        let text = "Links: https://example.com/one., https://example.com/two! and https://example.com/three?";
        let facets = extract_link_facets(text);
        assert_eq!(facets.len(), 3);

        assert_eq!(
            &text[facets[0].index.byte_start..facets[0].index.byte_end],
            "https://example.com/one"
        );
        assert_eq!(
            &text[facets[1].index.byte_start..facets[1].index.byte_end],
            "https://example.com/two"
        );
        assert_eq!(
            &text[facets[2].index.byte_start..facets[2].index.byte_end],
            "https://example.com/three"
        );
    }

    #[test]
    fn test_extract_link_facets_markdown_quotes_and_cjk_punctuation() {
        let text = "Markdown: **https://example.com/bold**, *https://example.com/italic*, ~https://example.com/strike~, quotes: “https://example.com/quote”, ‘https://example.com/single’, angle: <https://example.com/angle>, ellipsis: https://example.com/more…, cjk: https://example.com/cjk。, brackets: 《https://example.com/book》, 【https://example.com/notice】, （https://example.com/fullparens）, zwsp: https://example.com/hidden\u{200B}, percent: https://example.com/foo%20bar.";
        let facets = extract_link_facets(text);
        assert_eq!(facets.len(), 13);

        let expected_urls = [
            "https://example.com/bold",
            "https://example.com/italic",
            "https://example.com/strike",
            "https://example.com/quote",
            "https://example.com/single",
            "https://example.com/angle",
            "https://example.com/more",
            "https://example.com/cjk",
            "https://example.com/book",
            "https://example.com/notice",
            "https://example.com/fullparens",
            "https://example.com/hidden",
            "https://example.com/foo%20bar",
        ];

        for (i, expected) in expected_urls.iter().enumerate() {
            let slice = &text[facets[i].index.byte_start..facets[i].index.byte_end];
            assert_eq!(slice, *expected, "failed at index {i}");
            match &facets[i].features[0] {
                FacetFeature::Link { uri } => assert_eq!(uri, *expected),
                _ => panic!("expected Link feature"),
            }
        }
    }

    #[test]
    fn test_extract_link_facets_parentheses_and_brackets() {
        let text = "Auth URL is (https://example.com/auth) or [https://example.com/alt].";
        let facets = extract_link_facets(text);
        assert_eq!(facets.len(), 2);

        assert_eq!(
            &text[facets[0].index.byte_start..facets[0].index.byte_end],
            "https://example.com/auth"
        );
        assert_eq!(
            &text[facets[1].index.byte_start..facets[1].index.byte_end],
            "https://example.com/alt"
        );
    }

    #[test]
    fn test_extract_link_facets_balanced_parentheses_in_url() {
        // Balanced parens in Wikipedia URL should be preserved
        let text = "Read https://en.wikipedia.org/wiki/Rust_(programming_language) today.";
        let facets = extract_link_facets(text);
        assert_eq!(facets.len(), 1);
        assert_eq!(
            &text[facets[0].index.byte_start..facets[0].index.byte_end],
            "https://en.wikipedia.org/wiki/Rust_(programming_language)"
        );

        // Parens surrounding the Wikipedia URL should have only the outer paren stripped
        let text2 = "Read (https://en.wikipedia.org/wiki/Rust_(programming_language)) today.";
        let facets2 = extract_link_facets(text2);
        assert_eq!(facets2.len(), 1);
        assert_eq!(
            &text2[facets2[0].index.byte_start..facets2[0].index.byte_end],
            "https://en.wikipedia.org/wiki/Rust_(programming_language)"
        );

        // Markdown link syntax with Wikipedia URL
        let text3 = "Check [Wikipedia](https://en.wikipedia.org/wiki/Rust_(programming_language)) for details.";
        let facets3 = extract_link_facets(text3);
        assert_eq!(facets3.len(), 1);
        assert_eq!(
            &text3[facets3[0].index.byte_start..facets3[0].index.byte_end],
            "https://en.wikipedia.org/wiki/Rust_(programming_language)"
        );
    }

    #[test]
    fn test_send_message_payload_serialization() {
        let payload_no_links = SendMessagePayload::new("Plain text message");
        assert!(payload_no_links.facets.is_none());
        let json_no_links = serde_json::to_value(&payload_no_links).unwrap();
        assert_eq!(json_no_links["text"], "Plain text message");
        assert!(json_no_links.get("facets").is_none());

        let payload_with_link = SendMessagePayload::new("Visit https://example.com now");
        assert!(payload_with_link.facets.is_some());
        let json_with_link = serde_json::to_value(&payload_with_link).unwrap();
        assert_eq!(json_with_link["text"], "Visit https://example.com now");

        let facets = json_with_link["facets"].as_array().unwrap();
        assert_eq!(facets.len(), 1);
        assert_eq!(facets[0]["index"]["byteStart"], 6);
        assert_eq!(facets[0]["index"]["byteEnd"], 25);
        assert_eq!(
            facets[0]["features"][0]["$type"],
            "app.bsky.richtext.facet#link"
        );
        assert_eq!(facets[0]["features"][0]["uri"], "https://example.com");
    }

    #[test]
    fn test_send_message_payload_deserialization() {
        let json_str = r#"{
            "text": "Hello https://test.org",
            "facets": [
                {
                    "index": { "byteStart": 6, "byteEnd": 22 },
                    "features": [
                        { "$type": "app.bsky.richtext.facet#link", "uri": "https://test.org" }
                    ]
                }
            ]
        }"#;

        let payload: SendMessagePayload = serde_json::from_str(json_str).unwrap();
        assert_eq!(payload.text, "Hello https://test.org");
        let facets = payload.facets.unwrap();
        assert_eq!(facets.len(), 1);
        assert_eq!(facets[0].index.byte_start, 6);
        assert_eq!(facets[0].index.byte_end, 22);
        match &facets[0].features[0] {
            FacetFeature::Link { uri } => assert_eq!(uri, "https://test.org"),
            _ => panic!("expected Link"),
        }
    }

    #[test]
    fn test_extract_link_facets_adversarial_stress() {
        // Test IPv4 and IPv6 bracketed addresses with ports
        let text_ip = "IPv4: http://127.0.0.1:8080/auth, IPv6: http://[::1]:9090/v1/auth?step=2";
        let facets_ip = extract_link_facets(text_ip);
        assert_eq!(facets_ip.len(), 2);
        assert_eq!(
            &text_ip[facets_ip[0].index.byte_start..facets_ip[0].index.byte_end],
            "http://127.0.0.1:8080/auth"
        );
        assert_eq!(
            &text_ip[facets_ip[1].index.byte_start..facets_ip[1].index.byte_end],
            "http://[::1]:9090/v1/auth?step=2"
        );

        // Test heavy multi-byte emojis (25-byte family emoji 👨‍👩‍👧‍👦, 8-byte flags 🇺🇸 🇬🇧) and RTL text
        let text_heavy_unicode =
            "Family 👨‍👩‍👧‍👦 flag 🇺🇸: https://example.com/family! Arabic مرحبا https://example.com/arabic?lang=ar#welcome Russian Привет: (https://example.com/russian).";
        let facets_heavy = extract_link_facets(text_heavy_unicode);
        assert_eq!(facets_heavy.len(), 3);
        assert_eq!(
            &text_heavy_unicode[facets_heavy[0].index.byte_start..facets_heavy[0].index.byte_end],
            "https://example.com/family"
        );
        assert_eq!(
            &text_heavy_unicode[facets_heavy[1].index.byte_start..facets_heavy[1].index.byte_end],
            "https://example.com/arabic?lang=ar#welcome"
        );
        assert_eq!(
            &text_heavy_unicode[facets_heavy[2].index.byte_start..facets_heavy[2].index.byte_end],
            "https://example.com/russian"
        );

        // Verify non-overlapping and strictly increasing offsets
        for i in 0..facets_heavy.len() {
            assert!(facets_heavy[i].index.byte_start < facets_heavy[i].index.byte_end);
            if i > 0 {
                assert!(facets_heavy[i - 1].index.byte_end <= facets_heavy[i].index.byte_start);
            }
        }

        // Nested and combined punctuation
        let text_punct =
            "Check ((https://example.com/nested?q=1&b=2))... or [https://example.com/bracket]!";
        let facets_punct = extract_link_facets(text_punct);
        assert_eq!(facets_punct.len(), 2);
        assert_eq!(
            &text_punct[facets_punct[0].index.byte_start..facets_punct[0].index.byte_end],
            "https://example.com/nested?q=1&b=2"
        );
        assert_eq!(
            &text_punct[facets_punct[1].index.byte_start..facets_punct[1].index.byte_end],
            "https://example.com/bracket"
        );
    }
}
