//! Fundraiser and payment-funnel URL extraction helpers for author profiles and feed records.

use crate::enricher::MAX_PROFILE_FUNDRAISER_URLS;

const FUNDRAISER_HOSTS: &[&str] = &[
    "chuffed.org",
    "gofundme.com",
    "gofund.me",
    "paypal.me",
    "ko-fi.com",
    "buymeacoffee.com",
    "spotfund.com",
    "givebutter.com",
    "donorbox.org",
    "launchgood.com",
    "fundrazr.com",
    "gogetfunding.com",
    "airfunding.net",
    "whydonate.com",
    "justgiving.com",
    "cash.app",
    "venmo.com",
    "aidme.site",
    "bsku.social",
    "lnan.site",
    "bske.social",
];

fn normalize_fundraiser_url(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_start_matches(['"', '\'', '(', '[', '<'])
        .trim_end_matches(['"', '\'', ')', ']', '>', ',', '.', ';', '!', '?']);
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
        || trimmed
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
    {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = url::Url::parse(&with_scheme).ok()?;
    let raw_host = parsed.host_str()?.to_ascii_lowercase();
    let match_host = raw_host.strip_prefix("www.").unwrap_or(&raw_host);
    let path = parsed.path();
    let is_fundraiser_host = FUNDRAISER_HOSTS
        .iter()
        .any(|dom| match_host == *dom || match_host.ends_with(&format!(".{dom}")))
        || (match_host == "paypal.com"
            && (path.starts_with("/ncp/")
                || path.starts_with("/donate")
                || path.starts_with("/pools")
                || path.starts_with("/paypalme")));
    if !is_fundraiser_host {
        return None;
    }
    let clean_path = path.trim_end_matches('/');
    Some(if clean_path.is_empty() {
        format!("https://{raw_host}")
    } else {
        format!("https://{raw_host}{clean_path}")
    })
}

pub(super) fn push_unique_fundraiser_url(out: &mut Vec<String>, candidate: &str) {
    if out.len() >= MAX_PROFILE_FUNDRAISER_URLS {
        return;
    }
    if let Some(norm) = normalize_fundraiser_url(candidate) {
        if !out.contains(&norm) {
            out.push(norm);
        }
    }
}

/// Extracts normalized donation, crowdfunding, or payment URLs from arbitrary post or bio text.
#[must_use]
pub fn extract_fundraiser_urls_from_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in text.split(|c: char| {
        c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']' | '<' | '>' | '"' | '\'')
    }) {
        if out.len() >= MAX_PROFILE_FUNDRAISER_URLS {
            break;
        }
        if token.contains('.') {
            push_unique_fundraiser_url(&mut out, token);
        }
    }
    out
}

pub(super) fn extract_urls_from_record_obj(rec: &serde_json::Value, out: &mut Vec<String>) {
    if let Some(txt) = rec.get("text").and_then(|v| v.as_str()) {
        for u in extract_fundraiser_urls_from_text(txt) {
            push_unique_fundraiser_url(out, &u);
        }
    }
    if let Some(facets) = rec.get("facets").and_then(|v| v.as_array()) {
        for facet in facets {
            if let Some(features) = facet.get("features").and_then(|v| v.as_array()) {
                for feat in features {
                    if let Some(uri) = feat.get("uri").and_then(|v| v.as_str()) {
                        push_unique_fundraiser_url(out, uri);
                    }
                }
            }
        }
    }
}

pub(super) fn extract_urls_from_embed_obj(emb: &serde_json::Value, out: &mut Vec<String>) {
    for candidate in [
        emb.get("external").and_then(|e| e.get("uri")),
        emb.get("media")
            .and_then(|m| m.get("external"))
            .and_then(|e| e.get("uri")),
        emb.get("uri"),
    ] {
        if let Some(uri) = candidate.and_then(|v| v.as_str()) {
            push_unique_fundraiser_url(out, uri);
        }
    }
}
