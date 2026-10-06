//! Environment-variable helpers with consistent dual-prefix resolution.
//!
//! Skybouncer accepts both bare (`FALLBACK_MODEL`) and namespaced
//! (`SKYBOUNCER_FALLBACK_MODEL`) variable names for backward compatibility.
//! These helpers centralize the lookup order, trimming, empty-value handling,
//! boolean parsing, and numeric parsing so individual call sites cannot diverge.

use std::str::FromStr;

/// Returns the first set, non-empty (after trimming) value among `keys`.
///
/// Keys are checked in order, enabling callers to express precedence explicitly
/// (e.g. `&["PDS_ENDPOINT", "SKYBOUNCER_PDS_URL"]`).
#[must_use]
pub fn var(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(raw) = std::env::var(key) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Returns the first set value among `keys`, or `default` if none are present.
#[must_use]
pub fn var_or(keys: &[&str], default: &str) -> String {
    var(keys).unwrap_or_else(|| default.to_string())
}

/// Parses the first set value among `keys` into `T`, returning `None` if absent
/// or unparseable.
#[must_use]
pub fn parsed<T: FromStr>(keys: &[&str]) -> Option<T> {
    var(keys).and_then(|value| value.parse::<T>().ok())
}

/// Parses the first set value among `keys` into `T`, falling back to `default`.
#[must_use]
pub fn parsed_or<T: FromStr>(keys: &[&str], default: T) -> T {
    parsed(keys).unwrap_or(default)
}

/// Interprets the first set value among `keys` as a boolean: `true`/`1`
/// (ASCII-case-insensitive).
///
/// Returns `None` when unset, and `Some(false)` for any other value. This
/// deliberately matches the historical parsing of `true`/`1` only.
#[must_use]
pub fn bool(keys: &[&str]) -> Option<bool> {
    var(keys).map(|value| {
        let lowered = value.to_ascii_lowercase();
        matches!(lowered.as_str(), "true" | "1")
    })
}

/// Interprets the first set value among `keys` as a boolean, falling back to `default`.
#[must_use]
pub fn bool_or(keys: &[&str], default: bool) -> bool {
    bool(keys).unwrap_or(default)
}

/// Loads `KEY=VALUE` pairs from a `.env`-style file into the process environment.
///
/// Existing environment variables take precedence and are never overwritten.
/// Blank lines and lines beginning with `#` are ignored; surrounding single or
/// double quotes on values are stripped. This intentionally supports only the
/// subset of the dotenv grammar Skybouncer documents (no `export`, escapes, or
/// multiline values).
pub fn load_dotenv_file(path: &std::path::Path) {
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');
                if std::env::var_os(key).is_none() {
                    std::env::set_var(key, val);
                }
            }
        }
    }
}

/// Initializes the global structured tracing subscriber.
///
/// Honors `RUST_LOG` via [`tracing_subscriber::EnvFilter`], defaulting to
/// `skybouncer=info,skybase=info,info`.
#[cfg(feature = "telemetry")]
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("skybouncer=info,skybase=info,info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();
}
