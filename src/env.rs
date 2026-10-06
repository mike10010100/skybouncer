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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Serializes env-mutating tests and yields a globally unique key suffix so
    /// parallel test threads never observe each other's variables.
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique(prefix: &str) -> (String, String) {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        (
            format!("SKYB_TEST_{prefix}_{n}_A"),
            format!("SKYB_TEST_{prefix}_{n}_B"),
        )
    }

    fn set(key: &str, value: &str) {
        std::env::set_var(key, value);
    }

    fn unset(key: &str) {
        std::env::remove_var(key);
    }

    #[test]
    fn var_returns_none_when_all_unset() {
        let (a, b) = unique("var_unset");
        unset(&a);
        unset(&b);
        assert_eq!(var(&[&a, &b]), None);
    }

    #[test]
    fn var_respects_key_precedence() {
        let (a, b) = unique("var_prec");
        set(&a, "first");
        set(&b, "second");
        assert_eq!(var(&[&a, &b]).as_deref(), Some("first"));
        unset(&a);
        assert_eq!(var(&[&a, &b]).as_deref(), Some("second"));
        unset(&b);
    }

    #[test]
    fn var_trims_and_skips_empty_values() {
        let (a, b) = unique("var_empty");
        set(&a, "   ");
        set(&b, "value");
        // Empty/whitespace in the higher-precedence key is skipped.
        assert_eq!(var(&[&a, &b]).as_deref(), Some("value"));
        unset(&a);
        unset(&b);
    }

    #[test]
    fn var_trims_surrounding_whitespace() {
        let (a, _b) = unique("var_trim");
        set(&a, "  spaced  ");
        assert_eq!(var(&[&a]).as_deref(), Some("spaced"));
        unset(&a);
    }

    #[test]
    fn var_or_falls_back_to_default() {
        let (a, _b) = unique("varor");
        unset(&a);
        assert_eq!(var_or(&[&a], "fallback"), "fallback");
        set(&a, "present");
        assert_eq!(var_or(&[&a], "fallback"), "present");
        unset(&a);
    }

    #[test]
    fn parsed_parses_and_rejects_invalid() {
        let (a, _b) = unique("parsed");
        set(&a, "42");
        assert_eq!(parsed::<u16>(&[&a]), Some(42));
        set(&a, "not-a-number");
        assert_eq!(parsed::<u16>(&[&a]), None);
        unset(&a);
        assert_eq!(parsed::<u16>(&[&a]), None);
    }

    #[test]
    fn parsed_or_falls_back_to_default() {
        let (a, _b) = unique("parsedor");
        unset(&a);
        assert_eq!(parsed_or::<usize>(&[&a], 7), 7);
        set(&a, "9");
        assert_eq!(parsed_or::<usize>(&[&a], 7), 9);
        set(&a, "bad");
        assert_eq!(parsed_or::<usize>(&[&a], 7), 7);
        unset(&a);
    }

    #[test]
    fn bool_accepts_only_true_and_one() {
        let (a, _b) = unique("bool");
        for truthy in ["true", "TRUE", "True", "1"] {
            set(&a, truthy);
            assert_eq!(bool(&[&a]), Some(true), "{truthy} must parse true");
        }
        for falsy in ["false", "0", "yes", "no", "on", "anything"] {
            set(&a, falsy);
            assert_eq!(bool(&[&a]), Some(false), "{falsy} must parse false");
        }
        unset(&a);
        assert_eq!(bool(&[&a]), None);
    }

    #[test]
    fn bool_or_uses_default_when_unset() {
        let (a, _b) = unique("boolor");
        unset(&a);
        assert!(!bool_or(&[&a], false));
        assert!(bool_or(&[&a], true));
        set(&a, "1");
        assert!(bool_or(&[&a], false));
        set(&a, "0");
        assert!(!bool_or(&[&a], true));
        unset(&a);
    }

    #[test]
    fn load_dotenv_file_parses_quotes_comments_and_preserves_existing() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "skyb_env_test_{}.env",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));

        let (existing_key, fresh_key) = unique("dotenv");
        let quoted_key = format!("{existing_key}_q");
        set(&existing_key, "original");

        let contents = format!(
            "# comment line\n\n{existing_key}=should_not_override\n{fresh_key}=fresh \n{quoted_key}=\"quoted value\"\nnot_a_pair\n",
        );
        std::fs::write(&path, contents).expect("write temp .env");

        load_dotenv_file(&path);

        // Existing var is never overwritten.
        assert_eq!(var(&[&existing_key]).as_deref(), Some("original"));
        // New vars are set, with surrounding quotes stripped.
        assert_eq!(var(&[&fresh_key]).as_deref(), Some("fresh"));
        assert_eq!(var(&[&quoted_key]).as_deref(), Some("quoted value"));

        let _ = std::fs::remove_file(&path);
        unset(&existing_key);
        unset(&fresh_key);
        unset(&quoted_key);
    }

    #[test]
    fn load_dotenv_file_missing_path_is_noop() {
        let path = std::env::temp_dir().join("skyb_definitely_missing_env_file.env");
        let _ = std::fs::remove_file(&path);
        // Must not panic.
        load_dotenv_file(&path);
    }
}
