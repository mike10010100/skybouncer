//! CLI argument parsing, configuration assembly, and report formatting.
//!
//! This module holds the logic that used to live inline in `src/main.rs`, factored
//! out so it can be unit-tested without a live daemon or network. `main.rs` remains
//! a thin dispatcher that calls into these functions.

use std::path::Path;

use crate::classifier::RuleRubric;
use crate::error::SkybouncerError;

/// Formats an integer with thousands-separator commas (e.g. `1000000` -> `"1,000,000"`).
#[must_use]
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (count, c) in s.chars().rev().enumerate() {
        if count > 0 && count % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Returns the value following `name` in `args`, if present and non-dangling.
#[must_use]
pub fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name && i + 1 < args.len() {
            return Some(args[i + 1].as_str());
        }
        i += 1;
    }
    None
}

/// Returns `true` if any argument equals `flag`.
#[must_use]
pub fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Resolves the target daemon base URL from CLI arguments, environment, or default fallback.
///
/// Precedence: `--url` argument, then `SKYBOUNCER_URL`/`SKYBOUNCER_STATUS_URL`, then
/// `http://127.0.0.1:{port}` using the web configuration port.
#[cfg(feature = "web")]
#[must_use]
pub fn resolve_daemon_url(args: &[String]) -> String {
    if let Some(url) = arg_value(args, "--url") {
        return url.trim_end_matches('/').to_string();
    }
    if let Some(url) = crate::env::var(&["SKYBOUNCER_URL", "SKYBOUNCER_STATUS_URL"]) {
        return url.trim_end_matches('/').to_string();
    }
    let web_config = crate::web::WebServerConfig::from_env();
    format!("http://127.0.0.1:{}", web_config.port)
}

/// Applies daemon CLI argument overrides (`--dry-run`, `--did`, `--admin`, `--rules`) to `config`.
///
/// # Errors
/// Returns [`SkybouncerError::Config`] if `--rules` fails to parse.
pub fn apply_daemon_overrides(
    config: &mut crate::engine::SkybouncerConfig,
    args: &[String],
) -> Result<(), SkybouncerError> {
    if has_flag(args, "--dry-run") || has_flag(args, "--shadow-mode") {
        config.dry_run = true;
    }
    let mut i = 0;
    while i < args.len() {
        if (args[i] == "--did" || args[i] == "--protected-did") && i + 1 < args.len() {
            config.protected_dids.insert(args[i + 1].clone());
            i += 1;
        } else if (args[i] == "--admin" || args[i] == "--admin-did") && i + 1 < args.len() {
            let admin = args[i + 1].clone();
            config.protected_dids.insert(admin.clone());
            config.admin_did = Some(admin);
            i += 1;
        } else if args[i] == "--rules" && i + 1 < args.len() {
            config.rubric = RuleRubric::parse(&args[i + 1])?;
            i += 1;
        }
        i += 1;
    }
    Ok(())
}

/// Parsed inputs for the `simulate` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulateArgs {
    /// Joined candidate text to evaluate.
    pub text: String,
    /// The raw `--image` value, if provided (path or URL).
    pub image_arg: Option<String>,
    /// Base64 payload for a local image file, if `--image` was a file.
    pub image_base64: Option<String>,
    /// Image URL, if `--image` was an `http(s)` URL.
    pub image_url: Option<String>,
    /// Whether `--offline` was passed (skip the live daemon).
    pub offline: bool,
}

/// Parses `simulate` arguments, joining positional text and classifying the image argument.
///
/// # Errors
/// Returns [`SkybouncerError::Config`] if no text is provided or a referenced image file
/// cannot be read.
pub fn parse_simulate_args(args: &[String]) -> Result<SimulateArgs, SkybouncerError> {
    let offline = has_flag(args, "--offline");
    let image_arg = arg_value(args, "--image").map(str::to_string);
    let mut text_parts = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if (args[i] == "--url" || args[i] == "--image") && i + 1 < args.len() {
            i += 2;
            continue;
        }
        if args[i] == "--offline" {
            i += 1;
            continue;
        }
        if !args[i].starts_with("--") {
            text_parts.push(args[i].clone());
        }
        i += 1;
    }

    let text = text_parts.join(" ");
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err(SkybouncerError::Config(
            "Missing text for simulation".into(),
        ));
    }

    let (image_base64, image_url) = classify_image_arg(image_arg.as_deref())?;

    Ok(SimulateArgs {
        text,
        image_arg,
        image_base64,
        image_url,
        offline,
    })
}

/// Classifies an `--image` value into a base64 payload (local file) or a URL.
///
/// `None` yields `(None, None)`. An `http(s)://` value is treated as a URL; otherwise it
/// is read from disk and Base64-encoded.
///
/// # Errors
/// Returns [`SkybouncerError::Config`] if a local file does not exist or cannot be read.
pub fn classify_image_arg(
    image: Option<&str>,
) -> Result<(Option<String>, Option<String>), SkybouncerError> {
    let Some(img) = image else {
        return Ok((None, None));
    };
    if img.starts_with("http://") || img.starts_with("https://") {
        return Ok((None, Some(img.to_string())));
    }
    let path = Path::new(img);
    if !path.exists() {
        return Err(SkybouncerError::Config(format!(
            "Image file not found: {img}"
        )));
    }
    let bytes = std::fs::read(path)
        .map_err(|e| SkybouncerError::Config(format!("Failed to read image file '{img}': {e}")))?;
    use base64::Engine;
    Ok((
        Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
        None,
    ))
}

/// Returns the human-readable evaluator badge for a simulation result.
#[cfg(feature = "web")]
#[must_use]
pub fn evaluator_badge(res: &crate::web::api::SimulateResponse) -> &'static str {
    if res.evaluator.contains("fallback") || res.evaluator.contains("vision") {
        "👁️  Vision Fallback (Tier 2 Multimodal)"
    } else if res.evaluator.contains("heuristic") {
        "⚡ Heuristic Pre-Filter"
    } else if res.images_evaluated > 0 || res.evaluator.contains("multimodal") {
        "🧠 Primary Model (Multimodal)"
    } else {
        "🧠 Primary Model (Text)"
    }
}

/// Formats the `simulate` result banner into a string (testable without stdout capture).
#[cfg(feature = "web")]
#[must_use]
pub fn format_simulation_report(
    text: &str,
    res: &crate::web::api::SimulateResponse,
    image_arg: &Option<String>,
) -> String {
    let mut out = String::new();
    out.push_str("╔══════════════════════════════════════════════════════════════════════════╗\n");
    out.push_str("║                   🧪  SKYBOUNCER SIMULATION RESULT                       ║\n");
    out.push_str(
        "╚══════════════════════════════════════════════════════════════════════════╝\n\n",
    );
    out.push_str(&format!("  Input Text:       \"{text}\"\n"));
    if let Some(ref img) = image_arg {
        out.push_str(&format!("  Attached Image:   {img}\n"));
    }
    out.push_str(&format!("  Images Evaluated: {}\n", res.images_evaluated));
    out.push_str(&format!("  Evaluator:        {}\n\n", evaluator_badge(res)));

    if res.violates {
        let cat = res.category.as_deref().unwrap_or("Unspecified");
        out.push_str(&format!("  Verdict:          🚨 VIOLATION [{cat}]\n"));
        out.push_str(&format!(
            "  Confidence:       {:.1}% (Threshold: {:.1}%)\n",
            res.confidence * 100.0,
            res.threshold * 100.0
        ));
        out.push_str(&format!(
            "  Threshold Met:    {}\n",
            if res.meets_threshold {
                "YES (Will Bounce)"
            } else {
                "NO (Borderline, Permitted)"
            }
        ));
        out.push_str(&format!("  Reason:           {}\n\n", res.reason));
        if res.meets_threshold {
            out.push_str(
                "  Action (Live):    💥 Author would be BOUNCED to sovereign PDS moderation list\n",
            );
        } else {
            out.push_str("  Action (Live):    ⚠️ Confidence below sensitivity threshold; interaction permitted\n");
        }
    } else {
        out.push_str("  Verdict:          ✅ PERMITTED\n");
        out.push_str(&format!(
            "  Confidence:       {:.1}% (Threshold: {:.1}%)\n",
            res.confidence * 100.0,
            res.threshold * 100.0
        ));
        out.push_str(&format!("  Reason:           {}\n\n", res.reason));
        out.push_str(
            "  Action (Live):    🛡️ Permitted through gate (zero PDS listitem mutations)\n",
        );
    }
    out.push('\n');
    out
}

/// Returns the general CLI usage text.
#[must_use]
pub fn help_text() -> String {
    let mut out = String::new();
    out.push_str("🛡️  Skybouncer — Sovereign ATProto Auto-Moderation & Bouncer\n\n");
    out.push_str("USAGE:\n");
    out.push_str("  skybouncer [daemon] [OPTIONS]     Run the 24/7 firehose moderation daemon\n");
    out.push_str("  skybouncer status [--url <URL>] [--json]\n");
    out.push_str(
        "  skybouncer simulate <TEXT...> [--image <PATH_OR_URL>] [--url <URL>] [--offline]\n",
    );
    out.push_str(
        "  skybouncer pardon <DID_OR_HANDLE> [--url <URL>] [--target <PROTECTED_DID>]\n\n",
    );
    out.push_str("DAEMON OPTIONS:\n");
    out.push_str("  --did <DID>               Add a protected account DID (repeatable)\n");
    out.push_str("  --admin <DID>             Set the system administrator DID\n");
    out.push_str("  --rules <RUBRIC>          Override the moderation rubric prompt\n");
    out.push_str("  --dry-run                 Shadow mode: evaluate but make zero PDS writes\n\n");
    out.push_str("STATUS OPTIONS:\n");
    out.push_str("  --url <URL>               Daemon base URL (default: http://127.0.0.1:3000)\n");
    out.push_str("  --json                    Output status as structured JSON\n\n");
    out.push_str("SIMULATE OPTIONS:\n");
    out.push_str(
        "  --image <PATH_OR_URL>     Attach image file or URL for multimodal evaluation\n",
    );
    out.push_str("  --url <URL>               Daemon base URL (default: http://127.0.0.1:3000)\n");
    out.push_str(
        "  --offline                 Force local offline evaluation without contacting daemon\n\n",
    );
    out.push_str("PARDON OPTIONS:\n");
    out.push_str("  --url <URL>               Daemon base URL (default: http://127.0.0.1:3000)\n");
    out.push_str("  --target <DID>            Protected user DID whose modlist to pardon from\n");
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn format_number_groups_thousands() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1_000), "1,000");
        assert_eq!(format_number(1_000_000), "1,000,000");
        assert_eq!(format_number(12_345_678), "12,345,678");
    }

    #[test]
    fn arg_value_and_has_flag() {
        let a = args(&["simulate", "hi", "--url", "http://x", "--offline"]);
        assert_eq!(arg_value(&a, "--url"), Some("http://x"));
        assert_eq!(arg_value(&a, "--image"), None);
        assert!(has_flag(&a, "--offline"));
        assert!(!has_flag(&a, "--json"));
        // Dangling flag yields None.
        assert_eq!(arg_value(&args(&["x", "--url"]), "--url"), None);
    }

    #[test]
    fn apply_daemon_overrides_sets_dry_run_and_dids() {
        let mut config = crate::engine::SkybouncerConfig::default();
        let a = args(&[
            "--dry-run",
            "--did",
            "did:plc:a",
            "--protected-did",
            "did:plc:b",
            "--admin",
            "did:plc:admin",
        ]);
        apply_daemon_overrides(&mut config, &a).expect("overrides");
        assert!(config.dry_run);
        assert!(config.protected_dids.contains("did:plc:a"));
        assert!(config.protected_dids.contains("did:plc:b"));
        assert!(config.protected_dids.contains("did:plc:admin"));
        assert_eq!(config.admin_did.as_deref(), Some("did:plc:admin"));
    }

    #[test]
    fn apply_daemon_overrides_parses_rules() {
        let mut config = crate::engine::SkybouncerConfig::default();
        let a = args(&["--rules", "Block all crypto spam"]);
        apply_daemon_overrides(&mut config, &a).expect("rules");
        assert!(config.rubric.prompt.contains("crypto spam"));
    }

    #[test]
    fn parse_simulate_args_joins_text_and_defaults() {
        let a = args(&["please", "evaluate", "this"]);
        let parsed = parse_simulate_args(&a).expect("parse");
        assert_eq!(parsed.text, "please evaluate this");
        assert!(!parsed.offline);
        assert!(parsed.image_arg.is_none());
        assert!(parsed.image_base64.is_none());
        assert!(parsed.image_url.is_none());
    }

    #[test]
    fn parse_simulate_args_strips_flags_and_detects_offline() {
        let a = args(&[
            "hello",
            "--url",
            "http://daemon",
            "--offline",
            "world",
            "--image",
            "https://cdn.example/x.jpg",
        ]);
        let parsed = parse_simulate_args(&a).expect("parse");
        assert_eq!(parsed.text, "hello world");
        assert!(parsed.offline);
        assert_eq!(
            parsed.image_url.as_deref(),
            Some("https://cdn.example/x.jpg")
        );
        assert!(parsed.image_base64.is_none());
    }

    #[test]
    fn parse_simulate_args_rejects_empty_text() {
        let a = args(&["--offline"]);
        let err = parse_simulate_args(&a).expect_err("must fail");
        assert!(matches!(err, SkybouncerError::Config(_)));
    }

    #[test]
    fn classify_image_arg_handles_none_and_urls() {
        assert_eq!(classify_image_arg(None).unwrap(), (None, None));
        let (b64, url) = classify_image_arg(Some("http://x/y.png")).unwrap();
        assert!(b64.is_none());
        assert_eq!(url.as_deref(), Some("http://x/y.png"));
        let (b64, url) = classify_image_arg(Some("https://x/y.png")).unwrap();
        assert!(b64.is_none());
        assert_eq!(url.as_deref(), Some("https://x/y.png"));
    }

    #[test]
    fn classify_image_arg_reads_local_file() {
        let path = std::env::temp_dir().join(format!(
            "skyb_cli_img_{}.bin",
            crate::time::current_time_us()
        ));
        std::fs::write(&path, b"PNGDATA").unwrap();
        let (b64, url) = classify_image_arg(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(b64.as_deref(), Some("UE5HREFUQQ=="));
        assert!(url.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn classify_image_arg_missing_file_errors() {
        let err = classify_image_arg(Some("/nonexistent/path/to/img.png")).expect_err("must fail");
        assert!(matches!(err, SkybouncerError::Config(_)));
    }

    #[cfg(feature = "web")]
    mod web_reports {
        use super::*;
        use crate::web::api::{SimulateResponse, TierStageDetail};

        fn base(violates: bool, evaluator: &str, images: usize) -> SimulateResponse {
            SimulateResponse {
                violates,
                category: if violates {
                    Some("crypto_spam".to_string())
                } else {
                    None
                },
                confidence: 0.9,
                reason: "because".to_string(),
                evaluator: evaluator.to_string(),
                meets_threshold: violates,
                threshold: 0.8,
                images_evaluated: images,
                tier1: None,
                tier2: None,
            }
        }

        #[test]
        fn evaluator_badge_variants() {
            assert!(
                evaluator_badge(&base(false, "fallback_uncertainty_classifier", 0))
                    .contains("Vision Fallback")
            );
            assert!(evaluator_badge(&base(true, "heuristic_prefilter", 0))
                .contains("Heuristic Pre-Filter"));
            assert!(
                evaluator_badge(&base(false, "primary_classifier (multimodal)", 1))
                    .contains("Multimodal")
            );
            assert!(evaluator_badge(&base(false, "primary_classifier", 0))
                .contains("Primary Model (Text)"));
        }

        #[test]
        fn format_simulation_report_violation_and_permit() {
            let img = Some("example.png".to_string());
            let v =
                format_simulation_report("bad text", &base(true, "primary_classifier", 1), &img);
            assert!(v.contains("VIOLATION [crypto_spam]"));
            assert!(v.contains("Attached Image:   example.png"));
            assert!(v.contains("BOUNCED"));

            let p =
                format_simulation_report("good text", &base(false, "primary_classifier", 0), &None);
            assert!(p.contains("PERMITTED"));
            assert!(p.contains("zero PDS listitem mutations"));
        }

        #[test]
        fn format_simulation_report_below_threshold_branch() {
            let mut res = base(false, "primary_classifier", 0);
            res.violates = true;
            res.meets_threshold = false;
            res.category = Some("spam".to_string());
            let out = format_simulation_report("borderline", &res, &None);
            assert!(out.contains("NO (Borderline, Permitted)"));
            assert!(out.contains("below sensitivity threshold"));
        }

        #[test]
        fn format_simulation_report_tier_details_ignored_but_present() {
            let mut res = base(false, "primary_classifier", 0);
            res.tier1 = Some(TierStageDetail {
                stage_name: "Tier 1".to_string(),
                model: "m".to_string(),
                status: "resolved".to_string(),
                violates: false,
                category: None,
                confidence: 0.9,
                reason: "r".to_string(),
            });
            let out = format_simulation_report("x", &res, &None);
            assert!(out.contains("PERMITTED"));
        }
    }

    #[test]
    fn help_text_lists_subcommands() {
        let h = help_text();
        assert!(h.contains("daemon"));
        assert!(h.contains("status"));
        assert!(h.contains("simulate"));
        assert!(h.contains("pardon"));
        assert!(h.contains("--dry-run"));
    }
}
