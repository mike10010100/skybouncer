//! Sovereign ATProto PDS configuration storage for zero-custody, stateless operation.
//!
//! Enables users to store and resolve their moderation rules and sensitivity thresholds directly
//! in their own sovereign ATProto repository (`social.skybouncer.config` or list metadata),
//! eliminating the need for centralized configuration databases.

use serde::{Deserialize, Serialize};
use skybase::repo::PdsRepoClient;

use crate::classifier::{RuleRubric, Sensitivity};
use crate::error::SkybouncerError;

/// The canonical ATProto NSID collection for sovereign skybouncer configuration.
pub const SOVEREIGN_CONFIG_COLLECTION: &str = "social.skybouncer.config";

/// The default record key (rkey) used for sovereign configuration records.
pub const SOVEREIGN_CONFIG_RKEY: &str = "self";

/// An ATProto repository record holding sovereign moderation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SovereignConfigRecord {
    /// ATProto type identifier.
    #[serde(rename = "$type")]
    pub record_type: String,
    /// Natural-language moderation rubric prompt.
    pub rules: String,
    /// Sensitivity string (`"low"`, `"medium"`, `"high"`).
    pub sensitivity: String,
    /// Optional bounce duration string (`"permanent"`, `"cooldown24h"`, `"timeout7d"`, `"timeout30d"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounce_duration: Option<String>,
    /// Whether accounts following the protected user bypass moderation evaluation.
    ///
    /// Defaults to `true` when absent, matching [`RuleRubric::bypass_incoming_followers`].
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub bypass_incoming_followers: bool,
    /// Timestamp of last modification in ISO 8601 format.
    pub updated_at: String,
}

/// Returns `true`, used as the serde default for opt-out bypass flags.
fn default_true() -> bool {
    true
}

/// Returns whether the flag is `true`, used to omit the default value during serialization.
fn is_true(value: &bool) -> bool {
    *value
}

impl SovereignConfigRecord {
    /// Creates a new [`SovereignConfigRecord`] from a [`RuleRubric`].
    #[must_use]
    pub fn from_rubric(rubric: &RuleRubric) -> Self {
        Self {
            record_type: SOVEREIGN_CONFIG_COLLECTION.to_string(),
            rules: rubric.prompt.clone(),
            sensitivity: rubric.sensitivity.as_str().to_string(),
            bounce_duration: Some(rubric.bounce_duration.to_db_string()),
            bypass_incoming_followers: rubric.bypass_incoming_followers,
            updated_at: crate::types::now_iso8601(),
        }
    }

    /// Converts this record into a domain [`RuleRubric`].
    #[must_use]
    pub fn to_rubric(&self) -> RuleRubric {
        let sensitivity = match self.sensitivity.to_lowercase().as_str() {
            "low" => Sensitivity::Low,
            "high" => Sensitivity::High,
            _ => Sensitivity::Medium,
        };
        let bounce_duration = self
            .bounce_duration
            .as_deref()
            .and_then(|s| s.parse::<crate::classifier::BounceDuration>().ok())
            .unwrap_or_default();
        RuleRubric {
            prompt: self.rules.clone(),
            sensitivity,
            bounce_duration,
            bypass_incoming_followers: self.bypass_incoming_followers,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ListMetadata {
    rules: String,
    sensitivity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bounce_duration: Option<String>,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    bypass_incoming_followers: bool,
}

/// Encodes rubric parameters into moderation list description metadata.
///
/// Format: `[skybouncer:{"rules":"...","sensitivity":"..."}]`
#[must_use]
pub fn format_list_description_with_rubric(base_description: &str, rubric: &RuleRubric) -> String {
    let clean_base = base_description
        .split("[skybouncer:")
        .next()
        .unwrap_or("")
        .trim_end();

    let meta = ListMetadata {
        rules: rubric.prompt.clone(),
        sensitivity: rubric.sensitivity.as_str().to_string(),
        bounce_duration: Some(rubric.bounce_duration.to_db_string()),
        bypass_incoming_followers: rubric.bypass_incoming_followers,
    };

    let json_str = serde_json::to_string(&meta).unwrap_or_default();
    let tag = format!("[skybouncer:{json_str}]");

    if clean_base.is_empty() {
        tag
    } else {
        format!("{clean_base}\n\n{tag}")
    }
}

/// Extracts a [`RuleRubric`] from an encoded moderation list description, if present.
#[must_use]
pub fn extract_rubric_from_list_description(description: &str) -> Option<RuleRubric> {
    let marker = "[skybouncer:";
    let start_idx = description.find(marker)? + marker.len();
    let end_idx = description[start_idx..].find(']')? + start_idx;
    let json_str = &description[start_idx..end_idx];

    let meta: ListMetadata = serde_json::from_str(json_str).ok()?;
    let sensitivity = match meta.sensitivity.to_lowercase().as_str() {
        "low" => Sensitivity::Low,
        "high" => Sensitivity::High,
        _ => Sensitivity::Medium,
    };
    let bounce_duration = meta
        .bounce_duration
        .as_deref()
        .and_then(|s| s.parse::<crate::classifier::BounceDuration>().ok())
        .unwrap_or_default();

    Some(RuleRubric {
        prompt: meta.rules,
        sensitivity,
        bounce_duration,
        bypass_incoming_followers: meta.bypass_incoming_followers,
    })
}

/// Client helper fetching sovereign configuration from a user's PDS repository.
///
/// Attempts to read `social.skybouncer.config/self` via XRPC `com.atproto.repo.getRecord`.
///
/// # Errors
/// Returns [`SkybouncerError::Repo`] on permanent network or parse errors.
pub async fn fetch_sovereign_config(
    pds_client: &PdsRepoClient,
    repo_did: &str,
) -> Result<Option<RuleRubric>, SkybouncerError> {
    let res = pds_client
        .get_record(repo_did, SOVEREIGN_CONFIG_COLLECTION, SOVEREIGN_CONFIG_RKEY)
        .await;

    match res {
        Ok(record_view) => {
            let record: SovereignConfigRecord =
                serde_json::from_value(record_view.value).map_err(|e| {
                    SkybouncerError::Repo(format!(
                        "Failed to deserialize sovereign config record: {e}"
                    ))
                })?;
            Ok(Some(record.to_rubric()))
        }
        Err(e) => {
            let msg = e.to_string();
            // If record doesn't exist (CouldNotFindRecord or 404), return None cleanly
            if msg.contains("CouldNotFindRecord")
                || msg.contains("404")
                || msg.contains("RecordNotFound")
            {
                Ok(None)
            } else {
                Err(SkybouncerError::Repo(format!(
                    "Failed to fetch sovereign config from PDS: {e}"
                )))
            }
        }
    }
}

/// Publishes or updates sovereign configuration to `social.skybouncer.config/self` on the user's PDS.
///
/// Uses `com.atproto.repo.putRecord` for idempotent upserting.
///
/// # Errors
/// Returns [`SkybouncerError::Repo`] on PDS mutation failure.
pub async fn publish_sovereign_config(
    pds_client: &PdsRepoClient,
    _repo_did: &str,
    rubric: &RuleRubric,
) -> Result<String, SkybouncerError> {
    let record = SovereignConfigRecord::from_rubric(rubric);
    let value = serde_json::to_value(&record).map_err(|e| {
        SkybouncerError::Repo(format!("Failed to serialize sovereign config record: {e}"))
    })?;

    let put_res = pds_client
        .put_record(
            SOVEREIGN_CONFIG_COLLECTION,
            SOVEREIGN_CONFIG_RKEY,
            &value,
            false,
        )
        .await
        .map_err(|e| {
            SkybouncerError::Repo(format!("Failed to put sovereign config record: {e}"))
        })?;

    Ok(put_res.uri)
}
