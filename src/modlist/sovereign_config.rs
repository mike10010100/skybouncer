//! Sovereign ATProto PDS configuration storage for zero-custody, stateless operation.
//!
//! Enables users to store and resolve their moderation rules and sensitivity thresholds directly
//! in their own sovereign ATProto repository (`social.skybouncer.config` or list metadata),
//! eliminating the need for centralized configuration databases.

use serde::{Deserialize, Serialize};
use skybase::repo::PdsRepoClient;

use crate::classifier::{bounce_duration_from_db, sensitivity_from_db, RuleRubric};
use crate::error::SkybouncerError;
use crate::types::{default_true, is_true};

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
    /// Optional AT-URI of the user's Skybouncer-managed moderation list (`app.bsky.graph.list`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mod_list_uri: Option<String>,
    /// Timestamp of last modification in ISO 8601 format.
    pub updated_at: String,
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
            mod_list_uri: None,
            updated_at: crate::types::now_iso8601(),
        }
    }

    /// Attaches a Skybouncer-owned moderation list AT-URI to this config record.
    #[must_use]
    pub fn with_mod_list_uri(mut self, mod_list_uri: Option<String>) -> Self {
        self.mod_list_uri = mod_list_uri;
        self
    }

    /// Converts this record into a domain [`RuleRubric`].
    #[must_use]
    pub fn to_rubric(&self) -> RuleRubric {
        let sensitivity = sensitivity_from_db(Some(&self.sensitivity));
        let bounce_duration = bounce_duration_from_db(self.bounce_duration.as_deref());
        let prompt: String = self
            .rules
            .chars()
            .take(crate::classifier::MAX_RUBRIC_PROMPT_CHARS)
            .collect();
        RuleRubric {
            prompt,
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
    let tail = &description[start_idx..];
    if !tail.starts_with('{') {
        return None;
    }

    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut json_end: Option<usize> = None;

    for (idx, b) in tail.bytes().enumerate() {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    json_end = Some(idx + 1);
                    break;
                }
            }
            _ => {}
        }
    }

    let end_rel = json_end?;
    if !tail[end_rel..].trim_start().starts_with(']') {
        return None;
    }
    let json_str = &tail[..end_rel];

    let meta: ListMetadata = serde_json::from_str(json_str).ok()?;
    let sensitivity = sensitivity_from_db(Some(&meta.sensitivity));
    let bounce_duration = bounce_duration_from_db(meta.bounce_duration.as_deref());
    let prompt: String = meta
        .rules
        .chars()
        .take(crate::classifier::MAX_RUBRIC_PROMPT_CHARS)
        .collect();

    Some(RuleRubric {
        prompt,
        sensitivity,
        bounce_duration,
        bypass_incoming_followers: meta.bypass_incoming_followers,
    })
}

fn verify_repo_owner(pds_client: &PdsRepoClient, repo_did: &str) -> Result<(), SkybouncerError> {
    let clean_repo = crate::util::require_non_empty_did(repo_did, "repo_did")?;
    if pds_client.did() != clean_repo {
        return Err(SkybouncerError::Repo(format!(
            "PDS client DID '{}' does not match target repository DID '{clean_repo}'",
            pds_client.did()
        )));
    }
    Ok(())
}

/// Fetches the raw [`SovereignConfigRecord`] and its current record CID (if non-empty) from a
/// user's PDS repository.
///
/// # Errors
/// Returns [`SkybouncerError::Repo`] on repository DID mismatch, permanent network errors,
/// or JSON parse errors.
pub async fn fetch_sovereign_config_record(
    pds_client: &PdsRepoClient,
    repo_did: &str,
) -> Result<Option<(SovereignConfigRecord, Option<String>)>, SkybouncerError> {
    verify_repo_owner(pds_client, repo_did)?;

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
            let cid = (!record_view.cid.trim().is_empty()).then_some(record_view.cid);
            Ok(Some((record, cid)))
        }
        Err(e) => {
            let msg = e.to_string();
            if crate::util::is_pds_record_not_found(&msg) {
                Ok(None)
            } else {
                Err(SkybouncerError::Repo(format!(
                    "Failed to fetch sovereign config from PDS: {e}"
                )))
            }
        }
    }
}

/// Fetches sovereign configuration and its current record CID from `social.skybouncer.config/self`.
///
/// # Errors
/// Returns [`SkybouncerError::Repo`] on repository DID mismatch, permanent network errors,
/// or parse errors.
pub async fn fetch_sovereign_config_with_cid(
    pds_client: &PdsRepoClient,
    repo_did: &str,
) -> Result<Option<(RuleRubric, Option<String>)>, SkybouncerError> {
    Ok(fetch_sovereign_config_record(pds_client, repo_did)
        .await?
        .map(|(rec, cid)| (rec.to_rubric(), cid)))
}

/// Client helper fetching sovereign configuration from a user's PDS repository.
///
/// Attempts to read `social.skybouncer.config/self` via XRPC `com.atproto.repo.getRecord`.
///
/// # Errors
/// Returns [`SkybouncerError::Repo`] on repository DID mismatch, permanent network errors,
/// or parse errors.
pub async fn fetch_sovereign_config(
    pds_client: &PdsRepoClient,
    repo_did: &str,
) -> Result<Option<RuleRubric>, SkybouncerError> {
    Ok(fetch_sovereign_config_record(pds_client, repo_did)
        .await?
        .map(|(rec, _)| rec.to_rubric()))
}

/// Publishes or updates sovereign configuration to `social.skybouncer.config/self` on the user's PDS,
/// using `com.atproto.repo.putRecord` with `swapRecord` CAS and optional `mod_list_uri`.
///
/// # Errors
/// Returns [`SkybouncerError::Repo`] on repository DID mismatch or PDS mutation failure.
pub async fn publish_sovereign_config_with_options(
    pds_client: &PdsRepoClient,
    repo_did: &str,
    rubric: &RuleRubric,
    mod_list_uri: Option<&str>,
    swap_record: Option<&str>,
) -> Result<String, SkybouncerError> {
    verify_repo_owner(pds_client, repo_did)?;

    let (mut current_swap, mut resolved_list_uri) = if let Some(cid) = swap_record {
        (Some(cid.to_string()), mod_list_uri.map(str::to_string))
    } else {
        match fetch_sovereign_config_record(pds_client, repo_did).await? {
            Some((existing, cid)) => (
                cid,
                mod_list_uri.map(str::to_string).or(existing.mod_list_uri),
            ),
            None => (None, mod_list_uri.map(str::to_string)),
        }
    };

    for attempt in 0..2 {
        let record =
            SovereignConfigRecord::from_rubric(rubric).with_mod_list_uri(resolved_list_uri.clone());
        let value = serde_json::to_value(&record).map_err(|e| {
            SkybouncerError::Repo(format!("Failed to serialize sovereign config record: {e}"))
        })?;

        match pds_client
            .put_record_with_swap(
                SOVEREIGN_CONFIG_COLLECTION,
                SOVEREIGN_CONFIG_RKEY,
                &value,
                false,
                current_swap.as_deref(),
            )
            .await
        {
            Ok(put_res) => return Ok(put_res.uri),
            Err(e) if attempt == 0 && e.to_string().contains("InvalidSwap") => {
                let refreshed = fetch_sovereign_config_record(pds_client, repo_did).await?;
                match refreshed {
                    Some((existing, cid)) => {
                        current_swap = cid;
                        if mod_list_uri.is_none() {
                            resolved_list_uri = existing.mod_list_uri;
                        }
                    }
                    None => {
                        current_swap = None;
                    }
                }
            }
            Err(e) => {
                return Err(SkybouncerError::Repo(format!(
                    "Failed to put sovereign config record: {e}"
                )));
            }
        }
    }

    Err(SkybouncerError::Repo(
        "Failed to put sovereign config record after CAS retry".to_string(),
    ))
}

/// Publishes or updates sovereign configuration to `social.skybouncer.config/self` on the user's PDS.
///
/// Uses `com.atproto.repo.putRecord` with compare-and-swap (`swapRecord`).
///
/// # Errors
/// Returns [`SkybouncerError::Repo`] on repository DID mismatch or PDS mutation failure.
pub async fn publish_sovereign_config(
    pds_client: &PdsRepoClient,
    repo_did: &str,
    rubric: &RuleRubric,
) -> Result<String, SkybouncerError> {
    publish_sovereign_config_with_options(pds_client, repo_did, rubric, None, None).await
}
