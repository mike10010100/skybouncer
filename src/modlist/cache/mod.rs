//! Thread-safe embedded SQLite deduplication and evaluation TTL cache.
//!
//! Provides a 3-table persistence engine:
//! - `mod_list_config`: stores provisioned moderation list metadata per protected user.
//! - `bounced_users`: records bounced violator DIDs and corresponding PDS listitem rkeys.
//! - `evaluation_cache`: caches classifier verdicts with configurable microsecond TTLs.
//!
//! Enforces zero lock holding across `.await` points by wrapping connections in
//! synchronous locks that are acquired and released exclusively inside method calls.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::classifier::Verdict;
use crate::error::SkybouncerError;
use crate::time::{current_time_us, i64_to_us, us_to_i64};

/// Persisted configuration of a provisioned ATProto moderation list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModListConfig {
    /// DID of the protected user owning this moderation list.
    pub user_did: String,
    /// Canonical AT-URI of the moderation list (`at://{did}/app.bsky.graph.list/{rkey}`).
    pub list_uri: String,
    /// Content identifier (CID) of the list record.
    pub list_cid: String,
    /// Microsecond Unix timestamp when the list was provisioned or discovered.
    pub created_at: u64,
}

/// Detailed record of a bounced violator persisted in SQLite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BouncedUser {
    /// Decentralized identifier (DID) of the bounced violator.
    pub subject_did: String,
    /// Protected user DID whose moderation list the violator was added to.
    #[serde(default)]
    pub protected_did: String,
    /// Canonical AT-URI of the created listitem record.
    pub listitem_uri: String,
    /// Record key (`rkey`) of the created listitem record on the PDS.
    pub listitem_rkey: String,
    /// Content identifier (CID) of the listitem record.
    pub listitem_cid: String,
    /// Category of the moderation violation.
    pub category: String,
    /// Classifier confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Human-readable or model-generated reason for the bounce.
    pub reason: String,
    /// AT-URI of the offending post that triggered the bounce.
    pub post_uri: String,
    /// Snippet or plaintext of the offending post that triggered the bounce.
    #[serde(default)]
    pub post_text: String,
    /// Microsecond Unix timestamp when the bounce was recorded.
    pub bounced_at: u64,
    /// Optional microsecond Unix timestamp when the temporary bounce expires (or `None` for permanent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl BouncedUser {
    /// Returns true if this bounce has an expiration timestamp and it has expired relative to `now_us`.
    #[must_use]
    pub fn is_expired(&self, now_us: u64) -> bool {
        self.expires_at.is_some_and(|exp| exp <= now_us)
    }
}

/// Canonical projection of `bounced_users` columns in [`map_bounced_user`] ordinal order.
pub(crate) const BOUNCED_USER_COLUMNS: &str = "subject_did, listitem_uri, listitem_rkey, \
     listitem_cid, category, confidence, reason, post_uri, bounced_at, protected_did, \
     post_text, expires_at";

/// Maps a `bounced_users` row (projected via [`BOUNCED_USER_COLUMNS`]) to a [`BouncedUser`].
pub(crate) fn map_bounced_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<BouncedUser> {
    let bounced_at = i64_to_us(row.get(8)?);
    let expires_at = row.get::<_, Option<i64>>(11)?.map(i64_to_us);
    Ok(BouncedUser {
        subject_did: row.get(0)?,
        listitem_uri: row.get(1)?,
        listitem_rkey: row.get(2)?,
        listitem_cid: row.get(3)?,
        category: row.get(4)?,
        confidence: row.get(5)?,
        reason: row.get(6)?,
        post_uri: row.get(7)?,
        bounced_at,
        protected_did: row.get(9)?,
        post_text: row.get(10)?,
        expires_at,
    })
}

/// Deletes all `bounced_users` and `bounced_user_rkeys` rows for `(protected_did, subject_did)`.
///
/// An empty `protected_did` matches the subject across every protected user.
fn delete_bounce_rows(
    tx: &rusqlite::Transaction<'_>,
    protected_did: &str,
    subject_did: &str,
) -> Result<(), SkybouncerError> {
    if protected_did.is_empty() {
        let mut delete_rkeys =
            tx.prepare_cached("DELETE FROM bounced_user_rkeys WHERE subject_did = ?1;")?;
        let _ = delete_rkeys.execute(params![subject_did]);

        let mut delete_stmt =
            tx.prepare_cached("DELETE FROM bounced_users WHERE subject_did = ?1;")?;
        delete_stmt.execute(params![subject_did])?;
    } else {
        let mut delete_rkeys = tx.prepare_cached(
            "DELETE FROM bounced_user_rkeys WHERE subject_did = ?1 AND protected_did = ?2;",
        )?;
        let _ = delete_rkeys.execute(params![subject_did, protected_did]);

        let mut delete_stmt = tx.prepare_cached(
            "DELETE FROM bounced_users WHERE subject_did = ?1 AND protected_did = ?2;",
        )?;
        delete_stmt.execute(params![subject_did, protected_did])?;
    }
    Ok(())
}

/// An account immunized on a protected user's moderation allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowlistEntry {
    /// Decentralized identifier (DID) of the protected user owning this allowlist.
    pub protected_did: String,
    /// Decentralized identifier (DID) of the allowed/immunized subject.
    #[serde(alias = "allowed_did")]
    pub subject_did: String,
    /// ATProto handle of the allowed subject, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Optional rationale explaining why the account was allowlisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Microsecond Unix timestamp when the entry was created.
    pub created_at: u64,
}

/// Comprehensive audit record of an AI evaluation (Tier 1 & Tier 2 breakdown) persisted in SQLite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationLogEntry {
    /// Auto-incrementing primary key ID.
    pub id: i64,
    /// Evaluation timestamp in microseconds since Unix epoch.
    pub timestamp_us: u64,
    /// Origin of this evaluation: "live" (Jetstream firehose) or "simulation" (test harness).
    pub source: String,
    /// Canonical AT-URI of the evaluated post.
    pub post_uri: String,
    /// Plaintext snippet or full text of the post.
    pub post_text: String,
    /// Decentralized identifier (DID) of the post author.
    pub author_did: String,
    /// ATProto handle of the author, if resolved.
    pub author_handle: String,
    /// Protected user DID targeted by this interaction.
    pub target_did: String,
    /// ATProto handle of the protected user, if resolved.
    pub target_handle: String,
    /// Whether the interaction included attached images.
    pub has_images: bool,
    /// Model name of the primary Tier-1 System-1 classifier.
    pub primary_model: String,
    /// Action emitted by Tier 1 ("allow" or "violation").
    pub primary_action: String,
    /// Confidence score from Tier 1 (0.0 to 1.0).
    pub primary_confidence: f64,
    /// Moderation category from Tier 1, if any.
    pub primary_category: String,
    /// Rationale emitted by Tier 1.
    pub primary_reason: String,
    /// Whether evaluation escalated to the Tier-2 fallback classifier.
    pub escalated: bool,
    /// Rationale explaining why escalation occurred or was bypassed.
    pub escalation_reason: Option<String>,
    /// Model name of the secondary Tier-2 fallback classifier, if escalated.
    pub fallback_model: Option<String>,
    /// Action emitted by Tier 2 ("allow" or "violation"), if escalated.
    pub fallback_action: Option<String>,
    /// Confidence score from Tier 2 (0.0 to 1.0), if escalated.
    pub fallback_confidence: Option<f64>,
    /// Moderation category from Tier 2, if escalated.
    pub fallback_category: Option<String>,
    /// Rationale emitted by Tier 2, if escalated.
    pub fallback_reason: Option<String>,
    /// Final verdict action adopted by the engine ("allow" or "violation").
    pub final_action: String,
    /// Final confidence score adopted by the engine.
    pub final_confidence: f64,
    /// Final operational outcome (e.g. "Bounced", "Permitted", "Below Rubric Threshold", "Rate Limited", etc.).
    pub outcome: String,
}

/// Unpersisted evaluation log record prepared for database insertion.
#[derive(Debug, Clone, PartialEq)]
pub struct NewEvaluationLog {
    /// Evaluation timestamp in microseconds since Unix epoch.
    pub timestamp_us: u64,
    /// Origin of this evaluation: "live" or "simulation".
    pub source: String,
    /// Canonical AT-URI of the evaluated post.
    pub post_uri: String,
    /// Plaintext snippet or full text of the post.
    pub post_text: String,
    /// Decentralized identifier (DID) of the post author.
    pub author_did: String,
    /// ATProto handle of the author, if resolved.
    pub author_handle: String,
    /// Protected user DID targeted by this interaction.
    pub target_did: String,
    /// ATProto handle of the protected user, if resolved.
    pub target_handle: String,
    /// Whether the interaction included attached images.
    pub has_images: bool,
    /// Model name of the primary Tier-1 System-1 classifier.
    pub primary_model: String,
    /// Action emitted by Tier 1 ("allow" or "violation").
    pub primary_action: String,
    /// Confidence score from Tier 1 (0.0 to 1.0).
    pub primary_confidence: f64,
    /// Moderation category from Tier 1, if any.
    pub primary_category: String,
    /// Rationale emitted by Tier 1.
    pub primary_reason: String,
    /// Whether evaluation escalated to the Tier-2 fallback classifier.
    pub escalated: bool,
    /// Rationale explaining why escalation occurred or was bypassed.
    pub escalation_reason: Option<String>,
    /// Model name of the secondary Tier-2 fallback classifier, if escalated.
    pub fallback_model: Option<String>,
    /// Action emitted by Tier 2 ("allow" or "violation"), if escalated.
    pub fallback_action: Option<String>,
    /// Confidence score from Tier 2 (0.0 to 1.0), if escalated.
    pub fallback_confidence: Option<f64>,
    /// Moderation category from Tier 2, if escalated.
    pub fallback_category: Option<String>,
    /// Rationale emitted by Tier 2, if escalated.
    pub fallback_reason: Option<String>,
    /// Final verdict action adopted by the engine.
    pub final_action: String,
    /// Final confidence score adopted by the engine.
    pub final_confidence: f64,
    /// Final operational outcome.
    pub outcome: String,
}

/// Origin and final outcome for an [`NewEvaluationLog`] audit record.
#[derive(Debug, Clone, Copy)]
pub struct EvaluationLogContext<'a> {
    /// Origin of the evaluation: `"live"` or `"simulation"`.
    pub source: &'a str,
    /// Final operational outcome label.
    pub outcome: &'a str,
}

impl NewEvaluationLog {
    /// Builds an audit log for a heuristic (regex pre-filter) violation, bypassing the model tiers.
    #[must_use]
    pub fn heuristic(
        interaction: &crate::matcher::Interaction,
        post_uri: &str,
        verdict: &Verdict,
        ctx: EvaluationLogContext<'_>,
        author_handle: String,
        target_handle: String,
    ) -> Self {
        Self {
            timestamp_us: current_time_us(),
            source: ctx.source.to_string(),
            post_uri: post_uri.to_string(),
            post_text: interaction.text.clone(),
            author_did: interaction.author_did.clone(),
            author_handle,
            target_did: interaction.target_did.clone(),
            target_handle,
            has_images: interaction.has_images(),
            primary_model: "heuristic_prefilter".to_string(),
            primary_action: "violation".to_string(),
            primary_confidence: 1.0,
            primary_category: verdict
                .category()
                .map(|c| c.to_string())
                .unwrap_or_default(),
            primary_reason: verdict.reason().to_string(),
            escalated: false,
            escalation_reason: Some("Heuristic regex instant match".to_string()),
            fallback_model: None,
            fallback_action: None,
            fallback_confidence: None,
            fallback_category: None,
            fallback_reason: None,
            final_action: "violation".to_string(),
            final_confidence: 1.0,
            outcome: ctx.outcome.to_string(),
        }
    }

    /// Builds an audit log from a tiered (primary + fallback) classifier evaluation.
    #[must_use]
    pub fn from_tiered(
        interaction: &crate::matcher::Interaction,
        post_uri: &str,
        detailed: &crate::classifier::TieredEvaluationResult,
        final_verdict: &Verdict,
        ctx: EvaluationLogContext<'_>,
        author_handle: String,
        target_handle: String,
    ) -> Self {
        let violation_label = |v: &Verdict| {
            if v.is_violation() {
                "violation".to_string()
            } else {
                "allow".to_string()
            }
        };
        Self {
            timestamp_us: current_time_us(),
            source: ctx.source.to_string(),
            post_uri: post_uri.to_string(),
            post_text: interaction.text.clone(),
            author_did: interaction.author_did.clone(),
            author_handle,
            target_did: interaction.target_did.clone(),
            target_handle,
            has_images: interaction.has_images(),
            primary_model: detailed.primary_model.clone(),
            primary_action: violation_label(&detailed.primary_verdict),
            primary_confidence: detailed.primary_verdict.confidence().unwrap_or(1.0),
            primary_category: detailed
                .primary_verdict
                .category()
                .map(|c| c.to_string())
                .unwrap_or_default(),
            primary_reason: detailed.primary_verdict.reason().to_string(),
            escalated: detailed.escalated,
            escalation_reason: detailed.escalation_reason.clone(),
            fallback_model: detailed.fallback_model.clone(),
            fallback_action: detailed.fallback_verdict.as_ref().map(violation_label),
            fallback_confidence: detailed
                .fallback_verdict
                .as_ref()
                .and_then(|v| v.confidence()),
            fallback_category: detailed
                .fallback_verdict
                .as_ref()
                .and_then(|v| v.category().map(|c| c.to_string())),
            fallback_reason: detailed
                .fallback_verdict
                .as_ref()
                .map(|v| v.reason().to_string()),
            final_action: violation_label(final_verdict),
            final_confidence: final_verdict.confidence().unwrap_or(1.0),
            outcome: ctx.outcome.to_string(),
        }
    }
}

/// Thread-safe embedded SQLite deduplication and evaluation TTL cache.
#[derive(Clone)]
pub struct DeduplicationCache {
    conn: Arc<Mutex<Connection>>,
}

mod allowlist;
mod bounces;
mod core;
mod dashboard;
mod evaluations;
mod handles;
mod modlist;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::classifier::ViolationCategory;

    /// Opens a fresh in-memory deduplication cache for tests.
    fn test_cache() -> DeduplicationCache {
        DeduplicationCache::open_in_memory().expect("open in-memory cache")
    }

    /// Builds an evaluation-log entry with benign defaults; override fields as needed.
    fn eval_log_fixture(timestamp_us: u64, author_did: &str, target_did: &str) -> NewEvaluationLog {
        NewEvaluationLog {
            timestamp_us,
            source: "live".to_string(),
            post_uri: format!("at://{author_did}/app.bsky.feed.post/1"),
            post_text: "Test text".to_string(),
            author_did: author_did.to_string(),
            author_handle: format!("{author_did}.bsky.social"),
            target_did: target_did.to_string(),
            target_handle: format!("{target_did}.bsky.social"),
            has_images: false,
            primary_model: "gemini-2.5-flash".to_string(),
            primary_action: "allow".to_string(),
            primary_confidence: 0.9,
            primary_category: String::new(),
            primary_reason: "Benign".to_string(),
            escalated: false,
            escalation_reason: None,
            fallback_model: None,
            fallback_action: None,
            fallback_confidence: None,
            fallback_category: None,
            fallback_reason: None,
            final_action: "allow".to_string(),
            final_confidence: 0.9,
            outcome: "Permitted".to_string(),
        }
    }

    /// Builds a bounce record with standard test defaults; override fields with struct update syntax.
    fn bounce_fixture(protected_did: &str, subject_did: &str) -> BouncedUser {
        BouncedUser {
            subject_did: subject_did.to_string(),
            protected_did: protected_did.to_string(),
            listitem_uri: format!("at://{protected_did}/app.bsky.graph.listitem/item1"),
            listitem_rkey: "item1".to_string(),
            listitem_cid: "bafyitemcid".to_string(),
            category: "crypto_spam".to_string(),
            confidence: 0.95,
            reason: "Test bounce".to_string(),
            post_uri: format!("at://{subject_did}/app.bsky.feed.post/1"),
            post_text: "Test post text".to_string(),
            bounced_at: 1_700_000_000,
            expires_at: None,
        }
    }

    #[test]
    fn test_mod_list_config_roundtrip() {
        let cache = test_cache();
        let config = ModListConfig {
            user_did: "did:plc:alice".to_string(),
            list_uri: "at://did:plc:alice/app.bsky.graph.list/123".to_string(),
            list_cid: "bafytestcid".to_string(),
            created_at: 1_700_000_000,
        };

        assert!(cache.get_mod_list("did:plc:alice").unwrap().is_none());
        cache.set_mod_list(&config).unwrap();

        let retrieved = cache.get_mod_list("did:plc:alice").unwrap().unwrap();
        assert_eq!(config, retrieved);

        // Update list_cid
        let updated = ModListConfig {
            list_cid: "bafyupdatedcid".to_string(),
            ..config
        };
        cache.set_mod_list(&updated).unwrap();
        let retrieved_updated = cache.get_mod_list("did:plc:alice").unwrap().unwrap();
        assert_eq!(retrieved_updated.list_cid, "bafyupdatedcid");
    }

    #[test]
    fn test_bounced_user_crud() {
        let cache = test_cache();
        let bounce = BouncedUser {
            protected_did: "did:plc:alice".to_string(),
            post_text: "Free airdrop at scam link".to_string(),
            ..bounce_fixture("did:plc:alice", "did:plc:badactor")
        };

        assert!(!cache.is_bounced("did:plc:badactor").unwrap());
        assert!(!cache
            .is_bounced_for("did:plc:alice", "did:plc:badactor")
            .unwrap());
        assert_eq!(cache.count_bounced().unwrap(), 0);

        cache.record_bounce(&bounce).unwrap();
        assert!(cache.is_bounced("did:plc:badactor").unwrap());
        assert!(cache
            .is_bounced_for("did:plc:alice", "did:plc:badactor")
            .unwrap());
        assert_eq!(cache.count_bounced().unwrap(), 1);

        let fetched = cache.get_bounced_user("did:plc:badactor").unwrap().unwrap();
        assert_eq!(fetched, bounce);

        let recent_alice = cache
            .list_recent_bounces_for(Some("did:plc:alice"), 10)
            .unwrap();
        assert_eq!(recent_alice.len(), 1);
        assert_eq!(recent_alice[0].post_text, "Free airdrop at scam link");

        // Remove bounce
        let rkey = cache.remove_bounce("did:plc:badactor").unwrap();
        assert_eq!(rkey.as_deref(), Some("item1"));
        assert!(!cache.is_bounced("did:plc:badactor").unwrap());
        assert!(!cache
            .is_bounced_for("did:plc:alice", "did:plc:badactor")
            .unwrap());
        assert_eq!(cache.count_bounced().unwrap(), 0);

        // Removing non-existent returns None
        assert!(cache.remove_bounce("did:plc:badactor").unwrap().is_none());
    }

    #[test]
    fn test_evaluation_ttl_and_pruning() {
        let cache = test_cache();
        let verdict = Verdict::Violation {
            category: ViolationCategory::Spam,
            confidence: 0.85,
            reason: "Automated mention spam".to_string(),
        };

        // Cache for 100ms
        cache
            .set_evaluation(
                "key1",
                "did:plc:spammer",
                &verdict,
                Duration::from_millis(100),
            )
            .unwrap();

        let cached = cache.get_evaluation("key1").unwrap();
        assert_eq!(cached, Some(verdict.clone()));

        // Expired evaluation (with 0ms TTL)
        cache
            .set_evaluation("key2", "did:plc:spammer2", &verdict, Duration::ZERO)
            .unwrap();

        // get_evaluation on expired item returns None and purges it
        let expired = cache.get_evaluation("key2").unwrap();
        assert_eq!(expired, None);

        // Pruning removes expired entries
        let pruned = cache.prune_expired_evaluations().unwrap();
        let _ = pruned;
    }

    #[test]
    fn test_legacy_schema_migration_order() {
        let conn = Connection::open_in_memory().unwrap();
        // Create the legacy table without protected_did or post_text
        conn.execute_batch(
            "
            CREATE TABLE bounced_users (
                subject_did TEXT PRIMARY KEY,
                listitem_uri TEXT NOT NULL,
                listitem_rkey TEXT NOT NULL,
                listitem_cid TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT NOT NULL,
                post_uri TEXT NOT NULL,
                bounced_at INTEGER NOT NULL
            );
            ",
        )
        .unwrap();

        // init_schema must smoothly migrate the legacy table and create the index without erroring
        DeduplicationCache::init_schema(&conn).unwrap();

        // Verify columns and index now exist
        let cache = DeduplicationCache {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
        };
        let bounce = BouncedUser {
            protected_did: "did:plc:legacy_owner".to_string(),
            reason: "Legacy migration test".to_string(),
            post_text: "Migrated text".to_string(),
            ..bounce_fixture("did:plc:legacy_owner", "did:plc:migrated_user")
        };
        cache.record_bounce(&bounce).unwrap();
        let fetched = cache
            .get_bounced_user("did:plc:migrated_user")
            .unwrap()
            .unwrap();
        assert_eq!(fetched.protected_did, "did:plc:legacy_owner");
        assert_eq!(fetched.post_text, "Migrated text");
    }

    #[test]
    fn test_evaluation_log_persistence_and_pruning() {
        let cache = test_cache();

        // 1. Record several evaluation log entries
        let entry1 = NewEvaluationLog {
            post_text: "Hey idiot".to_string(),
            primary_action: "violation".to_string(),
            primary_confidence: 0.92,
            primary_category: "harassment".to_string(),
            primary_reason: "Personal insult".to_string(),
            escalation_reason: Some("High primary confidence".to_string()),
            final_action: "violation".to_string(),
            final_confidence: 0.92,
            outcome: "Bounced".to_string(),
            ..eval_log_fixture(1_000_000, "did:plc:author1", "did:plc:target1")
        };

        let entry2 = NewEvaluationLog {
            post_uri: "at://did:plc:author2/app.bsky.feed.post/2".to_string(),
            post_text: "Look at this image".to_string(),
            has_images: true,
            primary_action: "allow".to_string(),
            primary_confidence: 0.45,
            primary_reason: "Text benign, requires vision inspection".to_string(),
            escalated: true,
            escalation_reason: Some("Attached visual image".to_string()),
            fallback_model: Some("gemini-2.5-pro".to_string()),
            fallback_action: Some("violation".to_string()),
            fallback_confidence: Some(0.88),
            fallback_category: Some("hate_speech".to_string()),
            fallback_reason: Some("Offensive imagery detected".to_string()),
            final_action: "violation".to_string(),
            final_confidence: 0.88,
            outcome: "Bounced".to_string(),
            ..eval_log_fixture(2_000_000, "did:plc:author2", "did:plc:target1")
        };

        let entry3 = NewEvaluationLog {
            source: "simulation".to_string(),
            post_uri: "at://did:plc:sim/app.bsky.feed.post/sim".to_string(),
            post_text: "Synthetic test".to_string(),
            author_did: "did:plc:sim".to_string(),
            primary_confidence: 0.99,
            primary_reason: "Benign question".to_string(),
            final_confidence: 0.99,
            ..eval_log_fixture(3_000_000, "did:plc:sim", "did:plc:target2")
        };

        let id1 = cache.record_evaluation_log(&entry1).unwrap();
        let id2 = cache.record_evaluation_log(&entry2).unwrap();
        let id3 = cache.record_evaluation_log(&entry3).unwrap();
        assert!(id1 > 0 && id2 > id1 && id3 > id2);

        // 2. Count verification
        assert_eq!(cache.count_evaluation_logs(None, None).unwrap(), 3);
        assert_eq!(
            cache
                .count_evaluation_logs(Some("did:plc:target1"), None)
                .unwrap(),
            2
        );
        assert_eq!(
            cache
                .count_evaluation_logs(None, Some("simulation"))
                .unwrap(),
            1
        );
        assert_eq!(cache.count_evaluation_logs(None, Some("live")).unwrap(), 2);

        // 3. List verification (ordered descending by timestamp)
        let all_logs = cache.list_evaluation_logs(None, None, 10, 0).unwrap();
        assert_eq!(all_logs.len(), 3);
        assert_eq!(all_logs[0].id, id3); // timestamp 3_000_000
        assert_eq!(all_logs[1].id, id2); // timestamp 2_000_000
        assert_eq!(all_logs[2].id, id1); // timestamp 1_000_000

        // Detailed field checks on escalated entry
        assert!(all_logs[1].escalated);
        assert_eq!(
            all_logs[1].fallback_model.as_deref(),
            Some("gemini-2.5-pro")
        );
        assert_eq!(
            all_logs[1].fallback_category.as_deref(),
            Some("hate_speech")
        );
        assert!(all_logs[1].has_images);

        // Filter by target
        let target1_logs = cache
            .list_evaluation_logs(Some("did:plc:target1"), None, 10, 0)
            .unwrap();
        assert_eq!(target1_logs.len(), 2);
        assert_eq!(target1_logs[0].author_did, "did:plc:author2");

        // 4. Pruning verification
        // Pruning retaining max 2 removes the oldest record (id1)
        let deleted = cache.prune_evaluation_logs(2).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(cache.count_evaluation_logs(None, None).unwrap(), 2);
        let remaining = cache.list_evaluation_logs(None, None, 10, 0).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].id, id3);
        assert_eq!(remaining[1].id, id2);
    }

    #[test]
    fn test_multitenant_bounce_isolation() {
        let cache = test_cache();

        let bounce_a = BouncedUser {
            listitem_uri: "at://did:plc:tenant_a/app.bsky.graph.listitem/item_a".to_string(),
            listitem_rkey: "item_a".to_string(),
            listitem_cid: "bafyitema".to_string(),
            category: "spam".to_string(),
            confidence: 0.99,
            reason: "Spam for A".to_string(),
            post_text: "Spam text".to_string(),
            ..bounce_fixture("did:plc:tenant_a", "did:plc:spammer")
        };

        let bounce_b = BouncedUser {
            listitem_uri: "at://did:plc:tenant_b/app.bsky.graph.listitem/item_b".to_string(),
            listitem_rkey: "item_b".to_string(),
            listitem_cid: "bafyitemb".to_string(),
            category: "harassment".to_string(),
            confidence: 0.95,
            reason: "Harassment for B".to_string(),
            post_uri: "at://did:plc:spammer/app.bsky.feed.post/2".to_string(),
            post_text: "Harassment text".to_string(),
            bounced_at: 1_700_000_100,
            ..bounce_fixture("did:plc:tenant_b", "did:plc:spammer")
        };

        // Record bounces for both tenants
        cache.record_bounce(&bounce_a).unwrap();
        cache.record_bounce(&bounce_b).unwrap();

        // Both are bounced in their respective tenant contexts
        assert!(cache
            .is_bounced_for("did:plc:tenant_a", "did:plc:spammer")
            .unwrap());
        assert!(cache
            .is_bounced_for("did:plc:tenant_b", "did:plc:spammer")
            .unwrap());
        assert!(!cache
            .is_bounced_for("did:plc:tenant_c", "did:plc:spammer")
            .unwrap());

        // Recent bounces list isolates records
        let list_a = cache
            .list_recent_bounces_for(Some("did:plc:tenant_a"), 10)
            .unwrap();
        assert_eq!(list_a.len(), 1);
        assert_eq!(list_a[0].listitem_rkey, "item_a");

        let list_b = cache
            .list_recent_bounces_for(Some("did:plc:tenant_b"), 10)
            .unwrap();
        assert_eq!(list_b.len(), 1);
        assert_eq!(list_b[0].listitem_rkey, "item_b");

        let list_c = cache
            .list_recent_bounces_for(Some("did:plc:tenant_c"), 10)
            .unwrap();
        assert_eq!(list_c.len(), 0);

        // Tenant A pardons spammer
        let removed = cache
            .remove_bounce_for("did:plc:tenant_a", "did:plc:spammer")
            .unwrap();
        assert_eq!(removed.as_deref(), Some("item_a"));

        // Tenant A no longer has spammer bounced, but Tenant B STILL DOES!
        assert!(!cache
            .is_bounced_for("did:plc:tenant_a", "did:plc:spammer")
            .unwrap());
        assert!(cache
            .is_bounced_for("did:plc:tenant_b", "did:plc:spammer")
            .unwrap());

        let list_b_after = cache
            .list_recent_bounces_for(Some("did:plc:tenant_b"), 10)
            .unwrap();
        assert_eq!(list_b_after.len(), 1);
        assert_eq!(list_b_after[0].listitem_rkey, "item_b");
    }

    #[test]
    fn test_bounced_rkey_aliases_and_expiry_and_count() {
        let cache = test_cache();
        // Multi-rkey accumulation via record_bounce (which also populates bounced_user_rkeys).
        let mut entry = bounce_fixture("did:plc:alice", "did:plc:spammer");
        entry.listitem_rkey = "rk1".to_string();
        entry.expires_at = Some(1_700_000_500);
        cache.record_bounce(&entry).unwrap();

        // Re-record with a new rkey for the same subject/protected pair.
        let mut entry2 = entry.clone();
        entry2.listitem_rkey = "rk2".to_string();
        cache.record_bounce(&entry2).unwrap();

        let scoped = cache
            .get_all_bounced_rkeys_for("did:plc:alice", "did:plc:spammer")
            .unwrap();
        assert!(scoped.contains(&"rk1".to_string()));
        assert!(scoped.contains(&"rk2".to_string()));

        // Unscoped aliases.
        let all = cache.get_all_bounced_rkeys("did:plc:spammer").unwrap();
        assert!(all.contains(&"rk1".to_string()));
        let alias = cache.get_bounced_rkeys("did:plc:spammer").unwrap();
        assert_eq!(all, alias);

        // list_recent_bounces (unscoped) and count.
        assert_eq!(cache.count_bounced().unwrap(), 1);
        assert_eq!(cache.list_recent_bounces(10).unwrap().len(), 1);

        // Expiry query returns the entry once now exceeds expires_at.
        assert_eq!(cache.list_expired_bounces(1_700_000_400).unwrap().len(), 0);
        assert_eq!(cache.list_expired_bounces(1_700_000_600).unwrap().len(), 1);
    }

    #[test]
    fn test_remove_all_bounces_and_scoped_removal() {
        let cache = test_cache();
        let mut e = bounce_fixture("did:plc:alice", "did:plc:spammer");
        e.listitem_rkey = "rka".to_string();
        cache.record_bounce(&e).unwrap();
        let mut e2 = e.clone();
        e2.listitem_rkey = "rkb".to_string();
        cache.record_bounce(&e2).unwrap();

        let removed = cache
            .remove_all_bounces_for("did:plc:alice", "did:plc:spammer")
            .unwrap();
        assert!(!removed.is_empty());
        assert_eq!(cache.count_bounced().unwrap(), 0);
        // Removing again yields empty.
        assert!(cache
            .remove_all_bounces_for("did:plc:alice", "did:plc:spammer")
            .unwrap()
            .is_empty());

        // Unscoped remove_all_bounces alias after re-adding.
        cache.record_bounce(&e).unwrap();
        assert!(!cache
            .remove_all_bounces("did:plc:spammer")
            .unwrap()
            .is_empty());
        assert_eq!(cache.count_bounced().unwrap(), 0);
    }

    #[test]
    fn test_get_bounced_user_scoped_and_unscoped() {
        let cache = test_cache();
        let e = bounce_fixture("did:plc:alice", "did:plc:spammer");
        cache.record_bounce(&e).unwrap();

        assert!(cache.get_bounced_user("did:plc:spammer").unwrap().is_some());
        assert!(cache
            .get_bounced_user_for("did:plc:alice", "did:plc:spammer")
            .unwrap()
            .is_some());
        assert!(cache
            .get_bounced_user_for("did:plc:other", "did:plc:spammer")
            .unwrap()
            .is_none());
        // Whitespace/empty protected DID falls back to the unscoped query.
        assert!(cache
            .get_bounced_user_for("   ", "did:plc:spammer")
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_legacy_bounced_user_rkeys_fk_migration() {
        let conn = Connection::open_in_memory().unwrap();
        // Legacy bounced_users with single-column PK + a bounced_user_rkeys that has a
        // foreign key referencing bounced_users, forcing both migration branches.
        conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            CREATE TABLE bounced_users (
                subject_did TEXT PRIMARY KEY,
                listitem_uri TEXT NOT NULL,
                listitem_rkey TEXT NOT NULL,
                listitem_cid TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT NOT NULL,
                post_uri TEXT NOT NULL,
                bounced_at INTEGER NOT NULL
            );
            CREATE TABLE bounced_user_rkeys (
                subject_did TEXT NOT NULL,
                listitem_rkey TEXT NOT NULL PRIMARY KEY,
                listitem_uri TEXT NOT NULL,
                listitem_cid TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (subject_did) REFERENCES bounced_users(subject_did)
            );
            ",
        )
        .unwrap();

        DeduplicationCache::init_schema(&conn).expect("migrate legacy rkeys FK");

        // The migrated rkeys table accepts composite-key inserts.
        let cache = DeduplicationCache {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
        };
        let bounce = bounce_fixture("did:plc:alice", "did:plc:spammer");
        cache.record_bounce(&bounce).unwrap();
        assert!(cache
            .get_all_bounced_rkeys_for("did:plc:alice", "did:plc:spammer")
            .unwrap()
            .contains(&bounce.listitem_rkey));
    }

    #[test]
    fn test_allowlist_crud_and_loading() {
        let cache = test_cache();

        assert!(!cache
            .is_allowlisted("did:plc:alice", "did:plc:friend")
            .unwrap());

        cache
            .add_to_allowlist("did:plc:alice", "did:plc:friend", Some("Friend of mine"))
            .unwrap();
        cache
            .add_to_allowlist("did:plc:alice", "did:plc:colleague", None)
            .unwrap();
        cache
            .add_to_allowlist("did:plc:bob", "did:plc:partner", Some("Work partner"))
            .unwrap();

        assert!(cache
            .is_allowlisted("did:plc:alice", "did:plc:friend")
            .unwrap());
        assert!(cache
            .is_allowlisted("did:plc:alice", "did:plc:colleague")
            .unwrap());
        assert!(!cache
            .is_allowlisted("did:plc:alice", "did:plc:partner")
            .unwrap());
        assert!(cache
            .is_allowlisted("did:plc:bob", "did:plc:partner")
            .unwrap());

        let alice_list = cache.list_allowlist("did:plc:alice").unwrap();
        assert_eq!(alice_list.len(), 2);
        assert!(alice_list
            .iter()
            .any(|e| e.subject_did == "did:plc:friend"
                && e.reason.as_deref() == Some("Friend of mine")));

        let all_map = cache.load_all_allowlists().unwrap();
        assert_eq!(all_map.get("did:plc:alice").unwrap().len(), 2);
        assert_eq!(all_map.get("did:plc:bob").unwrap().len(), 1);

        let removed = cache
            .remove_from_allowlist("did:plc:alice", "did:plc:friend")
            .unwrap();
        assert!(removed);
        assert!(!cache
            .is_allowlisted("did:plc:alice", "did:plc:friend")
            .unwrap());

        let removed_again = cache
            .remove_from_allowlist("did:plc:alice", "did:plc:friend")
            .unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn test_did_handle_cache_roundtrip_and_normalization() {
        let cache = test_cache();

        let did = "did:plc:7nf3vqbvea5gpbet3kmibxpm";
        let handle = "valoisdubins.bsky.social";

        // Unresolved lookups return None
        assert_eq!(cache.get_handle_for_did(did).unwrap(), None);
        assert_eq!(cache.get_did_for_handle(handle).unwrap(), None);

        // Store with surrounding whitespace and leading '@' to verify normalization
        cache
            .set_handle_for_did(&format!("  {did}  "), &format!("@{handle}"))
            .unwrap();

        assert_eq!(
            cache.get_handle_for_did(did).unwrap().as_deref(),
            Some(handle)
        );
        // get_did_for_handle trims '@' and is case-insensitive
        assert_eq!(
            cache.get_did_for_handle(handle).unwrap().as_deref(),
            Some(did)
        );
        assert_eq!(
            cache
                .get_did_for_handle(&format!("  @{}  ", handle.to_uppercase()))
                .unwrap()
                .as_deref(),
            Some(did)
        );

        // Upsert updates the existing mapping in place
        let updated = "newhandle.bsky.social";
        cache.set_handle_for_did(did, updated).unwrap();
        assert_eq!(
            cache.get_handle_for_did(did).unwrap().as_deref(),
            Some(updated)
        );
        assert_eq!(cache.get_did_for_handle(handle).unwrap(), None);
        assert_eq!(
            cache.get_did_for_handle(updated).unwrap().as_deref(),
            Some(did)
        );

        // Empty inputs are a no-op and never persisted
        cache.set_handle_for_did("   ", "some.handle").unwrap();
        cache.set_handle_for_did(did, "   ").unwrap();
        assert_eq!(cache.get_handle_for_did("").unwrap(), None);
    }

    #[test]
    fn test_get_did_for_handle_with_ttl() {
        let cache = test_cache();
        let did = "did:plc:ttluser";
        let handle = "ttluser.bsky.social";

        // Missing mapping returns None.
        assert_eq!(
            cache.get_did_for_handle_with_ttl(handle, u64::MAX).unwrap(),
            None
        );

        cache.set_handle_for_did(did, handle).unwrap();

        // A generous TTL returns the freshly written mapping.
        assert_eq!(
            cache
                .get_did_for_handle_with_ttl(handle, u64::MAX)
                .unwrap()
                .as_deref(),
            Some(did)
        );

        // A zero TTL treats the mapping as stale (cutoff == now), excluding it.
        assert_eq!(cache.get_did_for_handle_with_ttl(handle, 0).unwrap(), None);

        // The non-TTL lookup still sees the mapping regardless of age.
        assert_eq!(
            cache.get_did_for_handle(handle).unwrap().as_deref(),
            Some(did)
        );

        // remove_handle_for_handle clears it from all lookups.
        let removed = cache.remove_handle_for_handle(handle).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            cache.get_did_for_handle_with_ttl(handle, u64::MAX).unwrap(),
            None
        );
    }

    #[test]
    fn test_prune_did_handles_by_age_and_capacity() {
        let cache = test_cache();

        // All inserted with "now"; a zero cutoff ages out nothing, so only the
        // capacity bound should apply.
        for i in 0..10 {
            cache
                .set_handle_for_did(&format!("did:plc:user{i}"), &format!("user{i}.bsky.social"))
                .unwrap();
        }

        // Capacity bound retains the 3 most recently updated entries.
        let deleted = cache.prune_did_handles(0, 3).unwrap();
        assert_eq!(deleted, 7);
        let remaining = (0..10)
            .filter(|i| {
                cache
                    .get_handle_for_did(&format!("did:plc:user{i}"))
                    .unwrap()
                    .is_some()
            })
            .count();
        assert_eq!(remaining, 3);

        // A cutoff in the future expires all remaining rows regardless of capacity.
        let all_deleted = cache.prune_did_handles(u64::MAX, 1000).unwrap();
        assert_eq!(all_deleted, 3);

        // Zero cutoff with max_retained=0 still keeps at least one row (max(1)).
        cache
            .set_handle_for_did("did:plc:only", "only.bsky.social")
            .unwrap();
        assert_eq!(cache.prune_did_handles(0, 0).unwrap(), 0);
        assert!(cache.get_handle_for_did("did:plc:only").unwrap().is_some());
    }

    #[test]
    fn test_allowlist_handle_enrichment_via_join() {
        let cache = test_cache();

        let protected = "did:plc:alice";
        let friend_did = "did:plc:friend";
        let stranger_did = "did:plc:stranger";

        cache
            .add_to_allowlist(protected, friend_did, Some("Friend of mine"))
            .unwrap();
        cache
            .add_to_allowlist(protected, stranger_did, None)
            .unwrap();

        // Only the friend has a cached handle; the stranger resolves to None.
        cache
            .set_handle_for_did(friend_did, "friend.bsky.social")
            .unwrap();

        let entries = cache.list_allowlist(protected).unwrap();
        assert_eq!(entries.len(), 2);

        let friend = entries
            .iter()
            .find(|e| e.subject_did == friend_did)
            .expect("friend entry present");
        assert_eq!(friend.handle.as_deref(), Some("friend.bsky.social"));

        let stranger = entries
            .iter()
            .find(|e| e.subject_did == stranger_did)
            .expect("stranger entry present");
        assert_eq!(stranger.handle, None);
    }

    #[test]
    fn test_dashboard_stats_roundtrip_and_upsert() {
        let cache = test_cache();

        // No snapshot persisted yet.
        let missing: Option<serde_json::Value> = cache.load_dashboard_stats().unwrap();
        assert!(missing.is_none());

        let first = serde_json::json!({ "commits_received": 42_u64, "bounces_executed": 7_u64 });
        cache.save_dashboard_stats(&first).unwrap();
        let loaded: Option<serde_json::Value> = cache.load_dashboard_stats().unwrap();
        assert_eq!(loaded, Some(first));

        // Upsert replaces the single well-known row rather than appending.
        let second = serde_json::json!({ "commits_received": 100_u64, "bounces_executed": 9_u64 });
        cache.save_dashboard_stats(&second).unwrap();
        let loaded: Option<serde_json::Value> = cache.load_dashboard_stats().unwrap();
        assert_eq!(loaded, Some(second));

        let conn = cache.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM dashboard_stats;", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_dashboard_stats_corrupt_payload_returns_none() {
        let cache = test_cache();
        {
            let conn = cache.conn.lock();
            conn.execute(
                "INSERT INTO dashboard_stats (id, snapshot_json, updated_at) VALUES (1, 'not-json', 0);",
                [],
            )
            .unwrap();
        }
        let loaded: Option<serde_json::Value> = cache.load_dashboard_stats().unwrap();
        assert!(loaded.is_none());
    }
}
