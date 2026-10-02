//! Conversational command parser and dispatcher for the ATProto DM bot.
//!
//! Handles direct-message commands from Bluesky users:
//! - `help` / `?`: Show available commands and usage.
//! - `rules`: View active moderation rubric and sensitivity threshold.
//! - `set rules <prompt>`: Update active moderation rules.
//! - `sensitivity <low|medium|high>`: Update sensitivity threshold.
//! - `recent`: List recently bounced violators.
//! - `pardon <did>`: Pardon and remove an account from the moderation list.
//! - `status`: View engine operational telemetry and bounce counts.
//! - `test <text>`: Dry-run evaluation on sample text.

use std::sync::Arc;

use crate::classifier::{RuleRubric, Sensitivity, Verdict};
use crate::engine::SkybouncerEngine;
use crate::error::SkybouncerError;
use crate::matcher::Interaction;

/// Command parser and dispatcher for incoming direct messages.
#[derive(Clone)]
pub struct BotCommandHandler {
    engine: Arc<SkybouncerEngine>,
    bot_did: String,
}

impl BotCommandHandler {
    /// Creates a new [`BotCommandHandler`] bound to an engine instance and bot DID.
    #[must_use]
    pub fn new(engine: Arc<SkybouncerEngine>, bot_did: impl Into<String>) -> Self {
        Self {
            engine,
            bot_did: bot_did.into(),
        }
    }

    /// Returns the bot's own DID.
    #[must_use]
    pub fn bot_did(&self) -> &str {
        &self.bot_did
    }

    /// Dispatches an incoming direct message and generates a response.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if command execution fails.
    pub async fn handle_command(
        &self,
        sender_did: &str,
        message_text: &str,
    ) -> Result<String, SkybouncerError> {
        let trimmed = message_text.trim();
        if trimmed.is_empty() {
            return Ok("Type `help` to see available Skybouncer commands.".to_string());
        }

        if trimmed.eq_ignore_ascii_case("help") || trimmed == "?" {
            return Ok(self.cmd_help());
        }

        if trimmed.eq_ignore_ascii_case("rules") {
            return Ok(self.cmd_rules());
        }

        if trimmed.eq_ignore_ascii_case("set rules") {
            return self.cmd_set_rules("");
        }

        if let Some(prompt) = strip_prefix_ci(trimmed, "set rules ") {
            return self.cmd_set_rules(prompt);
        }

        if trimmed.eq_ignore_ascii_case("sensitivity") {
            return Ok("Usage: `sensitivity <low|medium|high>`".to_string());
        }

        if let Some(sens) = strip_prefix_ci(trimmed, "sensitivity ") {
            return self.cmd_set_sensitivity(sens.trim());
        }

        if trimmed.eq_ignore_ascii_case("recent") {
            return self.cmd_recent();
        }

        if trimmed.eq_ignore_ascii_case("pardon") {
            return Ok("Usage: `pardon <did>` (e.g. `pardon did:plc:...`)".to_string());
        }

        if let Some(target) = strip_prefix_ci(trimmed, "pardon ") {
            return self.cmd_pardon(sender_did, target.trim()).await;
        }

        if trimmed.eq_ignore_ascii_case("status") {
            return Ok(self.cmd_status());
        }

        if trimmed.eq_ignore_ascii_case("test") {
            return Ok("Usage: `test <text>` (dry-run evaluation on sample text)".to_string());
        }

        if let Some(sample) = strip_prefix_ci(trimmed, "test ") {
            return self.cmd_test(sender_did, sample.trim()).await;
        }

        Ok(format!(
            "Unknown command: `{trimmed}`\n\nType `help` to see available commands."
        ))
    }

    fn cmd_help(&self) -> String {
        "🛡️ Skybouncer Bot Commands:\n\n\
         • `rules` — View your active moderation prompt & sensitivity\n\
         • `set rules <prompt>` — Update your moderation prompt\n\
         • `sensitivity <low|medium|high>` — Adjust detection sensitivity\n\
         • `recent` — List the 5 most recently bounced accounts\n\
         • `pardon <did>` — Remove an account from your moderation list\n\
         • `status` — View engine telemetry & total bounces\n\
         • `test <text>` — Dry-run evaluation on sample text\n\
         • `help` — Show this help message"
            .to_string()
    }

    fn cmd_rules(&self) -> String {
        let rubric = self.engine.rubric();
        format!(
            "📋 Current Moderation Rubric:\n\n\
             Prompt: \"{}\"\n\
             Sensitivity: {} (threshold: {:.2})",
            rubric.prompt,
            rubric.sensitivity,
            rubric.sensitivity.threshold()
        )
    }

    fn cmd_set_rules(&self, prompt: &str) -> Result<String, SkybouncerError> {
        let prompt = prompt.trim();
        if prompt.is_empty() {
            return Ok("Please provide a moderation prompt. Example: `set rules Block crypto spam and bots.`".to_string());
        }

        let parsed = RuleRubric::parse(prompt)?;
        self.engine.set_rubric(parsed.clone());
        Ok(format!(
            "✅ Moderation rubric updated successfully!\n\n\
             Prompt: \"{}\"\n\
             Sensitivity: {}",
            parsed.prompt, parsed.sensitivity
        ))
    }

    fn cmd_set_sensitivity(&self, level: &str) -> Result<String, SkybouncerError> {
        let sens = match level {
            "low" => Sensitivity::Low,
            "medium" => Sensitivity::Medium,
            "high" => Sensitivity::High,
            _ => {
                return Ok(
                    "Invalid sensitivity level. Please use `low`, `medium`, or `high`.".to_string(),
                );
            }
        };

        let mut rubric = self.engine.rubric();
        rubric.sensitivity = sens;
        self.engine.set_rubric(rubric);

        Ok(format!(
            "✅ Sensitivity threshold updated to **{}** (confidence: {:.2}).",
            sens,
            sens.threshold()
        ))
    }

    fn cmd_recent(&self) -> Result<String, SkybouncerError> {
        let bounces = self.engine.list_recent_bounces(5)?;
        if bounces.is_empty() {
            return Ok("ℹ️ No accounts have been bounced yet.".to_string());
        }

        let mut out = String::from("🚫 Recently Bounced Accounts (last 5):\n\n");
        for (idx, b) in bounces.iter().enumerate() {
            let num = idx.saturating_add(1);
            out.push_str(&format!(
                "{num}. `{}` — **{}** ({:.0}% confidence)\n   Reason: {}\n",
                b.subject_did,
                b.category,
                b.confidence * 100.0,
                b.reason
            ));
        }

        Ok(out)
    }

    async fn cmd_pardon(
        &self,
        sender_did: &str,
        target_did: &str,
    ) -> Result<String, SkybouncerError> {
        let target_did = target_did.trim().trim_start_matches('@');
        if target_did.is_empty() {
            return Ok("Usage: `pardon <did>` (e.g. `pardon did:plc:...`)".to_string());
        }

        // Use sender_did as protected user if sender is protected, otherwise use first protected DID
        let protected_did = if self.engine.is_protected(sender_did) {
            sender_did.to_string()
        } else {
            self.engine
                .protected_dids()
                .into_iter()
                .next()
                .unwrap_or_else(|| sender_did.to_string())
        };

        match self.engine.pardon_user(&protected_did, target_did).await {
            Ok(true) => Ok(format!(
                "✅ Account `{target_did}` has been pardoned and removed from your moderation list."
            )),
            Ok(false) => Ok(format!(
                "ℹ️ Account `{target_did}` was not found in your bounced list."
            )),
            Err(e) => Ok(format!("❌ Failed to pardon account: {e}")),
        }
    }

    fn cmd_status(&self) -> String {
        let stats = self.engine.stats().snapshot();
        format!(
            "📊 Skybouncer Engine Status:\n\n\
             • Commits Received: {}\n\
             • Follows Synced: {}\n\
             • Interactions Matched: {}\n\
             • Bypassed (Followed Author): {}\n\
             • Bypassed (Self-Interaction): {}\n\
             • Dedup Cache Hits: {}\n\
             • Heuristic Pre-Filter Flags: {}\n\
             • Model Evaluations: {}\n\
             • Violations Detected: {}\n\
             • Bounces Executed on PDS: {}\n\
             • Permitted Interactions: {}",
            stats.commits_received,
            stats.follows_synced,
            stats.interactions_matched,
            stats.gate_bypassed_followed,
            stats.gate_bypassed_self,
            stats.dedup_cache_hits,
            stats.heuristic_violations,
            stats.model_evaluations,
            stats.violations_detected,
            stats.bounces_executed,
            stats.permitted,
        )
    }

    async fn cmd_test(&self, sender_did: &str, text: &str) -> Result<String, SkybouncerError> {
        let synthetic_interaction = Interaction {
            author_did: "did:plc:test-author-sample".to_string(),
            target_did: sender_did.to_string(),
            post_uri: "at://did:plc:test/app.bsky.feed.post/test1234".to_string(),
            post_cid: Some("bafytest1234".to_string()),
            text: text.to_string(),
            interaction_type: crate::matcher::InteractionType::DirectReply,
            parent_uri: None,
            root_uri: None,
            created_at_us: 0,
        };

        // Evaluate using heuristic first, then model
        let verdict = self
            .engine
            .heuristic_classifier()
            .evaluate(&synthetic_interaction);
        let final_verdict = if verdict.is_violation() {
            verdict
        } else {
            self.engine
                .primary_classifier()
                .classify(&synthetic_interaction)
                .await
                .unwrap_or(Verdict::Permitted {
                    reason: "Evaluation error or offline model".to_string(),
                })
        };

        match final_verdict {
            Verdict::Violation {
                category,
                confidence,
                reason,
            } => Ok(format!(
                "🔍 Test Evaluation: **VIOLATION**\n\n\
                 • Category: **{category}**\n\
                 • Confidence: **{:.1}%**\n\
                 • Reason: {reason}",
                confidence * 100.0
            )),
            Verdict::Permitted { reason } => Ok(format!(
                "🔍 Test Evaluation: **PERMITTED**\n\n\
                 • Rationale: {reason}"
            )),
        }
    }
}

/// Helper function performing case-insensitive prefix stripping on ASCII command prefixes.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    {
        s.get(prefix.len()..)
    } else {
        None
    }
}
