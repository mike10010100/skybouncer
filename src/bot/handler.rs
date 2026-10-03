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
    public_url: String,
}

impl BotCommandHandler {
    /// Creates a new [`BotCommandHandler`] bound to an engine instance and bot DID.
    #[must_use]
    pub fn new(engine: Arc<SkybouncerEngine>, bot_did: impl Into<String>) -> Self {
        let public_url = std::env::var("PUBLIC_URL")
            .or_else(|_| std::env::var("SKYBOUNCER_PUBLIC_URL"))
            .unwrap_or_else(|_| "https://skybouncer.mike10010100.com".to_string());
        Self {
            engine,
            bot_did: bot_did.into(),
            public_url,
        }
    }

    /// Sets the public base URL for onboarding authorization links.
    #[must_use]
    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// Returns the resolved 1-click authorization URL for account onboarding.
    #[must_use]
    pub fn auth_url(&self) -> String {
        format!("{}/auth", self.public_url.trim_end_matches('/'))
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

        let is_onboard_cmd = trimmed.eq_ignore_ascii_case("start")
            || trimmed.eq_ignore_ascii_case("onboard")
            || trimmed.eq_ignore_ascii_case("activate")
            || trimmed.eq_ignore_ascii_case("auth")
            || trimmed.eq_ignore_ascii_case("login")
            || trimmed.eq_ignore_ascii_case("join")
            || trimmed.eq_ignore_ascii_case("hi")
            || trimmed.eq_ignore_ascii_case("hello")
            || trimmed.eq_ignore_ascii_case("hey");

        if is_onboard_cmd {
            return Ok(self.cmd_onboarding(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("pause") {
            return Ok(self.cmd_pause(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("resume") {
            return Ok(self.cmd_resume(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("rules") {
            return Ok(self.cmd_rules(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("set rules") {
            return self.cmd_set_rules(sender_did, "");
        }

        if let Some(prompt) = strip_prefix_ci(trimmed, "set rules ") {
            return self.cmd_set_rules(sender_did, prompt);
        }

        if trimmed.eq_ignore_ascii_case("sensitivity") {
            return Ok("Usage: `sensitivity <low|medium|high>`".to_string());
        }

        if let Some(sens) = strip_prefix_ci(trimmed, "sensitivity ") {
            return self.cmd_set_sensitivity(sender_did, sens.trim());
        }

        if trimmed.eq_ignore_ascii_case("recent") {
            return self.cmd_recent();
        }

        if trimmed.eq_ignore_ascii_case("pardon") {
            return Ok("Usage: `pardon <did|@handle>` (e.g. `pardon did:plc:...` or `pardon @alice.bsky.social`)".to_string());
        }

        if let Some(target) = strip_prefix_ci(trimmed, "pardon ") {
            return self.cmd_pardon(sender_did, target.trim()).await;
        }

        if trimmed.eq_ignore_ascii_case("status") {
            return Ok(self.cmd_status(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("test") {
            return Ok("Usage: `test <text>` (dry-run evaluation on sample text)".to_string());
        }

        if let Some(sample) = strip_prefix_ci(trimmed, "test ") {
            return self.cmd_test(sender_did, sample.trim()).await;
        }

        let unknown_msg =
            format!("Unknown command: `{trimmed}`\n\nType `help` to see available commands.");
        if !self.engine.is_enrolled(sender_did) && !self.engine.is_protected(sender_did) {
            Ok(format!("{unknown_msg}\n\n(Tip: Your account is not yet protected. Visit {} to activate 1-click protection.)", self.auth_url()))
        } else {
            Ok(unknown_msg)
        }
    }

    fn cmd_help(&self) -> String {
        format!(
            "🛡️ Skybouncer Bot Commands:\n\n\
             • `rules` — View your active moderation prompt & sensitivity\n\
             • `set rules <prompt>` — Update your moderation prompt\n\
             • `sensitivity <low|medium|high>` — Adjust detection sensitivity\n\
             • `pause` — Temporarily suspend automated moderation\n\
             • `resume` — Reactivate automated moderation\n\
             • `recent` — List the 5 most recently bounced accounts\n\
             • `pardon <did|@handle>` — Remove an account from your moderation list\n\
             • `status` — View engine telemetry & total bounces\n\
             • `test <text>` — Dry-run evaluation on sample text\n\
             • `start` / `auth` — 1-click link to activate Skybouncer ({})\n\
             • `help` — Show this help message",
            self.auth_url()
        )
    }

    fn cmd_pause(&self, sender_did: &str) -> String {
        if self.engine.is_enrolled(sender_did) {
            let _ = self.engine.tenant_registry().set_active(sender_did, false);
        } else {
            let _ = self.engine.pause();
        }
        "⏸️ Skybouncer has been **paused**.\n\n\
         Automated moderation evaluations and PDS list mutations are temporarily suspended.\n\
         Send `resume` when you are ready to reactivate protection."
            .to_string()
    }

    fn cmd_resume(&self, sender_did: &str) -> String {
        if self.engine.is_enrolled(sender_did) {
            let _ = self.engine.tenant_registry().set_active(sender_did, true);
        } else {
            let _ = self.engine.resume();
        }
        "▶️ Skybouncer has been **resumed**.\n\n\
         Automated moderation evaluations and protection are now active."
            .to_string()
    }

    fn cmd_rules(&self, sender_did: &str) -> String {
        let rubric = self.engine.rubric_for(sender_did);
        format!(
            "📋 Current Moderation Rubric:\n\n\
             Prompt: \"{}\"\n\
             Sensitivity: {} (threshold: {:.2})",
            rubric.prompt,
            rubric.sensitivity,
            rubric.sensitivity.threshold()
        )
    }

    fn cmd_set_rules(&self, sender_did: &str, prompt: &str) -> Result<String, SkybouncerError> {
        let prompt = prompt.trim();
        if prompt.is_empty() {
            return Ok("Please provide a moderation prompt. Example: `set rules Block crypto spam and bots.`".to_string());
        }

        let parsed = RuleRubric::parse(prompt)?;
        if self.engine.is_enrolled(sender_did) {
            let _ = self
                .engine
                .tenant_registry()
                .update_rubric(sender_did, &parsed);
        } else {
            self.engine.set_rubric(parsed.clone());
        }

        // Asynchronously persist to sender's sovereign PDS repo
        let eng = self.engine.clone();
        let did = sender_did.to_string();
        tokio::spawn(async move {
            let _ = eng.publish_sovereign_config(&did).await;
        });

        Ok(format!(
            "✅ Moderation rubric updated successfully!\n\n\
             Prompt: \"{}\"\n\
             Sensitivity: {}",
            parsed.prompt, parsed.sensitivity
        ))
    }

    fn cmd_set_sensitivity(
        &self,
        sender_did: &str,
        level: &str,
    ) -> Result<String, SkybouncerError> {
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

        let mut rubric = self.engine.rubric_for(sender_did);
        rubric.sensitivity = sens;
        if self.engine.is_enrolled(sender_did) {
            let _ = self
                .engine
                .tenant_registry()
                .update_rubric(sender_did, &rubric);
        } else {
            self.engine.set_rubric(rubric);
        }

        // Asynchronously persist to sender's sovereign PDS repo
        let eng = self.engine.clone();
        let did = sender_did.to_string();
        tokio::spawn(async move {
            let _ = eng.publish_sovereign_config(&did).await;
        });

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
        raw_target: &str,
    ) -> Result<String, SkybouncerError> {
        let raw_target = raw_target.trim();
        if raw_target.is_empty() {
            return Ok("Usage: `pardon <did|@handle>` (e.g. `pardon did:plc:...` or `pardon @alice.bsky.social`)".to_string());
        }

        let clean = raw_target.trim_start_matches('@');
        let (resolved_did, was_handle) = if clean.starts_with("did:") {
            (clean.to_string(), false)
        } else {
            match self.engine.resolve_handle(clean).await {
                Some(did) => (did, true),
                None => {
                    return Ok(format!(
                        "❌ Could not resolve handle `@{clean}` to a DID. Please verify the handle or provide the account's DID directly (e.g. `pardon did:plc:...`)."
                    ));
                }
            }
        };

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

        let handle_prefix = if was_handle {
            format!("Resolved `@{clean}` to `{resolved_did}`.\n")
        } else {
            String::new()
        };

        match self.engine.pardon_user(&protected_did, &resolved_did).await {
            Ok(true) => Ok(format!(
                "{handle_prefix}✅ Account `{resolved_did}` has been pardoned and removed from your moderation list."
            )),
            Ok(false) => Ok(format!(
                "{handle_prefix}ℹ️ Account `{resolved_did}` was not found in your bounced list."
            )),
            Err(e) => Ok(format!("{handle_prefix}❌ Failed to pardon account: {e}")),
        }
    }

    fn cmd_status(&self, sender_did: &str) -> String {
        let stats = self.engine.stats().snapshot();
        let state_label = if self.engine.is_tenant_paused(sender_did) {
            "⏸️ PAUSED"
        } else {
            "▶️ ACTIVE"
        };
        format!(
            "📊 Skybouncer Engine Status:\n\n\
             • State: {}\n\
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
            state_label,
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

    fn cmd_onboarding(&self, sender_did: &str) -> String {
        let auth_url = self.auth_url();
        format!(
            "👋 Welcome to **Skybouncer** — your personal, sovereign automated bouncer for Bluesky!\n\n\
             Skybouncer monitors your incoming replies and mentions in real-time, using AI and your custom natural-language rules to catch spam bots, crypto schemes, and bad-faith harassment, placing them on your personal moderation list.\n\n\
             To activate 1-click protection for your account (`{sender_did}`), authorize Skybouncer here:\n\
             🔗 {auth_url}\n\n\
             Once authorized, your personal bouncer is live! You can message me anytime right here with:\n\
             • `rules` — View or update your moderation prompt\n\
             • `pause` / `resume` — Suspend or re-enable protection\n\
             • `status` — View your protection status and stats\n\
             • `help` — List all available commands"
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
            image_cids: Vec::new(),
            image_alts: Vec::new(),
            enriched_context: None,
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
                .unwrap_or_else(|_| Verdict::permitted("Evaluation error or offline model"))
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
            Verdict::Permitted { reason, confidence } => {
                let conf_str = confidence
                    .map(|c| format!("\n• Confidence: {:.1}%", c * 100.0))
                    .unwrap_or_default();
                Ok(format!(
                    "🔍 Test Evaluation: **PERMITTED**\n\n\
                     • Rationale: {reason}{conf_str}"
                ))
            }
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
