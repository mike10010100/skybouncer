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
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok(self.cmd_pause(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("resume") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok(self.cmd_resume(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("rules") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok(self.cmd_rules(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("set rules") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_set_rules(sender_did, "");
        }

        if let Some(prompt) = strip_prefix_ci(trimmed, "set rules ") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_set_rules(sender_did, prompt);
        }

        if trimmed.eq_ignore_ascii_case("sensitivity") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok("Usage: `sensitivity <low|medium|high>`".to_string());
        }

        if let Some(sens) = strip_prefix_ci(trimmed, "sensitivity ") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_set_sensitivity(sender_did, sens.trim());
        }

        if trimmed.eq_ignore_ascii_case("duration") || trimmed.eq_ignore_ascii_case("timeout") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok("Usage: `duration <permanent|24h|7d|30d>`".to_string());
        }

        if let Some(dur) = strip_prefix_ci(trimmed, "duration ")
            .or_else(|| strip_prefix_ci(trimmed, "timeout "))
            .or_else(|| strip_prefix_ci(trimmed, "set duration "))
            .or_else(|| strip_prefix_ci(trimmed, "set timeout "))
        {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_set_duration(sender_did, dur.trim());
        }

        if trimmed.eq_ignore_ascii_case("recent") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_recent(sender_did);
        }

        if trimmed.eq_ignore_ascii_case("allowlist") || trimmed.eq_ignore_ascii_case("allow list") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_allowlist(sender_did);
        }

        if trimmed.eq_ignore_ascii_case("allow") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok(
                "Usage: `allow <did|@handle>` (e.g. `allow @alice.bsky.social`)".to_string(),
            );
        }

        if let Some(target) = strip_prefix_ci(trimmed, "allow ") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_allow(sender_did, target.trim()).await;
        }

        if trimmed.eq_ignore_ascii_case("unallow") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok(
                "Usage: `unallow <did|@handle>` (e.g. `unallow @alice.bsky.social`)".to_string(),
            );
        }

        if let Some(target) = strip_prefix_ci(trimmed, "unallow ") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_unallow(sender_did, target.trim()).await;
        }

        if trimmed.eq_ignore_ascii_case("pardon") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok(
                "Usage: `pardon <did|@handle>` or `pardon and allow <did|@handle>`".to_string(),
            );
        }

        if let Some(target) = strip_prefix_ci(trimmed, "pardon and allow ") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_pardon_and_allow(sender_did, target.trim()).await;
        }

        if let Some(target) = strip_prefix_ci(trimmed, "pardon ") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            if let Some(immunized_target) = strip_prefix_ci(target.trim(), "and allow ") {
                return self
                    .cmd_pardon_and_allow(sender_did, immunized_target.trim())
                    .await;
            }
            return self.cmd_pardon(sender_did, target.trim()).await;
        }

        if trimmed.eq_ignore_ascii_case("status") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok(self.cmd_status(sender_did));
        }

        if trimmed.eq_ignore_ascii_case("test") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
            return Ok("Usage: `test <text>` (dry-run evaluation on sample text)".to_string());
        }

        if let Some(sample) = strip_prefix_ci(trimmed, "test ") {
            if !self.is_authorized_sender(sender_did) {
                return Ok(self.unauthorized_response());
            }
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
             • `duration <permanent|24h|7d|30d>` — Set timeout/cooldown duration\n\
             • `pause` — Temporarily suspend automated moderation\n\
             • `resume` — Reactivate automated moderation\n\
             • `recent` — List the 5 most recently bounced accounts\n\
             • `pardon <did|@handle>` — Remove an account from your moderation list\n\
             • `pardon and allow <did|@handle>` — Pardon and permanently immunize\n\
             • `allow <did|@handle>` — Add trusted account to your allowlist\n\
             • `unallow <did|@handle>` — Remove account from your allowlist\n\
             • `allowlist` — View your allowlisted accounts\n\
             • `status` — View engine telemetry & total bounces\n\
             • `test <text>` — Dry-run evaluation on sample text\n\
             • `start` / `auth` — 1-click link to activate Skybouncer ({})\n\
             • `help` — Show this help message",
            self.auth_url()
        )
    }

    fn cmd_pause(&self, sender_did: &str) -> String {
        if self.engine.is_enrolled(sender_did) {
            if let Err(e) = self.engine.tenant_registry().set_active(sender_did, false) {
                tracing::warn!(error = %e, sender_did, "Failed to pause tenant in registry");
                return format!("⚠️ Failed to update pause status: {e}");
            }
        } else if self.engine.is_admin(sender_did)
            || (self.engine.is_single_tenant() && self.engine.is_protected(sender_did))
        {
            let _ = self.engine.pause();
        } else {
            return "❌ You can only pause moderation for your own enrolled account.".to_string();
        }
        "⏸️ Skybouncer has been **paused**.\n\n\
         Automated moderation evaluations and PDS list mutations are temporarily suspended.\n\
         Send `resume` when you are ready to reactivate protection."
            .to_string()
    }

    fn cmd_resume(&self, sender_did: &str) -> String {
        if self.engine.is_enrolled(sender_did) {
            if let Err(e) = self.engine.tenant_registry().set_active(sender_did, true) {
                tracing::warn!(error = %e, sender_did, "Failed to resume tenant in registry");
                return format!("⚠️ Failed to update resume status: {e}");
            }
        } else if self.engine.is_admin(sender_did)
            || (self.engine.is_single_tenant() && self.engine.is_protected(sender_did))
        {
            let _ = self.engine.resume();
        } else {
            return "❌ You can only resume moderation for your own enrolled account.".to_string();
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
             Sensitivity: {} (threshold: {:.2})\n\
             Duration: {}",
            rubric.prompt,
            rubric.sensitivity,
            rubric.sensitivity.threshold(),
            rubric.bounce_duration.display_label()
        )
    }

    fn cmd_set_rules(&self, sender_did: &str, prompt: &str) -> Result<String, SkybouncerError> {
        let prompt = prompt.trim();
        if prompt.is_empty() {
            return Ok("Please provide a moderation prompt. Example: `set rules Block crypto spam and bots.`".to_string());
        }

        let parsed = RuleRubric::parse(prompt)?;
        if self.engine.is_enrolled(sender_did) {
            if let Err(e) = self
                .engine
                .tenant_registry()
                .update_rubric(sender_did, &parsed)
            {
                tracing::warn!(error = %e, sender_did, "Failed to update tenant rubric in registry");
                return Ok(format!("❌ Failed to update rubric: {e}"));
            }
        } else if self.engine.is_admin(sender_did)
            || (self.engine.is_single_tenant() && self.engine.is_protected(sender_did))
        {
            self.engine.set_rubric(parsed.clone());
        } else {
            return Ok("❌ You can only update rules for your own enrolled account.".to_string());
        }

        // Asynchronously persist to sender's sovereign PDS repo
        let eng = self.engine.clone();
        let did = sender_did.to_string();
        tokio::spawn(async move {
            if let Err(e) = eng.publish_sovereign_config(&did).await {
                tracing::warn!(error = %e, did = %did, "Failed to publish sovereign config to PDS");
            }
        });

        Ok(format!(
            "✅ Moderation rubric updated successfully!\n\n\
             Prompt: \"{}\"\n\
             Sensitivity: {}\n\
             Duration: {}",
            parsed.prompt,
            parsed.sensitivity,
            parsed.bounce_duration.display_label()
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
            if let Err(e) = self
                .engine
                .tenant_registry()
                .update_rubric(sender_did, &rubric)
            {
                tracing::warn!(error = %e, sender_did, "Failed to update tenant sensitivity in registry");
                return Ok(format!("❌ Failed to update sensitivity: {e}"));
            }
        } else if self.engine.is_admin(sender_did)
            || (self.engine.is_single_tenant() && self.engine.is_protected(sender_did))
        {
            self.engine.set_rubric(rubric);
        } else {
            return Ok(
                "❌ You can only update sensitivity for your own enrolled account.".to_string(),
            );
        }

        // Asynchronously persist to sender's sovereign PDS repo
        let eng = self.engine.clone();
        let did = sender_did.to_string();
        tokio::spawn(async move {
            if let Err(e) = eng.publish_sovereign_config(&did).await {
                tracing::warn!(error = %e, did = %did, "Failed to publish sovereign config to PDS");
            }
        });

        Ok(format!(
            "✅ Sensitivity threshold updated to **{}** (confidence: {:.2}).",
            sens,
            sens.threshold()
        ))
    }

    fn cmd_set_duration(&self, sender_did: &str, dur_str: &str) -> Result<String, SkybouncerError> {
        let dur = match dur_str.trim().parse::<crate::classifier::BounceDuration>() {
            Ok(d) => d,
            Err(_) => {
                return Ok(
                    "Invalid duration. Options: `permanent`, `24h` (cooldown), `7d`, `30d` (timeout), or seconds."
                        .to_string(),
                );
            }
        };

        let mut rubric = self.engine.rubric_for(sender_did);
        rubric.bounce_duration = dur;
        if self.engine.is_enrolled(sender_did) {
            if let Err(e) = self
                .engine
                .tenant_registry()
                .update_rubric(sender_did, &rubric)
            {
                tracing::warn!(error = %e, sender_did, "Failed to update tenant duration in registry");
                return Ok(format!("❌ Failed to update duration: {e}"));
            }
        } else if self.engine.is_admin(sender_did)
            || (self.engine.is_single_tenant() && self.engine.is_protected(sender_did))
        {
            self.engine.set_rubric(rubric);
        } else {
            return Ok(
                "❌ You can only update duration for your own enrolled account.".to_string(),
            );
        }

        // Asynchronously persist to sender's sovereign PDS repo
        let eng = self.engine.clone();
        let did = sender_did.to_string();
        tokio::spawn(async move {
            if let Err(e) = eng.publish_sovereign_config(&did).await {
                tracing::warn!(error = %e, did = %did, "Failed to publish sovereign config to PDS");
            }
        });

        Ok(format!(
            "✅ Moderation duration updated to **{}**.",
            dur.display_label()
        ))
    }

    fn cmd_recent(&self, sender_did: &str) -> Result<String, SkybouncerError> {
        let bounces = self.engine.list_recent_bounces_for(Some(sender_did), 5)?;
        if bounces.is_empty() {
            return Ok("ℹ️ No accounts have been bounced from your replies yet.".to_string());
        }

        let mut out = String::from("🚫 Recently Bounced Accounts from Your Replies (last 5):\n\n");
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

        // Sender is strictly the protected user whose modlist is being updated
        let protected_did = if self.engine.is_protected(sender_did)
            || self.engine.is_enrolled(sender_did)
            || self.engine.is_admin(sender_did)
        {
            sender_did.to_string()
        } else {
            return Ok(
                "❌ You do not have permission to pardon users on this moderation list."
                    .to_string(),
            );
        };

        let handle_prefix = if was_handle {
            format!("Resolved `@{clean}` to `{resolved_did}`.\n")
        } else {
            String::new()
        };

        match self.engine.pardon_user(&protected_did, &resolved_did).await {
            Ok(true) => Ok(format!(
                "{handle_prefix}✅ Account `{resolved_did}` has been pardoned and removed from your moderation list.\n\n\
                 💡 Tip: To permanently immunize this account against future bounces, use `pardon and allow {clean}` or `allow {clean}`."
            )),
            Ok(false) => Ok(format!(
                "{handle_prefix}ℹ️ Account `{resolved_did}` was not found in your bounced list."
            )),
            Err(e) => Ok(format!("{handle_prefix}❌ Failed to pardon account: {e}")),
        }
    }

    async fn cmd_pardon_and_allow(
        &self,
        sender_did: &str,
        raw_target: &str,
    ) -> Result<String, SkybouncerError> {
        let raw_target = raw_target.trim();
        if raw_target.is_empty() {
            return Ok("Usage: `pardon and allow <did|@handle>`".to_string());
        }

        let clean = raw_target.trim_start_matches('@');
        let (resolved_did, was_handle) = if clean.starts_with("did:") {
            (clean.to_string(), false)
        } else {
            match self.engine.resolve_handle(clean).await {
                Some(did) => (did, true),
                None => {
                    return Ok(format!(
                        "❌ Could not resolve handle `@{clean}` to a DID. Please verify the handle or provide the account's DID directly."
                    ));
                }
            }
        };

        let protected_did = if self.engine.is_protected(sender_did)
            || self.engine.is_enrolled(sender_did)
            || self.engine.is_admin(sender_did)
        {
            sender_did.to_string()
        } else {
            return Ok(
                "❌ You do not have permission to pardon users on this moderation list."
                    .to_string(),
            );
        };

        let handle_prefix = if was_handle {
            format!("Resolved `@{clean}` to `{resolved_did}`.\n")
        } else {
            String::new()
        };

        match self
            .engine
            .pardon_and_allowlist(
                &protected_did,
                &resolved_did,
                Some("Immunized via bot pardon-and-allow"),
            )
            .await
        {
            Ok(true) => Ok(format!(
                "{handle_prefix}✅ Account `{resolved_did}` has been pardoned and added to your allowlist!\n\
                 They are now permanently immunized against future automatic bounces."
            )),
            Ok(false) => Ok(format!(
                "{handle_prefix}ℹ️ Account `{resolved_did}` was not on your list, but has been added to your allowlist for future immunization."
            )),
            Err(e) => Ok(format!("{handle_prefix}❌ Failed to pardon and allowlist account: {e}")),
        }
    }

    async fn cmd_allow(
        &self,
        sender_did: &str,
        raw_target: &str,
    ) -> Result<String, SkybouncerError> {
        let raw_target = raw_target.trim();
        if raw_target.is_empty() {
            return Ok(
                "Usage: `allow <did|@handle>` (e.g. `allow @alice.bsky.social`)".to_string(),
            );
        }

        let clean = raw_target.trim_start_matches('@');
        let (resolved_did, was_handle) = if clean.starts_with("did:") {
            (clean.to_string(), false)
        } else {
            match self.engine.resolve_handle(clean).await {
                Some(did) => (did, true),
                None => {
                    return Ok(format!(
                        "❌ Could not resolve handle `@{clean}` to a DID. Please verify the handle or provide the account's DID directly."
                    ));
                }
            }
        };

        let handle_prefix = if was_handle {
            format!("Resolved `@{clean}` to `{resolved_did}`.\n")
        } else {
            String::new()
        };

        match self
            .engine
            .add_to_allowlist(sender_did, &resolved_did, Some("Added via DM bot"))
        {
            Ok(()) => Ok(format!(
                "{handle_prefix}✅ Account `{resolved_did}` has been added to your moderation allowlist.\n\
                 Their interactions will now bypass all moderation checks at zero cost."
            )),
            Err(e) => Ok(format!("{handle_prefix}❌ Failed to allowlist account: {e}")),
        }
    }

    async fn cmd_unallow(
        &self,
        sender_did: &str,
        raw_target: &str,
    ) -> Result<String, SkybouncerError> {
        let raw_target = raw_target.trim();
        if raw_target.is_empty() {
            return Ok(
                "Usage: `unallow <did|@handle>` (e.g. `unallow @alice.bsky.social`)".to_string(),
            );
        }

        let clean = raw_target.trim_start_matches('@');
        let (resolved_did, was_handle) = if clean.starts_with("did:") {
            (clean.to_string(), false)
        } else {
            match self.engine.resolve_handle(clean).await {
                Some(did) => (did, true),
                None => {
                    return Ok(format!(
                        "❌ Could not resolve handle `@{clean}` to a DID. Please verify the handle or provide the account's DID directly."
                    ));
                }
            }
        };

        let handle_prefix = if was_handle {
            format!("Resolved `@{clean}` to `{resolved_did}`.\n")
        } else {
            String::new()
        };

        match self.engine.remove_from_allowlist(sender_did, &resolved_did) {
            Ok(true) => Ok(format!(
                "{handle_prefix}✅ Account `{resolved_did}` has been removed from your moderation allowlist."
            )),
            Ok(false) => Ok(format!(
                "{handle_prefix}ℹ️ Account `{resolved_did}` was not found on your moderation allowlist."
            )),
            Err(e) => Ok(format!("{handle_prefix}❌ Failed to remove account from allowlist: {e}")),
        }
    }

    fn cmd_allowlist(&self, sender_did: &str) -> Result<String, SkybouncerError> {
        let entries = self.engine.list_allowlist(sender_did)?;
        if entries.is_empty() {
            return Ok("ℹ️ Your moderation allowlist is empty.\n\nUse `allow <did|@handle>` to exempt trusted accounts from moderation.".to_string());
        }

        let mut out = format!(
            "🛡️ Your Moderation Allowlist ({} account{}):\n\n",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        );
        for (idx, entry) in entries.iter().enumerate() {
            let num = idx.saturating_add(1);
            let reason_str = entry.reason.as_deref().unwrap_or("No reason provided");
            out.push_str(&format!(
                "{num}. `{}`\n   Reason: {} | Added: {}\n",
                entry.subject_did, reason_str, entry.created_at
            ));
        }

        Ok(out)
    }

    fn cmd_status(&self, sender_did: &str) -> String {
        let stats = self.engine.stats().snapshot();
        let state_label = if self.engine.is_tenant_paused(sender_did) {
            "⏸️ PAUSED"
        } else {
            "▶️ ACTIVE"
        };

        if self.engine.is_admin(sender_did) {
            format!(
                "📊 Skybouncer Engine Status (Admin Fleet View):\n\n\
                 • State: {}\n\
                 • Commits Received: {}\n\
                 • Follows Synced: {}\n\
                 • Interactions Matched: {}\n\
                 • Bypassed (Followed Author): {}\n\
                 • Bypassed (Incoming Follower): {}\n\
                 • Bypassed (Self-Interaction): {}\n\
                 • Bypassed (Allowlisted): {}\n\
                 • Dedup Cache Hits: {}\n\
                 • Heuristic Pre-Filter Flags: {}\n\
                 • Model Evaluations: {}\n\
                 • Violations Detected: {}\n\
                 • Bounces Executed on PDS: {}\n\
                 • Permitted Interactions: {}\n\
                 • Enrolled Tenants: {}\n\
                 • Dry-Run Mode: {}",
                state_label,
                stats.commits_received,
                stats.follows_synced,
                stats.interactions_matched,
                stats.gate_bypassed_followed,
                stats.gate_bypassed_follower,
                stats.gate_bypassed_self,
                stats.gate_bypassed_allowlist,
                stats.dedup_cache_hits,
                stats.heuristic_violations,
                stats.model_evaluations,
                stats.violations_detected,
                stats.bounces_executed,
                stats.permitted,
                self.engine.tenant_registry().count().unwrap_or(0),
                if self.engine.is_dry_run() {
                    "Yes (shadow)"
                } else {
                    "No (live)"
                }
            )
        } else {
            let rubric = self.engine.rubric_for(sender_did);
            let my_bounces = self
                .engine
                .list_recent_bounces_for(Some(sender_did), 100)
                .map(|b| b.len())
                .unwrap_or(0);
            let allowlist_count = self
                .engine
                .list_allowlist(sender_did)
                .map(|l| l.len())
                .unwrap_or(0);
            format!(
                "📊 Skybouncer Status for Your Account:\n\n\
                 • Defense State: {}\n\
                 • Sensitivity: {}\n\
                 • Active Prompt: \"{}\"\n\
                 • Accounts Bounced from Your Posts: {}\n\
                 • Allowlisted (Immunized) Accounts: {}\n\
                 • Protection Mode: {}",
                state_label,
                rubric.sensitivity,
                rubric.prompt,
                my_bounces,
                allowlist_count,
                if self.engine.is_dry_run() {
                    "Dry-Run (simulated)"
                } else {
                    "Active Sovereign Bouncer"
                }
            )
        }
    }

    fn cmd_onboarding(&self, sender_did: &str) -> String {
        let auth_url = self.auth_url();
        format!(
            "👋 Welcome to **Skybouncer** — your personal, sovereign automated bouncer for Bluesky!\n\n\
             Skybouncer monitors your incoming replies and mentions in real-time, using AI and your custom natural-language rules to catch spam bots, crypto schemes, and bad-faith harassment, placing them on your personal moderation list.\n\n\
             To activate 1-click protection for your account (`{sender_did}`), authorize Skybouncer here:\n\
             {auth_url}\n\n\
             Once authorized, your personal bouncer is live! You can message me anytime right here with:\n\
             • `rules` — View or update your moderation prompt\n\
             • `pause` / `resume` — Suspend or re-enable protection\n\
             • `status` — View your protection status and stats\n\
             • `help` — List all available commands"
        )
    }

    async fn cmd_test(&self, sender_did: &str, text: &str) -> Result<String, SkybouncerError> {
        let sender_rubric = self.engine.rubric_for(sender_did);
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
            rubric: Some(sender_rubric),
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

    /// Checks whether the sender is authorized to execute bouncer commands (enrolled tenant, admin, or protected DID).
    #[must_use]
    pub fn is_authorized_sender(&self, sender_did: &str) -> bool {
        self.engine.is_admin(sender_did)
            || self.engine.is_enrolled(sender_did)
            || self.engine.is_protected(sender_did)
    }

    /// Generates an onboarding response for unauthorized senders.
    #[must_use]
    pub fn unauthorized_response(&self) -> String {
        format!(
            "🛡️ Skybouncer: You do not have an active bouncer session.\n\n\
             To activate 1-click sovereign auto-moderation for your Bluesky account, visit:\n{}\n\n\
             Once activated, you can manage your moderation rules directly via DMs here!",
            self.auth_url()
        )
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
