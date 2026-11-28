//! Conversational command parser and dispatcher for the ATProto DM bot.
//!
//! Handles direct-message commands from Bluesky users:
//! - `help` / `?`: Show available commands and usage.
//! - `rules`: View active moderation rubric and sensitivity threshold.
//! - `set rules <prompt>`: Update active moderation rules.
//! - `sensitivity <low|medium|high>`: Update sensitivity threshold.
//! - `recent`: List recently bounced violators.
//! - `pardon <did|@handle>`: Pardon and remove an account from the moderation list.
//! - `bounce <did|@handle>`: Bounce or re-bounce an account onto the moderation list.
//! - `perm <did|@handle>`: Permanently block an account or upgrade a temporary bounce to permanent.
//! - `status`: View engine operational telemetry and bounce counts.
//! - `test <text>`: Dry-run evaluation on sample text.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::bot::render::{
    account_label_with_url, bsky_post_or_web_url, bsky_post_url_from_at_uri, command_target,
    truncate_chars,
};
use crate::classifier::{BounceDuration, Sensitivity, Verdict};
use crate::dogpile::ThreadgatePolicy;
use crate::engine::SkybouncerEngine;
use crate::error::SkybouncerError;
use crate::limiter::{EvaluationRateLimiter, RateLimiterConfig};
use crate::matcher::Interaction;
use crate::modlist::ManualBounceOutcome;

/// Default maximum DM commands accepted per sender DID per minute before throttling.
const DEFAULT_DM_RATE_LIMIT_PER_MIN: usize = 20;

/// Default DM rate-limit rolling window.
const DEFAULT_DM_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Default cooldown between consecutive unknown-command replies to the same sender.
const DEFAULT_UNKNOWN_CMD_COOLDOWN: Duration = Duration::from_secs(60);

/// Default maximum `test` dry-run commands per sender DID per minute.
const DEFAULT_DM_TEST_RATE_LIMIT_PER_MIN: usize = 10;

/// Default maximum concurrent `test` evaluations across DM bot commands.
const DEFAULT_DM_TEST_CONCURRENCY: usize = 2;

/// Maximum text length accepted by the DM `test` command.
const MAX_DM_TEST_TEXT_CHARS: usize = 2000;

/// Maximum allowlist entries displayed per DM `allowlist [page]` response.
const ALLOWLIST_PAGE_SIZE: usize = 10;

/// Maximum characters echoed back for an unrecognized DM command.
const MAX_UNKNOWN_CMD_ECHO_CHARS: usize = 60;

/// Maximum tracked sender buckets in [`DmSenderLimiter`].
const MAX_TRACKED_DM_SENDERS: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmRateDecision {
    Allowed,
    NotifyOnce,
    Suppress,
}

#[derive(Debug)]
struct DmSenderLimiterState {
    window: Duration,
    max_per_window: usize,
    unknown_cooldown: Duration,
    hits: HashMap<String, (VecDeque<Instant>, bool)>,
    unknown_last: HashMap<String, Instant>,
}

impl DmSenderLimiterState {
    fn new(max_per_window: usize, window: Duration, unknown_cooldown: Duration) -> Self {
        Self {
            window,
            max_per_window: max_per_window.max(1),
            unknown_cooldown,
            hits: HashMap::new(),
            unknown_last: HashMap::new(),
        }
    }

    fn check_rate(&mut self, sender_did: &str, now: Instant) -> DmRateDecision {
        if !self.hits.contains_key(sender_did) && self.hits.len() >= MAX_TRACKED_DM_SENDERS {
            let window = self.window;
            self.hits.retain(|_, (q, _)| {
                while let Some(&front) = q.front() {
                    if now.saturating_duration_since(front) >= window {
                        q.pop_front();
                    } else {
                        break;
                    }
                }
                !q.is_empty()
            });
            if self.hits.len() >= MAX_TRACKED_DM_SENDERS {
                if let Some(evict) = self.hits.keys().next().cloned() {
                    self.hits.remove(&evict);
                }
            }
        }

        let (queue, notified) = self
            .hits
            .entry(sender_did.to_string())
            .or_insert_with(|| (VecDeque::new(), false));
        while let Some(&front) = queue.front() {
            if now.saturating_duration_since(front) >= self.window {
                queue.pop_front();
                *notified = false;
            } else {
                break;
            }
        }

        if queue.len() >= self.max_per_window {
            if !*notified {
                *notified = true;
                return DmRateDecision::NotifyOnce;
            }
            return DmRateDecision::Suppress;
        }

        queue.push_back(now);
        DmRateDecision::Allowed
    }

    fn allow_unknown_reply(&mut self, sender_did: &str, now: Instant) -> bool {
        if self.unknown_cooldown.is_zero() {
            return true;
        }
        if !self.unknown_last.contains_key(sender_did)
            && self.unknown_last.len() >= MAX_TRACKED_DM_SENDERS
        {
            let cooldown = self.unknown_cooldown;
            self.unknown_last
                .retain(|_, ts| now.saturating_duration_since(*ts) < cooldown);
            if self.unknown_last.len() >= MAX_TRACKED_DM_SENDERS {
                if let Some(evict) = self.unknown_last.keys().next().cloned() {
                    self.unknown_last.remove(&evict);
                }
            }
        }
        if let Some(&prev) = self.unknown_last.get(sender_did) {
            if now.saturating_duration_since(prev) < self.unknown_cooldown {
                return false;
            }
        }
        self.unknown_last.insert(sender_did.to_string(), now);
        true
    }
}

/// Command parser and dispatcher for incoming direct messages.
#[derive(Clone)]
pub struct BotCommandHandler {
    engine: Arc<SkybouncerEngine>,
    bot_did: String,
    public_url: String,
    sender_limiter: Arc<Mutex<DmSenderLimiterState>>,
    cmd_test_limiter: Arc<EvaluationRateLimiter>,
    cmd_test_semaphore: Arc<Semaphore>,
}

impl BotCommandHandler {
    /// Creates a new [`BotCommandHandler`] bound to an engine instance and bot DID.
    #[must_use]
    pub fn new(engine: Arc<SkybouncerEngine>, bot_did: impl Into<String>) -> Self {
        let public_url = crate::env::var_or(
            &["PUBLIC_URL", "SKYBOUNCER_PUBLIC_URL"],
            "http://127.0.0.1:3000",
        )
        .trim()
        .trim_end_matches('/')
        .to_string();
        Self {
            engine,
            bot_did: bot_did.into(),
            public_url,
            sender_limiter: Arc::new(Mutex::new(DmSenderLimiterState::new(
                DEFAULT_DM_RATE_LIMIT_PER_MIN,
                DEFAULT_DM_RATE_WINDOW,
                DEFAULT_UNKNOWN_CMD_COOLDOWN,
            ))),
            cmd_test_limiter: Arc::new(EvaluationRateLimiter::new(RateLimiterConfig {
                max_evaluations: DEFAULT_DM_TEST_RATE_LIMIT_PER_MIN,
                window_duration: DEFAULT_DM_RATE_WINDOW,
            })),
            cmd_test_semaphore: Arc::new(Semaphore::new(DEFAULT_DM_TEST_CONCURRENCY)),
        }
    }

    /// Sets the public base URL for onboarding authorization links.
    #[must_use]
    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = url.into().trim().trim_end_matches('/').to_string();
        self
    }

    /// Configures the per-sender DM rate limit and unknown-command reply cooldown.
    #[must_use]
    pub fn with_dm_rate_limit(
        mut self,
        max_per_window: usize,
        window: Duration,
        unknown_cooldown: Duration,
    ) -> Self {
        self.sender_limiter = Arc::new(Mutex::new(DmSenderLimiterState::new(
            max_per_window,
            window,
            unknown_cooldown,
        )));
        self
    }

    /// Configures the per-DID rate limit and concurrency bound for the DM `test` command.
    #[must_use]
    pub fn with_test_limits(
        mut self,
        max_per_window: usize,
        window: Duration,
        concurrency: usize,
    ) -> Self {
        self.cmd_test_limiter = Arc::new(EvaluationRateLimiter::new(RateLimiterConfig {
            max_evaluations: max_per_window,
            window_duration: window,
        }));
        self.cmd_test_semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
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
    /// Returns an empty string when a reply should be suppressed (e.g., sender rate limit
    /// saturation or unknown-command cooldown) to prevent bot-to-bot ping-pong loops.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if command execution fails.
    pub async fn handle_command(
        &self,
        sender_did: &str,
        message_text: &str,
    ) -> Result<String, SkybouncerError> {
        if !self.bot_did.is_empty() && sender_did == self.bot_did {
            return Ok(String::new());
        }

        let now = Instant::now();
        match self.sender_limiter.lock().check_rate(sender_did, now) {
            DmRateDecision::Allowed => {}
            DmRateDecision::NotifyOnce => {
                return Ok(
                    "⏳ Too many direct messages. Please wait a minute before sending more commands."
                        .to_string(),
                );
            }
            DmRateDecision::Suppress => {
                return Ok(String::new());
            }
        }

        let trimmed = message_text.trim();
        let Some((w1, r1)) = take_next_token(trimmed) else {
            return Ok("Type `help` to see available Skybouncer commands.".to_string());
        };

        if (w1.eq_ignore_ascii_case("help") || w1 == "?") && r1.is_empty() {
            return Ok(self.cmd_help());
        }

        let is_onboard_cmd = r1.is_empty()
            && (w1.eq_ignore_ascii_case("start")
                || w1.eq_ignore_ascii_case("onboard")
                || w1.eq_ignore_ascii_case("activate")
                || w1.eq_ignore_ascii_case("auth")
                || w1.eq_ignore_ascii_case("login")
                || w1.eq_ignore_ascii_case("join")
                || w1.eq_ignore_ascii_case("hi")
                || w1.eq_ignore_ascii_case("hello")
                || w1.eq_ignore_ascii_case("hey"));

        if is_onboard_cmd {
            return Ok(self.cmd_onboarding(sender_did));
        }

        // `help`/`?` and onboarding remain available to unauthorized senders; every
        // privileged command below is gated on a single authorization probe.
        let authorized = self.is_authorized_sender(sender_did);

        let w2_pair = take_next_token(r1);
        let w3_pair = w2_pair.and_then(|(_, rest)| take_next_token(rest));

        if w1.eq_ignore_ascii_case("pause") && r1.is_empty() {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return Ok(self.cmd_pause(sender_did));
        }

        if w1.eq_ignore_ascii_case("resume") && r1.is_empty() {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return Ok(self.cmd_resume(sender_did));
        }

        if w1.eq_ignore_ascii_case("rules") && r1.is_empty() {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return Ok(self.cmd_rules(sender_did));
        }

        if w1.eq_ignore_ascii_case("set") {
            if let Some((w2, r2)) = w2_pair {
                if w2.eq_ignore_ascii_case("rules") {
                    if !authorized {
                        return Ok(self.unauthorized_response());
                    }
                    return self.cmd_set_rules(sender_did, r2);
                }
                if w2.eq_ignore_ascii_case("duration") || w2.eq_ignore_ascii_case("timeout") {
                    if !authorized {
                        return Ok(self.unauthorized_response());
                    }
                    if r2.is_empty() {
                        return Ok("Usage: `duration <permanent|24h|7d|30d>`".to_string());
                    }
                    return self.cmd_set_duration(sender_did, r2);
                }
            }
        }

        if w1.eq_ignore_ascii_case("sensitivity") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            if r1.is_empty() {
                return Ok("Usage: `sensitivity <low|medium|high>`".to_string());
            }
            return self.cmd_set_sensitivity(sender_did, r1);
        }

        if w1.eq_ignore_ascii_case("duration") || w1.eq_ignore_ascii_case("timeout") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            if r1.is_empty() {
                return Ok("Usage: `duration <permanent|24h|7d|30d>`".to_string());
            }
            return self.cmd_set_duration(sender_did, r1);
        }

        if (w1.eq_ignore_ascii_case("trust") || w1.eq_ignore_ascii_case("bypass"))
            && w2_pair.is_some_and(|(w2, _)| w2.eq_ignore_ascii_case("followers"))
        {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            let r2 = w2_pair.map_or("", |(_, rest)| rest);
            if r2.is_empty() {
                return Ok(
                    "Usage: `trust followers <on|off>` (toggle zero-cost bypass for accounts that follow you)"
                        .to_string(),
                );
            }
            return self.cmd_set_follower_bypass(sender_did, r2);
        }

        if w1.eq_ignore_ascii_case("recent") && r1.is_empty() {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_recent(sender_did);
        }

        if w1.eq_ignore_ascii_case("allowlist") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_allowlist(sender_did, r1);
        }

        if w1.eq_ignore_ascii_case("allow") {
            if let Some((w2, r2)) = w2_pair {
                if w2.eq_ignore_ascii_case("list") {
                    if !authorized {
                        return Ok(self.unauthorized_response());
                    }
                    return self.cmd_allowlist(sender_did, r2);
                }
            }
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            if r1.is_empty() {
                return Ok(
                    "Usage: `allow <did|@handle>` (e.g. `allow @alice.bsky.social`)".to_string(),
                );
            }
            return self.cmd_allow(sender_did, r1).await;
        }

        if w1.eq_ignore_ascii_case("unallow") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            if r1.is_empty() {
                return Ok(
                    "Usage: `unallow <did|@handle>` (e.g. `unallow @alice.bsky.social`)"
                        .to_string(),
                );
            }
            return self.cmd_unallow(sender_did, r1).await;
        }

        if w1.eq_ignore_ascii_case("pardon") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            if r1.is_empty() {
                return Ok(
                    "Usage: `pardon <did|@handle>` or `pardon and allow <did|@handle>`".to_string(),
                );
            }
            if let (Some((w2, _)), Some((w3, r3))) = (w2_pair, w3_pair) {
                if w2.eq_ignore_ascii_case("and") && w3.eq_ignore_ascii_case("allow") {
                    if r3.is_empty() {
                        return Ok("Usage: `pardon and allow <did|@handle>`".to_string());
                    }
                    return self.cmd_pardon_and_allow(sender_did, r3).await;
                }
            }
            return self.cmd_pardon(sender_did, r1).await;
        }

        if w1.eq_ignore_ascii_case("bounce")
            || w1.eq_ignore_ascii_case("rebounce")
            || w1.eq_ignore_ascii_case("re-bounce")
            || w1.eq_ignore_ascii_case("block")
        {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            if r1.is_empty() {
                return Ok(
                    "Usage: `bounce <did|@handle>` (bounce or re-bounce an account onto your moderation list)"
                        .to_string(),
                );
            }
            return self.cmd_bounce(sender_did, r1).await;
        }

        if w1.eq_ignore_ascii_case("make")
            && w2_pair.is_some_and(|(w2, _)| w2.eq_ignore_ascii_case("permanent"))
        {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            let r2 = w2_pair.map_or("", |(_, rest)| rest);
            if r2.is_empty() {
                return Ok(
                    "Usage: `perm <did|@handle>` (permanently block an account or upgrade a temporary block to permanent)"
                        .to_string(),
                );
            }
            return self.cmd_upgrade_perm(sender_did, r2).await;
        }

        if w1.eq_ignore_ascii_case("perm")
            && w2_pair.is_some_and(|(w2, _)| w2.eq_ignore_ascii_case("block"))
        {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            let r2 = w2_pair.map_or("", |(_, rest)| rest);
            if r2.is_empty() {
                return Ok(
                    "Usage: `perm <did|@handle>` (permanently block an account or upgrade a temporary block to permanent)"
                        .to_string(),
                );
            }
            return self.cmd_upgrade_perm(sender_did, r2).await;
        }

        if w1.eq_ignore_ascii_case("perm")
            || w1.eq_ignore_ascii_case("permanent")
            || w1.eq_ignore_ascii_case("upgrade")
        {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            if r1.is_empty() {
                return Ok(
                    "Usage: `perm <did|@handle>` (permanently block an account or upgrade a temporary block to permanent)"
                        .to_string(),
                );
            }
            return self.cmd_upgrade_perm(sender_did, r1).await;
        }

        if w1.eq_ignore_ascii_case("status") && r1.is_empty() {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return Ok(self.cmd_status(sender_did));
        }

        if w1.eq_ignore_ascii_case("storms") && r1.is_empty() {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_storms(sender_did);
        }

        if w1.eq_ignore_ascii_case("storm") {
            if r1.is_empty() {
                if !authorized {
                    return Ok(self.unauthorized_response());
                }
                return self.cmd_storms(sender_did);
            }
            if let Some((w2, r2)) = w2_pair {
                if w2.eq_ignore_ascii_case("status") && r2.is_empty() {
                    if !authorized {
                        return Ok(self.unauthorized_response());
                    }
                    return self.cmd_storms(sender_did);
                }
                if w2.eq_ignore_ascii_case("on") && r2.is_empty() {
                    if !authorized {
                        return Ok(self.unauthorized_response());
                    }
                    return self.cmd_storm_mode(sender_did, true);
                }
                if w2.eq_ignore_ascii_case("off") && r2.is_empty() {
                    if !authorized {
                        return Ok(self.unauthorized_response());
                    }
                    return self.cmd_storm_mode(sender_did, false);
                }
                if w2.eq_ignore_ascii_case("mode") {
                    if let Some((w3, r3)) = w3_pair {
                        if w3.eq_ignore_ascii_case("on") && r3.is_empty() {
                            if !authorized {
                                return Ok(self.unauthorized_response());
                            }
                            return self.cmd_storm_mode(sender_did, true);
                        }
                        if w3.eq_ignore_ascii_case("off") && r3.is_empty() {
                            if !authorized {
                                return Ok(self.unauthorized_response());
                            }
                            return self.cmd_storm_mode(sender_did, false);
                        }
                    }
                }
            }
        }

        if w1.eq_ignore_ascii_case("lock") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_lock(sender_did, r1).await;
        }

        if w1.eq_ignore_ascii_case("unlock") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_unlock(sender_did, r1).await;
        }

        if w1.eq_ignore_ascii_case("detach") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            return self.cmd_detach(sender_did, r1).await;
        }

        if w1.eq_ignore_ascii_case("test") {
            if !authorized {
                return Ok(self.unauthorized_response());
            }
            if r1.is_empty() {
                return Ok("Usage: `test <text>` (dry-run evaluation on sample text)".to_string());
            }
            return self.cmd_test(sender_did, r1).await;
        }

        if !self
            .sender_limiter
            .lock()
            .allow_unknown_reply(sender_did, now)
        {
            return Ok(String::new());
        }

        let echoed = truncate_chars(trimmed, MAX_UNKNOWN_CMD_ECHO_CHARS);
        let unknown_msg =
            format!("Unknown command: `{echoed}`\n\nType `help` to see available commands.");
        if !self.engine.is_enrolled(sender_did) && !self.engine.is_protected(sender_did) {
            Ok(format!("{unknown_msg}\n\n(Tip: Your account is not yet protected. Visit {} to activate 1-click protection.)", self.auth_url()))
        } else {
            Ok(unknown_msg)
        }
    }

    fn cmd_help(&self) -> String {
        format!(
            "🛡️ Skybouncer Bot Commands:\n\n\
             • `rules` — View active prompt & rules\n\
             • `set rules <prompt>` — Update rules\n\
             • `sensitivity <low|medium|high>` — Sensitivity\n\
             • `duration <permanent|24h|7d|30d>` — Duration\n\
             • `trust followers <on|off>` — Follower bypass\n\
             • `pause` — Suspend moderation\n\
             • `resume` — Resume moderation\n\
             • `recent` — Last 5 bounced accounts\n\
             • `pardon <did|@handle>` — Unban from list\n\
             • `pardon and allow <did|@handle>` — Pardon & allow\n\
             • `bounce <target>` / `perm <target>` — Block / perm\n\
             • `allow <target>` / `unallow <target>` / `allowlist`\n\
             • `storms` / `storm <on|off>` — Dogpile radar & mode\n\
             • `lock [post] [policy]` / `unlock [post]` — Reply lock\n\
             • `detach [post] [qt|all]` — Detach quote-posts\n\
             • `status` / `test <text>` — Telemetry & dry-run\n\
             • `start` / `auth` — Activate ({})\n\
             • `help` — Show commands",
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
        let follower_status = if rubric.bypass_incoming_followers {
            "Enabled (incoming followers trusted)"
        } else {
            "Disabled (evaluate incoming followers)"
        };
        format!(
            "📋 Current Moderation Rubric:\n\n\
             Prompt: \"{}\"\n\
             Sensitivity: {} (threshold: {:.2})\n\
             Duration: {}\n\
             Follower Bypass: {}",
            rubric.prompt,
            rubric.sensitivity,
            rubric.sensitivity.threshold(),
            rubric.bounce_duration.display_label(),
            follower_status
        )
    }

    fn cmd_set_rules(&self, sender_did: &str, prompt: &str) -> Result<String, SkybouncerError> {
        let prompt = prompt.trim();
        if prompt.is_empty() {
            return Ok("Please provide a moderation prompt. Example: `set rules Block crypto spam and bots.`".to_string());
        }

        let current = self.engine.rubric_for(sender_did);
        let parsed = match current.parse_updating(prompt) {
            Ok(r) => r,
            Err(e) => return Ok(format!("❌ Invalid rubric: {e}")),
        };
        if parsed.prompt.chars().count() > crate::classifier::MAX_RUBRIC_PROMPT_CHARS {
            return Ok(format!(
                "❌ Invalid rubric: prompt exceeds maximum length of {} characters.",
                crate::classifier::MAX_RUBRIC_PROMPT_CHARS
            ));
        }

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

        self.engine
            .set_bypass_incoming_followers(sender_did, parsed.bypass_incoming_followers);

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

    fn cmd_set_follower_bypass(
        &self,
        sender_did: &str,
        flag_str: &str,
    ) -> Result<String, SkybouncerError> {
        let bypass = match flag_str.trim().to_ascii_lowercase().as_str() {
            "on" | "true" | "enable" | "enabled" | "yes" | "1" => true,
            "off" | "false" | "disable" | "disabled" | "no" | "0" => false,
            _ => {
                return Ok(
                    "Invalid value. Please use `trust followers on` or `trust followers off`."
                        .to_string(),
                );
            }
        };

        let mut rubric = self.engine.rubric_for(sender_did);
        rubric.bypass_incoming_followers = bypass;

        if self.engine.is_enrolled(sender_did) {
            if let Err(e) = self
                .engine
                .tenant_registry()
                .update_rubric(sender_did, &rubric)
            {
                tracing::warn!(error = %e, sender_did, "Failed to update tenant follower bypass in registry");
                return Ok(format!("❌ Failed to update follower bypass: {e}"));
            }
        } else if self.engine.is_admin(sender_did)
            || (self.engine.is_single_tenant() && self.engine.is_protected(sender_did))
        {
            self.engine.set_rubric(rubric);
        } else {
            return Ok(
                "❌ You can only update follower bypass for your own enrolled account.".to_string(),
            );
        }

        self.engine
            .set_bypass_incoming_followers(sender_did, bypass);

        // Asynchronously persist to sender's sovereign PDS repo
        let eng = self.engine.clone();
        let did = sender_did.to_string();
        tokio::spawn(async move {
            if let Err(e) = eng.publish_sovereign_config(&did).await {
                tracing::warn!(error = %e, did = %did, "Failed to publish sovereign config to PDS");
            }
        });

        if bypass {
            Ok("✅ Incoming follower bypass **enabled**: accounts that follow you will bypass moderation checks at zero cost.".to_string())
        } else {
            Ok("✅ Incoming follower bypass **disabled**: accounts that follow you (unless you also follow them back) will be evaluated against your moderation rules.".to_string())
        }
    }

    fn cmd_set_sensitivity(
        &self,
        sender_did: &str,
        level: &str,
    ) -> Result<String, SkybouncerError> {
        let sens = match level.trim().to_ascii_lowercase().as_str() {
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
            let handle = self.engine.cached_handle_for_did(&b.subject_did);
            let label = account_label_with_url(&b.subject_did, handle.as_deref());
            let post_link = bsky_post_url_from_at_uri(&b.post_uri)
                .map(|url| format!("\n   Post: {url}"))
                .unwrap_or_default();
            let reply_to_link = b
                .reply_to_uri
                .as_deref()
                .and_then(bsky_post_or_web_url)
                .map(|url| format!("\n   Replying to: {url}"))
                .unwrap_or_default();

            out.push_str(&format!(
                "{num}. {label} — **{}** ({:.0}% confidence){post_link}{reply_to_link}\n   Reason: {}\n",
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

        let (resolved_did, resolved_handle, handle_prefix) = match self
            .resolve_dm_target(raw_target, " (e.g. `pardon did:plc:...`)")
            .await
        {
            Ok(v) => v,
            Err(msg) => return Ok(msg),
        };

        // Sender is strictly the protected user whose modlist is being updated
        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };

        let label = account_label_with_url(&resolved_did, resolved_handle.as_deref());
        let target = command_target(&resolved_did, resolved_handle.as_deref());

        match self.engine.pardon_user(&protected_did, &resolved_did).await {
            Ok(true) => Ok(format!(
                "{handle_prefix}✅ Account {label} has been pardoned and removed from your moderation list.\n\n\
                 💡 Tip: To permanently immunize this account against future bounces, use `pardon and allow {target}` or `allow {target}`.\n\
                 Changed your mind? Reply with `bounce {target}` or `perm {target}`."
            )),
            Ok(false) => Ok(format!(
                "{handle_prefix}ℹ️ Account {label} was not found in your bounced list."
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

        let (resolved_did, resolved_handle, handle_prefix) =
            match self.resolve_dm_target(raw_target, "").await {
                Ok(v) => v,
                Err(msg) => return Ok(msg),
            };

        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };

        let label = account_label_with_url(&resolved_did, resolved_handle.as_deref());
        let target = command_target(&resolved_did, resolved_handle.as_deref());

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
                "{handle_prefix}✅ Account {label} has been pardoned and added to your allowlist!\n\
                 They are now permanently immunized against future automatic bounces.\n\n\
                 💡 Changed your mind? Reply with `bounce {target}` or `perm {target}`."
            )),
            Ok(false) => Ok(format!(
                "{handle_prefix}ℹ️ Account {label} was not on your list, but has been added to your allowlist for future immunization."
            )),
            Err(e) => Ok(format!("{handle_prefix}❌ Failed to pardon and allowlist account: {e}")),
        }
    }

    async fn cmd_bounce(
        &self,
        sender_did: &str,
        raw_target: &str,
    ) -> Result<String, SkybouncerError> {
        let raw_target = raw_target.trim();
        if raw_target.is_empty() {
            return Ok(
                "Usage: `bounce <did|@handle>` (bounce or re-bounce an account onto your moderation list)"
                    .to_string(),
            );
        }

        let (resolved_did, resolved_handle, handle_prefix) = match self
            .resolve_dm_target(raw_target, " (e.g. `bounce did:plc:...`)")
            .await
        {
            Ok(v) => v,
            Err(msg) => return Ok(msg),
        };

        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };

        if let Err(guard_msg) =
            self.validate_moderation_target(&protected_did, &resolved_did, &handle_prefix)
        {
            return Ok(guard_msg);
        }

        let label = account_label_with_url(&resolved_did, resolved_handle.as_deref());
        let target = command_target(&resolved_did, resolved_handle.as_deref());

        match self
            .engine
            .manual_bounce_user(&protected_did, &resolved_did)
            .await
        {
            Ok((
                ManualBounceOutcome::Bounced {
                    duration,
                    restored_from_history,
                    ..
                },
                was_allowlisted,
            )) => {
                let allowlist_note = if was_allowlisted {
                    "\nAllowlist immunity was also removed."
                } else {
                    ""
                };
                let verb = if restored_from_history {
                    "re-added to"
                } else {
                    "added to"
                };
                if duration == BounceDuration::Permanent {
                    Ok(format!(
                        "{handle_prefix}✅ Account {label} has been {verb} your moderation list (**permanent** block).{allowlist_note}\n\n\
                         💡 Tip: To undo, reply with `pardon {target}` (or `pardon and allow {target}`)."
                    ))
                } else {
                    Ok(format!(
                        "{handle_prefix}✅ Account {label} has been {verb} your moderation list (Duration: **{}**).{allowlist_note}\n\n\
                         💡 Tip: Reply with `perm {target}` to make it permanent, or `pardon {target}` to undo.",
                        duration.display_label()
                    ))
                }
            }
            Ok((ManualBounceOutcome::AlreadyBounced { is_permanent: true }, _))
            | Ok((ManualBounceOutcome::UpgradedToPermanent, _)) => Ok(format!(
                "{handle_prefix}ℹ️ Account {label} is already permanently blocked on your moderation list."
            )),
            Ok((ManualBounceOutcome::AlreadyBounced { is_permanent: false }, _)) => Ok(format!(
                "{handle_prefix}ℹ️ Account {label} is already on your moderation list (temporary block).\n\n\
                 💡 Tip: Reply with `perm {target}` to make it permanent, or `pardon {target}` to undo."
            )),
            Err(e) => Ok(format!("{handle_prefix}❌ Failed to bounce account: {e}")),
        }
    }

    async fn cmd_upgrade_perm(
        &self,
        sender_did: &str,
        raw_target: &str,
    ) -> Result<String, SkybouncerError> {
        let raw_target = raw_target.trim();
        if raw_target.is_empty() {
            return Ok(
                "Usage: `perm <did|@handle>` (permanently block an account or upgrade a temporary block to permanent)"
                    .to_string(),
            );
        }

        let (resolved_did, resolved_handle, handle_prefix) = match self
            .resolve_dm_target(raw_target, " (e.g. `perm did:plc:...`)")
            .await
        {
            Ok(v) => v,
            Err(msg) => return Ok(msg),
        };

        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };

        if let Err(guard_msg) =
            self.validate_moderation_target(&protected_did, &resolved_did, &handle_prefix)
        {
            return Ok(guard_msg);
        }

        let label = account_label_with_url(&resolved_did, resolved_handle.as_deref());
        let target = command_target(&resolved_did, resolved_handle.as_deref());

        match self
            .engine
            .perm_bounce_user(&protected_did, &resolved_did)
            .await
        {
            Ok((ManualBounceOutcome::UpgradedToPermanent, was_allowlisted)) => {
                let allowlist_note = if was_allowlisted {
                    "\nAllowlist immunity was also removed."
                } else {
                    ""
                };
                Ok(format!(
                    "{handle_prefix}🔒 Temporary block for {label} has been upgraded to **permanent** on your moderation list.{allowlist_note}\n\n\
                     💡 Tip: If you later want to undo this block, reply with `pardon {target}` (or `pardon and allow {target}`)."
                ))
            }
            Ok((
                ManualBounceOutcome::Bounced {
                    restored_from_history,
                    ..
                },
                was_allowlisted,
            )) => {
                let allowlist_note = if was_allowlisted {
                    "\nAllowlist immunity was also removed."
                } else {
                    ""
                };
                let phrase = if restored_from_history {
                    "re-added and **permanently** blocked"
                } else {
                    "**permanently** blocked"
                };
                Ok(format!(
                    "{handle_prefix}🔒 Account {label} has been {phrase} on your moderation list.{allowlist_note}\n\n\
                     💡 Tip: If you later want to undo this block, reply with `pardon {target}` (or `pardon and allow {target}`)."
                ))
            }
            Ok((ManualBounceOutcome::AlreadyBounced { .. }, _)) => Ok(format!(
                "{handle_prefix}ℹ️ Account {label} is already permanently blocked on your moderation list."
            )),
            Err(e) => Ok(format!(
                "{handle_prefix}❌ Failed to permanently block account: {e}"
            )),
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

        let (resolved_did, resolved_handle, handle_prefix) =
            match self.resolve_dm_target(raw_target, "").await {
                Ok(v) => v,
                Err(msg) => return Ok(msg),
            };

        let label = account_label_with_url(&resolved_did, resolved_handle.as_deref());

        match self
            .engine
            .add_to_allowlist(sender_did, &resolved_did, Some("Added via DM bot"))
        {
            Ok(()) => Ok(format!(
                "{handle_prefix}✅ Account {label} has been added to your moderation allowlist.\n\
                 Their interactions will now bypass all moderation checks at zero cost."
            )),
            Err(e) => Ok(format!(
                "{handle_prefix}❌ Failed to allowlist account: {e}"
            )),
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

        let (resolved_did, resolved_handle, handle_prefix) =
            match self.resolve_dm_target(raw_target, "").await {
                Ok(v) => v,
                Err(msg) => return Ok(msg),
            };

        let label = account_label_with_url(&resolved_did, resolved_handle.as_deref());

        match self.engine.remove_from_allowlist(sender_did, &resolved_did) {
            Ok(true) => Ok(format!(
                "{handle_prefix}✅ Account {label} has been removed from your moderation allowlist."
            )),
            Ok(false) => Ok(format!(
                "{handle_prefix}ℹ️ Account {label} was not found on your moderation allowlist."
            )),
            Err(e) => Ok(format!(
                "{handle_prefix}❌ Failed to remove account from allowlist: {e}"
            )),
        }
    }

    fn cmd_allowlist(&self, sender_did: &str, page_arg: &str) -> Result<String, SkybouncerError> {
        let entries = self.engine.list_allowlist(sender_did)?;
        if entries.is_empty() {
            return Ok("ℹ️ Your moderation allowlist is empty.\n\nUse `allow <did|@handle>` to exempt trusted accounts from moderation.".to_string());
        }

        let total = entries.len();
        let total_pages = total.div_ceil(ALLOWLIST_PAGE_SIZE);
        let page = if page_arg.trim().is_empty() {
            1usize
        } else {
            match page_arg.trim().parse::<usize>() {
                Ok(p) if (1..=total_pages).contains(&p) => p,
                _ => {
                    return Ok(format!(
                        "ℹ️ Invalid page `{}`. Your allowlist has {total_pages} page{} (use `allowlist 1`–`allowlist {total_pages}`).",
                        page_arg.trim(),
                        if total_pages == 1 { "" } else { "s" }
                    ));
                }
            }
        };

        let start = page.saturating_sub(1).saturating_mul(ALLOWLIST_PAGE_SIZE);
        let end = start.saturating_add(ALLOWLIST_PAGE_SIZE).min(total);

        let mut out = if total_pages == 1 {
            format!(
                "🛡️ Your Moderation Allowlist ({total} account{}):\n\n",
                if total == 1 { "" } else { "s" }
            )
        } else {
            format!(
                "🛡️ Your Moderation Allowlist ({total} account{}, Page {page}/{total_pages}):\n\n",
                if total == 1 { "" } else { "s" }
            )
        };

        for (offset, entry) in entries[start..end].iter().enumerate() {
            let num = start.saturating_add(offset).saturating_add(1);
            let reason_str = entry.reason.as_deref().unwrap_or("No reason provided");
            let label = account_label_with_url(&entry.subject_did, entry.handle.as_deref());
            let added_iso = crate::types::format_system_time_iso8601(
                std::time::UNIX_EPOCH + std::time::Duration::from_micros(entry.created_at),
            );
            out.push_str(&format!(
                "{num}. {label}\n   Reason: {reason_str} | Added: {added_iso}\n"
            ));
        }

        if page < total_pages {
            out.push_str(&format!(
                "\nReply `allowlist {}` for the next page.",
                page.saturating_add(1)
            ));
        }

        Ok(out)
    }

    fn cmd_status(&self, sender_did: &str) -> String {
        let stats = self.engine.stats().snapshot();
        let storm_mode = self.engine.is_storm_mode_active(sender_did);
        let active_storms = self
            .engine
            .list_storms_for(Some(sender_did), true, 10)
            .map(|v| v.len())
            .unwrap_or(0);
        let state_label = if self.engine.is_tenant_paused(sender_did) {
            "⏸️ PAUSED"
        } else {
            "▶️ ACTIVE"
        };

        if self.engine.is_admin(sender_did) {
            format!(
                "📊 Skybouncer Engine Status (Admin Fleet View):\n\n\
                 • State: {}\n\
                 • Storm Mode: {}\n\
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
                 • Dogpiles Detected: {}\n\
                 • Storm Bounces Digested: {}\n\
                 • Enrolled Tenants: {}\n\
                 • Dry-Run Mode: {}",
                state_label,
                if storm_mode {
                    "⛈️ Active"
                } else {
                    "Normal"
                },
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
                stats.dogpiles_detected,
                stats.storm_bounces_digested,
                self.engine.tenant_registry().count().unwrap_or(0),
                if self.engine.is_dry_run() {
                    "Yes (shadow)"
                } else {
                    "No (live)"
                }
            )
        } else {
            let rubric = self.engine.rubric_for(sender_did);
            let my_bounces = self.engine.count_bounced_for(sender_did).unwrap_or(0);
            let allowlist_count = self
                .engine
                .list_allowlist(sender_did)
                .map(|l| l.len())
                .unwrap_or(0);
            format!(
                "📊 Skybouncer Status for Your Account:\n\n\
                 • Defense State: {}\n\
                 • Storm Mode: {}{}\n\
                 • Sensitivity: {}\n\
                 • Active Prompt: \"{}\"\n\
                 • Accounts Bounced from Your Posts: {}\n\
                 • Allowlisted (Immunized) Accounts: {}\n\
                 • Protection Mode: {}",
                state_label,
                if storm_mode {
                    "⛈️ Active"
                } else {
                    "Normal"
                },
                if active_storms > 0 {
                    format!(" ({active_storms} active storm(s))")
                } else {
                    String::new()
                },
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

    fn cmd_storms(&self, sender_did: &str) -> Result<String, SkybouncerError> {
        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };
        let storm_mode = self.engine.is_storm_mode_active(&protected_did);
        let active = self.engine.list_storms_for(Some(&protected_did), true, 5)?;
        let storm_badge = if storm_mode {
            "⛈️ **ACTIVE** (digest batching & 3x evaluation headroom)"
        } else {
            "🟢 Normal (immediate per-bounce DM alerts)"
        };

        if active.is_empty() {
            return Ok(format!(
                "📡 Skybouncer Storm Radar:\n\n\
                 • Storm Mode: {storm_badge}\n\
                 • Active Dogpile Storms: None detected right now.\n\n\
                 Use `storm on` / `storm off` to toggle Storm Mode manually."
            ));
        }

        let mut out = format!(
            "⛈️ Active Dogpile Storms ({}):\n• Storm Mode: {storm_badge}\n\n",
            active.len()
        );
        for (idx, storm) in active.iter().enumerate() {
            let num = idx.saturating_add(1);
            let target_hint = if storm.focal_post_uri.ends_with("/_mentions") {
                "Aggregate @mentions surge".to_string()
            } else {
                bsky_post_url_from_at_uri(&storm.focal_post_uri)
                    .unwrap_or_else(|| storm.focal_post_uri.clone())
            };
            let lock_state = if storm.threadgate_applied {
                "🔒 Replies Locked"
            } else {
                "🔓 Replies Open"
            };
            let snippet = truncate_chars(storm.focal_post_snippet.trim(), 90);
            let snippet_line = if snippet.is_empty() {
                String::new()
            } else {
                format!("\n   Post Snippet: \"{snippet}\"")
            };
            out.push_str(&format!(
                "{num}. [{}] Score {:.0}% • {} OON ({:.0}%) • {} bounced • {lock_state}\n   Target: {target_hint}{snippet_line}\n",
                storm.severity.as_str().to_ascii_uppercase(),
                storm.metrics.composite_score * 100.0,
                storm.metrics.unique_oon_authors_short,
                storm.metrics.out_of_network_ratio * 100.0,
                storm.bounces_during_storm,
            ));
        }

        out.push_str(
            "\nShield commands:\n\
             • `lock latest following` (or `nobody` / `followers`)\n\
             • `unlock latest` — Remove threadgate lock\n\
             • `detach latest` (or `detach latest all`) — Detach catalyst QTs\n\
             • `storm off` — Exit Storm Mode",
        );

        Ok(out)
    }

    fn cmd_storm_mode(&self, sender_did: &str, enabled: bool) -> Result<String, SkybouncerError> {
        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };
        self.engine.set_storm_mode(&protected_did, enabled);
        if enabled {
            Ok("⛈️ **Storm Mode ENABLED.**\n\n\
                • Individual bounce alerts are now batched into periodic digests.\n\
                • Evaluation rate-limit headroom has expanded 3x.\n\n\
                Reply `storms` to inspect active surges or `storm off` to return to normal alerts."
                .to_string())
        } else {
            Ok("🟢 **Storm Mode DISABLED.**\n\n\
                Resumed immediate per-bounce DM alerts and standard rate limits."
                .to_string())
        }
    }

    async fn cmd_lock(&self, sender_did: &str, raw_args: &str) -> Result<String, SkybouncerError> {
        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };

        let tokens: Vec<&str> = raw_args.split_whitespace().collect();
        let (target_arg, policy) = if tokens.is_empty()
            || (tokens.len() == 1 && tokens[0].eq_ignore_ascii_case("latest"))
        {
            ("latest", ThreadgatePolicy::FollowingOnly)
        } else if tokens.len() == 1 {
            if !tokens[0].starts_with("at://") && !tokens[0].starts_with("http") {
                if let Ok(parsed) = tokens[0].parse::<ThreadgatePolicy>() {
                    ("latest", parsed)
                } else {
                    (tokens[0], ThreadgatePolicy::FollowingOnly)
                }
            } else {
                (tokens[0], ThreadgatePolicy::FollowingOnly)
            }
        } else {
            let parsed = match tokens[1].parse::<ThreadgatePolicy>() {
                Ok(p) => p,
                Err(_) => {
                    return Ok(
                        "❌ Invalid lock policy. Choose `following`, `followers`, `mentions`, or `nobody`."
                            .to_string(),
                    );
                }
            };
            (tokens[0], parsed)
        };

        let post_target = if target_arg.eq_ignore_ascii_case("latest") {
            match self.resolve_latest_storm_post(&protected_did)? {
                Ok(uri) => uri,
                Err(msg) => return Ok(msg),
            }
        } else {
            match self
                .resolve_owned_dm_post_arg(&protected_did, target_arg)
                .await
            {
                Ok(v) => v,
                Err(msg) => return Ok(msg),
            }
        };

        if post_target.ends_with("/_mentions") {
            return Ok(
                "ℹ️ The latest storm is an aggregate @mentions surge without a single focal post.\n\
                 Provide your post URL or rkey explicitly: `lock <post_url|rkey> following`"
                    .to_string(),
            );
        }

        match self
            .engine
            .lock_thread(&protected_did, &post_target, policy)
            .await
        {
            Ok((_tg_uri, canonical_post)) => {
                let url = bsky_post_url_from_at_uri(&canonical_post)
                    .unwrap_or_else(|| canonical_post.clone());
                let rkey = canonical_post.rsplit('/').next().unwrap_or(&canonical_post);
                let dry_note = if self.engine.is_dry_run() {
                    "\n_(Shadow dry-run mode: simulated without writing to PDS)_"
                } else {
                    ""
                };
                Ok(format!(
                    "🔒 Thread replies locked (**{}**)\n\
                     Post: {url}{dry_note}\n\n\
                     Reply `unlock {rkey}` at any time to restore open replies.",
                    policy.display_label()
                ))
            }
            Err(e) => Ok(format!("❌ Failed to lock thread replies: {e}")),
        }
    }

    async fn cmd_unlock(
        &self,
        sender_did: &str,
        raw_target: &str,
    ) -> Result<String, SkybouncerError> {
        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };
        let target_arg = raw_target.split_whitespace().next().unwrap_or("");
        let post_target = if target_arg.is_empty() || target_arg.eq_ignore_ascii_case("latest") {
            match self.resolve_latest_storm_post(&protected_did)? {
                Ok(uri) => uri,
                Err(msg) => return Ok(msg),
            }
        } else {
            match self
                .resolve_owned_dm_post_arg(&protected_did, target_arg)
                .await
            {
                Ok(v) => v,
                Err(msg) => return Ok(msg),
            }
        };

        if post_target.ends_with("/_mentions") {
            return Ok(
                "ℹ️ Provide the specific post URL or rkey to unlock: `unlock <post_url|rkey>`"
                    .to_string(),
            );
        }

        match self
            .engine
            .unlock_thread(&protected_did, &post_target)
            .await
        {
            Ok(canonical_post) => {
                let url = bsky_post_url_from_at_uri(&canonical_post)
                    .unwrap_or_else(|| canonical_post.clone());
                let dry_note = if self.engine.is_dry_run() {
                    "\n_(Shadow dry-run mode: simulated without removing PDS record)_"
                } else {
                    ""
                };
                Ok(format!(
                    "🔓 Thread replies unlocked — open replies restored.\nPost: {url}{dry_note}"
                ))
            }
            Err(e) => Ok(format!("❌ Failed to unlock thread: {e}")),
        }
    }

    async fn cmd_detach(
        &self,
        sender_did: &str,
        raw_args: &str,
    ) -> Result<String, SkybouncerError> {
        let protected_did = match self.authorized_protected(sender_did) {
            Ok(did) => did,
            Err(msg) => return Ok(msg),
        };

        let tokens: Vec<&str> = raw_args.split_whitespace().collect();
        let (target_arg, qt_arg, disable_all) = if tokens.is_empty() {
            ("latest", None, false)
        } else if tokens.len() == 1 {
            if tokens[0].eq_ignore_ascii_case("all") {
                ("latest", None, true)
            } else {
                (tokens[0], None, false)
            }
        } else if tokens[1].eq_ignore_ascii_case("all") {
            (tokens[0], None, true)
        } else {
            (tokens[0], Some(tokens[1]), false)
        };

        let post_target = if target_arg.eq_ignore_ascii_case("latest") {
            match self.resolve_latest_storm_post(&protected_did)? {
                Ok(uri) => uri,
                Err(msg) => return Ok(msg),
            }
        } else {
            match self
                .resolve_owned_dm_post_arg(&protected_did, target_arg)
                .await
            {
                Ok(v) => v,
                Err(msg) => return Ok(msg),
            }
        };

        if post_target.ends_with("/_mentions") {
            return Ok(
                "ℹ️ Provide the specific post URL or rkey to detach quote-posts from: `detach <post_url|rkey> [qt_uri|all]`"
                    .to_string(),
            );
        }

        let explicit_qts = if let Some(raw_qt) = qt_arg {
            match self.resolve_any_post_at_uri(raw_qt).await {
                Ok(uri) => Some(vec![uri]),
                Err(msg) => return Ok(msg),
            }
        } else {
            None
        };

        match self
            .engine
            .detach_quotes(
                &protected_did,
                &post_target,
                explicit_qts.as_deref(),
                disable_all,
            )
            .await
        {
            Ok((_pg_uri, canonical_post, total_detached)) => {
                let url = bsky_post_url_from_at_uri(&canonical_post)
                    .unwrap_or_else(|| canonical_post.clone());
                let dry_note = if self.engine.is_dry_run() {
                    "\n_(Shadow dry-run mode: simulated without writing to PDS)_"
                } else {
                    ""
                };
                let mode_desc = if disable_all {
                    "and disabled all future quote-posts".to_string()
                } else {
                    format!("({total_detached} detached quote-post(s) total)")
                };
                Ok(format!(
                    "✂️ Updated `app.bsky.feed.postgate` shield {mode_desc}.\nPost: {url}{dry_note}"
                ))
            }
            Err(e) => Ok(format!("❌ Failed to apply postgate shield: {e}")),
        }
    }

    fn resolve_latest_storm_post(
        &self,
        protected_did: &str,
    ) -> Result<Result<String, String>, SkybouncerError> {
        if let Some(active) = self.engine.get_latest_active_storm_for(protected_did)? {
            return Ok(Ok(active.focal_post_uri));
        }
        let recent = self.engine.list_storms_for(Some(protected_did), false, 1)?;
        if let Some(latest) = recent.into_iter().next() {
            return Ok(Ok(latest.focal_post_uri));
        }
        Ok(Err(
            "ℹ️ No recent dogpile storm found. Provide a post URL or rkey explicitly.".to_string(),
        ))
    }

    async fn resolve_owned_dm_post_arg(
        &self,
        _protected_did: &str,
        raw: &str,
    ) -> Result<String, String> {
        let trimmed = raw.trim();
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return self.resolve_any_post_at_uri(trimmed).await;
        }
        Ok(trimmed.to_string())
    }

    async fn resolve_any_post_at_uri(&self, raw: &str) -> Result<String, String> {
        let trimmed = raw.trim();
        if trimmed.starts_with("at://") {
            return Ok(trimmed.to_string());
        }
        if let Ok(parsed) = url::Url::parse(trimmed) {
            let segments: Vec<&str> = parsed
                .path_segments()
                .map(|s| s.filter(|p| !p.is_empty()).collect())
                .unwrap_or_default();
            if segments.len() == 4 && segments[0] == "profile" && segments[2] == "post" {
                let actor = segments[1];
                let rkey = segments[3];
                let did = if actor.starts_with("did:") {
                    if skyauth::identity::validate_did_syntax(actor).is_err() {
                        return Err(format!("❌ Invalid DID syntax in post URL: `{actor}`."));
                    }
                    actor.to_string()
                } else {
                    match self.engine.resolve_handle(actor).await {
                        Some(resolved) => resolved,
                        None => {
                            return Err(format!(
                                "❌ Could not resolve Bluesky handle `@{actor}` from URL."
                            ));
                        }
                    }
                };
                return Ok(format!("at://{did}/app.bsky.feed.post/{rkey}"));
            }
        }
        Err(format!(
            "❌ Expected an `at://` post URI or Bluesky post URL (`https://bsky.app/profile/.../post/...`), got `{trimmed}`."
        ))
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
        if text.chars().count() > MAX_DM_TEST_TEXT_CHARS {
            return Ok(format!(
                "❌ Sample text exceeds maximum length of {MAX_DM_TEST_TEXT_CHARS} characters."
            ));
        }
        if !self.cmd_test_limiter.check_and_record(sender_did) {
            return Ok(
                "⏳ Rate limit reached for `test`. Please wait a minute before running more dry-run evaluations."
                    .to_string(),
            );
        }
        let Ok(_permit) = self.cmd_test_semaphore.try_acquire() else {
            return Ok(
                "⏳ Dry-run evaluator is currently busy; please retry in a moment.".to_string(),
            );
        };

        let sender_rubric = self.engine.rubric_for(sender_did);
        let synthetic_interaction = Interaction::synthetic(
            "did:plc:test-author-sample",
            sender_did,
            text,
            crate::matcher::InteractionType::DirectReply,
        )
        .with_post_uri("at://did:plc:test/app.bsky.feed.post/test1234")
        .with_post_cid("bafytest1234")
        .with_rubric(sender_rubric.clone());

        // Evaluate using heuristic first (only when enabled), then model
        let verdict = if self.engine.config().enable_heuristic_prefilter {
            self.engine
                .heuristic_classifier()
                .evaluate(&synthetic_interaction)
        } else {
            Verdict::permitted("Heuristic pre-filter disabled")
        };
        let final_verdict = if verdict.is_violation() {
            verdict
        } else {
            match self
                .engine
                .primary_classifier()
                .classify(&synthetic_interaction)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    return Ok(format!(
                        "⚠️ Test Evaluation Unavailable:\n\n\
                         • Reason: Classifier returned an error ({e})."
                    ));
                }
            }
        };

        match final_verdict {
            Verdict::Violation {
                category,
                confidence,
                reason,
            } => {
                let threshold_pct = sender_rubric.sensitivity.threshold() * 100.0;
                if sender_rubric.meets_threshold(&category, confidence) {
                    Ok(format!(
                        "🔍 Test Evaluation: **VIOLATION**\n\n\
                         • Category: **{category}**\n\
                         • Confidence: **{:.1}%** (Threshold: {:.0}% {})\n\
                         • Action: **Would Bounce**\n\
                         • Reason: {reason}",
                        confidence * 100.0,
                        threshold_pct,
                        sender_rubric.sensitivity
                    ))
                } else {
                    Ok(format!(
                        "🔍 Test Evaluation: **PERMITTED (BELOW THRESHOLD)**\n\n\
                         • Category: **{category}**\n\
                         • Confidence: **{:.1}%** (below your {:.0}% {} sensitivity threshold)\n\
                         • Action: **Permitted** (no bounce)\n\
                         • Reason: {reason}",
                        confidence * 100.0,
                        threshold_pct,
                        sender_rubric.sensitivity
                    ))
                }
            }
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

    /// Resolves a DM command target (`did:...` or `@handle`) to a DID and handle.
    ///
    /// Returns `(resolved_did, resolved_handle, handle_prefix)` where `handle_prefix`
    /// is a one-line "Resolved @handle to did" note for handle inputs (empty for DID
    /// inputs). On failure, returns the user-facing error message to display instead.
    async fn resolve_dm_target(
        &self,
        raw_target: &str,
        hint_suffix: &str,
    ) -> Result<(String, Option<String>, String), String> {
        let clean = crate::util::normalize_handle(raw_target);
        if clean.starts_with("did:") {
            if skyauth::identity::validate_did_syntax(clean).is_err() {
                return Err(format!("❌ Invalid DID syntax: `{clean}`."));
            }
            return Ok((clean.to_string(), None, String::new()));
        }
        match self.engine.resolve_handle(clean).await {
            Some(did) => {
                let prefix = format!("Resolved `@{clean}` to `{did}`.\n");
                Ok((did, Some(clean.to_string()), prefix))
            }
            None => Err(format!(
                "❌ Could not resolve handle `@{clean}` to a DID. Please verify the handle or provide the account's DID directly{hint_suffix}."
            )),
        }
    }

    /// Rejects attempts to bounce the protected user themselves or the Skybouncer bot account.
    fn validate_moderation_target(
        &self,
        protected_did: &str,
        resolved_did: &str,
        handle_prefix: &str,
    ) -> Result<(), String> {
        if resolved_did == protected_did {
            return Err(format!(
                "{handle_prefix}⚠️ You cannot bounce or block your own account on your moderation list."
            ));
        }
        if !self.bot_did.is_empty() && resolved_did == self.bot_did {
            return Err(format!(
                "{handle_prefix}⚠️ You cannot bounce the Skybouncer bot account."
            ));
        }
        Ok(())
    }

    /// Returns the sender DID if they are authorized to mutate a protected user's
    /// moderation list, or the permission-denied message otherwise.
    fn authorized_protected(&self, sender_did: &str) -> Result<String, String> {
        if self.is_authorized_sender(sender_did) {
            Ok(sender_did.to_string())
        } else {
            Err("❌ You do not have permission to modify this moderation list.".to_string())
        }
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

/// Extracts the next Unicode-whitespace-delimited token and the remaining trimmed tail.
fn take_next_token(s: &str) -> Option<(&str, &str)> {
    let trimmed = s.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.find(char::is_whitespace) {
        Some(idx) => Some((&trimmed[..idx], trimmed[idx..].trim_start())),
        None => Some((trimmed, "")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn dm_sender_limiter_evicts_and_expires_sender_buckets() {
        let mut limiter =
            DmSenderLimiterState::new(1, Duration::from_secs(10), Duration::from_secs(10));
        let t0 = Instant::now();

        for idx in 0..=MAX_TRACKED_DM_SENDERS {
            let did = format!("did:plc:sender{idx}");
            assert_eq!(limiter.check_rate(&did, t0), DmRateDecision::Allowed);
            assert!(limiter.allow_unknown_reply(&did, t0));
        }

        // Advance past window/cooldown so retention sweeps expired buckets cleanly.
        let t1 = t0 + Duration::from_secs(11);
        assert_eq!(
            limiter.check_rate("did:plc:fresh", t1),
            DmRateDecision::Allowed
        );
        assert!(limiter.allow_unknown_reply("did:plc:fresh", t1));
        assert!(!limiter.allow_unknown_reply("did:plc:fresh", t1));
    }
}
