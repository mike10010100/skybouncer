use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::*;

/// Maximum size of a URL-fetched simulation image (2 MiB).
const MAX_SIMULATION_IMAGE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum characters accepted in a guest sandbox evaluation.
pub const GUEST_SANDBOX_MAX_TEXT_CHARS: usize = 500;

/// Default per-IP rolling quota for the anonymous sandbox.
pub const GUEST_SANDBOX_PER_IP_LIMIT: usize = 6;

/// Default global rolling quota across all anonymous sandbox callers.
pub const GUEST_SANDBOX_GLOBAL_LIMIT: usize = 30;

/// Rolling rate-limit window duration in seconds for the anonymous sandbox.
pub const GUEST_SANDBOX_WINDOW_SECS: u64 = 60;

/// Maximum distinct client IP buckets retained simultaneously in memory.
const GUEST_SANDBOX_MAX_TRACKED_IPS: usize = 2048;

/// Maximum length of an unsaved draft rubric prompt on `POST /api/simulate`.
const MAX_DRAFT_PROMPT_CHARS: usize = 4000;

/// Outcome of checking the guest sandbox sliding-window rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestRateLimitDecision {
    /// Request permitted with remaining per-IP attempts in the current window.
    Allowed {
        /// Remaining evaluations available for this IP in the rolling window.
        remaining: usize,
        /// Per-IP limit configured on the limiter.
        limit: usize,
    },
    /// Request rejected because per-IP or global rolling quota is exhausted.
    RateLimited {
        /// Minimum seconds until at least one slot re-opens.
        retry_after_secs: u64,
        /// Per-IP limit configured on the limiter.
        limit: usize,
    },
}

#[derive(Debug)]
struct GuestLimiterState {
    global_hits: VecDeque<Instant>,
    per_ip_hits: HashMap<String, VecDeque<Instant>>,
}

/// Bounded in-memory sliding-window rate limiter guarding `POST /api/simulate/guest`.
#[derive(Debug)]
pub struct GuestSandboxLimiter {
    per_ip_limit: usize,
    global_limit: usize,
    window: Duration,
    inner: Mutex<GuestLimiterState>,
}

impl Default for GuestSandboxLimiter {
    fn default() -> Self {
        Self::new(
            GUEST_SANDBOX_PER_IP_LIMIT,
            GUEST_SANDBOX_GLOBAL_LIMIT,
            Duration::from_secs(GUEST_SANDBOX_WINDOW_SECS),
        )
    }
}

impl GuestSandboxLimiter {
    /// Creates a new [`GuestSandboxLimiter`] with explicit per-IP, global, and window bounds.
    #[must_use]
    pub fn new(per_ip_limit: usize, global_limit: usize, window: Duration) -> Self {
        Self {
            per_ip_limit: per_ip_limit.max(1),
            global_limit: global_limit.max(1),
            window,
            inner: Mutex::new(GuestLimiterState {
                global_hits: VecDeque::new(),
                per_ip_hits: HashMap::new(),
            }),
        }
    }

    /// Checks whether `ip_key` may execute a guest simulation at `now = Instant::now()` and records it if allowed.
    #[must_use]
    pub fn check_and_record(&self, ip_key: &str) -> GuestRateLimitDecision {
        let now = Instant::now();
        let mut guard = self.inner.lock();

        while let Some(&front) = guard.global_hits.front() {
            if now.saturating_duration_since(front) >= self.window {
                guard.global_hits.pop_front();
            } else {
                break;
            }
        }

        if guard.global_hits.len() >= self.global_limit {
            let retry_after_secs = guard
                .global_hits
                .front()
                .map(|&oldest| {
                    self.window
                        .saturating_sub(now.saturating_duration_since(oldest))
                        .as_secs()
                        .max(1)
                })
                .unwrap_or(1);
            return GuestRateLimitDecision::RateLimited {
                retry_after_secs,
                limit: self.per_ip_limit,
            };
        }

        if !guard.per_ip_hits.contains_key(ip_key)
            && guard.per_ip_hits.len() >= GUEST_SANDBOX_MAX_TRACKED_IPS
        {
            let window = self.window;
            guard.per_ip_hits.retain(|_, q| {
                while let Some(&front) = q.front() {
                    if now.saturating_duration_since(front) >= window {
                        q.pop_front();
                    } else {
                        break;
                    }
                }
                !q.is_empty()
            });
            if guard.per_ip_hits.len() >= GUEST_SANDBOX_MAX_TRACKED_IPS {
                if let Some(evict_key) = guard.per_ip_hits.keys().next().cloned() {
                    guard.per_ip_hits.remove(&evict_key);
                }
            }
        }

        let ip_queue = guard.per_ip_hits.entry(ip_key.to_string()).or_default();
        while let Some(&front) = ip_queue.front() {
            if now.saturating_duration_since(front) >= self.window {
                ip_queue.pop_front();
            } else {
                break;
            }
        }

        if ip_queue.len() >= self.per_ip_limit {
            let retry_after_secs = ip_queue
                .front()
                .map(|&oldest| {
                    self.window
                        .saturating_sub(now.saturating_duration_since(oldest))
                        .as_secs()
                        .max(1)
                })
                .unwrap_or(1);
            return GuestRateLimitDecision::RateLimited {
                retry_after_secs,
                limit: self.per_ip_limit,
            };
        }

        ip_queue.push_back(now);
        let used = ip_queue.len();
        guard.global_hits.push_back(now);

        GuestRateLimitDecision::Allowed {
            remaining: self.per_ip_limit.saturating_sub(used),
            limit: self.per_ip_limit,
        }
    }
}

fn extract_client_ip_key(headers: &HeaderMap) -> String {
    let candidates = ["cf-connecting-ip", "x-real-ip", "x-forwarded-for"];
    for name in candidates {
        if let Some(raw) = headers.get(name).and_then(|v| v.to_str().ok()) {
            let first = raw.split(',').next().unwrap_or("").trim();
            if !first.is_empty() {
                let sanitized: String = first
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-'))
                    .take(64)
                    .collect();
                if !sanitized.is_empty() {
                    return sanitized;
                }
            }
        }
    }
    "local".to_string()
}

fn resolve_guest_preset(
    raw: Option<&str>,
) -> Result<(&'static str, RuleRubric), (StatusCode, String)> {
    let key = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("balanced");
    match key {
        "balanced" => Ok((
            "balanced",
            RuleRubric::new(
                "Filter blatant spam, automated bot promotions, crypto/NFT shilling, unwanted commercial links, and direct harassment or personal attacks. Allow constructive critique, benign banter, and standard disagreements.",
                Sensitivity::Medium,
            ),
        )),
        "anti_crypto" => Ok((
            "anti_crypto",
            RuleRubric::new(
                "Aggressively filter all cryptocurrency, token, airdrop, memecoin, pump-and-dump, web3 wallet, NFT promotions, unsolicited WhatsApp/Telegram investment invitations, and high-frequency automated bot links.",
                Sensitivity::High,
            ),
        )),
        "anti_hostility" => Ok((
            "anti_hostility",
            RuleRubric::new(
                "Strictly filter hostile language, targeted harassment, abusive insults, slurs, doxxing threats, demeaning personal attacks, and aggressive intimidation directed at users.",
                Sensitivity::High,
            ),
        )),
        "anti_ragebait" => Ok((
            "anti_ragebait",
            RuleRubric::new(
                "Filter bad-faith sealioning, deceptive ragebait, troll provocations intended to incite conflict, and bad-faith harassment campaigns.",
                Sensitivity::Medium,
            ),
        )),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "Unknown sandbox preset. Supported presets: balanced, anti_crypto, anti_hostility, anti_ragebait.".to_string(),
        )),
    }
}

/// Fetches a simulation image through `skyauth`'s SSRF-hardened HTTP client, which
/// enforces scheme/host/IP validation, DNS pinning, redirect bounds, and a body size cap.
async fn fetch_simulation_image(url_str: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    skyauth::ssrf::SsrfFilter::default()
        .safe_get(url_str, MAX_SIMULATION_IMAGE_BYTES)
        .await
        .map_err(|e| map_ssrf_error(&e))
}

/// Maps an [`skyauth::SsrfError`] to an HTTP status and client-facing message.
fn map_ssrf_error(err: &skyauth::SsrfError) -> (StatusCode, String) {
    use skyauth::SsrfError;
    match err {
        SsrfError::InsecureScheme(_) | SsrfError::InvalidUrl(_) => {
            (StatusCode::BAD_REQUEST, format!("Invalid image URL: {err}"))
        }
        SsrfError::BlockedIp(_) | SsrfError::BlockedHost(_) => {
            (StatusCode::BAD_REQUEST, format!("SSRF protection: {err}"))
        }
        SsrfError::ResponseTooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("Simulation image exceeds limit: {err}"),
        ),
        SsrfError::DnsResolutionFailed(_)
        | SsrfError::TooManyRedirects
        | SsrfError::HttpStatus(_, _)
        | SsrfError::Http(_)
        | SsrfError::Io(_)
        | SsrfError::Json(_) => (
            StatusCode::BAD_GATEWAY,
            format!("Failed to fetch simulation image: {err}"),
        ),
    }
}

/// Converts an engine [`crate::engine::simulate::SimulateTierStage`] into the wire [`TierStageDetail`].
fn into_tier_detail(
    stage: Option<crate::engine::simulate::SimulateTierStage>,
) -> Option<TierStageDetail> {
    stage.map(|s| TierStageDetail {
        stage_name: s.stage_name,
        model: s.model,
        status: s.status,
        violates: s.violates,
        category: s.category,
        confidence: s.confidence,
        reason: s.reason,
    })
}

/// Handler for `POST /api/simulate`: runs a dry-run evaluation on sample text and optional images.
pub async fn simulate_interaction(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>, (StatusCode, String)> {
    let caller_did = extract_authenticated_caller(&headers, &state.engine).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication required to run evaluation simulation".to_string(),
        )
    })?;

    let is_admin = state.engine.is_admin(&caller_did);

    let text = payload.text.trim().to_string();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Text cannot be empty".to_string()));
    }

    let author_did = payload
        .author_did
        .unwrap_or_else(|| "did:plc:sample-author".to_string());
    let target_did = if is_admin {
        payload.target_did.unwrap_or_else(|| caller_did.clone())
    } else {
        caller_did.clone()
    };

    let draft_override = if payload.draft_prompt.is_some() || payload.draft_sensitivity.is_some() {
        let mut base = state.engine.rubric_for(&target_did);
        if let Some(prompt) = payload.draft_prompt.as_deref().map(str::trim) {
            if prompt.chars().count() > MAX_DRAFT_PROMPT_CHARS {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Draft prompt exceeds {MAX_DRAFT_PROMPT_CHARS} character limit"),
                ));
            }
            if !prompt.is_empty() {
                base.prompt = prompt.to_string();
            }
        }
        if let Some(sens) = payload.draft_sensitivity {
            base.sensitivity = sens;
        }
        Some(base)
    } else {
        None
    };

    // Resolve an optional image. A URL is fetched through the SSRF filter and
    // re-encoded; a provided base64 payload is used as-is.
    let (image_base64, fetched_url_image) =
        if let Some(b64) = payload.image_base64.filter(|s| !s.trim().is_empty()) {
            (Some(b64), false)
        } else if let Some(url) = payload.image_url.filter(|s| !s.trim().is_empty()) {
            let bytes = fetch_simulation_image(&url).await?;
            use base64::Engine;
            (
                Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
                true,
            )
        } else {
            (None, false)
        };

    let mut inputs = crate::engine::simulate::SimulationInputs::new(text, author_did, target_did)
        .with_image(image_base64, fetched_url_image)
        .with_persist_log(true);
    if let Some(rubric) = draft_override {
        inputs = inputs.with_rubric_override(rubric);
    }

    let result = state.engine.run_simulation(inputs).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Classification failed: {e}"),
        )
    })?;

    Ok(Json(SimulateResponse {
        violates: result.violates,
        category: result.category,
        confidence: result.confidence,
        reason: result.reason,
        evaluator: result.evaluator,
        meets_threshold: result.meets_threshold,
        threshold: result.threshold,
        images_evaluated: result.images_evaluated,
        tier1: into_tier_detail(result.tier1),
        tier2: into_tier_detail(result.tier2),
    }))
}

/// Handler for `POST /api/simulate/guest`: runs a rate-limited anonymous live sandbox dry-run
/// against one of Skybouncer's built-in public rubric presets.
pub async fn simulate_guest_interaction(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<GuestSimulateRequest>,
) -> Response {
    let text = payload.text.trim().to_string();
    if text.is_empty() {
        return (StatusCode::BAD_REQUEST, "Text cannot be empty").into_response();
    }
    if text.chars().count() > GUEST_SANDBOX_MAX_TEXT_CHARS {
        return (
            StatusCode::BAD_REQUEST,
            format!("Guest sandbox text exceeds {GUEST_SANDBOX_MAX_TEXT_CHARS} character limit"),
        )
            .into_response();
    }

    let (preset_key, rubric) = match resolve_guest_preset(payload.preset.as_deref()) {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };

    let ip_key = extract_client_ip_key(&headers);
    let (remaining_quota, quota_limit) = match state.guest_limiter.check_and_record(&ip_key) {
        GuestRateLimitDecision::Allowed { remaining, limit } => (remaining, limit),
        GuestRateLimitDecision::RateLimited {
            retry_after_secs,
            limit,
        } => {
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Free live sandbox limit reached ({limit} evaluations/min). Sign in with Bluesky for unlimited custom rule testing, or retry in {retry_after_secs}s."
                ),
            )
                .into_response();
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
            resp.headers_mut().insert(
                header::HeaderName::from_static("x-ratelimit-limit"),
                HeaderValue::from(limit),
            );
            resp.headers_mut().insert(
                header::HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from(0usize),
            );
            return resp;
        }
    };

    let inputs = crate::engine::simulate::SimulationInputs::new(
        text,
        "did:plc:guest-author",
        "did:plc:guest-sandbox",
    )
    .with_persist_log(false)
    .with_rubric_override(rubric);

    let result = match state.engine.run_simulation(inputs).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Classification failed: {e}"),
            )
                .into_response();
        }
    };

    let body = GuestSimulateResponse {
        simulation: SimulateResponse {
            violates: result.violates,
            category: result.category,
            confidence: result.confidence,
            reason: result.reason,
            evaluator: result.evaluator,
            meets_threshold: result.meets_threshold,
            threshold: result.threshold,
            images_evaluated: result.images_evaluated,
            tier1: into_tier_detail(result.tier1),
            tier2: into_tier_detail(result.tier2),
        },
        preset: preset_key.to_string(),
        remaining_quota,
        quota_limit,
        window_seconds: GUEST_SANDBOX_WINDOW_SECS,
    };

    let mut resp = (StatusCode::OK, Json(body)).into_response();
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-ratelimit-limit"),
        HeaderValue::from(quota_limit),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-ratelimit-remaining"),
        HeaderValue::from(remaining_quota),
    );
    resp
}
