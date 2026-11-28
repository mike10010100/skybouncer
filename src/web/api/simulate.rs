use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::*;

/// Maximum characters accepted in a guest sandbox evaluation.
pub const GUEST_SANDBOX_MAX_TEXT_CHARS: usize = 500;

/// Maximum characters accepted in `POST /api/simulate` post text.
pub const SIMULATE_MAX_TEXT_CHARS: usize = 4000;

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

/// Maximum base64-encoded image string size (~2 MiB decoded + data URI headroom).
const MAX_SIMULATE_IMAGE_BASE64_LEN: usize = 4 * 1024 * 1024;

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
        /// `true` when the global capacity ceiling triggered, `false` for per-IP throttling.
        is_global: bool,
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
                is_global: true,
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
                is_global: false,
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

pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

fn is_ip_in_trusted_proxies(ip: IpAddr, trusted_proxies: &[ipnet::IpNet]) -> bool {
    let canon = canonical_ip(ip);
    trusted_proxies.iter().any(|net| net.contains(&canon))
}

/// Extracts the client IP key for rate limiting.
///
/// Forwarded proxy headers (`cf-connecting-ip`, `x-real-ip`, or rightmost untrusted
/// `x-forwarded-for` hop) are honored ONLY when both:
/// 1. `peer_addr` is present and matches `trusted_proxies`, and
/// 2. `trusted_header` explicitly selects that header.
///
/// Direct/untrusted callers cannot spoof forwarded headers.
pub(crate) fn extract_client_ip_key(
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    trusted_header: Option<&str>,
    trusted_proxies: &[ipnet::IpNet],
) -> String {
    let Some(addr) = peer_addr else {
        return "local".to_string();
    };
    let peer_ip = canonical_ip(addr.ip());

    if let Some(hdr_name) = trusted_header
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|_| is_ip_in_trusted_proxies(peer_ip, trusted_proxies))
    {
        let hdr_lower = hdr_name.to_ascii_lowercase();
        if let Some(raw) = headers
            .get(hdr_lower.as_str())
            .and_then(|v| v.to_str().ok())
        {
            match hdr_lower.as_str() {
                "cf-connecting-ip" | "x-real-ip" => {
                    if let Ok(ip) = raw.trim().parse::<IpAddr>() {
                        return canonical_ip(ip).to_string();
                    }
                }
                "x-forwarded-for" => {
                    let parsed_hops: Vec<IpAddr> = raw
                        .split(',')
                        .filter_map(|part| part.trim().parse::<IpAddr>().ok())
                        .map(canonical_ip)
                        .collect();
                    if let Some(&client_ip) = parsed_hops
                        .iter()
                        .rev()
                        .find(|&&ip| !is_ip_in_trusted_proxies(ip, trusted_proxies))
                    {
                        return client_ip.to_string();
                    }
                    if let Some(&first_ip) = parsed_hops.first() {
                        return first_ip.to_string();
                    }
                }
                _ => {}
            }
        }
    }

    peer_ip.to_string()
}

fn decode_and_validate_base64_image(raw_b64: &str) -> Result<String, (StatusCode, String)> {
    let trimmed = raw_b64.trim();
    let payload_b64 = if let Some(after_data) = trimmed.strip_prefix("data:") {
        if let Some((meta, data)) = after_data.split_once(";base64,") {
            if !meta.to_ascii_lowercase().starts_with("image/") {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Unsupported data URI MIME type (expected image/*)".to_string(),
                ));
            }
            data.trim()
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid base64 image data URI".to_string(),
            ));
        }
    } else {
        trimmed
    };

    if payload_b64.len() > MAX_SIMULATE_IMAGE_BASE64_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            "Image exceeds maximum 2 MiB size limit".to_string(),
        ));
    }

    let compact: String = payload_b64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if compact.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid base64 image payload".to_string(),
        ));
    }

    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid base64 image payload".to_string(),
            )
        })?;

    if bytes.len() > crate::engine::simulate::MAX_SIMULATION_IMAGE_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            "Decoded image exceeds maximum 2 MiB size limit".to_string(),
        ));
    }

    if !crate::enricher::is_valid_image_magic_bytes(&bytes) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Unsupported or invalid image format (expected JPEG, PNG, GIF, or WebP)".to_string(),
        ));
    }

    Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
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
                crate::classifier::PRESET_BALANCED_PROMPT,
                Sensitivity::Medium,
            ),
        )),
        "anti_crypto" => Ok((
            "anti_crypto",
            RuleRubric::new(
                crate::classifier::PRESET_ANTI_CRYPTO_PROMPT,
                Sensitivity::High,
            ),
        )),
        "anti_hostility" => Ok((
            "anti_hostility",
            RuleRubric::new(
                crate::classifier::PRESET_ANTI_HOSTILITY_PROMPT,
                Sensitivity::High,
            ),
        )),
        "anti_ragebait" => Ok((
            "anti_ragebait",
            RuleRubric::new(
                crate::classifier::PRESET_ANTI_RAGEBAIT_PROMPT,
                Sensitivity::Medium,
            ),
        )),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "Unknown sandbox preset. Supported presets: balanced, anti_crypto, anti_hostility, anti_ragebait.".to_string(),
        )),
    }
}

/// Fetches a simulation image through `skyauth`'s SSRF-hardened HTTP client and enforces
/// image magic-byte validation (JPEG, PNG, GIF, or WebP) before base64-encoding it.
async fn fetch_and_validate_simulation_image_with_filter(
    url_str: &str,
    filter: &skyauth::ssrf::SsrfFilter,
) -> Result<String, (StatusCode, String)> {
    let bytes = crate::engine::simulate::fetch_simulation_image_bytes_with_filter(url_str, filter)
        .await
        .map_err(|e| map_ssrf_error(&e))?;
    if !crate::enricher::is_valid_image_magic_bytes(&bytes) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Fetched URL does not contain a valid image (expected JPEG, PNG, GIF, or WebP)"
                .to_string(),
        ));
    }
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
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

    if !state.simulate_limiter.check_and_record(&caller_did) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Simulation rate limit reached. Please wait a minute before running more evaluations."
                .to_string(),
        ));
    }

    let is_admin = state.engine.is_admin(&caller_did);

    let text = payload.text.trim().to_string();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Text cannot be empty".to_string()));
    }
    if text.chars().count() > SIMULATE_MAX_TEXT_CHARS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Text exceeds {SIMULATE_MAX_TEXT_CHARS} character limit"),
        ));
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

    // Resolve and strictly validate optional image attachments (decoded <= 2 MiB + magic bytes).
    let (image_base64, fetched_url_image) =
        if let Some(b64) = payload.image_base64.filter(|s| !s.trim().is_empty()) {
            let normalized = decode_and_validate_base64_image(&b64)?;
            (Some(normalized), false)
        } else if let Some(url) = payload.image_url.filter(|s| !s.trim().is_empty()) {
            let encoded = fetch_and_validate_simulation_image_with_filter(
                &url,
                &skyauth::ssrf::SsrfFilter::default(),
            )
            .await?;
            (Some(encoded), true)
        } else {
            (None, false)
        };

    let _sim_permit = state.simulate_semaphore.try_acquire().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "Simulator is busy processing concurrent evaluations; please retry shortly."
                .to_string(),
        )
    })?;

    let mut inputs = crate::engine::simulate::SimulationInputs::new(text, author_did, target_did)
        .with_image(image_base64, fetched_url_image)
        .with_persist_log(true);
    if let Some(rubric) = draft_override {
        inputs = inputs.with_rubric_override(rubric);
    }

    let result = state.engine.run_simulation(inputs).await.map_err(|e| {
        tracing::error!(error = %e, "Simulation classification failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Classification failed".to_string(),
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
    OptionalConnectInfo(peer_addr): OptionalConnectInfo,
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

    let ip_key = extract_client_ip_key(
        &headers,
        peer_addr,
        state.trusted_proxy_header.as_deref(),
        &state.trusted_proxies,
    );
    let (remaining_quota, quota_limit) = match state.guest_limiter.check_and_record(&ip_key) {
        GuestRateLimitDecision::Allowed { remaining, limit } => (remaining, limit),
        GuestRateLimitDecision::RateLimited {
            retry_after_secs,
            limit,
            is_global,
        } => {
            let msg = if is_global {
                format!(
                    "Free live sandbox is currently at global capacity. Sign in with Bluesky for dedicated custom rule testing, or retry in {retry_after_secs}s."
                )
            } else {
                format!(
                    "Free live sandbox limit reached ({limit} evaluations/min). Sign in with Bluesky for unlimited custom rule testing, or retry in {retry_after_secs}s."
                )
            };
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
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

    let Ok(_sim_permit) = state.simulate_semaphore.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "Simulator is busy processing concurrent evaluations; please retry shortly.",
        )
            .into_response();
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
            tracing::error!(error = %e, "Guest simulation classification failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Classification failed").into_response();
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn guest_sandbox_limiter_global_window_expiry_and_eviction() {
        // 1. Global circuit breaker triggers even across distinct IPs.
        let global_capped = GuestSandboxLimiter::new(5, 2, Duration::from_secs(60));
        assert!(matches!(
            global_capped.check_and_record("10.0.0.1"),
            GuestRateLimitDecision::Allowed { .. }
        ));
        assert!(matches!(
            global_capped.check_and_record("10.0.0.2"),
            GuestRateLimitDecision::Allowed { .. }
        ));
        assert!(matches!(
            global_capped.check_and_record("10.0.0.3"),
            GuestRateLimitDecision::RateLimited {
                retry_after_secs,
                limit: 5,
                is_global: true,
            } if retry_after_secs >= 1
        ));

        // 2. Global + per-IP entries expire once the sliding window elapses.
        let short_window = GuestSandboxLimiter::new(1, 10, Duration::from_millis(5));
        assert!(matches!(
            short_window.check_and_record("10.0.0.9"),
            GuestRateLimitDecision::Allowed { remaining: 0, .. }
        ));
        std::thread::sleep(Duration::from_millis(12));
        assert!(matches!(
            short_window.check_and_record("10.0.0.9"),
            GuestRateLimitDecision::Allowed { remaining: 0, .. }
        ));

        // 3. Saturated tracked-IP map evicts an existing bucket when none are expired.
        let capacity_limiter = GuestSandboxLimiter::new(1, 5000, Duration::from_secs(60));
        for idx in 0..=GUEST_SANDBOX_MAX_TRACKED_IPS {
            let key = format!("192.0.2.{idx}");
            assert!(matches!(
                capacity_limiter.check_and_record(&key),
                GuestRateLimitDecision::Allowed { .. }
            ));
        }

        // 4. Saturated tracked-IP map prunes expired buckets first when window has elapsed.
        let prune_limiter = GuestSandboxLimiter::new(1, 5000, Duration::from_millis(4));
        for idx in 0..GUEST_SANDBOX_MAX_TRACKED_IPS {
            let key = format!("198.51.100.{idx}");
            assert!(matches!(
                prune_limiter.check_and_record(&key),
                GuestRateLimitDecision::Allowed { .. }
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
        assert!(matches!(
            prune_limiter.check_and_record("203.0.113.1"),
            GuestRateLimitDecision::Allowed { .. }
        ));
    }

    #[test]
    fn test_extract_client_ip_key_trusted_proxy_and_cidr_matrix() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("198.51.100.77"),
        );
        hdrs.insert("x-real-ip", HeaderValue::from_static("198.51.100.88"));
        hdrs.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.1, 203.0.113.5, 10.0.0.2"),
        );

        let untrusted_peer = Some(SocketAddr::from(([192, 0, 2, 10], 44321)));
        let cf_peer = Some(SocketAddr::from(([172, 21, 0, 5], 50000)));
        let local_peer = Some(SocketAddr::from(([127, 0, 0, 1], 50001)));

        let cidrs = vec![
            "172.21.0.0/16".parse::<ipnet::IpNet>().unwrap(),
            "127.0.0.1/32".parse::<ipnet::IpNet>().unwrap(),
            "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap(),
        ];

        // No configured header or empty trusted proxies -> always use peer IP
        assert_eq!(
            extract_client_ip_key(&hdrs, untrusted_peer, None, &cidrs),
            "192.0.2.10"
        );
        assert_eq!(
            extract_client_ip_key(&hdrs, cf_peer, Some("cf-connecting-ip"), &[]),
            "172.21.0.5"
        );
        // Untrusted peer spoofing cf-connecting-ip -> rejected, falls back to peer IP
        assert_eq!(
            extract_client_ip_key(&hdrs, untrusted_peer, Some("cf-connecting-ip"), &cidrs),
            "192.0.2.10"
        );
        // Trusted CIDR peer + cf-connecting-ip -> honors cf-connecting-ip
        assert_eq!(
            extract_client_ip_key(&hdrs, cf_peer, Some("cf-connecting-ip"), &cidrs),
            "198.51.100.77"
        );
        // Trusted peer + x-real-ip -> honors x-real-ip
        assert_eq!(
            extract_client_ip_key(&hdrs, local_peer, Some("x-real-ip"), &cidrs),
            "198.51.100.88"
        );
        // Trusted peer + x-forwarded-for -> picks rightmost untrusted hop (203.0.113.5, skipping 10.0.0.2)
        assert_eq!(
            extract_client_ip_key(&hdrs, local_peer, Some("x-forwarded-for"), &cidrs),
            "203.0.113.5"
        );
        // Trusted peer + x-forwarded-for with ONLY trusted hops -> falls back to first hop
        let mut trusted_only = HeaderMap::new();
        trusted_only.insert(
            "x-forwarded-for",
            HeaderValue::from_static("127.0.0.1, 10.0.0.2"),
        );
        assert_eq!(
            extract_client_ip_key(&trusted_only, local_peer, Some("x-forwarded-for"), &cidrs),
            "127.0.0.1"
        );
        // Missing header on trusted peer -> falls back to peer IP
        assert_eq!(
            extract_client_ip_key(&HeaderMap::new(), local_peer, Some("x-real-ip"), &cidrs),
            "127.0.0.1"
        );
    }

    #[test]
    fn test_decode_and_validate_base64_image_and_magic_bytes() {
        assert!(decode_and_validate_base64_image("").is_err());
        assert!(decode_and_validate_base64_image("!!!invalid!!!").is_err());
        assert!(decode_and_validate_base64_image("aGVsbG8=").is_err()); // "hello" -> bad magic
        assert!(decode_and_validate_base64_image("data:image/png;notbase64").is_err());
        assert!(decode_and_validate_base64_image("data:text/plain;base64,aGVsbG8=").is_err());
        assert!(
            decode_and_validate_base64_image(&"A".repeat(MAX_SIMULATE_IMAGE_BASE64_LEN + 8))
                .is_err()
        );

        let valid_png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
        assert!(decode_and_validate_base64_image(valid_png_b64).is_ok());
        assert!(decode_and_validate_base64_image(&format!(
            "data:image/png;base64,{valid_png_b64}"
        ))
        .is_ok());
        assert!(crate::enricher::is_valid_image_magic_bytes(
            b"\xff\xd8\xff\xe0"
        ));
        assert!(!crate::enricher::is_valid_image_magic_bytes(
            b"<html>bad</html>"
        ));
    }

    #[tokio::test]
    async fn test_fetch_and_validate_simulation_image_url_magic_bytes_and_ssrf() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bad.html"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"<html>not an image</html>".as_slice()),
            )
            .mount(&server)
            .await;

        let valid_png: &[u8] = &[
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H',
            b'D', b'R',
        ];
        Mock::given(method("GET"))
            .and(path("/good.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(valid_png))
            .mount(&server)
            .await;

        let bad_url = format!("{}/bad.html", server.uri());
        let good_url = format!("{}/good.png", server.uri());

        // Production default SSRF filter rejects loopback HTTP URLs.
        let (ssrf_status, ssrf_msg) = fetch_and_validate_simulation_image_with_filter(
            &bad_url,
            &skyauth::ssrf::SsrfFilter::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(ssrf_status, StatusCode::BAD_REQUEST);
        assert!(ssrf_msg.contains("Invalid image URL") || ssrf_msg.contains("SSRF protection"));

        // Non-image content fetched over URL fails magic-byte validation with 400.
        let local_filter = skyauth::ssrf::SsrfFilter::new(true);
        let (magic_status, magic_msg) =
            fetch_and_validate_simulation_image_with_filter(&bad_url, &local_filter)
                .await
                .unwrap_err();
        assert_eq!(magic_status, StatusCode::BAD_REQUEST);
        assert!(magic_msg.contains("Fetched URL does not contain a valid image"));

        // Valid PNG bytes fetched over URL pass magic-byte validation and return base64.
        let encoded = fetch_and_validate_simulation_image_with_filter(&good_url, &local_filter)
            .await
            .unwrap();
        use base64::Engine;
        assert_eq!(
            encoded,
            base64::engine::general_purpose::STANDARD.encode(valid_png)
        );
    }
}
