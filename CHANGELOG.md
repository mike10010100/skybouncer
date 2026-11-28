# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.7] - 2026-11-28

### Added

- **Web Trusted Reverse-Proxy, Per-Endpoint Rate Limits & Timeouts (`src/web/{mod,oauth}.rs`, `src/web/api/{mod,simulate,resolve,telemetry}.rs`, `src/modlist/cache/core.rs`)**:
  - Added `TRUSTED_PROXY_HEADER` (`cf-connecting-ip`, `x-real-ip`, `x-forwarded-for`) and `TRUSTED_PROXIES` IP/CIDR allowlist (`ipnet`), honoring proxy headers only when `ConnectInfo<SocketAddr>` is inside configured trusted CIDRs and walking `x-forwarded-for` to the rightmost untrusted hop.
  - Added `OptionalConnectInfo` and wired Hyper HTTP/1 10s `header_read_timeout` + `GracefulShutdown` + `ConnectInfo(peer_addr)` in `run_web_server`, alongside router `TimeoutLayer` (130s), `ConcurrencyLimitLayer` (128), 64 KiB default body limit, and 8 MiB override on `/api/simulate`.
  - Added per-DID rate limiting (`20/min`) and concurrency semaphore (`2`) on `POST /api/simulate`, IP rate limits on `/api/auth/typeahead`, `/api/auth/preview`, and `/oauth/login`, distinct global vs per-IP 429 messages on `/api/simulate/guest`, memoized custom `AppViewClient`, and lightweight SQLite `SELECT 1` liveness probing in `/healthz` (`200`/`503`).
- **DM Bot Reliability, Grapheme Chunking & Closed-DM Backoff (`src/bot/{poller,handler,dispatcher,render}.rs`, `src/modlist/cache/bounces.rs`)**:
  - Added grapheme-cluster chunking/truncation via `unicode-segmentation` (`MAX_DM_CHUNKS = 10` cap + 100ms burst pacing) and routed `deliver_reauth_dm` through `send_dm_chunked`.
  - Added `ConvoIdCache` (`did -> convo_id`) and exponential `DeliveryBackoff` for closed/failing re-auth DMs.
  - Added bounded FIFO LRU `ProcessedMessageCache`, cursor pagination across `list_convo_requests`/`list_convos`/`get_messages`, `status == "request"` auto-acceptance, SQL `COUNT(*)` (`count_bounced_for`) in `cmd_status`, paginated `allowlist [page]` with ISO-8601 dates, `cmd_test` rate/concurrency limits + `enable_heuristic_prefilter` parity, and per-sender DM rate limits + unknown-command cooldowns to defeat bot ping-pong loops.
- **Environment Variable Reconciliation (`src/daemon.rs`, `src/engine/mod.rs`, `src/limiter.rs`, `.env.example`, `deploy/systemd/skybouncer.env.example`)**:
  - Extracted `BotEnvSettings::from_env()` and wired `CHAT_POLL_INTERVAL_SECS` / `SKYBOUNCER_CHAT_POLL_INTERVAL_SECS`, `SKYBOUNCER_JETSTREAM_URL`, `SENSITIVITY` / `SKYBOUNCER_SENSITIVITY`, `SKYBOUNCER_EVAL_CACHE_TTL_SECS` / `EVALUATION_CACHE_TTL_HOURS`, `LIST_NAME` / `LIST_DESCRIPTION`, `RATE_LIMIT_PER_HOUR`, `TRUSTED_PROXY_HEADER`, and `TRUSTED_PROXIES`.

### Changed

- **DM Bot Security, Ordering & Poison-Pill Resilience (`src/bot/{poller,handler,dispatcher}.rs`, `src/daemon.rs`)**:
  - Removed `PDS_ACCESS_TOKEN` and random `protected_dids` fallbacks for DM bot credentials and removed hardcoded `https://skybouncer.mike10010100.com` URL fallbacks.
  - Ordered `set_bypass_incoming_followers` strictly *after* authorization and SQLite persistence, enforced `skyauth::identity::validate_did_syntax` on `did:` targets, normalized Unicode whitespace command splitting, and prevented `get_messages` failures / `user_taken == 0` / failed `send_dm_chunked` from marking bot or unread messages read.
  - Prevented poller poison-pill loops by returning `Ok("❌ Invalid rubric: ...")` on invalid `set rules` and sending a generic error reply + read ack on unexpected handler failures.
- **Simulator Payload Bounds & Ops Hardening (`src/web/api/simulate.rs`, `src/modlist/cache/mod.rs`, `scripts/{backup,deploy}.sh`, `docker-compose.yml`, `deploy/systemd/{skybouncer.service,install.sh}`)**:
  - Enforced 4,000-char `SimulateRequest::text` cap, 2,000-char `evaluation_log.post_text` cap, 2 MiB + magic-byte validation on both `image_base64` and `image_url`, and empty/whitespace `?did=` `400` validation on `/api/resolve`.
  - Hardened `scripts/backup.sh` with `--user 10001:10001`, `.timeout 5000`, `PRAGMA integrity_check;`, stdout `gzip -c` streaming under `umask 077`, `0700`/`0600` permissions, and `shellcheck` cleanliness; moved `latest` tag in `scripts/deploy.sh` after healthcheck passes.
  - Bound Docker ports to `127.0.0.1`, added `read_only: true` + `/tmp` `tmpfs` + `pids_limit: 256` + `30s` `/healthz` check, hardened systemd unit sandboxing + `install.sh` key generation and eMudhra/Comodo CA distrust parity check.

## [0.3.6] - 2026-11-28

### Changed

- **SQLite Performance, Migrations, Indexes & Lock Elimination (`src/util.rs`, `src/modlist/cache/`, `src/tenant/registry/`, `src/engine/`, `src/web/api/`)**:
  - Updated `apply_common_pragmas` to apply `busy_timeout` before `journal_mode = WAL`, enable `auto_vacuum = INCREMENTAL`, and set `journal_size_limit` to 64 MiB (`67_108_864`).
  - Implemented non-colliding bit-packed `PRAGMA user_version` transactional migrations (`(tenant_ver << 16) | cache_ver`, `BEGIN IMMEDIATE ... COMMIT`, toggling `PRAGMA foreign_keys = OFF` outside the transaction), inspected `PRAGMA table_info` instead of ignoring `ALTER TABLE` errors, migrated `bounced_user_rkeys` PK to `(protected_did, listitem_rkey)` with matching `ON CONFLICT(protected_did, listitem_rkey) DO NOTHING`, added 5 composite/expression indexes (`idx_did_handles_handle_nocase`, `idx_tenants_handle_lower`, `idx_bounced_users_protected_at`, `idx_evaluation_log_target_source_ts`, `idx_dogpile_events_target_focal_status`), dropped redundant PK-prefix indexes (`idx_bounced_users_protected`, `idx_allowlist_protected`), and switched `list_evaluation_logs` / `count_evaluation_logs` to static `prepare_cached` arms.
  - Added per-`target_did` `evaluation_log` 5,000-row retention cap guarded by `GROUP BY target_did HAVING COUNT(*) > ?1`, added retention pruning for resolved `dogpile_events` and `bounce_history`, and ran periodic `PRAGMA incremental_vacuum` + `PRAGMA optimize` via `tokio::task::spawn_blocking`.
  - Added `TenantMeta` / `TenantSummary` + `RwLock<HashMap<String, TenantMeta>>` cache and lightweight SQL projections (`get_status`, `get_rubric`, `get_handle`, single-query `list_summaries`) on `TenantRegistry`, eliminating hot-path SQLite locks and AES-GCM decryptions/PEM parsing across engine ingestion, daemon startup, and web endpoints.
- **Modularized `src/enricher/` & AppView/CDN Hardening (`src/enricher/{mod,timing,fundraiser,appview,mock}.rs`)**:
  - Split `src/enricher.rs` into `src/enricher/{mod,timing,fundraiser,appview,mock}.rs` while preserving all public/`pub(crate)` exports and `--no-default-features` compilation.
  - Passed `depth=0` and `parentHeight=12` to `app.bsky.feed.getPostThread` and extracted `parent_post` (with `cid`) / `quoted_post` directly from `focal_post` (eliminating duplicate `getPosts` RPCs).
  - Parallelized CDN image fetching (`buffer_unordered(4)`) with a 6 MiB aggregate batch budget, strict `Content-Type: image/*` and magic-byte validation (`JPEG`/`PNG`/`WebP`/`GIF`), and strict ASCII `did:` / `cid` validation rejecting path traversal.
  - Reused a single `IdentityResolver` on `AppViewContextEnricher`, added a 20-minute TTL to `target_cache`, and excluded self-replies before counting `repeated_reply_template_count`.
- **Memory Bounds, Graph & Radar Optimization (`src/engine/handles.rs`, `src/matcher/`, `src/dogpile/tracker.rs`)**:
  - Normalized `handle_cache` keys (including `invalidate_handle`) to ASCII lowercase, capped at 10,000 entries, and pruned expired entries during maintenance.
  - Updated `FollowGraph::hydrate_followers` to populate `followers` under a single write lock without inserting `incoming_rkey_index` entries, cleaned empty outer map keys on unfollow, kept mutual protected-to-protected follow/unfollow edges consistent, and routed `hydrate_follows` / `hydrate_follow_records` through `FollowGraph::hydrate_batch`.
  - Added zero-allocation `&serde_json::Value` 4-vector DID probing in `TargetMatcher::match_all_interactions` before deserializing `PostRecord`.
  - Sharded `DogpileTracker` by `target_did`, bounded per-bucket deques/windows, and maintained incremental short-window author refcounts plus a lock-ordered `active_storms` index for O(1) commit ingestion and `is_storm_mode_active`.

### Fixed

- **Daemon `SIGTERM`, Shutdown Drain, `fast_path` Offload & CLI/Engine Polish (`src/daemon.rs`, `src/engine/`, `src/app.rs`, `src/tenant/registry/sessions.rs`)**:
  - Added Unix `SignalKind::terminate()` (`SIGTERM`) and `join_set.join_next()` task-crash monitoring to `daemon::run`, aligned drain timeout to 20s, added `PRAGMA wal_checkpoint(TRUNCATE)` on clean exit, and bounded `hydrate_cold_start` concurrency with cancellation checks.
  - Stopped dequeuing new items in `queue_worker` and `storm_worker` (and skipped `rx.try_recv()` drain) on cancellation so in-flight PDS writes finish cleanly; skipped `reauth_required` tenants in `prune_expired_bounces` and `get_pds_client`.
  - Offloaded `fast_path` remote I/O (`act_on_verdict`) onto the background worker queue and continued multi-target interaction loops on per-target errors.
  - Required `commit.rkey == "self"` on sovereign config `Create | Update` and `purpose == "app.bsky.graph.defs#modlist"` on `handle_list_commit`; aligned `SkybouncerEngine::new` with `Builder::build`, deduplicated heuristic logging, surfaced daemon HTTP errors and `--image <URL>` offline in `run_cli_simulate`, and URL-encoded `--handle` queries in `run_cli_pardon`.

## [0.3.5] - 2026-11-28

### Security

- **Classifier & Stage 3 Prompt-Injection Boundary Hardening (`src/classifier/`, `src/enricher.rs`, `src/dogpile/stance.rs`, `src/modlist/sovereign_config.rs`, `src/web/api/auth.rs`, `src/bot/handler.rs`)**:
  - Wrapped all untrusted candidate post text and enriched metadata (`author_profile`, `target_profile`, `image_alts`, `thread`, `quoted_post`, `link_card`, `author_signals`) inside a single per-request 64-bit hex nonce `<untrusted_input id="...">...</untrusted_input>` block with case-insensitive tag neutralization, control-character/newline normalization, quote escaping, JSON-encoded post text, and 80-character `display_name` caps (`MAX_DISPLAY_NAME_CHARS = 80`).
  - Moved anti-injection instructions into the Ollama `system` prompt and SystemOne `state` preamble, and enforced `MAX_RUBRIC_PROMPT_CHARS = 2000` across `RuleRubric::parse_updating`, `SovereignConfigRecord::to_rubric`, `extract_rubric_from_list_description`, `POST /api/rules`, DM `set rules`, and `JevClassifier`.
  - Isolated `LlmStormStanceClassifier` Stage 3 prompts (`focal_post`, `top_quotes`, `sample_replies`) with per-request nonce delimiters, JSON string escaping, and explicit anti-injection instructions across Ollama, StandardJev, and SystemOne dialects, and added a benign-stance veto floor in `compute_composite_score_with_metrics` when defensive distress or `violation_rate` is high.
- **PDS Gate & Threadgate Hardening (`src/dogpile/gates.rs`, `src/engine/storm_ops.rs`)**:
  - Removed the `"mutuals"` alias from `ThreadgatePolicy::from_str` with an explicit explanation recommending `following`.
  - Hardened `is_valid_rkey` / `parse_owned_post_uri` to reject `.`, `..`, `_mentions`, and `_storm`, and validated `app.bsky.feed.post` collection URIs in `PostgateRecord::merge_detaches`.
  - Restricted `apply_postgate_detach` missing-record detection to `is_pds_record_not_found`, propagated JSON deserialize errors, preserved existing `hiddenReplies` and `createdAt` in `apply_threadgate`, and switched both `apply_postgate_detach` and `apply_threadgate` to `put_record_with_swap` with CAS retry on `InvalidSwap`.

### Fixed

- **Tiered Confidence Arbitration, Routing, Endpoint Parsing & Retry Bounds (`src/classifier/`, `src/engine/`, `src/limiter.rs`, `src/error.rs`)**:
  - Removed eager `rubric.is_actionable()` downgrades from `JevClassifier::build_verdict` so nuanced `0.85..0.90` violations reach `TieredClassifier` and `act_on_verdict` enforces `rubric.meets_threshold` post-Tier-2.
  - Updated `CertaintyConfig::should_escalate` to escalate any `Permitted` confidence `< max_confidence` (or `NaN`) so fragmented softmax outputs escalate rather than bypassing Tier-2.
  - Replaced string-matched escalation counters with typed `EscalationReason` (`NuancedViolation` > `VisualMedia` > `SuspiciousBotSignals` > `UncertaintyBand`), fixing `tier2_image_escalations`.
  - Wired `DynamicModelPolicy` in `SkybouncerEngineBuilder::build` with configured model names and certainty flags, and reported dynamically routed model names in `DynamicPrimaryClassifier` detailed evaluations.
  - Fixed `reply_recipient_line` for quote+reply hybrids, added `"custom_rule"` and `"hate_speech"` to SystemOne criteria, fixed `/api/generate` -> `/api/chat` URL rewriting via shared `url::Url` resolution, added resilient `<think>`/fence/balanced-JSON Ollama extraction with `#[serde(default)]` `reason`, and hoisted prompt/JSON serialization outside retry loops.
  - Removed inner 100ms timeout retries in `JevClassifier`, bounded per-candidate HTTP 500 retries with a `ClassifierCircuitBreaker` distinguishing poison-pill 500s from 502/503/504 outages, added non-consuming `EvaluationRateLimiter::is_exhausted` before `enricher.check_relationship()`, shared an inference semaphore between `eval_worker` and `storm_worker` for matching Ollama endpoints, recorded heuristic violations in `DogpileTracker`, and fixed multi-directive `[...]` loops in `RuleRubric::parse_updating`.
- **Dogpile Radar Lifecycle, Clock, Catalyst & Math Fixes (`src/dogpile/`, `src/engine/`, `src/modlist/cache/storms.rs`, `src/time.rs`)**:
  - Resolved active SQLite storms on `set_storm_mode(..., false)`, added startup storm reconciliation/rehydration in both `SkybouncerEngineBuilder::build` and `SkybouncerEngine::new`, added `dismissed_until_us` suppression + immediate digest flush in `dismiss_storm`, deduplicated concurrent Stage 2/3 evaluations via an RAII in-flight set, rolled back `last_eval_us` on `storm_tx.try_send` drop, and enforced atomic high-water-mark severity in `upsert_active_storm`.
  - Unified storm/tracker timing on `monotonic_time_us()`, switched `eval_outcomes` pruning to `retain` + cap, counted quote+mention/quote+reply catalysts, left `dunk_ratio = 0.0` when `focal_post` is `None` while taking true max `dunk_ratio` across `quote_snaps`, guarded `DogpileConfig::from_env()` and `compute_burst_acceleration` against non-finite/degenerate floats, decoupled `postgate_state` and `alert_cooldowns` from 5m window pruning, stopped `evict_oldest_locked` below capacity, timestamped + reservoir-sampled `oon_samples`, and tracked actual newly-added detaches in `postgate_detaches_applied`.

## [0.3.4] - 2026-11-28

### Security

- **Zero-Logout `web_sessions` Migration & Pass-the-Hash Elimination (`src/tenant/registry/core.rs`, `src/tenant/registry/sessions.rs`)**:
  - Added atomic startup migration in `init_schema` prefixing existing 64-character lowercase hex `web_sessions` rows with `sha256:` and hashing any legacy unprefixed tokens in place.
  - Updated `create_web_session`, `validate_web_session`, and `delete_web_session` to query strictly `WHERE token = ?1` using `sha256:{hash}`, eliminating the raw pass-the-hash `OR token = ?2` clause.
- **Auto-Generated `0600` `.skybouncer.key`, Zero-Logout Secret Re-Encryption & Strict AAD (`src/crypto.rs`, `src/tenant/registry/sessions.rs`, `src/modlist/cache/core.rs`)**:
  - Added `SessionCipher::resolve_for_db_path`, loading/atomically creating `<db_dir>/.skybouncer.key` (`0600` on Unix) when `SKYBOUNCER_SESSION_ENCRYPTION_KEY` is unset and failing closed on malformed keys or unwritable directories.
  - Added `SessionCipher::decrypt_strict_with_aad` returning `zeroize::Zeroizing<String>`, enforced `session.sub == did` on reads and writes, set `0600` permissions on SQLite `.db`/`-wal`/`-shm` files, and added `TenantRegistry::migrate_encrypted_secrets` to transparently re-seal legacy plaintext, empty-AAD, and host-keyed secrets at startup.
  - Propagated `TenantRegistry::from_connection` errors in `SkybouncerEngineBuilder::build` and `SkybouncerEngine::new` instead of falling back to an in-memory database, and removed `std::process::exit(1)` from `TenantRegistry::fallback`.
- **Handle Cache Integrity (`src/web/api/resolve.rs`, `src/modlist/cache/handles.rs`, `src/tenant/registry/handles.rs`, `src/enricher.rs`)**:
  - Removed unauthenticated `did_handles` writes from `GET /api/auth/preview`, added `handle_verified` column gating reverse handle-to-DID lookups, normalized handles to ASCII lowercase, cleared stale cross-DID handle rows transactionally, enforced `ORDER BY` on lookups, and verified PLC fallback handles bidirectionally while ignoring `"handle.invalid"`.
- **OAuth Login CSRF, Same-Site CSRF, API Token, `/metrics` Auth & Error Sanitization (`src/web/`)**:
  - Bound `/oauth/login` to `/oauth/callback` via an `HttpOnly; SameSite=Lax` `skybouncer_oauth_state` SHA-256 state cookie verified with constant-time equality, revoked prior `skybouncer_session` cookies on re-login, and aborted session issuance if tenant enrollment fails.
  - Added same-site CSRF middleware (`Sec-Fetch-Site: same-origin` or `Origin` matching `public_url`) for cookie-authenticated non-`GET`/non-`HEAD` `/api/*` requests.
  - Replaced `validate_configured_api_token` comparison with constant-time SHA-256 matching, removed the `PDS_ACCESS_TOKEN` fallback, failed closed when `admin_did` is unset in multi-tenant mode, gated `/metrics` and `/api/metrics` behind Admin / `SKYBOUNCER_API_TOKEN` / `SKYBOUNCER_METRICS_TOKEN` (with `SKYBOUNCER_METRICS_PUBLIC=true` opt-in), fixed `logout` `Secure` cookie detection and Bearer session revocation, added `Cache-Control: no-store` and HSTS headers, and sanitized internal error messages in HTTP 500/502 responses and OAuth redirects.
- **Synchronous Startup `.env` Loading (`src/main.rs`, `src/env.rs`)**:
  - Replaced `#[tokio::main]` with a synchronous `fn main()` that runs `load_dotenv_file` (with empty/`=`/NUL key and NUL value guards) before building the Tokio runtime.

### Fixed

- **OAuth Refresh Concurrency, CAS & Single-Retry 401 Recovery (`src/tenant/registry/`, `src/engine/`)**:
  - Added epoch-guarded `pds_clients` eviction, SQL CAS (`WHERE did = ?1 AND session_json = ?2`) for `update_session_cas` (with transient DB retries and error propagation) and `mark_reauth_required_cas`, single-flight PDS HTTP 401 `ExpiredToken`/`InvalidToken` refresh+retry across all 11 PDS call sites, transactional `web_sessions` cleanup in `TenantRegistry::remove`, `BEGIN IMMEDIATE` / re-select race fix in `load_or_create_oauth_client_key`, and atomic `upsert_oauth_session` for `/oauth/callback`.
- **Multi-Tenant Isolation, Modlist Discovery & Sovereign Config (`src/modlist/`, `src/engine/`, `src/web/api/`)**:
  - Introduced `BounceOutcome::{Bounced, AlreadyBounced, BelowThreshold}`, per-tenant rubric/threshold enforcement in `ModListManager::bounce`, `pds_client.did() == protected_did` checks on PDS mutations, strict `is_single_tenant()` checks, `POST /api/tenant/toggle` `404` & `protected_dids` sync, non-admin `update_rules` protection, and fail-closed validation on blank `protected_did` values.
  - Switched `ModListManager::list_pds_records` to cursor-paginated `pds_client.list_records`, restricted `ensure_mod_list` to Skybouncer-owned lists (or persisted `mod_list_uri`) with AT-URI validation, made `pardon_user` delete SQLite `rkey`s incrementally with idempotent not-found handling, serialized `publish_sovereign_config` via `StripedAsyncLocks` + `put_record_with_swap`, fixed `"Could not locate record"` matching, and replaced `extract_rubric_from_list_description` delimiter heuristics with balanced JSON scanning.
- **Dependency Upgrades (`Cargo.toml`, `Cargo.lock`)**:
  - Updated `skyauth` to `0.3.14`, `skybase` to `0.1.13`, `tokio` to `1.53.3`, and added `zeroize` `1.8`.

## [0.3.3] - 2026-11-23

### Fixed

- **Bounded Classifier Timeout Retries, Self-Reply Prompt Disambiguation & Ollama Configuration (`src/classifier/jev.rs`, `src/dogpile/stance.rs`, `src/error.rs`, `src/engine/mod.rs`, `src/engine/processing.rs`, `.env.example`, `deploy/systemd/skybouncer.env.example`)**:
  - Added `SkybouncerError::is_classifier_timeout` and `JevClassifier` timeout error formatting (`"Jev API request timed out after ...ms"`) so per-request timeouts are distinguished from hard connection/5xx outages.
  - Added `SkybouncerConfig::max_classifier_timeout_retries` (`DEFAULT_MAX_CLASSIFIER_TIMEOUT_RETRIES = 2`, configurable via `MAX_CLASSIFIER_TIMEOUT_RETRIES` / `SKYBOUNCER_MAX_CLASSIFIER_TIMEOUT_RETRIES`) and bounded per-candidate timeout retries in `evaluate_candidate_inner` so a slow prompt cannot hold the single worker permit indefinitely while offline/5xx outages still hold and retry.
  - Added explicit self-reply disambiguation guidance in `JevClassifier` (both `system_prompt` rule `(1)(a)` and `reply_recipient_line` for `Replying To: Author`) so reasoning-capable Tier-2 models resolve `Replying To: Author` continuations against the conversation thread promptly without looping.
  - Raised `DEFAULT_FALLBACK_TIMEOUT_MS` to `120_000` (120s), exposed optional `OllamaChatRequest::think` (`OLLAMA_THINK` / `SKYBOUNCER_OLLAMA_THINK` / `FALLBACK_THINK`, `JevClassifier::with_ollama_think`), and set `think: Some(false)` on `LlmStormStanceClassifier` Ollama requests.
- Updated `skybase` dependency (`0.1.11` -> `0.1.12`) to pick up the persistent Jetstream idle read deadline fix.

## [0.3.2] - 2026-11-22

### Changed

- **Docker Dependency Layer Caching, CI Speedups & Security Update (`Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml`, `AGENTS.md`, `Cargo.lock`)**:
  - Added Stage 0 `manifest-prep` version normalization and dummy dependency pre-building in `Dockerfile` plus `5s` healthcheck intervals across `Dockerfile` and `docker-compose.yml` so app changes and version bumps reuse compiled crate layers.
  - Updated `mutants-smoke` in `.github/workflows/ci.yml` to run `--no-default-features` (`shared-key: "mutants-lean"`, keeping 17/17 mutant detection while skipping heavy feature crates) and added `Swatinem/rust-cache@v2` (`shared-key: "publish"`) to the `publish` job.
  - Unified local test + `llvm-cov nextest` verification in `AGENTS.md` and updated `url` (`2.5.8` -> `2.5.9`, `form_urlencoded` `1.2.2` -> `1.2.3`) in `Cargo.lock` to resolve `RUSTSEC-2026-0592`.

## [0.3.1] - 2026-11-21

### Fixed

- **Reply-Bait Bot Behavioral Enrichment, Timing Signals & System-2 Escalation (`src/enricher.rs`, `src/classifier/tiered.rs`, `src/classifier/jev.rs`, `src/lib.rs`)**:
  - Added zero-dependency UTC ISO-8601 timestamp parsing (`parse_iso8601_utc_secs`), strict ATProto TID decoding (`extract_rkey_from_at_uri`, `decode_tid_timestamp_us`), and zero-cost reply latency / forged-TID detection (`compute_reply_timing_signals`, `FAST_REPLY_LATENCY_MS = 2_500`, `FORGED_TID_DRIFT_SECS = 3_600`).
  - Added `AuthorActivitySignals` (`EnrichedContext::author_signals`) and opt-in `app.bsky.feed.getAuthorFeed` enrichment in `AppViewContextEnricher::from_env()` (`AUTHOR_FEED_CONTEXT=true` default, disabled in `AppViewContextEnricher::new()` for hermetic callers) to surface 1-hop reposted/quoted/bio fundraiser funnels (`chuffed.org`, `gofund.me`, `paypal.com/ncp/`, etc.), 10-minute stranger reply blasts (`REPLY_BLAST_MIN_DISTINCT_TARGETS = 4`), repeated reply templates, and up to 3 other-reply snippets while preserving zero-leakage privacy on benign accounts.
  - Added `CertaintyConfig::escalate_suspicious_bot_signals` (default `true`) and `CertaintyConfig::should_escalate_interaction` so `TieredClassifier` escalates Tier-1 `Permitted` verdicts to System-2 whenever `AuthorActivitySignals::has_suspicious_bot_signals()` triggers, without escalating benign organic mutual-aid boosters.
  - Extended `JevClassifier` (`Ollama` rule `(4)` and `SystemOne` `spam`/`permitted` criteria) to classify linkless automated reply-bait appeals backed by sniping, bursts, or fundraiser funnels as `"spam"` while explicitly permitting substantive on-topic replies from organic users who share fundraiser links on their profile.

## [0.3.0] - 2026-11-20

### Added

- **Personal Dogpile Radar (`src/dogpile/`, `src/enricher.rs`, `src/stream.rs`, `src/engine/storm_ops.rs`, `src/engine/processing.rs`)**:
  - Added reusable, feature-independent `dogpile` subsystem designed for future extraction into a standalone network-wide radar (`skydoppler`): rolling short/medium cascade windows (`DogpileTracker`), pure cascade/ratio math (`compute_direct_ratio`, `compute_dunk_ratio`, `compute_power_asymmetry`, `compute_burst_acceleration`, `compute_structural_score`, `compute_composite_score`), bundled Stage 3 LLM stance classifier (`LlmStormStanceClassifier`, `StormStanceClassifier`), and ATProto PDS gate helpers (`apply_threadgate`, `remove_threadgate`, `apply_postgate_detach`).
  - Added `app.bsky.feed.getPosts` engagement snapshot & `getProfile` follower-count enrichment on `ContextEnricher` / `AppViewContextEnricher` to identify top amplifying quote-post catalysts (`dunk_ratio`, `power_asymmetry`) without per-reply enrichment calls.
  - Subscribed Jetstream default collections to `app.bsky.feed.postgate` and `app.bsky.graph.block` so a protected user's manual blocks and postgate detaches boost surge detection as defensive distress signals while filtering routine in-network viral traffic.
- **Storm Mode & Digests (`src/dogpile/tracker.rs`, `src/modlist/cache/storms.rs`, `src/limiter.rs`, `src/bot/dispatcher.rs`)**:
  - Persisted active, resolved, and dismissed surge events in SQLite `dogpile_events` and added proactive DM storm & escalation alerts (`run_storm_alert_dispatcher`) with metrics, catalyst links, and stance summaries.
  - Collapsed individual per-bounce DM alerts into periodic Storm Mode digests (`run_storm_digest_dispatcher`) and expanded Tier-4 evaluation rate-limit headroom 3x (`EvaluationRateLimiter::check_and_record_with_multiplier`) while a storm is active.
- **Sovereign On-Demand PDS Shields, Bot Commands, Web API & UI (`src/bot/handler.rs`, `src/web/api/storms.rs`, `src/web/api/telemetry.rs`, `src/cli.rs`, `assets/dashboard.html`)**:
  - Added conversational DM commands (`storms`, `storm on|off`, `lock [post|latest] [policy]`, `unlock [post|latest]`, `detach [post|latest] [qt_uri|all]`) and authenticated Web API routes (`GET /api/storms`, `POST /api/storms/mode`, `POST /api/storms/dismiss`, `POST /api/storms/lock`, `POST /api/storms/unlock`, `POST /api/storms/detach`) enforcing strict tenant ownership.
  - Added Prometheus counters (`skybouncer_dogpiles_detected_total`, `skybouncer_storm_alerts_emitted_total`, `skybouncer_storm_bounces_digested_total`, `skybouncer_defensive_signals_observed_total`, `skybouncer_threadgates_applied_total`, `skybouncer_postgate_detaches_applied_total`), CLI final telemetry summary counters, and the Dashboard Active Storm Banner & Dogpile Radar card.

## [0.2.35] - 2026-11-14

### Fixed

- **Rhetorical Second-Person Apostrophe, Embed Metadata Enrichment & Lazy System-2 Context Vision (`src/enricher.rs`, `src/classifier/tiered.rs`, `src/classifier/jev.rs`, `src/engine/mod.rs`)**:
  - Extended `AppViewContextEnricher` to extract zero-extra-RPC embed metadata (`PostEmbedSummary`: external link-card titles/descriptions, image alt texts, and attached media presence markers) plus deduplicated `ContextImageRef` handles for focal parent/quoted posts and their nested quotes (`EnrichedContext::thread_ancestor_embeds`, `EnrichedContext::context_image_refs`, `EnrichedContext::image_alts`), rendered in `EnrichedContext::format_for_interaction` while leaving `format_for_classifier()` unchanged.
  - Added lazy System-2 context image hydration (`TieredClassifier::with_context_enricher`, wired in `EngineBuilder::build`) so parent/quoted thumbnails (`EnrichedContext::context_images_base64`, up to `MAX_CONTEXT_IMAGES = 2`) are fetched ONLY when Tier-1 already escalates, without forcing image escalation on benign replies.
  - Updated `JevClassifier` (`Ollama` modality framing + rules `(1)(b)`/`(2)`/`(3)` and `SystemOne` `harassment`/`permitted` criteria) to keep context images strictly separated from Author-uploaded images and to permit rhetorical second-person apostrophe addressing a named third-party person or public figure (e.g. `"Just for you Ari, you prick"`) distinct from `Target` while still flagging slang/insult vocatives (`"Karen"`, `"Bozo"`, `"Einstein"`, `"buddy"`, `"pal"`) and unqualified second-person attacks aimed at `Target`.

## [0.2.34] - 2026-11-13

### Fixed

- **Standalone Quote-Post Thread Enrichment & Group-Label Quote-Dunk Detection (`src/enricher.rs`, `src/classifier/jev.rs`, `src/classifier/rubric.rs`)**:
  - Updated `AppViewContextEnricher::enrich` so standalone `InteractionType::Quote` interactions (`parent_uri = None`, `quote_uri = Some(...)`) resolve the quoted post's conversation thread when it has multi-post ancestors (`ancestors.len() > 1`) or embedded quotes (`!quotes.is_empty()`), preventing multi-post debate context above a quoted post from being dropped.
  - Updated `EnrichedContext::format_for_interaction` to tag standalone quote-post thread focal entries with `[QUOTED POST — Author is quote-posting this post]` instead of `[IMMEDIATE PARENT — Author is replying to this post]`.
  - Added an explicit `Quoting: Target (...)` framing header in `reply_recipient_line` (`build_candidate_prompt`) and extended both Ollama System-2 (`(1)(c)`/`(2)`/`(3)`) and SystemOne (`harassment`/`permitted`) criteria so standalone quote-posts demeaning `Target` via a group/camp label representing `Target`'s stance in the quoted post/thread are flagged as targeted harassment while external-group agreement and non-abusive policy disagreements remain permitted.
  - Updated `DEFAULT_RUBRIC_PROMPT` (`quote-posts demeaning the protected user via supporter or group labels` with a streamlined third-party `Permit` clause aligned with `PRESET_BALANCED_PROMPT`) and added `LEGACY_DEFAULT_RUBRIC_PROMPT_V0_2_25` to `LEGACY_PROMPT_UPGRADES` for idempotent startup migration.

## [0.2.33] - 2026-11-13

### Fixed

- **Third-Person Commiseration & Ancestor Quote Coreference (`src/enricher.rs`, `src/classifier/jev.rs`, `src/lib.rs`)**:
  - Added `QuotedAncestor` (`EnrichedContext::thread_ancestor_quotes`) and `extract_ancestor_quote` to preserve embedded quote-post views (`app.bsky.embed.record#view` and `app.bsky.embed.recordWithMedia#view`, safely ignoring media-only, blocked, detached, or not-found embeds) along `getPostThread` ancestor walks without changing `ThreadPost` or `format_for_classifier()`.
  - Rendered ancestor quote summaries (`[quoting OtherUser @handle (did): "..."]`) before `[IMMEDIATE PARENT]` in `EnrichedContext::format_for_interaction`, exposing the third-party subject when `Target` or earlier commenters quote another user.
  - Expanded Ollama System-2 disambiguation rules (`(1)(a)`/`(1)(b)`/`(2)`/`(3)`) and SystemOne (`nimble`) criteria (`harassment`, `permitted`) so third-person insults/criticism (`"he"`, `"him"`, `"his"`, `"she"`, `"they"`) commiserating with `Target` about a quoted `OtherUser` or third party already discussed by `Target` are permitted, while third-person dunks aimed at `Target` for an audience when no third-party subject is under discussion remain flagged.

## [0.2.32] - 2026-11-11

### Fixed

- **Sub-Thread Reply Recipient Disambiguation & Target-Scoped Presets (`src/enricher.rs`, `src/classifier/jev.rs`, `src/classifier/rubric.rs`, `src/web/api/simulate.rs`, `assets/dashboard.html`, `src/tenant/registry/core.rs`, `src/engine/tenant_ops.rs`)**:
  - Added an explicit `Replying To:` speaker-role header (`Target`, `Author`, or `OtherUser [NOT Target — sub-thread reply to another commenter; second-person 'you'/'your' addresses this OtherUser unless Target is explicitly named or @mentioned]`) in `build_candidate_prompt` and tagged the final ancestor post in `EnrichedContext::format_for_interaction` with `[IMMEDIATE PARENT — Author is replying to this post]`, preventing sub-thread replies aimed at other commenters inside a protected user's thread from losing immediate-parent framing when `THREAD_CONTEXT=true`.
  - Tightened both Ollama System-2 disambiguation rules and SystemOne (`nimble`) criteria (`harassment`, `sealioning_or_bad_faith`, `spam`, `permitted`) so second-person insults (`"you"`, `"your"`) in `Replying To: OtherUser` sub-threads and generic rubric clauses (`"direct harassment"`, `"personal attacks"`) strictly require targeting the protected `Target` user rather than commenter-on-commenter arguments.
  - Scoped built-in rubric presets (`PRESET_BALANCED_PROMPT`, `PRESET_ANTI_HOSTILITY_PROMPT`, `PRESET_ANTI_RAGEBAIT_PROMPT`) across both the web dashboard (`RUBRIC_PRESETS`) and guest sandbox (`resolve_guest_preset`), and added idempotent startup migration (`LEGACY_PROMPT_UPGRADES` / `RuleRubric::upgrade_legacy_prompt`) across SQLite (`TenantRegistry::init_schema`) and ATProto sovereign configs (`SkybouncerEngine::sync_sovereign_config`, with best-effort PDS writeback) while preserving all custom tenant prompts verbatim.

## [0.2.31] - 2026-11-11

### Added

- **Rate-Limited Anonymous Live Classifier Sandbox (`src/web/api/simulate.rs`, `src/web/api/mod.rs`, `src/web/mod.rs`, `src/lib.rs`)**:
  - Added `POST /api/simulate/guest` (`simulate_guest_interaction`) backed by `GuestSandboxLimiter` (`6/min` per client IP + `30/min` global circuit breaker, `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `Retry-After` headers, 4 curated presets, `500`-char text cap, and zero `evaluation_log` database writes) so logged-out visitors can test live AI reply classification immediately without signing in.
- **Unsaved Draft House Rule Simulation (`src/engine/simulate.rs`, `src/web/api/simulate.rs`, `src/web/api/mod.rs`, `src/app.rs`)**:
  - Added `SimulationInputs::rubric_override` and optional `draft_prompt` / `draft_sensitivity` fields on `SimulateRequest` (`POST /api/simulate`) so authenticated tenants can test unsaved rubric edits live in the simulator before committing changes to their active rules.

### Changed

- **Progressive-Disclosure Onboarding & 3-Tab Tenant Workspace (`assets/dashboard.html`, `tests/web_tests.rs`)**:
  - Replaced the logged-out telemetry wall and locked rule forms with a dedicated **Onboarding Hero + Try the Live Classifier** sandbox (`#onboarding-view`).
  - Reorganized the signed-in dashboard into a focused 3-tab workspace (**Activity & Pardons** with personal summary tiles, bounce action wrapping, and Bluesky DM bot quick-reference; **House Rules & Sandbox** side-by-side editor + draft simulator; **Trusted Allowlist**).
  - Tucked engine KPIs and evaluation audit logs into a collapsed `<details id="operator-drawer">` (`Engine & Operator Telemetry`) and strictly hid `#admin-fleet-card` unless signed in as an administrator (`user.is_admin`).

## [0.2.30] - 2026-11-11

### Fixed

- **Authoritative PDS Chat Proxy Discovery for ATProto DM Bot (`Cargo.toml`, `src/daemon.rs`, `.env.example`, `tests/daemon_helpers_tests.rs`)**:
  - Upgraded `skybase` to `0.1.11` so `ChatClient::login_with_app_password` automatically extracts the bot account's `#atproto_pds` `serviceEndpoint` from `createSession`/`refreshSession` `didDoc` and proxies `chat.bsky.convo.*` calls through the PDS with `atproto-proxy: did:web:api.bsky.chat#bsky_chat`, resolving `401 BadJwtType` (`Invalid jwt type "at+jwt"`) rejections from `api.bsky.chat` and eliminating `refreshSession` retry storms.
  - Logged the resolved `chat_endpoint` at daemon startup in `resolve_bot_client` and updated `.env.example` so `CHAT_ENDPOINT` is commented out by default.

## [0.2.29] - 2026-11-11

### Changed

- **Atmosphere Suite Dashboard Redesign & Sister-App Unification (`assets/dashboard.html`)**:
  - Redesigned the embedded single-file Sovereign Moderation Dashboard around the shared **Atmosphere Instrument** visual system (`1px` architectural hairlines, `tabular-nums` counters, inline stroke SVG iconography, and cobalt `#3b82f6` / `#2563eb` signature accents) unified with sister app `for-your-consideration`.
  - Added a zero-FOUC `<head>` theme bootstrap and 3-way header theme switcher (`System` / `Light` / `Dark`) persisted in `localStorage` (`atmosphere-theme`) with synchronized `aria-pressed` accessibility state and live `prefers-color-scheme` tracking.
  - Added a `.suite-nav` sister-app switcher pill in the sticky header and footer cross-link routing dynamically between Skybouncer and For Your Consideration (`localhost:3030/dashboard` locally, `fyc.mike10010100.com/dashboard` in production).
  - Condensed pipeline KPI cards into a compact single-row horizontal telemetry strip above the fold with responsive full-span mobile wrapping and equal-height side-by-side workspace cards.

## [0.2.28] - 2026-11-11

### Fixed

- **Release Auto-Publish DAG Condition (`.github/workflows/ci.yml`)**:
  - Added `always() && needs.quality-gate.result == 'success'` to the `publish` job's `if:` expression so GitHub Actions does not transitively skip release publishing when the PR-only `mutants-smoke` job is skipped on `main` pushes.

## [0.2.27] - 2026-11-11

### Changed

- **Parallelized & Cached CI Quality Gate Pipeline (`.github/workflows/ci.yml`, `Cargo.toml`)**:
  - Split the monolithic serial quality gate into parallel `lint-and-audit`, `coverage-and-tests`, and PR-scoped `mutants-smoke` jobs fanned into the branch-protected `Rust Quality Gate` check, eliminating redundant sibling repository checkouts and dynamically reading `skybase`/`skyauth` dependency versions during release publishing.
  - Combined `cargo nextest` and `cargo llvm-cov` into a single `cargo llvm-cov nextest --all-targets` pass with `CARGO_LLVM_COV_TARGET_DIR=target` so `Swatinem/rust-cache` caches third-party dependency builds across coverage runs instead of rebuilding from scratch twice per run.
  - Configured `cargo mutants` with `--in-place --cargo-arg --lib` and scoped `[profile.dev.package."*"]` / `[profile.test.package."*"]` `opt-level = 1` to dependencies so mutation smoke tests reuse cached dependencies, link only the library unit-test binary rather than all 34 integration test binaries, and execute all 17 mutants cleanly without `-D warnings` unviable false negatives.

## [0.2.26] - 2026-11-11

### Added

- **Parent `"Replying to:"` Deep Links in Bounce Alerts & `recent` DMs (`src/engine/mod.rs`, `src/engine/processing.rs`, `src/bot/dispatcher.rs`, `src/bot/handler.rs`, `src/bot/render.rs`, `src/modlist/cache/`)**:
  - Added `BounceNotification::reply_to_uri` and persisted `BouncedUser::reply_to_uri` (`bounced_users.reply_to_uri`) populated from `Interaction::parent_uri` whenever a bounced post is a reply.
  - Updated `format_bounce_alert` and `BotCommandHandler` (`recent`) to emit a hotlinkable `Replying to: https://bsky.app/profile/.../post/...` line alongside `Profile:` and `Post:` (omitted cleanly for non-reply mentions and standalone quotes), plus line-aligned DM chunking (`MAX_DM_CHARS`) so outbound ATProto Chat messages stay within `chat.bsky.convo.defs#messageInput` grapheme limits.
- **Post-Pardon `bounce` & `perm` DM Commands with Bounce History Restoration (`src/bot/handler.rs`, `src/engine/modlist_ops.rs`, `src/modlist/manager.rs`, `src/modlist/cache/`)**:
  - Added `bounce <did|@handle>` (aliases `rebounce`, `re-bounce`, `block`) and upgraded `perm <did|@handle>` so protected users can re-bounce or permanently block an account via DM after `pardon`, `pardon and allow`, or temporary TTL expiration (automatically revoking any prior allowlist immunity and guarding against self/bot targets).
  - Added the `bounce_history` SQLite table (`ArchivedBounce`, `DeduplicationCache::get_bounce_history_for`) to preserve violation category, confidence, rationale, offending post URI/text, and parent `reply_to_uri` across pardons and expirations when an account is re-bounced or permanently blocked.

### Fixed

- **Enriched Handle Persistence & Interleaved DM Alert Polling (`src/engine/processing.rs`, `src/bot/poller.rs`)**:
  - Persisted author handles resolved during live `ContextEnricher` evaluations and bounce notifications into SQLite `did_handles` so subsequent `recent` DMs, dashboard `/api/bounces` feeds, and `@handle` commands render `@handle` without redundant remote lookups.
  - Fixed `run_bot_poller` so unread user DM commands are never skipped or prematurely marked read when a proactive bounce alert from `run_bounce_alert_dispatcher` interleaves as `convo.last_message` within the same polling interval.

## [0.2.25] - 2026-11-11

### Added

- **Target-Aware Default Rubric & Nuanced Interpersonal Tier-2 Escalation (`src/classifier/rubric.rs`, `src/classifier/mod.rs`, `src/classifier/tiered.rs`, `src/engine/mod.rs`, `src/tenant/registry/core.rs`)**:
  - Added `DEFAULT_RUBRIC_PROMPT` (and idempotent SQLite startup migration from `LEGACY_DEFAULT_RUBRIC_PROMPT` for unmodified default tenant rubrics) explicitly scoping harassment and sea-lioning to attacks aimed at the protected user while carving out non-targeted profanity, sarcasm, blunt disagreement, heated political debate, quoting the protected user to argue with someone else, and hostility directed at third parties, politicians, groups, or other commenters.
  - Added `ViolationCategory::is_nuanced_interpersonal` and `CertaintyConfig::escalate_nuanced_violations` (default `true`, configurable via `ESCALATE_NUANCED_VIOLATIONS` / `SKYBOUNCER_ESCALATE_NUANCED_VIOLATIONS`) so Tier-1 interpersonal violation candidates (`harassment`, `sea_lioning`, `hate_speech`, `custom`) escalate to System-2 reasoning before bouncing an account, while automated `crypto_spam`, `phishing`, and `spam` resolve immediately at Tier-1.
- **Quote Post, Target Profile, & Speaker-Role Enrichment (`src/matcher/interaction.rs`, `src/matcher/target.rs`, `src/enricher.rs`)**:
  - Added `Interaction::quote_uri` preserved across all four `TargetMatcher::match_all_interactions` vectors (`DirectReply`, `ThreadReply`, `Mention`, `Quote`).
  - Enriched cached protected `target` profiles and `quoted_post` records in `AppViewContextEnricher`, enabled `thread_context: true` by default in `AppViewContextEnricher::from_env` (`THREAD_CONTEXT` / `SKYBOUNCER_THREAD_CONTEXT`), and added `EnrichedContext::format_for_interaction` labeling thread/parent/quote speakers as `Author`, `Target`, or `OtherUser`.

### Fixed

- **SystemOne & Deterministic Ollama Classification Precision (`src/classifier/jev.rs`)**:
  - Injected `Active House Rules for Target` into `SystemOne` `state` payloads, rewrote choice criteria around target directionality (catching derisive third-person nicknames while excluding non-targeted profanity and mild grumbling), and read `probabilities.get(&answer.choice)` before falling back to `1.0 - permitted` when computing `SystemOne` violation confidence.
  - Enforced deterministic `temperature: 0.0` in `OllamaChatOptions`, added explicit multi-turn pronoun/thread referent disambiguation rules to the Ollama system prompt, and normalized verbose LLM category labels to canonical `ViolationCategory` variants.
- **AppView Immediate Parent & `#blockedPost` Thread Truncation (`src/enricher.rs`)**:
  - Fixed `AppViewContextEnricher::fetch_thread_chain` to retain the immediate parent post when `app.bsky.feed.getPostThread` is queried by `parent_uri` and to hop across up to 3 ATProto `app.bsky.feed.defs#blockedPost` boundaries so multi-turn threads involving blocked participants are not truncated.

## [0.2.24] - 2026-11-10

### Changed

- **Upgraded `skyauth` to `0.3.13`, `skybase` to `0.1.10`, & `rusqlite` to `0.41` (`Cargo.toml`)**:
  - Incorporates `skyauth 0.3.13` (formally verified Verus/rustc clock-skew leeway kernel, required service-auth claims, strict `did:plc`/`did:web` syntax checks, IPv6 SSRF validation) and `skybase 0.1.10` (transactional index notifications, monotonic cursor persistence, fail-closed `DPoP-Nonce` challenge handling, and `ChatClient`/`AppViewClient` hardening).
  - Upgraded `rusqlite` from `0.40` to `0.41` (`libsqlite3-sys 0.37.0`) to resolve `RUSTSEC-2026-0459`.

### Fixed

- **Engine, Tenant Isolation, & Follower Hydration Correctness (`src/app.rs`, `src/daemon.rs`, `src/engine/mod.rs`, `src/engine/processing.rs`, `src/engine/simulate.rs`, `src/engine/tenant_ops.rs`, `src/matcher/follow_graph.rs`)**:
  - Hydrated `bypass_incoming_followers` and `protected_dids` across startup (`hydrate_from_registry`), `register_tenant`, and `sync_tenant_from_registry`, and recorded `gate_bypassed_allowlist` in `AppMetrics::from_engine`.
  - Filtered inactive tenants (`!t.is_active`) from startup PDS provisioning in `daemon::provision_pds_resources` and set `supports_images: true` on the fallback Ollama HTTP classifier.
  - Logged heuristic hit verdicts to the tenant activity log in queued (`ApprovalMode::Queue`) mode and matched heuristic confidence/outcome parity in `simulate_interaction`.
  - Scoped `rkey`-based follow deletion (`delete_record_by_rkey`) by tenant DID when `hydrate_followers` replaces a tenant's incoming follower snapshot.
- **Sovereign Config, Rubric, Bot, & Web API Hardening (`src/modlist/sovereign_config.rs`, `src/classifier/rubric.rs`, `src/bot/handler.rs`, `src/web/api/tenant.rs`, `src/web/oauth.rs`, `assets/dashboard.html`)**:
  - Replaced substring `find("}]")` in `SovereignConfigManager::extract_Rules_from_description` with balanced JSON array bracket scanning so rule strings containing `"}]"` are preserved intact.
  - Normalized `{"custom": 0}` to `BounceDuration::Permanent` in `BounceDuration::deserialize` and made DM bot `sensitivity` commands case-insensitive.
  - Preserved existing `is_active` and `sensitivity` state when an existing tenant re-authenticates via OAuth (`oauth_callback`), isolated `POST /api/tenant/toggle` to per-tenant pause (`set_tenant_paused`) rather than halting the global multi-tenant engine, and omitted `Secure` from the cleared session cookie on plain HTTP localhost logout.

## [0.2.23] - 2026-11-03

### Changed

- **Upgraded `skyauth` to `0.3.12` & `skybase` to `0.1.9` (`Cargo.toml`)**:
  - Incorporates runtime-scoped connection-pooled `SsrfDnsResolver` (`reqwest::dns::Resolve`) eliminating per-request TLS client rebuilds across all SSRF-protected outbound PDS, PLC, and OAuth requests.

## [0.2.22] - 2026-11-03

### Changed

- **Formally Verified `skyauth 0.3.11` & Hardened `skybase 0.1.8` Upgrade (`Cargo.toml`, `src/tenant/registry/mod.rs`)**:
  - Upgraded `skyauth` to `0.3.11` (Verus + Kani formally verified `service_auth` Multikey & curve binding kernels) and `skybase` to `0.1.8`.
  - Added disk-backed `TenantRegistry::open` persistence and nested directory creation test coverage (`93.09%` total line coverage).

## [0.2.21] - 2026-11-03

### Changed

- **Unified ATProto Plane Consolidation (`Cargo.toml`, `src/stream.rs`, `src/matcher/interaction.rs`, `src/matcher/target.rs`, `src/web/api/resolve.rs`, `src/enricher.rs`)**:
  - Upgraded to `skybase 0.1.7` and `skyauth 0.3.10`.
  - Delegated `src/stream.rs` (`run_jetstream_streamer`, `resolve_resume_cursor`, and cursor rewind constants) to `skybase::ingest::streamer`, gaining periodic 15-second WebSocket keepalive pings and lock-free `CursorTracker` watermark management.
  - Delegated AT-URI authority extraction (`extract_did_from_at_uri`, `extract_did_for_collection`) and `app.bsky.embed.gallery` extraction (`Embed::extract_gallery_items`) to `skybase::repo` and `skybase::lexicon`.
  - Reused a shared `AppViewClient` connection pool across `GET /api/auth/typeahead` and `GET /api/auth/preview` instead of constructing a new `reqwest::Client` per request, and unified DID document fallback resolution in `AppViewContextEnricher::resolve_did` onto `skyauth::identity::IdentityResolver`.

## [0.2.20] - 2026-11-01

### Added

- **Capped Weekly Re-Authentication Reminder DMs (`src/tenant/registry/mod.rs`, `src/tenant/registry/core.rs`, `src/tenant/registry/sessions.rs`, `src/bot/dispatcher.rs`)**:
  - Added `DEFAULT_REAUTH_REMINDER_INTERVAL` (7 days) and `MAX_REAUTH_NOTIFICATIONS = 3` to configure re-auth reminder frequency and pacing.
  - Added `reauth_notify_count` tracking column to `tenants` table with automatic backfill migration for previously notified tenants, resetting to 0 upon successful OAuth reconnection.
  - Added `format_reauth_alert_with_count` to tailor message copy across the initial notification, weekly reminder 1/2 (with an opt-out reminder via `pause`), and final reminder 2/2.
  - Updated `run_reauth_alert_dispatcher` with an automated 60-second periodic sweep checking for pending reminders against the 7-day interval and 3-notification cap.

## [0.2.19] - 2026-11-01

### Fixed

- **Short-Circuit Moderation & Startup Provisioning for Tenants Awaiting Re-Authentication (`src/engine/tenant_ops.rs`, `src/daemon.rs`, `src/engine/mod.rs`)**:
  - Updated `SkybouncerEngine::is_tenant_paused` to return `true` when `TenantRegistry::is_reauth_required(did)` is set (or fail closed on database lookup error), short-circuiting incoming firehose interactions at Tier 3.5 with `InteractionOutcome::Paused` instead of running LLM classifier evaluations and failing with `invalid_grant` during `act_on_verdict`.
  - Updated `daemon::provision_pds_resources` to skip remote PDS moderation list verification and sovereign config synchronization for tenants marked with `reauth_required = 1` until they re-authenticate via OAuth.

## [0.2.18] - 2026-10-31

### Added

- **Temporary-to-Permanent Bounce Upgrade (`src/modlist/cache/bounces.rs`, `src/modlist/manager.rs`, `src/engine/modlist_ops.rs`, `src/bot/handler.rs`, `src/bot/dispatcher.rs`, `src/web/api/bounces.rs`, `assets/dashboard.html`)**:
  - Added `DeduplicationCache::make_bounce_permanent_for`, `ModListManager::upgrade_bounce_to_permanent`, and `SkybouncerEngine::upgrade_bounce_to_permanent` to clear `expires_at` (`NULL`) on temporary bounces so they are never auto-pardoned by background expiration maintenance.
  - Added DM bot command `perm <did|@handle>` (with aliases `permanent`, `upgrade`, `make permanent`, `perm block`) to upgrade a temporary block to permanent via ATProto Direct Messages.
  - Included `bounce_duration` in `BounceNotification` and updated `bot::format_bounce_alert` so proactive DM alerts for temporary blocks display the active duration and remind the user of `perm <target>` alongside the existing `pardon <target>` and `pardon and allow <target>` instructions.
  - Added `POST /api/bounces/upgrade` (`UpgradeBounceRequest` / `UpgradeBounceResponse`) and a one-click **Make Perm** button on temporary (`⏳ TTL`) bounce rows in the web dashboard.

## [0.2.17] - 2026-10-29

### Added

- **Persistent Jetstream Cursor Tracking & Replay (`src/engine/mod.rs`, `src/engine/processing.rs`, `src/stream.rs`, `src/daemon.rs`)**:
  - Added `last_cursor_us` to `EngineStats` and `EngineStatsSnapshot`, updated on every ingested `JetstreamCommit` (`commit.time_us`) and persisted to SQLite (`dashboard_stats`) during periodic maintenance and graceful shutdown.
  - Added `stream::resolve_resume_cursor` (rewinding 5 seconds for overlap safety and clamping to Jetstream's 72-hour replay retention window) and wired `daemon::run` to automatically resume from the persisted cursor (or `JETSTREAM_CURSOR` / `SKYBOUNCER_JETSTREAM_CURSOR` override) across container restarts and deployments.

## [0.2.16] - 2026-10-29

### Fixed

- **Jetstream WebSocket Idle Read Timeout (`src/stream.rs`, `src/daemon.rs`)**:
  - Added `DEFAULT_READ_TIMEOUT` (30 seconds) and `StreamConfig::with_read_timeout` (configurable via `JETSTREAM_READ_TIMEOUT_SECS` / `SKYBOUNCER_JETSTREAM_READ_TIMEOUT_SECS`) wrapping `read_half.next()` in `run_jetstream_streamer`.
  - Prevents silent half-open TCP stalls from hanging firehose ingestion indefinitely when an upstream Jetstream server stops sending frames without a TCP `FIN`/`RST` or WebSocket `Close` frame, automatically closing the stalled socket and reconnecting with a 5-second cursor rewind.
- **Evaluation Queue Hold & Retry During Classifier Outages (`src/engine/lifecycle.rs`, `src/engine/processing.rs`, `src/engine/mod.rs`, `src/error.rs`)**:
  - Added `SkybouncerError::is_transient_classifier_error`, `SkybouncerConfig::hold_queue_on_classifier_unavailable` (enabled by default in `SkybouncerConfig::from_env()`), `SkybouncerConfig::classifier_retry_backoff`, and `SkybouncerEngine::evaluate_candidate_queued`.
  - When the classifier backend (e.g. `nmo` Jev / Ollama) is unreachable or returning transient 5xx errors, the background evaluation worker now holds its concurrency permit and retries the in-flight candidate with exponential backoff (2s up to 15s) until the classifier recovers instead of draining and dropping queued candidates.
  - Updated `queue_worker` to increment `eval_queue_processed` after candidate evaluation completes so `skybouncer_eval_queue_depth` (`Queue Backlog`) accurately reflects both waiting and in-flight evaluations.

## [0.2.15] - 2026-10-28

### Added

- **Confidential OAuth Client (`private_key_jwt` / RFC 7523)**:
  - Upgraded `skyauth` to `0.3.9` and added `TenantRegistry::load_or_create_oauth_client_key` (`oauth_client_keys` SQLite table with AES-256-GCM at-rest encryption and `OAUTH_CLIENT_PRIVATE_KEY` / `SKYBOUNCER_OAUTH_CLIENT_PRIVATE_KEY` environment override).
  - Added `web::build_oauth_client_with_key` and updated `daemon::run` and `web::run_web_server` so `/oauth/client-metadata.json` advertises `"token_endpoint_auth_method": "private_key_jwt"`, `"token_endpoint_auth_signing_alg": "ES256"`, and the public `"jwks"` key set, lifting the 14-day public-client refresh token lifetime ceiling on Bluesky PDS authorization servers.
- **Proactive Background OAuth Session Keep-Alive**:
  - Added `SkybouncerEngine::refresh_expiring_tenant_sessions` and wired it into `SkybouncerEngine::run_maintenance` so active enrolled tenants' OAuth sessions are rotated ahead of expiry even during quiet periods without incoming firehose bounces.
- **One-Shot Proactive DM Re-Authentication Alerts**:
  - Added `ReauthNotification`, `SkybouncerEngine::subscribe_reauth_alerts`, `bot::format_reauth_alert`, and `bot::run_reauth_alert_dispatcher`.
  - Added `reauth_required` and `reauth_notified_at` tracking columns to `tenants` (`mark_reauth_required`, `mark_reauth_notified`, `is_reauth_required`, `is_reauth_notification_pending`, `list_pending_reauth_notifications`, `is_permanent_oauth_refresh_error`) so permanent refresh failures (`invalid_grant`, `unauthorized_client`, `invalid_client`, or missing refresh token) trigger a single deduplicated Bluesky DM with a direct `/?auth=login` reconnect link, automatically resetting once the user signs in again.

## [0.2.14] - 2026-10-27

### Added

- **Ollama Context Window Configuration (`num_ctx = 16384`)**:
  - `JevClassifier` now sets explicit runtime inference options (`OllamaChatOptions { num_ctx }`) on all Ollama `/api/chat` requests (including `gemma4:26b`), defaulting to `16_384` tokens (`DEFAULT_OLLAMA_NUM_CTX`).
  - Configurable via `OLLAMA_NUM_CTX` / `SKYBOUNCER_OLLAMA_NUM_CTX` / `JEV_NUM_CTX` / `FALLBACK_NUM_CTX` environment variables and `JevClassifier::with_num_ctx(num_ctx)` (clamped to a safe minimum of 1,024 tokens).
  - Documented `OLLAMA_NUM_CTX=16384` in `.env.example` and `deploy/systemd/skybouncer.env.example`.
- **Multi-Image Gallery Embed Support (`app.bsky.embed.gallery`)**:
  - Added `MAX_POST_IMAGES = 20` to `enricher`, raising image thumbnail inspection ceiling from 4 to 20 to support ATProto gallery embeds alongside legacy `app.bsky.embed.images`.
  - `TargetMatcher` now extracts image CIDs and alt texts from `app.bsky.embed.gallery` records (both direct gallery embeds and `app.bsky.embed.recordWithMedia` wrapping a gallery) up to the 20-image lexicon limit.

### Fixed

- **Incoming Follower Bypass Retention & Lazy Relationship Backfill** (`src/matcher/follow_graph.rs`, `src/daemon.rs`, `src/enricher.rs`, `src/engine/processing.rs`):
  - Fixed a bug in `FollowGraph::handle_commit` where incoming `CommitOperation::Delete` follow events for untracked `rkey`s invoked `remove_synthetic_follower_fallback(&commit.did)`, falsely evicting cold-start hydrated followers whenever they unfollowed any unrelated account on Bluesky.
  - Updated `daemon::hydrate_cold_start` to hydrate follows and followers for all active enrolled tenants in `tenant_registry` in addition to `config.protected_dids`.
  - Added `ContextEnricher::check_relationship` (`app.bsky.graph.getRelationships`) and lazy `FollowGraph` backfill in `evaluate_candidate` so older followers beyond AppView `getFollowers` cursor pagination depth are discovered, cached in `FollowGraph`, and bypassed before invoking the AI classifier.

## [0.2.13] - 2026-10-26

### Security

- **Transitive Cryptographic & Runtime Advisory Remediation** (`Cargo.toml`, `Cargo.lock`, `deny.toml`, `.github/workflows/ci.yml`):
  - Upgraded `skyauth` to `0.3.8`, `skybase` to `0.1.6`, `crypto-bigint` to `0.7.10` (`RUSTSEC-2026-0387`), and `ctutils` to `0.4.6` (`RUSTSEC-2026-0385`).
  - Banned vulnerable prior releases (`crypto-bigint < 0.7.6`, `ctutils < 0.4.4`, `tokio < 1.53.3`) in `deny.toml`.

## [0.2.12] - 2026-10-22

### Changed

- **Idempotent Container Startup in `scripts/deploy.sh`**: Removed `--force-recreate` from `docker compose up -d skybouncer` so boot-time and repeat deployments only recreate the container when the built image digest or Compose configuration changes.

## [0.2.11] - 2026-10-21

### Security

- **eMudhra Intermediate CA Compromise Mitigation** (`Cargo.toml`, `Cargo.lock`, `deny.toml`, `Dockerfile`, `tests/emudhra_tls_distrust_tests.rs`):
  - Upgraded `skyauth` to `0.3.7` and `skybase` to `0.1.5`, enforced `rustls-webpki >= 0.103.16` and `webpki-roots >= 1.0.10` in `[dependencies]`, and banned vulnerable versions (`rustls-webpki < 0.103.16`, `webpki-roots < 1.0.10`, `webpki-root-certs < 1.0.10`) in `deny.toml`.
  - Ensures all outbound HTTPS and WSS connections (Jetstream firehose ingestion, DID/handle resolution, OAuth 2.1 PDS discovery, DPoP moderation writes, and AppView lookups) reject the 8 compromised eMudhra intermediate CA SubjectPublicKeyInfos (`Error::CertDistrusted`) across both direct `emSign` and Sectigo `AAA Certificate Services` cross-signed chains.
  - Hardened the production `Dockerfile` with `--locked` builds and explicit `/etc/ca-certificates.conf` distrust rules for `mozilla/emSign_ECC_Root_CA_-_G3.crt` and `mozilla/Comodo_AAA_Services_root.crt`.

## [0.2.10] - 2026-10-18

### Fixed

- **OAuth Pre-Flight Discovery & DID Validation (`GET /api/auth/preview`, `web::create_web_router`)**:
  - `create_web_router` now attaches the provided `AtprotoOAuthClient` to `SkybouncerEngine` when `engine.oauth_client()` is unset, and `auth_preview` falls back to a default `skyauth::identity::IdentityResolver` when running without an `AtprotoOAuthClient` so custom-PDS provider host discovery works in all router configurations.
  - `auth_preview` now validates `did:` inputs via `resolve_did_to_handle` when OAuth endpoint discovery fails, returning `502 Bad Gateway` for unresolvable DIDs instead of accepting arbitrary `did:` prefixes.
  - Hardened the dashboard's `previewAndConfirmAccount` network error handler so raw handle entries surface a clear connection error rather than advancing to confirmation with an unverified default provider.

## [0.2.9] - 2026-10-18

### Added

- **Pre-Flight Identity & Provider Confirmation (`GET /api/auth/preview`)**: Resolves a user's handle or DID prior to OAuth redirect, returning their canonical DID, handle, display name, avatar, and hosting provider (`pds_host` / `auth_server_host`) for the *"Is this you?"* confirmation step.
- **Live Handle Typeahead (`GET /api/auth/typeahead`)**: Proxies `app.bsky.actor.searchActorsTypeahead` so the Sign-In modal provides real-time handle autocomplete with avatars and display names while preserving password-manager autofill attributes.
- **Bare Handle `.bsky.social` Completion (`util::normalize_handle_or_default`)**: Single-label handles entered without a domain (e.g. `alice` or `@alice`) automatically assume `.bsky.social` across `GET /oauth/login`, `GET /api/auth/preview`, and `SkybouncerEngine::resolve_handle`, with a live inline UI hint (`No domain included — .bsky.social is assumed`).
- **Upgraded Atmosphere OAuth Sign-In Modal**:
  - **Returning User Account Picker ("Welcome back")**: Remembers signed-in accounts locally in `localStorage` (`skybouncer_saved_accounts`) for 1-click sign-in, with an **Edit / `✕` ("Forget account on this device")** toggle and **"Use another account"**.
  - **Pre-Flight Confirmation ("Is this you?")**: Displays the user's resolved avatar, display name, `@handle`, DID, and hosting provider with **`Continue to <provider-host> →`**, a *"Stepping out to `<provider-host>`…"* handoff message, **`Switch account`**, and *"Skybouncer never sees your password"* reassurance.
  - **"How signing in works" (`ⓘ`) Explainer**: In-modal explainer with the `You —(🔑)→ Your Provider —(🎟️)→ Skybouncer` diagram and a clear breakdown of what Skybouncer **can** and **can't** do before redirect.

## [0.2.8] - 2026-10-16

### Added

- **CLI Authentication & Immunization (`--token`, `--allowlist`)**: `skybouncer status`, `skybouncer pardon`, and `skybouncer simulate` now support `--token <TOKEN>` (and `SKYBOUNCER_TOKEN` / `SKYBOUNCER_API_TOKEN` / `SKYBOUNCER_SESSION_TOKEN` / `PDS_ACCESS_TOKEN`), `skybouncer pardon --allowlist [--reason <TEXT>]`, and `skybouncer --version` (`-V`).
- **DM Follower Bypass Command (`trust followers <on|off>`)**: Added `trust followers <on|off>` (and `bypass followers <on|off>`) to the Bluesky DM bot and surfaced `Follower Bypass:` status in `rules` and `help`.

### Changed

- **State-Preserving Rubric Updates (`RuleRubric::parse_updating`)**: Updating prompt text via DM `set rules <prompt>` or `POST /api/rules` now preserves existing `sensitivity`, `bounce_duration`, and `bypass_incoming_followers` settings unless explicitly overridden by inline directives.
- **DM `test <text>` Threshold & Error Accuracy**: `test <text>` now evaluates confidence against the user's configured sensitivity threshold (`VIOLATION` vs `PERMITTED (BELOW THRESHOLD)`) and surfaces classifier errors clearly.
- **Sovereign Web Dashboard UX**: Increased `/api/simulate` request body limit to 8 MB for base64 image uploads, added sign-in prompts and loading states on `Evaluate`, `● Unsaved Changes` dirty-state tracking in the House Rules card, friendly preset names with overwrite confirmation, automatic Sign-In modal trigger on `/auth` (`/?auth=login`), Escape/backdrop modal dismissal, dark-mode `select`/`.badge-*` styles, click-to-expand `.expandable-text`, and an unauthenticated telemetry notice banner.
- **Strict CLI Flag Validation**: Unrecognized CLI flags or missing flag arguments now return `SkybouncerError::Config` instead of silently launching the live daemon.

## [0.2.7] - 2026-10-15

### Changed

- **Classifier Fallback Model**: Upgraded default System-2 multimodal fallback model from `gemma4:12b` to `gemma4:26b` across environment configurations (`.env.example`, `skybouncer.env.example`), dashboard simulation UI, benchmarks, and deployment documentation.
- **Dependencies**: Updated `rustls` to `0.23.46` to resolve security advisories RUSTSEC-2026-0347, RUSTSEC-2026-0348, and RUSTSEC-2026-0349.

## [0.2.6] - 2026-10-14

### Fixed

- **Container build / deployment**: The production `Dockerfile` no longer compiles the sibling `skybase` and `skyauth` crates from local `path = "../..."` checkouts. Those local checkouts drift behind the versions that `skybouncer` expects, which caused release builds from `main` to fail (stale `skybase` used `rusqlite 0.32` / `libsqlite3-sys 0.30`, conflicting with `skybouncer`'s `rusqlite 0.39` / `libsqlite3-sys 0.37` over the `links = "sqlite3"` native library). `skybase` and `skyauth` are now consumed from crates.io, matching `for-your-consideration`, and the Compose build context is narrowed to the `skybouncer` repository.

## [0.2.5] - 2026-10-14

### Changed

- **Dependencies & CI**: Upgraded `axum` (`0.8`), `thiserror` (`2.0`), `tokio-tungstenite` (`0.30`), `rusqlite` (`0.39`), and `base64` (`0.23`) for compatibility with `skyauth 0.3.5` and `skybase 0.1.3`, updated MSRV to Rust `1.89`, and aligned sibling repository checkouts in CI to `main`.

## [0.2.4] - 2026-10-14

### Changed

- **CI Dependencies**: Bumped `actions/checkout` from v4 to v7 in GitHub Actions workflows.

## [0.2.3] - 2026-10-10

### Added

- **Tenant-Scoped Bounces & Fleet Scope Selector**:
  - The dashboard "Recently Bounced Violators" feed now defaults to scoping directly to the authenticated user's account (`user_did=<did>`), preventing other tenants' moderation events from cluttering the user's view.
  - Authenticated administrators now have a **Scope selector** (`bounces-scope-select`) to seamlessly toggle between "My Bounces Only", "Fleet-Wide (All Tenants)", and individual enrolled tenants.
  - Added dynamic "Target Account" column in the dashboard table when viewing fleet-wide bounces to clearly show which tenant's post received the offending interaction.
  - Enriched `BouncedUserWithHandle` and `GET /api/bounces` with `protected_handle` to display human-readable handles for protected targets.
  - Updated dashboard "Pardon" and "Pardon & Allow" actions to pass `protected_did`, ensuring pardons execute against the correct tenant's moderation list.

## [0.2.2] - 2026-10-10

### Changed

- **Dependabot Configuration**: Added `.github/dependabot.yml` configured with weekly checks and grouped PR updates for `cargo`, `github-actions`, and `docker` dependencies.

## [0.2.1] - 2026-10-08

### Changed

- **Human-friendly, hotlinkable DM output**: bot DMs now reference accounts by
  resolved `@handle` (falling back to DID only when unresolvable) and embed literal
  `https://bsky.app/profile/...` / `.../post/...` URLs so Chat auto-links them.
  - New shared `bot::render` helpers (`bsky_profile_url`, `bsky_post_url`,
    `bsky_post_url_from_at_uri`, `account_label`, `account_label_with_url`,
    `command_target`).
  - `BounceNotification` gains an optional `violator_handle`, populated from the
    enriched author context (or the handle cache) at bounce time.
  - Proactive bounce alerts, `recent`, `allowlist`, `pardon`, `pardon and allow`,
    `allow`, and `unallow` replies now render handles, profile links, clickable post
    links, and handle-based follow-up commands.

## [0.2.0] - 2026-10-07

### Added

- **Dynamic Tier-1 multimodal primary routing**: image-bearing interactions can
  be routed to a multimodal System-1 model at Tier-1 instead of escalating every
  image to the heavyweight System-2 fallback. Enabled via `MULTIMODAL_PRIMARY_MODEL`
  (plus `MULTIMODAL_API_BASE_URL` / `MULTIMODAL_API_KEY` / `MULTIMODAL_TIMEOUT_MS` /
  `MULTIMODAL_MAX_RETRIES`). When enabled, image-triggered Tier-2 escalation is
  disabled automatically; uncertainty-band escalation still applies. The default
  (flag unset) path is unchanged.
  - New `DynamicPrimaryClassifier` + `DynamicModelPolicy` selecting a text-only or
    multimodal Tier-1 model per interaction, with bypass-on-decisive-text-violation
    and routing telemetry.
  - New `JevConfig::supports_images` (`JEV_SUPPORTS_IMAGES`): System-One decision
    models reject image payloads with HTTP 400, so images are only attached when
    the model supports them.
- **Optional conversation-thread context**: `EnrichedContext::thread_ancestors`
  and `AppViewContextEnricher::fetch_thread_ancestors` (`app.bsky.feed.getPostThread`,
  oldest-first, capped), opt-in via `with_thread_context(true)`.
- Benchmark example (`examples/thread_context_benchmark.rs`) and fixtures replaying
  curated/proven vectors, captured live logs, and a synthetic hard corpus.

### Changed

- `TieredClassifier` and `DynamicPrimaryClassifier` now store
  `Arc<dyn Classifier + Send + Sync>` so they can wrap `dyn Classifier` trait objects.

## [0.1.22] - 2026-10-07

### Changed

- **Publishable sibling dependencies**: pinned `skybase` to `0.1.1` and
  `skyauth` to `0.3.3`, which now ship the modules `skybouncer` consumes
  (`skybase::appview`, `skybase::chat`, `skybase::lexicon`, `skyauth::sealed`).
  This makes `cargo publish` resolve the sibling crates from crates.io instead
  of failing on path-only dependencies. No source changes.

## [0.1.21] - 2026-10-06

### Changed

- **DRY Cleanup, Dependency Hygiene & Structural Refactor** (see `docs/CLEANUP.md`):
  - Dependency hygiene: removed unused `http` and direct `ring` dependencies, moved `tower` to dev-dependencies, and feature-gated `web`/`stream`/`bot`/`telemetry` with a lean-core CI gate.
  - Dead code / lints: removed the never-read `stateless_mode` config; replaced `too_many_arguments` allows with a unified `BounceRequest` + `ModListManager::bounce` (23 call sites); renamed `matcher/matcher.rs` to `matcher/target.rs`.
  - Internal dedup: new `env`, `time`, and `util` helper modules; shared row mappers, parsers, builders, and test fixtures.
  - Structural splits: `engine`, `modlist::cache`, `web::api`, and `tenant::registry` split into focused submodules; dashboard HTML externalized to `assets/dashboard.html`.
  - Pipeline dedup: extracted `dispatch_commit`, `fast_path`, and `SkybouncerEngine::run_simulation`; deduped the `FollowGraph` reverse index.

### Removed

- **Sibling-Crate Deduplication** (requires `skybase` and `skyauth` releases carrying the pulled-up modules):
  - Removed the in-crate ATProto Chat client and chat/lexicon models (~1,800 LOC); now re-exported from `skybase::chat` / `skybase::lexicon`.
  - `SessionCipher` now delegates to `skyauth::sealed::SealedBox`; SSRF image fetch uses `skyauth::ssrf::SsrfFilter`; the Jetstream streamer uses `skybase::ingest` primitives.

## [0.1.20] - 2026-10-05

### Changed

- **Canonical Property-Test Suite (`tests/property_tests.rs`)**:
  - Consolidated library-facing property tests into the blueprint-mandated `tests/property_tests.rs`, matching the `rust-best-practices` convention that `proptest` is the preferred structured/typed testing tool (over `cargo-fuzz`).
  - Moved the heuristic classifier `proptest!` blocks out of `classifier_tests.rs` into the canonical suite; speculative test-local property tests (type-redesign `Confidence`/`AtDid`) intentionally remain colocated with those types in `type_redesign_verification_tests.rs`.

### Added

- **Duration, Scheduling & Panic-Freedom Property Coverage**:
  - Added `proptest` algebraic laws for `BounceDuration`: `expires_at_us` is `None` iff `Permanent`, is monotonic non-decreasing in `now`, saturates to `u64::MAX` on overflow (clock-warp / overflow safety), and preserves its effective timeout duration across `to_db_string`/`FromStr` round-trips.
  - Added sliding-window scheduling-bound laws for `EvaluationRateLimiter`: a fresh limiter permits exactly `max_evaluations`, `remaining()` decreases monotonically, and `reset` restores the full allowance.
  - Added `Sensitivity` threshold ordering/bounds laws and panic-freedom/well-formedness properties for `extract_did_from_at_uri`/`extract_did_for_collection` and `format_system_time_iso8601`.

## [0.1.19] - 2026-10-05

### Added

- **Dashboard Control for Incoming-Follower Trust**:
  - Added a "Trust accounts that follow me" checkbox to the dashboard moderation rules card so each user can toggle the incoming-follower bypass directly, instead of relying on the undocumented `bypass_followers:` rubric directive.
  - `RulesResponse` now includes `bypass_incoming_followers`, and `UpdateRulesRequest` accepts `bypass_incoming_followers: Option<bool>`, so `GET /api/rules` echoes the current setting and `POST /api/rules` updates it.
  - `update_rules` applies the toggle to the in-memory gate immediately via `SkybouncerEngine::set_bypass_incoming_followers`, so the change takes effect without a restart, and it persists through the tenant registry and the user's sovereign PDS config as before.
  - The outgoing "following" bypass remains unconditionally enabled by design; only the incoming direction is user-configurable.
  - Added API round-trip coverage and expanded the dashboard DOM-contract test to assert the toggle is present and wired into the rules load/save JavaScript.

## [0.1.18] - 2026-10-05

### Added

- **Incoming Follower Trust (Reverse-Direction Bypass)**:
  - Accounts that follow a protected user now bypass moderation evaluation at the `$0` cost-control gate, mirroring the existing treatment of accounts the protected user follows. Previously only the outgoing direction (`protected -> author`) was honored, so an inbound-only follower could be classified and auto-blocked.
  - `FollowGraph` now tracks the reverse direction with `is_followed_by(protected_did, candidate_did)` plus an `incoming_rkey_index` (`follower_did -> rkey -> protected_did`) so real-time unfollow `Delete` commits — which omit the record subject — resolve without any network calls.
  - `FollowGraph::handle_commit` now records inbound follows from untracked authors when the record `subject` is a protected DID, emitting new `FollowSyncEvent::FollowerAdded` / `FollowerRemoved` variants. A cheap read-lock probe (`tracks_incoming_follower`) avoids write-lock contention for unfollows from accounts that never followed a protected user.
  - New `BypassReason::FollowerAuthor` (`"follower_author"`) evaluated as gate stage 2.5, wired through both `process_interaction` and `process_interaction_queued` with a new `gate_bypassed_follower` telemetry counter.
  - Added `AppViewContextEnricher::fetch_followers` (XRPC `app.bsky.graph.getFollowers`) and cold-start hydration of incoming followers via deterministic synthetic `hydrate_in_{n}` rkeys, including synthetic-rkey reconciliation on delete.
- **Per-User Opt-Out for Incoming-Follower Trust**:
  - Added `RuleRubric::bypass_incoming_followers` (default `true`), configurable via the `bypass_followers: false` rubric directive or `with_bypass_incoming_followers`.
  - Persisted through `SovereignConfigRecord` and moderation-list metadata (legacy payloads default to enabled) and a new `bypass_followers` tenants column with an idempotent `ALTER TABLE` migration.
  - `NonFollowedGate` mirrors the flag in an in-memory cache (`set_bypass_incoming_followers` / `bypass_incoming_followers`), seeded at startup and refreshed on sovereign-config hot-reload, preserving the `<1µs`, zero-query gate guarantee.
- **Telemetry & Dashboards**: `gate_bypassed_follower` surfaced in `EngineStats`/`EngineStatsSnapshot`, the Prometheus `skybouncer_gate_bypassed_total{reason="follower"}` metric, the CLI status/summary output, and the web dashboard and bot status KPIs.

## [0.1.17] - 2026-10-05

### Added & Enhanced

- **Persistent Dashboard Telemetry Counters**:
  - Dashboard KPI counters for both users and administrators now survive process restarts and deployments instead of resetting to zero.
  - Added a single-row `dashboard_stats` SQLite table and `DeduplicationCache::{save_dashboard_stats, load_dashboard_stats}` to persist the serialized `EngineStatsSnapshot` via an atomic `ON CONFLICT` upsert; the loader tolerates corrupt/legacy payloads by falling back to defaults.
  - Added `EngineStats::from_snapshot` to rehydrate live atomic counters from a persisted snapshot, and `SkybouncerEngine::persist_stats` to snapshot the current counters to durable storage.
  - Cumulative counters are now restored at engine construction (`SkybouncerEngine::new` and `SkybouncerEngineBuilder::build`) and flushed on every maintenance tick (drift-free 60s loop) and during graceful shutdown in `main`.

### Added

- **Consistent SQLite Backup Tooling**:
  - Added `scripts/backup.sh`, which takes a consistent online backup of the Skybouncer database from its Docker named volume using SQLite's `.backup` API, verifies it with `PRAGMA integrity_check`, gzip-compresses it, and prunes old snapshots (default: retain 5).
  - Runs in an ephemeral container from the already-present `skybouncer` image, so it is safe while the service is live and the app container need not be running; supports `SKYBOUNCER_BACKUP_DIR`, `SKYBOUNCER_BACKUP_RETAIN`, `SKYBOUNCER_VOLUME`, `SKYBOUNCER_DB_NAME`, and `SKYBOUNCER_IMAGE` overrides.
  - Documented Docker and systemd backup/restore procedures in `docs/DEPLOYMENT.md`.

## [0.1.16] - 2026-10-05

### Fixed & Remediated

- **Per-Tenant Custom Rubric Semantic Inference**:
  - Threaded tenant-specific `RuleRubric` through `Interaction` (`pub rubric: Option<RuleRubric>`, builder `with_rubric`) and new `Classifier` trait methods (`classify_with_rubric`, `classify_detailed_with_rubric`, `classify_detailed_with_stats_and_rubric`).
  - Updated `JevClassifier`, `TieredClassifier`, `HeuristicClassifier`, and `MockClassifier` to evaluate against tenant-specific prompt rules and sensitivity thresholds during inference.
  - `SkybouncerEngine::evaluate_candidate` and `process_interaction` now resolve the target tenant's specific rubric via `rubric_for(&target_did)` and pass it into the classification pipeline, eliminating the defect where tenant-custom rules were ignored in favor of the global fleet rubric.
- **Sovereign Config Deletion Rubric Reset**:
  - `SkybouncerEngine::handle_sovereign_config_commit` now handles `CommitOperation::Delete` on `social.skybouncer.config` records, resetting the tenant's rubric back to the default in both `TenantRegistry` (SQLite) and engine in-memory state and emitting `ProcessCommitResult::SovereignConfigSynced(SovereignConfigSyncEvent::Deleted { did })`.
- **Follow Graph Cold Hydration TID Reconciliation**:
  - Resolved synthetic vs real TID rkey mismatch when processing unfollow events following cold-start hydration via `hydrate_follows`.
  - Implemented multi-tiered synthetic fallback reconciliation in `FollowGraph::handle_commit`: exact rkey match, then payload `subject` DID, then a DID-valued rkey, then synthetic-key reconciliation.
  - Synthetic-fallback selection is now deterministic (ascending `hydrate_<n>` index, then `seed_*` lexicographic) rather than relying on `HashMap` iteration order, and never selects a real rkey, keeping behavior reproducible across restarts.
- **Handle Resolution Caching TTL & Monotonic Invalidation**:
  - Added `TenantRegistry::get_by_handle_with_ttl(&self, handle, max_age)` and `invalidate_handle(&self, handle)` with microsecond-precision SQLite timestamp validation against `DEFAULT_HANDLE_TTL` (1 hour).
  - Added a dedicated `tenants.handle_updated_at` column (with idempotent migration + backfill) so handle freshness is advanced only when the handle mapping itself changes — never by unrelated writes such as OAuth session token refreshes.
  - Added a monotonic in-memory `handle_cache` to `SkybouncerEngine` using `Instant::now()` and clock-warp safe `saturating_duration_since`, without holding locks across `.await` points.
  - Unified the resolution hierarchy with the persisted SQLite `did_handles` cache from v0.1.15: in-memory cache -> registry TTL -> **TTL-bounded** persisted cache (`DeduplicationCache::get_did_for_handle_with_ttl`) -> AppView enricher. The persisted cache is now TTL-bounded so a stale mapping cannot shadow a rotated handle.
  - Added `engine.invalidate_handle()` and `engine.clear_handle_cache()` plus `DeduplicationCache::remove_handle_for_handle` to evict rotated handles across all tiers.
- **Expired Session Refresh Failure Handling & Client Eviction**:
  - Hardened `TenantRegistry::get_pds_client` against OAuth token refresh failures: if session refresh fails, the refresh token is missing, or no OAuth client is available for an expired session, it returns a typed `Err(SkybouncerError::Auth(...))` rather than caching and returning a dead client wrapping an expired token.
  - Synchronously evicts dead or unrefreshable clients from the in-memory `pds_clients` cache upon failure, preventing cache pollution and repeated 401 responses.

## [0.1.15] - 2026-10-04

### Added & Enhanced

- **DID-to-Handle Resolution Cache & API**:
  - Added `did_handles` SQLite table with an `updated_at` index to persist resolved DID ↔ handle mappings across restarts, powering instant, network-free lookups.
  - Added `DeduplicationCache::{set_handle_for_did, get_handle_for_did, get_did_for_handle}` with input normalization (whitespace and leading `@` trimming) and case-insensitive handle matching.
  - Extended `SkybouncerEngine::resolve_handle` and `resolve_did_to_handle` to consult the local DID/handle cache before falling back to the context enricher, and to persist successfully resolved mappings.
  - Added `GET /api/resolve` endpoint (`ResolveQuery`/`ResolveResponse`) resolving a DID to a handle or a handle to a DID via `did`, `handle`, or generic `actor` query parameters. The endpoint requires authentication since cache misses trigger outbound AppView/PLC lookups.
  - Added `DeduplicationCache::prune_did_handles` for age- and capacity-bounded eviction of stale mappings, wired into the periodic maintenance loop (`DEFAULT_DID_HANDLE_CACHE_TTL` of 30 days, `DEFAULT_DID_HANDLE_CACHE_MAX_ENTRIES` of 50,000).
- **Handle Enrichment Across Dashboard & API**:
  - `GET /api/bounces` now returns `BouncedUserWithHandle` entries enriched with resolved ATProto handles while remaining forward/backward compatible with plain `BouncedUser` deserialization.
  - `GET /api/allowlist`, `POST /api/allowlist`, and `GET /api/admin/tenants` responses now include resolved handles (via LEFT JOIN on `did_handles` and the local cache), and `AddAllowlistResponse` reports the resolved handle.
  - List endpoints now resolve handles from local caches only (`SkybouncerEngine::cached_handle_for_did`), eliminating an N+1 fan-out of serial outbound lookups; unresolved entries are progressively backfilled client-side.
  - `AllowlistEntry` gained an optional `handle` field with `skip_serializing_if` semantics.
- **Dashboard Account Display**:
  - Replaced raw DID columns in the bounces, allowlist, admin fleet, and evaluation audit tables with a shared `formatAccountCell` renderer that shows `@handle` with DID subtext and a Bluesky profile link.
  - Added progressive client-side handle resolution (`resolveDidToHandle`, `enhanceUnresolvedAccountCells`) that backfills unresolved accounts and caches results in `didHandleCache`.
  - Pardon, remove, allowlist, and tenant-toggle confirmation/toast messages now prefer the resolved `@handle` label over the raw DID.
- **Tests**:
  - Added `test_did_handle_cache_roundtrip_and_normalization` and `test_allowlist_handle_enrichment_via_join` cache unit tests.
  - Added `test_api_resolve_identity_endpoint` and `test_api_bounces_and_allowlist_handle_enrichment` web integration tests, plus updated dashboard DOM contract assertions.

## [0.1.14] - 2026-10-04

### Fixed & Enhanced

- **Dashboard Date/Timestamp Formatting Normalization**:
  - Implemented `parseTimestampToMs` in web dashboard JavaScript to automatically normalize timestamps across microsecond epoch timestamps (from SQLite cache, tenant registry, and evaluations), millisecond timestamps, second timestamps, and ISO 8601 strings.
  - Fixed date formatting calculation bug where microsecond timestamps passed directly to JavaScript `Date` evaluated into year ~58,729, resulting in erratic calendar days in the distant past or future.
  - Added `formatFullDate` providing full localized timestamp tooltips on hover across allowlist records, fleet admin tenants, audit evaluation logs, and bounced violator TTL/expiration badges.
- **Moderation Allowlist Subject Display**:
  - Resolved blank account entries in the Moderation Allowlist UI table by reading `subject_did` (with fallback to `allowed_did`), rendering valid Bluesky profile links and monospace DID code blocks.
  - Attached correct subject DIDs to `data-did` on allowlist "Remove" action buttons, restoring allowlist removal functionality from the dashboard.
  - Added `#[serde(alias = "allowed_did")]` to `AllowlistEntry` in Rust backend for backwards and cross-client compatibility.
- **Contract Tests**:
  - Added `test_allowlist_entry_alias_deserialization` and `test_ui_dom_allowlist_and_timestamp_contract_validation` to `tests/web_tests.rs`.

## [0.1.13] - 2026-10-04

### Added & Fixed

- **Dedicated Line Formatting for DM Onboarding Links**:
  - Isolated authorization URL onto its own clean line in `cmd_onboarding` without leading emoji or adjacent characters, preventing client-side autolink parsing glitches.
- **ATProto Rich Text Link Facets (`app.bsky.richtext.facet#link`)**:
  - Added `Facet`, `FacetIndex`, `FacetFeature`, and `LinkFacetFeature` structures conforming to the ATProto `app.bsky.richtext.facet` schema.
  - Implemented `extract_link_facets` to detect HTTP/HTTPS URLs with exact UTF-8 byte boundary calculations (`byteStart`, `byteEnd`), correctly trimming trailing terminal punctuation, unbalanced brackets, and CJK fullwidth characters.
  - Integrated automatic link facet generation into `ChatClient::send_message` so Bluesky mobile and web clients render links as native clickable hyperlinks.
- **Integration Tests**:
  - Added WireMock integration tests in `tests/bot_tests.rs` verifying wire-level facet payload transmission and multi-byte offset calculations.

## [0.1.12] - 2026-10-04

### Fixed & Enhanced

- **Flexible Bounce Duration Deserialization & Normalization**:
  - Implemented visitor-based deserializer for `BounceDuration` accepting string formats (`"24h"`, `"7d"`, `"30d"`, `"cooldown24h"`, `"timeout7d"`, `"timeout30d"`, `"permanent"`), numeric seconds (`86400`, `604800`, `2592000`, `0`), and `{ "custom": seconds }` objects.
  - Resolved UI form submission deserialization error when selecting non-permanent cooldown options in the web dashboard.
  - Normalized duration selection values in the frontend dashboard to ensure seamless round-trip synchronization between buttons, state, and API payload.
- **Tenant Registry & Sovereign Repository Bounce Duration Persistence**:
  - Added `bounce_duration` column to `tenants` SQLite schema with automatic idempotent migration.
  - Enrolled tenants now persist custom bounce durations across server restarts, registry reloads, and web session reconnects.
  - Added `bounce_duration` to `SovereignConfigRecord` and moderation list metadata tags (`[skybouncer:...]`) in sovereign PDS repositories.
- **Bot Handler Duration Commands**:
  - Added `duration <permanent|24h|7d|30d>` and `set duration <val>` bot command for adjusting tenant timeout lifecycles via ATProto DMs.
  - Updated `rules` and `set rules` responses to display active bounce duration.

## [0.1.11] - 2026-10-04

### Added & Enhanced

- **Temporary "Time-Out" / Cooldown Bounces (TTL Bouncing with Background PDS Pruning, PRD §7.1 Item 2)**:
  - Added `BounceDuration` enum (`Permanent`, `Cooldown24h`, `Timeout7d`, `Timeout30d`, `Custom(u64)`) to `RuleRubric` with directive parsing (`duration: 24h`, `timeout: 7d`).
  - Added `expires_at` column and partial index `idx_bounced_users_expires` to SQLite cache `bounced_users` with seamless migration support across legacy schema versions.
  - Added `expires_at` calculation in `ModListManager::bounce_user_with_text` and `SkybouncerEngine::process_commit`.
  - Implemented `SkybouncerEngine::prune_expired_bounces()` in periodic maintenance loop to automatically unbounce and delete expired listitem records from sovereign PDS repositories and purge SQLite cache entries.
  - Added `Violation Duration` segmented control to web dashboard House Rules card and `⏳ TTL` expiration indicators to Recently Bounced table.
- **Prometheus `/metrics` Observability Endpoint (PRD §7.3 Item 6)**:
  - Mounted `GET /metrics` and `GET /api/metrics` serving standard Prometheus 0.0.4 text exposition format (`Content-Type: text/plain; version=0.0.4; charset=utf-8`).
  - Exports telemetry counters: `skybouncer_commits_received_total`, `skybouncer_follow_sync_events_total`, `skybouncer_interactions_matched_total`, `skybouncer_gate_bypassed_total{reason=...}`, `skybouncer_candidates_evaluated_total`, `skybouncer_dedup_cache_hits_total`, `skybouncer_eval_cache_hits_total`, `skybouncer_heuristic_violations_total`, `skybouncer_model_evaluations_total`, `skybouncer_bounces_total`, `skybouncer_permitted_total`, `skybouncer_eval_queue_overflows_total`, and gauges for evaluation queue depth, protected users, enrolled tenants, and build info.
- **Tenant-Scoped Evaluation Audit Log (PRD §7.1 Item 3)**:
  - Added `GET /api/evaluations` with strict tenant isolation: non-admin tenants view evaluations on interactions targeting their own posts, while administrators retain fleet-wide visibility.
  - Enabled dynamic `#admin-eval-card` for all authenticated tenants to inspect evaluation decisions and confidence scores in real time.
- **Dashboard Rubric Presets & Bounced Search Filtering (PRD §7.3 Item 5)**:
  - Added one-click rubric preset buttons (*Balanced Defense*, *Zero Crypto*, *Anti-Hostility*, and *Anti-Ragebait*).
  - Added real-time client-side search filtering input on the Recently Bounced table.
  - Added "Pardon & Allow" one-click button on bounce entries.
  - Added dedicated Allowlist Management card for viewing, searching, adding, and removing allowlisted users.
- **Persistent Moderation Allowlist & Pardon Immunization (PRD §7.1 Item 1)**:
  - Added dedicated SQLite persistence (`allowlist` table) and in-memory multi-tenant lookup in `NonFollowedGate` with `<1µs` SLA (~218ns average).
  - Added `BypassReason::AllowlistedAuthor` bypassing non-followed interactions without classifier inference or PDS writes.
  - Implemented `SkybouncerEngine::pardon_and_allowlist` to permanently immunize pardoned authors from future re-bouncing ("pardon loop").
  - Added ATProto DM bot commands: `allow <did|@handle>`, `unallow <did|@handle>`, `allowlist`, and `pardon and allow <did|@handle>`.
  - Added Web REST API endpoints: `GET /api/allowlist`, `POST /api/allowlist`, `DELETE /api/allowlist/:did`, and `allowlist: bool` parameter on `POST /api/bounces/pardon`.
- **Confidence Floating-Point Precision (`f64`)**:
  - Upgraded `primary_confidence`, `fallback_confidence`, and `final_confidence` from `f32` to native `f64` across `EvaluationLogEntry`, `NewEvaluationLog`, SQLite storage, and web telemetry.
- **Symmetrical Interaction Outcome Tracking**:
  - Refined `InteractionOutcome::AlreadyBounced` to carry both `author_did` and `target_did` symmetrically, ensuring `target_did()` returns `Some` on all interaction variants.

## [0.1.10] - 2026-10-04

### Added & Fixed

- **Auto-Accept Conversation Requests (`chat.bsky.convo.listConvoRequests` & `acceptConvo`)**:
  - Implemented `list_convo_requests()` and `accept_convo()` on `ChatClient`.
  - Added strongly-typed `ListConvoRequestsResponse`, `AcceptConvoRequest`, and `AcceptConvoResponse` structs, and added `status: Option<String>` to `ConvoView`.
  - Enhanced `run_bot_poller` to poll conversation requests on each tick, automatically accept pending DM requests from non-followed accounts, and immediately evaluate and reply to incoming commands.
- **Automated ATProto Session Refresh & Recovery**:
  - Solved the 2-hour ATProto session expiration failure loop where `listConvos` errored with HTTP 400 `{"error":"ExpiredToken"}`.
  - Implemented single-flight transparent session refresh (`refreshSession` via `refreshJwt`) with fallback to App Password re-login (`createSession`).
  - Concurrent requests arriving during token expiration deduplicate onto a single refresh operation without burning tokens or causing races.
- **Test Suite**:
  - Added unit and integration tests verifying `listConvoRequests`, `acceptConvo`, automatic token refresh on `ExpiredToken`, App Password re-login fallback, and poller auto-acceptance.

## [0.1.9] - 2026-10-04

### Security & Correctness Hardening (AI Review Remediation)

- **DM Bot Authorization Gate (C1)**:
  - Enforced sender authorization across all DM commands via `is_authorized_sender`.
  - Restricted fleet-wide commands (`cmd_pause`, `cmd_resume`, global rubric/sensitivity adjustments) to fleet administrator or single-tenant deployments.
  - Eliminated arbitrary protected DID fallback in `cmd_pardon`, ensuring pardons can only operate on the sender's own moderation list.
  - Handled sovereign config commit sync errors with explicit warnings.
- **Session Encryption Key & AAD Binding (C2 & AI 2 #4)**:
  - Added explicit warning log when fallback deterministic key is used for session encryption.
  - Bound tenant DID as Additional Authenticated Data (`encrypt_with_aad` / `decrypt_or_passthrough_with_aad`), cryptographically preventing token swapping between tenants.
  - Stored SHA-256 hashes of web session tokens at rest (`hash_session_token`).
- **Simulate Endpoint Authentication & DNS-Pinning (H1, M9)**:
  - Added session authentication check to `/api/simulate`, preventing wallet-drain DoS and audit log pollution by anonymous callers.
  - Hardened image fetch against DNS rebinding TOCTOU by pinning resolved IP directly in `reqwest::ClientBuilder::resolve()` and capping payloads to 2MB.
- **Firehose Cursor Tracking & Jittered Backoff (H2, L5)**:
  - Stream consumer continuously records cursor timestamps from observed firehose events.
  - On reconnection, rewinds cursor by 5 seconds (5,000,000 µs) to prevent dropped moderation events during network blips.
  - Added randomized jittered exponential backoff that only resets after receiving at least 5 successful frames.
- **Strict Classifier Confidence Handling (H3)**:
  - Removed fabricated 0.95 confidence default on missing model scores, returning explicit errors instead to prevent erroneous moderation actions.
  - Capped interaction prompt text to 4000 characters and isolated candidate content within `<candidate_content>` tags.
- **PDS Client Resolution & Single-Flight Token Refresh (H4, H5)**:
  - Replaced open fallback with `resolve_pds_client_for`, returning `Err` if a tenant's credentials cannot be resolved and preventing unintended writes using administrator credentials.
  - Introduced per-DID striped async mutexes (`refresh_locks`) to serialize concurrent OAuth token refreshes and eliminate token revocation races.
- **Multi-Tenant Modlist & Dedup Isolation (M1, M2, M3, M4 / AI 2 #5)**:
  - Migrated `bounced_users` table to composite primary key `(protected_did, subject_did)` with schema migration, ensuring violator bans for tenant A do not suppress bans for tenant B.
  - Added secondary index `idx_bounced_users_subject` maintaining sub-microsecond lookup latency SLA.
  - Added compensating PDS record deletion if cache persistence fails after remote PDS write.
  - Added separate `listblock_provision_locks` to prevent deadlock and TOCTOU races in listblock provisioning.
  - Propagated remote discovery errors with `?` in `ensure_mod_list` to prevent duplicate modlist creation during transient PDS 500s.
- **Engine Invariants & Performance (M5, M6, M7, M8, M10, M12, M14, M15, L2, L3, L4, L8, L11)**:
  - `is_tenant_paused` fails closed on database errors.
  - Moved rate-limit token consumption from enqueue to dequeue in `evaluate_candidate`.
  - Scoped tenant toggles to prevent affecting global pause state in multi-tenant mode.
  - Redacted protected DIDs and telemetry in `/api/status` for unauthenticated callers.
  - Logged warnings on failed audit trail writes rather than dropping silently.
  - Poller processes all unread DMs in chronological order with bounded deduplication cache (2048 entries).
  - Replaced per-commit `HashSet` clones in firehose hot path with zero-allocation reference checks.
  - Enforced minimum queue capacity of 100 in `SkybouncerConfig`.
  - Added `; Secure` flag to logout session clearing cookie.
  - Hardened HTML hrefs in UI with HTML entity escaping and DID/rkey regex sanitization.
  - Strengthened Content-Security-Policy with `object-src 'none'; base-uri 'self';`.
  - Paginated follow graph hydration up to 10,000 accounts and added XRPC `listRecords` hydration for real follow rkeys.
  - Removed `std::process::abort()` from fallback registry.

## [0.1.8] - 2026-10-04

### Fixed

- **Bluesky Post & Profile URL Formatting**:
  - Fixed an issue where clicking offending post links (`at://did:plc:.../app.bsky.feed.post/...`) navigated to `https://bsky.app/profile/did%3Aplc%3A.../post/...` which caused Bluesky's web router to fail with `Error: Invalid DID or handle`.
  - Introduced `bskyProfileUrl` and `bskyPostUrl` helpers in the web dashboard preserving literal colons in DID path segments (`https://bsky.app/profile/did:plc:.../post/...`) and trimming leading `@` symbols on handles.
  - Defined missing `formatDid` helper for evaluation logs to prevent `ReferenceError` on raw DID rendering.

## [0.1.7] - 2026-10-04

### Security & Hardening

- **AES-256-GCM Session Encryption at Rest (Issue #9)**:
  - Implemented `SessionCipher` in `src/crypto.rs` using `ring::aead::AES_256_GCM` with random 96-bit nonces generated via CSPRNG (`ring::rand::SystemRandom`) and 128-bit authentication tags.
  - Transparent envelope format `enc:v1:<base64(12B nonce + ciphertext + 16B tag)>` stored in the `session_json` column of the `tenants` SQLite table.
  - Zero-downtime, transparent backward compatibility: legacy unencrypted JSON rows are automatically recognized and parsed seamlessly without data loss or schema migration downtime, and re-encrypted on next write/refresh.
  - Key management via `SKYBOUNCER_SESSION_ENCRYPTION_KEY` supporting 64-character hex keys, high-entropy secret passphrases, or machine-stable fallback derivation based on `HOSTNAME`/`SERVICE_DID`.
  - Integrated into `TenantRegistry` methods `register_or_update`, `update_session`, and `get`.
  - Added unit and integration tests verifying ciphertext structure, absence of plaintext tokens in raw SQLite data, legacy migration, and tampering/key mismatch rejection.

## [0.1.6] - 2026-10-04

### Security & Hardening

- **Cryptographic Web Session Authentication**:
  - Replaced client-asserted `x-skybouncer-did` header and plain DID cookie with 256-bit CSPRNG session tokens stored in SQLite table `web_sessions` with automatic expiration and pruning.
  - Endpoints (`/api/me`, `/api/rules`, `/api/bounces`, `/api/pardon`, `/api/tenant/toggle`, `/api/admin/*`) strictly validate caller session tokens from `skybouncer_session` cookie or `Authorization: Bearer` header.
- **Admin Privilege Hardening**:
  - Eliminated insecure fallback where any protected DID was granted admin privileges when `ADMIN_DID` was unset.
  - Strictly check configured `admin_did` with zero per-invocation `std::env::var` re-reading.
- **Strict Multi-Tenant Scoping & Privacy Isolation**:
  - Scoped `GET /api/bounces` and DM bot `cmd_recent` to caller's own replies only, preventing cross-tenant privacy leaks.
  - Blocked cross-tenant pardon operations (`POST /api/pardon`) unless caller is fleet administrator.
  - Guarded tenant rubric updates (`POST /api/rules`) from mutating engine-wide fallback rubric.
  - Scoped DM bot `cmd_status` to personal tenant metrics, reserving global fleet metrics for administrator.
- **Server-Side Request Forgery (SSRF) Defense**:
  - Enforced strict SSRF validation on `/api/simulate` image fetching with pre-resolution IP checking against private/loopback/cloud metadata (`169.254.169.254`) ranges, HTTP redirect blocking, 5-second timeout, and 4MB payload cap.
- **XSS & DOM Security**:
  - Enhanced `escapeHtml` to escape quotes (`"`, `'`) in addition to `&`, `<`, `>`.
  - Replaced inline `onclick` handlers with delegated event listeners.
  - Injected defense-in-depth HTTP security headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`.
- **CORS & Cookie Hardening**:
  - Replaced permissive CORS with restricted origin/method/header policy on authenticated and mutating routes.
  - Issued session cookies with `HttpOnly; SameSite=Lax` and conditional `Secure` on HTTPS.
- **Resource Exhaustion Mitigation**:
  - Added `prune_stale` and automatic empty-bucket eviction to `EvaluationRateLimiter` preventing unbounded growth.
  - Replaced infinite fallback loop in `TenantRegistry::fallback()` with explicit error propagation in engine builder.

## [0.1.5] - 2026-10-04

### Fixed

- **Startup Order Optimization for OAuth Client Metadata Discovery**:
  - Activated the Sovereign Web Dashboard early in the service bootstrap sequence before remote PDS listblock verification and sovereign config synchronization.
  - Ensures the OAuth client metadata endpoint (`/oauth/client-metadata.json`) is actively serving requests when remote PDS authorization servers fetch client metadata during startup token refreshes, eliminating `invalid_client_metadata (Bad Gateway)` errors.

## [0.1.4] - 2026-10-04

### Added

- **Persistent OAuth Token Auto-Refresh for Background PDS Operations**:
  - Integrated `AtprotoOAuthClient` with `SkybouncerEngine` and `TenantRegistry` for automated background session lifecycle management.
  - Automatic detection of expired or expiring (within 60s) DPoP OAuth access tokens when resolving tenant `PdsRepoClient`s.
  - Seamless token refresh against the authorization server using stored OAuth refresh tokens with single-flight deduplication.
  - Automatic persistence of refreshed session tokens to SQLite (`update_session`), preserving updated credentials across service restarts.
  - Resolved `Token expired` warnings during startup sovereign config synchronization, listblock checks, and firehose config mutations.
  - Added comprehensive unit test `test_tenant_session_auto_refresh_on_expired_token` verifying transparent token refresh, SQLite cache consistency, and in-memory caching.

## [0.1.3] - 2026-10-04

### Added

- **Tier 1 & Tier 2 Evaluation Audit Log (`👑 Tier 1 & Tier 2 Evaluation Log`)**:
  - Persistent SQLite evaluation audit logging in table `evaluation_log` tracking all evaluations across live firehose ingestion and manual simulations.
  - Granular breakdown per evaluation: author DID and handle, target DID and handle, offending post text, image presence, heuristic pre-filter status, Tier 1 model verdict/confidence/reasoning, and Tier 2 escalation details.
  - Automatic table retention management capping evaluation log entries to the 5,000 most recent records.
  - Admin-only API endpoint `GET /api/admin/evaluations` strictly protected by `is_admin(&caller_did)` gate.
  - Admin dashboard evaluation log card with live filtering by evaluation source (`All`, `Live Firehose`, `Simulations`), Bluesky profile/post links, and auto-refresh after test simulations.

## [0.1.2] - 2026-10-03

### Fixed

- **SQLite Schema Migration Ordering**:
  - Ensured `ALTER TABLE bounced_users ADD COLUMN protected_did` runs before creating dependent index `idx_bounced_users_protected`, resolving startup database error on existing installations.

## [0.1.1] - 2026-10-03

### Added

- **Offending Post Tracking & Direct Bluesky Inspection**:
  - Added `post_text` snippet tracking to `BouncedUser` SQLite records.
  - Added new "Offending Post" column to the "Recently Bounced Violators" dashboard table with inline post text preview and direct clickable link (`🔗 Post {rkey}`) to the offending post on Bluesky (`https://bsky.app/profile/{actor}/post/{rkey}`).
  - Added clickable Bluesky profile link for violator DIDs in the dashboard table.
- **Per-User Scoped Bounce Feeds & Pardons**:
  - Added `protected_did` indexing and filtering to `bounced_users` in SQLite deduplication cache with forward-compatible database migration.
  - Added `user_did` query parameter to `GET /api/bounces` and scoped `pardonUser` requests to the active tenant/user DID.

## [0.1.0] - 2026-10-03

Initial open-source production release of `skybouncer`: the sovereign, rule-driven automated moderation bouncer for AT Protocol and Bluesky.

### Added

- **Interaction Ingestion & Target Matching (`skybouncer::ingest`)**:
  - Live Jetstream event stream listener for protected account interactions.
  - Precision targeting for direct replies, thread root replies, mentions, and quotes.
  - Resilient WebSocket connection management with automatic reconnect.

- **Non-Followed Direct Interaction Gate (`skybouncer::classifier::gate`)**:
  - In-memory thread-safe `FollowGraph` keeping track of trusted follow relationships.
  - Dynamic follow/unfollow synchronization directly from the Jetstream firehose.
  - Sub-microsecond bypass for followed accounts and self-authored posts ($0 model cost, zero latency).

- **Pluggable Structured Classification Engine (`skybouncer::classifier`)**:
  - Trait-based `Classifier` contract delivering structured `Verdict` results (`Violation` vs `Permitted`).
  - `JevClassifier`: asynchronous client for Jev-like structured LLM decision endpoints (`JEV_API_BASE_URL`, `JEV_API_KEY`, `JEV_MODEL`).
  - `HeuristicClassifier`: regex and keyword fast-path pre-filter.
  - `MockClassifier`: deterministic offline classifier for integration testing.
  - Structured `RuleRubric` evaluator supporting Low, Medium, and High sensitivity thresholds.

- **Sovereign PDS Moderation Mutator & Deduplication (`skybouncer::pds`, `skybouncer::index`)**:
  - Auto-provisioning and synchronization of sovereign `app.bsky.graph.list` (`#modlist`).
  - DPoP-signed XRPC `createRecord` mutations for `app.bsky.graph.listitem` via `skybase` / `skyauth`.
  - Embedded SQLite audit history and deduplication cache to prevent duplicate evaluations or list items.
  - Support for unbanning and pardoning (`deleteRecord`).

- **Flexible Interaction Modes & Administration**:
  - Continuous daemon mode (`skybouncer daemon`).
  - Single-target manual dry-run audit CLI (`skybouncer audit`).
  - Web dashboard and REST API with live stats, audit log, and rule management (`skybouncer::web`).
  - Interactive bot command handler for real-time moderation adjustments via Bluesky mentions (`skybouncer::bot`).
  - Sovereign PDS configuration sync (`social.skybouncer.config` / list metadata).

- **Safety & Quality Standards**:
  - `#![forbid(unsafe_code)]` crate-wide.
  - Strict compiler lint safety guard denying unwraps, expects, panics, and missing documentation.
  - Comprehensive unit, integration, and property-based test suites.
