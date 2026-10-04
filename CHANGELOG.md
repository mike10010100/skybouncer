# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.11] - 2026-10-04

### Added & Enhanced

- **Persistent Moderation Allowlist & Pardon Immunization (PRD §7.1)**:
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
