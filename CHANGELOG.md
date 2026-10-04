# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
