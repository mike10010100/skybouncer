# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
