# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
