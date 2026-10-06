# Skybouncer Refactoring & Cleanup Plan

> Living document. Work items are ordered by phase (risk-adjusted ROI).
> Each item records exact locations, the intended change, the verification
> performed, and a status marker. Update the status row as work lands.
>
> Status legend: `[ ]` not started · `[~]` in progress · `[x]` done & verified · `[!]` blocked

---

## Quality gates (run before marking ANY item complete)

Per `AGENTS.md` and the `rust-best-practices` blueprint:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo deny check
```

Additional blueprint tooling (currently unavailable locally, install if needed):
`cargo nextest run`, `cargo llvm-cov`, `cargo mutants`. `cargo-audit` optional.

**No production `unwrap`/`expect`/`panic`/`todo`/`unimplemented`.** Every fallible
operation returns `Result<T, SkybouncerError>`. Never lower lint gates.
Never hold a lock across `.await`. Use clock-warp-safe time math.

---

## Cross-repo coordination

The three crates are **independent git repositories**, not a cargo workspace:

| Crate | Path | Role | Version |
|---|---|---|---|
| `skybouncer` | `/home/mike10010100/git/skybouncer` | this crate | 0.1.20 |
| `skybase` | `/home/mike10010100/git/skybase` | ATProto engine | 0.1.0 |
| `skyauth` | `/home/mike10010100/git/skyauth` | OAuth/DPoP/security | 0.3.2 |

When pulling code up into a parent, add it to the parent repo with its own tests,
then consume it from skybouncer via the path dependency. Do not commit in the
parents unless explicitly requested.

---

## Phase 0 — Baseline & dependency hygiene  (low risk)

| ID | Item | Location | Change | Status |
|----|------|----------|--------|--------|
| D1 | Remove unused `http` crate | `Cargo.toml:34` | All HTTP types come from `axum::http` / `reqwest`; `http` has zero direct uses. Delete the dep. | `[x]` |
| D2 | Move `tower` to dev-deps | `Cargo.toml:32` | Only `tests/*.rs` use `tower::ServiceExt`; no library consumer. | `[x]` |
| D3 | Feature-gate optional subsystems | `Cargo.toml` | Add `[features]`: `web = [dep:axum, dep:tower-http]`, `stream = [dep:tokio-tungstenite]`, `bot`, `telemetry`; `default` = all. Keep `rusqlite`/`ring`/`futures-util` in core. | `[x]` |
| D4 | Bin-only `tracing-subscriber` | `Cargo.toml:67`, `src/main.rs:29` | Made optional behind `telemetry`; bin requires it. | `[x]` |
| D5 | `tokio-util` via skybase re-export | `Cargo.toml:48` | **Deferred**: `CancellationToken` is passed across the API by skybouncer itself, so a direct dep is clearer than re-exporting through skybase. | `[!]` |
| D6 | Stale `Cargo.lock` versions | `Cargo.lock` | `cargo update` (7 packages); `cargo deny check` clean. Remaining `base64`/`thiserror` dupes are transitive and not directly removable. | `[x]` |

---

## Phase 1 — Dead code & lint-suppression removal  (low risk)

| ID | Item | Location | Change | Status |
|----|------|----------|--------|--------|
| C1 | `stateless_mode` dead config | `src/engine.rs` | Removed field, default, env parse, and struct init; was never read. | `[x]` |
| C2 | Dead `CreateSessionResponse.did` | `src/bot/client.rs:26` | `did` is actually read at `:186` (returned to caller); removed the stale `#[allow(dead_code)]`. | `[x]` |
| C3 | `too_many_arguments` suppressions | `src/modlist/manager.rs` | Added `BounceRequest<'a>` (+ `new`/`with_post_text`/`with_expires_at`); replaced `bounce_user`/`bounce_user_with_text` with unified `bounce(&PdsRepoClient, BounceRequest)`. Removed both allows. Migrated 23 call sites (engine + 4 test files); exported `BounceRequest`. | `[x]` |
| C4 | `cast_possible_truncation` allow | `src/stream.rs` | Now `u64::try_from(capped).unwrap_or(u64::MAX)`; allow removed. | `[x]` |
| C5 | `module_inception` allow | `src/matcher/mod.rs` | Renamed `matcher/matcher.rs` → `matcher/target.rs`; allow removed. | `[x]` |

---

## Phase 2 — Internal dedup (mechanical, high confidence)

| ID | Item | Location | Change | Status |
|----|------|----------|--------|--------|
| I1 | `BouncedUser` row mapping ×5 | `src/modlist/cache.rs` | Added `BOUNCED_USER_COLUMNS` + `map_bounced_user`; all 5 query sites use them. | `[x]` |
| I2 | `get_bounced_user` / `_for` merge | `src/modlist/cache.rs` | Added private `get_bounced_user_scoped`; both public getters delegate. | `[x]` |
| I3 | Bounce delete logic ×2 | `src/modlist/cache.rs` | Added `delete_bounce_rows(tx, protected_did, subject_did)` used by both removers. | `[x]` |
| I4 | `current_time_us` ×3 | new `src/time.rs` | Consolidated into `time::current_time_us`; removed local copies in `cache.rs`, `manager.rs`, `registry.rs`; engine/web use `crate::time`. | `[x]` |
| I5 | `default_true` ×3 (+`is_true`) | `src/types.rs` | Added `types::default_true` / `types::is_true`; removed 3 local copies. | `[x]` |
| I6 | `i64`/`u64` time conversions ×30 | new `src/time.rs` | Added `us_to_i64` / `i64_to_us`; applied across cache/registry. | `[x]` |
| I7 | `Sensitivity` parse dup | `src/classifier/rubric.rs` | Added `sensitivity_from_db`; sovereign_config + registry now use it. | `[x]` |
| I8 | `BounceDuration` parse dup | `src/classifier/rubric.rs` | Added `bounce_duration_from_db`; sovereign_config + registry now use it. | `[x]` |
| I9 | Handle normalize / DID check ×20 | across modules | Completed via `util::normalize_handle` (see S2). | `[x]` |
| I10 | Target-handle lookup ×4 | `src/engine.rs` | Added `SkybouncerEngine::target_handle`; 4 sites updated. | `[x]` |
| I11 | Synthetic `Interaction` build ×3 | `src/matcher/interaction.rs` | Added `Interaction::synthetic` + `with_post_uri`/`with_post_cid`/`with_enriched_context_opt`; 3 sites updated. | `[x]` |
| I12 | `InteractionOutcome` label match ×2 | `src/engine.rs` | Added `InteractionOutcome::label()`; heuristic path preserves its `(Regex Pre-filter)` variants. | `[x]` |
| I13 | Evaluation-log construction ×4 | `src/modlist/cache.rs` | Added `NewEvaluationLog::heuristic` / `::from_tiered` with `EvaluationLogContext`; 4 sites updated. | `[x]` |
| I14 | Jev prompt/state template ×2 | `src/classifier/jev.rs` | Added `enrichment_suffix` + `build_candidate_prompt`; both endpoints use them. | `[x]` |
| I15 | SQLite pragma setup ×2 | `src/util.rs` | Added `apply_common_pragmas`; cache/registry keep their specific pragmas. | `[x]` |
| I16 | Shard hashing ×2 | `src/util.rs` | Added `shard_index`; manager `shard_for` and limiter `shard_idx` use it. | `[x]` |
| I17 | CLI arg parsing ×3 | `src/main.rs` | **Deferred to Phase 3 (E-series)**: covered by env/config unification. | `[!]` |
| I18 | Test fixtures | across `#[cfg(test)]` modules | Added `test_cache`/`bounce_fixture`/`eval_log_fixture` (cache) and `test_registry` (registry); migrated 12 + 10 constructor sites. | `[x]` |

---

## Phase 3 — Env & config unification  (low/medium risk)

| ID | Item | Location | Change | Status |
|----|------|----------|--------|--------|
| E1 | Dual-prefix env parsing ×60 | new `src/env.rs` | Added `var`, `var_or`, `parsed`, `parsed_or`, `bool`, `bool_or`; migrated `SkybouncerConfig::from_env`, `JevConfig::from_env`, `WebServerConfig::from_env`, `SessionCipher::from_env`, `RateLimiterConfig::from_env`, bot handler, `main.rs`. | `[x]` |
| E2 | Divergent daemon URL resolution | `src/main.rs` | `resolve_daemon_url` now derives the port from `WebServerConfig::from_env` (honors `HOST`/`PORT`), no longer hardcodes 127.0.0.1:3000. | `[x]` |
| E3 | Double `WebServerConfig::from_env()` | `src/main.rs` | Removed the second call; bot handler reuses the daemon-scoped `web_config`. | `[x]` |
| E4 | AppView endpoint re-derived | `src/enricher.rs` | Added `AppViewContextEnricher::from_env()`; `main.rs` uses it. | `[x]` |
| E5 | Hand-rolled dotenv parser | `src/env.rs` | Moved to `env::load_dotenv_file`; `main.rs` delegates. | `[x]` |
| E6 | `init_tracing` helper | `src/env.rs` | Added `env::init_tracing()` behind the `telemetry` feature; `main.rs` delegates. | `[x]` |
| I17 | CLI arg parsing ×3 | `src/main.rs` | Added `arg_value`; pardon/simulate use it. | `[x]` |

---

## Phase 4 — Sibling-crate reuse & pull-ups

| ID | Item | Direction | Change | Status |
|----|------|-----------|--------|--------|
| S1 | SSRF image fetch reuse | reuse `skyauth` | Replaced 118-line `fetch_simulation_image` with `SsrfFilter::default().safe_get(url, 2MiB)` + `map_ssrf_error`. SSRF test passes. | `[x]` |
| S2 | Handle/DID normalization reuse | reuse `skyauth` | Added `util::normalize_handle` (preserves skybouncer's trim + strip-`@`, case-preserving semantics) and migrated ~24 sites. Strict `skyauth::identity::normalize_handle` intentionally not used for cache keys (case-folding/label validation would change behavior). | `[x]` |
| S3 | AT-URI helpers reuse | reuse `skybase` | Deduped the two local parsers via `split_at_uri`; kept behavior (skybase `parse_at_uri` rejects `at://did:x` with no collection, which skybouncer accepts). | `[x]` |
| S4 | Error composition | reuse both | **Deferred**: adding `#[from]` transparent variants changes `SkybouncerError`'s public shape and 44 tests match on variants; treat as a dedicated breaking change. | `[!]` |
| S5 | Jetstream stream loop | reuse `skybase` | `StreamConfig::build_url` now wraps `build_subscription_url_full`; replaced hand-rolled jitter/doubling with `skybase::ingest::backoff::BackoffManager`; removed `apply_jitter`. | `[x]` |
| S6 | `SessionCipher` AES-256-GCM envelope | pull up → `skyauth` | Added `skyauth::sealed::SealedBox` (`seal`/`open` + AAD + hex key + envelope prefix) with 10 new tests in `skyauth/tests/sealed_box_tests.rs`; added `CryptoError::{Seal,Open,InvalidEnvelope,Utf8}`. skybouncer `SessionCipher` is now a thin adapter; removed direct `ring` dep. Also bumped `skyauth`'s `rustls` 0.23.43→0.23.45 to clear RUSTSEC-2026-0285. | `[x]` |
| S7 | AppView XRPC reads + pagination | pull up → `skybase` | Added `skybase::appview::AppViewClient` (typed profile/post/follows/followers/follow-records + generic `get`/`paginate` + `thumbnail_url`) with 8 wiremock tests; `AppViewContextEnricher` now delegates to it (~230 LOC removed from skybouncer). | `[x]` |
| S8 | Bot chat client | pull up → `skybase` | Moved `ChatClient` + all `chat.bsky.convo.*` types to `skybase::chat` (7 new tests); added `SkybaseError::Chat`. skybouncer re-exports from `skybase`, deleting `bot/{client,types}.rs` (~1,225 LOC). | `[x]` |
| S9 | Lexicon record models | pull up → `skybase` | Moved the full lexicon to `skybase::lexicon`: richtext (ByteSlice/Facet/FacetFeature/`extract_link_facets`) + records (StrongRef/ReplyRef/Embed/PostRecord/FollowRecord/ModListRecord/ListItemRecord/ListBlockRecord/RepoRecordItem/ListRecordsResponse) + `format/now_iso8601` (18 unit tests). `skybouncer/types.rs` is now a re-export shim. | `[x]` |

---

## Phase 5 — Structural splits (medium effort, behavior-preserving)

| ID | Item | Location | Change | Status |
|----|------|----------|--------|--------|
| T1 | Split `engine.rs` | `src/engine/` | Split into `mod` (config/stats/outcomes/types/builder) + `accessors`, `handles`, `modlist_ops`, `tenant_ops`, `lifecycle`, `processing` modules. | `[x]` |
| T2 | Split `cache.rs` | `src/modlist/cache/` | Split into `mod` (types/schema/tests) + `core`, `modlist`, `bounces`, `evaluations`, `dashboard`, `allowlist`, `handles`. | `[x]` |
| T3 | Externalize dashboard HTML | `src/web/ui.rs` | Moved the ~100KB `DASHBOARD_HTML` string to `assets/dashboard.html` + `include_str!`; `ui.rs` is now ~14 lines. Verified `cargo package --list` includes the asset. | `[x]` |
| T4 | Split `web/api.rs` | `src/web/api/` | Split into `mod` (DTOs/auth helpers/tests) + `telemetry`, `auth`, `bounces`, `simulate`, `tenant`, `resolve`. | `[x]` |
| T5 | Split `tenant/registry.rs` | `src/tenant/registry/` | Split into `mod` (types/schema/tests) + `core`, `sessions`, `handles`, `admin`. | `[x]` |
| T6 | Thin `main.rs` | `src/engine/simulate.rs` | Added `SkybouncerEngine::run_simulation` (+`SimulationInputs`/`SimulationResult`/`SimulateTierStage`), extracting the tiered simulate pipeline shared by the web handler and the CLI `--offline` path (which now builds a dry-run engine). Both paths now use `classify_detailed` and produce tier detail. | `[x]` |

---

## Phase 6 — Behavior-sensitive pipeline dedup (verify carefully)

| ID | Item | Location | Change | Status |
|----|------|----------|--------|--------|
| P1 | `process_commit` / `_queued` twins | `engine.rs` | Extracted `dispatch_commit -> CommitDispatch`; both entry points are now ~15-line wrappers. | `[x]` |
| P2 | `process_interaction` / `_queued` fast path | `engine.rs` | Extracted `fast_path -> FastPath`; sync path emits the heuristic audit log (including the error case) via `FastPath::Heuristic(Result, Verdict)`. | `[x]` |
| P3 | `FollowGraph` reverse-index mirror | `matcher/follow_graph.rs` | **Deferred**: the two indexes are asymmetric (incoming index is keyed by follower but stores the protected DID, not a set member), so a single generic `ReverseIndex` cannot model both without risking real-time unfollow reconciliation. | `[!]` |
| P4 | `list_active` / `list_all` merge | `tenant/registry.rs` | Added `list_filtered(active_only)`; both public methods delegate. | `[x]` |
| P7 | Generic pagination helper | `enricher.rs` | Added private `paginate<T,I,F>`; `fetch_follows`/`fetch_followers`/`fetch_follow_records` now thin projections. | `[x]` |
| P5 | Bot dispatch auth guard ×15 | `bot/handler.rs` | Hoisted one `is_authorized_sender` probe (`authorized`) replacing 20 inline checks; added `resolve_dm_target` + `authorized_protected` replacing 4 duplicated target/permission blocks. `help`/onboarding stay ungated. | `[x]` |
| P6 | HTTP status/error boilerplate | `bot/client.rs` | Added `build_request` helper used by the initial and post-refresh retry sends. Broader cross-module unification left as-is (distinct error variants + bounded-body helpers already localized). | `[x]` |

---

## Progress log

- 2026-10-06 (T6 complete): Extracted `SkybouncerEngine::run_simulation` (engine/simulate.rs) as
  the single dry-run evaluation pipeline; the web `/api/simulate` handler and the CLI
  `simulate --offline` path (now via a dry-run engine) both delegate to it. skybouncer
  430 + 48 tests, clippy/fmt/deny clean.

- 2026-10-06 (S9 complete): Extended `skybase::lexicon` with the full record model set
  (StrongRef/ReplyRef/Embed/PostRecord/FollowRecord/ModListRecord/ListItemRecord/
  ListBlockRecord/RepoRecordItem/ListRecordsResponse + format/now_iso8601). skybouncer
  `types.rs` is now a re-export shim (~590 LOC removed). skybase 302 tests, skybouncer
  430 + 48, all clippy/fmt/deny clean.

- 2026-10-06 (S8 + partial S9): Pulled the ATProto Chat client (`ChatClient` + `chat.bsky.convo.*`
  types) into `skybase::chat` and the richtext lexicon (`ByteSlice`/`Facet`/`FacetFeature`/
  `extract_link_facets`) into `skybase::lexicon`; added `SkybaseError::Chat` and
  `From<SkybaseError> for SkybouncerError`. skybouncer deleted `bot/{client,types}.rs`
  (~1,225 LOC) and re-exports from skybase. Verified: skybouncer 437 + 55 tests pass,
  clippy (`--all-targets` + lean core) clean; skybase 294 tests pass, clippy clean;
  skyauth 890 tests pass. All fmt/deny clean.

- 2026-10-05: Plan authored from two-codebase exploration + standards review. Baseline
  quality gates captured: 446 tests pass, fmt/clippy/deny clean.
- 2026-10-05 (Phase 0): D1 removed `http`; D2 moved `tower` to dev-deps; D3 added
  `web`/`stream`/`bot`/`telemetry` features with `#[cfg]`-gated modules/re-exports;
  D4 made `tracing-subscriber` optional behind `telemetry`; D6 ran `cargo update`.
  D5 deferred (rationale above). Added CI step `2b` for the lean-core clippy gate.
  Verified: `cargo build --lib --no-default-features` clean, `cargo clippy
  --all-targets --all-features -D warnings` clean, `cargo test --all-targets` = 446 pass,
  `cargo test --no-default-features --lib` = 54 pass, `cargo deny check` clean.
- 2026-10-05 (Phase 1): C1 removed dead `stateless_mode`; C2 removed stale `allow(dead_code)`
  (`did` is used); C3 added `BounceRequest` + unified `ModListManager::bounce`, migrating 23
  call sites; C4 replaced truncating cast with `u64::try_from`; C5 renamed
  `matcher/matcher.rs` → `matcher/target.rs`. All 446 tests pass; clippy/fmt/deny clean.
- 2026-10-05 (Phase 2): I1-I8, I10-I16 completed via new `src/time.rs` and `src/util.rs`
  and builders on `Interaction`, `InteractionOutcome`, `NewEvaluationLog`. I9 deferred to
  S2, I17 deferred to E-series. Each step verified with `cargo build --all-targets` and a
  final full `cargo test --all-targets` (446 pass) + clippy `-D warnings` clean.
- 2026-10-05 (Phase 3): E1-E6 + I17 completed via new `src/env.rs` (dual-prefix helpers,
  `load_dotenv_file`, `init_tracing`). Removed ~60 hand-rolled `std::env::var` chains;
  `resolve_daemon_url` no longer hardcodes host/port; removed duplicate
  `WebServerConfig::from_env` call; added `arg_value`. 446 tests pass; clippy/fmt/deny clean.
- 2026-10-05 (Phase 4, partial): S1 (SSRF reuse), S2 (`util::normalize_handle`), S3
  (`split_at_uri`), S5 (skybase `BackoffManager` + `build_subscription_url_full`), S6
  (`skyauth::sealed::SealedBox` pull-up + skybouncer adapter + `ring` removal) landed.
  skyauth: new `sealed` module, 10 tests, 890 tests pass, clippy all-features clean, deny
  clean (rustls bumped to 0.23.45). S4/S7/S8/S9 deferred with rationale.
- 2026-10-05 (Phase 6, partial): P4 (`list_filtered`), P7 (generic `paginate`) landed.
  Final skybouncer state: `cargo test --all-targets` = **447 pass**, `--no-default-features
  --lib` = 55 pass, clippy (`--all-targets` and lean core) `-D warnings` clean, fmt clean,
  `cargo deny check` clean.
- Remaining (documented, not yet done): P3 (FollowGraph reverse-index, asymmetric),
  S4 (error composition, breaking), S8/S9 (chat client + lexicon models, larger
  cross-repo lifts), T6 (simulate pipeline, divergent response shapes). All other
  items in Phases 0-6 are complete.
- 2026-10-05 (Phases 4-6 + splits, continued):
  - S7: added `skybase::appview::AppViewClient` (+8 tests); delegated `AppViewContextEnricher`.
  - P1/P2: extracted `dispatch_commit` and `fast_path` in the engine.
  - P4/P5/P6/P7: registry list merge, bot auth/target helpers, chat request builder,
    enricher pagination.
  - T1: split `engine.rs` → `src/engine/{mod,accessors,handles,modlist_ops,tenant_ops,
    lifecycle,processing}.rs`.
  - T2: split `cache.rs` → `src/modlist/cache/{mod,core,modlist,bounces,evaluations,
    dashboard,allowlist,handles}.rs`.
  - T4: split `web/api.rs` → `src/web/api/{mod,telemetry,auth,bounces,simulate,tenant,resolve}.rs`.
  - T5: split `tenant/registry.rs` → `src/tenant/registry/{mod,core,sessions,handles,admin}.rs`.
  - I18: test fixtures.
  Each step verified: skybouncer 447 tests pass, clippy `-D warnings` clean across
  `--all-targets` and the lean core; fmt clean.

## Baseline notes

Captured 2026-10-05 at `skybouncer 0.1.20` (rustc 1.98.0), before any edits:

- `cargo fmt --all -- --check` → clean
- `cargo clippy --all-targets -- -D warnings` → clean (17s incremental)
- `cargo test --all-targets` → **446 passed / 0 failed**
- `cargo deny check` → advisories ok, bans ok, licenses ok, sources ok
