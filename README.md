# 🛡️ Skybouncer

> **Sovereign, Rule-Driven Auto-Moderation & Bouncer Service for AT Protocol and Bluesky**

[![Crates.io](https://img.shields.io/crates/v/skybouncer.svg)](https://crates.io/crates/skybouncer)
[![Rust Safe](https://img.shields.io/badge/Rust-Safe_2021-brightgreen.svg)](#)
[![Forbid Unsafe](https://img.shields.io/badge/%23!%5Bforbid(unsafe_code)%5D-enforced-blue.svg)](#)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#)

---

## 📖 Overview

**Skybouncer** is an automated moderation service and personal bouncer for the AT Protocol (ATProto) and Bluesky. Inspired by community discussions on sovereign, decentralized moderation, it protects users from low-effort hostility, bad-faith sea-lioning, and crypto spam bots without manual toil or blunt third-party blocklists.

### Key Capabilities
1. **Natural-Language Rule Enforcement**: Define personal house rules (e.g. *"Block crypto scam bots, harassment, and aggressive sea-lioning"*).
2. **Sub-50ms System-1 Classification**: Evaluates incoming replies, mentions, and quotes using **Jev** (TypeSafe AI) or lightweight multimodal LLMs with tiered escalation.
3. **Native ATProto Mod Lists**: Violators are added as `app.bsky.graph.listitem` records to an ATProto Moderation List (`app.bsky.graph.list` with `purpose: "app.bsky.graph.defs#modlist"`). Subscribing natively mutes or blocks them across the entire network.
4. **Stateless & Sovereign**: Rules and lists live in each user's sovereign repository on their PDS (`social.skybouncer.config/self` + `app.bsky.graph.list`), requiring zero platform lock-in.
5. **Dogpile Radar & Storm Mode**: Detects out-of-network reply/quote surges, switches notifications to digest batching, and lets you lock threads (`app.bsky.feed.threadgate`) or detach quote-posts (`app.bsky.feed.postgate`).
6. **Dual Interaction Topologies**:
   - **DM Bot Interface (`chat.bsky.convo.*`)**: Website-free interaction. DM the bot account to configure rules, manage allowlists, handle storms, test text, and view bouncer activity:
     - `rules` / `set rules <prompt>`: View or update your active moderation prompt.
     - `sensitivity <low|medium|high>`: Adjust classification confidence threshold.
     - `duration <permanent|24h|7d|30d>`: Configure temporary timeout vs permanent block duration.
     - `trust followers <on|off>`: Toggle automatic bypass for accounts that follow you.
     - `pause` / `resume`: Suspend or resume automated moderation for your account.
     - `recent`: List recently bounced violators.
     - `pardon <did|@handle>` / `pardon and allow <did|@handle>`: Remove an account from your moderation list (and optionally immunize them).
     - `bounce <target>` / `perm <target>`: Manually bounce or permanently block an account.
     - `allow <target>` / `unallow <target>` / `allowlist [page]`: Manage your trusted allowlist.
     - `storms` / `storm <on|off>`: Inspect active dogpile surges or toggle Storm Mode.
     - `lock [post] [policy]` / `unlock [post]`: Apply or remove an `app.bsky.feed.threadgate` reply lock.
     - `detach [post] [qt|all]`: Detach catalyst quote-posts or disable quotes via `app.bsky.feed.postgate`.
     - `status` / `test <text>`: View live telemetry and run dry-run evaluations on sample text.
     - `start` / `auth` / `help`: Get an activation link or view all available commands.
   - **Sovereign Web Dashboard (`skyauth`)**: Strict-CSP Web UI with ATProto OAuth 2.0 PKCE + DPoP login, live sandbox simulator, paginated audit logs, and Storm Mode controls.

---

## 📐 Architecture Pipeline

```text
Incoming Jetstream (app.bsky.feed.post)
            │
            ▼
┌───────────────────────────────────────┐
│ Interaction Watcher                   │
│ Matches replies, mentions & quotes    │
└───────────────────┬───────────────────┘
                    │
                    ▼
┌───────────────────────────────────────┐
│ Context Enricher & Cache              │
│ Embedded SQLite check + author bio    │
└───────────────────┬───────────────────┘
                    │
                    ▼
┌───────────────────────────────────────┐
│ Evaluation Engine                     │
│ Jev System-1 classifier / LLM fallback│
└───────────────────┬───────────────────┘
                    │ (if VIOLATION)
                    ▼
┌───────────────────────────────────────┐
│ Sovereign List Mutator                │
│ Writes app.bsky.graph.listitem (DPoP) │
└───────────────────────────────────────┘
```

---

## 🐳 Deployment & Operations

For complete production deployment instructions, system hardening, and operational runbooks, see the [**Production Deployment & Operations Guide**](docs/DEPLOYMENT.md).

### Quickstart with Docker Compose

1. Copy `.env.example` to `.env` and configure your credentials:
   ```bash
   cp .env.example .env
   chmod 0600 .env
   ```

2. Launch Skybouncer with persistent SQLite storage:
   ```bash
   docker compose up --build -d
   ```
   *(To run with a self-contained local Ollama vision model, use: `docker compose --profile local-ai up -d`)*

3. View live logs and telemetry:
   ```bash
   docker compose logs -f skybouncer
   ```

4. Access the embedded sovereign dashboard: `<http://127.0.0.1:3031>` (Docker Compose default `PORT_BIND=3031` -> container port `3000`; bare-metal systemd defaults to `<http://127.0.0.1:3000>`).

### Bare Metal / VPS Deployment with Systemd

For Linux servers, an automated idempotent installer with strict process sandboxing is provided:
```bash
cargo build --release --bin skybouncer
sudo ./deploy/systemd/install.sh
```

---

## 🛠️ Repository Standards & Quality Gates

`skybouncer` enforces strict production-grade Rust safety standards:
* `#![forbid(unsafe_code)]`
* Zero unwraps/panics in production code paths
* Strongly typed errors via `SkybouncerError`
* Clock-warp safe monotonic time handling
* 100% documentation coverage (`missing_docs`)
* `>= 92%` line test coverage

Before every commit and in CI (`.github/workflows/ci.yml`), all quality gates must pass:
```bash
# 1. Verify Semantic Version bump & CHANGELOG entry (required on PR branches)
./scripts/check_version_bump.sh

# 2. Format check
cargo fmt --all -- --check

# 3. Strict clippy (full targets & lean core)
cargo clippy --all-targets -- -D warnings
cargo clippy --lib --no-default-features -- -D warnings

# 4. Unit, integration, coverage (>= 92%), lean-core & doc tests
cargo test --lib --no-default-features
cargo llvm-cov clean --workspace
cargo llvm-cov nextest --all-targets --lcov --output-path lcov.info
cargo llvm-cov report --fail-under-lines 92
rm -f lcov.info
cargo test --doc

# 5. Dependency governance, vulnerability & shell script scans
cargo deny check
cargo audit
shellcheck scripts/*.sh deploy/systemd/install.sh
```

For full architectural requirements, see [`PRD.md`](PRD.md) and [`AGENTS.md`](AGENTS.md).
