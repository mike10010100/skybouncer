# 🛡️ Skybouncer

> **Sovereign, Rule-Driven Auto-Moderation & Bouncer Service for AT Protocol and Bluesky**

[![Crates.io](https://img.shields.io/badge/crates.io-v0.1.0-blue.svg)](https://crates.io/crates/skybouncer)
[![Rust Safe](https://img.shields.io/badge/Rust-Safe_2021-brightgreen.svg)](#)
[![Forbid Unsafe](https://img.shields.io/badge/%23!%5Bforbid(unsafe_code)%5D-enforced-blue.svg)](#)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#)

---

## 📖 Overview

**Skybouncer** is an automated moderation service and personal bouncer for the AT Protocol (ATProto) and Bluesky. Inspired by community discussions on sovereign, decentralized moderation, it protects users from low-effort hostility, bad-faith sea-lioning, and crypto spam bots without manual toil or blunt third-party blocklists.

### Key Capabilities
1. **Natural-Language Rule Enforcement**: Define personal house rules (e.g. *"Block crypto scam bots, harassment, and aggressive sea-lioning"*).
2. **Sub-50ms System-1 Classification**: Evaluates incoming replies, mentions, and quotes using **Jev** (TypeSafe AI) or lightweight LLMs.
3. **Native ATProto Mod Lists**: Violators are added as `app.bsky.graph.listitem` records to an ATProto Moderation List (`app.bsky.graph.list` with `purpose: "app.bsky.graph.defs#modlist"`). Subscribing natively mutes or blocks them across the entire network.
4. **Stateless & Sovereign**: Rules and lists can live directly in the user's sovereign repository on their PDS, requiring zero external database custody.
5. **Dual Interaction Topologies**:
   - **DM Bot Interface (`chat.bsky.convo.*`)**: Website-free interaction. DM the bot account to configure rules, test text, and view bouncer activity:
     - `rules`: View current moderation rubric and sensitivity.
     - `set rules <prompt>`: Update your moderation rubric in real time.
     - `sensitivity <low|medium|high>`: Adjust classification threshold.
     - `recent`: List recently bounced violators.
     - `pardon <did>`: Pardon and remove an account from your moderation list.
     - `status`: View live engine telemetry and bounce counts.
     - `test <text>`: Dry-run evaluation on sample text.
     - `help`: View all available commands.
   - **Sovereign Web Dashboard (`skyauth`)**: Web UI with ATProto OAuth 2.0 PKCE + DPoP login and real-time rule playground.

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

## 🐳 Deployment & Containerization

### Running with Docker Compose

1. Copy `.env.example` to `.env` and configure your protected DIDs, PDS credentials, and Jev API keys:
   ```bash
   cp .env.example .env
   ```

2. Build and start the service with persistent SQLite storage:
   ```bash
   docker compose up --build -d
   ```

3. View live logs and telemetry:
   ```bash
   docker compose logs -f skybouncer
   ```

4. Access the embedded sovereign dashboard in your browser:
   ```
   http://localhost:3000
   ```

### Building Standalone Docker Image

From the workspace root (`atproto-experiments/`):
```bash
docker build -f skybouncer/Dockerfile -t skybouncer:latest .
```

---

## 🛠️ Repository Standards & Quality Gates

`skybouncer` enforces strict production-grade Rust safety standards:
* `#![forbid(unsafe_code)]`
* Zero unwraps/panics in production code paths
* Strongly typed errors via `SkybouncerError`
* Clock-warp safe monotonic time handling
* 100% documentation coverage

Before every commit and in CI (`.github/workflows/ci.yml`), all 4 gates must pass:
```bash
# 1. Format check
cargo fmt --all -- --check

# 2. Strict clippy
cargo clippy --all-targets -- -D warnings

# 3. Unit and integration tests
cargo test --all-targets

# 4. Dependency governance & security scan
cargo deny check
```

For full architectural requirements, see [`PRD.md`](PRD.md) and [`AGENTS.md`](AGENTS.md).
