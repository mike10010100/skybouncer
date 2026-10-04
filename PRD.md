# 📄 Product Requirements Document (PRD)

# `skybouncer`
### Sovereign, Rule-Driven Auto-Moderation & Bouncer Service for AT Protocol and Bluesky

---

## ⚡ Executive 1-Pager (The TL;DR)

| Dimension | Specification |
| :--- | :--- |
| **Product** | `skybouncer`: A hosted, multi-tenant sovereign auto-moderation service and public bouncer for Bluesky and the AT Protocol (ATProto). |
| **The Core Problem** | Social spam, bad-faith sea-lioning, crypto airdrop bots, and targeted harassment degrade conversations on Bluesky. Existing solutions require tedious manual muting/blocking, crude static keyword filters, or blanket third-party blocklists that lack personal nuance and context. |
| **The Solution** | `skybouncer` allows any Bluesky user to define personalized, natural-language moderation rules (e.g., *"Block crypto scam bots, harassment, and aggressive sea-lioning"*). An interaction watcher monitors incoming mentions, replies, and quotes directed at enrolled users via the Jetstream firehose, evaluates interactions using low-latency System-1 classifiers (**Jev** / lightweight LLMs), and automatically appends offending accounts to each user's sovereign ATProto Moderation List (`app.bsky.graph.listitem`). The user subscribes to their own list, natively muting or blocking violators across the entire Bluesky network. |
| **Dual UX Topologies** | **1. Public DM Bot Interface (`chat.bsky.convo.*`)**: Conversational onboarding and self-service management for anyone on Bluesky. Unenrolled users receive a friendly greeting and 1-click authorization link; enrolled users configure rules, view recent actions, or adjust sensitivity.<br/>**2. Sovereign Web Portal (`skyauth`)**: Web UI powered by ATProto OAuth 2.0 with PKCE and DPoP cryptographic proofs, featuring multi-tenant onboarding, live rule playground, and audit stream. |
| **The Sovereign Multi-Tenant Model** | Moderation rules and lists are published directly to each user's sovereign repository on their PDS (e.g., as custom ATProto records or encoded list metadata). The service operates in a **sovereign, multi-tenant mode**—storing only encrypted OAuth DPoP sessions and caching interaction evaluations, with zero platform lock-in. |
| **Underlying Engine & Release** | Published on crates.io (`skybouncer v0.1.6`), built in 100% Safe Rust (`#![forbid(unsafe_code)]`), powered directly by sibling crates [`skybase`] (Jetstream ingestion, SQLite caching, DPoP PDS write client) and [`skyauth`] (OAuth 2.0 PKCE + DPoP session lifecycle). |

---

## 1. Problem Statement & Ecosystem Context

### 1.1 The Personal Moderation Crisis in Decentralized Social Networks
On open social networks like Bluesky, public discourse is vulnerable to:
1. **Low-Effort Hostility & Sea-Lioning**: Users frequently face bad-faith derailment, persistent sea-lioning, and coordinated quote-tweet pile-ons.
2. **Automated Crypto & Phishing Scams**: Bots reply to trending conversations with airdrop lures, fake giveaways, and phishing links.
3. **The Limitations of Manual Moderation**:
   - Manually reviewing profiles and clicking "Block" or "Mute" on dozens of accounts per day induces severe cognitive fatigue.
   - By the time a user blocks someone, the emotional and conversational damage has already occurred.
4. **The Flaws of Coarse Blocklists**:
   - Community-curated moderation lists (e.g., Ozone labels or public blocklists) often suffer from maintainer bias, stale entries, and collateral damage (blocking innocent bystanders).
   - What one user considers unacceptable harassment, another user may consider robust debate. **Moderation criteria are inherently subjective and personal.**

### 1.2 The Catalyst: Hoopy Frood's Proposal
The concept for `skybouncer` directly realizes the architectural pattern discussed in the Bluesky developer ecosystem:

> **Hoopy Frood (`@huwupy.kawaii.social`)**:
> *"complaining that Aaron has access to secret moderating tools that block people for him is funny because i’m pretty sure what he has access to is claude code and five dollars"*
> 
> *"actually that would be a fun little project to set up, the user SSO’s in and sets some rules, and then you use Jev or a Jevlike to populate a list that they can subscribe to. theoretically stateless too, unless you want the rules to be private"*
> 
> *"literally the only annoying thing would be making a website. instead, make this an account you DM with"*
> 
> *"For cost control the rule has to be “all posts directed at them, but by a user they don’t follow” of course"*


### 1.3 What is "Jev" and Why Now?
In mid-September 2026, TypeSafe AI introduced **Jev**, a specialized "System 1" AI model designed specifically for low-latency, structured classification rather than open-ended text generation:
* **Structured Decision Output**: Returns deterministic booleans, category labels, or ordinal scores with confidence metrics (e.g., `{ "violates": true, "category": "crypto_spam", "confidence": 0.96 }`).
* **Sub-50ms Latency**: Executes in a fraction of the time required by autoregressive LLMs (Claude, GPT-4, Gemini).
* **Fraction-of-a-Cent Cost**: Operates at a cost profile orders of magnitude cheaper than standard conversational APIs, making real-time firehose interaction monitoring economically viable.

`skybouncer` abstracts this evaluation step through a pluggable classifier interface, natively supporting **Jev**, lightweight LLMs (e.g. Gemini Flash / Claude Haiku), and local heuristic rules.

---

## 2. ATProto Architectural Alignment

### 2.1 Native ATProto Moderation Lists
In the AT Protocol, moderation lists are sovereign records stored in a user's repository:
* **List Definition (`app.bsky.graph.list`)**:
  ```json
  {
    "$type": "app.bsky.graph.list",
    "name": "Skybouncer Auto-Filter",
    "purpose": "app.bsky.graph.defs#modlist",
    "description": "Personalized automated moderation list managed by @skybouncer.bsky.social",
    "createdAt": "2026-10-01T20:00:00.000Z"
  }
  ```
* **List Item (`app.bsky.graph.listitem`)**:
  ```json
  {
    "$type": "app.bsky.graph.listitem",
    "subject": "did:plc:violatingactor123",
    "list": "at://did:plc:user456/app.bsky.graph.list/3mwu...",
    "createdAt": "2026-10-01T20:05:00.000Z"
  }
  ```
* **Client Behavior**: When a user subscribes to an `app.bsky.graph.defs#modlist` and selects **"Block"** or **"Mute"**, the Bluesky AppView and official clients automatically suppress all content from members of that list across feeds, notifications, and search results.

### 2.2 Sovereign Data Sovereignty (Stateless Mode)
Unlike centralized Web2 moderation bots that require a database of user accounts, hashed passwords, and proprietary rule records:
1. **Rules as ATProto Records**: The user's moderation prompt and settings can be stored in their own PDS repository under a custom record collection (e.g. `social.skybouncer.config`) or embedded in the `app.bsky.graph.list` description metadata.
2. **Stateless Ingestion**: `skybouncer` resolves the user's config directly from the ATProto repository.
3. **Zero Data Custody**: If a user revokes OAuth access or stops using the bot, their modlist remains permanently in their own repository. No lock-in, no vendor dependency.

---

## 3. Product Architecture & System Topologies

```
                  ┌────────────────────────────────────────────────────────┐
                  │                    PUBLIC INTERNET                     │
                  │   - Any Bluesky User (@alice.bsky.social)              │
                  │   - Bluesky PDS Authorization Servers                  │
                  └──────────────────────────┬─────────────────────────────┘
                                             │ HTTPS
                                             ▼
                                  ┌────────────────────┐
                                  │  Cloudflare Edge   │
                                  │(SSL / DDoS Shield) │
                                  └──────────┬─────────┘
                                             │ Encrypted Tunnel
                                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                   DOCKER COMPOSE POD (skybouncer_net)                    │
│                                                                          │
│   ┌────────────────────┐   Isolated Network     ┌────────────────────┐   │
│   │    cloudflared     │ ─────────────────────> │     skybouncer     │   │
│   │ (Tunnels into host)│   http://skybouncer    │ (Port 3000, non-   │   │
│   └────────────────────┘      (internal)        │  root, read-only)  │   │
│                                                 └─────────┬──────────┘   │
│                                                           │              │
│       ┌───────────────────────────────────────────────────┼──────────┐   │
│       │ Subsystems within skybouncer:                     │          │   │
│       │  1. Multi-Tenant Registry (SQLite /data)          │          │   │
│       │  2. skyauth OAuth Gateway (/auth/login, /callback)│          │   │
│       │  3. Public @skybouncer.bot DM Onboarding & Comms  │          │   │
│       │  4. Global Jetstream Firehose (watches all DIDs)  │          │   │
│       │  5. Non-Followed Gate (per-tenant FollowGraph)    │          │   │
│       │  6. Multi-Tenant PDS Mutator (Alice's DPoP keys)  │          │   │
│       │                                                   ▼          │   │
│       │                                            Persistent Disk   │   │
│       └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
  NOTE: Completely isolated from sibling compose stacks (e.g. for-your-consideration)
        via independent Docker Compose bridge networking (`skybouncer_net`).
```

---

## 4. Key Functional Features

### 4.1 Ingestion & Target Matching
* **Jetstream Edge Filtering**: Connects to global Jetstream WebSocket firehoses using `skybase::ingest`, filtering for `app.bsky.feed.post` and `app.bsky.graph.follow` commit events.
* **Target Detection**: Rapidly inspects incoming posts to determine if they interact with a protected user:
  * **Direct Replies**: `record.reply.parent.uri` matching protected user's DID.
  * **Thread Infiltration**: `record.reply.root.uri` owned by protected user.
  * **Mentions**: Text facets containing `app.bsky.richtext.facet#mention` with protected user's DID.
  * **Quotes**: Embeds of type `app.bsky.embed.record` pointing to protected user's posts.
* **The Non-Followed Direct Interaction Gate (Cost Control Invariant)**:
  * **Core Invariant**: For strict cost control and false-positive prevention, an interaction is **ONLY** dispatched to the classifier if it is directed at the protected user **by an author the protected user DOES NOT follow**.
  * **Instant Short-Circuit ($0 Cost, $<1\mu s$ Latency)**: If `author_did == protected_user_did` OR `protected_user.follows(author_did)`, the post is immediately bypassed with zero external API calls.
  * **Follow-Graph Dynamic Synchronization**:
    * On initialization, `skybouncer` loads the protected user's active `app.bsky.graph.follow` records into a lock-free in-memory set (`HashSet<Did>` or bitset).
    * `skybase::ingest` continuously listens to commit events (`create` and `delete`) on the user's `app.bsky.graph.follow` collection, dynamically keeping the follow-graph bypass set up to date in real time without requiring restarts.
  * **Social Context Preservation**: Ensures friends, mutuals, and accounts the user actively chose to follow are never accidentally moderated or blocked due to playful, sarcastic, or edgy banter.


### 4.2 Pluggable Classification Engine
* **Trait-Based Classifier Interface**:
  ```rust
  #[async_trait]
  pub trait Classifier: Send + Sync {
      async fn evaluate(&self, ctx: &EvaluationContext) -> Result<Verdict, SkybouncerError>;
  }
  ```
* **Evaluation Context**:
  * Offending post text & embedded media facets.
  * Offending author DID, handle, bio/description, display name, account creation date.
  * Parent post context (what post they are replying to).
  * User-specified rule rubric and sensitivity threshold.
* **Classifier Implementations**:
  1. **`JevClassifier`**: Calls TypeSafe AI's Jev API for sub-50ms structured binary decision.
  2. **`LlmClassifier`**: Structured JSON schema prompt for Gemini, Claude, or local Ollama endpoints.
  3. **`HeuristicClassifier`**: Fast zero-cost regex matching for known spam phrases, malicious links, and bot signatures.
* **Confidence Gating**: Only issues mutations if the classifier confidence meets or exceeds the user-configured sensitivity threshold (e.g., $\ge 0.85$).

### 4.3 Sovereign PDS Mutations & Deduplication
* **List Provisioning**: Automatically detects or creates the user's dedicated `app.bsky.graph.list` with `purpose: "app.bsky.graph.defs#modlist"`.
* **Idempotent List Insertion**: Checks local embedded SQLite cache (`skybase::index`) to ensure `app.bsky.graph.listitem` is not created multiple times for the same offending DID.
* **DPoP-Signed Writes**: Mutations are cryptographically signed via `skybase::repo::PdsRepoClient` using the user's OAuth DPoP credentials or the service bot's session.
* **Undo & Unban**: Removing an item from the modlist via DM command or web UI immediately issues a `deleteRecord` mutation.

### 4.4 Interaction Modes

#### Mode 1: Public ATProto Chat / DM Bot (`chat.bsky.convo.*`)
* **Conversational Onboarding (For Any Bluesky User)**:
  * Any user on Bluesky can message `@skybouncer.bot`.
  * If the sender is **not yet enrolled**, the bot replies with an introduction and a 1-click authorization link (`https://skybouncer.example.com/auth`) to activate protection on their account.
* **Management Commands (For Enrolled Users)**:
  * `rules`: Display the user's active moderation rubric.
  * `set rules <text>`: Update the user's rule rubric and sync to their sovereign PDS.
  * `status`: Show user's protection state (Active/Paused), bounced account count, and modlist link.
  * `recent`: List the last 5 accounts added with violation category and snippet.
  * `pardon @handle` or `pardon <did>`: Remove an account from their personal moderation list on their PDS.
  * `pause` / `resume`: Temporarily disable or enable automated actions for their account.
  * `sensitivity <low|medium|high>`: Adjust the user's confidence threshold.

#### Mode 2: Sovereign Web Portal & OAuth 2.1 Gateway (`skyauth`)
* Public web service hosted at `https://skybouncer.example.com`.
* **ATProto OAuth 2.1 Login**: Users sign in with their Bluesky handle via `skyauth` (PKCE + DPoP), granting permission to manage their moderation list.
* **Live Sandbox & Simulator**: Test hypothetical posts or paste thread URLs to preview classifier decisions against their custom rubric.
* **Audit Dashboard**: Chronological timeline of evaluations, model confidence, and 1-click unban buttons.

### 4.5 Production Deployment & Docker Compose Network Isolation
* **Zero-Leakage Container Network Isolation**:
  * Runs in its own dedicated, user-defined Docker bridge network (`skybouncer_net`).
  * Sibling Docker Compose stacks (such as `for-your-consideration`) run in separate, isolated bridge networks. Containers in one stack cannot see, resolve, or communicate with containers in another stack.
* **Cloudflare Tunnel Edge Ingress**:
  * Companion `cloudflared` container mounts `~/.cloudflared` read-only and tunnels traffic from `https://skybouncer.example.com` directly into `http://skybouncer:3000` over `skybouncer_net`.
  * **Zero Inbound Router Ports**: No open ports on the firewall or host router; all traffic enters encrypted via Cloudflare's edge with automatic TLS termination and DDoS mitigation.
* **Port Conflict Prevention**:
  * Default host port mapping `PORT_BIND=3031` (bound to `127.0.0.1:3031:3000`), completely eliminating port collisions with `for-your-consideration` on `3030`.
* **Hardened Execution Environment**:
  * `#![forbid(unsafe_code)]` binary stripped and running as non-root user `appuser:appgroup` (UID 10001).
  * `read_only: true`, `security_opt: [no-new-privileges:true]`, `cap_drop: [ALL]`.

---

## 5. Non-Functional & Safety Requirements

### 5.1 Rust Safety & Quality Gates
Adhering to [`AGENTS.md`](AGENTS.md) and [`rust-best-practices`](https://github.com/mike10010100/rust-best-practices):
* `#![forbid(unsafe_code)]` in all crates and binaries.
* `#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, missing_docs, rust_2018_idioms)]`.
* Zero unwrap/panic in production paths; all errors mapped to strongly-typed `SkybouncerError`.
* Clock-warp safe time computations (`now.saturating_duration_since(earlier)`).
* Background tasks managed via `tokio::task::JoinSet` with `tokio_util::sync::CancellationToken`.

### 5.2 Anti-Denial-of-Wallet & Cost Safeguards
* **Tier 1: Non-Followed Pre-Filter ($0 Cost, $<1\mu s$)**: All interactions authored by accounts the user follows (or the user themselves) are dropped immediately before any network or model calls.
* **Tier 2: Deduplication & Evaluation Caching ($0 Cost, $<100\mu s$)**: Previously evaluated authors are cached in the embedded SQLite store (`skybase::index`) with a configurable TTL (e.g. 24 hours), avoiding redundant re-evaluations.
* **Tier 3: Heuristic Short-Circuit ($0 Cost, $<500\mu s$)**: Zero-cost heuristic pre-filters (e.g. obvious spam keyword patterns, known malicious domains, bot link structures) can trigger immediate list additions without external API calls.
* **Tier 4: Per-User Evaluation Rate Limits**: Hard ceiling on LLM/classifier evaluations per user per hour (e.g., max 100 external model evaluations/hour) to prevent malicious actors from triggering expensive model calls by spam-mentioning a protected user.


---

## 6. Implementation Milestones

| Milestone | Deliverables | Status |
| :--- | :--- | :--- |
| **M1: Core Domain & Classifier Engine** | `skybouncer` crate structure, typed `SkybouncerError`, `Classifier` trait, `JevClassifier` client, `MockClassifier` for hermetic testing, `RuleRubric` parser. | ✅ **Completed & Published (`v0.1.0`)** |
| **M2: Jetstream Ingestion & Target Matching** | Integration with `skybase::ingest`, reply/mention/quote detector, deduplication cache in embedded SQLite (`skybase::index`). | ✅ **Completed & Published (`v0.1.0`)** |
| **M3: Mod List Provisioning & PDS Mutations** | Integration with `skybase::repo`, `app.bsky.graph.list` creation, `app.bsky.graph.listitem` upsert and pardon mutations with DPoP signing. | ✅ **Completed & Published (`v0.1.0`)** |
| **M4: ATProto DM Bot Interface** | ATProto Chat client (`chat.bsky.convo.*`), conversational command parser (`rules`, `recent`, `pardon`, `sensitivity`), automated DM alert dispatcher. | ✅ **Completed & Published (`v0.1.0`)** |
| **M5: Web Dashboard & Automated Release** | Minimal Web UI with `skyauth` OAuth login, dry-run simulator, 100% test coverage, GitHub Actions automated crates.io publish & release pipeline. | ✅ **Completed & Published (`v0.1.0`)** |
| **M6: Multi-Tenant Hosted Service & Onboarding** | SQLite `TenantRegistry` managing dynamic multi-user DPoP sessions, public bot conversational onboarding flow for unenrolled users, and production Docker Compose with Cloudflare Tunnel isolation. | ✅ **Completed & Published (`v0.1.2`)** |
| **M7: Scoped Bounces & Offending Post Transparency** | Per-user scoped bounce feeds, offending post URI & text tracking, direct Bluesky post inspection links, and schema migration stabilization. | ✅ **Completed & Published (`v0.1.3`)** |
| **M8: Persistent OAuth Token Auto-Refresh** | Background PDS operation token refresh with single-flight deduplication, SQLite token persistence across restarts, and early dashboard activation. | ✅ **Completed & Published (`v0.1.4` / `v0.1.5`)** |
| **M9: Tier 1 & Tier 2 Evaluation Audit Log** | Persistent SQLite evaluation audit logging, granular telemetry breakdown, retention management, and admin oversight view. | ✅ **Completed & Published (`v0.1.5`)** |
| **M10: Web & Auth Layer Security Hardening** | 256-bit CSPRNG web session tokens, admin privilege verification, SSRF blocking, DOM XSS prevention, security headers, scoped DM bot privacy, and rate limiter memory eviction. | ✅ **Completed & Published (`v0.1.6`)** |

---

## 7. System Hardening & Quality of Life Roadmap

### 7.1 Moderation Accuracy & Safety QoL (Future)
1. **Moderation Allowlist & False-Positive Immunization ("Pardon & Whitelist")**:
   - **Problem**: Pardoning an account currently removes them from the blocklist, but if they reply again in the future, the Non-Followed Gate treats them as an unfollowed candidate and re-evaluates them, risking repeated false positives.
   - **Solution**: Introduce a persistent `allowlist` in SQLite and add a "Pardon & Whitelist" action on the web dashboard and DM bot. The Gate immediately bypasses (`Outcome::Bypassed`) allowlisted DIDs without model calls.
2. **Temporary "Time-Out" / Cooldown Bounces (TTL Bouncing)**:
   - Configurable bounce durations: Permanent, 24-Hour Cooldown, 7-Day Timeout, 30-Day Timeout.
   - Automated background scheduler periodically prunes expired temporary `listitem` records from the user's sovereign PDS repository.
3. **Tenant-Scoped Evaluation Audit Log (User View)**:
   - Provide a tenant-scoped endpoint `GET /api/evaluations` where `target_did == caller_did`.
   - Regular users who sign in via OAuth can view evaluations performed on interactions targeting their own posts.

### 7.3 UX & Observability Polish (M10)
5. **Dashboard Rubric Presets & Bounced Search**:
   - Quick-select rubric templates in the Web Rules Editor (e.g. *Balanced Defense*, *Zero Crypto / Airdrop Spam*, *Anti-Hostility / Harassment*, *Anti-Ragebait / Sealioning*).
   - Search bar and filtering on the Recently Bounced dashboard table by handle, DID, or offending post keyword.
6. **Production Observability & Webhook Notifications**:
   - Native Prometheus `/metrics` endpoint exposing event ingestion rates, evaluation latency, bounce counts, and error metrics.
   - Discord/Slack webhook notifications alerting moderators when an account is bounced with direct link to the offending post.

---

## 8. Disambiguation & Namespace Verification

* **Crate Name**: `skybouncer`
* **Crates.io Status**: ✅ **Published & Active** ([`skybouncer 0.1.0`](https://crates.io/api/v1/crates/skybouncer/0.1.0) and [`skybase 0.1.0`](https://crates.io/api/v1/crates/skybase/0.1.0) are live on crates.io).
* **Bluesky Handle Status**: Verified completely free (`@skybouncer` and `@skybouncer.bsky.social` have 0 users).
* **Prior Art Disambiguation**:
  * Distinct from `@skysentry.bsky.social` (an existing manual blocklist curator).
  * Distinct from `@skyshield-filter.bsky.social` (an existing political content filter).
  * Seamlessly harmonizes with sibling projects [`skyauth`] and [`skybase`].
