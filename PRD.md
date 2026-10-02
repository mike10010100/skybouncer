# 📄 Product Requirements Document (PRD)

# `skybouncer`
### Sovereign, Rule-Driven Auto-Moderation & Bouncer Service for AT Protocol and Bluesky

---

## ⚡ Executive 1-Pager (The TL;DR)

| Dimension | Specification |
| :--- | :--- |
| **Product** | `skybouncer`: A sovereign, rule-driven automated moderation service and bouncer for Bluesky and the AT Protocol (ATProto). |
| **The Core Problem** | Social spam, bad-faith sea-lioning, crypto airdrop bots, and targeted harassment degrade conversations on Bluesky. Existing solutions require tedious manual muting/blocking, crude static keyword filters, or blanket third-party blocklists that lack personal nuance and context. |
| **The Solution** | `skybouncer` allows users to define natural-language moderation rules (e.g., *"Block crypto scam bots, harassment, and aggressive sea-lioning"*). An interaction watcher monitors incoming mentions, replies, and quotes directed at protected users via the Jetstream firehose, evaluates interactions using low-latency System-1 classifiers (**Jev** / lightweight LLMs), and automatically appends offending accounts to an ATProto Moderation List (`app.bsky.graph.listitem`). The user subscribes to their own list, natively muting or blocking violators across the entire Bluesky network. |
| **Dual UX Topologies** | **1. DM Bot Interface (`chat.bsky.convo.*`)**: Website-free interaction. Users direct-message `@skybouncer.bsky.social` to configure rules, view recent actions, or toggle aggressive vs. permissive modes.<br/>**2. Sovereign Web Dashboard (`skyauth`)**: Web UI powered by ATProto OAuth 2.0 with PKCE and DPoP cryptographic proofs, featuring a live rule playground and audit stream. |
| **The Stateless Invariant** | Moderation rules and lists can be published directly to the user's sovereign repository on their PDS (e.g., as custom ATProto records or encoded list metadata). The service can operate in a **completely stateless, zero-custody mode**—holding zero user databases or persistent credentials. |
| **Underlying Engine** | Built in 100% Safe Rust (`#![forbid(unsafe_code)]`), powered directly by sibling workspace crates [`skybase`] (Jetstream ingestion, SQLite caching, DPoP PDS write client) and [`skyauth`] (OAuth 2.0 PKCE + DPoP session lifecycle). |

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
                             USER INTERFACES
      ┌─────────────────────────────────────────────────────────────┐
      │  Topology A: ATProto DM Bot       Topology B: Web Dashboard │
      │  (chat.bsky.convo via XRPC)       (skyauth OAuth 2.0 DPoP)  │
      └──────────────────────────────┬──────────────────────────────┘
                                     │ User Rules & Target List
                                     ▼
                         ┌───────────────────────┐
                         │   Rule & User Store   │
                         │ (Stateless or SQLite) │
                         └───────────┬───────────┘
                                     │ Active Watch Targets
                                     ▼
┌─────────────────────────┐      ┌───────────────────────────────┐
│ Global Jetstream Stream │ ───► │   Interaction Watcher         │
│ (skybase::ingest)       │      │   - Mentions (facets)         │
└─────────────────────────┘      │   - Replies (reply.parent)    │
                                 │   - Quotes (embed)            │
                                 └───────────────┬───────────────┘
                                                 │ Candidate Interaction
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │   Context Enricher & Cache    │
                                 │   - Embedded SQLite check     │
                                 │   - Author bio & recent post  │
                                 └───────────────┬───────────────┘
                                                 │ Enriched Payload
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │   Evaluation Engine           │
                                 │   - Fast Heuristics / DenyList│
                                 │   - Jev Classifier (System 1) │
                                 │   - LLM Classifier (Fallback) │
                                 └───────────────┬───────────────┘
                                                 │ Verdict: VIOLATION
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │   Sovereign List Mutator      │
                                 │   (skybase::repo::PdsClient)  │
                                 │   Writes app.bsky.graph.listitem│
                                 └───────────────┬───────────────┘
                                                 │
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │   Audit & User Notification   │
                                 │   (DM alert / Webhook / Log)  │
                                 └───────────────────────────────┘
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

#### Mode 1: ATProto Chat / DM Bot (`chat.bsky.convo.*`)
* **Commands**:
  * `rules`: Display current active moderation rules.
  * `set rules <text>`: Update rule rubric.
  * `status`: Show list subscriber status, total accounts bounced, and uptime.
  * `recent`: List the last 5 accounts added with reason and post snippet.
  * `pardon @handle`: Remove an account from the moderation list.
  * `pause` / `resume`: Temporarily disable or enable automated actions.
  * `sensitivity <low|medium|high>`: Adjust confidence threshold.

#### Mode 2: Sovereign Web Dashboard (OAuth via `skyauth`)
* Single-page web application served locally or hosted.
* **Live Sandbox / Simulator**: Paste a post URL or handle to simulate how current rules would evaluate it.
* **Audit Timeline**: View chronological feed of bounced accounts, post snippets, classifier reasoning, and one-click pardon buttons.

---

## 5. Non-Functional & Safety Requirements

### 5.1 Rust Safety & Quality Gates
Adhering to [`AGENTS.md`](AGENTS.md) and [`rust-best-practices`](/Users/mike10010100/git/rust-best-practices):
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
| **M1: Core Domain & Classifier Engine** | `skybouncer` crate structure, typed `SkybouncerError`, `Classifier` trait, `JevClassifier` client, `MockClassifier` for hermetic testing, `RuleRubric` parser. | ✅ **Completed** |
| **M2: Jetstream Ingestion & Target Matching** | Integration with `skybase::ingest`, reply/mention/quote detector, deduplication cache in embedded SQLite (`skybase::index`). | ✅ **Completed** |
| **M3: Mod List Provisioning & PDS Mutations** | Integration with `skybase::repo`, `app.bsky.graph.list` creation, `app.bsky.graph.listitem` upsert and pardon mutations with DPoP signing. | ✅ **Completed** |
| **M4: ATProto DM Bot Interface** | ATProto Chat client (`chat.bsky.convo.*`), conversational command parser (`rules`, `recent`, `pardon`, `sensitivity`), automated DM alert dispatcher. | ✅ **Completed** |
| **M5: Web Dashboard & Verification Suite** | Minimal Web UI with `skyauth` OAuth login, dry-run simulator, 100% test coverage, clippy/fmt/deny compliance. | ✅ **Completed** |

---

## 7. Disambiguation & Namespace Verification

* **Crate Name**: `skybouncer`
* **Crates.io Status**: Verified available (0 registered crates as of Oct 2026).
* **Bluesky Handle Status**: Verified completely free (`@skybouncer` and `@skybouncer.bsky.social` have 0 users).
* **Prior Art Disambiguation**:
  * Distinct from `@skysentry.bsky.social` (an existing manual blocklist curator).
  * Distinct from `@skyshield-filter.bsky.social` (an existing political content filter).
  * Seamlessly harmonizes with sibling projects [`skyauth`] and [`skybase`].
