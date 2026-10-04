# Skybouncer ATProto Moderation Service: Comprehensive Ontology Review & Type System Invariants

**Document Version:** 1.0.0 (Publication-Grade Audit)  
**Target Repository:** `skybouncer v0.1.12`  
**Reference Standards:** `AGENTS.md`, `PRD.md`, `rust-best-practices`, ATProto Specifications (`atproto.com/specs/lexicon`, `atproto.com/specs/repository`)  
**Workspace Root:** `/Users/mike10010100/git/atproto-experiments/skybouncer`  
**Crate Safety Guard:** `#![forbid(unsafe_code)]`, zero production panics, strongly-typed errors  

---

## Executive Summary

`skybouncer` is an autonomous, rule-driven moderation service and public bouncer engineered for the AT Protocol (ATProto) and the Bluesky social network. Unlike centralized Web2 moderation architectures that maintain proprietary user databases and opaque blocklists, Skybouncer operates on a **sovereign, multi-tenant paradigm**: moderation rules and moderation list memberships are published directly to each enrolled user's Personal Data Server (PDS) repository as native ATProto records (`app.bsky.graph.list`, `app.bsky.graph.listitem`, and `social.skybouncer.config`). The local service acts as a low-latency, cache-accelerated stream evaluator, firehose filter, and cryptographic mutation agent.

This document delivers a definitive ontology audit across five foundational dimensions:
1. **Domain Ontology Catalog (§1)**: An exhaustive mapping of all root aggregates, entities, value objects, lifetimes, concurrency primitives, and the SQLite 9-table persistence schema (7 in `DeduplicationCache`, 2 in `TenantRegistry`).
2. **ATProto Lexicon Alignment Matrix (§2)**: A field-by-field protocol fidelity audit evaluating internal Rust structs against official Lexicons (`app.bsky.graph.*`, `chat.bsky.convo.*`, `com.atproto.repo.*`, and sovereign collections), highlighting protocol gaps such as the chat union deserialization risk.
3. **State Machine Lifecycles & Invariant Enforcement (§3)**: Six detailed Mermaid state machine specifications covering ingestion, gating, detection, PDS mutations, firehose sync, and OAuth sessions, coupled with an audit of race conditions, drift edge cases, and illegal states.
4. **Identity & Tenant Ontology Analysis (§4)**: An investigation of DID vs handle boundaries, AES-256-GCM encryption with DID as Additional Authenticated Data (AAD), sovereign PDS isolation, and multi-tenant memory structures.
5. **Type Redesign Proposals (§5)**: Four production-grade Rust redesigns implementing validated protocol newtypes (`AtDid`, `AtUri`, `RecordKey`), pipeline typestates (`Interaction<Stage>`), an explicit multi-tenant lifecycle finite-state machine (`SovereignTenant`), and a structured error hierarchy (`SkybouncerError`) bounded by strict zero-panic invariants.

---

## 1. Comprehensive Entity-Relationship Catalog (R1)

### 1.1 Architecture & Domain Topology

The Skybouncer domain ontology separates high-volume stream ingestion from asynchronous classifier inference and sovereign PDS repository mutations. The root aggregate `SkybouncerEngine` orchestrates sub-aggregates managing social graph caches, rate limits, multi-tenant credentials, and SQLite persistence.

```
                    ┌────────────────────────────────────────────────────────┐
                    │                   SkybouncerEngine                     │
                    │               (Root Coordinator Aggregate)             │
                    └───────────┬────────────────────────────┬───────────────┘
                                │                            │
                  1:1           │                            │ 1:1
                                ▼                            ▼
                  ┌───────────────────────────┐┌───────────────────────────┐
                  │       TenantRegistry      ││      ModListManager       │
                  │   (Multi-Tenant Aggregate)││  (Sovereign PDS Mutator)  │
                  └─────────────┬─────────────┘└─────────────┬─────────────┘
                                │ 1:N                        │
                                ▼                            ▼ 1:1
                  ┌───────────────────────────┐┌───────────────────────────┐
                  │          Tenant           ││    DeduplicationCache     │
                  │  (Enrollment & DPoP Keys) ││ (SQLite Embedded Engine)  │
                  └─────────────┬─────────────┘└─────────────┬─────────────┘
                                │                            │
                 1:1 (optional) │               1:N          │
                                ▼              ┌─────────────┴─────────────┐
                  ┌───────────────────────────┐│                           │
                  │        OAuthSession       │▼                           ▼
                  │    (Cryptographic DPoP)   │ BouncedUser           AllowlistEntry
                  └───────────────────────────┘(SQLite Table)        (SQLite Table)
```

---

### 1.2 Root Aggregates & System Boundaries

#### 1. `SkybouncerEngine` (`src/engine.rs:880`)
* **Role**: Root system coordinator aggregate. Drives the Jetstream event consumer, follow-graph synchronization, the non-followed direct interaction gate, classifier routing, and sovereign PDS list mutations.
* **Fields & Ownership**:
  * `config: SkybouncerConfig` — Immutable engine configuration parameters (network endpoints, limits, operational flags).
  * `protected_dids: Arc<RwLock<HashSet<String>>>` — Shared in-memory watch-set of protected user DIDs actively monitored on the firehose.
  * `rubric: Arc<RwLock<RuleRubric>>` — Fleet-wide default moderation rubric and sensitivity threshold.
  * `follow_graph: Arc<FollowGraph>` — Dynamic in-memory follow graph synchronized in real-time with Jetstream commit events.
  * `gate: Arc<NonFollowedGate>` — Sub-microsecond cost-control filter evaluating interaction authors against follow-graph and allowlist caches.
  * `heuristic_classifier: HeuristicClassifier` — Zero-cost compiled regex pre-filter for instantaneous detection of spam and scam patterns.
  * `classifier: Arc<dyn Classifier>` — Pluggable semantic classifier trait object (defaults to `TieredClassifier` wrapping `JevClassifier` and local fallback).
  * `modlist_manager: Arc<ModListManager>` — Sovereign PDS list provisioning, violator bouncing, and pardoning orchestrator.
  * `cache: Arc<DeduplicationCache>` — Embedded SQLite deduplication engine and evaluation TTL cache.
  * `tenant_registry: Arc<TenantRegistry>` — Multi-tenant registry managing DPoP sessions and per-tenant PDS repository clients.
  * `pds_client: Arc<PdsRepoClient>` — Default administrative PDS repository client used for bot interactions and single-tenant deployments.
  * `rate_limiter: Arc<EvaluationRateLimiter>` — Sharded sliding-window rate limiter enforcing per-user model evaluation ceilings (Tier 4 Anti-Denial-of-Wallet).
  * `enricher: Arc<dyn ContextEnricher>` — Trait object enriching candidate interactions with author profiles and parent thread context via the Bluesky AppView.
  * `stats: Arc<EngineStats>` — Lock-free atomic operational telemetry counters (`AtomicU64`).
  * `paused: Arc<AtomicBool>` — Global engine execution pause flag.
  * `bounce_notifier: broadcast::Sender<BounceNotification>` — Bounded broadcast channel emitting real-time notifications on successful PDS list mutations.
  * `oauth_client: Arc<RwLock<Option<Arc<AtprotoOAuthClient>>>>` — OAuth 2.1 gateway handle for automatic background token refreshes.
* **Memory Lifetime**: `'static` via `Arc` wrapping across asynchronous Tokio tasks.
* **Concurrency Semantics**: Employs `parking_lot::RwLock` for fast synchronous read paths. Guards are strictly dropped before encountering asynchronous `.await` points to prevent deadlocks.

#### 2. `TenantRegistry` (`src/tenant/registry.rs:91`)
* **Role**: Multi-tenant state and session aggregate root. Manages tenant persistence in SQLite, AES-256-GCM token encryption, and single-flight token refreshing.
* **Fields & Ownership**:
  * `conn: Arc<Mutex<rusqlite::Connection>>` — Mutex-guarded SQLite connection configured with Write-Ahead Logging (WAL).
  * `pds_clients: Arc<RwLock<HashMap<String, Arc<PdsRepoClient>>>>` — Sharded cache of active, authenticated PDS repository clients indexed by tenant DID.
  * `oauth_client: Arc<RwLock<Option<Arc<AtprotoOAuthClient>>>>` — Optional handle to the OAuth gateway client.
  * `cipher: SessionCipher` — Authenticated AES-256-GCM cipher encrypting OAuth sessions at rest with tenant DID as Additional Authenticated Data (AAD).
  * `refresh_locks: Arc<StripedAsyncLocks>` — 64-shard striped async mutex pool serializing single-flight token refreshes per tenant DID.
* **Memory Lifetime**: `'static` (Arc-managed).

#### 3. `ModListManager` (`src/modlist/manager.rs:83`)
* **Role**: Sovereign moderation list lifecycle and mutation aggregate. Manages cache-first list provisioning, violator bouncing, and pardons across the PDS and SQLite cache.
* **Fields & Ownership**:
  * `cache: Arc<DeduplicationCache>` — Local deduplication and configuration cache handle.
  * `rubric: Arc<RwLock<Option<RuleRubric>>>` — Tenant-overridable evaluation rubric.
  * `list_name: String` — Default provisioned list name (`"Skybouncer Moderation List"`).
  * `list_description: Option<String>` — Default provisioned list description template.
  * `list_provision_locks: Arc<StripedAsyncLocks>` — Sharded async locks serializing `app.bsky.graph.list` provisioning per protected DID.
  * `listblock_provision_locks: Arc<StripedAsyncLocks>` — Sharded async locks serializing `app.bsky.graph.listblock` provisioning per protected DID.
  * `bounce_locks: Arc<StripedAsyncLocks>` — Sharded async locks serializing `app.bsky.graph.listitem` mutations per composite key `(protected_did:candidate_did)`.
  * `dry_run: bool` — Flag indicating whether remote PDS network writes should be simulated (`"shadow_"` prefixing).
* **Cardinality**: 1 `ModListManager` manages $N$ protected tenants, each owning 1 moderation list and $M$ list items.

#### 4. `DeduplicationCache` (`src/modlist/cache.rs:200`)
* **Role**: Persistence aggregate wrapping the embedded SQLite database. Implements the 7-table cache schema (`mod_list_config`, `bounced_users`, `bounced_user_rkeys`, `evaluation_cache`, `listblock_cache`, `evaluation_log`, `allowlist`) with microsecond TTL evaluation caching, listblock state persistence, allowlist caching, and evaluation audit logs.
* **Fields & Ownership**:
  * `conn: Arc<Mutex<rusqlite::Connection>>` — Connection wrapped in synchronous `parking_lot::Mutex`.
* **Invariants**: Synchronous lock is acquired and released strictly inside method boundaries; never held across asynchronous `.await` points.

#### 5. `FollowGraph` (`src/matcher/follow_graph.rs:61`)
* **Role**: Dynamic graph aggregate maintaining active follow sets to enforce the Non-Followed Direct Interaction Gate ($<1\mu s$ latency, $0 cost).
* **Fields & Ownership**:
  * `inner: RwLock<FollowGraphInner>` wrapping:
    * `follows: HashMap<String, HashSet<String>>` — Direct index mapping `protected_did -> HashSet<followed_did>` for $O(1)$ containment checks.
    * `rkey_to_followed: HashMap<String, HashMap<String, String>>` — Reverse index mapping `protected_did -> (rkey -> followed_did)` required for $O(1)$ deletion reconciliation when Jetstream `CommitOperation::Delete` commits arrive without record payloads.
* **Cardinality**: 1 protected user to $N$ followed accounts; 1 protected user to $N$ follow record keys.

#### 6. `NonFollowedGate` (`src/matcher/gate.rs:95`)
* **Role**: Frontline cost-control and social context gate aggregate.
* **Fields & Ownership**:
  * `follow_graph: Arc<FollowGraph>` — Shared follow graph reference.
  * `allowlist: Arc<RwLock<HashMap<String, HashSet<String>>>>` — Fast in-memory cache of persistent allowlist entries (`protected_did -> HashSet<allowed_did>`).

#### 7. `BotCommandHandler` (`src/bot/handler.rs:22`)
* **Role**: Conversational command dispatcher for the Bluesky DM bot (`chat.bsky.convo.*`).
* **Fields & Ownership**:
  * `engine: Arc<SkybouncerEngine>` — Handle to root engine for rule updates, status queries, and manual pardons.
  * `bot_did: String` — DID of the bot service account.
  * `public_url: String` — Base public URL for generating 1-click OAuth onboarding links.
  *(Note: `ChatClient` is not a field of `BotCommandHandler`, but is caller-owned by runner tasks `run_bot_poller` [`src/bot/poller.rs:28`] and `run_bounce_alert_dispatcher` [`src/bot/dispatcher.rs:45`]).*
* **Memory Lifetime**: `'static` (Arc-managed).

---

### 1.3 Domain Entities, Value Objects & State Enums

#### 1. Core ATProto Records (`src/types.rs`)

| Type Name | Kind | Lexicon NSID | Primary Fields | Ownership / Lifetime | Cardinality / Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `StrongRef` (`:11`) | Value Object | `com.atproto.repo.strongRef` | `uri: String`, `cid: String` | Owned / Heap allocated | Canonical reference to any ATProto record. |
| `ReplyRef` (`:38`) | Value Object | `app.bsky.feed.post#replyRef` | `root: StrongRef`, `parent: StrongRef` | Owned / Heap allocated | 1:1 post thread ancestry reference. |
| `ByteSlice` (`:68`) | Value Object | `app.bsky.richtext.facet#byteSlice` | `byte_start: usize`, `byte_end: usize` | Copy / Stack allocated | UTF-8 byte boundary range for rich text facets. |
| `FacetFeature` (`:89`) | Value Object (Enum) | `app.bsky.richtext.facet#features` | `Mention { did }`, `Link { uri }`, `Tag { tag }`, `Unknown` | Owned (`$type` tagged) | Feature union inside rich text facets. |
| `Facet` (`:132`) | Value Object | `app.bsky.richtext.facet` | `index: ByteSlice`, `features: Vec<FacetFeature>` | Owned / Heap allocated | 1:N relationship with features within a byte slice. |
| `RecordEmbed` (`:162`) | Value Object | `app.bsky.embed.record` | `record_type: Option<String>`, `record: StrongRef` | Owned / Heap allocated | Quoted record embed container. |
| `RecordWithMediaEmbed` (`:183`) | Value Object | `app.bsky.embed.recordWithMedia` | `record_type: Option<String>`, `record: RecordEmbed`, `media: Option<Value>` | Owned / Heap allocated | Composite quote post with attached media. |
| `Embed` (`:209`) | Value Object (Enum) | `app.bsky.feed.post#embed` | `Record`, `RecordWithMedia(Box)`, `Images(Value)`, `External(Value)`, `Video(Value)`, `Unknown` | Owned (`$type` tagged) | Union of embedded attachments on post records. |
| `PostRecord` (`:318`) | Entity | `app.bsky.feed.post` | `record_type: Option<String>`, `text: String`, `reply: Option<ReplyRef>`, `facets: Option<Vec<Facet>>`, `embed: Option<Embed>`, `created_at: String`, `langs: Option<Vec<String>>`, `tags: Option<Vec<String>>` | Owned / Heap allocated | Complete deserialized model of a Bluesky post. |
| `FollowRecord` (`:401`) | Entity | `app.bsky.graph.follow` | `record_type: Option<String>`, `subject: String`, `created_at: String` | Owned / Heap allocated | Graph follow relationship record. |
| `ModListRecord` (`:426`) | Entity | `app.bsky.graph.list` | `record_type: Option<String>`, `purpose: String`, `name: String`, `description: Option<String>`, `description_facets: Option<Vec<Facet>>`, `avatar: Option<Value>`, `created_at: String` | Owned / Heap allocated | Moderation list container record in user repository. |
| `ListItemRecord` (`:495`) | Entity | `app.bsky.graph.listitem` | `record_type: Option<String>`, `subject: String`, `list: String`, `created_at: String` | Owned / Heap allocated | Individual membership record placing `subject` on `list`. |
| `ListBlockRecord` (`:527`) | Entity | `app.bsky.graph.listblock` | `record_type: Option<String>`, `subject: String`, `created_at: String` | Owned / Heap allocated | Auto-blocking subscription record pointing to list URI. |
| `RepoRecordItem<T>` (`:551`) | DTO / Value Object | `com.atproto.repo.listRecords#record` | `uri: String`, `cid: String`, `value: T` | Owned / Heap allocated | Generic committed record envelope returned by `com.atproto.repo.listRecords`. |
| `ListRecordsResponse<T>` (`:562`) | DTO | `com.atproto.repo.listRecords` | `records: Vec<RepoRecordItem<T>>`, `cursor: Option<String>` | Owned / Heap allocated | Generic paginated response payload from `com.atproto.repo.listRecords`. |

#### 2. Pipeline, Evaluation & Gating Models (`src/matcher/`, `src/classifier/`, `src/engine.rs`)

| Type Name | Kind | Module | Fields / Variants | Ownership / Lifetime | Role in Lifecycle |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `InteractionType` | Value Object (Enum) | `src/matcher/interaction.rs:9` | `DirectReply`, `ThreadReply`, `Mention`, `Quote` | Copy / Stack | Classifies the interaction vector detected by `TargetMatcher`. |
| `Interaction` | Entity / Value Object | `src/matcher/interaction.rs:41` | `post_uri`, `post_cid`, `author_did`, `target_did`, `text`, `interaction_type`, `parent_uri`, `root_uri`, `created_at_us`, `image_cids`, `image_alts`, `enriched_context` | Owned / Heap allocated | Normalized candidate interaction traversing the pipeline. |
| `BypassReason` | Value Object (Enum) | `src/matcher/gate.rs:17` | `SelfInteraction`, `FollowedAuthor`, `AllowlistedAuthor` | Copy / Stack | Explains why candidate was dropped at Non-Followed Gate. |
| `GateDecision` | State Machine Enum | `src/matcher/gate.rs:40` | `Candidate(Interaction)`, `Bypassed { reason, interaction }` | Owned | Outcome of gate evaluation before classification. |
| `Sensitivity` | Value Object (Enum) | `src/classifier/rubric.rs:12` | `Low` (0.90), `Medium` (0.75), `High` (0.60) | Copy / Stack | Governs minimum confidence threshold for moderation actions. |
| `BounceDuration` | Value Object (Enum) | `src/classifier/rubric.rs:86` | `Permanent`, `Cooldown24h`, `Timeout7d`, `Timeout30d`, `Custom(u64)` | Copy / Stack | Cooldown / timeout duration for moderation bounces. |
| `RuleRubric` | Value Object | `src/classifier/rubric.rs:291` | `prompt: String`, `sensitivity: Sensitivity`, `bounce_duration: BounceDuration` | Owned / Heap allocated | User's personalized moderation policy rubric. |
| `ViolationCategory` | Value Object (Enum) | `src/classifier/mod.rs:27` | `Spam`, `CryptoSpam`, `Harassment`, `SeaLioning`, `Phishing`, `HateSpeech`, `Custom(String)` | Owned | Taxonomic category of detected policy violation. |
| `Verdict` | State Machine Enum | `src/classifier/mod.rs:110` | `Violation { category, confidence, reason }`, `Permitted { reason, confidence }` | Owned | Decision produced by classifier engines. |
| `InteractionOutcome` | State Machine Enum | `src/engine.rs:598` | `Bypassed`, `AlreadyBounced`, `Permitted`, `Bounced`, `BelowThreshold`, `RateLimited`, `QueuedForEvaluation`, `QueueOverflow`, `Paused` | Owned | Terminal outcome of an interaction traversing the engine. |
| `BounceNotification` | Event Value Object | `src/engine.rs:690` | `target_did`, `violator_did`, `category`, `confidence`, `reason`, `post_uri`, `post_snippet` | Owned | Broadcast payload dispatched to alert workers and DM bot. |
| `SovereignConfigSyncEvent` | Event Enum | `src/engine.rs:779` | `Updated`, `ListMetadataUpdated`, `Deleted`, `Ignored` | Owned | Firehose synchronization outcome for sovereign rule changes. |
| `ProcessCommitResult` | State Machine Enum | `src/engine.rs:812` | `FollowSynced(FollowSyncEvent)`, `SovereignConfigSynced(SovereignConfigSyncEvent)`, `NoMatch`, `InteractionsProcessed(Vec<InteractionOutcome>)`, `Ignored` | Owned | High-level outcome of evaluating an incoming Jetstream commit. |

#### 3. Multi-Tenant, Identity & Cryptographic Models (`src/tenant/`, `src/crypto.rs`)

| Type Name | Kind | Module | Fields | Ownership / Lifetime | Cardinality / Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `Tenant` | Entity (Aggregate Root) | `src/tenant/registry.rs:26` | `did: String`, `handle: Option<String>`, `session: Option<OAuthSession>`, `rubric: Option<RuleRubric>`, `is_active: bool`, `created_at: u64`, `updated_at: u64` | Owned / Heap allocated | Represents an enrolled user. 1:1 with DID. |
| `SessionCipher` | Cryptographic Entity | `src/crypto.rs:30` | `key_bytes: [u8; 32]` | Owned / Stack allocated | Derives or holds AES-256-GCM storage key; enforces AAD binding. |
| `OAuthSession` | Entity | `skyauth::session::OAuthSession` | `sub: String`, `access_token: String`, `refresh_token: Option<String>`, `token_type: String`, `scope: Option<String>`, `expires_at: Option<SystemTime>`, `dpop_key: DPoPKey`, `pds_endpoint: Option<String>`, `auth_server_issuer: Option<String>`, `token_endpoint: Option<String>`, `created_at: SystemTime` | Owned / Zeroized on drop | Cryptographically bound DPoP session; zeroizes tokens on drop. |

#### 4. ATProto Chat / DM Bot Models (`src/bot/types.rs`)

| Type Name | Kind | Lexicon NSID | Fields | Ownership | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ConvoMember` (`:7`) | Value Object | `chat.bsky.convo.defs#convoMember` | `did: String`, `handle: Option<String>`, `display_name: Option<String>` | Owned | Participant in chat thread. |
| `MessageSender` (`:20`) | Value Object | `chat.bsky.convo.defs#messageViewSender` | `did: String` | Owned | Author of chat message. |
| `MessageView` (`:27`) | Entity | `chat.bsky.convo.defs#messageView` | `id: String`, `rev: String`, `text: String`, `sender: MessageSender`, `sent_at: String` | Owned | Received chat message. |
| `ConvoView` (`:44`) | Entity | `chat.bsky.convo.defs#convoView` | `id: String`, `rev: String`, `members: Vec<ConvoMember>`, `last_message: Option<MessageView>`, `unread_count: u64`, `status: Option<String>` | Owned | Full conversation view. |
| `ListConvosResponse` (`:66`) | DTO | `chat.bsky.convo.listConvos` | `convos: Vec<ConvoView>`, `cursor: Option<String>` | Owned | Paginated conversation list. |
| `ListConvoRequestsResponse` (`:77`) | DTO | `chat.bsky.convo.listConvoRequests` | `requests: Vec<ConvoView>`, `cursor: Option<String>` | Owned | Incoming message requests. |
| `AcceptConvoRequest` (`:88`) | DTO | `chat.bsky.convo.acceptConvo` | `convo_id: String` | Owned | Request body to accept DM. |
| `AcceptConvoResponse` (`:96`) | DTO | `chat.bsky.convo.acceptConvo` | `rev: Option<String>` | Owned | Acceptance response. |
| `GetMessagesResponse` (`:104`) | DTO | `chat.bsky.convo.getMessages` | `messages: Vec<MessageView>`, `cursor: Option<String>` | Owned | Message history payload. |
| `SendMessagePayload` (`:115`) | Value Object | `chat.bsky.convo.defs#messageInput` | `text: String` | Owned | Content of outgoing message. |
| `SendMessageRequest` (`:122`) | DTO | `chat.bsky.convo.sendMessage` | `convo_id: String`, `message: SendMessagePayload` | Owned | Request payload to send DM. |
| `UpdateReadRequest` (`:132`) | DTO | `chat.bsky.convo.updateRead` | `convo_id: String`, `message_id: String` | Owned | Acknowledges read state. |

---

### 1.4 Persistence & Cache Domain Models (SQLite 9-Table Schema across DeduplicationCache & TenantRegistry)

The embedded SQLite persistence layer (`src/modlist/cache.rs` and `src/tenant/registry.rs`) defines nine distinct relational tables partitioned across two persistence aggregates: seven tables in `DeduplicationCache` and two tables in `TenantRegistry`:

```
┌────────────────────────────────┐       ┌────────────────────────────────┐
│            tenants             │       │          web_sessions          │
├────────────────────────────────┤       ├────────────────────────────────┤
│ did: TEXT (PK)                 │       │ token: TEXT (PK)               │
│ handle: TEXT                   │       │ did: TEXT (INDEX)              │
│ session_json: TEXT (AES-256)   │       │ created_at: INTEGER            │
│ rubric_prompt: TEXT            │       │ expires_at: INTEGER (INDEX)    │
│ sensitivity: TEXT              │       └────────────────────────────────┘
│ bounce_duration: TEXT          │
│ is_active: INTEGER             │       ┌────────────────────────────────┐
│ created_at: INTEGER            │       │        mod_list_config         │
│ updated_at: INTEGER            │       ├────────────────────────────────┤
└───────────────┬────────────────┘       │ user_did: TEXT (PK)            │
                │                        │ list_uri: TEXT                 │
                │                        │ list_cid: TEXT                 │
                │                        │ created_at: INTEGER            │
                │                        └────────────────────────────────┘
                │                        ┌────────────────────────────────┐
                │                        │        listblock_cache         │
                │                        ├────────────────────────────────┤
                │                        │ user_did: TEXT (PK)            │
                │                        │ list_uri: TEXT                 │
                │                        │ blocked_at: INTEGER            │
                │                        └────────────────────────────────┘
                │
                ├────────────────────────────────┬───────────────────────────────┐
                ▼                                ▼                               ▼
┌────────────────────────────────┐┌────────────────────────────────┐┌────────────────────────────────┐
│         bounced_users          ││      bounced_user_rkeys        ││           allowlist            │
├────────────────────────────────┤├────────────────────────────────┤├────────────────────────────────┤
│ protected_did: TEXT (PK-1)     ││ listitem_rkey: TEXT (PK)       ││ protected_did: TEXT (PK-1)     │
│ subject_did: TEXT (PK-2)       ││ protected_did: TEXT            ││ subject_did: TEXT (PK-2)       │
│ listitem_uri: TEXT             ││ subject_did: TEXT              ││ reason: TEXT                   │
│ listitem_rkey: TEXT            ││ listitem_uri: TEXT             ││ created_at: INTEGER            │
│ listitem_cid: TEXT             ││ listitem_cid: TEXT             │└────────────────────────────────┘
│ category: TEXT                 ││ created_at: INTEGER            │
│ confidence: REAL               │└────────────────────────────────┘┌────────────────────────────────┐
│ reason: TEXT                   │                                  │        evaluation_cache        │
│ post_uri: TEXT                 │                                  ├────────────────────────────────┤
│ post_text: TEXT                │                                  │ cache_key: TEXT (PK)           │
│ bounced_at: INTEGER            │                                  │ author_did: TEXT               │
│ expires_at: INTEGER (Nullable) │                                  │ verdict_json: TEXT             │
└────────────────────────────────┘                                  │ evaluated_at: INTEGER          │
                                                                    │ expires_at: INTEGER            │
┌──────────────────────────────────────────────────────────────────┐└────────────────────────────────┘
│                          evaluation_log                          │
├──────────────────────────────────────────────────────────────────┤
│ id: INTEGER (PK AUTOINCREMENT)   │ timestamp_us: INTEGER         │
│ source: TEXT ('live'/'sim')      │ post_uri: TEXT                │
│ post_text: TEXT                  │ author_did: TEXT              │
│ author_handle: TEXT              │ target_did: TEXT              │
│ target_handle: TEXT              │ has_images: INTEGER           │
│ primary_model: TEXT              │ primary_action: TEXT          │
│ primary_confidence: REAL         │ primary_category: TEXT        │
│ primary_reason: TEXT             │ escalated: INTEGER            │
│ escalation_reason: TEXT          │ fallback_model: TEXT          │
│ fallback_action: TEXT            │ fallback_confidence: REAL     │
│ fallback_category: TEXT          │ fallback_reason: TEXT         │
│ final_action: TEXT               │ final_confidence: REAL        │
│ outcome: TEXT                    │                               │
└──────────────────────────────────────────────────────────────────┘
```

#### Detailed Table Specifications (9 Tables Across Persistence Layer):

##### A. `TenantRegistry` Tables (`src/tenant/registry.rs`)
1. **`tenants`** (`src/tenant/registry.rs:250`): Stores enrolled user records, encrypted OAuth sessions, and custom rubrics.
   * `did TEXT PRIMARY KEY`: Canonical ATProto DID.
   * `handle TEXT`: Normalized user handle (e.g. `alice.bsky.social`).
   * `session_json TEXT`: AES-256-GCM ciphertext envelope (`enc:v1:<base64>`) authenticated with `did` as AAD.
   * `rubric_prompt TEXT`, `sensitivity TEXT`, `bounce_duration TEXT`: Tenant-specific policy rubric overrides.
   * `is_active INTEGER DEFAULT 1`: Flag for pausing/resuming automated moderation.
   * `created_at INTEGER`, `updated_at INTEGER`: Microsecond epoch timestamps.
2. **`web_sessions`** (`src/tenant/registry.rs:268`): Dashboard user authentication sessions.
   * `token TEXT PRIMARY KEY`: 256-bit CSPRNG hex session token.
   * `did TEXT`: Associated tenant DID.
   * `created_at INTEGER`: Session creation timestamp.
   * `expires_at INTEGER`: Expiration timestamp pruned periodically by maintenance workers.

##### B. `DeduplicationCache` Tables (`src/modlist/cache.rs`)
3. **`mod_list_config`** (`src/modlist/cache.rs:285`): Local record of provisioned ATProto moderation list.
   * `user_did TEXT PRIMARY KEY`: Protected user owning the list.
   * `list_uri TEXT`, `list_cid TEXT`: Canonical AT-URI and CID of the `app.bsky.graph.list` record on the PDS.
   * `created_at INTEGER`: List creation timestamp.
4. **`bounced_users`** (`src/modlist/cache.rs:292`): Active moderation list memberships.
   * Composite Primary Key: `(protected_did, subject_did)`.
   * `listitem_uri TEXT`, `listitem_rkey TEXT`, `listitem_cid TEXT`: Pointers to committed PDS record.
   * `category TEXT`, `confidence REAL`, `reason TEXT`: Violation taxonomy and scoring.
   * `post_uri TEXT`, `post_text TEXT`: Offending interaction evidence.
   * `bounced_at INTEGER`: Microsecond timestamp of bounce.
   * `expires_at INTEGER`: Nullable microsecond expiration timestamp supporting TTL cooldowns (`M13`).
5. **`bounced_user_rkeys`** (`src/modlist/cache.rs:308`): Reverse index mapping `listitem_rkey` to violator and protected user.
   * `listitem_rkey TEXT PRIMARY KEY`: PDS record key (`rkey`). Enables comprehensive cleanup during unban/pardon operations to eliminate orphaned list items.
   * `protected_did TEXT`, `subject_did TEXT`, `listitem_uri TEXT`, `listitem_cid TEXT`, `created_at INTEGER`.
6. **`evaluation_cache`** (`src/modlist/cache.rs:317`): Short-circuit evaluation cache.
   * `cache_key TEXT PRIMARY KEY`: Format `{post_uri}:{target_did}`.
   * `author_did TEXT`: Interaction author DID.
   * `verdict_json TEXT`, `evaluated_at INTEGER`, `expires_at INTEGER`: Cached classifier decision with configurable TTL (default 24h).
7. **`listblock_cache`** (`src/modlist/cache.rs:325`): Caches active `app.bsky.graph.listblock` records for automated moderation list subscriptions.
   * `user_did TEXT PRIMARY KEY`: Protected user subscribing to the moderation list block.
   * `list_uri TEXT NOT NULL`: Canonical AT-URI of the blocked moderation list.
   * `blocked_at INTEGER NOT NULL`: Microsecond timestamp when the listblock record was created on the PDS.
   * *Role in Lifecycle*: Queried and populated by `ModListManager::ensure_list_blocked` (`cache.rs:613, 637`). Ensures idempotent listblock provisioning, prevents duplicate PDS record creation, and eliminates redundant remote XRPC queries on restart.
8. **`allowlist`** (`src/modlist/cache.rs:359`): Persistent moderation allowlist.
   * Composite Primary Key: `(protected_did, subject_did)`.
   * `reason TEXT`, `created_at INTEGER`: Audit justification.
   * Immunizes trusted accounts from automated moderation actions.
9. **`evaluation_log`** (`src/modlist/cache.rs:331`): Granular evaluation audit log capturing full Tier-1 / Tier-2 classification telemetry.
   * `id INTEGER PRIMARY KEY AUTOINCREMENT`: Monotonic sequence identifier.
   * Logs timestamp, source, post URI/text, author/target DIDs and handles, image flags, primary/fallback model outputs, confidence, categories, escalation rationale, and terminal outcome.

---

## 2. ATProto Lexicon Alignment & Protocol Fidelity Matrix (R2)

### 2.1 Repository Record Schemas

#### 1. `app.bsky.graph.list` vs `ModListRecord` (`src/types.rs:426`)
* **Official Lexicon**:
  * `$type`: Must be `"app.bsky.graph.list"`
  * `purpose`: Must be an `at-identifier` (e.g. `"app.bsky.graph.defs#modlist"`, `"app.bsky.graph.defs#curatelist"`, `"app.bsky.graph.defs#referencelist"`)
  * `name`: string (max 64 graphemes, max 640 bytes)
  * `description`: optional string (max 3000 graphemes, max 30000 bytes)
  * `descriptionFacets`: optional array of `app.bsky.richtext.facet`
  * `avatar`: optional blob reference (`image/png`, `image/jpeg`, max 1MB)
  * `labels`: optional `com.atproto.label.defs#selfLabels` union
  * `createdAt`: datetime string (RFC 3339)
* **Rust Struct Representation**:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct ModListRecord {
      #[serde(rename = "$type", default, skip_serializing_if = "Option::is_none")]
      pub record_type: Option<String>,
      pub purpose: String,
      pub name: String,
      pub description: Option<String>,
      pub description_facets: Option<Vec<Facet>>,
      pub avatar: Option<serde_json::Value>,
      pub created_at: String,
  }
  ```
* **Protocol Discrepancies**:
  * **Omission**: `labels` (`com.atproto.label.defs#selfLabels`) is completely omitted. If a user has pre-existing moderation self-labels on their list, deserialization silently ignores them, and updating the list record will drop existing self-labels.
  * **Type Loose**: `avatar` is typed as `Option<serde_json::Value>`. While functional for Serde passthrough, it does not validate ATProto blob structure (`$type: "blob"`, `ref: { "$link": CID }`, `mimeType`, `size`).
  * **Stringly Typed Purpose**: `purpose` is represented as raw `String` rather than a typed enum (`ListPurpose`). While `ModListRecord::is_modlist()` checks `self.purpose == "app.bsky.graph.defs#modlist"`, invalid purpose strings can be created at runtime.

#### 2. `app.bsky.graph.listitem` vs `ListItemRecord` (`src/types.rs:495`)
* **Official Lexicon**:
  * `$type`: Must be `"app.bsky.graph.listitem"`
  * `subject`: `at-identifier` (must be a valid DID)
  * `list`: `at-uri` (must be an AT-URI pointing to an `app.bsky.graph.list` record)
  * `createdAt`: datetime string (RFC 3339)
* **Rust Struct Representation**:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct ListItemRecord {
      #[serde(rename = "$type", default, skip_serializing_if = "Option::is_none")]
      pub record_type: Option<String>,
      pub subject: String,
      pub list: String,
      pub created_at: String,
  }
  ```
* **Protocol Discrepancies**:
  * **Wire Compatibility**: 100% field alignment with official schema. Correctly serializes and deserializes camelCase JSON for PDS writes.
  * **Type Safety Gap**: `subject` and `list` are raw `String`s rather than validated newtypes (`Did`, `AtUri`). Passing a malformed URI or handle instead of a DID will only fail downstream at PDS XRPC validation.

#### 3. `app.bsky.graph.listblock` vs `ListBlockRecord` (`src/types.rs:527`)
* **Official Lexicon**:
  * `$type`: Must be `"app.bsky.graph.listblock"`
  * `subject`: `at-uri` (must be an AT-URI pointing to an `app.bsky.graph.list` record)
  * `createdAt`: datetime string (RFC 3339)
* **Rust Struct Representation**:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct ListBlockRecord {
      #[serde(rename = "$type", default, skip_serializing_if = "Option::is_none")]
      pub record_type: Option<String>,
      pub subject: String,
      pub created_at: String,
  }
  ```
* **Protocol Discrepancies**:
  * **Wire Compatibility**: Exact 1:1 field alignment with official schema. Correctly establishes list-blocking subscriptions so the Bluesky AppView blocks all members of the list for the protected user.

#### 4. `app.bsky.feed.post` vs `PostRecord` (`src/types.rs:318`)
* **Official Lexicon**:
  * `$type`: Must be `"app.bsky.feed.post"`
  * `text`: string (max 300 graphemes, max 3000 bytes)
  * `reply`: optional `replyRef`
  * `facets`: optional array of `app.bsky.richtext.facet`
  * `embed`: optional union of `app.bsky.embed.images`, `app.bsky.embed.video`, `app.bsky.embed.external`, `app.bsky.embed.record`, `app.bsky.embed.recordWithMedia`
  * `langs`: optional array of language codes
  * `labels`: optional `com.atproto.label.defs#selfLabels`
  * `tags`: optional array of string tags (max 8 tags, max 640 chars)
  * `createdAt`: datetime string (RFC 3339)
* **Protocol Discrepancies**:
  * **Omission**: `labels` (`com.atproto.label.defs#selfLabels`) is omitted.
  * **Embed Union Precision**: In `Embed::RecordWithMedia`, `media` is parsed as `Option<serde_json::Value>` rather than a strongly typed `MediaEmbed` union. However, `Embed::extract_images()` safely navigates both direct `app.bsky.embed.images` and composite `app.bsky.embed.recordWithMedia` embeds to extract image CIDs and alt texts.

#### 5. `app.bsky.graph.follow` vs `FollowRecord` (`src/types.rs:401`)
* **Official Lexicon**:
  * `$type`: Must be `"app.bsky.graph.follow"`
  * `subject`: `at-identifier` (DID of followed user)
  * `createdAt`: datetime string (RFC 3339)
* **Protocol Discrepancies**:
  * Exactly matches official lexicon fields.

---

### 2.2 ATProto Chat Service Lexicons (`chat.bsky.convo.*`)

The ATProto DM bot interface (`src/bot/types.rs`, `src/bot/client.rs`) interacts with the Bluesky Chat service (`https://api.bsky.chat`).

#### 1. `chat.bsky.convo.defs#convoView` vs `ConvoView` (`src/bot/types.rs:44`)
* **Official Lexicon**:
  ```json
  {
    "id": "convoView",
    "type": "object",
    "required": ["id", "rev", "members", "muted", "unreadCount"],
    "properties": {
      "id": { "type": "string" },
      "rev": { "type": "string" },
      "members": { "type": "array", "items": { "type": "ref", "ref": "#convoMember" } },
      "lastMessage": { "type": "union", "refs": ["#messageView", "#deletedMessageView"] },
      "muted": { "type": "boolean" },
      "status": { "type": "string", "knownValues": ["request", "accepted"] },
      "unreadCount": { "type": "integer" }
    }
  }
  ```
* **Rust Struct Representation**:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  pub struct ConvoView {
      pub id: String,
      #[serde(default)]
      pub rev: String,
      #[serde(default)]
      pub members: Vec<ConvoMember>,
      #[serde(rename = "lastMessage", default)]
      pub last_message: Option<MessageView>,
      #[serde(rename = "unreadCount", default)]
      pub unread_count: u64,
      #[serde(default)]
      pub status: Option<String>,
  }
  ```
* **Protocol Discrepancies**:
  * **Omission**: `muted: bool` is missing from `ConvoView`.
  * **Critical Deserialization Risk (Deleted Messages)**: The official lexicon specifies `lastMessage` as a union: `["#messageView", "#deletedMessageView"]`. In `deletedMessageView`, the `text` field does not exist. Because Skybouncer's `ConvoView` types `last_message` strictly as `Option<MessageView>` (where `text: String` is required), if a user deletes the last message in a chat thread, **Serde deserialization of the conversation will fail with a missing field error**, breaking the polling worker for that conversation.

#### 2. `chat.bsky.convo.sendMessage` vs `SendMessageRequest` / `SendMessagePayload` (`src/bot/types.rs:115`)
* **Official Lexicon**:
  * `convoId`: string
  * `message`: object (`text`: string, optional `facets`: array, optional `embed`: union)
* **Rust Struct Representation**:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  pub struct SendMessagePayload {
      pub text: String,
  }
  ```
* **Protocol Discrepancies**:
  * **Missing Facet & Embed Support**: `SendMessagePayload` only supports plain `text`. Outgoing bot messages containing links (e.g. the 1-click onboarding URL `<https://skybouncer.mike10010100.com/auth>` or post URLs in bounce alerts) cannot include explicit `app.bsky.richtext.facet#link` rich-text facets. The bot relies entirely on Bluesky client frontends to auto-detect and hyperlink URLs.

#### 3. Proxying Header Requirement
* **Protocol Requirement**: When accessing chat endpoints through a PDS rather than directly through `api.bsky.chat`, ATProto requires the HTTP header `atproto-proxy: did:web:api.bsky.chat#bsky_chat`.
* **Implementation Fidelity**: `ChatClient::new` (`src/bot/client.rs:82`) correctly inspects `base_url`: if it does not contain `"api.bsky.chat"`, it automatically attaches `HeaderName::from_static("atproto-proxy")` with `HeaderValue::from_static("did:web:api.bsky.chat#bsky_chat")`.

---

### 2.3 Sovereign Repository Storage Schemas

Skybouncer implements two distinct mechanisms for sovereign configuration storage in a user's repository:

#### 1. Custom ATProto Collection: `social.skybouncer.config` (`src/modlist/sovereign_config.rs:14`)
* **Collection NSID**: `social.skybouncer.config`
* **Record Key (rkey)**: Fixed singleton key `"self"`
* **Record Schema**:
  ```json
  {
    "$type": "social.skybouncer.config",
    "rules": "Block crypto spam, phishing, and aggressive sea-lioning",
    "sensitivity": "medium",
    "bounceDuration": "permanent",
    "updatedAt": "2026-10-04T12:00:00.000Z"
  }
  ```
* **Protocol Fidelity & Invariants**:
  * **Idempotent Mutations**: Written via `pds_client.put_record("social.skybouncer.config", "self", ...)`.
  * **Schema Validation Bypass**: ATProto PDS instances reject unrecognized record types if validation is enforced. In `publish_sovereign_config` (`src/modlist/sovereign_config.rs:190`), the call specifies `validate: false` to allow storing custom service records on standard Bluesky PDS nodes without requiring custom Lexicon registration on the PDS.
  * **Firehose Interception**: The live streaming daemon (`src/stream.rs:47`) explicitly subscribes to `wantedCollections=social.skybouncer.config`. When a user updates their rules from any ATProto client, the engine intercepts the commit and hot-reloads the user's rubric in real time (`src/engine.rs:1023`).

#### 2. Embedded List Description Metadata (`src/modlist/sovereign_config.rs:83`)
* **Format**:
  `[skybouncer:{"rules":"...","sensitivity":"medium","bounce_duration":"permanent"}]`
* **Protocol Fidelity & Invariants**:
  * Encoded at the end of the `description` field in the user's standard `app.bsky.graph.list` record.
  * Ensures 100% interoperability even if a PDS strictly forbids custom record collections.
  * Intercepted via Jetstream `wantedCollections=app.bsky.graph.list` commit handler (`src/engine.rs:1031`).

---

### 2.4 Comprehensive Protocol Fidelity Matrix

| Schema / Lexicon | Struct / Type | Alignment Status | Identified Discrepancies | Impact Assessment |
| :--- | :--- | :---: | :--- | :--- |
| `app.bsky.graph.list` | `ModListRecord` | **High** | 1. Missing `labels`<br/>2. Untyped `avatar` (`Option<Value>`)<br/>3. `purpose` is raw `String` | Low operational impact; self-labels could be lost on list update. |
| `app.bsky.graph.listitem` | `ListItemRecord` | **High** | Fields are raw `String` rather than `Did` / `AtUri` newtypes | Functional; relies on runtime string validation. |
| `app.bsky.graph.listblock` | `ListBlockRecord` | **High** | Subject is raw `String` | Fully compatible on the wire. |
| `app.bsky.graph.follow` | `FollowRecord` | **Exact** | None | Exact field-for-field parity. |
| `app.bsky.feed.post` | `PostRecord` | **High** | Missing `labels`; `media` in composite embed is loose `Value` | Functional; media extraction handles both images and quotes. |
| `app.bsky.richtext.facet` | `Facet`, `ByteSlice` | **Exact** | UTF-8 byte slices properly modeled | Correct byte-level alignment with ATProto standards. |
| `com.atproto.repo.strongRef`| `StrongRef` | **Exact** | None | Exact match (`uri`, `cid`). |
| `chat.bsky.convo.defs#convoView` | `ConvoView` | **Medium** | 1. Missing `muted: bool`<br/>2. `last_message` lacks `#deletedMessageView` union | **High Risk**: Deleted last message can break conversation parsing. |
| `chat.bsky.convo.defs#convoMember` | `ConvoMember` | **High** | Missing `avatar` | Negligible impact. |
| `chat.bsky.convo.defs#messageView` | `MessageView` | **Medium** | Missing `facets` and `embed` | Incoming DMs containing attachments cannot be parsed. |
| `chat.bsky.convo.sendMessage` | `SendMessageRequest` | **Medium** | Payload lacks `facets` and `embed` | Outgoing bot DMs cannot include rich text links. |
| `social.skybouncer.config` | `SovereignConfigRecord` | **Exact** | Custom collection; requires `validate: false` on PDS | Fully compatible with unvalidated PDS storage. |
| `com.atproto.repo.listRecords` | `ListRecordsResponse<T>`, `RepoRecordItem<T>` | **Exact** | Generic payload envelope; optional cursor pagination | Exact match with repository record listing endpoint. |

---

## 3. State Machine Transitions & Invariant Enforcement (R3)

### 3.1 Jetstream Event Ingestion Pipeline

The ingestion engine (`src/stream.rs` and `src/engine.rs`) consumes JSON WebSocket events from the ATProto Jetstream firehose (`wss://jetstream*.firehose.us-east.opt-blue.net/subscribe`).

```mermaid
stateDiagram-v2
    [*] --> Disconnected

    Disconnected --> Connecting: connect() with last_cursor
    Connecting --> Connected: WebSocket handshake 101 OK
    Connecting --> BackoffWait: Handshake error / TCP drop

    Connected --> Ingesting: Stream open
    Ingesting --> FrameParse: Raw WS Text Frame
    Ingesting --> ReconnectWait: Stream closed / Ping timeout / Error

    FrameParse --> CommitFilter: Valid JSON Commit
    FrameParse --> Ingesting: Ping / Non-commit / Invalid JSON

    CommitFilter --> CursorCommit: Update cursor (time_us)
    CursorCommit --> FastPathGate: Evaluate Collection Type

    state FastPathGate {
        [*] --> CollectionCheck
        CollectionCheck --> FollowGraphSync: app.bsky.graph.follow
        CollectionCheck --> ConfigSync: social.skybouncer.config
        CollectionCheck --> ModListSync: app.bsky.graph.list / listitem
        CollectionCheck --> PostEvaluation: app.bsky.feed.post
        CollectionCheck --> Ignored: Other collections
    }

    PostEvaluation --> EvaluatorQueue: Bounded Channel (eval_tx: 256)
    EvaluatorQueue --> Ingesting: Enqueued successfully
    EvaluatorQueue --> QueueOverflow: Channel full (Capacity 256)
    QueueOverflow --> Ingesting: Drop post & increment overflow stats

    ReconnectWait --> BackoffWait: Rewind cursor by 5s (saturating_sub)
    BackoffWait --> Connecting: Exponential backoff + jitter elapsed
```

#### Detailed Ingestion Mechanics & Invariants:
1. **Cursor Tracking & Rewind Invariant**:
   - The Jetstream cursor tracks microsecond timestamps (`time_us`). On disconnect, `stream.rs:242` rewinds the stored cursor by 5,000,000 microseconds (5 seconds): `cursor.saturating_sub(5_000_000)`.
   - **Invariant**: Replaying up to 5 seconds of stream events ensures zero event loss across reconnections. Idempotency is strictly delegated to the evaluation and bounce deduplication caches in SQLite (`src/modlist/cache.rs`).
2. **Backpressure & Load Shedding**:
   - The ingestion loop pushes candidate posts into `eval_tx`, a bounded `tokio::sync::mpsc::channel(256)` (`src/engine.rs:434`).
   - If the evaluation queue worker is blocked (e.g., slow Tier-2 LLM inference or PDS API latency), `eval_tx.try_send()` fails.
   - **Invariant**: The engine deliberately drops posts via `InteractionOutcome::QueueOverflow` rather than blocking the WebSocket stream. This preserves firehose synchronization and prevents TCP socket buffer backpressure from causing Jetstream disconnects.

---

### 3.2 Rule Evaluation Waterfall

Rule evaluation follows an 8-tier waterfall architecture designed to minimize latency by short-circuiting benign interactions within nanoseconds before invoking expensive network-bound classifiers.

```mermaid
stateDiagram-v2
    [*] --> IngestedPost: Worker dequeues from eval_tx
    
    IngestedPost --> TargetMatcher: Target DID enrolled?
    TargetMatcher --> Dropped: Target not protected / enrolled
    
    TargetMatcher --> FollowGate: Fast-path follow check (<1µs)
    FollowGate --> Permitted_Follower: Author in follow_graph
    
    FollowGate --> AllowlistGate: Check allowlist (<1µs)
    AllowlistGate --> Permitted_Allowlisted: Author in allowlist
    
    AllowlistGate --> DedupCache: Check evaluation cache (<50µs)
    DedupCache --> CachedResult: Post URI + Target DID seen
    CachedResult --> Permitted_Cached: Cache verdict == Permitted
    CachedResult --> Bounced_Cached: Cache verdict == Violation
    
    DedupCache --> HeuristicPreFilter: Regex match (<500ns)
    HeuristicPreFilter --> DecisiveViolation: Instant hit (e.g. banned crypto patterns)
    
    HeuristicPreFilter --> ModelClassifier: System-1 / System-2 Inference
    ModelClassifier --> ModelVerdict: Verdict computed
    
    ModelVerdict --> CacheStore: Write verdict to SQLite eval cache
    CacheStore --> SensitivityGate: Compare confidence with rubric threshold
    
    SensitivityGate --> Permitted_BelowThreshold: confidence < threshold
    SensitivityGate --> SovereignBounce: confidence >= threshold
    
    SovereignBounce --> [*]
    Permitted_BelowThreshold --> [*]
    Permitted_Follower --> [*]
    Permitted_Allowlisted --> [*]
    Dropped --> [*]
```

#### Evaluation Waterfall Stages (`src/engine.rs:1418-1580`):
- **Tier 1 (Target Matcher)**: Validates if the post is a reply or mention targeting an enrolled protected DID.
- **Tier 2 (Follower Gate)**: Checks in-memory `FollowGraph` (`HashSet<String>`). If the author is followed by the target, returns `InteractionOutcome::Bypassed`.
- **Tier 3 (Allowlist Gate)**: Checks in-memory allowlist. If present, returns `InteractionOutcome::Bypassed`.
- **Tier 4 (Dedup & Evaluation Cache)**: Queries SQLite `evaluations` table for key `"{post_uri}:{target_did}"`. If present, returns cached outcome.
- **Tier 5 (Already Bounced Gate)**: Checks `cache.is_bounced_for(target_did, author_did)`. If already on the list, returns `InteractionOutcome::AlreadyBounced`.
- **Tier 6 (Heuristic Pre-filter)**: Evaluates regex patterns (`src/classifier/heuristic.rs`). If matched decisively, bypasses external model inference.
- **Tier 7 (Model Classification)**: Evaluates interaction text and image metadata via `TieredClassifier`.
- **Tier 8 (Rubric Sensitivity Gate & PDS Action)**: Reads tenant rubric from `tenant_registry`, evaluates `rubric.meets_threshold(&category, confidence)`, and executes bounce if met.

---

### 3.3 Violator Detection, Scoring & Escalation

Detection uses a two-tiered cognitive architecture (`TieredClassifier` in `src/classifier/tiered.rs`), coupling a fast System-1 classifier with a deeper System-2 multimodal model.

```mermaid
stateDiagram-v2
    [*] --> EvaluateCandidate: Candidate post received
    
    EvaluateCandidate --> System1_Jev: Tier-1 evaluation (HTTP / Jev API)
    
    System1_Jev --> ImageEscalationCheck: System-1 verdict produced
    
    state ImageEscalationCheck {
        [*] --> CheckDecisive
        CheckDecisive --> DecisiveViolation: Confidence >= 0.85
        CheckDecisive --> CheckImages: Confidence < 0.85
        CheckImages --> HasImages: Post has attached images
        CheckImages --> CheckBand: No images
        CheckBand --> Uncertain: 0.40 <= Confidence < 0.85
        CheckBand --> DecisivePermitted: Confidence < 0.40
    }
    
    DecisiveViolation --> Tier1_Return: Return Tier-1 Violation
    DecisivePermitted --> Tier1_Return: Return Tier-1 Permitted
    
    HasImages --> System2_Escalation: Escalate: Visual context required
    Uncertain --> System2_Escalation: Escalate: Low confidence band
    
    System2_Escalation --> System2_Ollama: Tier-2 evaluation (LLM/Multimodal)
    System2_Ollama --> Tier2_Return: Return Tier-2 Verdict
    
    System2_Ollama --> Tier1_Fallback: Tier-2 network/timeout error
    Tier1_Fallback --> Tier1_Return: Fallback to Tier-1 Verdict
    
    Tier1_Return --> [*]
    Tier2_Return --> [*]
```

#### Invariants & Escalation Rules:
1. **Decisive Violation Short-Circuit**:
   - If Tier-1 produces a `Verdict::Violation` with `confidence >= 0.85`, it is accepted immediately, even if the post contains image embeds (`tiered.rs:245-250`).
2. **Visual Escalation Invariant**:
   - If a post contains images (`interaction.has_images()`) and Tier-1 confidence is below `0.85`, the classifier *always* escalates to Tier-2 (`tiered.rs:252-257`).
3. **Uncertainty Band Invariant**:
   - For text-only posts, if Tier-1 confidence falls in the uncertainty band `[0.40, 0.85)`, the interaction is escalated to Tier-2.
4. **Resilient Degradation**:
   - If Tier-2 fails (timeout, network error, OOM), the system catches the error, increments `tier2_errors`, and degrades gracefully by returning the Tier-1 verdict (`tiered.rs:293-300`).

---

### 3.4 Mutator Actions & Moderation List Enforcement

When an actionable violation is confirmed, `ModListManager` (`src/modlist/manager.rs`) issues record mutations against the violator on the protected user's sovereign PDS repository.

```mermaid
stateDiagram-v2
    [*] --> ActionableViolation: Model verdict meets rubric threshold

    ActionableViolation --> AcquireShardLock: Acquire bounce_locks.shard_for(target, author)
    AcquireShardLock --> CheckExistingBounce: Query SQLite is_bounced_for(target, author)

    CheckExistingBounce --> AlreadyBounced: Exists in cache
    AlreadyBounced --> ReleaseLock: Return Ok(None)

    CheckExistingBounce --> CheckDryRun: Not in cache
    CheckDryRun --> DryRunComplete: dry_run == true (simulate)
    DryRunComplete --> RecordCache

    CheckDryRun --> PdsCreateRecord: dry_run == false
    PdsCreateRecord --> PdsSuccess: com.atproto.repo.createRecord (app.bsky.graph.listitem)
    PdsCreateRecord --> PdsFailure: PDS API error / HTTP 5xx / 401
    PdsFailure --> ReleaseLock: Return Err(SkybouncerError::Repo)

    PdsSuccess --> RecordCache: Insert bounced_users row in SQLite
    
    state RecordCache {
        [*] --> SQLiteInsert
        SQLiteInsert --> InsertOK: Transaction committed
        SQLiteInsert --> InsertFailed: SQLite disk / constraint error
        
        InsertFailed --> CompensatingDelete: Compensating delete on PDS
        CompensatingDelete --> DeleteSuccess: PDS deleteRecord succeeded
        CompensatingDelete --> DeleteFailed: PDS deleteRecord failed (Orphaned Record!)
    }

    InsertOK --> ReleaseLock: Return Ok(Some(uri))
    DeleteSuccess --> ReleaseLock: Return Err(cache_err)
    DeleteFailed --> ReleaseLock: Log error & Return Err(cache_err)

    ReleaseLock --> [*]
```

#### Compensating Deletion & Locking Invariants:
1. **Concurrency Sharding**:
   - Mutator actions are guarded by `StripedAsyncLocks` (`src/modlist/manager.rs:43`), partitioned across 64 shards using key `"{protected_did}:{candidate_did}"`.
   - **Invariant**: Two concurrent firehose posts from the same violator targeting the same user serialize at the lock shard, preventing duplicate PDS listitem creations and race conditions across async `.await` boundaries.
2. **Compensating Deletion Pipeline (`manager.rs:611-632`)**:
   - If PDS record creation succeeds but SQLite cache insertion fails, the system executes an immediate compensating deletion: `pds_client.delete_record("app.bsky.graph.listitem", &rkey)`.
   - **Failure Mode**: If compensating deletion also fails (e.g. network partition immediately following PDS write), the listitem remains orphaned on the user's sovereign PDS without an index in local SQLite.

#### The Pardon Lifecycle:
```mermaid
stateDiagram-v2
    [*] --> PardonRequested: User issues 'pardon <target>' via Bot or API
    
    PardonRequested --> AcquireShardLock: bounce_locks.shard_for(protected, subject)
    AcquireShardLock --> LookupRkeys: cache.get_all_bounced_rkeys_for(protected, subject)
    
    LookupRkeys --> NoRkeysFound: rkeys.is_empty()
    NoRkeysFound --> ReleaseLock: Return Ok(false) [Zero PDS Calls]
    
    LookupRkeys --> ForEachRkey: rkeys found (Vec<String>)
    
    state ForEachRkey {
        [*] --> DeletePdsRecord
        DeletePdsRecord --> DeleteNext: pds_client.delete_record(...) OK
        DeletePdsRecord --> PdsDeleteError: Network / Auth error
    }
    
    ForEachRkey --> PurgeCache: All records deleted from PDS
    PurgeCache --> CheckAllowlist: Was 'pardon and allow' requested?
    
    CheckAllowlist --> AllowlistInsert: Yes -> cache.add_allowlisted_user(...)
    CheckAllowlist --> Complete: No
    AllowlistInsert --> Complete
    
    Complete --> ReleaseLock: Return Ok(true)
    PdsDeleteError --> ReleaseLock: Return Err(SkybouncerError::Repo)
    ReleaseLock --> [*]
```

---

### 3.5 Moderation List & Sovereign Config Sync

The system synchronizes sovereign configuration records, moderation lists, and follow graphs by actively intercepting commits from the Jetstream firehose.

```mermaid
stateDiagram-v2
    [*] --> JetstreamCommit: Commit event received
    
    JetstreamCommit --> DispatchCollection
    
    state DispatchCollection {
        [*] --> CheckCollection
        CheckCollection --> HandleConfig: social.skybouncer.config
        CheckCollection --> HandleFollow: app.bsky.graph.follow
        CheckCollection --> HandleList: app.bsky.graph.list
    }
    
    state HandleConfig {
        [*] --> ConfigOpCheck
        ConfigOpCheck --> ConfigUpsert: Create | Update
        ConfigOpCheck --> ConfigDelete: Delete
        
        ConfigUpsert --> ParseRecord: Parse SovereignConfigRecord
        ParseRecord --> UpdateTenantRegistry: tenant_registry.update_rubric(did, rubric)
        UpdateTenantRegistry --> CheckAdminSingleTenant: Is admin or single-tenant?
        CheckAdminSingleTenant --> UpdateEngineRubric: Yes -> engine.set_rubric(rubric)
        CheckAdminSingleTenant --> ConfigDone: No
        UpdateEngineRubric --> ConfigDone
        
        ConfigDelete --> LogConfigDeleted: Logged & stat incremented
        LogConfigDeleted --> ConfigDone: ⚠️ Stale rubric NOT reset!
    }
    
    state HandleFollow {
        [*] --> FollowOpCheck
        FollowOpCheck --> FollowCreate: Create
        FollowOpCheck --> FollowDelete: Delete
        
        FollowCreate --> AddFollow: follow_graph.add_follow(did, rkey, subject)
        FollowDelete --> RemoveFollow: follow_graph.remove_follow(did, rkey)
    }

    ConfigDone --> [*]
    AddFollow --> [*]
    RemoveFollow --> [*]
```

---

### 3.6 Multi-Tenant Session Lifecycle

Skybouncer manages two distinct classes of sessions:
1. **PDS OAuth 2.1 Sessions**: Long-lived DPoP-bound OAuth sessions granting access to tenant repositories.
2. **Web Administrative Sessions**: Ephemeral browser sessions for configuration dashboards.

```mermaid
stateDiagram-v2
    [*] --> OAuthEnrollment: User initiates OAuth 2.1 PKCE Flow
    
    OAuthEnrollment --> TokenExchange: Exchange auth code with PDS
    TokenExchange --> EncryptSession: Encrypt session with AES-256-GCM (DID as AAD)
    EncryptSession --> StoreTenantSQLite: Insert into tenants table
    
    StoreTenantSQLite --> ActiveSession: Session Active
    
    state ActiveSession {
        [*] --> ClientRequested: Engine needs PdsRepoClient
        ClientRequested --> FastPathCache: Check pds_clients read cache
        
        FastPathCache --> ClientValid: Cached & expires_in > 60s
        ClientValid --> [*]: Return Arc<PdsRepoClient> (<50ns)
        
        FastPathCache --> RefreshNeeded: Expired or expiring within 60s
        RefreshNeeded --> AcquireRefreshLock: refresh_locks.shard_for(did).lock().await
        
        AcquireRefreshLock --> DoubleCheckCache: Re-verify cache under lock
        DoubleCheckCache --> ClientValid: Another thread refreshed
        DoubleCheckCache --> ExecuteOAuthRefresh: Session still needs refresh
        
        ExecuteOAuthRefresh --> PdsTokenRefresh: DPoP token refresh request to PDS
        PdsTokenRefresh --> RefreshSuccess: New access + refresh tokens
        PdsTokenRefresh --> RefreshFailure: 400 Bad Request / Token Revoked
        
        RefreshSuccess --> UpdateSQLiteSession: Encrypt & update session_json in SQLite
        UpdateSQLiteSession --> EvictOldPdsClient: Remove old client from pds_clients map
        EvictOldPdsClient --> ConstructPdsClient: Create new PdsRepoClient
        ConstructPdsClient --> CachePdsClient: Insert into pds_clients map
        
        RefreshFailure --> StaleFallback: ⚠️ Construct client with expired session!
    }

    CachePdsClient --> [*]
    StaleFallback --> [*]
```

---

### 3.7 Catalog of Illegal States, Race Conditions & Drift Edge Cases

| Subsystem | Failure Mode | Trigger Condition | Verbatim Code Reference | Impact Severity |
| :--- | :--- | :--- | :--- | :--- |
| **List Sync** | **Rubric Drift on Deletion** | Sovereign config record deleted on PDS (`CommitOperation::Delete`) | `src/engine.rs:2372-2384` | **HIGH**: The tenant's rubric in `tenant_registry` and `engine.rubric` is never reset to default. Deleted rules persist indefinitely. |
| **List Sync** | **Follow Graph Desynchronization** | Cold-start hydration using synthetic rkeys (`hydrate_N`) followed by Jetstream unfollow | `src/engine.rs:1827`, `src/matcher/follow_graph.rs:110` | **MEDIUM**: Jetstream delete commits transmit real ATProto TIDs. Because reverse index only contains `hydrate_N`, unfollows are ignored and accounts remain followed in memory. |
| **Classifier** | **Global Rubric Multi-Tenant Leak** | Candidate evaluation in `JevClassifier` during multi-tenant execution | `src/classifier/jev.rs:263`, `src/engine.rs:1522` | **HIGH**: All candidate posts are classified against the global default rubric in System-1, ignoring tenant-specific custom prompt rules during inference. |
| **Session** | **Stale Client Caching on Refresh Failure** | OAuth token refresh fails (network error, revoked credentials) | `src/tenant/registry.rs:900-915` | **MEDIUM**: Expired session is still wrapped into `PdsRepoClient` and cached, causing downstream API operations to fail with HTTP 401 instead of bubbling an auth error. |
| **Modlist** | **Permanent Orphan on Cache Loss** | User pardon requested after cache purge or external listitem addition | `src/modlist/manager.rs:667-677` | **MEDIUM**: `pardon_user` only deletes rkeys recorded in local SQLite. If cache was purged or modified externally, accounts cannot be pardoned via Skybouncer. |
| **Evaluation** | **In-Flight Rubric Mutation Race** | Sovereign config updated while candidate post is buffered in `eval_tx` | `src/engine.rs:1567-1697` | **LOW**: Post was queued when Rubric A was active, but evaluated against Rubric B at dequeue time. |
| **Identity** | **Handle Squatting via Stale Tenant Cache** | Enrolled tenant changes their handle on Bluesky | `src/engine.rs:2045-2047` | **MEDIUM**: `resolve_handle()` checks local SQLite before network resolution. Old handle permanently points to the previous tenant's DID. |

---

## 4. Identity & Tenant Ontology Analysis (R4)

### 4.1 Identity Boundaries: DIDs vs Handles

ATProto enforces a strict duality between decentralized identifiers (DIDs) and human-readable handles:
- **DIDs (`did:plc:*`, `did:web:*`)**: Cryptographically anchored, immutable identifiers.
- **Handles (`*.bsky.social`, custom domains)**: Mutable, rotatable pointers resolved via DNS TXT (`_atproto`) or HTTPS `.well-known/atproto-did`.

#### Threat Analysis & Implementation in Skybouncer:
1. **Primary Key Boundary**:
   - Skybouncer correctly models all primary keys, cache indices, and relationship graphs using DIDs (`author_did`, `target_did`, `subject_did`, `protected_did`).
   - SQLite tables `tenants`, `bounced_users`, `evaluation_cache`, and `web_sessions` strictly key on DID.
2. **Handle Resolution & Cache Stagnation Vulnerability (`src/engine.rs:2040-2075`)**:
   ```rust
   pub async fn resolve_handle(&self, handle: &str) -> Option<String> {
       let clean = handle.trim().trim_start_matches('@');
       if clean.starts_with("did:") {
           return Some(clean.to_string());
       }
       if let Ok(Some(tenant)) = self.tenant_registry.get_by_handle(clean) {
           return Some(tenant.did);
       }
       self.enricher.resolve_handle(clean).await
   }
   ```
   - **Vulnerability**: If Tenant A registers with handle `@alice.bsky.social` and later changes their handle to `@alice-new.bsky.social`, their old handle remains recorded in `tenants.handle`.
   - If User B claims `@alice.bsky.social`, any subsequent Skybouncer lookup (e.g. from the bot command `allow @alice.bsky.social` or web UI lookup) will resolve `@alice.bsky.social` to Tenant A's DID instead of User B.
   - **Remediation**: SQLite handle lookups must enforce a maximum cache TTL (e.g., 1 hour) or be verified against the network on handle change.

---

### 4.2 Tenant Credential & Session Isolation

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TRUST BOUNDARY HIERARCHY                        │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Ephemeral Web Browser Boundary                                      │
│    • Token: 256-bit CSPRNG (43-char URL-safe base64)                   │
│    • Storage: SHA-256 digest in SQLite (web_sessions)                  │
│    • Lifetime: 30 days                                                 │
├────────────────────────────────────────────────────────────────────────┤
│ 2. Atproto OAuth 2.1 & DPoP Boundary                                   │
│    • Secrets: Refresh Token, DPoP ES256 Private Key                    │
│    • Encryption at Rest: AES-256-GCM                                   │
│    • AAD Binding: Tenant DID (Associated Authenticated Data)           │
├────────────────────────────────────────────────────────────────────────┤
│ 3. Sovereign PDS Repository Boundary                                   │
│    • Storage: app.bsky.graph.listitem, social.skybouncer.config        │
│    • Authority: DPoP Access Token with com.atproto.repo:* scope        │
└────────────────────────────────────────────────────────────────────────┘
```

#### Cryptographic Isolation Guarantees (`src/tenant/cipher.rs`):
1. **Ciphertext Swapping Protection**:
   - OAuth sessions are encrypted via AES-256-GCM before writing to `tenants.session_json`.
   - When encrypting, the tenant's DID is supplied as **Additional Authenticated Data (AAD)**:
     `cipher.encrypt_with_aad(session_bytes, did.as_bytes())`.
   - **Security Guarantee**: An attacker with read/write access to the SQLite database cannot copy an encrypted session ciphertext from Tenant A into Tenant B's row. Any attempt to decrypt Tenant A's ciphertext under Tenant B's DID fails GCM authentication verification.
2. **Master Key Derivation**:
   - The cipher uses the environment variable `SKYBOUNCER_SESSION_ENCRYPTION_KEY`.
   - If omitted, it falls back to HKDF-SHA256 derivation over host attributes (hostname, OS user, machine-id). Production deployments must supply an explicit 32-byte hex key.

---

### 4.3 Multi-Tenant Isolation in Memory & Persistence

#### Evaluation Cache Isolation:
- **SQLite Key**: `evaluation_cache.cache_key` is formatted as `"{post_uri}:{target_did}"`.
- **Verdict**: A post violating Tenant A's rules is evaluated independently of Tenant B. If the same post is a mention targeting both Tenant A and Tenant B, it generates two separate cache rows and two independent verdicts.

#### The Global Rubric Leak in `JevClassifier`:
- **Architecture**: `JevClassifier` holds `rubric: Arc<RwLock<RuleRubric>>`.
- **The Defect**: The `Classifier` trait defines:
  ```rust
  async fn classify(&self, interaction: &Interaction) -> Result<Verdict, SkybouncerError>;
  ```
  The trait method takes only `&Interaction`, with no `RuleRubric` parameter!
- In `src/engine.rs:1522`, `self.classifier.classify_detailed_with_stats(&interaction, true)` executes the classification using the *engine-wide global rubric*.
- The tenant-specific rubric (`self.rubric_for(&target_did)`) is only evaluated in **Tier 8** (`act_on_verdict`), where it checks `meets_threshold(&category, confidence)`.
- **Impact**: If Tenant A configures a custom moderation prompt (e.g. banning mentions of specific topics), that prompt is **never seen** by the classifier. The classifier evaluates every post against the global default rules, and only uses Tenant A's sensitivity setting to filter the resulting confidence score.

#### Unscoped Query Leakage Risk:
- `DeduplicationCache` provides two methods:
  - `is_bounced_for(protected_did, subject_did)` -> Tenant-scoped (Safe)
  - `is_bounced(subject_did)` -> `SELECT 1 FROM bounced_users WHERE subject_did = ?1 LIMIT 1;` (Unscoped!)
- Both `Engine::is_bounced` (`src/engine.rs:1859`) and `ModListManager::is_bounced` (`src/modlist/manager.rs:750`) expose this unscoped check.
- **Risk**: While the core evaluation pipeline correctly uses `is_bounced_for`, calling `engine.is_bounced` from management tooling or future bot commands reports a user as bounced if *any* tenant has bounced them, leaking cross-tenant moderation status.

---

### 4.4 Sovereign PDS Storage Boundaries

Skybouncer's sovereign design prioritizes user data ownership over centralized database reliance:
1. **Repository Partitioning**:
   - Every moderation list and listitem record is created directly inside the protected user's personal data server repository (`at://{protected_did}/app.bsky.graph.listitem/{rkey}`).
   - Skybouncer never hosts a centralized blocklist that users subscribe to; each user owns their list.
2. **Revocation & Portability**:
   - A user can revoke Skybouncer's OAuth authorization at any time from their Bluesky account settings.
   - If revoked, Skybouncer instantly loses write access to the user's repository. Existing moderation records remain intact on the user's PDS, ensuring no data loss.
3. **Decoupled Local Persistence**:
   - The SQLite database acts strictly as an acceleration index and cache for low-latency firehose filtering.
   - Any corruption or loss of the local SQLite database does not destroy the user's moderation state on Bluesky.

---

## 5. Type Redesign Proposals & Actionable Gap Analysis (R5)

This section presents four concrete, production-grade Rust type redesigns designed to enforce domain invariants at compile time ("make invalid states unrepresentable"). All proposals strictly satisfy `AGENTS.md`: `#![forbid(unsafe_code)]`, zero unwrap/expect/panic, typed error propagation, and defensive concurrency.

---

### 5.1 Proposal 1: Validated Protocol Newtypes & Smart Constructors

#### Design Objective
Eliminate untyped strings for protocol primitives (`AtDid`, `AtUri`, `RecordKey`, `Confidence`). Enforce validation in private constructors, guarantee zero-cost borrowing (`Deref<Target = str>`), prevent double-slash bypasses (`at://did:plc:alice//3k234`) via strict collection reverse-DNS NSID validation in `AtUri::parse`, and provide Serde integration with zero runtime panics.

#### Concrete Implementation
```rust
//! Production-grade validated ATProto protocol newtypes.
//! Adheres strictly to AGENTS.md: zero panics, safe Rust, typed errors.

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::error::SkybouncerError;

/// Validated ATProto Decentralized Identifier (`did:plc:...`, `did:web:...`).
/// Invariant: Must begin with `did:` and contain at least 2 colon-separated segments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AtDid(String);

impl AtDid {
    /// Validates and constructs an [`AtDid`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if the string is not a valid DID.
    pub fn parse(s: impl AsRef<str>) -> Result<Self, SkybouncerError> {
        let s_ref = s.as_ref().trim();
        if !s_ref.starts_with("did:") {
            return Err(SkybouncerError::Config(format!(
                "Invalid DID '{s_ref}': must begin with 'did:'"
            )));
        }
        let parts: Vec<&str> = s_ref.split(':').collect();
        if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
            return Err(SkybouncerError::Config(format!(
                "Invalid DID '{s_ref}': must contain method and identifier (did:method:id)"
            )));
        }
        if s_ref.len() > 2048 || s_ref.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err(SkybouncerError::Config(format!(
                "Invalid DID '{s_ref}': illegal characters or exceeds length limit"
            )));
        }
        Ok(Self(s_ref.to_string()))
    }

    /// Returns a borrowed string slice of the canonical DID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the DID method segment (e.g. "plc" or "web").
    #[must_use]
    pub fn method(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or("unknown")
    }
}

impl Deref for AtDid {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for AtDid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for AtDid {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AtDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for AtDid {
    type Err = SkybouncerError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for AtDid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AtDid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Validated ATProto record key (`rkey`).
/// Invariant: 1 to 512 characters matching `[a-zA-Z0-9_.~-]`. Cannot be '.' or '..'.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey(String);

impl RecordKey {
    /// Validates and constructs a [`RecordKey`].
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `s` is not a valid ATProto rkey.
    pub fn parse(s: impl AsRef<str>) -> Result<Self, SkybouncerError> {
        let s_ref = s.as_ref().trim();
        if s_ref.is_empty() || s_ref.len() > 512 {
            return Err(SkybouncerError::Config(
                "Record key length must be between 1 and 512 characters".to_string(),
            ));
        }
        if s_ref == "." || s_ref == ".." {
            return Err(SkybouncerError::Config(
                "Record key cannot be '.' or '..'".to_string(),
            ));
        }
        let valid = s_ref.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '~' || c == '-'
        });
        if !valid {
            return Err(SkybouncerError::Config(format!(
                "Invalid record key '{s_ref}': illegal characters"
            )));
        }
        Ok(Self(s_ref.to_string()))
    }

    /// Returns a borrowed string slice of the record key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for RecordKey {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for RecordKey {
    type Err = SkybouncerError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for RecordKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RecordKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Strongly-typed canonical AT-URI (`at://{authority}/{collection}/{rkey}`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AtUri {
    authority: AtDid,
    collection: String,
    rkey: RecordKey,
    canonical: String,
}

impl AtUri {
    /// Constructs a strongly-typed [`AtUri`].
    #[must_use]
    pub fn new(authority: AtDid, collection: impl Into<String>, rkey: RecordKey) -> Self {
        let coll = collection.into();
        let canonical = format!("at://{}/{}/{}", authority.as_str(), coll, rkey.as_str());
        Self {
            authority,
            collection: coll,
            rkey,
            canonical,
        }
    }

    /// Parses a canonical AT-URI string.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if the URI is malformed.
    pub fn parse(uri: impl AsRef<str>) -> Result<Self, SkybouncerError> {
        let raw = uri.as_ref().trim();
        let stripped = raw.strip_prefix("at://").ok_or_else(|| {
            SkybouncerError::Config(format!("AT-URI '{raw}' must start with 'at://'"))
        })?;

        let mut parts = stripped.split('/');
        let authority_str = parts.next().ok_or_else(|| {
            SkybouncerError::Config(format!("AT-URI '{raw}' missing authority"))
        })?;
        let collection = parts.next().ok_or_else(|| {
            SkybouncerError::Config(format!("AT-URI '{raw}' missing collection"))
        })?;
        if collection.is_empty() || !collection.contains('.') {
            return Err(SkybouncerError::Config(format!(
                "Invalid collection NSID '{collection}' in AT-URI '{raw}': must be non-empty reverse-DNS identifier containing at least one '.' separator"
            )));
        }
        let rkey_str = parts.next().ok_or_else(|| {
            SkybouncerError::Config(format!("AT-URI '{raw}' missing record key"))
        })?;

        if parts.next().is_some() {
            return Err(SkybouncerError::Config(format!(
                "AT-URI '{raw}' contains unexpected trailing segments"
            )));
        }

        let authority = AtDid::parse(authority_str)?;
        let rkey = RecordKey::parse(rkey_str)?;

        Ok(Self::new(authority, collection, rkey))
    }

    /// Returns the authority DID.
    #[must_use]
    pub fn authority(&self) -> &AtDid {
        &self.authority
    }

    /// Returns the collection NSID.
    #[must_use]
    pub fn collection(&self) -> &str {
        &self.collection
    }

    /// Returns the record key.
    #[must_use]
    pub fn rkey(&self) -> &RecordKey {
        &self.rkey
    }

    /// Returns the canonical string representation (`at://did:plc:.../coll/rkey`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl Deref for AtUri {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AtUri {
    type Err = SkybouncerError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for AtUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AtUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}
```

---

### 5.2 Proposal 2: Pipeline Typestate Pattern & Phantom Types

#### Design Objective
Make bypassing the $0 Non-Followed Cost Control Gate a **compile-time error**. Structurally couple interaction vector metadata (parent, root, and quoted URIs) into an algebraic enum (`InteractionVector`), eliminating quote URI loss and image metadata length mismatches.

```
       Jetstream Commit Event
                 │
                 ▼
      Interaction<Ungated> ───────┐
                 │                 │
                 │ evaluate()      │ Cannot call
                 ▼                 │ Classifier::classify()!
        NonFollowedGate            │ (Compile Error)
                 │                 │
      ┌──────────┴──────────┐      │
      ▼                     ▼      │
GateDecision::       GateDecision:: │
Bypassed             Candidate     │
(Dropped $0)                │      │
                            ▼      ▼
                  Interaction<Gated>
                            │
                            ▼
                  Classifier::classify()
                            │
                            ▼
                  Interaction<Evaluated>
                            │
                            ▼
                  RuleRubric::evaluate()
                            │
                            ▼
              Interaction<ActionableViolation>
                            │
                            ▼
                 ModListManager::bounce()
```

#### Concrete Implementation
```rust
//! Pipeline Typestate implementation for ATProto interaction processing.
//! Enforces that interactions cannot be evaluated by classifiers or mutated on PDS
//! without progressing through the required gating and evaluation stages.

use std::marker::PhantomData;
use crate::error::SkybouncerError;
use crate::classifier::{Verdict, ViolationCategory};

/// Interaction vector variants guaranteeing required reference URIs exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InteractionVector {
    /// Direct reply to a post. Must have parent URI and thread root URI.
    DirectReply {
        /// Immediate parent post being replied to.
        parent: AtUri,
        /// Thread root post.
        root: AtUri,
    },
    /// Reply deeper in a thread where immediate parent is not the protected user,
    /// but the thread root was authored by the protected user.
    ThreadReply {
        /// Immediate parent post.
        parent: AtUri,
        /// Thread root post owned by protected user.
        root: AtUri,
    },
    /// Explicit user mention in richtext facets.
    Mention,
    /// Quote post embedding a protected user's post.
    Quote {
        /// The specific post AT-URI quoted by the candidate post.
        quoted_post: AtUri,
    },
}

/// Attached image with guaranteed paired CID and alt text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttachedImage {
    /// Content identifier (CID) hash string.
    pub cid: String,
    /// Accessibility alt text description.
    pub alt: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Typestate Markers (Zero-Sized Types)
// ─────────────────────────────────────────────────────────────────────────────

/// Marker: Interaction freshly extracted from Jetstream; has NOT passed non-followed gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ungated;

/// Marker: Interaction passed Non-Followed Gate; guaranteed non-self, non-followed, non-allowlisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gated;

/// Marker: Interaction evaluated by primary/fallback classifier and paired with a Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluated;

/// Marker: Confirmed violation whose confidence meets/exceeds rubric sensitivity threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionableViolation;

/// Core interaction candidate parameterized by lifecycle typestate `Stage`.
#[derive(Debug, Clone)]
pub struct Interaction<Stage> {
    post_uri: AtUri,
    post_cid: Option<String>,
    author_did: AtDid,
    target_did: AtDid,
    text: String,
    vector: InteractionVector,
    created_at_us: u64,
    images: Vec<AttachedImage>,
    _stage: PhantomData<Stage>,
}

impl Interaction<Ungated> {
    /// Creates a raw, ungated interaction extracted from a firehose commit.
    #[must_use]
    pub fn new_ungated(
        post_uri: AtUri,
        post_cid: Option<String>,
        author_did: AtDid,
        target_did: AtDid,
        text: String,
        vector: InteractionVector,
        created_at_us: u64,
        images: Vec<AttachedImage>,
    ) -> Self {
        Self {
            post_uri,
            post_cid,
            author_did,
            target_did,
            text,
            vector,
            created_at_us,
            images,
            _stage: PhantomData,
        }
    }

    /// Fast-path self-interaction check.
    #[must_use]
    pub fn is_self_interaction(&self) -> bool {
        self.author_did == self.target_did
    }

    /// Promotes an ungated interaction into a gated candidate upon passing NonFollowedGate.
    ///
    /// Available across module boundaries so [`NonFollowedGate`] can cleanly
    /// promote interactions without exposing private struct fields.
    #[must_use]
    pub(crate) fn into_gated(self) -> Interaction<Gated> {
        Interaction {
            post_uri: self.post_uri,
            post_cid: self.post_cid,
            author_did: self.author_did,
            target_did: self.target_did,
            text: self.text,
            vector: self.vector,
            created_at_us: self.created_at_us,
            images: self.images,
            _stage: PhantomData,
        }
    }
}

impl<Stage> Interaction<Stage> {
    /// Author DID of the interaction.
    #[must_use]
    pub fn author_did(&self) -> &AtDid {
        &self.author_did
    }

    /// Protected target user DID.
    #[must_use]
    pub fn target_did(&self) -> &AtDid {
        &self.target_did
    }

    /// Post canonical AT-URI.
    #[must_use]
    pub fn post_uri(&self) -> &AtUri {
        &self.post_uri
    }

    /// Plaintext content.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Interaction vector metadata.
    #[must_use]
    pub fn vector(&self) -> &InteractionVector {
        &self.vector
    }

    /// Attached images.
    #[must_use]
    pub fn images(&self) -> &[AttachedImage] {
        &self.images
    }

    /// Microsecond timestamp.
    #[must_use]
    pub fn created_at_us(&self) -> u64 {
        self.created_at_us
    }
}

/// Result of evaluating an [`Interaction<Ungated>`] through the gate.
pub enum TypeSafeGateDecision {
    /// Candidate passed all checks: author != target, author not followed, not allowlisted.
    Candidate(Interaction<Gated>),
    /// Bypassed at zero cost without model invocation.
    Bypassed {
        /// Reason candidate was bypassed.
        reason: crate::matcher::BypassReason,
        /// Original ungated interaction.
        interaction: Interaction<Ungated>,
    },
}

/// Type-safe classifier interface preventing gate bypasses at compile time.
#[async_trait::async_trait]
pub trait TypeSafeClassifier: Send + Sync {
    /// Classifies an interaction.
    ///
    /// # Compile-Time Guarantee
    /// ONLY accepts [`Interaction<Gated>`]. Passing an `Interaction<Ungated>`
    /// will fail to compile, eliminating cost-control gate bypasses.
    async fn classify(&self, candidate: &Interaction<Gated>) -> Result<Verdict, SkybouncerError>;
}

/// Evaluated candidate paired with its classifier verdict.
pub struct EvaluatedInteraction {
    /// Candidate in evaluated state.
    pub interaction: Interaction<Evaluated>,
    /// Returned verdict.
    pub verdict: Verdict,
}

impl Interaction<Gated> {
    /// Pairs a gated candidate with a returned verdict, promoting it to `Evaluated`.
    #[must_use]
    pub fn with_verdict(self, verdict: Verdict) -> EvaluatedInteraction {
        let interaction = Interaction {
            post_uri: self.post_uri,
            post_cid: self.post_cid,
            author_did: self.author_did,
            target_did: self.target_did,
            text: self.text,
            vector: self.vector,
            created_at_us: self.created_at_us,
            images: self.images,
            _stage: PhantomData,
        };
        EvaluatedInteraction { interaction, verdict }
    }
}

/// Confirmed actionable violation ready for sovereign PDS mutation.
pub struct ConfirmedViolation {
    /// Interaction in actionable violation state.
    pub interaction: Interaction<ActionableViolation>,
    /// Violation category.
    pub category: ViolationCategory,
    /// Violation confidence score.
    pub confidence: f64,
    /// Violation reasoning.
    pub reason: String,
}

impl EvaluatedInteraction {
    /// Evaluates the verdict against the rubric sensitivity threshold.
    /// Returns `Some(ConfirmedViolation)` if and only if actionable.
    #[must_use]
    pub fn filter_actionable(
        self,
        rubric: &crate::classifier::RuleRubric,
    ) -> Option<ConfirmedViolation> {
        match self.verdict {
            Verdict::Violation { category, confidence, reason } => {
                if rubric.meets_threshold(&category, confidence) {
                    Some(ConfirmedViolation {
                        interaction: Interaction {
                            post_uri: self.interaction.post_uri,
                            post_cid: self.interaction.post_cid,
                            author_did: self.interaction.author_did,
                            target_did: self.interaction.target_did,
                            text: self.interaction.text,
                            vector: self.interaction.vector,
                            created_at_us: self.interaction.created_at_us,
                            images: self.interaction.images,
                            _stage: PhantomData,
                        },
                        category,
                        confidence,
                        reason,
                    })
                } else {
                    None
                }
            }
            Verdict::Permitted { .. } => None,
        }
    }
}
```

---

### 5.3 Proposal 3: Multi-Tenant State Machine (`SovereignTenant`)

#### Design Objective
Eliminate untyped collections of optional fields in `Tenant`. Model the tenant lifecycle as an algebraic sum-type state machine (`TenantLifecycle`). Enforce that PDS mutations can only be executed by an active tenant with valid cryptographic DPoP credentials, eliminating silent fallback to bot/admin credentials in single-tenant deployments. Crucially, distinguish read-only client resolution (`resolve_read_client`) from write client resolution (`resolve_mutation_client`), strictly rejecting `Paused` tenants from issuing automated PDS blocklist writes while permitting administrative inspections.

```
                    ┌───────────────────────────┐
                    │  EnrolledAwaitingAuth     │
                    │  (Handle known, 0 session)│
                    └─────────────┬─────────────┘
                                  │ OAuth 2.1 PKCE+DPoP
                                  │ Authentication Success
                                  ▼
      ┌────────────────────────────────────────────────────────┐
      │                        Active                          │
      │        (AuthenticatedSession + RuleRubric)             │
      └───┬───────────────────────────┬────────────────────┬───┘
          │                           │                    │
          │ DM bot / Web UI           │ Access token       │ User revokes
          │ "pause" command           │ expired; refresh   │ OAuth consent
          │                           │ fails              │
          ▼                           ▼                    ▼
   ┌─────────────┐             ┌─────────────┐      ┌─────────────┐
   │   Paused    │             │ AuthExpired │      │   Revoked   │
   │  (Active    │             │  (Refresh   │      │(Purged from │
   │   Session)  │             │   Failed)   │      │   memory)   │
   └──────┬──────┘             └──────┬──────┘      └─────────────┘
          │ "resume"                  │ Re-auth via
          │ command                   │ 1-click link
          └───────────────────────────┘
```

#### Concrete Implementation
```rust
//! Multi-tenant state machine and sovereign isolation model.
//! Guarantees that unauthenticated or expired tenants cannot trigger PDS writes
//! and eliminates silent fallback to bot credentials.

use std::sync::Arc;
use std::time::Duration;
use skyauth::session::OAuthSession;
use skybase::repo::PdsRepoClient;
use crate::error::SkybouncerError;
use crate::classifier::RuleRubric;

/// Validated authenticated session with DPoP credentials.
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    inner: OAuthSession,
}

impl AuthenticatedSession {
    /// Wraps an authenticated [`OAuthSession`], ensuring it is not already expired.
    pub fn new(session: OAuthSession) -> Result<Self, SkybouncerError> {
        if session.is_expired() && session.refresh_token().is_none() {
            return Err(SkybouncerError::Auth(
                "Cannot construct AuthenticatedSession: token is expired and has no refresh token".to_string(),
            ));
        }
        Ok(Self { inner: session })
    }

    /// Checks if the access token is valid (with 60-second leeway).
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        !self.inner.is_expired_with_leeway(Duration::from_secs(60))
    }

    /// Access the underlying [`OAuthSession`].
    #[must_use]
    pub fn session(&self) -> &OAuthSession {
        &self.inner
    }

    /// Mutable access for refreshing tokens.
    pub fn session_mut(&mut self) -> &mut OAuthSession {
        &mut self.inner
    }
}

/// Strict lifecycle state machine for an enrolled tenant.
#[derive(Debug, Clone)]
pub enum TenantLifecycle {
    /// User initiated onboarding via DM bot or web UI; waiting for OAuth authorization.
    EnrolledAwaitingAuth {
        /// Bluesky handle if known.
        handle: Option<String>,
        /// Timestamp when user started onboarding.
        registered_at: u64,
    },
    /// Fully authenticated tenant actively protected by the service.
    Active {
        /// Valid DPoP session.
        session: AuthenticatedSession,
        /// Personalized moderation rubric.
        rubric: RuleRubric,
    },
    /// Moderation temporarily suspended by the user via DM (`pause`) or web toggle.
    Paused {
        /// Session remains valid so it can be resumed instantly.
        session: AuthenticatedSession,
        /// Moderation rubric.
        rubric: RuleRubric,
        /// Microsecond timestamp when paused.
        paused_at: u64,
    },
    /// Session expired and automatic background refresh failed; user must re-authorize.
    AuthenticationExpired {
        /// The expired session metadata.
        last_session: OAuthSession,
        /// Moderation rubric preserved.
        rubric: RuleRubric,
        /// Failure timestamp.
        failed_at: u64,
    },
    /// User explicitly unlinked the service or revoked OAuth access.
    Revoked {
        /// Revocation timestamp.
        revoked_at: u64,
    },
}

/// Tenant entity enforcing lifecycle state machine invariants.
#[derive(Debug, Clone)]
pub struct SovereignTenant {
    did: AtDid,
    handle: Option<String>,
    lifecycle: TenantLifecycle,
    created_at: u64,
    updated_at: u64,
}

impl SovereignTenant {
    /// Creates a new tenant in the `EnrolledAwaitingAuth` stage.
    #[must_use]
    pub fn new_onboarding(did: AtDid, handle: Option<String>, now_us: u64) -> Self {
        Self {
            did,
            handle: handle.clone(),
            lifecycle: TenantLifecycle::EnrolledAwaitingAuth {
                handle,
                registered_at: now_us,
            },
            created_at: now_us,
            updated_at: now_us,
        }
    }

    /// Returns the tenant's DID.
    #[must_use]
    pub fn did(&self) -> &AtDid {
        &self.did
    }

    /// Returns the tenant's handle if available.
    #[must_use]
    pub fn handle(&self) -> Option<&str> {
        self.handle.as_deref()
    }

    /// Returns a reference to the active lifecycle state.
    #[must_use]
    pub fn lifecycle(&self) -> &TenantLifecycle {
        &self.lifecycle
    }

    /// Transitions tenant to `Active` upon successful OAuth completion.
    pub fn activate(
        &mut self,
        session: AuthenticatedSession,
        rubric: RuleRubric,
        now_us: u64,
    ) {
        self.lifecycle = TenantLifecycle::Active { session, rubric };
        self.updated_at = now_us;
    }

    /// Pauses an active tenant.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if tenant is not currently `Active`.
    pub fn pause(&mut self, now_us: u64) -> Result<(), SkybouncerError> {
        match std::mem::replace(&mut self.lifecycle, TenantLifecycle::Revoked { revoked_at: now_us }) {
            TenantLifecycle::Active { session, rubric } => {
                self.lifecycle = TenantLifecycle::Paused {
                    session,
                    rubric,
                    paused_at: now_us,
                };
                self.updated_at = now_us;
                Ok(())
            }
            other => {
                self.lifecycle = other;
                Err(SkybouncerError::Config(
                    "Only Active tenants can be paused".to_string(),
                ))
            }
        }
    }

    /// Resumes a paused tenant.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if tenant is not currently `Paused`.
    pub fn resume(&mut self, now_us: u64) -> Result<(), SkybouncerError> {
        match std::mem::replace(&mut self.lifecycle, TenantLifecycle::Revoked { revoked_at: now_us }) {
            TenantLifecycle::Paused { session, rubric, .. } => {
                self.lifecycle = TenantLifecycle::Active { session, rubric };
                self.updated_at = now_us;
                Ok(())
            }
            other => {
                self.lifecycle = other;
                Err(SkybouncerError::Config(
                    "Only Paused tenants can be resumed".to_string(),
                ))
            }
        }
    }

    /// Helper to construct a [`PdsRepoClient`] from an authenticated session.
    fn build_client(
        &self,
        auth_session: &AuthenticatedSession,
        oauth_client: Option<&Arc<skyauth::client::AtprotoOAuthClient>>,
    ) -> Result<Arc<PdsRepoClient>, SkybouncerError> {
        let session_arc = Arc::new(auth_session.session().clone());
        let client = match oauth_client {
            Some(oc) => PdsRepoClient::new(session_arc, Arc::clone(oc)).map_err(|e| {
                SkybouncerError::Config(format!(
                    "Failed to create PdsRepoClient with OAuthClient for {}: {e}",
                    self.did
                ))
            })?,
            None => PdsRepoClient::from_session(session_arc).map_err(|e| {
                SkybouncerError::Config(format!(
                    "Failed to create PdsRepoClient from session for {}: {e}",
                    self.did
                ))
            })?,
        };
        Ok(Arc::new(client))
    }

    /// Attempts to resolve the tenant's [`PdsRepoClient`] for read-only operations.
    ///
    /// # Permitted States
    /// Permits read queries (e.g. reading sovereign configuration or inspecting moderation lists)
    /// for both `Active` and `Paused` tenants. Fails strictly if unauthenticated, expired, or revoked.
    pub fn resolve_read_client(
        &self,
        oauth_client: Option<&Arc<skyauth::client::AtprotoOAuthClient>>,
    ) -> Result<Arc<PdsRepoClient>, SkybouncerError> {
        match &self.lifecycle {
            TenantLifecycle::Active { session, .. } | TenantLifecycle::Paused { session, .. } => {
                self.build_client(session, oauth_client)
            }
            TenantLifecycle::EnrolledAwaitingAuth { .. } => {
                Err(SkybouncerError::Auth(format!(
                    "Tenant {} is awaiting OAuth authorization; read client unavailable",
                    self.did
                )))
            }
            TenantLifecycle::AuthenticationExpired { .. } => {
                Err(SkybouncerError::Auth(format!(
                    "Tenant {} session has expired; re-authorization required",
                    self.did
                )))
            }
            TenantLifecycle::Revoked { .. } => {
                Err(SkybouncerError::Auth(format!(
                    "Tenant {} has revoked access; client unavailable",
                    self.did
                )))
            }
        }
    }

    /// Attempts to resolve the tenant's [`PdsRepoClient`] for repository write/mutation operations.
    ///
    /// # Critical Safety Invariant: Mutation Rejection for Paused Tenants
    /// Returns an authenticated client ONLY when the tenant is strictly in [`TenantLifecycle::Active`].
    ///
    /// If the tenant is in [`TenantLifecycle::Paused`], mutation operations are strictly **rejected**,
    /// guaranteeing that paused tenants cannot execute automated PDS blocklist writes or
    /// list membership changes while moderation defense is paused.
    pub fn resolve_mutation_client(
        &self,
        oauth_client: Option<&Arc<skyauth::client::AtprotoOAuthClient>>,
    ) -> Result<Arc<PdsRepoClient>, SkybouncerError> {
        match &self.lifecycle {
            TenantLifecycle::Active { session, .. } => {
                self.build_client(session, oauth_client)
            }
            TenantLifecycle::Paused { .. } => {
                Err(SkybouncerError::Auth(format!(
                    "Tenant {} is paused; automated PDS mutations (listitem additions/deletions) are forbidden",
                    self.did
                )))
            }
            TenantLifecycle::EnrolledAwaitingAuth { .. } => {
                Err(SkybouncerError::Auth(format!(
                    "Tenant {} is awaiting OAuth authorization; cannot mutate PDS",
                    self.did
                )))
            }
            TenantLifecycle::AuthenticationExpired { .. } => {
                Err(SkybouncerError::Auth(format!(
                    "Tenant {} session has expired; re-authorization required",
                    self.did
                )))
            }
            TenantLifecycle::Revoked { .. } => {
                Err(SkybouncerError::Auth(format!(
                    "Tenant {} has revoked access; cannot mutate PDS",
                    self.did
                )))
            }
        }
    }

    /// Backward-compatible alias for read-only client resolution.
    #[inline]
    pub fn resolve_pds_client(
        &self,
        oauth_client: Option<&Arc<skyauth::client::AtprotoOAuthClient>>,
    ) -> Result<Arc<PdsRepoClient>, SkybouncerError> {
        self.resolve_read_client(oauth_client)
    }
}
```

---

### 5.4 Proposal 4: Structured Error Hierarchy & Bounded Invariant Types

#### Design Objective
Replace unconstrained `f64` confidence scores with a bounded `Confidence` newtype using idiomatic `!(0.0..=1.0).contains(&val)` range validation. Deconstruct stringly-typed `SkybouncerError` into domain-specific structured sub-enums (`ProtocolError`, `TenantError`, `ClassifierError`, `RepoError`, `ChatError`), while preserving `Chat(String)` to maintain complete backward compatibility with the ATProto DM bot service (`chat.bsky.convo.*`), ensuring zero production panics and typed error propagation.

#### Concrete Implementation
```rust
//! Structured error hierarchy and bounded invariant primitives.

use std::fmt;
use std::time::Duration;
use thiserror::Error;

/// Normalized confidence score strictly bounded in `[0.0, 1.0]`.
/// Invariant: Cannot be NaN, negative, or greater than 1.0.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Confidence(f64);

impl Confidence {
    /// Constructs a [`Confidence`] score, rejecting NaN and values outside `[0.0, 1.0]`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if out of bounds or NaN.
    pub fn new(val: f64) -> Result<Self, SkybouncerError> {
        if !(0.0..=1.0).contains(&val) {
            return Err(SkybouncerError::Config(format!(
                "Confidence score must be finite and between 0.0 and 1.0, got: {val}"
            )));
        }
        Ok(Self(val))
    }

    /// Constructs a [`Confidence`] score by clamping finite values to `[0.0, 1.0]`.
    /// Maps `NaN` to `0.0`.
    #[must_use]
    pub fn clamped(val: f64) -> Self {
        if val.is_nan() {
            Self(0.0)
        } else {
            Self(val.clamp(0.0, 1.0))
        }
    }

    /// Returns the raw `f64` value.
    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Structured Domain Errors
// ─────────────────────────────────────────────────────────────────────────────

/// ATProto protocol parsing and lexicon validation failures.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Malformed Decentralized Identifier.
    #[error("Malformed DID: {0}")]
    InvalidDid(String),

    /// Malformed AT-URI structure.
    #[error("Malformed AT-URI: {0}")]
    InvalidAtUri(String),

    /// Malformed repository record key.
    #[error("Malformed Record Key: {0}")]
    InvalidRecordKey(String),

    /// Unexpected collection encountered in record processing.
    #[error("Unexpected collection: expected {expected}, found {found}")]
    CollectionMismatch {
        /// Expected collection NSID.
        expected: String,
        /// Actual collection NSID found.
        found: String,
    },
}

/// Tenant isolation and authentication lifecycle failures.
#[derive(Debug, Error)]
pub enum TenantError {
    /// Tenant not found in persistence store.
    #[error("Tenant '{0}' not found in registry")]
    NotFound(AtDid),

    /// Tenant has not completed OAuth authorization.
    #[error("Tenant '{0}' is awaiting authorization")]
    Unauthenticated(AtDid),

    /// Tenant OAuth session expired and could not be refreshed.
    #[error("Tenant '{0}' OAuth session has expired")]
    SessionExpired(AtDid),

    /// Cross-tenant boundary violation attempt detected.
    #[error("Cross-tenant boundary violation: requested {requested}, authenticated as {authenticated}")]
    IsolationViolation {
        /// Requested tenant DID.
        requested: AtDid,
        /// Authenticated tenant DID.
        authenticated: AtDid,
    },
}

/// Upstream classifier model evaluation failures.
#[derive(Debug, Error)]
pub enum ClassifierError {
    /// Evaluation request timed out.
    #[error("Classifier request timed out after {0:?}")]
    Timeout(Duration),

    /// Upstream model server returned an HTTP error.
    #[error("Upstream model HTTP error: status {status}, message: {message}")]
    UpstreamHttp {
        /// HTTP status code.
        status: u16,
        /// Error message body.
        message: String,
    },

    /// Upstream model response failed JSON parsing.
    #[error("Model response could not be parsed: {0}")]
    ParseError(String),

    /// Sharded rate limit exceeded for user.
    #[error("Tier-4 rate limit exceeded for user '{did}'; retry after {retry_after:?}")]
    RateLimited {
        /// User DID being throttled.
        did: AtDid,
        /// Suggested retry backoff.
        retry_after: Duration,
    },
}

/// Sovereign PDS repository mutation failures.
#[derive(Debug, Error)]
pub enum RepoError {
    /// Remote PDS rejected write or delete mutation.
    #[error("PDS mutation rejected with status {status}: {message}")]
    MutationRejected {
        /// HTTP status code.
        status: u16,
        /// Detailed error message from PDS.
        message: String,
    },

    /// Retries failed after PDS issued DPoP nonce challenge.
    #[error("PDS DPoP nonce challenge retry failed")]
    DPoPNonceFailure,

    /// Target record does not exist on remote repository.
    #[error("Repository record not found: {0}")]
    RecordNotFound(String),
}

/// ATProto Chat service and direct message dispatch failures.
#[derive(Debug, Error)]
pub enum ChatError {
    /// Conversation polling failure.
    #[error("Failed to poll conversations: {0}")]
    PollingFailure(String),

    /// Deserialization error, such as encountering a deleted message union.
    #[error("Failed to parse conversation payload: {0}")]
    PayloadError(String),

    /// Message dispatch failure.
    #[error("Failed to send chat message: {0}")]
    SendFailure(String),
}

/// Top-level strongly-typed error hierarchy for `skybouncer`.
#[derive(Debug, Error)]
pub enum SkybouncerError {
    /// ATProto protocol parsing error.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// Tenant lifecycle error.
    #[error(transparent)]
    Tenant(#[from] TenantError),

    /// Model classifier error.
    #[error(transparent)]
    Classifier(#[from] ClassifierError),

    /// Repository mutation error.
    #[error(transparent)]
    Repo(#[from] RepoError),

    /// Failure communicating with ATProto Chat / DM service.
    /// Preserved from existing `src/error.rs:30` to prevent breaking DM bot polling and alerting.
    #[error("Chat/DM service error: {0}")]
    Chat(String),

    /// Underlying SQLite persistence error.
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// JSON serialization or deserialization failure.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// HTTP client transport error.
    #[error("Network HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// Service configuration or parsing failure.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Authentication failure.
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Firehose WebSocket ingestion failure.
    #[error("Ingestion error: {0}")]
    Ingestion(String),
}

impl From<ChatError> for SkybouncerError {
    fn from(err: ChatError) -> Self {
        Self::Chat(err.to_string())
    }
}
```

---

### 5.5 Actionable 4-Phase Migration Roadmap

| Phase | Milestone Name | Affected Modules | Target Invariants Enforced |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Protocol Newtypes** | `src/types.rs`, `src/matcher/` | Validated `AtDid`, `AtUri`, `RecordKey`, `Confidence`; eliminate stringly-typed identifiers across public structs. |
| **Phase 2** | **Structured Error Hierarchy** | `src/error.rs`, `src/tenant/`, `src/classifier/` | Expand `SkybouncerError` with `ProtocolError`, `TenantError`, and `ClassifierError` sub-enums; preserve SQLite source errors. |
| **Phase 3** | **Pipeline Typestates** | `src/matcher/interaction.rs`, `src/engine.rs` | Refactor `Interaction<Stage>`; algebraically couple parent/root/quote URIs; make gate bypass a compile-time error. |
| **Phase 4** | **Multi-Tenant State Machine** | `src/tenant/registry.rs`, `src/engine.rs` | Introduce `SovereignTenant` and `TenantLifecycle`; eliminate credential fallback and silent admin substitution. |

---

## 6. Verification & Engineering Standards Adherence

All analysis and proposed code structures comply with the engineering gates mandated in `AGENTS.md`:

| Quality Standard | Invariant Rule | Compliance Status & Evidence |
| :--- | :--- | :--- |
| **Zero Unsafe Code** | `#![forbid(unsafe_code)]` | **Compliant**: 100% safe Rust across all proposed newtypes, typestates, and state machine enums. |
| **Zero Production Panics** | `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` | **Compliant**: All constructors and transitions return typed `Result<T, SkybouncerError>`. No panics or unwrap calls. |
| **Typed Error Hierarchy** | Domain-specific variants in `src/error.rs` | **Compliant**: Structured error sub-enums (`ProtocolError`, `TenantError`, `ClassifierError`, `RepoError`) preserve causality. |
| **Defensive Concurrency & Locks** | No locks held across `.await` points | **Compliant**: Striped mutexes (`StripedAsyncLocks`) and synchronous locks (`parking_lot`) are dropped before async points. |
| **Clock-Warp Safety** | Saturating arithmetic on monotonic clocks | **Compliant**: Microsecond timestamps employ saturating subtraction and addition for rewinds and TTL checks. |
| **100% Documentation Coverage** | `missing_docs` denied | **Compliant**: All structs, enums, fields, and public methods feature doc comments with bare URLs enclosed in angle brackets. |
