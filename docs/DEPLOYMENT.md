# 🚀 Skybouncer Production Deployment & Operations Guide

This guide covers production-grade deployment, containerization, security hardening, and operational runbooks for **Skybouncer**: the sovereign, rule-driven automated moderation service and bouncer for Bluesky and the AT Protocol.

---

## 📋 Table of Contents
1. [Architecture & Topology Overview](#1-architecture--topology-overview)
2. [Deployment Option A: Docker & Docker Compose](#2-deployment-option-a-docker--docker-compose)
   - [Standard Deployment (Remote Jev/Gemini)](#standard-deployment-remote-jevgemini)
   - [Self-Contained Local AI Deployment (Ollama Multimodal)](#self-contained-local-ai-deployment-ollama-multimodal)
3. [Deployment Option B: Systemd Service (Bare Metal / VPS)](#3-deployment-option-b-systemd-service-bare-metal--vps)
   - [Idempotent Automated Installation](#idempotent-automated-installation)
   - [Manual Installation Steps](#manual-installation-steps)
   - [Sandboxing & Process Hardening](#sandboxing--process-hardening)
4. [Reverse Proxy & Domain Configuration](#4-reverse-proxy--domain-configuration)
   - [Caddy (Automatic HTTPS)](#caddy-automatic-https)
   - [Nginx](#nginx)
5. [Configuration Variable Reference](#5-configuration-variable-reference)
6. [Operational Runbooks & Maintenance](#6-operational-runbooks--maintenance)
   - [Graceful Shutdown & Zero-Downtime Restarts](#graceful-shutdown--zero-downtime-restarts)
   - [Database Backup & Maintenance](#database-backup--maintenance)
   - [Healthchecks & Telemetry Monitoring](#healthchecks--telemetry-monitoring)
   - [Emergency Unbanning & Pardon](#emergency-unbanning--pardon)

---

## 1. Architecture & Topology Overview

Skybouncer runs as a single, low-footprint, resilient binary. It continuously consumes the ATProto Jetstream firehose over WebSockets, matches incoming interactions against protected users, evaluates candidates through a low-latency System-1 classifier, and updates sovereign moderation lists (`app.bsky.graph.listitem`) via DPoP-signed PDS mutations.

```
       ┌───────────────────────────────┐
       │   Global Jetstream Firehose   │
       │   (wss://jetstream*.bsky.*)   │
       └───────────────┬───────────────┘
                       │ WebSocket
                       ▼
       ┌───────────────────────────────┐
       │    Skybouncer Ingestion       │
       │    - Non-Followed Gate (<1µs) │
       │    - SQLite Deduplication     │
       └───────────────┬───────────────┘
                       │ Unfiltered Candidate
                       ▼
       ┌───────────────────────────────┐
       │   Tiered Classifier Engine    │
       │   Tier 1: Jev / SystemOne     │
       │   Tier 2: Multimodal Fallback │
       └───────────────┬───────────────┘
                       │ Actionable Violation
                       ▼
       ┌───────────────────────────────┐
       │     Sovereign PDS Mutator     │
       │  (Writes app.bsky.graph.list) │
       └───────────────────────────────┘
```

---

## 2. Deployment Option A: Docker & Docker Compose

Containerized deployment is the fastest way to run Skybouncer with zero host-level dependency overhead.

### Standard Deployment (Remote Jev/Gemini)

1. Clone repository and navigate to `skybouncer`:
   ```bash
   git clone https://github.com/mike10010100/atproto-experiments.git
   cd atproto-experiments/skybouncer
   ```

2. Copy the environment configuration:
   ```bash
   cp deploy/systemd/skybouncer.env.example .env
   chmod 0600 .env
   nano .env
   ```

3. Build and launch the container in detached mode:
   ```bash
   docker compose up -d --build
   ```

4. Check real-time logs:
   ```bash
   docker compose logs -f skybouncer
   ```

---

### Self-Contained Local AI Deployment (Ollama Multimodal)

To run Skybouncer completely self-contained with a local multimodal vision model (e.g. `gemma4:12b` or `llava`) for Tier 2 fallback evaluations:

1. Configure `.env`:
   ```env
   FALLBACK_JEV_API_BASE_URL=http://ollama:11434/api/chat
   FALLBACK_JEV_MODEL=gemma4:12b
   CERTAINTY_MIN=0.40
   CERTAINTY_MAX=0.85
   ```

2. Launch Skybouncer with the `local-ai` profile:
   ```bash
   docker compose --profile local-ai up -d --build
   ```

3. Pull your desired vision model inside the Ollama container:
   ```bash
   docker compose exec ollama ollama pull gemma4:12b
   ```

---

## 3. Deployment Option B: Systemd Service (Bare Metal / VPS)

For bare-metal servers or cloud virtual machines (Debian/Ubuntu/RHEL), Skybouncer provides a fully hardened Systemd service unit.

### Idempotent Automated Installation

1. Build the release binary:
   ```bash
   cargo build --release --bin skybouncer
   ```

2. Run the automated installer:
   ```bash
   sudo ./deploy/systemd/install.sh
   ```

3. Edit your credentials:
   ```bash
   sudo nano /etc/skybouncer/skybouncer.env
   ```

4. Enable and start the service:
   ```bash
   sudo systemctl enable --now skybouncer
   sudo systemctl status skybouncer
   ```

---

### Sandboxing & Process Hardening

The provided `skybouncer.service` unit enforces strict Linux security sandboxing:

* **Dedicated Unprivileged User**: Runs as `skybouncer:skybouncer` with `/sbin/nologin`.
* **`NoNewPrivileges=true`**: Prevents child processes from gaining elevated permissions via `setuid`/`setgid`.
* **`ProtectSystem=strict`**: Mounts `/usr`, `/boot`, `/etc`, and system directories read-only.
* **`ProtectHome=true`**: Makes `/home`, `/root`, and `/run/user` completely inaccessible.
* **`PrivateTmp=true` & `PrivateDevices=true`**: Isolated `/tmp` and denial of raw device access.
* **`ReadWritePaths=/var/lib/skybouncer`**: Restricts filesystem writes exclusively to the SQLite database directory.
* **`MemoryDenyWriteExecute=true`**: Disallows creating writable and executable memory mappings (W^X enforcement).

---

## 4. Reverse Proxy & Domain Configuration

For the **Web Dashboard** and **ATProto OAuth 2.0 PKCE + DPoP** flow, a valid HTTPS public domain is required.

### Caddy (Automatic HTTPS)

Copy `deploy/caddy/Caddyfile` to `/etc/caddy/Caddyfile`, replace `moderation.example.com` with your actual domain, and reload:
```bash
sudo systemctl reload caddy
```

### Nginx

Copy `deploy/nginx/skybouncer.conf` to `/etc/nginx/sites-available/skybouncer.conf`, link to `sites-enabled`, obtain TLS certificates with Certbot, and reload:
```bash
sudo certbot --nginx -d moderation.example.com
sudo systemctl reload nginx
```

---

## 5. Configuration Variable Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PROTECTED_DIDS` | *(Required)* | Comma-separated list of protected ATProto DIDs shielded by this instance. |
| `PDS_URL` | `https://bsky.social` | Endpoint of the user's sovereign PDS repository. |
| `PDS_USERNAME` | — | Protected user handle or DID for PDS mutations. |
| `PDS_PASSWORD` | — | App password generated in Bluesky Settings -> App Passwords. |
| `MODERATION_RULES` | — | Natural-language moderation instructions evaluated by the classifier. |
| `SENSITIVITY` | `medium` | Confidence threshold: `low` ($\ge 0.90$), `medium` ($\ge 0.75$), `high` ($\ge 0.60$). |
| `JEV_API_BASE_URL` | `https://api.jev.ai` | Primary Decision Gateway / Jev classification endpoint. |
| `JEV_MODEL` | `nimble` | Primary classifier model name. |
| `FALLBACK_JEV_API_BASE_URL` | — | Optional secondary multimodal fallback endpoint (e.g. Ollama chat). |
| `FALLBACK_JEV_MODEL` | — | Multimodal fallback model (e.g. `gemma4:12b`, `llava`). |
| `CERTAINTY_MIN` | `0.40` | Lower bound of uncertainty escalation band. |
| `CERTAINTY_MAX` | `0.85` | Upper bound of uncertainty escalation band. |
| `BOT_DID` | — | Bot account DID for ATProto direct-messaging interface. |
| `CHAT_ACCESS_TOKEN` | — | Access token with `chat.bsky.convo` scope. |
| `WEB_ENABLED` | `true` | Whether to launch the Axum web dashboard. |
| `HOST` | `127.0.0.1` | Web server listening address. |
| `PORT` | `3000` | Web server listening port. |
| `PUBLIC_URL` | `http://127.0.0.1:3000` | Publicly reachable HTTPS URL for OAuth 2.0 redirects. |
| `SKYBOUNCER_DATABASE_PATH`| `skybouncer.db` | Filesystem path for SQLite deduplication and cache store. |
| `DRY_RUN` | `false` | When `true`, streams live firehose and evaluates models without writing PDS mutations. |
| `RATE_LIMIT_PER_HOUR` | `100` | Maximum model calls permitted per author DID per hour. |

---

## 6. Operational Runbooks & Maintenance

### Graceful Shutdown & Zero-Downtime Restarts

Skybouncer hooks into `SIGINT` (Ctrl+C) and `SIGTERM`. When a shutdown signal is received:
1. Firehose WebSocket subscription stops ingesting new events.
2. In-flight evaluations and PDS write requests drain with a 30-second timeout ceiling.
3. Open SQLite connections commit WAL logs and close cleanly.

To restart the systemd service safely:
```bash
sudo systemctl restart skybouncer
```

---

### Database Backup & Maintenance

The SQLite database (`skybouncer.db`) stores evaluated author TTLs, list metadata, and audit logs using Write-Ahead Logging (`WAL`).

To take a live, lock-free online backup:
```bash
sqlite3 /var/lib/skybouncer/skybouncer.db ".backup /var/backups/skybouncer-$(date +%Y%m%d%H%M%S).db"
```

To schedule daily automated backups via crontab:
```cron
0 3 * * * sqlite3 /var/lib/skybouncer/skybouncer.db ".backup /var/backups/skybouncer-$(date +\%F).db" && find /var/backups -name "skybouncer-*.db" -mtime +14 -delete
```

---

### Healthchecks & Telemetry Monitoring

Skybouncer exposes two observability endpoints:

1. **Liveness / Readiness Probe**:
   ```bash
   curl -f http://127.0.0.1:3000/healthz
   # Response: HTTP 200 OK {"status":"ok","version":"0.1.0"}
   ```

2. **Detailed Engine Telemetry**:
   ```bash
   curl -s http://127.0.0.1:3000/api/status | jq .
   ```
   *Returns real-time commit rates, bypass counts, violation counts, and PDS mutation statistics.*

---

### Emergency Unbanning & Pardon

If an account was incorrectly moderated:

1. **Via Web Dashboard**:
   Navigate to `https://moderation.example.com`, locate the violator in the Recent Bounces table, and click **Pardon**.

2. **Via REST API**:
   ```bash
   curl -X POST http://127.0.0.1:3000/api/pardon \
     -H "Content-Type: application/json" \
     -d '{"subject_did": "did:plc:accounttoopen"}'
   ```

3. **Via ATProto DM Bot**:
   Direct-message your Skybouncer bot account from the Bluesky app:
   ```text
   pardon @handle.bsky.social
   ```
