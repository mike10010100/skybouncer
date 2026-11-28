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
   git clone https://github.com/mike10010100/skybouncer.git
   cd skybouncer
   ```

2. Copy the environment configuration:
   ```bash
   cp .env.example .env
   chmod 0600 .env
   nano .env
   ```

3. Build and launch the container in detached mode (or run `./scripts/deploy.sh`):
   ```bash
   docker compose up -d --build
   ```

4. Check real-time logs:
   ```bash
   docker compose logs -f skybouncer
   ```

---

### Self-Contained Local AI Deployment (Ollama Multimodal)

To run Skybouncer completely self-contained with a local multimodal vision model (e.g. `gemma4:26b` or `llava`) for Tier 2 fallback evaluations:

1. Configure `.env`:
   ```env
   FALLBACK_API_BASE_URL=http://ollama:11434/api/chat
   FALLBACK_MODEL=gemma4:26b
   UNCERTAINTY_MIN=0.40
   UNCERTAINTY_MAX=0.85
   ```

2. Launch Skybouncer with the `local-ai` profile:
   ```bash
   docker compose --profile local-ai up -d --build
   ```

3. Pull your desired vision model inside the Ollama container:
   ```bash
   docker compose exec ollama ollama pull gemma4:26b
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

Copy `deploy/caddy/Caddyfile` to `/etc/caddy/Caddyfile`, replace `moderation.example.com` with your actual domain (and update `127.0.0.1:3000` to `127.0.0.1:3031` if using Docker Compose), and reload:
```bash
sudo systemctl reload caddy
```

### Nginx

Copy `deploy/nginx/skybouncer.conf` to `/etc/nginx/sites-available/skybouncer.conf` (adjusting `127.0.0.1:3000` to `127.0.0.1:3031` if using Docker Compose), link to `sites-enabled`, obtain TLS certificates with Certbot, and reload:
```bash
sudo certbot --nginx -d moderation.example.com
sudo systemctl reload nginx
```

---

## 5. Configuration Variable Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ADMIN_DID` | — | Explicit Administrator DID (fleet oversight, tenant management, telemetry inspection). |
| `SKYBOUNCER_PROTECTED_DIDS` | — | Optional comma-separated additional protected DIDs to shield on startup. |
| `PDS_ENDPOINT` | `https://bsky.social` | Endpoint of the sovereign PDS repository. |
| `SKYBOUNCER_RULES` | *(Built-in default)* | Natural-language moderation instructions evaluated by the classifier. |
| `SKYBOUNCER_SENSITIVITY` | `medium` | Confidence threshold: `low` ($\ge 0.90$), `medium` ($\ge 0.75$), `high` ($\ge 0.60$). |
| `SKYBOUNCER_JETSTREAM_URL` | `wss://jetstream2.us-east.bsky.network/subscribe` | ATProto Jetstream WebSocket firehose endpoint. |
| `JEV_API_BASE_URL` | `http://localhost:8000` | Primary Decision Gateway / Jev classification endpoint. |
| `JEV_MODEL` | `nimble` | Primary classifier model name. |
| `FALLBACK_API_BASE_URL` | — | Optional secondary multimodal fallback endpoint (e.g. Ollama `/api/chat`). |
| `FALLBACK_MODEL` | — | Multimodal fallback model (e.g. `gemma4:26b`, `llava`). |
| `UNCERTAINTY_MIN` | `0.40` | Lower bound of uncertainty escalation band. |
| `UNCERTAINTY_MAX` | `0.85` | Upper bound of uncertainty escalation band. |
| `BOT_HANDLE` / `BOT_APP_PASSWORD` | — | Bot account handle and App Password for ATProto DM interface (or `BOT_DID` + `CHAT_ACCESS_TOKEN`). |
| `WEB_ENABLED` | `true` | Whether to launch the Axum web dashboard. |
| `HOST` | `127.0.0.1` (`0.0.0.0` in Docker) | Web server listening address inside process/container. |
| `PORT` / `PORT_BIND` | `3000` / `3031` | Internal web server port (`3000`) and Docker Compose host bind (`127.0.0.1:3031`). |
| `PUBLIC_URL` | `http://127.0.0.1:3000` | Publicly reachable HTTPS URL for OAuth 2.0 redirects and CSRF origin checks. |
| `SKYBOUNCER_DATABASE_PATH` | `skybouncer.db` | Filesystem path for SQLite deduplication, tenant registry, and cache store. |
| `SKYBOUNCER_SESSION_ENCRYPTION_KEY` | *(Auto-generated `0600` `.skybouncer.key`)* | 64-char hex AES-256-GCM key encrypting OAuth sessions & DPoP keys at rest. |
| `SKYBOUNCER_API_TOKEN` | — | Operator bearer token for authenticated `/api/*` and `/metrics` requests. |
| `SKYBOUNCER_METRICS_TOKEN` / `SKYBOUNCER_METRICS_PUBLIC` | — / `false` | Dedicated Prometheus scrape bearer token, or `true` for unauthenticated private-network scrapes. |
| `TRUSTED_PROXY_HEADER` / `TRUSTED_PROXIES` | — | Reverse-proxy client-IP header (`cf-connecting-ip`, `x-real-ip`, `x-forwarded-for`) and trusted proxy CIDRs. |
| `DRY_RUN` | `false` | When `true`, streams live firehose and evaluates models without writing PDS mutations. |
| `SKYBOUNCER_RATE_LIMIT_EVALS_PER_HOUR` | `100` | Maximum model calls permitted per target DID per hour. |

---

## 6. Operational Runbooks & Maintenance

### Graceful Shutdown & Zero-Downtime Restarts

Skybouncer hooks into `SIGINT` (Ctrl+C) and `SIGTERM`. When a shutdown signal is received:
1. Firehose WebSocket subscription stops ingesting new events.
2. In-flight evaluations and PDS write requests drain with a 20-second timeout ceiling (`stop_grace_period: 30s` in Docker Compose).
3. Open SQLite connections checkpoint (`PRAGMA wal_checkpoint(TRUNCATE)`) and close cleanly.

To restart the systemd service safely:
```bash
sudo systemctl restart skybouncer
```

---

### Database Backup & Maintenance

The SQLite database (`skybouncer.db`) stores evaluated author TTLs, list metadata, tenant sessions, and audit logs using Write-Ahead Logging (`WAL`). Snapshots **must** be taken with SQLite's online backup API (`.backup` / `VACUUM INTO`) rather than copying the file, so that WAL contents are captured consistently while the service is live.

#### Docker Deployment (recommended)

`scripts/backup.sh` takes a consistent online snapshot from the `skybouncer_data`
named volume (via an ephemeral container running as `--user 10001:10001` with `.timeout 5000`), verifies it with
`PRAGMA integrity_check`, gzip-compresses it with `0700`/`0600` permissions, and prunes old snapshots. It works
whether or not the application container is running.

```bash
# Ad-hoc backup using the defaults (writes to ${HOME}/backups/skybouncer, keeps 5)
./scripts/backup.sh
```

Behavior is configurable via environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SKYBOUNCER_BACKUP_DIR` | `${HOME}/backups/skybouncer` | Destination directory for snapshots. |
| `SKYBOUNCER_BACKUP_RETAIN` | `5` | Number of most-recent snapshots to keep. |
| `SKYBOUNCER_VOLUME` | `skybouncer_data` | Docker named volume holding the database. |
| `SKYBOUNCER_DB_NAME` | `skybouncer.db` | Database filename within the volume. |
| `SKYBOUNCER_IMAGE` | `skybouncer:latest` | Image providing `sqlite3` + `gzip`. |

Snapshots are named `skybouncer-YYYY-MM-DD-HHMMSS.db.gz`. A simple crontab entry to run
daily at 03:00 and retain the last 5 days:

```cron
0 3 * * * /path/to/skybouncer/scripts/backup.sh >> ${HOME}/backups/skybouncer/backup.log 2>&1
```

To restore a snapshot, stop the service, remove stale `-wal`/`-shm` sidecars, decompress over the volume database with `0600` permissions, and restart:

```bash
docker compose stop skybouncer
gunzip -c ~/backups/skybouncer/skybouncer-2026-11-28-030000.db.gz \
  | docker run --rm -i -v skybouncer_data:/data --user 10001:10001 \
      --entrypoint sh skybouncer:latest -c 'rm -f /data/skybouncer.db-wal /data/skybouncer.db-shm && cat > /data/skybouncer.db && chmod 0600 /data/skybouncer.db'
docker compose up -d skybouncer
```

#### systemd (non-Docker) Deployment

For the bare-metal systemd install, take an online backup directly:

```bash
sqlite3 /var/lib/skybouncer/skybouncer.db ".backup /var/backups/skybouncer-$(date +%Y%m%d%H%M%S).db"
```

```cron
0 3 * * * sqlite3 /var/lib/skybouncer/skybouncer.db ".backup /var/backups/skybouncer-$(date +\%F).db" && find /var/backups -name "skybouncer-*.db" -mtime +14 -delete
```

---

### Healthchecks & Telemetry Monitoring

Skybouncer exposes two observability endpoints (on `127.0.0.1:3031` for Docker Compose, or `127.0.0.1:3000` for systemd):

1. **Liveness / Readiness Probe**:
   ```bash
   curl -f http://127.0.0.1:3031/healthz
   # Response: HTTP 200 OK {"status":"healthy","version":"0.3.8"}
   ```

2. **Detailed Engine Telemetry** (requires authenticated Admin session or `SKYBOUNCER_API_TOKEN` for full unredacted stats):
   ```bash
   curl -s -H "Authorization: Bearer ${SKYBOUNCER_API_TOKEN}" http://127.0.0.1:3031/api/status | jq .
   ```
   *Returns real-time commit rates, bypass counts, violation counts, and PDS mutation statistics.*

---

### Emergency Unbanning & Pardon

If an account was incorrectly moderated:

1. **Via Web Dashboard**:
   Navigate to `https://moderation.example.com`, locate the violator in the Recent Bounces table, and click **Pardon**.

2. **Via REST API** (requires Admin session or `SKYBOUNCER_API_TOKEN`):
   ```bash
   curl -X POST http://127.0.0.1:3031/api/pardon \
     -H "Authorization: Bearer ${SKYBOUNCER_API_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{"subject_did": "did:plc:accounttoopen"}'
   ```

3. **Via ATProto DM Bot**:
   Direct-message your Skybouncer bot account from the Bluesky app:
   ```text
   pardon @handle.bsky.social
   ```
