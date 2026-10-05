#!/usr/bin/env bash
# ==============================================================================
# Script: backup.sh
# Purpose: Takes a consistent online backup of the Skybouncer SQLite database
#          from its Docker named volume, verifies integrity, compresses it, and
#          prunes old snapshots (default: keep the last 5 daily backups).
#
# Notes:
#   - Uses SQLite's online backup API (`.backup`), so it is safe to run while
#     the service is live and using WAL mode.
#   - Runs an ephemeral container from the already-present `skybouncer` image
#     (which bundles sqlite3 + gzip) with the data volume mounted; the app
#     container does not need to be running.
# ==============================================================================

set -euo pipefail

# ------------------------------- Configuration --------------------------------
# Overridable via environment variables (e.g. in cron).
BACKUP_DIR="${SKYBOUNCER_BACKUP_DIR:-/home/mike10010100/backups/skybouncer}"
RETAIN="${SKYBOUNCER_BACKUP_RETAIN:-5}"
VOLUME_NAME="${SKYBOUNCER_VOLUME:-skybouncer_data}"
DB_NAME="${SKYBOUNCER_DB_NAME:-skybouncer.db}"
IMAGE="${SKYBOUNCER_IMAGE:-skybouncer:latest}"
LOCK_FILE="${SKYBOUNCER_BACKUP_LOCK:-${BACKUP_DIR}/.backup.lock}"

# Preserve ownership of created files to the invoking user (cron runs as them).
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
STAMP="$(date +%F)"
ARCHIVE_NAME="skybouncer-${STAMP}.db.gz"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S%z')] $*"
}

fail() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S%z')] ERROR: $*" >&2
    exit 1
}

# ------------------------------- Preflight ------------------------------------
command -v docker >/dev/null 2>&1 || fail "docker is not installed or not on PATH"

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    fail "Docker image '${IMAGE}' not found. Deploy the service first (scripts/deploy.sh)."
fi

if ! docker volume inspect "${VOLUME_NAME}" >/dev/null 2>&1; then
    fail "Docker volume '${VOLUME_NAME}' not found."
fi

mkdir -p "${BACKUP_DIR}"

# ------------------------------- Locking --------------------------------------
# Prevent overlapping runs (e.g. a slow run and the next cron tick).
exec 9>"${LOCK_FILE}"
if command -v flock >/dev/null 2>&1; then
    flock -n 9 || fail "Another backup is already in progress (lock: ${LOCK_FILE})."
fi

# ------------------------------- Backup ---------------------------------------
log "Starting Skybouncer backup (volume=${VOLUME_NAME}, db=${DB_NAME}, retain=${RETAIN})"

# The script runs inside the container as root so it can read the appuser-owned
# volume files and delete/prune older backups, then chowns outputs to the host
# user so crontab-owned retention works. The trailing `; exit` ensures the
# container reflects any failure in the embedded script.
docker run --rm \
    --user 0:0 \
    -v "${VOLUME_NAME}:/data" \
    -v "${BACKUP_DIR}:/backup" \
    -e "BACKUP_ARCHIVE=${ARCHIVE_NAME}" \
    -e "BACKUP_RETAIN=${RETAIN}" \
    -e "BACKUP_DB_NAME=${DB_NAME}" \
    -e "BACKUP_HOST_UID=${HOST_UID}" \
    -e "BACKUP_HOST_GID=${HOST_GID}" \
    --entrypoint sh "${IMAGE}" -c '
        set -eu
        SRC="/data/${BACKUP_DB_NAME}"
        TMP="/backup/.${BACKUP_ARCHIVE%.gz}.tmp"
        DEST="/backup/${BACKUP_ARCHIVE}"

        if [ ! -f "${SRC}" ]; then
            echo "ERROR: database not found at ${SRC}" >&2
            exit 1
        fi

        # 1. Consistent online backup (safe while WAL-mode DB is in use).
        rm -f "${TMP}" "${TMP}-journal" "${TMP}-wal" "${TMP}-shm"
        sqlite3 "${SRC}" ".backup ${TMP}"

        # 2. Verify the backup is not corrupt before we trust it.
        INTEGRITY="$(sqlite3 "${TMP}" "PRAGMA integrity_check;")"
        if [ "${INTEGRITY}" != "ok" ]; then
            echo "ERROR: integrity_check failed on backup: ${INTEGRITY}" >&2
            rm -f "${TMP}"
            exit 1
        fi

        # 3. Compress atomically.
        gzip -c "${TMP}" > "${DEST}.part"
        mv "${DEST}.part" "${DEST}"
        rm -f "${TMP}"

        # 4. Prune to the newest ${BACKUP_RETAIN} snapshots.
        cd /backup
        KEEP="${BACKUP_RETAIN}"
        # Newest-first by filename (date-stamped), drop everything past the cap.
        ls -1 skybouncer-*.db.gz 2>/dev/null | sort -r | tail -n +"$((KEEP + 1))" | while IFS= read -r old; do
            echo "Pruning old backup: ${old}"
            rm -f -- "${old}"
        done

        # 5. Restore host ownership on remaining artifacts.
        chown "${BACKUP_HOST_UID}:${BACKUP_HOST_GID}" "${DEST}" 2>/dev/null || true
        chown "${BACKUP_HOST_UID}:${BACKUP_HOST_GID}" skybouncer-*.db.gz 2>/dev/null || true
    '

# ------------------------------- Postflight -----------------------------------
[ -f "${BACKUP_DIR}/${ARCHIVE_NAME}" ] || fail "Backup archive was not created: ${BACKUP_DIR}/${ARCHIVE_NAME}"

SIZE="$(du -h "${BACKUP_DIR}/${ARCHIVE_NAME}" | cut -f1)"
log "Backup complete: ${BACKUP_DIR}/${ARCHIVE_NAME} (${SIZE})"

REMAINING="$(find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'skybouncer-*.db.gz' | wc -l | tr -d ' ')"
log "Retained ${REMAINING} snapshot(s) in ${BACKUP_DIR}"
