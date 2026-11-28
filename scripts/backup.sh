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
BACKUP_DIR="${SKYBOUNCER_BACKUP_DIR:-${HOME}/backups/skybouncer}"
RETAIN="${SKYBOUNCER_BACKUP_RETAIN:-5}"
VOLUME_NAME="${SKYBOUNCER_VOLUME:-skybouncer_data}"
DB_NAME="${SKYBOUNCER_DB_NAME:-skybouncer.db}"
IMAGE="${SKYBOUNCER_IMAGE:-skybouncer:latest}"
LOCK_FILE="${SKYBOUNCER_BACKUP_LOCK:-${BACKUP_DIR}/.backup.lock}"

STAMP="$(date +%F-%H%M%S)"
ARCHIVE_NAME="skybouncer-${STAMP}.db.gz"
DEST_FILE="${BACKUP_DIR}/${ARCHIVE_NAME}"
PART_FILE="${DEST_FILE}.part.$$"

cleanup() {
    rm -f "${PART_FILE:-}"
}
trap cleanup EXIT

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

umask 077
mkdir -p "${BACKUP_DIR}"
chmod 0700 "${BACKUP_DIR}"

# ------------------------------- Locking --------------------------------------
# Prevent overlapping runs (e.g. a slow run and the next cron tick).
exec 9>"${LOCK_FILE}"
if command -v flock >/dev/null 2>&1; then
    flock -n 9 || fail "Another backup is already in progress (lock: ${LOCK_FILE})."
fi

# ------------------------------- Backup ---------------------------------------
log "Starting Skybouncer backup (volume=${VOLUME_NAME}, db=${DB_NAME}, retain=${RETAIN})"

# Run inside the container as appuser (10001:10001) mounting ONLY the data volume so
# WAL/SHM files never become root-owned, and stream verified gzipped bytes to stdout
# into a host-owned 0600 archive.
docker run --rm \
    --user 10001:10001 \
    -v "${VOLUME_NAME}:/data" \
    -e "BACKUP_DB_NAME=${DB_NAME}" \
    --entrypoint sh "${IMAGE}" -c '
        set -eu
        SRC="/data/${BACKUP_DB_NAME}"
        TMP="/tmp/skybouncer-backup.$$.db"
        trap '\''rm -f "${TMP}" "${TMP}-journal" "${TMP}-wal" "${TMP}-shm"'\'' EXIT

        if [ ! -f "${SRC}" ]; then
            echo "ERROR: database not found at ${SRC}" >&2
            exit 1
        fi

        # 1. Consistent online backup (safe while WAL-mode DB is in use).
        rm -f "${TMP}" "${TMP}-journal" "${TMP}-wal" "${TMP}-shm"
        sqlite3 -cmd ".timeout 5000" "${SRC}" ".backup ${TMP}"

        # 2. Verify the backup is not corrupt before streaming.
        INTEGRITY="$(sqlite3 "${TMP}" "PRAGMA integrity_check;")"
        if [ "${INTEGRITY}" != "ok" ]; then
            echo "ERROR: integrity_check failed on backup: ${INTEGRITY}" >&2
            exit 1
        fi

        # 3. Stream compressed archive to stdout.
        gzip -c "${TMP}"
    ' > "${PART_FILE}"

mv "${PART_FILE}" "${DEST_FILE}"
chmod 0600 "${DEST_FILE}"

# Prune to the newest ${RETAIN} snapshots on host.
while IFS= read -r old; do
    [ -n "${old}" ] || continue
    log "Pruning old backup: ${old}"
    rm -f -- "${BACKUP_DIR}/${old}"
done < <(find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'skybouncer-*.db.gz' -printf '%f\n' | sort -r | tail -n +"$((RETAIN + 1))")

# ------------------------------- Postflight -----------------------------------
[ -f "${DEST_FILE}" ] || fail "Backup archive was not created: ${DEST_FILE}"

SIZE="$(du -h "${DEST_FILE}" | cut -f1)"
log "Backup complete: ${DEST_FILE} (${SIZE})"

REMAINING="$(find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'skybouncer-*.db.gz' | wc -l | tr -d ' ')"
log "Retained ${REMAINING} snapshot(s) in ${BACKUP_DIR}"
