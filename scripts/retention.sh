#!/bin/bash
# scripts/retention.sh
# ---------------------
# Bounded retention for scan reports. Each scan creates one timestamped
# directory under the reports root (YYYY-MM-DDThhmmssZ). This keeps the N most
# recent report directories and deletes the rest — a deterministic, bounded
# replacement for the old "keep the 199 newest files, wipe the rest" ad-hoc
# hourly cleanup, which had no lower bound and ran every hour.
#
# Scheduled via supercronic (see crontab). Non-fatal: a missing root or a
# single bad directory is logged, not fatal (no set -e), so a scheduled job
# can never take the container down.
#
# Config:
#   REPORT_DIR        reports root       (default /app/reports)
#   RETENTION_KEEP    dirs to keep (>=1) (default 12)
set -uo pipefail

REPORT_DIR="${REPORT_DIR:-/app/reports}"
KEEP="${RETENTION_KEEP:-12}"

# Guard: refuse to operate on a misconfigured or empty REPORT_DIR — safer to log
# and exit than to `rm -rf` the wrong place.
if [ -z "${REPORT_DIR}" ] || [ ! -d "${REPORT_DIR}" ]; then
  echo "[retention] reports root ${REPORT_DIR:-<empty>} not found — nothing to do" >&2
  exit 0
fi

# KEEP must be a positive integer.
case "${KEEP}" in
  (*[!0-9]*|"") echo "[retention] invalid RETENTION_KEEP='${KEEP}' — defaulting to 12" >&2; KEEP=12 ;;
esac
[ "$KEEP" -ge 1 ] || KEEP=1

# Timestamped report dirs, newest first. Names are ISO-ish timestamps so a plain
# reverse lexicographic sort orders them newest→oldest. Hidden files (marker,
# manifest) and non-dir artefacts are excluded by -type d / -mindepth 1.
mapfile -t dirs < <(find "${REPORT_DIR}" -mindepth 1 -maxdepth 1 -type d | sort -r)

echo "[retention] keeping ${KEEP} newest report dir(s) under ${REPORT_DIR} (${#dirs[@]} found)"

if [ "${#dirs[@]}" -le "$KEEP" ]; then
  echo "[retention] nothing to delete"
  exit 0
fi

count=0
for d in "${dirs[@]}"; do
  if [ "$count" -ge "$KEEP" ]; then
    if rm -rf "${d}" 2>/dev/null; then
      echo "[retention] deleted old report dir: ${d}"
    else
      echo "[retention] ⚠️ failed to delete ${d}" >&2
    fi
  fi
  count=$((count + 1))
done
