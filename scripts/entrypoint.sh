#!/bin/bash
set -euo pipefail

echo "[entrypoint] brahma-danda starting"

echo "[entrypoint] schedule: ${SCAN_SCHEDULE_CRON}"

# Render the real schedule into a writable crontab (image fs is read-only,
# so we write the rendered file into the tmpfs-backed /tmp instead).
RENDERED_CRON="/tmp/crontab"
sed "s|__SCHEDULE__|${SCAN_SCHEDULE_CRON}|" /app/crontab > "${RENDERED_CRON}"

# First-boot detection: only run initial scan if no previous runs exist
if [ "${RUN_ON_STARTUP:-true}" = "true" ]; then
  FIRST_BOOT_MARKER="/app/reports/.first_boot_marker"
  if [ ! -f "${FIRST_BOOT_MARKER}" ]; then
    echo "[entrypoint] first boot detected — running initial scan"
    /app/scripts/run_scan.sh || echo "[entrypoint] initial scan failed — check /app/reports/last_run.log"
    # Create marker so subsequent restarts don't re-trigger
    touch "${FIRST_BOOT_MARKER}"
  else
    echo "[entrypoint] previous boot detected (marker exists) — skipping startup scan"
  fi
fi

echo "[entrypoint] handing off to cron daemon for scheduled runs"
# Install rendered crontab and start cron in background
crontab "${RENDERED_CRON}"
cron
echo "[entrypoint] cron started"
# Keep container alive - wait for any child process or sleep indefinitely
exec tail -f /dev/null
