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
    if /app/scripts/run_scan.sh; then
      # Only record first-boot success when the scan actually finished. If it
      # failed we deliberately leave the marker absent so the next boot retries
      # the initial scan rather than permanently skipping it.
      echo "[entrypoint] initial scan succeeded — recording first-boot marker"
      touch "${FIRST_BOOT_MARKER}"
    else
      rc=$?
      echo "[entrypoint] initial scan FAILED (exit ${rc}) — marker NOT set, will retry on next boot (check /app/reports/last_run.log)"
    fi
  else
    echo "[entrypoint] previous boot detected (marker exists) — skipping startup scan"
  fi
fi

echo "[entrypoint] handing off to supercronic for scheduled runs"
# Launch supercronic in the foreground (exec: it becomes PID 1, handles signals,
# and is the container's long-running process). It reads the rendered schedule
# we wrote to the tmpfs-backed /tmp. No system cron daemon, no /var/spool/cron
# spool, no PID1-as-cron pitfalls — supercronic is purpose-built to run a
# crontab inside a container.
#
# Scheduled runs go through the same Phase-4 concurrency lock in run_scan.sh, so
# a scheduled scan can never interleave with a manual or first-boot scan.
exec /usr/local/bin/supercronic "${RENDERED_CRON}"
