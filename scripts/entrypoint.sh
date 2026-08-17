#!/bin/bash
set -euo pipefail

echo "[entrypoint] brahma-danda starting"
echo "[entrypoint] schedule: ${SCAN_SCHEDULE_CRON}"

# Render the real schedule into a writable crontab (image fs is read-only,
# so we write the rendered file into the tmpfs-backed /tmp instead).
RENDERED_CRON="/tmp/crontab"
sed "s|__SCHEDULE__|${SCAN_SCHEDULE_CRON}|" /app/crontab > "${RENDERED_CRON}"

# Run once immediately on first start so DevOps gets a Slack message right
# away to confirm the deployment worked, instead of waiting a month.
if [ "${RUN_ON_STARTUP:-true}" = "true" ]; then
  echo "[entrypoint] running initial scan now (set RUN_ON_STARTUP=false to skip)"
  /app/scripts/run_scan.sh || echo "[entrypoint] initial scan failed — check /app/reports/last_run.log"
fi

echo "[entrypoint] handing off to supercronic for scheduled monthly runs"
exec supercronic "${RENDERED_CRON}"
