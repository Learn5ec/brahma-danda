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

# ── Boot self-check: make per-server scheduling/config divergence obvious ──
# When several servers "behave differently", the deciding facts are all visible
# from inside ONE container. Print them at boot so `docker logs brahma-danda`
# shows at a glance: the schedule that actually got rendered, the container
# clock/TZ, the LLM model + backend, and whether secrets/volume/lock/supercronic
# are in a runnable state. Every line is best-effort (guarded) — this NEVER
# blocks or aborts startup, even if a check command fails.
echo "[entrypoint][self-check] ── scheduling & config ──────────────────────"
echo "[entrypoint][self-check] rendered schedule : $(head -n1 "${RENDERED_CRON}" 2>/dev/null || echo '(unreadable)')"
echo "[entrypoint][self-check] SCAN_SCHEDULE_CRON   : ${SCAN_SCHEDULE_CRON:-<unset>}"
echo "[entrypoint][self-check] container clock (UTC): $(date -u '+%Y-%m-%d %H:%M:%S' 2>/dev/null)  TZ=${TZ:-<unset, defaults to UTC>}"
_diag_model="${ANTHROPIC_MODEL:-${CLAUDE_MODEL:-}}"
if [ -n "${ANTHROPIC_BASE_URL:-}" ]; then
  echo "[entrypoint][self-check] LLM backend        : gateway ${ANTHROPIC_BASE_URL}"
else
  echo "[entrypoint][self-check] LLM backend        : Anthropic cloud (no ANTHROPIC_BASE_URL)"
fi
if [ -n "${_diag_model}" ]; then
  echo "[entrypoint][self-check] LLM model          : ${_diag_model}  (must be a model the backend actually serves — a wrong id → fatal 404, no report)"
else
  echo "[entrypoint][self-check] LLM model          : <unset → remediate.py falls back to 'claude-sonnet-5'; ⚠️ custom gateways often don't serve it>"
fi
if [ -z "${ANTHROPIC_MODEL:-}" ] && [ -z "${CLAUDE_MODEL:-}" ] && [ -z "${OLLAMA_BASE_URL:-}" ]; then
  echo "[entrypoint][self-check] ⚠️  no ANTHROPIC_MODEL/CLAUDE_MODEL and no Ollama configured — remediation is likely to fail."
fi
echo "[entrypoint][self-check] secrets            : slack_bot_token=$( [ -r /run/secrets/slack_bot_token ] && echo OK || echo MISSING)  claude_api_key=$( [ -r /run/secrets/claude_api_key ] && echo present || echo absent)"
if mkdir -p /app/reports/.selfcheck 2>/dev/null; then
  rmdir /app/reports/.selfcheck 2>/dev/null || true
  echo "[entrypoint][self-check] reports volume     : writable"
else
  echo "[entrypoint][self-check] ⚠️  reports volume NOT writable (scans will fail to persist)"
fi
if [ -f /tmp/brahmadanda_scan.lock ]; then
  echo "[entrypoint][self-check] scan lock          : PRESENT — a scan may be running OR wedged (rm -f /tmp/brahmadanda_scan.lock if stale)"
else
  echo "[entrypoint][self-check] scan lock          : free"
fi
echo "[entrypoint][self-check] supercronic        : $( [ -x /usr/local/bin/supercronic ] && echo present || echo 'MISSING — scheduled runs will NOT fire' )"
echo "[entrypoint][self-check] ─────────────────────────────────────────────"

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
