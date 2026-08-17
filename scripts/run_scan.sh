#!/bin/bash
# Orchestrates all scan tools against the read-only host mount at /host,
# writes raw + combined reports, then hands off to remediate.py for the
# Claude-generated priority plan + Slack post.
set -uo pipefail   # no -e: one tool failing shouldn't kill the whole run

TS="$(date -u +%Y-%m-%dT%H%M%SZ)"
REPORT_DIR="/app/reports/${TS}"
mkdir -p "${REPORT_DIR}"

HOST_LABEL="${HOSTNAME_OVERRIDE:-$(cat /host/etc/hostname 2>/dev/null || echo unknown-host)}"
echo "[run_scan] starting scan of ${HOST_LABEL} at ${TS}"

# ── 1. Trivy — OS package + known-CVE scan against the mounted host root ──
# Pre-create trivy cache dir — /home/brahmadanda/.cache is a tmpfs owned by root
# so trivy (running as brahmadanda) can't mkdir inside it. Also ensure /tmp/trivy
# is writable since some trivy versions fall back to ~/.cache/trivy.
mkdir -p /home/brahmadanda/.cache/trivy 2>/dev/null || true
mkdir -p /tmp/trivy 2>/dev/null || true
# Also fix ownership on the tmpfs cache dir (we can't chown without CAP_CHOWN,
# but we can mkdir it as root... actually we run as brahmadanda. So we need the
# volume mount instead — see docker-compose.yml trivy_cache).
echo "[run_scan] running trivy rootfs scan..."
trivy rootfs /host \
  --format json \
  --severity CRITICAL,HIGH,MEDIUM \
  --scanners vuln \
  --skip-dirs /host/proc,/host/sys,/host/dev,/host/tmp,/host/var/lib/docker \
  --timeout 30m \
  --output "${REPORT_DIR}/trivy.json" \
  2> "${REPORT_DIR}/trivy.stderr.log" \
  || echo "[run_scan] trivy exited non-zero, continuing (see trivy.stderr.log)"

# Validate Trivy output is non-empty
if [ ! -s "${REPORT_DIR}/trivy.json" ]; then
  echo "[run_scan] ⚠️ ERROR: trivy.json is empty — Trivy scan failed"
fi

# ── 2. debsecan — Debian-tracker cross-check against the real dpkg status file ──
# NOTE: debsecan's default feed is Debian's security tracker. On Ubuntu hosts
# this is a best-effort cross-check, not authoritative — Trivy is the primary
# source of truth here since its DB properly covers Ubuntu's own patch levels.
echo "[run_scan] running debsecan (best-effort)..."
if [ -f /host/var/lib/dpkg/status ]; then
  debsecan --status-file /host/var/lib/dpkg/status --format detail \
    > "${REPORT_DIR}/debsecan.txt" 2>"${REPORT_DIR}/debsecan.stderr.log" \
    || echo "[run_scan] debsecan finished with non-zero exit (often just 'suite mismatch' on Ubuntu, non-fatal)"
else
  echo "no dpkg status file found — not a Debian/Ubuntu host, skipping" > "${REPORT_DIR}/debsecan.txt"
fi

# ── 3. Config hardening checks — SSH + nginx, against real host config files ──
echo "[run_scan] running config checks..."
/app/scripts/checks/ssh_checks.sh /host > "${REPORT_DIR}/ssh_checks.json"
/app/scripts/checks/nginx_checks.sh /host > "${REPORT_DIR}/nginx_checks.json"

# ── 4. nmap — self-scan of THIS host's real listening ports (needs network_mode: host,
#    see docker-compose.yml for the documented trade-off). Safe script categories by
#    default; dos/exploit/brute/fuzzer only if NMAP_ALLOW_INTRUSIVE=true. ──
if [ "${NMAP_SELF_SCAN:-true}" = "true" ]; then
  NMAP_CATEGORIES="${NMAP_SCRIPT_CATEGORIES:-default,discovery,safe,vuln,auth}"
  if [ "${NMAP_ALLOW_INTRUSIVE:-false}" = "true" ]; then
    echo "[run_scan] ⚠️ NMAP_ALLOW_INTRUSIVE=true — including exploit,dos,brute,fuzzer scripts"
    echo "[run_scan] ⚠️ this WILL actively attack services on this host, confirm maintenance window"
    NMAP_CATEGORIES="${NMAP_CATEGORIES},exploit,dos,brute,fuzzer"
  fi
  echo "[run_scan] running nmap self-scan (categories: ${NMAP_CATEGORIES})..."
  nmap -sV -sC \
    --script "${NMAP_CATEGORIES}" \
    -p- \
    --max-retries 2 \
    --host-timeout 20m \
    -oX "${REPORT_DIR}/nmap.xml" \
    -oN "${REPORT_DIR}/nmap.txt" \
    localhost \
    2> "${REPORT_DIR}/nmap.stderr.log" \
    || echo "[run_scan] nmap exited non-zero, continuing (see nmap.stderr.log)"

  # Validate nmap output is non-empty
  if [ ! -s "${REPORT_DIR}/nmap.xml" ]; then
    echo "[run_scan] ⚠️ ERROR: nmap.xml is empty — nmap scan failed"
  fi
else
  echo "[run_scan] NMAP_SELF_SCAN=false, skipping port scan"
fi

# ── 5. Combine everything into one manifest for the remediation step ──
jq -n \
  --arg host "${HOST_LABEL}" \
  --arg ts "${TS}" \
  --slurpfile ssh "${REPORT_DIR}/ssh_checks.json" \
  --slurpfile nginx "${REPORT_DIR}/nginx_checks.json" \
  '{host: $host, scanned_at: $ts, ssh_checks: $ssh[0], nginx_checks: $nginx[0]}' \
  > "${REPORT_DIR}/combined_meta.json"

echo "[run_scan] raw reports written to ${REPORT_DIR}"

# ── 6. Hand off to Claude for the prioritized remediation plan + Slack post ──
python3 /app/scripts/remediate.py --report-dir "${REPORT_DIR}" --host "${HOST_LABEL}"

echo "[run_scan] done"
