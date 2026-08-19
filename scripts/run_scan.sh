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
# Both the vuln DB and Java DB are stored in the persistent trivy_cache volume
# at /root/.cache/trivy. Neither will re-download on container restarts.
mkdir -p /root/.cache/trivy 2>/dev/null || true

# Pre-download Java DB if not already cached (one-time, ~907 MB).
# Stored in persistent volume so restarts/rebuilds won't re-fetch it.
if [ ! -f "/root/.cache/trivy/java-db/trivy-java.db" ]; then
  echo "[run_scan] Java DB not found in cache — downloading once (this takes ~15m)..."
  trivy image --download-java-db-only --cache-dir /root/.cache/trivy 2>&1 | tail -5 || true
  echo "[run_scan] Java DB download complete, stored persistently."
else
  echo "[run_scan] Java DB already cached — skipping download."
fi

echo "[run_scan] running trivy rootfs scan..."
trivy rootfs /host \
  --format json \
  --severity CRITICAL,HIGH,MEDIUM \
  --pkg-types os \
  --scanners vuln \
  --skip-version-check \
  --skip-dirs /host/proc,/host/sys,/host/dev,/host/tmp,/host/var/lib/docker,/host/root,/host/var/lib,/host/etc/ssh,/host/etc/ssl,/host/var/log,/host/var/ossec \
  --timeout 30m \
  --output "${REPORT_DIR}/trivy.json" \
  2> "${REPORT_DIR}/trivy.stderr.log" \
  || echo "[run_scan] trivy exited non-zero, continuing (see trivy.stderr.log)"

# Validate Trivy output is non-empty
if [ ! -s "${REPORT_DIR}/trivy.json" ]; then
  echo "[run_scan] ⚠️ ERROR: trivy.json is empty — Trivy scan failed"
fi

# ── 2. debsecan — Debian-tracker cross-check against the real dpkg status file ──
echo "[run_scan] running debsecan (best-effort)..."
if [ -f /host/var/lib/dpkg/status ]; then
  debsecan --status-file /host/var/lib/dpkg/status --format detail \
    > "${REPORT_DIR}/debsecan.txt" 2>"${REPORT_DIR}/debsecan.stderr.log" \
    || echo "[run_scan] debsecan finished with non-zero exit (often just 'suite mismatch' on Ubuntu, non-fatal)"
else
  echo "no dpkg status file found — not a Debian/Ubuntu host, skipping" > "${REPORT_DIR}/debsecan.txt"
fi

# ── 3. Config hardening checks — SSH + nginx + Docker, against real host config files ──
echo "[run_scan] running config checks..."
/app/scripts/checks/ssh_checks.sh /host > "${REPORT_DIR}/ssh_checks.json"
/app/scripts/checks/nginx_checks.sh /host > "${REPORT_DIR}/nginx_checks.json"
/app/scripts/docker_checks.sh "${REPORT_DIR}/docker_checks.json"

# ── 3.1 Host Hardening (Lynis) ──
echo "[run_scan] running lynis..."
# Run lynis in non-privileged mode as best effort.
lynis audit system --quick --pentest --logfile "${REPORT_DIR}/lynis.log" --report-file "${REPORT_DIR}/lynis-report.dat" > /dev/null 2>&1 || true

# ── 3.2 Network Exposure / Firewall ──
echo "[run_scan] gathering network exposure and firewall data..."
ss -tlnp > "${REPORT_DIR}/ss_listeners.txt" 2>/dev/null || ss -tln > "${REPORT_DIR}/ss_listeners.txt"
ufw status verbose > "${REPORT_DIR}/ufw_status.txt" 2>/dev/null || echo "ufw not found or insufficient permissions" > "${REPORT_DIR}/ufw_status.txt"
iptables-save > "${REPORT_DIR}/iptables.txt" 2>/dev/null || echo "iptables-save failed" > "${REPORT_DIR}/iptables.txt"
nft list ruleset > "${REPORT_DIR}/nftables.txt" 2>/dev/null || echo "nft failed" > "${REPORT_DIR}/nftables.txt"

# ── 4. nmap — self-scan of THIS host's real listening ports (needs network_mode: host,
#    see docker-compose.yml for the documented trade-off). Safe script categories by
#    default; dos/exploit/brute/fuzzer only if NMAP_ALLOW_INTRUSIVE=true. ──
if [ "${NMAP_SELF_SCAN:-true}" = "true" ]; then
  # No 'vuln' category — it's banner-grabbing CVE matching, a known source of
  # false positives on distro-packaged software. Trivy already does evidence-based
  # CVE detection from the package DB. We use behavioral probes instead.
  NMAP_CATEGORIES="${NMAP_SCRIPT_CATEGORIES:-default,discovery,safe}"
  NMAP_EXTRA="${NMAP_EXTRA_SCRIPTS:-ssh-auth-methods,ssh-hostkey,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,ftp-anon,smtp-open-relay,smb-security-mode,smb2-security-mode,mysql-empty-password,redis-info,http-methods}"
  NMAP_ALL="${NMAP_CATEGORIES},${NMAP_EXTRA}"
  if [ "${NMAP_ALLOW_INTRUSIVE:-false}" = "true" ]; then
    echo "[run_scan] ⚠️ NMAP_ALLOW_INTRUSIVE=true — including exploit,dos,brute,fuzzer scripts"
    echo "[run_scan] ⚠️ this WILL actively attack services on this host, confirm maintenance window"
    NMAP_ALL="${NMAP_ALL},exploit,dos,brute,fuzzer"
  fi
  echo "[run_scan] running nmap self-scan (categories: ${NMAP_ALL})..."
  nmap -sV -sC \
    --script "${NMAP_ALL}" \
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
  else
    # ── 4.1 testssl.sh on discovered TLS ports ──
    echo "[run_scan] extracting TLS ports for testssl.sh..."
    TLS_PORTS=$(python3 -c '
import xml.etree.ElementTree as ET, sys
try:
    for p in ET.parse(sys.argv[1]).findall(".//port"):
        if p.find("state").get("state") == "open":
            svc = p.find("service")
            if svc is not None and (svc.get("tunnel") == "ssl" or "ssl" in svc.get("name", "")):
                print(p.get("portid"))
except:
    pass
' "${REPORT_DIR}/nmap.xml")

    for port in $TLS_PORTS; do
      echo "[run_scan] running testssl.sh on port $port..."
      # Use JSON output, ignore the testssl.sh warnings about being run as root if applicable, use --quiet to limit stdout spam
      testssl.sh --quiet --jsonfile "${REPORT_DIR}/testssl_${port}.json" "localhost:${port}" >/dev/null 2>&1 || true
    done
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
  --slurpfile docker "${REPORT_DIR}/docker_checks.json" \
  '{host: $host, scanned_at: $ts, ssh_checks: $ssh[0], nginx_checks: $nginx[0], docker_checks: $docker[0]}' \
  > "${REPORT_DIR}/combined_meta.json"

echo "[run_scan] raw reports written to ${REPORT_DIR}"

# ── 6. Hand off to Claude for the prioritized remediation plan + Slack post ──
python3 /app/scripts/remediate.py --report-dir "${REPORT_DIR}" --host "${HOST_LABEL}"

echo "[run_scan] done"
