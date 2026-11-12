#!/bin/bash
# Orchestrates all scan tools against the read-only host mount at /host,
# writes raw + combined reports, then hands off to remediate.py for the
# Claude-generated priority plan + Slack post.
set -uo pipefail   # no -e: one tool failing shouldn't kill the whole run

# ── Phase 4: exclusive concurrency lock ─────────────────────────────────────
# Refuse to run a second scan while one is already in progress — a manual
# trigger overlapping a scheduled run, or a retry overlapping the first-boot
# scan — would otherwise interleave two runs against the same read-only host.
# The lock is held on fd 200 via flock, so it auto-releases on process exit
# (crash-safe: no stale lock is left behind). If flock is unavailable we fall
# back to an atomic mkdir(2) lock, cleaned up on exit via a trap. The lock file
# is /tmp/brahmadanda_scan.lock (set via BRAHMADANDA_LOCK) — /tmp is sticky
# world-writable 1777 tmpfs scratch, so the non-root 999 scan user can create
# it, and tmpfs means stale locks never accumulate on the persistent volume.
LOCKFILE="${BRAHMADANDA_LOCK:-/tmp/brahmadanda_scan.lock}"
mkdir -p "$(dirname "$LOCKFILE")" 2>/dev/null || true
LOCK_HELD=0
if command -v flock >/dev/null 2>&1; then
  # NOTE: do NOT append `2>/dev/null` here — a redirection-only `exec`
  # applies the redirect permanently to this shell, which would hide the
  # message below. We want fd 200 open (holds the lock); stderr stays as-is.
  if exec 200>"$LOCKFILE" && flock -n 200; then
    echo "[run_scan] acquired exclusive lock ${LOCKFILE}"
  else
    LOCK_HELD=1
  fi
else
  if mkdir "$LOCKFILE" 2>/dev/null; then
    trap 'rmdir "$LOCKFILE" 2>/dev/null || true' EXIT
    echo "[run_scan] acquired exclusive lock ${LOCKFILE} (mkdir fallback)"
  else
    LOCK_HELD=1
  fi
fi
if [ "$LOCK_HELD" -eq 1 ]; then
  echo "[run_scan] ${LOCKFILE} is locked by another scan — refusing to run concurrently" >&2
  exit 0
fi

# ── Cache refresh mode ──
REFRESH_CACHE=false
if [ "${1:-}" = "--refresh-cache" ]; then
    REFRESH_CACHE=true
    echo "[run_scan] cache-refresh mode — will only refresh Java DB, skip actual scan"
fi

TS="$(date -u +%Y-%m-%dT%H%M%SZ)"
REPORT_DIR="/app/reports/${TS}"
mkdir -p "${REPORT_DIR}"

# Phase 1: unique run id — 24 hex chars in MongoDB ObjectId format, so every
# artefact in this run's directory traces back to a single scan. `od` is used
# (not `xxd`) because it ships on the minimal Alpine base that carries trivy.
export SCAN_ID="$(LC_ALL=C head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 24)"

# ── Phase 0.1 / 1.x: run-scoped state inherited by every child process ────────
# Export REPORT_DIR so remediate.py and scripts/checks/*.sh all write into the
# SAME directory instead of each recomputing a timestamp (single source of
# truth — removes the "artefacts in mismatched timestamp dirs" bug class).
export REPORT_DIR

# LOG_LEVEL gates [run_scan]/[remediate] verbosity. DEBUG reveals the raw LLM
# request/response, HTTP status and stop_reason for every call (Phase 0.3).
_LOG_LEVEL_RAW="${LOG_LEVEL:-INFO}"
LOG_LEVEL="$(printf '%s' "${_LOG_LEVEL_RAW}" | tr '[:lower:]' '[:upper:]')"
case "${LOG_LEVEL}" in
    INFO|DEBUG) : ;;
    *)  LOG_LEVEL="INFO"
        echo "[run_scan] unknown LOG_LEVEL='${_LOG_LEVEL_RAW}' — defaulting to INFO" >&2 ;;
esac
export LOG_LEVEL

# ── Phase 0.2: stream run_scan.sh output to stdout AND a per-run log file ─────
# tee keeps container stdout intact (docker compose logs still sees this) while
# the file survives restarts. run_scan.log rides along with the raw artefacts
# when remediate.py uploads the thread (Phase 0).
exec > >(tee -a "${REPORT_DIR}/run_scan.log") 2>&1

HOST_LABEL="${HOSTNAME_OVERRIDE:-$(cat /host/etc/hostname 2>/dev/null || echo unknown-host)}"
echo "[run_scan] starting scan of ${HOST_LABEL} at ${TS} (LOG_LEVEL=${LOG_LEVEL})"

# ── 1. Trivy — OS package + known-CVE scan against the mounted host root ──
# Both the vuln DB and Java DB live at Trivy's DEFAULT cache dir,
# /root/.cache/trivy — which is the persistent trivy_cache named volume (see
# docker-compose.yml).  Do NOT point --cache-dir at /app/.trivy: /app is on
# the container's read-only rootfs, writes silently fail there, and the Java
# DB re-downloaded (and silently failed) on every single run.
JAVA_DB="/root/.cache/trivy/java-db/trivy-java.db"

# Pre-download Java DB if not already cached (one-time, ~907 MB).
# Stored in the persistent volume so restarts/rebuilds won't re-fetch it.
if [ ! -f "$JAVA_DB" ]; then
  echo "[run_scan] Java DB not found in cache — downloading once (this takes ~15m)..."
  # NOTE: no `|| true` — a swallowed failure here looked like success for
  # months ("stored persistently") while writing nothing.  pipefail is on.
  if trivy image --download-java-db-only 2>&1 | tail -5; then
    echo "[run_scan] Java DB download complete, stored persistently."
  else
    echo "[run_scan] WARNING: Java DB download FAILED — jar/war findings may be incomplete this run" >&2
  fi
else
  echo "[run_scan] Java DB already cached — skipping download."
fi

# slack_notify TEXT — post a run_scan notification to Slack and CHECK the
# response. Slack returns API errors as HTTP 200 + {"ok": false}, so a bare
# `curl -s ... >/dev/null` posts blind (2026-09-14: notifications silently
# vanished). Logs the error code on rejection; never fails the scan.
slack_notify() {
    local _tok=$(cat /run/secrets/slack_bot_token 2>/dev/null)
    local _ch="${SLACK_CHANNEL_ID:-}"
    [ -z "$_tok" ] || [ -z "$_ch" ] && return 0
    local _body
    _body=$(jq -n --arg c "$_ch" --arg t "$1" '{channel:$c,text:$t}') || { echo "[run_scan] WARNING: could not build Slack JSON" >&2; return 0; }
    local _resp
    _resp=$(curl -s --connect-timeout 10 --max-time 30 \
        -X POST "https://slack.com/api/chat.postMessage" \
        -H "Authorization: Bearer ${_tok}" \
        -H "Content-Type: application/json" \
        -d "$_body" 2>/dev/null)
    case "$_resp" in
        *'"ok":true'*) : ;;
        *) echo "[run_scan] WARNING: Slack notification rejected: ${_resp:-<no response>}" >&2 ;;
    esac
}

# ── Cache refresh complete — exit before actual scan ──
if [ "$REFRESH_CACHE" = true ]; then
    echo "[run_scan] cache refresh complete"
    # Send Slack notification
    slack_notify ":arrows_counterclockwise: *Java DB cache refreshed* for ${HOST_LABEL}
The Trivy Java vulnerability database has been successfully updated with the latest signatures. Next scan will use fresh data."
    exit 0
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
# These read-only probes need root.  The container runs as user: "0" (root), so
# sudo is normally NOT needed — and is in fact BROKEN here: docker-compose sets
# cap_drop: ALL (keeping only NET_RAW/NET_ADMIN/DAC_*), which removes CAP_SETUID,
# so sudo dies with "PERM_SUDOERS: setresuid(...): Operation not permitted" and
# every probe fell back to an error string (observed 2026-09-09: ufw/iptables/
# nftables artefacts were blank).  Resolve the privilege prefix ONCE: empty when
# already root (or sudo missing), "sudo" only when unprivileged and sudo exists
# (a future UID-999 deployment). All four probes are strictly read-only.
if [ "$(id -u)" -eq 0 ] || ! command -v sudo >/dev/null 2>&1; then
  SUDO=""
else
  SUDO="sudo"
fi
echo "[run_scan] gathering network exposure and firewall data (privilege prefix: '${SUDO:-<none>}')..."
${SUDO} ss -tlnp > "${REPORT_DIR}/ss_listeners.txt" 2>/dev/null || ss -tln > "${REPORT_DIR}/ss_listeners.txt"
${SUDO} ufw status verbose > "${REPORT_DIR}/ufw_status.txt" 2>/dev/null || echo "ufw not found or insufficient permissions" > "${REPORT_DIR}/ufw_status.txt"
${SUDO} iptables-save > "${REPORT_DIR}/iptables.txt" 2>/dev/null || echo "iptables-save failed" > "${REPORT_DIR}/iptables.txt"
${SUDO} nft list ruleset > "${REPORT_DIR}/nftables.txt" 2>/dev/null || echo "nft failed" > "${REPORT_DIR}/nftables.txt"

# ── 3.2b HOST UFW *configuration* (read from the read-only host mount) ──────
# `ufw status verbose` above reports the CONTAINER's own UFW: the image ships its
# own /etc/ufw, and an INACTIVE UFW prints NO per-port rules at all — so that
# probe can never reveal the HOST's intended firewall config ("Status: inactive"
# tells us nothing about which ports UFW is configured to allow/deny). Read the
# host's UFW config files directly from the read-only /host mount to capture the
# real ENABLED state, the default policies, and the FULL per-port ruleset even
# while UFW is inactive. Strictly read-only. We parse the files rather than run
# the host's `ufw` because the container drops CAP_SYS_CHROOT, so `chroot /host
# ufw …` is not possible — file parsing is the correct minimal-privilege path.
HOST_ROOT="${HOST_ROOT:-/host}"
# Render the host ruleset as the native `ufw status` To/Action/From table (with
# the source IP and the inline `# comment` ufw stores in each rule) using the
# parser in scripts/checks/. Fall back to a raw grep of the rule files if
# python3 is ever unavailable, so the artefact is always produced.
UFW_REPORT_PY="/app/scripts/checks/ufw_rules_report.py"
if command -v python3 >/dev/null 2>&1 && [ -r "$UFW_REPORT_PY" ]; then
  python3 "$UFW_REPORT_PY" "$HOST_ROOT" \
      "${REPORT_DIR}/iptables.txt" "${REPORT_DIR}/nftables.txt" \
      > "${REPORT_DIR}/ufw_rules.txt" 2>"${REPORT_DIR}/ufw_rules.stderr.log" \
    || { echo "ufw_rules_report.py failed — see ufw_rules.stderr.log" > "${REPORT_DIR}/ufw_rules.txt"; \
         echo "[run_scan] ⚠️ ufw_rules_report.py failed"; }
else
  {
    echo "# HOST UFW CONFIGURATION — raw rules (python3 unavailable; table renderer skipped)"
    echo "ENABLED: $(grep -E '^[[:space:]]*ENABLED=' "${HOST_ROOT}/etc/ufw/ufw.conf" 2>/dev/null || echo 'unknown')"
    for f in user.rules user6.rules; do
      echo "## ${HOST_ROOT}/etc/ufw/${f}"
      grep -E '^### tuple ###|^-A ufw-user-input|^-A ufw6-user-input' \
        "${HOST_ROOT}/etc/ufw/${f}" 2>/dev/null || echo "(none)"
    done
  } > "${REPORT_DIR}/ufw_rules.txt" 2>/dev/null
fi

# ── 4. nmap — self-scan of THIS host's real listening ports (needs network_mode: host,
#    see docker-compose.yml for the documented trade-off). Safe script categories by
#    default; dos/exploit/brute/fuzzer only if NMAP_ALLOW_INTRUSIVE=true. ──
if [ "${NMAP_SELF_SCAN:-true}" = "true" ]; then
  # No 'vuln' category — it's banner-grabbing CVE matching, a known source of
  # false positives on distro-packaged software. Trivy already does evidence-based
  # CVE detection from the package DB. We use behavioral probes instead.
  NMAP_CATEGORIES="${NMAP_SCRIPT_CATEGORIES:-default,safe,vuln,auth,version,malware}"
  NMAP_EXTRA="${NMAP_EXTRA_SCRIPTS:-}"  # Dynamic: reads from .env, empty by default in fallback
  if [ -n "$NMAP_EXTRA" ]; then
    NMAP_ALL="${NMAP_CATEGORIES},${NMAP_EXTRA}"
  else
    NMAP_ALL="${NMAP_CATEGORIES}"
  fi
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

# ── Phase 1: write a run manifest so each scan is traceable to its scan_id and
#    every artefact can be reproduced/audited. Written BEFORE the remediation
#    step so remediate.py can read it (as reference — never as an input) and
#    attach it to the Slack thread. Version probes are best-effort: a tool that
#    is not installed simply leaves its field empty, never fatal (no set -e). ──
SCAN_TRIVY="$(trivy --version 2>/dev/null | awk '{print $3}' | tr -d '"' || true)"
SCAN_DEBSECAN="$(debsecan --version 2>/dev/null | head -1 | tr -d '"' || true)"
SCAN_NMAP="$(nmap --version 2>/dev/null | head -1 | tr -d '"' || true)"
SCAN_LYNIS="$(lynis --version 2>/dev/null | tr -d '"' || true)"
jq -n \
  --arg scan_id "${SCAN_ID}" \
  --arg scanned_at "${TS}" \
  --arg host_label "${HOST_LABEL}" \
  --arg trivy "${SCAN_TRIVY}" \
  --arg debsecan "${SCAN_DEBSECAN}" \
  --arg nmap "${SCAN_NMAP}" \
  --arg lynis "${SCAN_LYNIS}" \
  '{scan_id: $scan_id, scanned_at: $scanned_at, host_label: $host_label,
    scan_tools: {trivy: $trivy, debsecan: $debsecan, nmap: $nmap, lynis: $lynis}}' \
  > "${REPORT_DIR}/.scan_manifest.json"
echo "[run_scan] scan_id=${SCAN_ID} manifest written to .scan_manifest.json"

# ── 6. Hand off to Claude for the prioritized remediation plan + Slack post ──
python3 /app/scripts/remediate.py --report-dir "${REPORT_DIR}" --host "${HOST_LABEL}"
REMEDIATE_EXIT=$?

# ── 7. Slack notification for scan completion ──
SLACK_TOKEN=$(cat /run/secrets/slack_bot_token 2>/dev/null)
CHANNEL="${SLACK_CHANNEL_ID:-}"
if [ -n "$SLACK_TOKEN" ] && [ -n "$CHANNEL" ]; then
    if [ $REMEDIATE_EXIT -eq 0 ]; then
        slack_notify ":white_check_mark: *Scan completed successfully* for ${HOST_LABEL}
Reports and remediation plan posted to Slack."
    else
        slack_notify ":x: *Scan failed* for ${HOST_LABEL}
Remediation step exited with code ${REMEDIATE_EXIT}. Check logs for details."
    fi
fi

echo "[run_scan] done"
exit $REMEDIATE_EXIT
