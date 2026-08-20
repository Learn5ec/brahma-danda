# brahma-danda

> The Brahmadanda is a supreme divine staff created by Lord Brahma. Unlike
> offensive celestial weapons meant for destruction, it functions as an
> absolute defensive shield. Accessible exclusively through immense spiritual
> power, it represents the ultimate authority of cosmic law and righteousness.

**Brahma-Danda** draws its name and philosophy from this divine staff. Just as
the Brahmadanda absorbs and neutralizes any celestial attack without firing a
single blow, this tool stands as a **purely defensive** security layer for
your servers. It doesn't patch, exploit, or modify anything on the host —
it only observes, analyzes, and reports.

**Core Principles (inspired by the divine staff):**

- **Pure Defense Only:** Like Vashistha using the Brahmadanda to neutralize
  the Brahmastra, this agent detects and repels threats through observation
  alone. Zero offensive capabilities. Zero host modifications. The host
  filesystem is mounted **read-only** (`/:/host:ro`). The agent can audit
  but never alter.

- **Absorbs Any Attack:** Whether it's CVEs from Trivy, config drift from
  Lynis, open ports from nmap, or misconfigured SSH/nginx/Docker — all scan
  data flows into one pipeline. Like the Brahmadanda absorbing the Brahmastra,
  every attack vector is detected, categorized, and reported before it
  becomes an incident.

- **Authority of Cosmic Law:** The agent enforces security best practices
  (NIST, CIS benchmarks, vendor hardening guides) as its "cosmic law."
  Findings are ranked by severity so the human reviewer can prioritize
  remediation with full context.

## What it actually checks

| Tool | What it does | Why |
|---|---|---|
| **Trivy** (`rootfs` scan) | OS package CVEs against the real installed versions | Primary source of truth — matches actual patch level, not just a version banner |
| **debsecan** | Debian security-tracker cross-check | Best-effort secondary check. On Ubuntu hosts this is *not* authoritative (Ubuntu maintains its own patch levels) — Trivy wins if they disagree |
| **SSH config check** | `PermitRootLogin`, `PasswordAuthentication`, `LoginGraceTime`, `MaxAuthTries`, `X11Forwarding` | Config-level hardening, not just CVEs |
| **nginx config check** | HSTS, CSP, `X-Frame-Options`, `server_tokens`, TLS version, rate limiting | Same, for the web layer |
| **nmap** (self-scan, NSE scripts) | Real open ports on this host + CVE-detection scripts, `default,safe,vuln,auth,version,malware` categories + behavioral probes | Same category of check as your original manual scan — Claude is prompted to flag distro-backport false positives instead of trusting the banner |
| **Claude / Ollama** | Reads all of the above, writes the prioritized plan | Turns raw tool output into "fix this first, here's the exact command" |

## What it actually checks

| Tool | What it does | Why |
|---|---|---|
| **Trivy** (`rootfs` scan) | OS package CVEs against the real installed versions | Primary source of truth — matches actual patch level, not just a version banner |
| **debsecan** | Debian security-tracker cross-check | Best-effort secondary check. On Ubuntu hosts this is *not* authoritative (Ubuntu maintains its own patch levels) — Trivy wins if they disagree |
| **SSH config check** | `PermitRootLogin`, `PasswordAuthentication`, `LoginGraceTime`, `MaxAuthTries`, `X11Forwarding` | Config-level hardening, not just CVEs |
| **nginx config check** | HSTS, CSP, `X-Frame-Options`, `server_tokens`, TLS version, rate limiting | Same, for the web layer |
| **nmap** (self-scan, NSE scripts) | Real open ports on this host + CVE-detection scripts, `default,safe,vuln,auth,version,malware` categories + behavioral probes | Same category of check as your original manual scan — Claude is prompted to flag distro-backport false positives instead of trusting the banner |
| **Claude / Ollama** | Reads all of the above, writes the prioritized plan | Turns raw tool output into "fix this first, here's the exact command" |

## ⚠️ About nmap's NSE script categories

nmap's script categories include `dos`, `exploit`, `brute`, and `fuzzer` —
these don't just detect, they **actively attack**: intentionally crashing
services, exploiting vulnerabilities, brute-forcing credentials, sending
malformed input. Running the full script set monthly means this agent would
periodically attack the very server it's protecting.

**Default here:** `default, safe, vuln, auth, version, malware` — full
CVE-detection coverage, malware detection, no attacks.

Additionally, **specific behavioral probes** run by default:
```
ssh-auth-methods, ssh-hostkey, ssl-heartbleed, ssl-poodle, ssl-ccs-injection,
ssl-dh-params, ftp-anon, smtp-open-relay, smb-security-mode, smb2-security-mode,
mysql-empty-password, redis-info, http-methods
```

These are configurable via `NMAP_EXTRA_SCRIPTS` in `.env`. Set to empty to
disable: `NMAP_EXTRA_SCRIPTS=`

Set `NMAP_ALLOW_INTRUSIVE=true` in `.env` to add `exploit,dos,brute,fuzzer`
back in, but only during a maintenance window you've planned for, since it
can crash services or lock out accounts on this host. Set `NMAP_SELF_SCAN=false`
to disable nmap entirely.

## 🚀 Setup Script

```bash
bash setup.sh
```

Interactive setup flow:
1. Initialize `.env` from `.env.example`
2. Check prerequisites (Docker, curl)
3. Slack bot token with generation instructions
4. LLM backend selection (5 options: Claude API, custom gateway, Ollama, custom gateway + Ollama fallback, Ollama only)
5. LLM health check — tests primary backend first, graceful failure handling
6. Slack channel ID
7. Docker build
8. Init container
9. Slack onboarding message (`<hostname> _onned_*`)

## ⚠️ About network_mode: host

To report this host's *real* open ports (not the container's own isolated
network namespace, which would be meaningless), the container runs with
`network_mode: host`. This is the one place this agent's visibility is wider
than "read-only file access" — it can observe host network traffic/sockets.
It still cannot modify the host: the root filesystem mount stays read-only,
and the container has no capabilities beyond the two nmap's scan itself
needs (`NET_RAW`, `NET_ADMIN`). Set `NMAP_SELF_SCAN=false` if you'd rather
not grant this and only want the file-based checks (Trivy/debsecan/config).

---

## 1. Install (5 minutes)

```bash
git clone <this-repo> brahma-danda && cd brahma-danda

# Non-secret config
cp .env.example .env
# edit .env: set SLACK_CHANNEL_ID (the channel ID, not the name — right-click
# the channel in Slack → View channel details → copy Channel ID)

# Secrets — see step 2 before filling these in
cp secrets/claude_api_key.txt.example secrets/claude_api_key.txt
cp secrets/slack_bot_token.txt.example secrets/slack_bot_token.txt
```

## 2. Fill in secrets securely

```bash
# Slack bot token — needs chat:write and files:write scopes,
# and must be invited to the target channel (/invite @yourbot)
echo -n "xoxb-..." > secrets/slack_bot_token.txt

chmod 600 secrets/*.txt
```

These are mounted into the container as **files** at `/run/secrets/`, never
as environment variables — env vars are visible via `docker inspect` and
`/proc/<pid>/environ`; these files are not, and are readable only by the
scan process. Do not put either value in `.env` or anywhere with `ENV`/`ARG`
in the Dockerfile.

### LLM Backend Priority

The remediation step uses the following priority order:

1. **Ollama (primary)** — Local model if configured (offline, no API costs)
2. **Claude API (fallback)** — Uses Anthropic's cloud API or a custom gateway

This ensures you get local processing by default, with Claude as a fallback
for higher quality when API is available.

### LLM Parameters (Temperature & Top P)

Control randomness and focus of the LLM via `.env`:

```bash
LLM_TEMPERATURE=0.3      # 0.0=deterministic, 1.0=creative (recommended: 0.0-0.3 for security)
LLM_TOP_P=0.3            # Nucleus sampling threshold (0.0-1.0, recommended: 0.1-0.3 for security)
```

Lower values = more consistent, focused output. Higher values = more creative/varied.

### Dynamic Recursive Chunking

Large scan reports (e.g., 100MB+ trivy.json) are processed with dynamic recursive chunking:

1. **Initial split:** 50 MB chunks
2. **On LLM failure:** chunk is halved at newline boundary (preserves JSON/XML)
3. **Recursive halving:** 50MB → 25MB → 12.5MB → 6.25MB ... until LLM succeeds
4. **Minimum floor:** 1 MB — if even that fails, logs warning and continues
5. **No silent skips:** Every byte of every report is guaranteed to be processed

This ensures 100% of scan data is analyzed without character loss.

### Using a custom Anthropic-compatible gateway (optional)

If you're routing the remediation LLM through a custom proxy or endpoint
(e.g. an internal API gateway, a local model server, or a third-party
Anthropic-compatible endpoint), set these in `.env`:

```bash
# .env
ANTHROPIC_BASE_URL=https://your-gateway.example.com/anthropic
ANTHROPIC_AUTH_TOKEN=your-auth-token-here
ANTHROPIC_MODEL=ornith-1.0
```

The `remediate.py` script uses `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`
as the `base_url` and `api_key` for the Anthropic SDK, routing the LLM call
to your gateway instead of `api.anthropic.com`.
The `ANTHROPIC_MODEL` env var overrides `CLAUDE_MODEL` when set.

When these env vars are **not** set, the container falls back to the
classic `secrets/claude_api_key.txt` file (for the default Anthropic cloud API).

### Using a local Ollama instance (fallback)

For offline or cost-sensitive scenarios, run Ollama on your host. The container
uses the OpenAI-compatible `/api/chat` endpoint that Ollama exposes.

```bash
# .env
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=deepseek-coder-v2:16b
```

**Setup:**
1. Install Ollama on your host (https://ollama.ai)
2. Pull the model: `ollama pull deepseek-coder-v2:16b`
3. Set the env vars above in `.env`

**Ollama lifecycle:**
- Ollama needs to be running on your host when the scan completes (for the primary to work)
- You can keep it running in a terminal, or set it up as a systemd service
- The container checks if Ollama is reachable at `OLLAMA_BASE_URL` before using it
- If Ollama is not running when needed, tries Claude API as fallback
- If both fail → playful Slack fallback message + raw reports in thread

## 📅 Cache Refresh Cron

To keep Trivy's Java vulnerability database fresh:

```
0 1 25 * *  find /root/.cache/trivy/java -type f -delete 2>/dev/null || true
0 2 26 * *  /app/scripts/run_scan.sh --refresh-cache >> /app/reports/last_run.log 2>&1
```

- **25th:** Clears cached Java vulnerability DB
- **26th:** Re-downloads fresh Java DB + runs scan
- **Slack notifications** sent on completion/failure of both steps

## 🔄 Scan Triggers

1. **First boot** — initial scan on container start
2. **Monthly** — cron schedule (default: 03:00 on 1st of every month)
3. **Manual** — `docker compose exec brahma-danda /app/scripts/run_scan.sh`

**Notes:**
- `host.docker.internal` resolves to the host machine from inside Docker
- Ollama is the **fallback** — Claude API is tried first
- The 16b model is ~10GB; for faster inference on slower hardware, use `deepseek-coder-v2:7b` (smaller) or reduce `max_tokens` in the system prompt
- This approach avoids external API costs and keeps scan data on-premise

**How fallback works:**
- If Claude API call succeeds → use the response (primary path), Ollama not used
- If Claude API call fails (timeout, auth error, etc.) → try Ollama
- If both fail → the container logs the error and exits with status 1

## 3. Run it

```bash
docker compose up -d --build
```

That's it. On first start it runs one scan immediately (to confirm Slack
delivery works), then schedules itself for the 1st of every month at 03:00
(configurable via `SCAN_SCHEDULE_CRON` in `.env`, standard cron syntax).

---

## Troubleshooting

**No message in Slack after `docker compose up`**
```bash
docker compose logs -f brahma-danda
```
Common causes:
- Bot not invited to the channel → `/invite @yourbot` in Slack
- Wrong `SLACK_CHANNEL_ID` → must be the ID (`C0123...`), not `#channel-name`
- Token missing `chat:write` / `files:write` scopes → check Slack app's OAuth scopes page

**Claude API errors in logs**
- If using `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` in `.env`, double-check the
  gateway URL is reachable from the container and the token is valid
- If using the `secrets/claude_api_key.txt` fallback, check it has no trailing
  newline/whitespace issues (the read strips whitespace, but double-check the key
  is complete and active)
- Check outbound HTTPS to the configured endpoint isn't blocked by an egress firewall

**Trivy step is slow / times out on first run**
Normal — first run downloads Trivy's vulnerability DB (~500MB-1GB). Subsequent
runs reuse the cache in the `scan_reports` volume's neighboring cache layer.
If your host has restricted egress, allowlist `ghcr.io` and Trivy's DB OCI registry.

**debsecan reports "suite mismatch" or looks empty on Ubuntu**
Expected — see the table above. Trivy is authoritative; debsecan is a bonus
cross-check that's most reliable on actual Debian hosts.

**nmap step fails with "operation not permitted"**
Confirm `cap_add: [NET_RAW, NET_ADMIN]` is present in `docker-compose.yml`
(it is by default) and that your Docker host's AppArmor/SELinux policy isn't
blocking raw sockets at the host level. If you don't need port scanning,
set `NMAP_SELF_SCAN=false` in `.env` instead of troubleshooting this.

**nmap step is slow**
`-p-` (all 65535 ports) with NSE scripts genuinely takes several minutes on
a host with many services. That's expected for a thorough monthly run.

**Want to test without waiting a month**
```bash
docker compose exec brahma-danda /app/scripts/run_scan.sh
```

**Want to see the raw reports without Slack**
They're written to the `scan_reports` named volume under a timestamped folder:
```bash
docker run --rm -v scan_reports:/reports alpine ls -la /reports
```

---

## Security notes on this container itself

- Runs as non-root (`brahmadanda` user)
- `cap_drop: ALL` with only `NET_RAW`+`NET_ADMIN` added back for nmap's scan — nothing broader
- `no-new-privileges:true`, own filesystem `read_only: true`
- Host filesystem mounted **read-only** — the agent cannot modify anything on
  the host it's auditing
- `network_mode: host` is required for real port visibility — see the
  callout above for exactly what that does and doesn't expose
- No secrets in the image, in `ENV`/`ARG`, or in git — see step 2
- Pinned base image and pinned tool versions — no `:latest` anywhere

---

## 📊 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           brahma-danda:1.0.0 Container                      │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     ENTRYPOINT (entrypoint.sh)                       │   │
│  │                                                                     │   │
│  │  1. Check first-boot marker (/app/reports/.first_boot_marker)       │   │
│  │     ├─ Missing → Run initial scan, create marker                    │   │
│  │     └─ Exists → Skip initial scan (previous boot detected)          │   │
│  │                                                                     │   │
│  │  2. Start cron daemon                                               │   │
│  │     └─ Load crontab: monthly scan + cache refresh + cleanup         │   │
│  │                                                                     │   │
│  │  3. exec tail -f /dev/null (keep container alive)                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    TRIGGER: Manual / Monthly / First Boot            │   │
│  │                     ↓                                                 │   │
│  │               run_scan.sh                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    STEP 1: TRIVY (rootfs scan)                       │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  nmap --script=default,vuln  -p- localhost                  │   │   │
│  │  │  nmap --script=ssh-auth-methods,ssh-hostkey,...             │   │   │
│  │  │                                                                     │   │
│  │  │  Trivy rootfs scan → trivy.json                                │   │   │
│  │  │                                                                     │   │
│  │  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │  │  trivy scan → trivy.json (OS package CVEs)                 │  │   │
│  │  │  │  debsecan → debsecan.txt (best-effort cross-check)         │  │   │
│  │  │  │  ssh_checks → ssh_checks.json                              │  │   │
│  │  │  │  nginx_checks → nginx_checks.json                          │  │   │
│  │  │  │  docker_checks → docker_checks.json                        │  │   │
│  │  │  │  ss_listeners → ss_listeners.txt                           │  │   │
│  │  │  │  ufw_status → ufw_status.txt                               │  │   │
│  │  │  │  iptables → iptables.txt                                   │  │   │
│  │  │  │  nftables → nftables.txt                                   │  │   │
│  │  │  │  lynis → lynis-report.dat                                  │  │   │
│  │  │  │  nmap → nmap.xml + nmap.txt                                │  │   │
│  │  │  │  testssl → testssl_*.json                                  │  │   │
│  │  │  └─────────────────────────────────────────────────────────────┘  │   │
│  │  └─────────────────────────────────────────────────────────────────────┘   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  Report directory: /app/reports/{timestamp}Z/              │   │   │
│  │  │  Local copy: ~/Downloads/brahma-danda_reports/{timestamp}Z/ │   │   │
│  │  └───────────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                  STEP 2: REMEDIATE.PY (LLM Analysis)                 │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  _file_inputs(report_dir)                                   │   │   │
│  │  │  └─ Return (label, content) for each artefact (no truncation)│   │   │
│  │  └─────────────────────────────────────────────────────────────────────┘   │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  analyze_files() → Dynamic Recursive Chunking                │   │   │
│  │  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │  │  For each (label, content):                                │  │   │
│  │  │  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │  │  │  if len(content) <= 50MB:                                  │  │   │
│  │  │  │  │  │  → _process_single_chunk(content, label, ...)           │  │   │
│  │  │  │  │  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │  │  │  │  │  1. Send to LLM with PER_FILE_SYSTEM_PROMPT                 │  │   │
│  │  │  │  │  │  │  2. Parse JSON response → findings list                     │  │   │
│  │  │  │  │  │  │  3. If empty/error:                                       │  │   │
│  │  │  │  │  │  │     └─ Return empty (no chunk left to split)               │  │   │
│  │  │  │  │  │  └─────────────────────────────────────────────────────────────┘  │   │
│  │  │  │  │  else:                                                              │   │   │
│  │  │  │  │    └─ _split_text_at_newline(content) → first_half, second_half   │   │   │
│  │  │  │  │       → _process_with_chunking(first_half, label + ".a", ...)      │   │   │
│  │  │  │  │       → _process_with_chunking(second_half, label + ".b", ...)     │   │   │
│  │  │  │  │       → Merge findings from both halves                            │   │   │
│  │  │  │  └─────────────────────────────────────────────────────────────┘  │   │
│  │  │  └─────────────────────────────────────────────────────────────────────┘   │   │
│  │  └─────────────────────────────────────────────────────────────────────┘   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  combine_findings(all_findings, host)                        │   │   │
│  │  │  └─ Send to LLM with COMBINE_SYSTEM_PROMPT                   │   │   │
│  │  │     → Threat Brief (Slack mrkdwn format)                     │   │   │
│  │  └─────────────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                  STEP 3: POST TO SLACK (or fallback)                 │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  if threat_brief is None:                                    │   │   │
│  │  │  │  → Playful fallback message                              │   │   │
│  │  │  │  → Raw reports in thread                                 │   │   │
│  │  │  └─────────────────────────────────────────────────────────────────────┘   │   │
│  │  │  else:                                                                     │   │
│  │  │    → Post Threat Brief to channel (Slack mrkdwn)                         │   │   │
│  │  │    → Announce raw reports in thread                                      │   │   │
│  │  │    → Upload each raw file to thread (split if >50MB)                     │   │   │
│  │  │    → Copy reports to local ~/Downloads/brahma-danda_reports/             │   │   │
│  │  └─────────────────────────────────────────────────────────────────────┘   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 🧠 LLM Decision Flow

```
                        ┌─────────────────────┐
                        │  remediate.py starts  │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │  OLLAMA configured?    │
                        └───────────┬───────────┘
                              YES │         │ NO
                                ┌─▼─────┐   ┌─▼─────────────────┐
                                │  Ollama │   │  Claude configured│
                                │  FIRST  │   │  (API or gateway) │
                                └────┬────┘   └────────┬──────────┘
                                   │                │
                        ┌───────────▼────────┐       │
                        │  call_ollama()      │       │
                        │  (primary backend)  │       │
                        └───────────┬────────┘       │
                          YES │       │ NO          │
                        ┌────▼─┐  ┌──▼──┐           │
                        │ OK   │  │ FAIL│           │
                        └──┬───┘  └──┬──┘           │
                           │         │               │
                           │    ┌────▼─────┐         │
                           │    │  Claude   │         │
                           │    │  (fallback│         │
                           │    │   API)    │         │
                           │    └────┬─────┘         │
                           │      YES │       │ NO   │
                           │   ┌────▼──┐  ┌──▼──┐   │
                           │   │  OK   │  │ FAIL│   │
                           │   └──┬────┘  └──┬──┘   │
                           │      │          │       │
                        ┌──▼──────▼──────────▼───────▼──┐
                        │  Response received or None     │
                        └───────────┬───────────────────┘
                                    │
                        ┌───────────▼───────────┐
                        │  Process findings      │
                        └───────────────────────┘
```

## 🔧 NMAP Configuration Flow

```
.env / .env.example
│
├─ NMAP_SELF_SCAN=true|false          → Disable/enable nmap entirely
│
├─ NMAP_SCRIPT_CATEGORIES=            → Main script categories
│   default, safe, vuln, auth, version, malware
│
├─ NMAP_EXTRA_SCRIPTS=                → Additional specific probes
│   ssh-auth-methods, ssh-hostkey,
│   ssl-heartbleed, ssl-poodle, ...
│
└─ NMAP_ALLOW_INTRUSIVE=true|false    → Enable aggressive scripts
    dos, exploit, brute, fuzzer

run_scan.sh
│
├─ NMAP_CATEGORIES = ${NMAP_SCRIPT_CATEGORIES}
├─ NMAP_EXTRA = ${NMAP_EXTRA_SCRIPTS}
│
├─ if NMAP_ALLOW_INTRUSIVE=true:
│   └─ NMAP_ALL = categories + extras + aggressive
│
└─ nmap -sV -sC --script "${NMAP_ALL}" -p- localhost
```

## 📦 Volume Persistence

```
docker-compose.yml
│
├─ scan_reports:/app/reports    → Timestamped scan data
│   └─ /app/reports/2026-08-20T091710Z/
│       ├─ trivy.json
│       ├─ debsecan.txt
│       ├─ ssh_checks.json
│       └─ ...
│
└─ trivy_cache:/root/.cache/trivy  → Persistent vulnerability DB
    └─ /root/.cache/trivy/java/
        └─ (cleared 25th, refreshed 26th)
```

## 📅 Cron Schedule

```
__SCHEDULE__ /app/scripts/run_scan.sh >> /app/reports/last_run.log 2>&1
0 1 25 * *  find /root/.cache/trivy/java -type f -delete 2>/dev/null || true
0 2 26 * *  /app/scripts/run_scan.sh --refresh-cache >> /app/reports/last_run.log 2>&1
0 * * * * find /app/reports -mindepth 2 -type f -name "*.json" -o -name "*.txt" -o -name "*.xml" -o -name "*.dat" | xargs ls -t 2>/dev/null | tail -n +200 | xargs rm -f 2>/dev/null || true
```

- **Monthly scan:** 03:00 on 1st (configurable via SCAN_SCHEDULE_CRON)
- **Cache cleanup:** 01:00 on 25th
- **Cache refresh + scan:** 02:00 on 26th
- **Report cleanup:** hourly (keep last 200 files)

## 🔐 Security Model

```
Host Filesystem (read-only)
│
├─ /:/host:ro           → Container scans host state
│   └─ Agent can READ but NOT modify host
│
├─ cap_drop: ALL        → Drop all capabilities
│   └─ cap_add: NET_RAW, NET_ADMIN  → Only for nmap
│
├─ read_only: true      → Container's own filesystem is read-only
│   └─ tmpfs: /tmp, /run, /var/spool  → Temporary writable
│
└─ /run/secrets/*       → Secrets as files (not env vars)
    └─ slack_bot_token.txt  → 0400 permissions
```
