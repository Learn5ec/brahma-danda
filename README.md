# brahma-danda

A containerized agent that scans **the server it's deployed on**, runs monthly,
and posts a Claude-generated, priority-ordered remediation plan to Slack —
along with the raw scan data.

## What it actually checks

| Tool | What it does | Why |
|---|---|---|
| **Trivy** (`rootfs` scan) | OS package CVEs against the real installed versions | Primary source of truth — matches actual patch level, not just a version banner |
| **debsecan** | Debian security-tracker cross-check | Best-effort secondary check. On Ubuntu hosts this is *not* authoritative (Ubuntu maintains its own patch levels) — Trivy wins if they disagree |
| **SSH config check** | `PermitRootLogin`, `PasswordAuthentication`, `LoginGraceTime`, `MaxAuthTries`, `X11Forwarding` | Config-level hardening, not just CVEs |
| **nginx config check** | HSTS, CSP, `X-Frame-Options`, `server_tokens`, TLS version, rate limiting | Same, for the web layer |
| **nmap** (self-scan, NSE scripts) | Real open ports on this host + CVE-detection scripts, `default,discovery,safe,vuln,auth` categories | Same category of check as your original manual scan — Claude is prompted to flag distro-backport false positives instead of trusting the banner |
| **Claude (Sonnet)** | Reads all of the above, writes the prioritized plan | Turns raw tool output into "fix this first, here's the exact command" |

## ⚠️ About nmap's NSE script categories

nmap's script categories include `dos`, `exploit`, `brute`, and `fuzzer` —
these don't just detect, they **actively attack**: intentionally crashing
services, exploiting vulnerabilities, brute-forcing credentials, sending
malformed input. Running the full script set monthly means this agent would
periodically attack the very server it's protecting.

**Default here:** `default,discovery,safe,vuln,auth` — full CVE-detection
coverage, no attacks. Set `NMAP_ALLOW_INTRUSIVE=true` in `.env` to add
`exploit,dos,brute,fuzzer` back in, but only during a maintenance window
you've planned for, since it can crash services or lock out accounts on
this host. Set `NMAP_SELF_SCAN=false` to disable nmap entirely.

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

1. **Claude API (primary)** — Uses Anthropic's cloud API or a custom gateway
2. **Ollama (fallback)** — Local model if Claude API is unavailable

This ensures you get the best quality from Claude by default, with Ollama as a
reliable fallback for offline or cost-sensitive scenarios.

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
- Ollama needs to be running on your host when the scan completes (for the fallback to work)
- You can keep it running in a terminal, or set it up as a systemd service
- The container checks if Ollama is reachable at `OLLAMA_BASE_URL` before falling back to it
- If Ollama is not running when needed, the fallback fails and the container exits with an error

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
# brahma-danda
