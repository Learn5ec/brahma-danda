# Brahma-Danda Command Guide

## Startup / Lifecycle

```bash
docker compose up -d --build        # build & start (runs initial scan)
docker compose down                 # stop & remove container
docker compose restart              # restart (triggers another scan)
```

## Manual Scan

```bash
docker compose exec brahma-danda /app/scripts/run_scan.sh     # run scan now
docker compose exec brahma-danda /bin/bash                    # drop into container shell
```

## Live Scan + Logs (combined)

```bash
# Run a scan and stream its logs in real-time
docker compose exec brahma-danda /app/scripts/run_scan.sh 2>&1 | tee /tmp/scan-log-$(date -u +%Y%m%dT%H%M%SZ).log
```

```bash
# Watch ongoing container logs while a scan is running
docker compose logs -f brahmadanda
```

## Logs & Debugging

```bash
docker compose logs -f brahmadanda                          # live logs
docker compose logs brahmadanda --tail 50                   # last 50 lines
docker inspect brahma-danda --format '{{.State.Status}} OOM={{.State.OOMKilled}}'  # health check
```

## Raw Report Access

```bash
# List all scan runs
docker run --rm -v scan_reports:/r alpine ls -la /r

# Inspect a specific run
docker run --rm -v scan_reports:/r alpine ls -la /r/2026-08-17T100210Z/

# Copy a run's reports to your host
docker run --rm -v scan_reports:/r -v ~/Downloads/brahma-danda_reports:/out alpine cp -r /r/2026-08-17T100210Z/* /out/
```

## Secrets & Config

```bash
docker compose secrets inspect slack_bot_token          # verify secret is mounted
cat .env                                                 # non-secret config
docker compose exec brahma-danda cat /run/secrets/slack_bot_token   # check token inside container
```

## Scheduled Runs

```bash
# Check rendered crontab
docker compose exec brahma-danda cat /tmp/crontab

# Default schedule: 0 3 1 * * (1st of every month at 03:00)
# Override in .env: SCAN_SCHEDULE_CRON="0 6 15 * *"
```

## Ollama Fallback

```bash
systemctl status ollama                                 # is Ollama running?
systemctl restart ollama                                # restart Ollama
ollama list                                             # check downloaded models
```

## Switching LLM Backend

```bash
# In .env:
ANTHROPIC_BASE_URL=             # set to use custom gateway
ANTHROPIC_AUTH_TOKEN=           # standard Bearer token for custom gateways
ANTHROPIC_MODEL=ornith-1.0      # override CLAUDE_MODEL
OLLAMA_BASE_URL=http://host.docker.internal:11434   # fallback URL
OLLAMA_MODEL=deepseek-coder-v2:16b                   # fallback model
```

## Optional Scan Modules

```bash
# Enable optional scans in .env:
DOCKER_CHECKS=true              # Docker runtime security checks (default: true)
LYNIS_SCAN=true                 # Lynis Linux hardening audit (default: false)
TLS_SCAN=true                   # testssl.sh TLS certificate audit (default: false)
NMAP_SELF_SCAN=true             # nmap port scan (default: true)
```

**Docker Runtime Checks** (always on):
- Docker socket permissions
- daemon.json security config (TLS, userns-remap, live-restore)
- TCP port exposure (2375, 2376)
- Docker group membership

**Lynis Audit** (optional, LYNIS_SCAN=true):
- Full Linux security hardening audit
- Takes ~2-3 minutes
- Output: lynis-report.dat (data file) and lynis.log (text log)

**testssl.sh TLS Audit** (optional, TLS_SCAN=true):
- Scans SSL/TLS ports identified by nmap
- Certificate validity, TLS version support, cipher suites
- Output: testssl.txt (structured text report)

## Public Exposure Context

The scanner collects:
- `ss_listeners.txt` — which services bind to 0.0.0.0 (internet) vs 127.0.0.1 (local)
- `ufw_status.txt` — UFW firewall rules
- `iptables.txt` — iptables rules
- `nftables.txt` — nftables rules

Claude uses this to classify risk: a Critical CVE on a local-only service is Medium risk in practice.

## Slack Threat Brief Format

The remediation output is a **Threat Brief** designed for quick human review. It strictly contains:
- **Executive Summary** — 1-3 sentences with the number of exposed services and the single highest-risk finding.
- **Critical & High Findings** — Documented with Risk, precise Evidence (file and exact line/value), and concrete Impact.
- **Note to Reviewer** — A reminder that remediation decisions are left to the reviewer and that lower severity findings exist in the raw reports.

Medium, Low, and Informational findings are explicitly omitted from the Slack message to prevent alert fatigue, but all raw scan files are attached in the thread for a complete deep-dive.
