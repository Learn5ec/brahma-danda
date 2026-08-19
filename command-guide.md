# Brahma-Danda Command Guide

## Lifecycle

```bash
docker compose up --build -d        # build & start (runs initial scan on startup)
docker compose down                 # stop & remove container (volumes preserved)
docker compose down -v              # ⚠️ full reset — also destroys Trivy DB cache (forces re-download)
docker compose restart brahmadanda  # restart container (triggers another scan)
```

---

## Container Shell

```bash
docker exec -it brahma-danda /bin/bash
```

After landing in the shell, check Trivy logs:
```bash
LATEST=$(ls -t /app/reports | grep -v latest | head -1) && tail -f /app/reports/$LATEST/trivy.stderr.log
```

---

## Manual Scan

```bash
# Trigger a full scan
docker exec brahma-danda /app/scripts/run_scan.sh

# Run scan and stream logs in real-time
docker compose exec brahma-danda /app/scripts/run_scan.sh 2>&1 | tee /tmp/scan-log-$(date -u +%Y%m%dT%H%M%SZ).log

# Re-run only the Slack/remediation step (uses last scan's data — great for prompt iteration)
docker exec brahma-danda bash -c 'LATEST=$(ls -t /app/reports | grep -v latest | head -1) && python3 -u /app/scripts/remediate.py --report-dir /app/reports/$LATEST --host $(hostname)'
```

---

## Trivy DB Cache

The Trivy vulnerability DB and Java DB are stored in the persistent `trivy_cache` Docker volume at `/root/.cache/trivy/`. They download once and survive all container restarts and rebuilds.

| DB | Size | Path |
|---|---|---|
| Vuln DB | ~108 MB | `/root/.cache/trivy/db/` |
| Java DB | ~907 MB | `/root/.cache/trivy/java-db/` |

```bash
# Check vuln DB cache
docker exec brahma-danda ls -lh /root/.cache/trivy/db/

# Check Java DB cache
docker exec brahma-danda ls -lh /root/.cache/trivy/java-db/

# Check Trivy version
docker exec brahma-danda trivy --version

# Clear cache (forces full re-download of both DBs)
docker exec brahma-danda sh -c 'rm -rf /root/.cache/trivy/*'

# Manual Trivy scan (for testing inside shell)
docker exec brahma-danda trivy rootfs /host \
  --severity CRITICAL,HIGH,MEDIUM \
  --pkg-types os \
  --scanners vuln \
  --skip-version-check \
  --output /tmp/trivy.json \
  --timeout 30m
```

---

## Logs & Debugging

```bash
docker logs brahma-danda -f                                                    # live container logs
docker logs brahma-danda --tail 50                                             # last 50 lines
docker logs brahma-danda 2>&1 | grep "\[remediate\]"                          # remediate step only
docker inspect brahma-danda --format '{{.State.Status}} OOM={{.State.OOMKilled}}'  # OOM health check
grep -i 'trivy' /var/log/syslog | grep -i 'oom\|killed' | tail -5            # OOM kill history
```

---

## Raw Report Access

```bash
# List all scan runs
docker exec brahma-danda ls -lt /app/reports/ | head -10

# View files in the latest run
LATEST=$(docker exec brahma-danda sh -c 'ls -t /app/reports | grep -v latest | head -1') && \
docker exec brahma-danda ls -lh /app/reports/$LATEST/

# View remediation plan
LATEST=$(docker exec brahma-danda sh -c 'ls -t /app/reports | grep -v latest | head -1') && \
docker exec brahma-danda cat /app/reports/$LATEST/remediation_plan.md

# Copy a run's reports to your host (replace timestamp)
docker run --rm -v scan_reports:/r -v ~/Downloads/brahma-danda_reports:/out alpine cp -r /r/2026-08-18T133518Z/* /out/
```

---

## Secrets & Config

```bash
cat .env                                                                       # view non-secret config
docker compose exec brahma-danda cat /run/secrets/slack_bot_token             # check Slack token inside container
```

---

## Scheduled Runs

```bash
# Check rendered crontab inside container
docker compose exec brahma-danda cat /tmp/crontab

# Default schedule: 0 3 1 * * (1st of every month at 03:00 UTC)
# Override in .env:
SCAN_SCHEDULE_CRON="0 6 15 * *"
```

---

## Ollama Fallback

```bash
systemctl status ollama        # is Ollama running?
systemctl restart ollama       # restart Ollama
ollama list                    # check downloaded models
curl http://172.17.0.1:11434/api/tags   # verify Ollama reachable from container network
```

---

## LLM Backend Config (in `.env`)

```bash
ANTHROPIC_BASE_URL=                               # custom gateway URL (optional)
ANTHROPIC_AUTH_TOKEN=                             # Bearer token for custom gateway
ANTHROPIC_MODEL=ornith-1.0                        # model override
OLLAMA_BASE_URL=http://host.docker.internal:11434 # Ollama fallback URL
OLLAMA_MODEL=deepseek-coder-v2:16b               # Ollama fallback model
```

---

## Optional Scan Modules (in `.env`)

```bash
DOCKER_CHECKS=true     # Docker runtime security checks (default: true)
LYNIS_SCAN=true        # Lynis Linux hardening audit (default: false, ~2-3 min)
TLS_SCAN=true          # testssl.sh TLS certificate audit (default: false)
NMAP_SELF_SCAN=true    # nmap port scan (default: true)
```

---

## Resource Monitoring

```bash
docker stats brahma-danda --no-stream   # container CPU/memory usage
cat /proc/meminfo | head -5             # host available memory
```

---

## Slack Threat Brief Format

The Slack message is a **Threat Brief** designed for quick human review:
- **Executive Summary** — 1-3 sentences with the number of exposed services and the single highest-risk finding.
- **Critical & High Findings** — Documented with Risk, precise Evidence (file and exact line/value), and concrete Impact.
- **Note to Reviewer** — Lower severity findings are omitted from the message to prevent alert fatigue; all raw scan files are attached in the thread for a complete deep-dive.
