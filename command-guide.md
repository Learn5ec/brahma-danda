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
docker compose logs -f brahma-danda
```

## Logs & Debugging

```bash
docker compose logs -f brahma-danda                          # live logs
docker compose logs brahma-danda --tail 50                   # last 50 lines
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
ANTHROPIC_MODEL=ornith-1.0      # override CLAUDE_MODEL
OLLAMA_BASE_URL=http://host.docker.internal:11434   # fallback URL
OLLAMA_MODEL=deepseek-coder-v2:16b                   # fallback model
```
