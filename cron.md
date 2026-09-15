# brahma-danda — Scheduled Runs (cron)

How scheduling works, when each job fires, and the prerequisites that must hold
for a scheduled run to actually execute.

## How scheduling is wired

- `supercronic` (not system cron) runs as the container's foreground process —
  see `scripts/entrypoint.sh`.
- The image ships a template crontab at `/app/crontab` with a `__SCHEDULE__`
  placeholder.
- At container start, the entrypoint substitutes `SCAN_SCHEDULE_CRON` (from
  `.env`, default `0 3 1 * *`) into the template and writes the rendered file
  to `/tmp/crontab` (the image rootfs is read-only; `/tmp` is tmpfs).
- supercronic then executes the rendered crontab.

## The schedule — what runs when

With the default `SCAN_SCHEDULE_CRON=0 3 1 * *`, the rendered crontab is:

| Schedule | Job | What it does |
|---|---|---|
| `0 3 1 * *` | `run_scan.sh` | **Full security scan** — 03:00 on the 1st of every month. Output appended to `/app/reports/last_run.log`. |
| `0 1 25 * *` | `find … java-db -delete` | Prune Trivy's Java vulnerability DB cache (monthly, 25th @ 01:00). |
| `0 2 26 * *` | `run_scan.sh --refresh-cache` | Refresh Trivy's Java DB with fresh signatures, then exit without scanning (26th @ 02:00). |
| `0 * * * *` | find/xargs housekeeping | Delete scan artefacts beyond the 199 newest files, hourly. |

All times are the container's local time (UTC unless `TZ` is set).

## Startup scan behavior

- On **first boot** the entrypoint runs a scan immediately, unless
  `RUN_ON_STARTUP=false` is set in the environment.
- First-boot detection uses the marker file `/app/reports/.first_boot_marker`:
  - Marker absent → scan runs; the marker is written **only on success**, so a
    failed first scan retries on the next boot.
  - Marker present → startup scan is skipped.
- To force a startup scan again:
  ```bash
  docker exec brahma-danda rm /app/reports/.first_boot_marker
  # next `docker compose up` will trigger a scan on startup
  ```

## Prerequisites for a scheduled run

A cron tick only produces a scan if all of the following hold:

1. **Container is up and supercronic is alive (PID 1):**
   ```bash
   docker exec brahma-danda pgrep -a supercronic
   # → /usr/local/bin/supercronic /tmp/crontab
   ```

2. **The scan lock is free.** `run_scan.sh` takes an exclusive lock at
   `/tmp/brahmadanda_scan.lock`; a scheduled scan that finds the lock held
   (e.g. a still-running manual scan) refuses to run and logs:
   `is locked by another scan — refusing to run concurrently`.
   ```bash
   docker exec brahma-danda test -f /tmp/brahmadanda_scan.lock \
     && echo "LOCKED — a scan is running" || echo "free"
   ```
   A stale lock (killed scan) must be removed manually:
   ```bash
   docker exec brahma-danda rm -f /tmp/brahmadanda_scan.lock
   ```

3. **Reports volume is mounted and writable** (not shadowed by a deleted
   volume directory):
   ```bash
   docker exec brahma-danda mkdir -p /app/reports/sanity \
     && docker exec brahma-danda rmdir /app/reports/sanity && echo "volume OK"
   ```

4. **Secrets are present:**
   ```bash
   docker exec brahma-danda test -r /run/secrets/slack_bot_token && echo "slack OK"
   docker exec brahma-danda test -r /run/secrets/claude_api_key  && echo "claude OK"
   ```
   Note: the compose service is named `brahmadanda`, but the container is
   `brahma-danda` — `docker exec brahmadanda …` fails with "No such container".

5. **Trivy Java DB cached** (optional but avoids a ~15 min download at scan
   start; the 26th `--refresh-cache` job keeps it warm):
   ```bash
   docker exec brahma-danda test -d /root/.cache/trivy/java-db \
     && echo "DB ready" || echo "DB missing — run: run_scan.sh --refresh-cache"
   ```

## On-demand alternatives (same pipeline as cron)

```bash
# Run a full scan right now (goes through the same concurrency lock)
docker exec brahma-danda /app/scripts/run_scan.sh

# Refresh the Java vulnerability DB only (no scan)
docker exec brahma-danda /app/scripts/run_scan.sh --refresh-cache
```

A manually triggered scan streams to your terminal **and** tees to
`/app/reports/<scan-ts>/run_scan.log` — if your terminal dies, the log survives:
```bash
docker exec brahma-danda tail -f /app/reports/<scan-ts>/run_scan.log
```

## Changing the schedule

Edit `.env` on the host:

```bash
SCAN_SCHEDULE_CRON="30 4 * * 1"   # e.g. 04:30 every Monday
```

Then recreate the container so the entrypoint re-renders the crontab:

```bash
docker compose up -d   # recreation picks up the new env; no --build needed
```

Verify what got rendered:

```bash
docker exec brahma-danda cat /tmp/crontab
docker logs brahma-danda 2>&1 | grep "schedule:"
```
