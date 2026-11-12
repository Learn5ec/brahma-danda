# Rolling out v1.1.0 to the 3 production servers — step-by-step

Audience: DevOps engineer (assume first time on this tool). Read this whole page
before touching a server. Work on **one server at a time** and finish its
verification before moving to the next.

The app is a single Docker container named **`brahma-danda`** (started by the
compose service `brahmadanda`) that scans the host it runs on and posts a report
to Slack on a schedule. Each of the 3 servers has its **own** copy of this repo
folder, its own `.env`, and its own Docker container. You repeat these steps on
each one.

---

## 0. What this update changes (why we are deploying)
- Fixes scans that collected data but posted **nothing to Slack** (a wrong model
  id caused a fatal error).
- Adds a **real host firewall report** (`ufw_rules.txt`) — per-port rules,
  source IPs, and comments.
- Adds a **boot self-check** to `docker logs` so problems are obvious.
- **Pins the timezone to Asia/Kolkata** so the schedule fires at the same real
  wall-clock time on every server (it was running in UTC before).

---

## 1. Prerequisites (check on the server BEFORE you start)

```bash
# 1a. You are in the right folder (it must contain docker-compose.yml)
cd <path-to>/brahma-danda
ls docker-compose.yml .env

# 1b. Docker + compose are available and the daemon starts on boot
docker --version
docker compose version
systemctl is-enabled docker   # must print: enabled   (if not: sudo systemctl enable docker)

# 1c. The container currently exists and is running
docker ps --filter name=brahma-danda
```

If **1c shows nothing**, the container isn't running — that alone explains a
server whose scheduled jobs never fire. Note it; it gets fixed in step 4 anyway.

---

## 2. Make sure `.env` is correct on THIS server (most common cause of breakage)

Open `.env` in an editor and confirm these lines exist and are correct. Do **not**
change anything else (tokens/keys live here — leave secrets alone).

```bash
nano .env        # or your usual editor
```

Required / recommended values:

```ini
# The model MUST be one your AI gateway actually serves. For this deployment
# the working value is:  coder
ANTHROPIC_MODEL=coder
CLAUDE_MODEL=coder

# Custom gateway (already set in the working box — keep the same across servers)
ANTHROPIC_BASE_URL=https://ai-gateway-api.webelight.co.in/anthropic

# Pin the timezone so cron fires at the same real time on every server
TZ=Asia/Kolkata

# Slack destination (channel ID, not the name)
SLACK_CHANNEL_ID=<this server's channel id>
```

> ⚠️ **The single most common mistake:** leaving `ANTHROPIC_MODEL` as `haiku` or
> empty. That makes every scan run, collect everything, then die silently with a
> `404 "…not configured globally"` — so **no report ever reaches Slack**. Fix the
> value here, and it is applied in step 4.

Verify the model truly works before relying on it (optional but recommended):

```bash
set -a; . ./.env; set +a
curl -s "$ANTHROPIC_BASE_URL/v1/messages" \
  -H "authorization: Bearer $ANTHROPIC_AUTH_TOKEN" \
  -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
  -d '{"model":"coder","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}'
# ✅ a JSON reply with "type":"message"  = good
# ❌ "404 ... not configured globally"   = WRONG model — fix .env before continuing
```

---

## 3. Get the new code

```bash
cd <path-to>/brahma-danda
git fetch origin
git checkout branch-3
git pull origin branch-3
git log --oneline -1          # should show a v1.1.0 commit (self-check / UFW / 1.1.0)
```

---

## 4. Rebuild and restart (this is what APPLIES all the fixes)

A running container keeps its OLD settings — editing `.env` or `git pull` does
nothing until the container is **recreated**. This step does that.

```bash
cd <path-to>/brahma-danda
docker compose down
docker compose up -d --build
```

- `--build` rebuilds the image (picks up the new code + `tzdata`).
- `up -d` recreates the container and loads the current `.env`.

The container is now running v1.1.0.

---

## 5. VERIFY — do not skip, do this on every server

```bash
# 5a. Read the new boot self-check. Look for the lines below in green/ok state:
docker logs --tail 40 brahma-danda
```

Expected self-check output (all healthy):

```
[entrypoint][self-check] rendered schedule : 0 3 1 * * /app/scripts/run_scan.sh ...
[entrypoint][self-check] container clock (UTC): <today>  TZ=Asia/Kolkata
[entrypoint][self-check] LLM backend        : gateway https://ai-gateway-api...
[entrypoint][self-check] LLM model          : coder  ...
[entrypoint][self-check] secrets            : slack_bot_token=OK ...
[entrypoint][self-check] reports volume     : writable
[entrypoint][self-check] scan lock          : free
[entrypoint][self-check] supercronic        : present
```

⚠️ Anything that reads `MISSING`, `NOT writable`, `LOCKED/PRESENT`,
`<unset>`, or a model other than `coder` = fix before moving on (see §7).

```bash
# 5b. Confirm the clock is actually on Kolkata time (should show +0530 / IST)
docker exec brahma-danda date
docker exec brahma-danda sh -c 'echo TZ=$TZ'      # must print Asia/Kolkata
```

**5c. Run one scan now to prove the whole pipeline end-to-end** (takes ~15 min;
it will post to Slack). This is the real test.

```bash
docker exec brahma-danda /app/scripts/run_scan.sh
```

Success = the command finishes **and a new Threat Brief appears in Slack**.
If it runs but nothing posts → it's the model/secrets (§7).

```bash
# 5d. Confirm the NEW firewall report was produced and looks right
docker exec brahma-danda sh -c 'cat "$(ls -dt /app/reports/*/ | head -1)ufw_rules.txt"'
# You should see a "To / Action / From" table plus a "Reconciliation" line.
```

Only mark this server DONE when 5a is clean, 5b shows IST, and 5c posted to Slack.

---

## 6. Move to the next server
Repeat **steps 1 → 5** on server 2, then server 3. Do not batch them — you want
to see the result of each before touching the next.

---

## 7. Troubleshooting (map the symptom → the fix)

| Symptom in self-check / logs | Cause | Fix |
|---|---|---|
| `LLM model : haiku` or `<unset>`, scan runs but no Slack | bad/missing model | set `ANTHROPIC_MODEL=coder` in `.env`, then `docker compose up -d --build` |
| No `[self-check]` block at all | still old image | you skipped `--build` — rerun step 4 |
| `TZ=<unset>` / clock is UTC | `.env` lacks TZ or not recreated | add `TZ=Asia/Kolkata`, rerun step 4 |
| `scan lock : PRESENT` and log says "refusing to run" | a previous scan is wedged | `docker exec brahma-danda rm -f /tmp/brahmadanda_scan.lock` |
| `secrets: slack_bot_token=MISSING` | secret file absent | restore `./secrets/slack_bot_token.txt`, rerun step 4 |
| `reports volume NOT writable` | volume/perm problem | `docker compose down && docker compose up -d --build`; the init container fixes ownership |
| Scheduled jobs never fire, container exists | container wasn't up at fire time (host rebooted) | ensure `systemctl enable docker` and `restart: unless-stopped`; supercronic does **not** catch up on missed times |
| Container not running after a host reboot | Docker not set to start on boot | `sudo systemctl enable docker && sudo systemctl start docker` |

---

## 8. Rollback (only if something is broken)

```bash
cd <path-to>/brahma-danda
git log --oneline -5                 # find the last-known-good commit (pre-v1.1.0)
git checkout <that-commit>
docker compose down
docker compose up -d --build
docker logs --tail 40 brahma-danda   # confirm it came back up
```

Data and reports are on named Docker volumes and are **not** deleted by these
steps. `--build` never touches your `.env` or secrets.

---

## 9. Sign-off checklist (per server — tick all before leaving)
- [ ] `.env` has `ANTHROPIC_MODEL=coder`, `TZ=Asia/Kolkata`, correct `SLACK_CHANNEL_ID`
- [ ] `git log --oneline -1` shows the v1.1.0 commit
- [ ] `docker compose up -d --build` completed with no errors
- [ ] self-check block shows: model `coder`, TZ `Asia/Kolkata`, secrets OK, volume writable, lock free, supercronic present
- [ ] `docker exec brahma-danda date` shows IST (+0530)
- [ ] a full `run_scan.sh` completed and a Threat Brief landed in Slack
- [ ] `ufw_rules.txt` shows the To/Action/From table
