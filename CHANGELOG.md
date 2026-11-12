# Changelog

All notable changes to this project are documented here.

## [1.1.0] — 2026-11-12

Image tag bumped `1.0.0 → 1.1.0`. Minor release: the scanner now reports the
**host's real firewall configuration**, the silent remediation failure is fixed,
and scheduled runs are made deterministic across servers.

### ✨ Highlights
- **Host UFW configuration is now visible**, rendered as the native
  `ufw status` **To / Action / From** table (per-port rules, source IPs, and
  inline `#` comments) — previously invisible.
- **Scan no longer dies silently** before posting to Slack due to a wrong
  model id (HTTP 404).
- **Boot self-check** prints schedule / clock-TZ / model / secrets / lock /
  supercronic to `docker logs`, so per-server differences are obvious at a glance.
- **Timezone is pinned** to `Asia/Kolkata` (configurable) so cron fires at the
  same real-world time on every server.

### Added
- **`scripts/checks/ufw_rules_report.py`** — reconstructs the host's UFW ruleset
  from the read-only `/host` mount and renders it as the native `ufw status`
  To/Action/From table: per-port allow/deny rules with source IP and inline
  comment, enabled state, default INPUT/OUTPUT policies, IPv4 **and** IPv6, plus
  a **reconciliation** line that checks the live iptables/nftables ruleset to
  report whether the rules are actually enforced. Parses files rather than
  `chroot`-ing into the host (the container drops `CAP_SYS_CHROOT`).
- **`ufw_rules.txt`** scan artefact — generated in `run_scan.sh` §3.2b via that
  parser (raw-grep fallback if `python3` is unavailable); registered in
  `remediate.py` analysis inputs and Slack-attachment lists.
- **Boot self-check** in `scripts/entrypoint.sh` — logs the rendered schedule,
  `SCAN_SCHEDULE_CRON`, container clock/TZ, LLM backend+model (warns if unset),
  and runnable state (secrets, reports-volume writable, scan lock, supercronic
  present). All lines guarded — never blocks startup.

### Fixed
- **Scan failing at the remediation step (LLM 404).** A running container with a
  stale `ANTHROPIC_MODEL=haiku` made every scan collect data successfully and
  then abort at the first LLM call with `404 "haiku not configured globally"`
  (a non-retryable/fatal class), so **no Threat Brief reached Slack**. The AI
  gateway serves `coder` (HTTP 200); `haiku` / `claude-sonnet-5` return 404.
  Resolution: correct the value in `.env` and **recreate the container** so it
  re-reads the environment. See *Upgrade notes*.
- **Misleading firewall guidance.** `ufw_status.txt` is the *container's* own
  `ufw status` (always "inactive" here) and was being read as if it were the
  host's. Prompt guidance now says so and points to `ufw_rules.txt`.

### Changed
- **Timezone pinned for cron determinism.** `TZ=Asia/Kolkata` is now set in the
  container (default in `docker-compose.yml`, documented in `.env.example`) and
  `tzdata` is installed in the image. Cron day-of-month times were previously
  interpreted as UTC; they now fire at Kolkata local time on every server.
  Override per-host via `TZ=` in `.env` if a different zone is required.

### Verified
- Full scan `2026-11-12T071602Z` completed end-to-end (Threat Brief posted to
  Slack, 0 failed chunks); a targeted UFW-only analysis + Slack post also
  succeeded, with findings sourced from `ufw_rules.txt`.

### ⬆️ Upgrade notes (read before deploying)
1. **`ANTHROPIC_MODEL` must be a model your gateway actually serves.** A wrong
   id is fatal and produces *no report* while the scan still "runs". Verify with
   `GET <base>/v1/models` and a real `/v1/messages` call.
2. **The model / schedule / TZ values only take effect when the container is
   recreated** (`docker compose up -d --build`). Editing `.env` alone does not
   change an already-running container — this exact staleness caused the outage.
3. After deploy, run the boot self-check with `docker logs brahma-danda` and
   confirm model, TZ, secrets, and lock are healthy on each server.
