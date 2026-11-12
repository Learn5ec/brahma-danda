# Changelog

All notable changes to this project are documented here.

## Unreleased — 2026-11-12 (branch-3)

### Fixed — scan failing at the remediation step (LLM 404)
- Root cause of the failed `2026-11-12T060452Z` scan: the running container had a
  **stale `ANTHROPIC_MODEL=haiku`** baked in. The AI gateway serves `coder`
  (HTTP 200) but returns `404 "haiku not configured globally"` for `haiku` (and
  for `claude-sonnet-5`), and `remediate.py` treats a 404 as a non-retryable
  fatal error → the Threat Brief / Slack post never ran even though every
  collection tool succeeded.
- `.env` already specified `ANTHROPIC_MODEL=coder`; the fix was to **rebuild the
  image and recreate the container** so it re-reads `.env`. Verified: the
  Anthropic SDK forced-tool-use call now succeeds and full scans post to Slack.
- Note: the in-code fallback model `"claude-sonnet-5"` (`_make_anthropic_client`)
  is also not served by this gateway, but it only applies when both
  `ANTHROPIC_MODEL` and `CLAUDE_MODEL` are empty, and it is correct for the
  real Anthropic-cloud path — left unchanged.

### Added — host UFW configuration reported as a native `ufw status` table
Previously the firewall artefact (`ufw_status.txt`) came from running
`ufw status verbose` **inside the container**, which reads the container's own
`/etc/ufw` (not the host's) and prints **no per-port rules when UFW is
inactive** — so the host's real, per-port firewall configuration (which ports it
allows, from which source IPs) was invisible.

- **New `scripts/checks/ufw_rules_report.py`** — stdlib-only parser that
  reconstructs the host's UFW ruleset from the read-only `/host` mount and
  renders it in the native `ufw status` **To / Action / From** table, including
  each rule's source IP and inline `# comment`, plus the enabled state, default
  INPUT/OUTPUT policies, IPv4 **and** IPv6 rules, and a **reconciliation** line
  that checks the live iptables/nftables ruleset to report whether the rules are
  actually enforced. It parses files rather than `chroot`-ing into the host
  because the container drops `CAP_SYS_CHROOT`.
- **`scripts/run_scan.sh`** (§3.2b) now generates a new
  `${REPORT_DIR}/ufw_rules.txt` artefact via that parser, with a raw-grep
  fallback if `python3` is ever unavailable.
- **`scripts/remediate.py`** — `ufw_rules.txt` registered in the analysis-input
  list and both Slack-attachment lists, so it is analysed by the model and
  attached to the report.
- **`scripts/prompts.py`** — corrected the misleading guidance ("inactive" in
  `ufw_status.txt` reflects the scanner image, NOT the host) and added
  instructions to report/reconcile `ufw_rules.txt`, treating `From: Anywhere`
  allow rules as world-exposed while not over-flagging rules scoped to a
  specific source IP.

### Verified
- Full scan `2026-11-12T071602Z` completed end-to-end (Threat Brief posted to
  Slack, 0 failed chunks). Targeted UFW-only analysis + Slack post also
  succeeded (findings sourced from `ufw_rules.txt`).
