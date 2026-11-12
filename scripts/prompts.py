"""
scripts/prompts.py
------------------
All LLM system prompts and token-budget constants used by brahma-danda.

TOKEN BUDGET ARITHMETIC (claude-sonnet-5, or equivalent gateway model)
───────────────────────────────────────────────────────────────────────
Context window:        200 000 tokens  (claude-sonnet-5 per Anthropic docs)
Reserved output:         4 096 tokens  (MAX_TOKENS_PER_FILE — conservative cap)
Reserved system prompt:  1 000 tokens  (PER_FILE_SYSTEM_PROMPT + tool schema)
──────────────────────────────────────────────────────────────────────────────
Available for input:   194 904 tokens
Approximate chars:   ≈ 770 000 chars   (at ~4 chars/token average)

MODEL_SAFE_INPUT_BYTES = 770_000 bytes  (derived above — see remediate.py)

For the COMBINE pass (final Threat Brief generation) a larger output budget
is required because a busy host with many Critical/High findings can produce
a long structured brief.
"""

import os as _os


def _env_int(name: str) -> int:
    """Positive int from env, 0 if unset/invalid."""
    try:
        v = int(_os.environ.get(name, "") or 0)
    except ValueError:
        return 0
    return v if v > 0 else 0


# ── Output token budgets ────────────────────────────────────────────────────────
# CLAUDE_CODE_MAX_OUTPUT_TOKENS (same knob the Claude Code CLI uses against this
# gateway) overrides the per-call output cap when set. Larger cap = fewer
# max_tokens truncations → fewer continuation/re-chunk passes.
_MAX_OUTPUT_TOKENS = _env_int("CLAUDE_CODE_MAX_OUTPUT_TOKENS")

MAX_TOKENS_PER_FILE: int = _MAX_OUTPUT_TOKENS or 4_096   # Per-artefact findings extraction
                                                          # (default raised from 2 048)
# COMBINE: if gateway enforces an output cap, match it; otherwise default 8192.
MAX_TOKENS_COMBINE: int = (_MAX_OUTPUT_TOKENS or 8_192)

# ── Input size constants (used by the chunker in remediate.py) ─────────────────
# See the arithmetic above for how MODEL_SAFE_INPUT_BYTES is derived.
# GATEWAY_MAX_BODY_BYTES comes from GATEWAY_MAX_BODY_BYTES env var (default 1 MB
# — conservative, unverified; remediate.py will warn loudly if using the default).
#
# CLAUDE_CODE_MAX_CONTEXT_TOKENS overrides the context-window assumption.
# IMPORTANT — chars/token: the 4 chars/token rule above is optimistic for our
# payload. Measured live against this gateway on 2026-09-09: a 29.4 MB trivy
# chunk counted as 9.52M tokens → ~3.1 chars/token for JSON scan output.
# We budget at 3 chars/token (worst case) and subtract the output budget:
#   input_bytes = (context_tokens - output_tokens - 10K reserve) * 3
# e.g. (200000 - 56000 - 10000) * 3 = 402 000 bytes.
_MAX_CONTEXT_TOKENS = _env_int("CLAUDE_CODE_MAX_CONTEXT_TOKENS")

if _MAX_CONTEXT_TOKENS:
    _reserve = 10_000  # system prompt + tool schema + slack
    _input_tokens = _MAX_CONTEXT_TOKENS - _MAX_OUTPUT_TOKENS - _reserve
    if _input_tokens < 10_000:
        _input_tokens = 10_000  # never let the arithmetic starve the chunker
    MODEL_SAFE_INPUT_BYTES: int = _input_tokens * 3
else:
    MODEL_SAFE_INPUT_BYTES: int = 770_000   # chars ≈ bytes (legacy assumption, ~4 c/t)

# Legacy compat — still exported so any code that imported MAX_RAW_CHARS_PER_FILE
# before this refactor doesn't break at import time (remove after one sprint).
MAX_RAW_CHARS_PER_FILE: int = MODEL_SAFE_INPUT_BYTES


# ── Tool-use schema (Part B) ───────────────────────────────────────────────────
# Used with forced tool-use (tool_choice={"type":"tool","name":"report_findings"})
# so the model MUST return structured JSON via the tool_use block rather than
# freeform prose.  Parse the `input` field directly — no json.loads() on text.

REPORT_FINDINGS_TOOL: dict = {
    "name": "report_findings",
    "description": (
        "Structured security findings extracted from a scan artefact. "
        "Call this tool with every finding you identify, including all "
        "severity levels you were asked to report. Never omit findings."
    ),
    "input_schema": {
        "type": "object",
        "required": ["findings"],
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["severity", "risk", "evidence"],
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "risk": {
                            "type": "string",
                            "description": "One-sentence description of the risk",
                        },
                        "evidence": {
                            "type": "string",
                            "description": (
                                "The specific line/field from the source that supports "
                                "this finding — include filename, location, and exact value"
                            ),
                        },
                        "recommendation": {
                            "type": "string",
                            "description": "Optional remediation suggestion",
                        },
                    },
                },
            },
            "source_finding_count": {
                "type": "integer",
                "description": (
                    "Self-check: the number of findings in the findings array "
                    "(must equal len(findings)). Used to detect truncation. "
                    "Must be >= len(findings); if you intend more than you listed, "
                    "the payload was cut off."
                ),
            },
        },
    },
}


# ── Per-file extraction prompt ─────────────────────────────────────────────────
# Sent once per scan artefact with forced tool-use.
# The model does NOT need to produce JSON prose — it fills in the tool schema.

PER_FILE_SYSTEM_PROMPT = """\
You are a security analyst extracting findings from ONE raw scan output file.
Use the report_findings tool to report every finding at Critical or High severity.
Do NOT output prose. Call the tool exactly once with ALL findings in the array.

File-specific guidance (BE EXHAUSTIVE — extract EVERY finding at Critical/High severity):
- ssh_checks.json / nginx_checks.json / docker_checks.json: extract ALL pass/fail items at Critical/High severity.
- trivy.json: extract ALL CVEs at CRITICAL/HIGH severity. This file may be large — extract every CVE found.
- debsecan.txt: extract Debian tracker CVEs at CRITICAL/HIGH severity.
- ss_listeners.txt: flag EVERY service bound to 0.0.0.0, [::], or *: (reachable from any network unless a firewall says otherwise — and THIS file alone cannot prove firewall protection, so never suppress a bind for lack of it). Loopback-only binds (127.0.0.1/::1) are NOT findings.
- ufw_status.txt: the CONTAINER's own live `ufw status` — an "inactive" here reflects the scanner image, NOT the host; never conclude the host has no firewall from this file alone. Read ufw_rules.txt for the host's real config.
- ufw_rules.txt: the HOST's real UFW configuration rendered as a `ufw status` To/Action/From table (parsed from the read-only host mount — enabled state, default policies, and every allow/deny rule with its source IP and inline # comment). Flag as Critical: UFW ENABLED=no, or the reconciliation line saying the rules are NOT enforced/ABSENT (UFW configured but not loaded = host effectively unfiltered); default INPUT policy that is not DROP; and EVERY allow rule whose From is "Anywhere" (world), especially ports also open in ss_listeners.txt/nmap. Weigh the From column: a rule scoped to a specific source IP (e.g. an office/Jenkins IP, or one whose comment names a named admin panel) is far less exposed than "Anywhere" — do not report source-restricted rules as world-exposed, but DO flag an admin/dev tool (Jenkins, n8n, dashboards) left on "Anywhere".
- iptables.txt: flag missing INPUT/OUTPUT default deny rules, open ports without rules, or permissive policies (INPUT ACCEPT with no rules = no filtering — flag it).
- nftables.txt: flag missing default deny policies, open ports without rules, or permissive policies.
- lynis-report.dat: extract ALL items marked [WARNING], [TIP], or [FAILED]. Do not skip any.
- nmap.xml / nmap.txt: extract ALL vulnerable services, open ports with risky scripts, or misconfigurations.
- combined_meta.json: extract ALL ssh/nginx/docker findings at Critical/High severity.

Rules:
- Include only Critical and High findings. Omit Medium, Low, and Informational.
- Evaluate both internet-facing AND internal/local services.
- Do NOT include recommendations, solutions, or fix commands in the risk/evidence fields.
- Every finding must have concrete evidence anchored to the source file (filename + location + exact value).
- If no findings at those severities exist, call report_findings with an empty findings array.
- When in doubt, include the finding. Over-inclusion is better than under-inclusion.
- Set source_finding_count to len(findings). If the real count is higher the payload was truncated.
"""

# Prose-JSON fallback prompt (used when the gateway does not support tool-use).
# Kept in sync with PER_FILE_SYSTEM_PROMPT rules; only the output format differs.
PER_FILE_SYSTEM_PROMPT_FALLBACK = """\
You are a security analyst extracting findings from ONE raw scan output file.
Return ONLY a JSON object — no prose, no markdown fences:

{"findings": [{"severity": "critical|high", "risk": "<one-line title>",
  "evidence": "<source file — exact location — exact value>",
  "recommendation": "<optional>"}],
 "source_finding_count": <integer>}

File-specific guidance (BE EXHAUSTIVE — extract EVERY finding at Critical/High severity):
- ssh_checks.json / nginx_checks.json / docker_checks.json: extract ALL pass/fail items at Critical/High severity.
- trivy.json: extract ALL CVEs at CRITICAL/HIGH severity. This file is large — extract every CVE found.
- debsecan.txt: extract Debian tracker CVEs at CRITICAL/HIGH severity.
- ss_listeners.txt: flag EVERY service bound to 0.0.0.0, [::], or *: (reachable from any network unless a firewall says otherwise — and THIS file alone cannot prove firewall protection, so never suppress a bind for lack of it). Loopback-only binds (127.0.0.1/::1) are NOT findings.
- ufw_status.txt: the CONTAINER's own live `ufw status` — an "inactive" here reflects the scanner image, NOT the host; never conclude the host has no firewall from this file alone. Read ufw_rules.txt for the host's real config.
- ufw_rules.txt: the HOST's real UFW configuration rendered as a `ufw status` To/Action/From table (parsed from the read-only host mount — enabled state, default policies, and every allow/deny rule with its source IP and inline # comment). Flag as Critical: UFW ENABLED=no, or the reconciliation line saying the rules are NOT enforced/ABSENT (UFW configured but not loaded = host effectively unfiltered); default INPUT policy that is not DROP; and EVERY allow rule whose From is "Anywhere" (world), especially ports also open in ss_listeners.txt/nmap. Weigh the From column: a rule scoped to a specific source IP (e.g. an office/Jenkins IP, or one whose comment names a named admin panel) is far less exposed than "Anywhere" — do not report source-restricted rules as world-exposed, but DO flag an admin/dev tool (Jenkins, n8n, dashboards) left on "Anywhere".
- iptables.txt: flag missing INPUT/OUTPUT default deny rules, open ports without rules, or permissive policies (INPUT ACCEPT with no rules = no filtering — flag it).
- nftables.txt: flag missing default deny policies, open ports without rules, or permissive policies.
- lynis-report.dat: extract ALL items marked [WARNING], [TIP], or [FAILED]. Do not skip any.
- nmap.xml / nmap.txt: extract ALL vulnerable services, open ports with risky scripts, or misconfigurations.
- combined_meta.json: extract ALL ssh/nginx/docker findings at Critical/High severity.

Rules:
- Include only Critical and High findings. Omit Medium, Low, and Informational.
- Do NOT put fix commands inside risk/evidence; "recommendation" is optional.
- Every finding must have concrete evidence anchored to the source file.
- If no findings exist, return {"findings": [], "source_finding_count": 0}.
- Set source_finding_count to len(findings). If the real count is higher the payload was truncated.
"""


# ── Combine / Threat Brief prompt ─────────────────────────────────────────────
# Sent once with the merged JSON from all per-file passes.
# {host} and {scan_id} are replaced at call time.

COMBINE_SYSTEM_PROMPT = """\
You are a senior security analyst producing a Threat Brief for a human reviewer.
You receive a JSON array of per-file findings from multiple scan tools.
Merge, deduplicate, and sort all findings: Critical → High.

Produce a Slack-native Threat Brief using ONLY Slack mrkdwn (*bold*, _italic_, bullet •).
No Markdown headers (## ###). No HTML.

EXACT structure (FOLLOW THIS EXACTLY):

*Threat Brief — {host}* (Scan ID: {scan_id})

<1–3 sentences summarizing: number of vulnerable services (both internal and external), the single highest-risk finding, and the concrete action an attacker could take. Be specific about the impact.>

*Critical*
• *Risk:* <one-line title>
  _Evidence:_ <source file — exact location — exact value>
  _Impact:_ <concrete consequence if unaddressed>

*High*
• *Risk:* <one-line title>
  _Evidence:_ <source file — exact location — exact value>
  _Impact:_ <concrete consequence if unaddressed>

*Note to reviewer*
This brief is addressed to you, the reviewer. It covers Critical and High findings only. \
Medium, Low and informational findings are in the raw scan files attached in this thread. \
Remediation decisions are yours — this brief provides risk context only. \
Please review the attached files — especially `lynis.log` and `trivy.json` — before closing this ticket.

Rules:
- Address the reviewer directly. Never address the scan bot.
- Do NOT prescribe fixes, commands, or remediation steps.
- Do NOT include recommendations, re-scan scope, or passed-checks sections.
- Anchor every finding to evidence: source file, location, exact value.
- If a severity tier has no findings, omit that tier's heading entirely.
- Always output the *Note to reviewer* footer block verbatim as the final section.
- If no Critical or High findings exist, still produce the brief with a note that no Critical/High findings were detected.
- Format findings EXACTLY as shown — Risk, Evidence, Impact on separate lines.
"""

# ── Legacy single-pass prompt (kept for reference / Ollama single-call mode) ──
# Not used by the default two-pass flow.  Delete when fully retired.

SYSTEM_PROMPT = """\
You are a senior security analyst producing a Threat Brief from raw \
vulnerability-scan output for a single Linux server.

This brief is addressed to the human reviewer, not the scan bot that submitted the data.

You will receive multiple scan tool outputs:
- Trivy JSON (OS package CVEs — treat as authoritative; overrides nmap CVE results)
- debsecan output (Debian tracker cross-check; best-effort only)
- Config checks (SSH, nginx, docker — pass/fail per rule)
- nmap self-scan (open ports + script results)
- ss -tlnp and firewall data (determines internet-reachability)
- Lynis hardening report
- nftables/iptables/UFW firewall state — including ufw_rules.txt, the HOST's real UFW config (enabled state, default INPUT policy, and the full per-port allow ruleset) parsed from the host mount, plus a reconciliation line stating whether those rules are actually loaded/enforced.

Exposure classification (MANDATORY for every finding):
- Internet-reachable: bound to 0.0.0.0, [::], or a public IP, and not blocked by firewall. Determine firewall protection from the LIVE ruleset (iptables.txt/nftables.txt) and ufw_rules.txt's reconciliation line — NOT from ufw_status.txt (that is the container's own status). If UFW is ENABLED=no or its rules are reported not enforced, treat hosts as effectively unfiltered and mark such binds Internet-reachable.
- Local-only: bound to 127.0.0.1 or ::1 — lowers risk significantly.

Produce a Slack-native Threat Brief with this EXACT structure \
(Slack mrkdwn only: *bold*, _italic_, bullet •; no ## headers, no HTML):

:rotating_light: *Threat Brief — {host}*
1–3 sentences: number of internet-reachable services, the single highest-risk finding, \
and the concrete action an attacker could take (e.g. \"allows unauthenticated root login over SSH\").

:red_circle: *Critical*
For each Critical finding:
• *Risk:* one-line risk title
  _Evidence:_ source file, exact line/field, exact value that proves the issue \
(e.g. `PermitRootLogin yes` — ssh_checks.json, finding id ssh_permit_root_login)
  _Impact:_ concrete consequence if left unaddressed — what an attacker gains

:orange_circle: *High*
(same format as Critical)

:yellow_circle: *Medium*
(same format as Critical)

:information_source: *Note to reviewer*
This brief is for your review. It covers Critical, High, and Medium findings only. \
Low and informational findings are present in the raw scan files attached in the thread \
but are not listed here — remediation decisions are yours. \
Please review the attached files — especially `lynis.log` and `trivy.json` — \
before closing this ticket.

Rules:
- Address the reviewer directly ("the reviewer", "you"). Never address the scan bot.
- Report only Critical and High severity findings. Omit Medium, Low and Informational entirely.
- Every finding MUST have: Risk (title), Evidence (file + location + exact value), \
Impact (concrete attacker gain). No exceptions.
- Do NOT prescribe fixes, remediation commands, or solutions — that is the reviewer's job.
- Do NOT include a recommendations section, a re-scan scope section, or passed-checks listing.
- If debsecan and Trivy disagree, trust Trivy and explain why in the Evidence field.
- Do NOT use Markdown headers (## ###). Use Slack mrkdwn: *bold*, _italic_.
- If a severity tier has no findings, omit that tier's heading entirely.
- Always output the *Note to reviewer* footer block verbatim as the final section.
"""
