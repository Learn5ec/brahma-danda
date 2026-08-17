#!/usr/bin/env python3
"""
Reads the raw scan output for one run, asks Claude to turn it into a
prioritized remediation plan, then posts the plan + raw reports to Slack.

Secrets are read from /run/secrets/*, never from environment variables.
"""
import argparse
import datetime
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import requests
from anthropic import Anthropic

MAX_RAW_CHARS_PER_FILE = 60_000  # keep the prompt bounded on noisy hosts

SYSTEM_PROMPT = """You are a security engineer producing a remediation plan from raw \
vulnerability-scan output for a single Linux server. You will receive:
- Trivy JSON (OS package CVEs, matched against the real installed versions — treat as \
authoritative for CVE presence/absence)
- debsecan output (Debian-tracker cross-check; on Ubuntu hosts this is best-effort only, \
Trivy is the primary source of truth if they disagree)
- SSH and nginx config-hardening check results (JSON, pass/fail per rule)
- nmap self-scan output (open ports + NSE script results, including CVE-detection scripts)

CRITICAL — for the nmap section specifically, actively distinguish real findings from likely \
false positives:
- NSE CVE-detection scripts (vulners, vulscan, etc.) match on the raw banner version string. \
Distro-packaged software (especially Debian/Ubuntu OpenSSH, with a distro suffix like \
'Ubuntu-3ubuntuNN.NN') is very often patched via backport while the banner stays the same — \
flag these explicitly as "likely false positive — verify via package manager" rather than \
listing them as confirmed. Cross-check against what Trivy/debsecan say about the same package \
where possible, since those ARE package-manager-accurate.
- Slowloris and similar DoS-heuristic script results ("LIKELY VULNERABLE") are weak heuristics — \
label them as needing manual verification (e.g. slowhttptest), not as confirmed vulnerabilities.
- Unidentified/unconfirmed services (nmap's own '?' suffix) are open questions needing manual \
verification, not findings.

Produce a markdown remediation plan with this exact structure:

## Security Scan Summary — {host}
One paragraph: overall risk posture, headline numbers (X critical, Y high, etc), and how many \
nmap findings are high-confidence vs. likely false positive.

## Priority 1 — Fix Immediately (Critical)
## Priority 2 — Fix This Sprint (High)
## Priority 3 — Verify First (flagged as possible false positive — confirm before acting)
## Priority 4 — Fix When Convenient (Medium/Low)

Under each priority, list each finding as:
- **[finding name]** — one-line description of the risk
  - Fix: exact command or config change (or exact verification step, for Priority 3 items)

Rules:
- Only include a finding once, in its highest applicable severity bucket.
- If a Trivy CVE affects a package where the installed version string suggests a distro \
backport, say so explicitly and mark it lower confidence rather than omitting it.
- If debsecan and Trivy disagree, note the disagreement and say which one to trust and why.
- Passing checks: do not list them individually, just note the count that passed.
- Be concrete. Never say "add security headers" — give the exact header/value/line.
- End with a "## Suggested Re-Scan Scope" section listing exactly what to verify after fixes \
are applied.
"""


def read_secret(name: str) -> str:
    path = Path(f"/run/secrets/{name}")
    if not path.exists():
        print(f"[remediate] ERROR: secret file {path} not found", file=sys.stderr)
        sys.exit(1)
    return path.read_text().strip()


def read_truncated(path: Path) -> str:
    if not path.exists():
        return f"(file not found: {path.name})"
    text = path.read_text(errors="replace")
    if len(text) > MAX_RAW_CHARS_PER_FILE:
        return text[:MAX_RAW_CHARS_PER_FILE] + f"\n...[truncated, {len(text)} chars total]"
    return text


def summarize_nmap_xml(xml_path: Path) -> str:
    """Compact text summary of nmap's XML — bounded size, keeps the CVE
    script output that actually matters for the remediation plan."""
    if not xml_path.exists():
        return "(nmap scan did not run or nmap.xml not found — see NMAP_SELF_SCAN in .env)"
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        return f"(failed to parse nmap.xml: {e})"

    root = tree.getroot()
    lines = []
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port.get("portid")
            protocol = port.get("protocol")
            service_el = port.find("service")
            service_str = "unknown"
            if service_el is not None:
                name = service_el.get("name", "?")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                extrainfo = service_el.get("extrainfo", "")
                service_str = f"{name} {product} {version} {extrainfo}".strip()
            lines.append(f"- {protocol}/{portid} open — {service_str}")
            for script in port.findall("script"):
                script_id = script.get("id")
                output = (script.get("output") or "").strip()
                if len(output) > 1200:
                    output = output[:1200] + "...[truncated]"
                lines.append(f"    [script: {script_id}]\n    {output}")

    return "\n".join(lines) if lines else "(nmap ran but found no open ports)"


def build_user_prompt(report_dir: Path, host: str) -> str:
    trivy = read_truncated(report_dir / "trivy.json")
    debsecan = read_truncated(report_dir / "debsecan.txt")
    ssh_checks = read_truncated(report_dir / "ssh_checks.json")
    nginx_checks = read_truncated(report_dir / "nginx_checks.json")
    nmap_summary = summarize_nmap_xml(report_dir / "nmap.xml")
    if len(nmap_summary) > MAX_RAW_CHARS_PER_FILE:
        nmap_summary = nmap_summary[:MAX_RAW_CHARS_PER_FILE] + "\n...[truncated]"

    return f"""Host: {host}

=== TRIVY (rootfs scan, JSON) ===
{trivy}

=== DEBSECAN (best-effort cross-check) ===
{debsecan}

=== SSH CONFIG CHECKS (JSON) ===
{ssh_checks}

=== NGINX CONFIG CHECKS (JSON) ===
{nginx_checks}

=== NMAP SELF-SCAN (open ports + NSE script output) ===
{nmap_summary}
"""


def call_claude(model: str, user_prompt: str) -> str:
    # Prefer env-driven gateway config (custom proxy / local endpoint),
    # fall back to /run/secrets/claude_api_key for the default Anthropic
    # cloud API.  This lets the same container run against any
    # Anthropic-compatible endpoint without rebuilding the image.
    base_url = os.environ.get("ANTHROPIC_BASE_URL")
    api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN") or read_secret("claude_api_key")

    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
        print(f"[remediate] using custom Anthropic gateway: {base_url}")

    client = Anthropic(**kwargs)
    resp = client.messages.create(
        model=model,
        max_tokens=4000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return "".join(block.text for block in resp.content if block.type == "text")


def call_ollama(model: str, base_url: str, system_prompt: str, user_prompt: str) -> str:
    """Call a local Ollama instance using the OpenAI-compatible API."""
    import json as _json

    url = f"{base_url.rstrip('/')}/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {"num_predict": 4000},
    }

    print(f"[remediate] calling Ollama ({model}) at {base_url}")
    resp = requests.post(url, json=payload, timeout=600)
    resp.raise_for_status()
    data = resp.json()
    return data.get("message", {}).get("content", "")


def upload_file_to_slack(channel: str, file_path: Path, title: str) -> bool:
    """Upload a file to Slack using the 3-step External Upload API."""
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Get upload URL
    file_size = file_path.stat().st_size
    if file_size == 0:
        print(f"[remediate] Skipping empty file: {file_path.name}", file=sys.stderr)
        return True  # Not an error, just skip

    url_resp = requests.post(
        "https://slack.com/api/files.getUploadURLExternal",
        headers=headers,
        data={
            "filename": file_path.name,
            "length": str(file_size),
        },
        timeout=30,
    )
    url_resp.raise_for_status()
    url_data = url_resp.json()
    if not url_data.get("ok"):
        print(f"[remediate] Step 1 failed for {file_path.name}: {url_data}", file=sys.stderr)
        return False

    upload_url = url_data["upload_url"]
    file_id = url_data["file_id"]

    # Step 2: Upload file content
    with open(file_path, "rb") as f:
        content_resp = requests.post(
            upload_url,
            headers={"Authorization": f"Bearer {token}"},
            data=f.read(),
            timeout=120,
        )
    content_resp.raise_for_status()

    # Step 3: Complete upload
    complete_resp = requests.post(
        "https://slack.com/api/files.completeUploadExternal",
        headers={**headers, "Content-Type": "application/json"},
        json={
            "files": [
                {
                    "id": file_id,
                    "title": title,
                }
            ],
            "channel_id": channel,
            "initial_comment": f"{host} — {file_path.name}",
        },
        timeout=30,
    )
    complete_resp.raise_for_status()
    complete_data = complete_resp.json()
    if not complete_data.get("ok"):
        print(f"[remediate] Step 3 failed for {file_path.name}: {complete_data}", file=sys.stderr)
        return False

    # Verify channel membership
    files = complete_data.get("files", [])
    if files:
        channels = files[0].get("channels", [])
        groups = files[0].get("groups", [])
        if not channels and not groups:
            print(f"[remediate] ⚠️ File uploaded but not posted to channel (bot may not be invited): {file_path.name}", file=sys.stderr)

    return True


def post_to_slack(channel: str, markdown: str, report_dir: Path, host: str) -> None:
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}

    # Slack markdown is "mrkdwn", not full GFM — convert the essentials.
    slack_text = markdown.replace("## ", "*").replace("**", "*")
    # Slack messages have a ~40k char hard cap; keep headroom.
    if len(slack_text) > 38000:
        slack_text = slack_text[:38000] + "\n...[truncated — see attached full report]"

    # Split into multiple blocks if needed (Slack limit: 3001 chars per text)
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f":shield: *Monthly security scan complete for `{host}`*"}},
        {"type": "divider"},
    ]

    # Split text into chunks of 3000 chars
    chunk_size = 3000
    for i in range(0, len(slack_text), chunk_size):
        chunk = slack_text[i:i+chunk_size]
        if i > 0:
            chunk = f"_(continued from previous message)_\n\n{chunk}"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})

    msg_resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=headers,
        json={
            "channel": channel,
            "text": f":shield: Monthly security scan complete for *{host}*",
            "blocks": blocks,
        },
        timeout=30,
    )
    msg_resp.raise_for_status()
    if not msg_resp.json().get("ok"):
        print(f"[remediate] Slack chat.postMessage error: {msg_resp.json()}", file=sys.stderr)

    thread_ts = msg_resp.json().get("ts")

    # Attach raw reports using 3-step External Upload API
    for raw_file in [
        "trivy.json", "debsecan.txt", "ssh_checks.json", "nginx_checks.json",
        "nmap.xml", "nmap.txt",
    ]:
        fpath = report_dir / raw_file
        if not fpath.exists():
            continue
        success = upload_file_to_slack(channel, fpath, f"{host} — {raw_file}")
        if not success:
            print(f"[remediate] ⚠️ Failed to upload {raw_file} to Slack", file=sys.stderr)


def copy_reports_to_local(report_dir: Path, host: str) -> Path:
    """Copy all raw reports to ~/Downloads/brahma-danda_reports/ for local access."""
    import shutil
    local_dir = Path.home() / "Downloads" / "brahma-danda_reports" / f"{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    local_dir.mkdir(parents=True, exist_ok=True)
    for f in report_dir.iterdir():
        if f.is_file():
            shutil.copy2(f, local_dir / f.name)
            print(f"[remediate] copied {f.name} to {local_dir}")
    print(f"[remediate] all reports saved to {local_dir}")
    return local_dir


def post_raw_reports_to_slack(channel: str, report_dir: Path, host: str) -> None:
    """Post raw reports to Slack without a summary when LLM fails."""
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}

    # Post a simple text message indicating LLM unavailable and raw reports attached
    msg_resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=headers,
        json={
            "channel": channel,
            "text": f":warning: Security scan complete for {host} — LLM unavailable, raw reports attached",
            "blocks": [
                {"type": "section", "text": {
                    "type": "mrkdwn",
                    "text": f":warning: *Security scan complete for `{host}`*\n\nLLM unavailable — summary not generated. Raw reports attached below.",
                }},
                {"type": "divider"},
            ],
        },
        timeout=30,
    )
    msg_resp.raise_for_status()

    # Attach all raw reports using 3-step External Upload API
    for raw_file in [
        "trivy.json", "debsecan.txt", "ssh_checks.json", "nginx_checks.json",
        "nmap.xml", "nmap.txt",
    ]:
        fpath = report_dir / raw_file
        if not fpath.exists():
            continue
        success = upload_file_to_slack(channel, fpath, f"{host} — {raw_file}")
        if not success:
            print(f"[remediate] ⚠️ Failed to upload {raw_file} to Slack", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    # ANTHROPIC_MODEL takes precedence (custom gateway flow), CLAUDE_MODEL is
    # the legacy env var, "claude-sonnet-5" is the fallback default.
    model = os.environ.get("ANTHROPIC_MODEL") or os.environ.get("CLAUDE_MODEL", "claude-sonnet-5")
    channel = os.environ["SLACK_CHANNEL_ID"]

    # Check if Ollama is configured (local model fallback)
    ollama_url = os.environ.get("OLLAMA_BASE_URL")
    ollama_model = os.environ.get("OLLAMA_MODEL")

    print(f"[remediate] building prompt from {report_dir}")
    user_prompt = build_user_prompt(report_dir, args.host)

    # Tiered fallback:
    #   1. Claude API (primary) → generate summary
    #   2. Ollama (fallback) → generate summary
    #   3. Both fail → post raw reports to Slack, copy to ~/Downloads
    plan_markdown = None
    backend_used = None

    # Try Claude (custom gateway or cloud API)
    print(f"[remediate] trying Claude ({model})")
    try:
        plan_markdown = call_claude(model, user_prompt)
        backend_used = "Claude"
        print(f"[remediate] Claude succeeded")
    except Exception as e:
        print(f"[remediate] Claude call failed: {e}")
        # Try Ollama if configured
        if ollama_url and ollama_model:
            print(f"[remediate] falling back to Ollama: {ollama_model} at {ollama_url}")
            try:
                plan_markdown = call_ollama(ollama_model, ollama_url, SYSTEM_PROMPT, user_prompt)
                backend_used = "Ollama"
                print(f"[remediate] Ollama succeeded")
            except Exception as e2:
                print(f"[remediate] Ollama call also failed: {e2}")
        else:
            print(f"[remediate] Ollama not configured — skipping")

    # If both LLMs failed, save locally and post raw reports only
    if plan_markdown is None:
        print(f"[remediate] ⚠️ Both Claude and Ollama failed — no summary available")
        copy_reports_to_local(report_dir, args.host)
        print(f"[remediate] posting raw reports to Slack channel {channel}")
        post_raw_reports_to_slack(channel, report_dir, args.host)
        print("[remediate] done (raw reports only)")
        return

    plan_path = report_dir / "remediation_plan.md"
    plan_path.write_text(plan_markdown)
    print(f"[remediate] plan written to {plan_path}")

    print(f"[remediate] posting to Slack channel {channel}")
    post_to_slack(channel, plan_markdown, report_dir, args.host)
    print("[remediate] done")


if __name__ == "__main__":
    main()
