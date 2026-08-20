#!/usr/bin/env python3
"""
Reads the raw scan output for one run, asks Claude to turn it into a
Threat Brief, then posts the plan + raw reports to Slack.

Secrets are read from /run/secrets/*, never from environment variables.
"""
import argparse
import datetime
import json
import os
import random
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import requests
from anthropic import Anthropic

# Playful fallback messages when LLM is unavailable
LLM_FALLBACK_MESSAGES = [
    "Looks like the Summarizer Agent is taking a well-deserved vacation. 😎 Guess it's time for us to roll up our sleeves and manually analyse the reports for vulnerabilities. The raw reports are attached in the thread below—fresh from the source, zero summarization, maximum adventure. 🔍🫡",
    "The Summarizer Agent appears to be MIA. 🫡 No worries—manual vulnerability hunting it is! The raw reports are waiting for us in the thread below, ready to be lovingly combed through the old-fashioned way. 😄",
    "Summarizer Agent is currently unavailable. Please enjoy this exciting new feature: **doing it yourself**™. 😄 The raw reports are attached in the thread below—because apparently, today we're choosing the *hands-on* experience. 🔎",
]

from prompts import (
    SYSTEM_PROMPT,
    PER_FILE_SYSTEM_PROMPT,
    COMBINE_SYSTEM_PROMPT,
    MAX_TOKENS_PER_FILE,
    MAX_TOKENS_COMBINE,
    MAX_RAW_CHARS_PER_FILE,
)



def read_secret(name: str) -> str:
    path = Path(f"/run/secrets/{name}")
    if not path.exists():
        print(f"[remediate] ERROR: secret file {path} not found", file=sys.stderr)
        sys.exit(1)
    return path.read_text().strip()


def summarize_trivy_json(json_path: Path) -> str:
    """Extract top 50 CVEs from trivy JSON, sorted by severity. Strips metadata."""
    if not json_path.exists():
        return "(trivy scan did not run or trivy.json not found)"
    try:
        data = json.loads(json_path.read_text(errors="replace"))
    except (json.JSONDecodeError, Exception):
        return "(failed to parse trivy.json)"

    cves = []
    for item in data.get("Results", []):
        for vuln in item.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "MEDIUM").lower()
            cves.append({
                "id": vuln.get("VulnerabilityID", "UNKNOWN"),
                "pkg": vuln.get("PkgName", "unknown"),
                "version": vuln.get("InstalledVersion", "?"),
                "fix": vuln.get("FixedVersion", "not fixed"),
                "severity": severity,
                "title": vuln.get("Title", "Unknown vulnerability"),
                "description": vuln.get("Description", "")[:200],
            })

    # Sort by severity: critical > high > medium > low
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    cves.sort(key=lambda x: severity_order.get(x["severity"], 4))

    # Take top 50
    top_cves = cves[:50]

    lines = [f"Total CVEs found: {len(cves)}"]
    lines.append("")
    for i, cve in enumerate(top_cves, 1):
        lines.append(f"{i}. [{cve['severity'].upper()}] {cve['id']} in {cve['pkg']} ({cve['version']})")
        lines.append(f"   {cve['title']}")
        if cve['fix'] != "not fixed":
            lines.append(f"   Fix: upgrade to {cve['fix']}")
        lines.append("")

    return "\n".join(lines)


def read_truncated(path: Path, max_lines: int = 5000) -> str:
    if not path.exists():
        return f"(file not found: {path.name})"
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n...[truncated, {len(lines)} lines total]"
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


def md_to_mrkdwn(text: str) -> str:
    import re
    # H2 → bold section header with surrounding newlines
    text = re.sub(r'^## (.+)$', r'\n*\1*\n', text, flags=re.MULTILINE)
    # H3 → italic
    text = re.sub(r'^### (.+)$', r'\n_\1_\n', text, flags=re.MULTILINE)
    # **bold** → *bold*  (Slack bold)
    text = re.sub(r'\*\*(.+?)\*\*', r'*\1*', text)
    # Bullet points with bold items
    text = re.sub(r'^- \*(.+?)\*', r'• *\1*', text, flags=re.MULTILINE)
    # Plain bullets
    text = re.sub(r'^- ', r'• ', text, flags=re.MULTILINE)
    return text


def build_user_prompt(report_dir: Path, host: str) -> str:
    trivy = summarize_trivy_json(report_dir / "trivy.json")
    debsecan = read_truncated(report_dir / "debsecan.txt")
    ssh_checks = read_truncated(report_dir / "ssh_checks.json")
    nginx_checks = read_truncated(report_dir / "nginx_checks.json")
    docker_checks = read_truncated(report_dir / "docker_checks.json")

    ss_listeners = read_truncated(report_dir / "ss_listeners.txt")
    ufw_status = read_truncated(report_dir / "ufw_status.txt")
    iptables = read_truncated(report_dir / "iptables.txt")
    nftables = read_truncated(report_dir / "nftables.txt")
    lynis_log = read_truncated(report_dir / "lynis.log")

    testssl_reports = ""
    for f in sorted(report_dir.glob("testssl_*.json")):
        testssl_reports += f"\n--- {f.name} ---\n{read_truncated(f)}\n"

    nmap_summary = summarize_nmap_xml(report_dir / "nmap.xml")
    if len(nmap_summary) > MAX_RAW_CHARS_PER_FILE:
        nmap_summary = nmap_summary[:MAX_RAW_CHARS_PER_FILE] + "\n...[truncated]"

    return f"""Host: {host}

=== YOUR TASK ===
Produce a Threat Brief addressed to the human reviewer (not the scan bot).
Use Slack mrkdwn (*bold*, _italic_, bullet •). No ## headers. No HTML.

:rotating_light: *Threat Brief — {host}*
1–3 sentences: number of internet-reachable services, highest-risk finding, concrete attacker action.

*Critical*
• *Risk:* one-line risk title
  _Evidence:_ source file, exact field/line, exact value
  _Impact:_ concrete consequence if unaddressed

*High*
(same format)

:information_source: *Note to reviewer*
This brief is for your review. It covers Critical and High findings only. \
Low and informational findings are in the raw files attached in the thread. \
Remediation decisions are yours — this brief provides risk context only.

RULES:
- Report only Critical and High findings. Omit Low and Informational entirely.
- Every finding MUST have Risk + Evidence (file, location, exact value) + Impact.
- Do NOT prescribe fixes, commands, or remediation steps.
- Do NOT include recommendations, re-scan scope, or passed-checks sections.
- If debsecan and Trivy disagree, trust Trivy and note why.
- If a severity tier has no findings, omit that tier's heading entirely.
- Always output the :information_source: footer block verbatim as the final section.

=== ACTUAL DATA FOLLOWS ===

=== TRIVY (rootfs scan, JSON) ===
{trivy}

=== DEBSECAN (best-effort cross-check) ===
{debsecan}

=== CONFIG CHECKS (JSON) ===
SSH: {ssh_checks}
NGINX: {nginx_checks}
DOCKER: {docker_checks}

=== HOST HARDENING (Lynis) ===
{lynis_log}

=== PUBLIC EXPOSURE / FIREWALL ===
SS Listeners:
{ss_listeners}

UFW Status:
{ufw_status}

IPtables:
{iptables}

NFTables:
{nftables}

=== NMAP SELF-SCAN (open ports + behavioural probes) ===
{nmap_summary}

=== TLS/SSL CHECKS (testssl.sh) ===
{testssl_reports}
"""


def _make_anthropic_client():
    """Return (client, model) or (None, '') if Anthropic is not configured."""
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()

    # If neither a gateway URL nor a bearer token is set, check for the secret
    # file. If that's also missing, skip Claude entirely — Ollama will be used.
    if not base_url and not api_key:
        secret_path = Path("/run/secrets/claude_api_key")
        if not secret_path.exists():
            print("[remediate] No Anthropic config found — skipping Claude, will use Ollama")
            return None, ""
        api_key = secret_path.read_text().strip()

    is_bearer_token = bool(os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip())
    model = (os.environ.get("ANTHROPIC_MODEL", "").strip()
             or os.environ.get("CLAUDE_MODEL", "").strip()
             or "claude-sonnet-5")

    kwargs: dict = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
        print(f"[remediate] using custom Anthropic gateway: {base_url}")
        if is_bearer_token:
            kwargs["default_headers"] = {"Authorization": f"Bearer {api_key}"}

    return Anthropic(**kwargs), model


def call_claude(client: Anthropic, model: str, system: str, user_prompt: str,
                max_tokens: int = 2048, temperature: float = 0.3, top_p: float = 0.3) -> str:
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user_prompt}],
        temperature=temperature,
        top_p=top_p,
    )
    return "".join(block.text for block in resp.content if block.type == "text")


def call_ollama(model: str, base_url: str, system: str, user_prompt: str,
                num_predict: int = 2048, temperature: float = 0.3, top_p: float = 0.3) -> str:
    """Call a local Ollama instance using the chat API."""
    url = f"{base_url.rstrip('/')}/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "num_predict": num_predict,
            "temperature": temperature,
            "top_p": top_p,
        },
    }
    print(f"[remediate] calling Ollama ({model}) at {base_url}")
    resp = requests.post(url, json=payload, timeout=600)
    resp.raise_for_status()
    return resp.json().get("message", {}).get("content", "")


def _llm(system: str, user: str, *, client=None, model: str = "",
         ollama_url: str = "", ollama_model: str = "", max_tokens: int = 2048,
         temperature: float = 0.3, top_p: float = 0.3) -> str | None:
    """Try Ollama then Claude; return None if both fail."""
    if ollama_url and ollama_model:
        try:
            return call_ollama(ollama_model, ollama_url, system, user, max_tokens, temperature, top_p)
        except Exception as e:
            print(f"[remediate] Ollama failed: {e}")
    if client:
        try:
            return call_claude(client, model, system, user, max_tokens, temperature, top_p)
        except Exception as e:
            print(f"[remediate] Claude failed: {e}")
    return None


# ── Per-file analysis helpers ─────────────────────────────────────────────────

def _file_inputs(report_dir: Path) -> list[tuple[str, str]]:
    """Return (label, content) for every available scan artefact."""
    inputs = []
    trivy = summarize_trivy_json(report_dir / "trivy.json")
    if "(trivy scan did not run" not in trivy:
        inputs.append(("trivy.json", trivy))
    for fname in ["debsecan.txt", "combined_meta.json", "ss_listeners.txt", "ufw_status.txt",
                  "iptables.txt", "nftables.txt", "lynis-report.dat"]:
        content = read_truncated(report_dir / fname)
        if "(file not found" not in content:
            inputs.append((fname, content))
    nmap = summarize_nmap_xml(report_dir / "nmap.xml")
    if "(nmap scan did not run" not in nmap and "(nmap ran but found no open ports)" not in nmap:
        inputs.append(("nmap.xml", nmap))
    for f in sorted(report_dir.glob("testssl_*.json")):
        content = read_truncated(f)
        if "(file not found" not in content:
            inputs.append((f.name, content))
    return inputs


def analyze_files(report_dir: Path, host: str, **llm_kw) -> list[dict]:
    """Send each scan artefact to the LLM individually; return flat findings list."""
    inputs = _file_inputs(report_dir)
    all_findings: list[dict] = []
    print(f"[remediate] analysing {len(inputs)} scan artefact(s) individually …")
    for label, content in inputs:
        if len(content) > MAX_RAW_CHARS_PER_FILE:
            content = content[:MAX_RAW_CHARS_PER_FILE] + "\n...[truncated]"
        user = f"Host: {host}\nSource file: {label}\n\n=== FILE CONTENT ===\n{content}"
        print(f"[remediate]   → {label} ({len(content):,} chars)")
        raw = _llm(PER_FILE_SYSTEM_PROMPT, user, max_tokens=MAX_TOKENS_PER_FILE, **llm_kw)
        if not raw:
            print(f"[remediate]   ⚠️  no response for {label}, skipping")
            continue
        raw = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
        raw = re.sub(r"\s*```$", "", raw.strip(), flags=re.MULTILINE)
        try:
            findings = json.loads(raw).get("findings", [])
            for f in findings:
                f.setdefault("evidence", {})
                f["evidence"].setdefault("file", label)
            all_findings.extend(findings)
            print(f"[remediate]   ✓ {len(findings)} finding(s) from {label}")
        except json.JSONDecodeError as e:
            print(f"[remediate]   ⚠️  JSON parse error for {label}: {e} — snippet: {raw[:120]}")
    return all_findings


def combine_findings(all_findings: list[dict], host: str, **llm_kw) -> str | None:
    """Merge per-file findings into the final Slack Threat Brief via LLM."""
    if not all_findings:
        return None
    system = COMBINE_SYSTEM_PROMPT.replace("{host}", host)
    user = f"Host: {host}\n\nPer-file findings (JSON):\n{json.dumps(all_findings, indent=2)}"
    print(f"[remediate] combining {len(all_findings)} finding(s) into Threat Brief …")
    return _llm(system, user, max_tokens=MAX_TOKENS_COMBINE, **llm_kw)




def split_file(file_path: Path, max_size: int) -> list[Path]:
    """Split a file into chunks of max_size bytes. Returns list of chunk paths."""
    if file_path.stat().st_size <= max_size:
        return [file_path]

    chunks = []
    chunk_num = 1
    with open(file_path, "rb") as f:
        while True:
            chunk_data = f.read(max_size)
            if not chunk_data:
                break
            chunk_path = file_path.parent / f"{file_path.stem}-{chunk_num}.part"
            with open(chunk_path, "wb") as chunk_f:
                chunk_f.write(chunk_data)
            chunks.append(chunk_path)
            chunk_num += 1

    # Clean up original file
    file_path.unlink()
    print(f"[remediate] Split {file_path.name} into {len(chunks)} chunks of {max_size} bytes")
    return chunks


def get_tool_updates(report_dir: Path) -> str:
    """Check logs for tool updates (e.g. Trivy) and format an alert message."""
    updates = []
    trivy_log = report_dir / "trivy.stderr.log"
    if trivy_log.exists():
        content = trivy_log.read_text(errors="replace")
        m = re.search(r"Version ([\d\.]+) of Trivy is now available, current version is ([\d\.]+)", content)
        if m:
            latest = m.group(1)
            current = m.group(2)
            updates.append(f"Update available for Trivy\ncurrent version: {current}\nlatest-version-available: {latest}")
    
    if updates:
        return "\n\n" + "\n\n".join(updates)
    return ""


def upload_file_to_slack(channel: str, file_path: Path, title: str,
                         host: str = "", thread_ts: str | None = None) -> bool:
    """Upload a file to Slack (3-step External Upload API).
    If thread_ts is given the file is attached to that thread."""
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

    # Step 3: Complete upload — attach to thread if thread_ts given
    complete_payload: dict = {
        "files": [{"id": file_id, "title": title}],
        "channel_id": channel,
        "initial_comment": f"{host} — {title}" if host else title,
    }
    if thread_ts:
        complete_payload["thread_ts"] = thread_ts
    complete_resp = requests.post(
        "https://slack.com/api/files.completeUploadExternal",
        headers={**headers, "Content-Type": "application/json"},
        json=complete_payload,
        timeout=30,
    )
    complete_resp.raise_for_status()
    complete_data = complete_resp.json()
    if not complete_data.get("ok"):
        print(f"[remediate] Step 3 failed for {file_path.name}: {complete_data}", file=sys.stderr)
        return False
    return True


def post_to_slack(channel: str, markdown: str, report_dir: Path, host: str) -> None:
    """Post Threat Brief as channel message; attach raw scan files in its thread."""
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}

    slack_text = md_to_mrkdwn(markdown)
    if len(slack_text) > 38000:
        slack_text = slack_text[:38000] + "\n...[truncated — see attached files in thread]"

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f":shield: *Security scan complete for `{host}`*"}},
        {"type": "divider"},
    ]
    chunk_size = 3000
    for i in range(0, len(slack_text), chunk_size):
        chunk = slack_text[i:i + chunk_size]
        if i > 0:
            chunk = f"_(continued)_\n\n{chunk}"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})

    # ── Channel message (Threat Brief only) ──
    msg_resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=headers,
        json={
            "channel": channel,
            "text": f":shield: Security scan complete for *{host}*",
            "blocks": blocks,
        },
        timeout=30,
    )
    msg_resp.raise_for_status()
    msg_data = msg_resp.json()
    if not msg_data.get("ok"):
        print(f"[remediate] Slack postMessage error: {msg_data}", file=sys.stderr)

    thread_ts = msg_data.get("ts")
    if not thread_ts:
        print("[remediate] ⚠️  no thread_ts — files will NOT be threaded", file=sys.stderr)

    # Announce that scan files follow in the thread
    if thread_ts:
        updates_text = get_tool_updates(report_dir)
        requests.post(
            "https://slack.com/api/chat.postMessage",
            headers=headers,
            json={
                "channel": channel,
                "thread_ts": thread_ts,
                "text": f":paperclip: Raw scan reports are attached in this thread for reviewer reference.{updates_text}",
            },
            timeout=30,
        )

    # ── Thread: raw scan artefacts ──
    MAX_CHUNK_SIZE = 50 * 1024 * 1024  # 50 MB
    for raw_file in [
        "trivy.json", "debsecan.txt", "combined_meta.json", "nmap.xml", "nmap.txt",
        "ss_listeners.txt", "ufw_status.txt", "iptables.txt", "nftables.txt", "lynis-report.dat",
    ]:
        fpath = report_dir / raw_file
        if not fpath.exists():
            continue
        chunks = split_file(fpath, MAX_CHUNK_SIZE)
        for i, chunk in enumerate(chunks, 1):
            title = raw_file if len(chunks) == 1 else f"{raw_file}.{i:03d}"
            success = upload_file_to_slack(channel, chunk, title, host, thread_ts=thread_ts)
            if not success:
                print(f"[remediate] ⚠️  failed to upload {title}", file=sys.stderr)
            chunk.unlink(missing_ok=True)


def post_fallback_to_slack(channel: str, fallback_msg: str, report_dir: Path, host: str) -> None:
    """Post playful fallback message with raw scan files in thread."""
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}

    updates_text = get_tool_updates(report_dir)
    msg_resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=headers,
        json={
            "channel": channel,
            "text": f":robot_face: Security scan complete for {host} — LLM on break, raw reports in thread",
            "blocks": [
                {"type": "section", "text": {
                    "type": "mrkdwn",
                    "text": (
                        f":shield: *Security scan complete for `{host}`*\n\n"
                        f"_{fallback_msg}_\n\n"
                        f"_Raw scan reports are attached in this thread for reviewer reference.{updates_text}_"
                    ),
                }},
                {"type": "divider"},
            ],
        },
        timeout=30,
    )
    msg_resp.raise_for_status()
    thread_ts = msg_resp.json().get("ts")

    # ── Thread: raw scan artefacts ──
    MAX_CHUNK_SIZE = 50 * 1024 * 1024  # 50 MB
    for raw_file in [
        "trivy.json", "debsecan.txt", "combined_meta.json", "nmap.xml", "nmap.txt",
        "ss_listeners.txt", "ufw_status.txt", "iptables.txt", "nftables.txt", "lynis-report.dat",
    ]:
        fpath = report_dir / raw_file
        if not fpath.exists():
            continue
        chunks = split_file(fpath, MAX_CHUNK_SIZE)
        for i, chunk in enumerate(chunks, 1):
            title = raw_file if len(chunks) == 1 else f"{raw_file}.{i:03d}"
            success = upload_file_to_slack(channel, chunk, title, host, thread_ts=thread_ts)
            if not success:
                print(f"[remediate] ⚠️  failed to upload {title}", file=sys.stderr)
            chunk.unlink(missing_ok=True)


def copy_reports_to_local(report_dir: Path, host: str) -> Path:
    """Copy all raw reports to ~/Downloads/brahma-danda_reports/ for local access."""
    import shutil
    local_dir = Path.home() / "Downloads" / "brahma-danda_reports" / f"{host}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    local_dir.mkdir(parents=True, exist_ok=True)
    for f in report_dir.iterdir():
        if f.is_file():
            shutil.copy2(f, local_dir / f.name)
            print(f"[remediate] copied {f.name} to {local_dir}")
    print(f"[remediate] all reports saved to {local_dir}")
    return local_dir


def post_raw_reports_to_slack(channel: str, report_dir: Path, host: str) -> None:
    """Fallback: warning channel message + raw files in its thread."""
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}

    updates_text = get_tool_updates(report_dir)
    msg_resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=headers,
        json={
            "channel": channel,
            "text": f":warning: Security scan complete for {host} — LLM unavailable, raw reports in thread",
            "blocks": [
                {"type": "section", "text": {
                    "type": "mrkdwn",
                    "text": (
                        f":warning: *Security scan complete for `{host}`*\n\n"
                        "LLM summary could not be generated. "
                        f"Raw scan reports are attached in this thread for reviewer reference.{updates_text}"
                    ),
                }},
                {"type": "divider"},
            ],
        },
        timeout=30,
    )
    msg_resp.raise_for_status()
    thread_ts = msg_resp.json().get("ts")

    MAX_CHUNK_SIZE = 50 * 1024 * 1024
    for raw_file in [
        "trivy.json", "debsecan.txt", "combined_meta.json", "nmap.xml", "nmap.txt",
        "ss_listeners.txt", "ufw_status.txt", "iptables.txt", "nftables.txt", "lynis-report.dat",
    ]:
        fpath = report_dir / raw_file
        if not fpath.exists():
            continue
        chunks = split_file(fpath, MAX_CHUNK_SIZE)
        for i, chunk in enumerate(chunks, 1):
            title = raw_file if len(chunks) == 1 else f"{raw_file}.{i:03d}"
            upload_file_to_slack(channel, chunk, title, host, thread_ts=thread_ts)
            chunk.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    channel = os.environ["SLACK_CHANNEL_ID"]
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "")
    ollama_model = os.environ.get("OLLAMA_MODEL", "")
    temperature = float(os.environ.get("LLM_TEMPERATURE", "0.3"))
    top_p = float(os.environ.get("LLM_TOP_P", "0.3"))

    # Build Anthropic client (optional — Ollama alone is also valid)
    claude_client, claude_model = None, ""
    try:
        claude_client, claude_model = _make_anthropic_client()
    except SystemExit:
        if not (ollama_url and ollama_model):
            print("[remediate] No LLM configured — exiting", file=sys.stderr)
            sys.exit(1)
        print("[remediate] Claude secret missing — using Ollama only")

    llm_kw = dict(
        client=claude_client, model=claude_model,
        ollama_url=ollama_url, ollama_model=ollama_model,
        temperature=temperature, top_p=top_p,
    )

    # ── Step 1: analyse each scan artefact individually ──
    all_findings = analyze_files(report_dir, args.host, **llm_kw)

    # ── Step 2: combine findings into Threat Brief ──
    threat_brief = combine_findings(all_findings, args.host, **llm_kw)

    # ── Step 3: post to Slack (or fallback) ──
    if threat_brief is None:
        print("[remediate] ⚠️  LLM unavailable — no summary generated")
        # Pick a random playful fallback message
        fallback_msg = random.choice(LLM_FALLBACK_MESSAGES)
        print(f"[remediate] Using fallback message: {fallback_msg}")
        try:
            copy_reports_to_local(report_dir, args.host)
        except OSError:
            pass  # container filesystem is read-only; reports stay on scan_reports volume
        print(f"[remediate] posting fallback message + raw reports to Slack channel {channel}")
        post_fallback_to_slack(channel, fallback_msg, report_dir, args.host)
        print("[remediate] done (raw reports with fallback message)")
        return

    plan_path = report_dir / "remediation_plan.md"
    plan_path.write_text(threat_brief)
    print(f"[remediate] brief written to {plan_path}")

    print(f"[remediate] posting Threat Brief to Slack channel {channel}")
    post_to_slack(channel, threat_brief, report_dir, args.host)
    print("[remediate] done")


if __name__ == "__main__":
    main()
