#!/usr/bin/env python3
"""
Reads raw scan output, sends each artefact to an LLM via structured tool-use,
reconciles findings, and posts a Threat Brief + raw files to Slack.

Parts implemented:
  A – structural chunking (JSON-array, line-boundary, XML-element)
  B – forced tool-use (report_findings schema)
  C – truncation detection + auto-continue
  D – failure classification + retry with backoff + fast-fail on config errors
  E – debug logging (stdout + file + raw dump on failure)
  F – reconciliation (nothing silently dropped)
  G – severity pre-filter (critical/high only to LLM; streamed for trivy.json)
  H – prompt caching (cache_control on static system prompt)
  I – regression fixtures + tests (see tests/)
"""
import argparse
import datetime
import json
import logging
import os
import random
import re
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import requests
from anthropic import Anthropic

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGGER = logging.getLogger("brahma-danda.remediate")

# ---------------------------------------------------------------------------
# Size constants  (Part A + C)
#
# MODEL_SAFE_INPUT_BYTES arithmetic (claude-sonnet-5):
#   context window  200 000 tokens
#   reserved output   4 096 tokens  (MAX_TOKENS_PER_FILE)
#   reserved prompt   1 000 tokens  (system prompt + tool schema)
#   available input 194 904 tokens × 4 chars/token ≈ 779 616 chars
#   → rounded down to 770 000 for safety
#
# GATEWAY_MAX_BODY_BYTES: read from env; default 1 MB (conservative/unverified).
#   Binary-search against the real gateway if this fires 413s frequently.
#
# safe_chunk_bytes = min(GATEWAY_MAX_BODY_BYTES, MODEL_SAFE_INPUT_BYTES) * 0.7
#   The 0.7 margin is intentional headroom — do NOT remove it.
#
# MODEL_SAFE_INPUT_BYTES is imported from prompts.py — single source of truth.
# ---------------------------------------------------------------------------

def _gateway_max_body_bytes() -> int:
    raw = os.environ.get("GATEWAY_MAX_BODY_BYTES", "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    LOGGER.warning(
        "GATEWAY_MAX_BODY_BYTES not set — defaulting to 1 000 000 bytes (1 MB). "
        "This is a conservative UNVERIFIED default. Binary-search the real gateway "
        "limit and set this env var to avoid unnecessary over-chunking."
    )
    return 1_000_000

def _safe_chunk_bytes() -> int:
    return int(min(_gateway_max_body_bytes(), MODEL_SAFE_INPUT_BYTES) * 0.7)

# Max continuation attempts before re-chunking (Part C)
MAX_CONTINUATION_ATTEMPTS: int = 2

# How deep re-chunking of a still-truncated chunk may nest (Part C)
MAX_RECHUNK_DEPTH: int = 1

# Cost/latency guard: if one artefact explodes past this many chunks, the rest
# are SKIPPED (loudly — recorded in reconciliation + incomplete notice).
MAX_CHUNKS_PER_FILE: int = 100

# Artefacts larger than this are not LLM-analysed at all (OOM guard).
MAX_ARTEFACT_BYTES: int = 500_000_000

# Retry config for transient failures (Part D)
RETRY_DELAYS: list[float] = [2.0, 8.0, 30.0]  # seconds; exponential-ish backoff

# Playful LLM-unavailable messages
LLM_FALLBACK_MESSAGES = [
    "Looks like the Summarizer Agent is taking a well-deserved vacation. 😎 "
    "Guess it's time to manually analyse the reports. Raw reports are attached. 🔍🫡",
    "The Summarizer Agent appears to be MIA. 🫡 No worries — manual vulnerability "
    "hunting it is! Raw reports are waiting in the thread below. 😄",
    "Summarizer Agent is currently unavailable. Please enjoy: **doing it yourself**™. 😄 "
    "Raw reports are attached — because today we're going hands-on. 🔎",
]

from prompts import (
    PER_FILE_SYSTEM_PROMPT,
    PER_FILE_SYSTEM_PROMPT_FALLBACK,
    COMBINE_SYSTEM_PROMPT,
    REPORT_FINDINGS_TOOL,
    MAX_TOKENS_PER_FILE,
    MAX_TOKENS_COMBINE,
    MODEL_SAFE_INPUT_BYTES,  # canonical value lives in prompts.py
)

# ---------------------------------------------------------------------------
# ScanStats  (Parts E + F)
# ---------------------------------------------------------------------------
class ScanStats:
    """Mutable counters shared across the pipeline."""

    def __init__(self) -> None:
        self.total_calls: int = 0
        self.total_errors: int = 0
        self.chunks_succeeded_first_try: int = 0
        self.chunks_succeeded_after_retry: int = 0
        self.chunks_failed: int = 0
        self.failed_chunk_ids: list[str] = []
        self.truncation_events: int = 0
        self.continuations_used: int = 0
        self.cache_read_tokens: int = 0
        self.cache_write_tokens: int = 0
        self.backend_calls: Counter = Counter()
        self.backend_used: str = ""
        self.file_findings: dict[str, int] = {}
        self.file_backend: dict[str, str] = {}
        self.scan_id: str = ""
        # Part F reconciliation: label -> {"expected", "extracted", "status", "failed_chunks"}
        self.reconciliation: dict[str, dict] = {}

    def summary(self) -> dict:
        failed_files = [l for l, n in self.file_findings.items() if n == 0]
        total_chunks = (
            self.chunks_succeeded_first_try
            + self.chunks_succeeded_after_retry
            + self.chunks_failed
        )
        return {
            "total_files": len(self.file_findings),
            "total_chunks": total_chunks,
            "chunks_succeeded_first_try": self.chunks_succeeded_first_try,
            "chunks_succeeded_after_retry": self.chunks_succeeded_after_retry,
            "chunks_failed": self.chunks_failed,
            "failed_chunks": self.failed_chunk_ids,
            "truncation_events": self.truncation_events,
            "continuations_used": self.continuations_used,
            "total_llm_calls": self.total_calls,
            "total_llm_failures": self.total_errors,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "files_with_findings": sum(1 for n in self.file_findings.values() if n > 0),
            "files_failed": len(failed_files),
            "failed_files": failed_files,
            "llm_backend_used": self.backend_used or (
                self.backend_calls.most_common(1)[0][0] if self.backend_calls else ""
            ),
        }


# ---------------------------------------------------------------------------
# Logging setup  (Part E)
# ---------------------------------------------------------------------------
def _configure_logging(report_dir: Path) -> None:
    level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    LOGGER.setLevel(level)
    for h in list(LOGGER.handlers):
        LOGGER.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] [remediate] %(message)s")
    stream = logging.StreamHandler(sys.stdout)
    stream.setLevel(level)
    stream.setFormatter(fmt)
    LOGGER.addHandler(stream)
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(report_dir / "remediate.log", encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        LOGGER.addHandler(fh)
    except OSError as exc:
        sys.stderr.write(f"[remediate] warning: cannot write remediate.log ({exc}); stdout only\n")


def _write_raw_debug(report_dir: Path, label: str, chunk_idx: int, raw: str) -> Path:
    """Always write raw LLM response to disk on failure (Part E.2)."""
    debug_dir = report_dir / "debug"
    debug_dir.mkdir(exist_ok=True)
    safe = re.sub(r"[^\w.\-]", "_", label)
    p = debug_dir / f"{safe}.{chunk_idx}.raw.txt"
    try:
        p.write_text(raw, encoding="utf-8", errors="replace")
    except OSError as exc:
        LOGGER.warning("could not write debug file %s: %s", p.name, exc)
    return p


def _preview(text: str, n: int = 400) -> str:
    if len(text) <= n:
        return text
    return f"{text[:n]} …[{len(text) - 2*n} chars omitted]… {text[-n:]}"


# ===========================================================================
# Part G — Severity pre-filter
# ===========================================================================
_TRIVY_KEEP = {"CRITICAL", "HIGH"}   # prompts only ask the model for these
_LYNIS_SKIP_PREFIXES = ("suggestion[", "manual[", "hardening_index")

# Fields sent to the LLM per CVE. "Description" (long prose, the bulk of
# trivy.json's 230 MB) is deliberately dropped — the model anchors evidence
# on VulnerabilityID / package / versions / Title.
_TRIVY_FIELDS = ("VulnerabilityID", "PkgName", "InstalledVersion",
                 "FixedVersion", "Severity", "Title")


def _trivy_expected_and_chunks(raw: str, target_bytes: int, label: str):
    """Stream-parse trivy.json ONCE and lazily yield chunk strings.

    Returns (expected_total, chunk_iterator).  Replaces the old
    parse→filter→re-dump-whole-file→split pipeline, which held a 230 MB raw
    string, a fully-parsed copy, a re-dumped filtered copy AND ~300 chunk
    strings in memory at once and was OOM-killed.

    The iterator yields one {"Target":…,"Vulnerabilities":[…]} JSON object per
    chunk, filtered to _TRIVY_KEEP severities and stripped to _TRIVY_FIELDS.
    Returns (0, None) if the content does not parse as trivy JSON.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return 0, None
    if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
        return 0, None

    expected = sum(len(r.get("Vulnerabilities") or []) for r in data["Results"])

    def _gen():
        kept = 0
        for result in data["Results"]:
            meta = {k: v for k, v in result.items() if k != "Vulnerabilities"}
            cur, cur_bytes = [], 0
            for v in result.get("Vulnerabilities") or []:
                if str(v.get("Severity", "")).upper() not in _TRIVY_KEEP:
                    continue
                slim = {k: v[k] for k in _TRIVY_FIELDS if k in v}
                vb = len(json.dumps(slim).encode())
                if cur and cur_bytes + vb > target_bytes:
                    kept += len(cur)
                    yield json.dumps({**meta, "Vulnerabilities": cur},
                                     separators=(",", ":"))
                    cur, cur_bytes = [], 0
                cur.append(slim)
                cur_bytes += vb
            if cur:
                kept += len(cur)
                yield json.dumps({**meta, "Vulnerabilities": cur},
                                 separators=(",", ":"))
        LOGGER.info("%s: streamed filter kept %d of %d vulns (critical/high only)",
                    label, kept, expected)

    return expected, _gen()


def _filter_lynis(content: str, label: str) -> tuple[str, int, int]:
    lines = content.splitlines(keepends=True)
    kept_lines, total, kept = [], len(lines), 0
    for line in lines:
        low = line.lower().lstrip()
        if any(low.startswith(p) for p in _LYNIS_SKIP_PREFIXES):
            continue
        kept_lines.append(line)
        kept += 1
    dropped = total - kept
    LOGGER.info("%s: kept %d of %d lines, dropped %d low-noise", label, kept, total, dropped)
    return "".join(kept_lines), kept, dropped


def _apply_severity_filter(label: str, content: str) -> tuple[str, int, int]:
    # trivy.json is handled by the streaming path (_trivy_expected_and_chunks)
    if label == "lynis-report.dat":
        return _filter_lynis(content, label)
    return content, 0, 0


# ===========================================================================
# Part A — Structural chunkers
# ===========================================================================

def _count_expected_findings(label: str, content: str) -> int:
    try:
        if label == "trivy.json":
            data = json.loads(content)
            return sum(len(r.get("Vulnerabilities") or []) for r in data.get("Results", []))
        if label == "nmap.xml":
            tree = ET.fromstring(content)
            return sum(
                1 for port in tree.iter("port")
                if port.find("state") is not None
                and port.find("state").get("state") in ("open", "filtered")
            )
    except Exception:
        pass
    return len([l for l in content.splitlines() if l.strip()])


def _chunks_from_json_array(content: str, target_bytes: int, label: str) -> list[str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        LOGGER.warning("%s: JSON parse failed pre-chunk — sending as single chunk", label)
        return [content]

    array: list | None = None
    
    def _split_trivy(data):
        # Trivy nested split: {"Results": [{"Vulnerabilities": [...]}]}
        results = data.get("Results", [])
        if not results: return [content]
        
        chunks = []
        for result in results:
            vulns = result.get("Vulnerabilities") or []
            if not vulns:
                chunks.append(json.dumps({"Results": [result]}))
                continue
                
            current_vulns = []
            current_bytes = 0
            
            for v in vulns:
                vb = len(json.dumps(v).encode())
                if current_vulns and current_bytes + vb > target_bytes:
                    res_copy = dict(result)
                    res_copy["Vulnerabilities"] = current_vulns
                    chunks.append(json.dumps({"Results": [res_copy]}))
                    current_vulns, current_bytes = [], 0
                current_vulns.append(v)
                current_bytes += vb
                
            if current_vulns:
                res_copy = dict(result)
                res_copy["Vulnerabilities"] = current_vulns
                chunks.append(json.dumps({"Results": [res_copy]}))
        return chunks

    if isinstance(data, dict) and "Results" in data and isinstance(data["Results"], list) and any("Vulnerabilities" in r for r in data["Results"]):
        return _split_trivy(data)

    wrapper: dict | None = None
    array_key: str = ""

    if isinstance(data, list):
        array = data
    elif isinstance(data, dict):
        for key in ("findings", "Vulnerabilities", "items", "Results"):
            if isinstance(data.get(key), list):
                array, wrapper, array_key = data[key], dict(data), key
                break

    if not array:
        return [content]

    chunks: list[str] = []
    current: list = []
    current_bytes = 0

    for element in array:
        eb = len(json.dumps(element).encode())
        if current and current_bytes + eb > target_bytes:
            if wrapper is not None:
                d = dict(wrapper); d[array_key] = current
                chunks.append(json.dumps(d))
            else:
                chunks.append(json.dumps(current))
            current, current_bytes = [], 0
        current.append(element)
        current_bytes += eb

    if current:
        if wrapper is not None:
            d = dict(wrapper); d[array_key] = current
            chunks.append(json.dumps(d))
        else:
            chunks.append(json.dumps(current))

    valid = []
    for i, c in enumerate(chunks):
        try:
            json.loads(c); valid.append(c)
        except json.JSONDecodeError as e:
            LOGGER.error("%s chunk %d invalid after split: %s — dropping", label, i, e)
    return valid or [content]


def _chunks_from_lines(content: str, target_bytes: int, label: str) -> list[str]:
    lines = content.splitlines(keepends=True)
    chunks, current_lines, current_bytes = [], [], 0
    for line in lines:
        lb = len(line.encode())
        if current_lines and current_bytes + lb > target_bytes:
            chunks.append("".join(current_lines))
            current_lines, current_bytes = [], 0
        current_lines.append(line)
        current_bytes += lb
    if current_lines:
        chunks.append("".join(current_lines))
    return chunks or [content]


def _chunks_from_xml(content: str, target_bytes: int, label: str) -> list[str]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        LOGGER.warning("%s: XML parse failed: %s — single chunk", label, e)
        return [content]

    hosts = root.findall("host")
    if not hosts:
        return [content]

    def _tmpl() -> ET.Element:
        el = ET.Element(root.tag, root.attrib)
        for child in root:
            if child.tag != "host":
                el.append(child)
        return el

    chunks, current = [], _tmpl()
    current_bytes = len(ET.tostring(current, encoding="unicode"))
    for host in hosts:
        hb = len(ET.tostring(host, encoding="unicode"))
        if current.findall("host") and current_bytes + hb > target_bytes:
            chunks.append(ET.tostring(current, encoding="unicode"))
            current, current_bytes = _tmpl(), len(ET.tostring(_tmpl(), encoding="unicode"))
        current.append(host)
        current_bytes += hb
    chunks.append(ET.tostring(current, encoding="unicode"))
    return chunks or [content]


def _smart_chunks(label: str, content: str, target: int | None = None) -> list[str]:
    if target is None:
        target = _safe_chunk_bytes()
    content_bytes = len(content.encode())
    if content_bytes <= target:
        LOGGER.debug("%s (%d bytes) fits in one chunk (target=%d)", label, content_bytes, target)
        return [content]
    suffix = Path(label).suffix.lower()
    LOGGER.info("%s (%d bytes) > target %d — splitting", label, content_bytes, target)
    if suffix == ".json":
        chunks = _chunks_from_json_array(content, target, label)
    elif suffix == ".xml":
        chunks = _chunks_from_xml(content, target, label)
    else:
        chunks = _chunks_from_lines(content, target, label)
    LOGGER.info("%s → %d chunk(s)", label, len(chunks))
    return chunks



# ===========================================================================
# Misc helpers
# ===========================================================================

def read_secret(name: str) -> str:
    path = Path(f"/run/secrets/{name}")
    if not path.exists():
        LOGGER.error("secret file %s not found", path)
        sys.exit(1)
    return path.read_text().strip()


def _make_anthropic_client():
    """Return (client, model) or (None, '') if Anthropic is not configured."""
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()
    if not base_url and not api_key:
        secret_path = Path("/run/secrets/claude_api_key")
        if not secret_path.exists():
            LOGGER.warning("no Anthropic config — skipping Claude, will use Ollama")
            return None, ""
        api_key = secret_path.read_text().strip()
    is_bearer = bool(os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip())
    model = (
        os.environ.get("ANTHROPIC_MODEL", "").strip()
        or os.environ.get("CLAUDE_MODEL", "").strip()
        or "claude-sonnet-5"
    )
    # max_retries=0: the SDK's internal retries (default 2) compound with our
    # _with_retry backoff — observed live: one 524 storm burned ~7 min per
    # attempt before our own retry counter even ticked.
    kwargs: dict = {"api_key": api_key, "max_retries": 0}
    if base_url:
        kwargs["base_url"] = base_url
        LOGGER.info("using custom Anthropic gateway: %s", base_url)
        if is_bearer:
            kwargs["default_headers"] = {"Authorization": f"Bearer {api_key}"}
    return Anthropic(**kwargs), model


# ===========================================================================
# Part H — Prompt caching verification
# ===========================================================================

_CACHING_VERIFIED: bool | None = None   # None = not yet tested


def _create_message(client: "Anthropic", **kwargs):
    """messages.create() wrapper that STREAMS unless REMEDIATE_NO_STREAM=1.

    Observed live: the gateway sits behind Cloudflare, which kills any
    non-streaming request whose response takes >120s (Error 524 — "origin
    took too long to respond").  Large chunks always take longer than that,
    so every big call died with 524.  SSE streaming sends bytes continuously,
    which keeps the proxy-read timer fed and the connection alive.

    Returns the final (fully-assembled) Message either way.
    """
    if os.environ.get("REMEDIATE_NO_STREAM", "").strip() in ("1", "true", "yes"):
        return client.messages.create(**kwargs)
    with client.messages.stream(**kwargs) as stream:
        return stream.get_final_message()


def _build_cached_system(prompt_text: str) -> list[dict]:
    """Wrap the static system prompt with cache_control for Part H."""
    return [{"type": "text", "text": prompt_text, "cache_control": {"type": "ephemeral"}}]


def _verify_caching(client: Anthropic, model: str, system_text: str) -> bool:
    """Send two identical requests; confirm cache_read_input_tokens > 0 on second."""
    global _CACHING_VERIFIED
    if _CACHING_VERIFIED is not None:
        return _CACHING_VERIFIED
    try:
        system_block = _build_cached_system(system_text)
        probe = {"role": "user", "content": "ping"}
        _create_message(client, model=model, max_tokens=16, system=system_block, messages=[probe])  # prime cache
        r2 = _create_message(client, model=model, max_tokens=16, system=system_block, messages=[probe])
        read = getattr(getattr(r2, "usage", None), "cache_read_input_tokens", 0) or 0
        _CACHING_VERIFIED = read > 0
        if not _CACHING_VERIFIED:
            LOGGER.warning(
                "prompt caching requested but gateway does not appear to support it "
                "(cache_read_input_tokens=0 on second probe) — falling back to uncached calls"
            )
        else:
            LOGGER.info("prompt caching verified (cache_read_input_tokens=%d on probe)", read)
    except Exception as e:
        LOGGER.warning("caching probe failed (%s) — proceeding uncached", e)
        _CACHING_VERIFIED = False
    return _CACHING_VERIFIED


# ===========================================================================
# Part B/C/D — LLM callers
# ===========================================================================

class _LLMFailure(Exception):
    """Typed failure so Part D can classify it."""
    def __init__(self, kind: str, msg: str, status: int | None = None, raw: str = ""):
        super().__init__(msg)
        self.kind = kind      # "transient" | "gateway_rejection" | "fatal"
        self.status = status
        self.raw = raw


class FatalLLMError(Exception):
    """Non-retryable config/gateway error (bad model name, bad key, …).

    Retrying cannot fix these — retrying 404 "model not found" against every
    chunk of a 230 MB trivy.json cost ~36 minutes and produced nothing.
    Propagates to main() which posts raw artefacts + exits non-zero.
    """


def _classify_exception(exc: Exception) -> str:
    """Part D: classify an exception into transient / gateway_rejection / fatal."""
    status = getattr(exc, "status_code", None)
    if status is None:  # requests.HTTPError carries status on .response
        resp = getattr(exc, "response", None)
        status = getattr(resp, "status_code", None) if resp is not None else None
    body = str(getattr(exc, "message", "") or getattr(exc, "body", "") or exc).lower()
    if status == 413 or "payload too large" in body or "request entity too large" in body:
        return "gateway_rejection"
    # Non-retryable: auth / model / request-shape errors. Retrying cannot fix
    # these — observed live when a wrong model name (404) was retried per chunk.
    if status in (400, 401, 403, 404, 422) \
            or "model not found" in body or "invalid_api_key" in body \
            or "authentication_error" in body:
        return "fatal"
    # Everything else (429, 5xx, timeouts, network errors) is worth retrying.
    return "transient"


def _extract_tool_result(response) -> tuple[dict | None, str | None]:
    """Part B: extract tool_use input block from an Anthropic response."""
    for block in response.content:
        if block.type == "tool_use" and block.name == "report_findings":
            return block.input, None
    # No tool_use block found — model may have output text instead
    text = "".join(b.text for b in response.content if b.type == "text")
    return None, text


def _log_llm_call(meta: dict, text: str) -> None:
    LOGGER.debug(
        "[llm] response backend=%s model=%s http_status=%s stop_reason=%s elapsed=%.3fs",
        meta.get("backend"), meta.get("model"), meta.get("http_status"),
        meta.get("stop_reason"), meta.get("elapsed_seconds"),
    )
    LOGGER.info("[llm] %s chunk response preview (%d chars): %s",
                meta.get("backend", "?"), len(text), _preview(text))


def call_claude_tool(
    client: Anthropic, model: str, system: str, user_prompt: str,
    max_tokens: int, stats: "ScanStats | None" = None,
    use_cache: bool = False,
) -> tuple[dict | None, str | None, dict]:
    """Part B: forced tool-use call. Returns (tool_input, fallback_text, meta)."""
    prompt_bytes = len(user_prompt.encode())
    system_content = _build_cached_system(system) if use_cache else system
    start = time.monotonic()
    resp = _create_message(
        client,
        model=model,
        max_tokens=max_tokens,
        system=system_content,
        messages=[{"role": "user", "content": user_prompt}],
        tools=[REPORT_FINDINGS_TOOL],
        tool_choice={"type": "tool", "name": "report_findings"},
    )
    elapsed = time.monotonic() - start
    usage = getattr(resp, "usage", None)
    cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
    cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
    if stats:
        stats.total_calls += 1
        stats.cache_read_tokens += cache_read
        stats.cache_write_tokens += cache_write
        backend = "claude-gateway" if os.environ.get("ANTHROPIC_BASE_URL") else "claude-cloud"
        stats.backend_calls[backend] += 1
        stats.backend_used = backend
    meta = {
        "backend": "claude-gateway" if os.environ.get("ANTHROPIC_BASE_URL") else "claude-cloud",
        "model": model,
        "prompt_bytes": prompt_bytes,
        "http_status": None,
        "stop_reason": getattr(resp, "stop_reason", None),
        "elapsed_seconds": round(elapsed, 3),
        "cache_read_tokens": cache_read,
        "cache_write_tokens": cache_write,
    }
    LOGGER.debug("[llm] tool call elapsed=%.3fs stop_reason=%s cache_read=%d cache_write=%d",
                 elapsed, meta["stop_reason"], cache_read, cache_write)
    tool_input, fallback_text = _extract_tool_result(resp)
    return tool_input, fallback_text, meta


def call_claude_prose(
    client: Anthropic, model: str, system: str, user_prompt: str,
    max_tokens: int, stats: "ScanStats | None" = None,
    use_cache: bool = False,
) -> tuple[str | None, dict]:
    """Prose-JSON fallback for Part B (when tool-use unsupported)."""
    system_content = _build_cached_system(system) if use_cache else system
    start = time.monotonic()
    resp = _create_message(
        client,
        model=model, max_tokens=max_tokens,
        system=system_content,
        messages=[{"role": "user", "content": user_prompt}],
    )
    elapsed = time.monotonic() - start
    usage = getattr(resp, "usage", None)
    cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
    cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
    if stats:
        stats.total_calls += 1
        stats.cache_read_tokens += cache_read
        stats.cache_write_tokens += cache_write
    text = "".join(b.text for b in resp.content if b.type == "text")
    meta = {
        "backend": "claude-gateway" if os.environ.get("ANTHROPIC_BASE_URL") else "claude-cloud",
        "model": model,
        "stop_reason": getattr(resp, "stop_reason", None),
        "elapsed_seconds": round(elapsed, 3),
        "cache_read_tokens": cache_read,
    }
    return text, meta


def call_ollama(
    model: str, base_url: str, system: str, user_prompt: str,
    num_predict: int = 4096, temperature: float = 0.3, top_p: float = 0.3,
    stats: "ScanStats | None" = None,
) -> tuple[str | None, dict]:
    prompt_bytes = len(user_prompt.encode())
    url = f"{base_url.rstrip('/')}/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {"num_predict": num_predict, "temperature": temperature, "top_p": top_p},
    }
    start = time.monotonic()
    resp = requests.post(url, json=payload, timeout=600)
    elapsed = time.monotonic() - start
    resp.raise_for_status()
    data = resp.json()
    text = data.get("message", {}).get("content", "")
    if stats:
        stats.total_calls += 1
        stats.backend_calls["ollama"] += 1
        if text:
            stats.backend_used = "ollama"
    meta = {
        "backend": "ollama",
        "model": model,
        "prompt_bytes": prompt_bytes,
        "http_status": resp.status_code,
        "stop_reason": data.get("done_reason") or data.get("stop"),
        "elapsed_seconds": round(elapsed, 3),
    }
    LOGGER.debug("[llm] ollama elapsed=%.3fs stop_reason=%s", elapsed, meta["stop_reason"])
    return text, meta


def _with_retry(fn, label: str, stats: "ScanStats | None", *args, **kwargs):
    """Part D: retry transient failures up to len(RETRY_DELAYS) times."""
    last_exc = None
    for attempt, delay in enumerate([0] + list(RETRY_DELAYS), 0):
        if delay:
            LOGGER.info("[retry] %s attempt %d/%d — waiting %.0fs", label, attempt, len(RETRY_DELAYS), delay)
            time.sleep(delay)
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            kind = _classify_exception(exc)
            status = getattr(exc, "status_code", None)
            last_exc = exc
            if kind != "transient":
                # gateway_rejection / fatal — retrying cannot help; stop now
                LOGGER.error("[retry] %s attempt %d failed kind=%s status=%s (not retrying): %s",
                             label, attempt, kind, status, exc)
                raise _LLMFailure(kind, str(exc), status) from exc
            LOGGER.warning("[retry] %s attempt %d failed kind=%s status=%s: %s",
                           label, attempt, kind, status, exc)
            if stats:
                stats.total_errors += 1
    raise _LLMFailure("transient", f"all retries exhausted for {label}: {last_exc}") from last_exc



# ===========================================================================
# Part C — Truncation continuation + Part B/D single-chunk processor
# ===========================================================================

def _parse_prose_json(raw: str) -> dict | None:
    """Strip markdown fences and parse JSON. Return None on failure."""
    stripped = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
    stripped = re.sub(r"\s*```$", "", stripped, flags=re.MULTILINE)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _call_with_continuation(
    client: Anthropic, model: str, system: str, user_prompt: str,
    label: str, chunk_idx: int, report_dir: Path,
    max_tokens: int, stats: "ScanStats | None",
    use_cache: bool, use_tool_use: bool,
) -> tuple[list[dict], int, str | None]:
    """Part C: call model, detect max_tokens truncation, auto-continue up to 2x.

    Returns (findings_list, source_finding_count, rechunk_content).
    rechunk_content is non-None when the response was still truncated after all
    continuations — the caller must re-chunk it and process the sub-chunks so
    nothing is silently dropped.
    """
    all_findings: list[dict] = []
    source_count = 0
    rechunk_content: str | None = None

    current_prompt = user_prompt
    continuation_attempt = 0

    while True:
        # --- call ---
        if use_tool_use:
            try:
                tool_input, fallback_text, meta = _with_retry(
                    call_claude_tool, f"{label}[{chunk_idx}]", stats,
                    client, model, system, current_prompt,
                    max_tokens, stats, use_cache,
                )
            except _LLMFailure:
                raise
        else:
            try:
                raw_text, meta = _with_retry(
                    call_claude_prose, f"{label}[{chunk_idx}]", stats,
                    client, model, system, current_prompt,
                    max_tokens, stats, use_cache,
                )
                tool_input = _parse_prose_json(raw_text or "")
                fallback_text = raw_text if tool_input is None else None
            except _LLMFailure:
                raise

        stop_reason = meta.get("stop_reason", "")

        # --- parse result ---
        if tool_input is not None:
            batch = tool_input.get("findings", [])
            sc = tool_input.get("source_finding_count", len(batch))
            all_findings.extend(batch)
            source_count = max(source_count, sc)
        else:
            # tool_use unavailable or prose parse failed
            if fallback_text:
                p = _write_raw_debug(report_dir, label, chunk_idx, fallback_text)
                LOGGER.warning("⚠️  %s[%d] tool_use block missing — raw saved to %s",
                               label, chunk_idx, p)
            return all_findings, source_count, None

        # --- Part C: truncation check ---
        if stop_reason not in ("max_tokens", "length"):
            break  # normal stop_reason — done

        if stats:
            stats.truncation_events += 1
        if continuation_attempt < MAX_CONTINUATION_ATTEMPTS:
            continuation_attempt += 1
            if stats:
                stats.continuations_used += 1
            LOGGER.warning(
                "⚠️  %s[%d] truncated at max_tokens, attempting continuation %d/%d",
                label, chunk_idx, continuation_attempt, MAX_CONTINUATION_ATTEMPTS,
            )
            already = json.dumps([f.get("risk", "") for f in all_findings])
            current_prompt = (
                f"{user_prompt}\n\n"
                f"[CONTINUATION {continuation_attempt}] "
                f"The previous response was cut off. "
                f"Continue the findings array from where you left off. "
                f"Do NOT repeat findings already returned. "
                f"Already reported risks: {already}"
            )
            continue
        # Cap reached — hand the still-truncated content back to the caller so
        # it can be re-chunked at half size and processed (not dropped).
        LOGGER.warning(
            "⚠️  %s[%d] still truncated after %d continuations — signalling re-chunk",
            label, chunk_idx, MAX_CONTINUATION_ATTEMPTS,
        )
        content_match = re.search(r"=== FILE CONTENT ===\n(.*)", user_prompt, re.DOTALL)
        rechunk_content = content_match.group(1) if content_match else None
        break

    return all_findings, source_count, rechunk_content


def _process_single_chunk(
    text: str, label: str, chunk_idx, host: str, report_dir: Path,
    client=None, model: str = "",
    ollama_url: str = "", ollama_model: str = "",
    temperature: float = 0.3, top_p: float = 0.3,
    stats: "ScanStats | None" = None,
    use_cache: bool = False,
    use_tool_use: bool = True,
    _depth: int = 0,
) -> tuple[list[dict], int]:
    """Send one chunk to the LLM. Returns (findings, source_finding_count).

    Part C: if the chunk truncates past the continuation cap, it is re-chunked
    at half size and the sub-chunks are processed here (depth-limited) — the
    data is never dropped, only split further.
    Part D: classifies failures and retries appropriately; fatal failures
    raise FatalLLMError to abort the run fast.
    Never silently drops data — all failures are logged + raw saved.
    """
    max_tokens = min(MAX_TOKENS_PER_FILE, max(1024, len(text) // 2))
    user = f"Host: {host}\nSource file: {label}\n\n=== FILE CONTENT ===\n{text}"
    system = PER_FILE_SYSTEM_PROMPT if use_tool_use else PER_FILE_SYSTEM_PROMPT_FALLBACK

    LOGGER.debug("[chunk] %s[%s] (%d chars) → LLM max_tokens=%d", label, chunk_idx, len(text), max_tokens)

    # Ollama path (prose-JSON only — Ollama doesn't support tool-use schema)
    use_ollama = ollama_url and ollama_model and not os.environ.get("ANTHROPIC_BASE_URL")
    if use_ollama:
        try:
            raw_text, meta = _with_retry(
                call_ollama, f"{label}[{chunk_idx}]", stats,
                ollama_model, ollama_url, PER_FILE_SYSTEM_PROMPT_FALLBACK,
                user, max_tokens, temperature, top_p, stats,
            )
            if stats:
                if meta.get("stop_reason") in ("max_tokens", "length"):
                    stats.truncation_events += 1
                    LOGGER.warning("⚠️  %s[%d] Ollama truncated at max_tokens", label, chunk_idx)
            parsed = _parse_prose_json(raw_text or "")
            if parsed is None:
                p = _write_raw_debug(report_dir, label, chunk_idx, raw_text or "")
                LOGGER.error("⚠️  %s[%d] prose-JSON parse failed — raw saved to %s", label, chunk_idx, p)
                if stats:
                    stats.chunks_failed += 1
                    stats.failed_chunk_ids.append(f"{label}[{chunk_idx}]")
                return [], 0
            findings = parsed.get("findings", [])
            sc = parsed.get("source_finding_count", len(findings))
            if stats:
                stats.chunks_succeeded_first_try += 1
            return findings, sc
        except _LLMFailure as e:
            if e.kind == "fatal":
                raise FatalLLMError(f"Ollama rejected the request (status={e.status}): {e}") from e
            LOGGER.error("⚠️  %s[%d] Ollama %s failure: %s", label, chunk_idx, e.kind, e)
            if stats:
                stats.chunks_failed += 1
                stats.failed_chunk_ids.append(f"{label}[{chunk_idx}]")
            return [], 0

    if client is None:
        LOGGER.error("%s[%d] no LLM client available", label, chunk_idx)
        if stats:
            stats.chunks_failed += 1
            stats.failed_chunk_ids.append(f"{label}[{chunk_idx}]")
        return [], 0

    # Claude path
    errors_before = stats.total_errors if stats else 0
    try:
        findings, sc, rechunk = _call_with_continuation(
            client, model, system, user,
            label, chunk_idx, report_dir,
            max_tokens, stats, use_cache, use_tool_use,
        )
        if stats:
            # Count as after-retry only if THIS chunk actually retried
            if stats.total_errors > errors_before:
                stats.chunks_succeeded_after_retry += 1
            else:
                stats.chunks_succeeded_first_try += 1
        for f in findings:
            f.setdefault("evidence", f.get("evidence", "") or label)

        # Part C: re-chunk a still-truncated chunk and process the pieces.
        if rechunk is not None:
            if _depth >= MAX_RECHUNK_DEPTH:
                LOGGER.error(
                    "⚠️  %s[%s] still truncated and re-chunk depth %d reached — "
                    "marking chunk incomplete (raw file attached for review)",
                    label, chunk_idx, MAX_RECHUNK_DEPTH,
                )
                if stats:
                    stats.chunks_failed += 1
                    stats.failed_chunk_ids.append(f"{label}[{chunk_idx}]")
                return findings, sc
            sub_target = _safe_chunk_bytes() // 2
            sub_chunks = _smart_chunks(label, rechunk, target=sub_target)
            LOGGER.info("%s[%s] re-chunked into %d sub-chunk(s), processing",
                        label, chunk_idx, len(sub_chunks))
            for j, sub in enumerate(sub_chunks):
                sub_findings, sub_sc = _process_single_chunk(
                    sub, label, f"{chunk_idx}.{j}", host, report_dir,
                    client=client, model=model,
                    ollama_url=ollama_url, ollama_model=ollama_model,
                    temperature=temperature, top_p=top_p, stats=stats,
                    use_cache=use_cache, use_tool_use=use_tool_use,
                    _depth=_depth + 1,
                )
                findings.extend(sub_findings)
                sc = max(sc, sub_sc)
                # Surface sub-chunk failures under the parent's reconciliation
                if stats and f"{label}[{chunk_idx}.{j}]" in stats.failed_chunk_ids:
                    stats.failed_chunk_ids.append(f"{label}[{chunk_idx}]")
        return findings, sc
    except _LLMFailure as e:
        if e.kind == "fatal":
            raise FatalLLMError(
                f"gateway rejected the request and this error is not retryable "
                f"(status={e.status}). Check ANTHROPIC_MODEL / credentials. Original: {e}"
            ) from e
        raw_info = ""
        if e.raw:
            p = _write_raw_debug(report_dir, label, chunk_idx, e.raw)
            raw_info = f" — raw saved to {p}"
        LOGGER.error("⚠️  %s[%d] %s failure (status=%s): %s%s",
                     label, chunk_idx, e.kind, e.status, e, raw_info)
        if stats:
            stats.total_errors += 1
            stats.chunks_failed += 1
            stats.failed_chunk_ids.append(f"{label}[{chunk_idx}]")
        return [], 0


# ===========================================================================
# Part F — Reconciliation helpers
# ===========================================================================

def _update_manifest(report_dir: Path, reconciliation: dict) -> None:
    """Merge reconciliation data into .scan_manifest.json (Part F)."""
    manifest_path = report_dir / ".scan_manifest.json"
    data: dict = {}
    if manifest_path.exists():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    if not isinstance(data, dict):
        data = {}
    data.setdefault("remediation", {})["files"] = reconciliation
    try:
        manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        LOGGER.debug("manifest updated with remediation reconciliation")
    except OSError as exc:
        LOGGER.warning("could not write manifest: %s", exc)


def _incomplete_notice(label: str, failed_chunks: list[int], extracted: int, model_count: int) -> str:
    """Generate the ⚠️ incomplete notice for Threat Brief / Slack."""
    short = f"⚠️ {label}: {len(failed_chunks)} chunk(s) failed"
    if model_count > extracted:
        short += f" — model reported {model_count} findings but only {extracted} extracted"
    short += " — raw file attached for manual review."
    return short



# ===========================================================================
# Top-level pipeline
# ===========================================================================

def _scan_manifest(report_dir: Path) -> dict | None:
    path = report_dir / ".scan_manifest.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8").strip())
    except (json.JSONDecodeError, OSError) as exc:
        LOGGER.warning("could not parse .scan_manifest.json: %s", exc)
        return None
    return data if isinstance(data, dict) else None


def _file_inputs(report_dir: Path) -> list[tuple[str, str]]:
    """Return (label, raw_content) for every available scan artefact."""
    inputs = []
    for fname in [
        "trivy.json", "debsecan.txt", "combined_meta.json",
        "ss_listeners.txt", "ufw_status.txt", "iptables.txt",
        "nftables.txt", "lynis-report.dat",
    ]:
        fpath = report_dir / fname
        if not fpath.exists():
            continue
        content = fpath.read_text(errors="replace")
        if content.strip():
            inputs.append((fname, content))
    # nmap XML
    nmap_path = report_dir / "nmap.xml"
    if nmap_path.exists():
        content = nmap_path.read_text(errors="replace")
        if content.strip():
            inputs.append(("nmap.xml", content))
    # testssl per-host JSONs
    for f in sorted(report_dir.glob("testssl_*.json")):
        content = f.read_text(errors="replace")
        if content.strip():
            inputs.append((f.name, content))
    return inputs


def analyze_files(report_dir: Path, host: str, **llm_kw) -> list[dict]:
    """Send each scan artefact through filter → chunk → LLM → reconcile (Parts A–G)."""
    inputs = _file_inputs(report_dir)
    stats: ScanStats | None = llm_kw.pop("stats", None)
    scan_id_env = llm_kw.pop("scan_id", "")

    # Phase 1: resolve scan_id
    manifest = _scan_manifest(report_dir)
    scan_id = scan_id_env
    if manifest:
        m_scan = manifest.get("scan_id", "")
        if m_scan:
            scan_id = m_scan
            if scan_id_env and m_scan != scan_id_env:
                LOGGER.warning("manifest scan_id %s != env SCAN_ID %s — using manifest", m_scan, scan_id_env)
        else:
            LOGGER.warning("manifest present but scan_id empty in %s", report_dir)
    elif scan_id_env:
        LOGGER.warning("SCAN_ID=%s but no .scan_manifest.json — run_scan.sh may not have written it", scan_id_env)
    if stats:
        stats.scan_id = scan_id

    # Part H: verify caching once before the loop
    client = llm_kw.get("client")
    model = llm_kw.get("model", "")
    use_cache = False
    if client and model:
        use_cache = _verify_caching(client, model, PER_FILE_SYSTEM_PROMPT)

    # Detect tool-use support (if first call fails with tool_use error, disable)
    use_tool_use = bool(client)  # Ollama never uses tool-use

    all_findings: list[dict] = []
    reconciliation: dict = {}
    incomplete_notices: list[str] = []

    LOGGER.info("analysing %d scan artefact(s) …", len(inputs))

    while inputs:
        label, raw_content = inputs.pop(0)
        LOGGER.info("→ %s (%d chars)", label, len(raw_content))

        # OOM guard: artefacts beyond this size are never parsed into memory
        size = len(raw_content.encode())
        if size > MAX_ARTEFACT_BYTES:
            notice = (f"⚠️ {label}: artefact too large for LLM analysis "
                      f"({size:,} bytes > {MAX_ARTEFACT_BYTES:,} limit) — "
                      f"raw file attached for manual review.")
            LOGGER.error(notice)
            incomplete_notices.append(notice)
            reconciliation[label] = {"expected": 0, "model_reported": 0,
                                     "extracted": 0, "status": "skipped_too_large",
                                     "failed_chunks": []}
            if stats:
                stats.file_findings[label] = 0
                stats.reconciliation[label] = reconciliation[label]
            raw_content = ""
            continue

        # Part G+A: filter & chunk.  trivy.json is streamed (parse ONCE, yield
        # chunks lazily) — materialising it fully is what OOM-killed the 2026-09-08 run.
        if label == "trivy.json":
            expected, chunks_iter = _trivy_expected_and_chunks(
                raw_content, _safe_chunk_bytes(), label)
            if chunks_iter is not None:
                raw_content = ""  # release the raw string before the LLM loop
            else:
                LOGGER.warning("%s: not valid trivy JSON — generic chunking", label)
                expected = _count_expected_findings(label, raw_content)
                chunks_iter = _smart_chunks(label, raw_content)
        else:
            expected = _count_expected_findings(label, raw_content)
            filtered_content, kept, dropped = _apply_severity_filter(label, raw_content)
            raw_content = ""
            chunks_iter = _smart_chunks(label, filtered_content)
            LOGGER.info("%s → %d chunk(s) after filter+split", label, len(chunks_iter))

        file_findings: list[dict] = []
        file_source_count = 0
        failed_chunk_indices: list[int] = []
        cap_hit = False

        for idx, chunk_text in enumerate(chunks_iter):
            if idx >= MAX_CHUNKS_PER_FILE:
                cap_hit = True
                LOGGER.error(
                    "⚠️  %s exceeded MAX_CHUNKS_PER_FILE=%d — remaining chunks "
                    "NOT analysed (recorded in reconciliation, not dropped silently)",
                    label, MAX_CHUNKS_PER_FILE)
                break
            findings, sc = _process_single_chunk(
                chunk_text, label, idx, host, report_dir,
                use_cache=use_cache,
                use_tool_use=use_tool_use,
                **llm_kw,
            )
            file_findings.extend(findings)
            file_source_count = max(file_source_count, sc)
            if stats and f"{label}[{idx}]" in stats.failed_chunk_ids:
                failed_chunk_indices.append(idx)

        if cap_hit:
            failed_chunk_indices.append(-1)  # sentinel: chunk-count cap hit

        # Part F: reconcile
        extracted = len(file_findings)
        status = "complete"
        if failed_chunk_indices or (file_source_count > 0 and extracted < file_source_count):
            status = "incomplete"
            if cap_hit:
                notice = (f"⚠️ {label}: more than {MAX_CHUNKS_PER_FILE} chunks — "
                          f"remaining chunks not analysed; raw file attached for manual review.")
            else:
                notice = _incomplete_notice(label, failed_chunk_indices, extracted, file_source_count)
            incomplete_notices.append(notice)
            LOGGER.warning("⚠️  %s", notice)

        reconciliation[label] = {
            "expected": expected,
            "model_reported": file_source_count,
            "extracted": extracted,
            "status": status,
            "failed_chunks": failed_chunk_indices,
        }

        all_findings.extend(file_findings)
        n = len(file_findings)
        if stats:
            stats.file_findings[label] = n
            stats.reconciliation[label] = reconciliation[label]

        if n:
            LOGGER.info("✓ %d finding(s) from %s", n, label)
        else:
            LOGGER.warning("✗ no findings from %s", label)

    # Part F: update manifest
    _update_manifest(report_dir, reconciliation)

    # Attach incomplete notices to findings so combine_findings can surface them
    if incomplete_notices:
        for notice in incomplete_notices:
            all_findings.append({
                "severity": "info",
                "risk": notice,
                "evidence": "reconciliation",
                "_incomplete_notice": True,
            })

    return all_findings


def combine_findings(all_findings: list[dict], host: str, **llm_kw) -> str | None:
    """Merge per-file findings into the final Slack Threat Brief via LLM."""
    if not all_findings:
        return None
    stats: ScanStats | None = llm_kw.pop("stats", None)
    scan_id = llm_kw.pop("scan_id", "") or ""
    client = llm_kw.get("client")
    model = llm_kw.get("model", "")
    ollama_url = llm_kw.get("ollama_url", "")
    ollama_model = llm_kw.get("ollama_model", "")
    temperature = llm_kw.get("temperature", 0.3)
    top_p = llm_kw.get("top_p", 0.3)

    system = COMBINE_SYSTEM_PROMPT.replace("{host}", host)
    system = system.replace("{scan_id}", scan_id) if scan_id else system.replace(" (Scan ID: {scan_id})", "")

    # Separate incomplete notices for explicit surfacing
    notices = [f for f in all_findings if f.get("_incomplete_notice")]
    real_findings = [f for f in all_findings if not f.get("_incomplete_notice")]

    user = f"Host: {host}\n\nPer-file findings (JSON):\n{json.dumps(real_findings, indent=2)}"
    LOGGER.info("combining %d finding(s) into Threat Brief …", len(real_findings))

    use_ollama = ollama_url and ollama_model and not os.environ.get("ANTHROPIC_BASE_URL")
    text: str | None = None

    if use_ollama:
        try:
            text, _ = _with_retry(
                call_ollama, "combine", stats,
                ollama_model, ollama_url, system, user,
                MAX_TOKENS_COMBINE, temperature, top_p, stats,
            )
        except _LLMFailure as e:
            if e.kind == "fatal":
                raise FatalLLMError(f"Ollama rejected combine (status={e.status}): {e}") from e
            LOGGER.error("combine Ollama failure: %s", e)
    elif client:
        try:
            text, _ = _with_retry(
                call_claude_prose, "combine", stats,
                client, model, system, user, MAX_TOKENS_COMBINE, stats, False,
            )
        except _LLMFailure as e:
            if e.kind == "fatal":
                raise FatalLLMError(f"gateway rejected combine (status={e.status}): {e}") from e
            LOGGER.error("combine Claude failure: %s", e)

    if text and notices:
        notice_block = "\n".join(f"• {n['risk']}" for n in notices)
        text += f"\n\n*⚠️ Incomplete Analysis*\n{notice_block}"

    return text



# ===========================================================================
# Slack + Outputs
# ===========================================================================

def get_tool_updates(report_dir: Path) -> str:
    """Check logs for tool updates (e.g. Trivy) and format an alert message."""
    updates = []
    trivy_log = report_dir / "trivy.stderr.log"
    if trivy_log.exists():
        content = trivy_log.read_text(errors="replace")
        m = re.search(r"Version ([\d\.]+) of Trivy is now available, current version is ([\d\.]+)", content)
        if m:
            latest, current = m.group(1), m.group(2)
            updates.append(f"Update available for Trivy\ncurrent version: {current}\nlatest-version-available: {latest}")
    return "\n\n" + "\n\n".join(updates) if updates else ""


def upload_file_to_slack(channel: str, file_path: Path, title: str,
                         host: str = "", thread_ts: str | None = None) -> bool:
    """Upload a file to Slack (3-step External Upload API)."""
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}
    file_size = file_path.stat().st_size
    if file_size == 0:
        return True

    # 1. Get URL
    url_resp = requests.post(
        "https://slack.com/api/files.getUploadURLExternal",
        headers=headers,
        data={"filename": file_path.name, "length": str(file_size)},
        timeout=30,
    )
    url_resp.raise_for_status()
    url_data = url_resp.json()
    if not url_data.get("ok"):
        LOGGER.warning("upload step 1 failed for %s: %s", file_path.name, url_data)
        return False
    upload_url = url_data["upload_url"]
    file_id = url_data["file_id"]

    # 2. Upload content
    with open(file_path, "rb") as f:
        content_resp = requests.post(
            upload_url, headers={"Authorization": f"Bearer {token}"},
            data=f.read(), timeout=120,
        )
    content_resp.raise_for_status()

    # 3. Complete upload
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
        json=complete_payload, timeout=30,
    )
    complete_resp.raise_for_status()
    complete_data = complete_resp.json()
    if not complete_data.get("ok"):
        LOGGER.warning("upload step 3 failed for %s: %s", file_path.name, complete_data)
        return False
    return True


def post_to_slack(channel: str, markdown: str, report_dir: Path, host: str) -> None:
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Simple mrkdwn converter
    slack_text = re.sub(r'^## (.+)$', r'\n*\1*\n', markdown, flags=re.MULTILINE)
    slack_text = re.sub(r'^### (.+)$', r'\n_\1_\n', slack_text, flags=re.MULTILINE)
    slack_text = re.sub(r'\*\*(.+?)\*\*', r'*\1*', slack_text)
    slack_text = re.sub(r'^- \*(.+?)\*', r'• *\1*', slack_text, flags=re.MULTILINE)
    slack_text = re.sub(r'^- ', r'• ', slack_text, flags=re.MULTILINE)

    if len(slack_text) > 38000:
        slack_text = slack_text[:38000] + "\n...[truncated — see attached files in thread]"

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f":shield: *Security scan complete for `{host}`*"}},
        {"type": "divider"},
    ]
    chunk_size = 3000
    for i in range(0, len(slack_text), chunk_size):
        chunk = slack_text[i:i + chunk_size]
        if i > 0: chunk = f"_(continued)_\n\n{chunk}"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})

    msg_resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=headers,
        json={"channel": channel, "text": f":shield: Security scan complete for *{host}*", "blocks": blocks},
        timeout=30,
    )
    msg_resp.raise_for_status()
    msg_data = msg_resp.json()
    thread_ts = msg_data.get("ts")

    if thread_ts:
        updates_text = get_tool_updates(report_dir)
        requests.post(
            "https://slack.com/api/chat.postMessage",
            headers=headers,
            json={"channel": channel, "thread_ts": thread_ts, 
                  "text": f":paperclip: Raw scan reports are attached in this thread for reviewer reference.{updates_text}"},
            timeout=30,
        )

    MAX_CHUNK_SIZE = 50 * 1024 * 1024
    for raw_file in [
        "trivy.json", "debsecan.txt", "combined_meta.json", "nmap.xml", "nmap.txt",
        "ss_listeners.txt", "ufw_status.txt", "iptables.txt", "nftables.txt", "lynis-report.dat",
        "run_scan.log", "remediate.log", ".scan_manifest.json",
    ]:
        fpath = report_dir / raw_file
        if not fpath.exists():
            continue
        # Split logic inline
        if fpath.stat().st_size <= MAX_CHUNK_SIZE:
            chunks = [fpath]
        else:
            chunks = []
            chunk_num = 1
            with open(fpath, "rb") as f:
                while True:
                    data = f.read(MAX_CHUNK_SIZE)
                    if not data: break
                    cp = fpath.parent / f"{fpath.stem}-{chunk_num}.part"
                    cp.write_bytes(data)
                    chunks.append(cp)
                    chunk_num += 1
            fpath.unlink()

        for i, chunk in enumerate(chunks, 1):
            title = raw_file if len(chunks) == 1 else f"{raw_file}.{i:03d}"
            upload_file_to_slack(channel, chunk, title, host, thread_ts=thread_ts)
            if len(chunks) > 1:
                chunk.unlink(missing_ok=True)


def copy_reports_to_local(report_dir: Path, host: str) -> None:
    import shutil
    local_dir = Path.home() / "Downloads" / "brahma-danda_reports" / f"{host}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    local_dir.mkdir(parents=True, exist_ok=True)
    for f in report_dir.iterdir():
        if f.is_file():
            shutil.copy2(f, local_dir / f.name)


def post_fallback_to_slack(channel: str, fallback_msg: str, report_dir: Path, host: str) -> None:
    token = read_secret("slack_bot_token")
    headers = {"Authorization": f"Bearer {token}"}
    updates_text = get_tool_updates(report_dir)
    msg_resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers=headers,
        json={
            "channel": channel,
            "text": f":warning: Security scan complete for {host} — LLM unavailable",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", 
                 "text": f":warning: *Security scan complete for `{host}`*\n\n_{fallback_msg}_\n\n_Raw scan reports attached.{updates_text}_"}},
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
        "run_scan.log", "remediate.log", ".scan_manifest.json",
    ]:
        fpath = report_dir / raw_file
        if not fpath.exists():
            continue
        if fpath.stat().st_size <= MAX_CHUNK_SIZE:
            chunks = [fpath]
        else:
            chunks = []
            chunk_num = 1
            with open(fpath, "rb") as f:
                while True:
                    data = f.read(MAX_CHUNK_SIZE)
                    if not data: break
                    cp = fpath.parent / f"{fpath.stem}-{chunk_num}.part"
                    cp.write_bytes(data)
                    chunks.append(cp)
                    chunk_num += 1
            fpath.unlink()

        for i, chunk in enumerate(chunks, 1):
            title = raw_file if len(chunks) == 1 else f"{raw_file}.{i:03d}"
            upload_file_to_slack(channel, chunk, title, host, thread_ts=thread_ts)
            if len(chunks) > 1:
                chunk.unlink(missing_ok=True)


# ===========================================================================
# Main
# ===========================================================================

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

    _configure_logging(report_dir)
    stats = ScanStats()

    claude_client, claude_model = None, ""
    try:
        claude_client, claude_model = _make_anthropic_client()
    except SystemExit:
        if not (ollama_url and ollama_model):
            LOGGER.error("no LLM configured — exiting")
            sys.exit(1)
        LOGGER.warning("Claude secret missing — using Ollama only")

    scan_id = os.environ.get("SCAN_ID", "")

    llm_kw = dict(
        client=claude_client, model=claude_model,
        ollama_url=ollama_url, ollama_model=ollama_model,
        temperature=temperature, top_p=top_p,
        stats=stats, scan_id=scan_id,
    )

    try:
        all_findings = analyze_files(report_dir, args.host, **llm_kw)
        threat_brief = combine_findings(all_findings, args.host, **llm_kw)
    except FatalLLMError as e:
        # Non-retryable config/gateway error (wrong model name, bad key, …).
        # Post the raw artefacts with an honest error instead of a fake summary,
        # then fail loudly so run_scan.sh / cron report the failure.
        LOGGER.error("FATAL — aborting fast (retrying cannot help): %s", e)
        try:
            post_fallback_to_slack(channel, f"LLM configuration error: {e}", report_dir, args.host)
        except Exception as slack_exc:
            LOGGER.error("could not post fallback to Slack: %s", slack_exc)
        LOGGER.info("SUMMARY %s", json.dumps(stats.summary(), sort_keys=True))
        sys.exit(1)

    if threat_brief is None:
        LOGGER.warning("LLM unavailable — no summary generated")
        fallback_msg = random.choice(LLM_FALLBACK_MESSAGES)
        LOGGER.info("using fallback message: %s", fallback_msg)
        try:
            copy_reports_to_local(report_dir, args.host)
        except OSError:
            pass
        LOGGER.info("posting fallback message + raw reports to Slack channel %s", channel)
        post_fallback_to_slack(channel, fallback_msg, report_dir, args.host)
    else:
        plan_path = report_dir / "remediation_plan.md"
        plan_path.write_text(threat_brief)
        LOGGER.info("brief written to %s", plan_path)
        LOGGER.info("posting Threat Brief to Slack channel %s", channel)
        post_to_slack(channel, threat_brief, report_dir, args.host)

    # Part E.3: single summary line
    LOGGER.info("SUMMARY %s", json.dumps(stats.summary(), sort_keys=True))


if __name__ == "__main__":
    main()
