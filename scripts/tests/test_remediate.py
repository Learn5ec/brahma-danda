"""Part I — regression tests for remediate.py.

Covers: chunking, severity filter, truncation/rechunk, fatal-error classification,
severity filter (critical/high only), and the FatalLLMError fast-fail path.
Run with:  pytest scripts/tests/test_remediate.py -v
"""
import json, os, re, sys, textwrap, unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ensure the module under test is importable
sys.path.insert(0, str(Path(__file__).parent.parent))
import prompts as _p  # noqa: E402  (prompts.py lives alongside remediate.py)
import remediate as r  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def trivy_json(n_vulns, sevs=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")):
    vulns = [
        {
            "VulnerabilityID": f"CVE-2024-{1000 + i}",
            "PkgName": "openssl",
            "InstalledVersion": "1.0.0",
            "FixedVersion": "2.0.0",
            "Severity": s,
            "Title": "Test vuln",
            "Description": "Lorem ipsum " * 20,
        }
        for i, s in enumerate([sevs[i % len(sevs)] for i in range(n_vulns)])
    ]
    return json.dumps({
        "SchemaVersion": 2,
        "Results": [{"Target": "debian", "Vulnerabilities": vulns}],
    })


def nmap_xml(n_hosts):
    hosts = ""
    for h in range(n_hosts):
        ports = "".join(
            f'<port protocol="tcp" portid="{8000+p}">'
            f'<state state="open"/><service name="http"/></port>'
            for p in range(4)
        )
        hosts += f'<host><address addr="10.0.0.{h}"/>{ports}</host>'
    return (
        '<?xml version="1.0"?>'
        '<nmaprun scanner="nmap">'
        + hosts +
        '</nmaprun>'
    )


# ---------------------------------------------------------------------------
# Part A — structural chunking
# ---------------------------------------------------------------------------

class TestJSONChunking(unittest.TestCase):
    def test_json_array_splits_at_target(self):
        target = 200
        data = [{"id": i, "text": "x" * 20} for i in range(100)]
        raw = json.dumps(data)
        chunks = r._chunks_from_json_array(raw, target, "test.json")
        for c in chunks:
            self.assertLessEqual(len(c.encode()), target)
        self.assertGreater(len(chunks), 1)

    def test_json_array_splits_trivy_nested_results(self):
        target = 400
        data = {
            "Results": [
                {"Target": f"img-{i}", "Vulnerabilities": [
                    {"VulnerabilityID": f"CVE-2024-{i*10+j}", "Severity": "CRITICAL",
                     "PkgName": "pkg", "InstalledVersion": "1.0", "Title": "Vuln"}
                    for j in range(5)
                ]}
                for i in range(10)
            ]
        }
        raw = json.dumps(data)
        chunks = r._chunks_from_json_array(raw, target, "trivy.json")
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            parsed = json.loads(c)
            self.assertIn("Results", parsed)

    def test_non_json_falls_back_to_single_chunk(self):
        chunks = r._chunks_from_json_array("not json {{{", 200, "test.txt")
        self.assertEqual(chunks, ["not json {{{"])


class TestLineChunking(unittest.TestCase):
    def test_respects_target_bytes(self):
        target = 100
        lines = [f"line {i}: " + "x" * 40 + "\n" for i in range(50)]
        raw = "".join(lines)
        chunks = r._chunks_from_lines(raw, target, "test.txt")
        for c in chunks:
            self.assertLessEqual(len(c.encode()), target)
        self.assertGreater(len(chunks), 1)

    def test_empty_returns_original(self):
        chunks = r._chunks_from_lines("", 100, "empty.txt")
        self.assertEqual(chunks, [""])


class TestXMLChunking(unittest.TestCase):
    def test_splits_on_host_element(self):
        raw = nmap_xml(20)
        chunks = r._chunks_from_xml(raw, 400, "nmap.xml")
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertIn("<nmaprun", c)  # wrapper preserved
            self.assertIn("</nmaprun>", c)

    def test_invalid_xml_single_chunk(self):
        chunks = r._chunks_from_xml("not xml <<<<", 200, "bad.xml")
        self.assertEqual(chunks, ["not xml <<<<"])


class TestSmartChunks(unittest.TestCase):
    def test_small_file_not_chunked(self):
        raw = "small content\n" * 5
        chunks = r._smart_chunks("test.txt", raw)
        self.assertEqual(chunks, [raw])

    def test_json_uses_json_chunker(self):
        target = 200
        data = [{"i": i} for i in range(200)]
        raw = json.dumps(data)
        chunks = r._smart_chunks("test.json", raw, target=target)
        self.assertGreater(len(chunks), 1)

    def test_xml_uses_xml_chunker(self):
        target = 200
        raw = nmap_xml(20)
        chunks = r._smart_chunks("nmap.xml", raw, target=target)
        self.assertGreater(len(chunks), 1)

    def test_target_override_respected(self):
        raw = "x" * 99 + "\n"
        raw = raw * 100
        small = r._smart_chunks("big.txt", raw, target=100)
        big = r._smart_chunks("big.txt", raw)  # uses default (≈539 KB)
        self.assertGreater(len(small), len(big))
        self.assertEqual(len(big), 1)


# ---------------------------------------------------------------------------
# Part G — severity filter
# ---------------------------------------------------------------------------

class TestSeverityFilter(unittest.TestCase):
    def test_trivy_handled_by_streaming_path(self):
        """trivy.json is no longer filtered here (streamed in _trivy_expected_and_chunks)."""
        raw = trivy_json(20)
        filtered, kept, dropped = r._apply_severity_filter("trivy.json", raw)
        self.assertEqual(filtered, raw)   # pass-through
        self.assertEqual((kept, dropped), (0, 0))

    def test_lynis_drops_suggestions(self):
        raw = textwrap.dedent("""\
            warning[SSH-0001]: SSH weak config
            suggestion[SSH-0002]: Enable client alive interval
            tip[NET-0001]: Firewall active
            hardening_index[overall]: 72
            suggestion[LOG-0001]: Check log directory
        """)
        filtered, kept, dropped = r._apply_severity_filter("lynis-report.dat", raw)
        self.assertEqual(kept, 2)   # warning + tip
        self.assertEqual(dropped, 3)  # 2 suggestions + hardening_index

    def test_other_files_pass_through(self):
        raw = "some content\n"
        for f in ["combined_meta.json", "ss_listeners.txt", "ufw_status.txt"]:
            filtered, kept, dropped = r._apply_severity_filter(f, raw)
            self.assertEqual(filtered, raw)
            self.assertEqual(kept, 0)


# ---------------------------------------------------------------------------
# Part A — trivy streaming (OOM guard)
# ---------------------------------------------------------------------------

class TestTrivyStreaming(unittest.TestCase):
    def test_streams_chunks_lazy(self):
        raw = trivy_json(200)
        expected, chunks_iter = r._trivy_expected_and_chunks(raw, 500, "trivy.json")
        self.assertEqual(expected, 200)
        self.assertTrue(callable(getattr(chunks_iter, "__next__", None)))
        chunks = list(chunks_iter)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            # target bounds the vuln payload; per-chunk metadata overhead is small
            self.assertLessEqual(len(c.encode()), 500 + 100)
            parsed = json.loads(c)
            self.assertIn("Vulnerabilities", parsed)
            # severity filter applied: only critical/high survive
            for v in parsed["Vulnerabilities"]:
                self.assertIn(v["Severity"], ("CRITICAL", "HIGH"))

    def test_non_trivy_returns_none(self):
        expected, chunks_iter = r._trivy_expected_and_chunks("not trivy", 200, "other.json")
        self.assertEqual(expected, 0)
        self.assertIsNone(chunks_iter)

    def test_description_stripped(self):
        raw = trivy_json(5)
        _, chunks_iter = r._trivy_expected_and_chunks(raw, 5000, "trivy.json")
        seen = False
        for chunk in chunks_iter:
            for v in json.loads(chunk)["Vulnerabilities"]:
                self.assertNotIn("Description", v)
                seen = True
        self.assertTrue(seen)

    def test_fields_preserved(self):
        raw = trivy_json(5)
        _, chunks_iter = r._trivy_expected_and_chunks(raw, 5000, "trivy.json")
        seen = False
        for chunk in chunks_iter:
            for v in json.loads(chunk)["Vulnerabilities"]:
                for field in ("VulnerabilityID", "PkgName", "InstalledVersion",
                              "FixedVersion", "Severity", "Title"):
                    self.assertIn(field, v)
                seen = True
        self.assertTrue(seen)


# ---------------------------------------------------------------------------
# Part D — exception classification
# ---------------------------------------------------------------------------

class TestExceptionClassification(unittest.TestCase):
    def _classify(self, exc):
        return r._classify_exception(exc)

    def _status_err(self, code, msg="gateway error"):
        err = Exception(f"Error code: {code} - {msg}")
        err.status_code = code   # anthropic APIStatusError / requests expose this
        return err

    def test_404_is_fatal(self):
        self.assertEqual(self._classify(self._status_err(404, "model not found")), "fatal")

    def test_401_is_fatal(self):
        self.assertEqual(self._classify(self._status_err(401, "invalid_api_key")), "fatal")

    def test_403_is_fatal(self):
        self.assertEqual(self._classify(self._status_err(403, "forbidden")), "fatal")

    def test_400_is_fatal(self):
        self.assertEqual(self._classify(self._status_err(400, "bad request")), "fatal")

    def test_413_is_gateway_rejection(self):
        err = Exception("Error code: 413 - payload too large")
        self.assertEqual(self._classify(err), "gateway_rejection")

    def test_429_is_transient(self):
        err = Exception("Error code: 429 - rate limited")
        self.assertEqual(self._classify(err), "transient")

    def test_500_is_transient(self):
        err = Exception("Error code: 500 - upstream error")
        self.assertEqual(self._classify(err), "transient")

    def test_timeout_is_transient(self):
        err = Exception("connection timeout")
        self.assertEqual(self._classify(err), "transient")

    def test_404_response_object(self):
        """requests.HTTPError carries status on .response, not directly."""
        resp = MagicMock()
        resp.status_code = 404
        err = Exception("404")
        err.response = resp
        self.assertEqual(self._classify(err), "fatal")

    def test_model_not_found_body(self):
        """Error may come back in the response body, not the status line."""
        err = Exception("{'status': 'Error', 'code': 404, 'message': 'model not found'}")
        self.assertEqual(self._classify(err), "fatal")


# ---------------------------------------------------------------------------
# Part C — rechunk continuation
# ---------------------------------------------------------------------------

def _tool_response(findings, source_count, stop_reason):
    """Fake anthropic messages.create() response with a report_findings tool_use."""
    from types import SimpleNamespace
    block = SimpleNamespace(type="tool_use", name="report_findings",
                            input={"findings": findings,
                                   "source_finding_count": source_count})
    return SimpleNamespace(
        content=[block], stop_reason=stop_reason,
        usage=SimpleNamespace(cache_read_input_tokens=0,
                              cache_creation_input_tokens=0),
    )


def _stream_client(responses):
    """Mock Anthropic client whose messages.stream() yields pre-canned final
    messages (one per call).  Also wired for messages.create() in case
    REMEDIATE_NO_STREAM is set."""
    client = MagicMock()
    it = iter(responses)

    def _stream(**kwargs):
        cm = MagicMock()
        cm.__enter__.return_value.get_final_message.return_value = next(it)
        cm.__exit__.return_value = False
        return cm

    client.messages.stream.side_effect = _stream
    client.messages.create.side_effect = lambda **kw: next(it)
    return client


class TestContinuation(unittest.TestCase):
    def test_rechunk_signal_on_persistent_truncation(self):
        """After MAX_CONTINUATION_ATTEMPTS truncations the file content is
        handed back for re-chunking — NOT dropped."""
        client = _stream_client([
            _tool_response([{"severity": "high", "risk": f"f{n}", "evidence": "x"}],
                           5, "max_tokens")
            for n in range(r.MAX_CONTINUATION_ATTEMPTS + 1)
        ])
        content = "line1\nline2\n" * 50
        user = f"Host: test\nSource file: test.txt\n\n=== FILE CONTENT ===\n{content}"
        findings, sc, rechunk = r._call_with_continuation(
            client, "coder", _p.PER_FILE_SYSTEM_PROMPT, user,
            "test.txt", 0, Path("/tmp"), 512, None, False, True,
        )
        self.assertEqual(client.messages.stream.call_count,
                         r.MAX_CONTINUATION_ATTEMPTS + 1)
        self.assertEqual(rechunk, content)
        self.assertEqual(sc, 5)
        self.assertGreaterEqual(len(findings), r.MAX_CONTINUATION_ATTEMPTS + 1)

    def test_normal_stop_no_rechunk(self):
        client = _stream_client([_tool_response(
            [{"severity": "high", "risk": "f", "evidence": "x"}], 1, "end_turn")])
        user = "Host: t\n\n=== FILE CONTENT ===\nabc"
        findings, sc, rechunk = r._call_with_continuation(
            client, "coder", _p.PER_FILE_SYSTEM_PROMPT, user,
            "test.txt", 0, Path("/tmp"), 512, None, False, True)
        self.assertIsNone(rechunk)
        self.assertEqual(sc, 1)


# ---------------------------------------------------------------------------
# Part C — f["risk"] → f.get("risk") KeyError fix
# ---------------------------------------------------------------------------

class TestContinuationKeyError(unittest.TestCase):
    def test_missing_risk_key_does_not_crash(self):
        """A finding without a 'risk' key must not raise KeyError during
        continuation prompt building (2026-09-08 static finding #3)."""
        # findings intentionally lack the 'risk' key in one entry
        resp = _tool_response([{"severity": "high", "evidence": "x"},
                               {"severity": "critical", "risk": "ok", "evidence": "y"}],
                              2, "max_tokens")
        client = _stream_client([resp] * (r.MAX_CONTINUATION_ATTEMPTS + 1))
        user = "Host: test\n\n=== FILE CONTENT ===\ncontent"
        findings, sc, rechunk = r._call_with_continuation(  # must not raise
            client, "coder", _p.PER_FILE_SYSTEM_PROMPT, user,
            "test.txt", 0, Path("/tmp"), 512, None, False, True,
        )
        self.assertGreaterEqual(len(findings), 2 * (r.MAX_CONTINUATION_ATTEMPTS + 1))
        self.assertIsNotNone(rechunk)


# ---------------------------------------------------------------------------
# FatalLLMError fast-fail
# ---------------------------------------------------------------------------

class TestFatalFastFail(unittest.TestCase):
    def test_fatal_error_raises_immediately_no_retry(self):
        """404 'model not found' must raise FatalLLMError after ONE attempt
        (the 2026-09-08 run retried it per chunk for 36 minutes)."""
        err = Exception("Error code: 404 - {'message': 'model not found'}")
        err.status_code = 404
        client = MagicMock()
        client.messages.stream.side_effect = err
        with self.assertRaises(r.FatalLLMError):
            r._process_single_chunk(
                "some content", "test.txt", 0, "host", Path("/tmp/bd-test"),
                client=client, model="wrong-model",
            )
        self.assertEqual(client.messages.stream.call_count, 1)  # NOT 4 attempts

    def test_transient_error_is_retried_and_chunk_marked_failed(self):
        err = Exception("Error code: 503 - upstream unavailable")
        err.status_code = 503
        client = MagicMock()
        client.messages.stream.side_effect = err
        stats = r.ScanStats()
        with patch.object(r, "RETRY_DELAYS", [0.0, 0.0]):  # no real sleeps
            findings, sc = r._process_single_chunk(
                "some content", "test.txt", 0, "host", Path("/tmp/bd-test"),
                client=client, model="coder", stats=stats,
            )
        self.assertEqual(findings, [])
        self.assertEqual(client.messages.stream.call_count, 3)  # initial + 2 patched retries
        self.assertEqual(stats.failed_chunk_ids, ["test.txt[0]"])


# ---------------------------------------------------------------------------
# Part F — reconciliation
# ---------------------------------------------------------------------------

class TestReconciliation(unittest.TestCase):
    def test_incomplete_notice_includes_gap(self):
        notice = r._incomplete_notice("trivy.json", [0, 1, 2], 5, 12)
        self.assertIn("trivy.json", notice)
        self.assertIn("3 chunk", notice)
        self.assertIn("model reported 12", notice)
        self.assertIn("only 5 extracted", notice)

    def test_incomplete_notice_no_gap(self):
        notice = r._incomplete_notice("trivy.json", [0], 0, 0)
        self.assertIn("trivy.json", notice)


# ---------------------------------------------------------------------------
# prompt consistency
# ---------------------------------------------------------------------------

class TestPrompts(unittest.TestCase):
    def test_trivy_focus_critical_high(self):
        """PER_FILE_SYSTEM_PROMPT must name critical and high for trivy."""
        for prompt in (_p.PER_FILE_SYSTEM_PROMPT,
                       _p.PER_FILE_SYSTEM_PROMPT_FALLBACK):
            self.assertIn("CRITICAL", prompt)
            self.assertIn("HIGH", prompt)
            self.assertIn("trivy.json", prompt)

    def test_tool_schema_has_optional_recommendation(self):
        finding_props = _p.REPORT_FINDINGS_TOOL["input_schema"]["properties"][
            "findings"]["items"]["properties"]
        self.assertIn("recommendation", finding_props)
        # but recommendation is NOT required
        self.assertEqual(
            _p.REPORT_FINDINGS_TOOL["input_schema"]["properties"]["findings"]
            ["items"]["required"], ["severity", "risk", "evidence"])

    def test_combine_prompt_has_scan_id_placeholder(self):
        self.assertIn("{scan_id}", _p.COMBINE_SYSTEM_PROMPT)

    def test_max_tokens_combine_defined(self):
        self.assertIsInstance(_p.MAX_TOKENS_COMBINE, int)
        self.assertGreater(_p.MAX_TOKENS_COMBINE, _p.MAX_TOKENS_PER_FILE)


# ---------------------------------------------------------------------------
# _create_message streaming (Cloudflare 524 mitigation)
# ---------------------------------------------------------------------------

class TestStreaming(unittest.TestCase):
    def test_streams_by_default(self):
        client = _stream_client(["MSG"])
        self.assertEqual(r._create_message(client, model="m"), "MSG")
        client.messages.stream.assert_called_once()
        client.messages.create.assert_not_called()

    def test_no_stream_env_falls_back_to_create(self):
        client = _stream_client(["MSG"])
        with patch.dict(os.environ, {"REMEDIATE_NO_STREAM": "1"}):
            r._create_message(client, model="m")
        client.messages.create.assert_called_once()
        client.messages.stream.assert_not_called()


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_max_chunks_per_file_reasonable(self):
        self.assertLess(r.MAX_CHUNKS_PER_FILE, 500)

    def test_max_rechunk_depth_is_small(self):
        self.assertLessEqual(r.MAX_RECHUNK_DEPTH, 2)

    def test_safe_chunk_bytes_nonzero(self):
        self.assertGreater(r._safe_chunk_bytes(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
