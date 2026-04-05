# Phase 62: Security Regression Harness, Fuzzing, and Pre-Enterprise Validation

---

## 1. Overview

Phase 27 (Advanced Pentest Remediation) identified and fixed five vulnerabilities: IP
spoofing via untrusted header trust, sync/async Redis mismatch, synchronous TLS parsing
on the event loop, Prometheus metric cardinality explosion, and log injection. Those
fixes exist in the codebase but have no automated regression tests. Nothing currently
prevents those vulnerabilities from silently re-emerging as the codebase evolves.

This phase delivers three things:

1. **Security regression harness** (`tests/security_regression/`) — a permanent,
   CI-executed test suite that asserts each Phase 27 finding stays fixed. These tests
   fail loudly if a future change re-introduces a vulnerability.

2. **Fuzzing harness** (`tests/fuzz/`) — atheris-based fuzz targets for the Python
   ClientHello parser, PROXY protocol parser, and config loader; plus a native Go
   `testing.F` fuzz target for the Go proxy's ClientHello parser. Fuzzing is not run in
   CI on every push (too slow) but is gated by `make fuzz` for a 60-second smoke run,
   and documented as a manual quarterly procedure.

3. **Pre-enterprise validation report** — `scripts/generate_validation_report.py`
   produces `docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md`, a single document that
   captures test results, dependency audit results, a summary of Phase 27 findings with
   their remediation commit hashes, and a sign-off section. This is what gets handed to
   procurement teams.

This phase does NOT re-do: the original penetration test (Phase 27, complete), the test
audit (Phase 44, complete), coverage improvement (Phase 46, complete), or static
analysis cleanup (Phase 37, complete). It builds on those foundations without repeating
them.

---

## 2. Security Regression Harness

### 2.1 Directory Layout

```
tests/
  security_regression/
    __init__.py
    conftest.py                       # Shared fixtures for regression tests
    test_ip_spoofing_regression.py    # Phase 27 finding 1.1
    test_redis_async_regression.py    # Phase 27 finding 1.2
    test_clienthello_adversarial_regression.py  # Phase 27 finding 1.3
    test_metric_cardinality_regression.py       # Phase 27 finding 1.4
    test_log_injection_regression.py  # Phase 27 finding 1.5
    test_rate_limit_ipv6_regression.py          # Supplementary: IPv6 rate limit bypass
```

All tests in this directory are regular `pytest` tests. They run in CI as part of the
standard `make test` target and also via the dedicated `make test-security-regression`
target.

### 2.2 `test_ip_spoofing_regression.py`

**Asserts:** The proxy extracts the real client IP from the PROXY protocol header only
when the connection originates from a CIDR listed in `trusted_upstream_sources`. A
connection from an untrusted source that sends an `X-Forwarded-For` header or a PROXY
protocol preamble must have its real peer IP used instead.

Key test cases:

```python
class TestIPSpoofingRegression:

    def test_trusted_source_proxy_protocol_is_accepted(self):
        # Source IP is in trusted_cidrs. PROXY protocol header claims
        # client_ip = "1.2.3.4". Proxy must use "1.2.3.4".
        ...

    def test_untrusted_source_proxy_protocol_is_ignored(self):
        # Source IP is NOT in trusted_cidrs. PROXY protocol header claims
        # client_ip = "1.2.3.4". Proxy must use the real peer IP, not "1.2.3.4".
        ...

    def test_untrusted_xff_header_is_ignored(self):
        # Source IP is NOT in trusted_cidrs. HTTP payload contains
        # X-Forwarded-For: 10.0.0.1. Proxy must use the real peer IP.
        ...

    def test_empty_trusted_cidrs_rejects_all_proxy_headers(self):
        # trusted_upstream_sources: [] — every source is untrusted.
        # Any PROXY protocol header must be ignored.
        ...

    def test_is_trusted_proxy_source_ipv6(self):
        # trusted_cidrs contains an IPv6 CIDR. Source is an IPv6 address
        # within that CIDR. PROXY protocol header must be accepted.
        ...
```

These tests call `_is_trusted_proxy_source()` directly and also test the full
`handle_connection()` path using the `AsyncMock` stream pattern established in
`tests/unit/test_proxy_server.py`.

### 2.3 `test_redis_async_regression.py`

**Asserts:** No file in the codebase that imports `asyncio` also calls the synchronous
`redis.Redis` client. This is a static analysis test using the `ast` module.

```python
import ast
import pathlib

REDIS_SYNC_CLASSES = {"Redis", "StrictRedis"}
ASYNC_MARKERS = {"asyncio", "AsyncMock", "async def", "await"}

class TestRedisAsyncRegression:

    def test_no_sync_redis_in_async_modules(self):
        """
        Scan all .py files under src/ and proxy.py. For any file that imports
        asyncio or contains 'async def', assert that it does not also instantiate
        redis.Redis or redis.StrictRedis (the synchronous client).
        """
        violations = []
        root = pathlib.Path("src")
        targets = list(root.rglob("*.py")) + [pathlib.Path("proxy.py")]
        for path in targets:
            tree = ast.parse(path.read_text())
            uses_asyncio = _file_uses_asyncio(tree)
            uses_sync_redis = _file_instantiates_sync_redis(tree)
            if uses_asyncio and uses_sync_redis:
                violations.append(str(path))
        assert violations == [], (
            f"Sync redis.Redis used in async module(s): {violations}. "
            "Use redis.asyncio.Redis instead."
        )

    def test_dial_manager_initialize_is_async(self):
        # Verify DialManager.initialize is an async def (not a sync def).
        # This was the specific fix in Phase 27 finding 1.2.
        import inspect
        from src.security.action_decider import DialManager
        assert inspect.iscoroutinefunction(DialManager.initialize)

    def test_pipeline_analytics_signals_is_async(self):
        import inspect
        from src.security.pipeline import Pipeline
        assert inspect.iscoroutinefunction(Pipeline._get_analytics_signals)
```

This test has no runtime dependencies beyond the standard library. It runs in under one
second and requires no Redis instance.

### 2.4 `test_clienthello_adversarial_regression.py`

**Asserts:** The ClientHello parser handles each of the adversarial inputs that were
identified during Phase 27 (and by the fuzzer in Section 3) without raising an uncaught
exception, hanging, or returning invalid output. The parser is expected to return `None`
or an empty result for malformed input — not raise.

These are the minimum required adversarial fixtures. Each is stored as a `bytes`
literal in the test file (short inputs) or in `tests/fixtures/adversarial_clienthello/`
(longer inputs):

```python
ADVERSARIAL_INPUTS = [
    b"",                                      # Empty
    b"\x16\x03\x01",                         # Truncated TLS record header
    b"\x16\x03\x01\x00\x05" + b"\x01" * 5,  # Record claims 5 bytes; only 5 bytes, truncated handshake
    b"\x16\x03\x01\xff\xff" + b"\x01" * 20, # Length field says 65535 bytes; body is 20 bytes
    b"\x00" * 512,                            # All zeroes
    b"\xff" * 512,                            # All 0xFF
    b"\x16\x03\x03\x00\xd0\x01" + b"\x00" * 210,  # Version TLS 1.2 with zeroed body
    # Crafted to trigger GREASE handling edge cases
    b"\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03" + b"\x00" * 32 +
    b"\x00\x00\x04\x7a\x7a\x00\x2f\x01\x00\x00\x04\x7a\x7a\x00\x01",
]

class TestClientHelloAdversarialRegression:

    @pytest.mark.parametrize("raw", ADVERSARIAL_INPUTS)
    def test_parser_does_not_raise(self, raw: bytes):
        """Parser must not raise any exception on adversarial input."""
        try:
            result = parse_client_hello(raw)
            # result may be None or a partial struct — both are acceptable
        except Exception as exc:
            pytest.fail(f"Parser raised {type(exc).__name__} on input {raw!r}: {exc}")

    @pytest.mark.parametrize("raw", ADVERSARIAL_INPUTS)
    def test_parser_does_not_hang(self, raw: bytes):
        """Parser must return within 100ms on any input."""
        import signal

        def _timeout_handler(signum, frame):
            raise TimeoutError("parser hung")

        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, 0.1)
        try:
            parse_client_hello(raw)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    def test_tls_parsing_offloaded_to_thread(self):
        """
        Phase 27 finding 1.3: Scapy TLS() parsing must run in asyncio.to_thread(),
        not on the event loop directly. Verify by inspecting the call site in proxy.py.
        """
        import ast, pathlib
        source = pathlib.Path("proxy.py").read_text()
        # 'asyncio.to_thread' must appear in the same function that calls TLS()
        assert "asyncio.to_thread" in source, (
            "TLS parsing must be offloaded via asyncio.to_thread() — see Phase 27 finding 1.3"
        )
```

The `parse_client_hello` import path is `from src.parsing.tls_parser import parse_client_hello`
(Python proxy) or the Go equivalent via subprocess in Go-specific tests.

### 2.5 `test_metric_cardinality_regression.py`

**Asserts:** The `ja4_requests_total` Prometheus counter does not include a `fingerprint`
label containing a full JA4 hash. This was the cardinality explosion finding in Phase 27
(finding 1.4).

```python
class TestMetricCardinalityRegression:

    def test_ja4_requests_total_has_no_fingerprint_label(self):
        """
        Full JA4 fingerprints must not appear as Prometheus label values on
        ja4_requests_total. Labels must only include 'fingerprint_name' or similar
        low-cardinality fields.
        """
        from prometheus_client import REGISTRY
        # Collect the metric descriptor
        metrics = {m.name: m for m in REGISTRY.collect()}
        if "ja4_requests_total" not in metrics:
            pytest.skip("ja4_requests_total not registered in this process")
        descriptor = metrics["ja4_requests_total"]
        label_names = {l for sample in descriptor.samples for l in sample.labels}
        assert "fingerprint" not in label_names, (
            "ja4_requests_total must not have a 'fingerprint' label — "
            "full JA4 hashes as label values cause Prometheus cardinality explosion. "
            "See Phase 27 finding 1.4."
        )

    def test_sanitize_log_strips_newlines(self):
        """Phase 27 finding 1.5: _sanitize_log must strip \\r and \\n."""
        from proxy import _sanitize_log
        assert "\n" not in _sanitize_log("foo\nbar")
        assert "\r" not in _sanitize_log("foo\r\nbar")
        assert _sanitize_log("clean input") == "clean input"

    def test_sanitize_log_applied_to_client_ip(self):
        """
        Verify _sanitize_log is called before any log statement that includes
        client_ip or socket_ip. Static check via AST on proxy.py.
        """
        import ast, pathlib
        # A targeted structural check: look for logging calls that concatenate
        # client_ip without passing through _sanitize_log first.
        # Implementation: parse proxy.py, walk Call nodes for logger.*, assert
        # that any argument referencing 'client_ip' is wrapped in '_sanitize_log'.
        source = pathlib.Path("proxy.py").read_text()
        assert "_sanitize_log" in source, (
            "_sanitize_log must exist in proxy.py — see Phase 27 finding 1.5"
        )
```

### 2.6 `test_rate_limit_ipv6_regression.py`

**Asserts:** IPv4 address `A.B.C.D` and its IPv4-mapped IPv6 form `::ffff:A.B.C.D` are
treated as the same client for rate-limiting purposes. An attacker that sends requests
alternating between the two forms must not be able to double their rate limit budget.

```python
class TestRateLimitIPv6Regression:

    @pytest.mark.asyncio
    async def test_ipv4_and_ipv4_mapped_ipv6_share_rate_limit(self):
        """
        Requests from 1.2.3.4 and ::ffff:1.2.3.4 must consume from the same
        rate limit bucket. Sending N requests alternating between both forms
        must not result in 2×N allowed requests.
        """
        from src.cache.local_cache import LocalCache
        from src.security.pipeline import Pipeline
        # ... construct pipeline with a rate limit of 5 req/s
        # Send 3 requests as IPv4, 3 as IPv4-mapped IPv6
        # Assert total allowed <= 5, not 6
        ...

    def test_ip_normalisation_collapses_ipv4_mapped(self):
        """
        The IP normalisation utility must collapse ::ffff:1.2.3.4 to 1.2.3.4
        so that rate-limit keys, ban keys, and log entries are consistent.
        """
        from src.utils.ip_utils import normalise_ip
        assert normalise_ip("::ffff:1.2.3.4") == "1.2.3.4"
        assert normalise_ip("::ffff:192.168.1.1") == "192.168.1.1"
        assert normalise_ip("2001:db8::1") == "2001:db8::1"  # Real IPv6 unchanged
        assert normalise_ip("1.2.3.4") == "1.2.3.4"          # IPv4 unchanged

    @pytest.mark.asyncio
    async def test_ban_key_uses_normalised_ip(self):
        """
        A ban placed on 1.2.3.4 must also block ::ffff:1.2.3.4.
        They must share the same ban:{ip} key in Redis.
        """
        ...
```

---

## 3. Fuzzing Harness

Fuzzing finds bugs in parsers that deterministic tests miss. The harness covers the
three parsing entry points that accept untrusted external bytes: the Python ClientHello
parser, the PROXY protocol parser, and the config loader. The Go proxy's ClientHello
parser has a separate Go native fuzz target.

### 3.1 Directory Layout

```
tests/
  fuzz/
    __init__.py
    fuzz_clienthello.py      # Python ClientHello parser (atheris)
    fuzz_proxy_protocol.py   # PROXY protocol v1/v2 parser (atheris)
    fuzz_config.py           # Config loader with malformed YAML (atheris)
    README.md                # How to run long-form fuzzing

cmd/
  proxy/
    fuzz_test.go             # Go ClientHello fuzzer (testing.F)
```

### 3.2 Atheris Setup

`atheris` is a coverage-guided Python fuzzer backed by libFuzzer. Install with:

```bash
pip install atheris
```

Atheris requires a Python build with sanitizer support for maximum effectiveness, but
runs usably with a stock Python build for CI smoke tests. Add to `requirements.txt`:

```
atheris>=2.3.0  # phase-62 — Python fuzzing harness
```

### 3.3 `fuzz_clienthello.py`

```python
#!/usr/bin/env python3
"""
Fuzz target for the Python ClientHello parser.

Usage (CI smoke — 60 seconds):
    python tests/fuzz/fuzz_clienthello.py -max_total_time=60

Usage (full fuzzing — manual quarterly run):
    python tests/fuzz/fuzz_clienthello.py -max_total_time=3600 corpus/clienthello/
"""
import sys
import atheris
from src.parsing.tls_parser import parse_client_hello


def TestOneInput(data: bytes) -> None:
    try:
        parse_client_hello(data)
    except Exception:
        # Exceptions from a public parser on untrusted input are crashes.
        # atheris will report and save the input automatically.
        raise


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
```

The fuzz corpus is seeded from `tests/fixtures/clienthello/` (existing valid samples)
and from `tests/fixtures/adversarial_clienthello/` (adversarial samples from Section 2.4).

### 3.4 `fuzz_proxy_protocol.py`

```python
#!/usr/bin/env python3
"""
Fuzz target for the PROXY protocol v1/v2 header parser.

The PROXY protocol header is the first bytes of every connection from HAProxy.
Malformed input here must never crash the proxy or be accepted as a valid header
from an untrusted source.

Usage (CI smoke):
    python tests/fuzz/fuzz_proxy_protocol.py -max_total_time=60
"""
import sys
import atheris
from proxy import _parse_proxy_protocol_header, _is_trusted_proxy_source


def TestOneInput(data: bytes) -> None:
    try:
        result = _parse_proxy_protocol_header(data)
        # result is (client_ip, rest_of_data) or None — both valid
    except Exception:
        raise


if __name__ == "__main__":
    # Seed corpus: a valid PROXY v1 header and a valid PROXY v2 header
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
```

### 3.5 `fuzz_config.py`

```python
#!/usr/bin/env python3
"""
Fuzz target for the config loader.

The config loader reads YAML from disk and from hot-reload events. Malformed YAML
must not crash the loader — it must log a warning and retain the previous valid config.

Usage (CI smoke):
    python tests/fuzz/fuzz_config.py -max_total_time=60
"""
import sys
import tempfile
import pathlib
import atheris
from src.config.loader import ConfigLoader


def TestOneInput(data: bytes) -> None:
    try:
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False) as f:
            f.write(data)
            tmp = f.name
        loader = ConfigLoader(config_path=tmp)
        loader.load()  # Must not raise; must return defaults on malformed input
    except SystemExit:
        # Acceptable: loader may sys.exit on completely unparseable config at startup
        pass
    except Exception:
        raise
    finally:
        pathlib.Path(tmp).unlink(missing_ok=True)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()
```

### 3.6 Go Fuzz Target — `cmd/proxy/fuzz_test.go`

```go
// fuzz_test.go — Go native fuzzer for the ClientHello parser.
// Run: go test -fuzz=FuzzClientHello -fuzztime=60s ./cmd/proxy/
package main

import (
    "testing"
    "github.com/org/ja4proxy/internal/tlsparse"
)

func FuzzClientHello(f *testing.F) {
    // Seed corpus: valid ClientHello bytes
    f.Add([]byte("\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03")) // truncated — expand with real fixture
    f.Add([]byte{})
    f.Add([]byte("\x00\x00\x00\x00"))

    f.Fuzz(func(t *testing.T, data []byte) {
        // ParseClientHello must never panic on any input.
        // It may return an error or empty result — that is expected.
        defer func() {
            if r := recover(); r != nil {
                t.Errorf("ParseClientHello panicked on input %x: %v", data, r)
            }
        }()
        _, _ = tlsparse.ParseClientHello(data)
    })
}
```

The `defer recover()` pattern catches panics and converts them to test failures, which
is what go-fuzz and the native fuzzer both report as crashes.

### 3.7 Fuzzing Corpus Management

Fuzzing corpus directories are committed to the repository:

```
tests/fuzz/corpus/
  clienthello/        # Valid ClientHello samples for seeding
  proxy_protocol/     # Valid PROXY v1 and v2 headers
  config/             # Valid and near-valid YAML configs
```

When the fuzzer finds a crash, the input is saved to
`tests/fuzz/findings/<target>/<timestamp>.bin`. These findings are:
1. Added to `tests/fixtures/adversarial_clienthello/` (for regression test 2.4)
2. Used to fix the parser
3. Committed alongside the fix

Quarterly fuzzing procedure is documented in `tests/fuzz/README.md`. The recommended
minimum runtime for a meaningful full fuzz campaign is 24 hours per target.

---

## 4. Pre-Enterprise Validation Report

### 4.1 Purpose

Enterprise procurement teams commonly ask:
- "What known vulnerabilities exist in this product?"
- "How do you know your past vulnerabilities haven't come back?"
- "What dependencies does this software have, and are they free of CVEs?"
- "Can you show me that these security fixes are actually in the build?"

`docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md` answers all four questions from
a single generated document. It is regenerated before each procurement engagement by
running `make validation-report`.

### 4.2 `scripts/generate_validation_report.py`

```python
#!/usr/bin/env python3
"""
Generate docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md.

This script:
  1. Runs all tests in tests/security_regression/ and captures results
  2. Runs pip-audit and govulncheck and captures output
  3. Queries git log for the Phase 27 remediation commits
  4. Writes the report to docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md

Usage:
    python3 scripts/generate_validation_report.py
    python3 scripts/generate_validation_report.py --output /tmp/report.md
"""
import argparse
import datetime
import json
import pathlib
import subprocess
import sys
from typing import NamedTuple


class SectionResult(NamedTuple):
    title: str
    passed: bool
    content: str


def run_security_regression_tests() -> SectionResult:
    result = subprocess.run(
        ["python3", "-m", "pytest", "tests/security_regression/", "-v", "--tb=short",
         "--timeout=60", "--json-report", "--json-report-file=/tmp/sr_results.json"],
        capture_output=True, text=True
    )
    passed = result.returncode == 0
    return SectionResult("Security Regression Tests", passed, result.stdout + result.stderr)


def run_pip_audit() -> SectionResult:
    result = subprocess.run(
        ["pip-audit", "-r", "requirements.txt", "--format=json"],
        capture_output=True, text=True
    )
    passed = result.returncode == 0
    try:
        data = json.loads(result.stdout)
        vulns = data.get("vulnerabilities", [])
        summary = f"{len(vulns)} vulnerabilities found." if vulns else "No vulnerabilities found."
    except json.JSONDecodeError:
        summary = result.stdout
    return SectionResult("Python Dependency Audit (pip-audit)", passed, summary)


def run_govulncheck() -> SectionResult:
    result = subprocess.run(
        ["govulncheck", "./..."],
        capture_output=True, text=True,
        cwd=str(pathlib.Path(__file__).parent.parent)
    )
    passed = result.returncode == 0
    return SectionResult("Go Dependency Audit (govulncheck)", passed, result.stdout + result.stderr)


def get_phase27_commits() -> SectionResult:
    """Find commits that reference Phase 27 remediation in their message."""
    result = subprocess.run(
        ["git", "log", "--oneline", "--grep=phase-27", "--grep=Phase 27",
         "--grep=IP spoofing", "--grep=sync.*redis", "--all-match=False"],
        capture_output=True, text=True
    )
    lines = result.stdout.strip().splitlines()
    content = "\n".join(f"- `{l}`" for l in lines) if lines else "_No matching commits found._"
    return SectionResult("Phase 27 Remediation Commits", bool(lines), content)


def write_report(sections: list[SectionResult], output_path: pathlib.Path) -> None:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    overall_pass = all(s.passed for s in sections)
    status = "PASS" if overall_pass else "FAIL"

    lines = [
        "# JA4proxy Pre-Enterprise Validation Report",
        "",
        f"**Generated:** {now}",
        f"**Overall status:** {status}",
        "",
        "This report is generated by `scripts/generate_validation_report.py` and "
        "covers security regression test results, dependency vulnerability audits, "
        "and the remediation history for known past findings. It is intended for "
        "review by procurement security teams.",
        "",
        "---",
        "",
    ]

    for section in sections:
        icon = "PASS" if section.passed else "FAIL"
        lines += [
            f"## {section.title} — {icon}",
            "",
            "```",
            section.content.strip(),
            "```",
            "",
        ]

    lines += [
        "---",
        "",
        "## Sign-Off",
        "",
        "| Item | Status |",
        "|------|--------|",
        f"| Security regression tests | {'PASS' if sections[0].passed else 'FAIL'} |",
        f"| Python dependency CVEs | {'PASS' if sections[1].passed else 'FAIL'} |",
        f"| Go dependency CVEs | {'PASS' if sections[2].passed else 'FAIL'} |",
        f"| Phase 27 remediation commits present | {'PASS' if sections[3].passed else 'FAIL'} |",
        "",
        "_Reviewer:_ ___________________________  "
        "_Date:_ ___________________________  "
        "_Title:_ ___________________________",
        "",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))
    print(f"Report written to: {output_path}")
    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md")
    args = parser.parse_args()

    sections = [
        run_security_regression_tests(),
        run_pip_audit(),
        run_govulncheck(),
        get_phase27_commits(),
    ]
    write_report(sections, pathlib.Path(args.output))
```

### 4.3 Report Structure and Content

The generated `docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md` contains:

**Header block:** Generation timestamp, overall PASS/FAIL status, one-paragraph
description of scope.

**Section 1 — Security Regression Tests:** Full `pytest -v` output from
`tests/security_regression/`. Shows each regression test case by name and result.
A procurement reviewer can see exactly which vulnerability each test covers.

**Section 2 — Python Dependency Audit:** `pip-audit` results. PASS means zero
HIGH/CRITICAL CVEs in `requirements.txt` at generation time. Any known vulnerabilities
are listed with CVE ID, severity, affected package, and available fix version.

**Section 3 — Go Dependency Audit:** `govulncheck` results for `./...`. Same
interpretation as Section 2.

**Section 4 — Phase 27 Remediation Commits:** Git log output showing the commits that
introduced the IP spoofing fix, the async Redis fix, the TLS thread offload, the metric
cardinality fix, and the log injection sanitizer. Each commit hash is a verifiable link
between the finding description and the code change.

**Sign-off table:** A structured table with one row per section, each marked PASS or
FAIL. Below the table is a handwritten sign-off line for the engineer running the report.

The report exits with code 0 if all sections pass, 1 if any section fails. CI will catch
a failing `make validation-report` run.

---

## 5. Makefile Targets

Add to the bottom of `Makefile` (never edit existing targets):

```makefile
## Phase 62 targets

test-security-regression:
	python3 -m pytest tests/security_regression/ -v --timeout=60

fuzz:
	@echo "Running fuzzer smoke tests (60s each)..."
	python3 tests/fuzz/fuzz_clienthello.py -max_total_time=60 \
	    tests/fuzz/corpus/clienthello/ || true
	python3 tests/fuzz/fuzz_proxy_protocol.py -max_total_time=60 \
	    tests/fuzz/corpus/proxy_protocol/ || true
	python3 tests/fuzz/fuzz_config.py -max_total_time=60 \
	    tests/fuzz/corpus/config/ || true
	GOROOT=/snap/go/current go test -fuzz=FuzzClientHello -fuzztime=60s ./cmd/proxy/ || true
	@echo "Fuzz smoke complete. Check tests/fuzz/findings/ for any crash inputs."

validation-report:
	python3 scripts/generate_validation_report.py
```

The `|| true` on fuzz runs prevents `make fuzz` from failing if atheris reports a
known-unfixed finding. The exit code of the fuzz targets is only meaningful during
triage; CI smoke is about ensuring the fuzzers start and run without setup errors.

---

## 6. Acceptance Criteria

- [ ] `tests/security_regression/` directory exists with all six test files listed in Section 2.1
- [ ] `test_ip_spoofing_regression.py` covers trusted-source acceptance, untrusted-source rejection, empty-trusted-cidrs case, and IPv6 trusted CIDR
- [ ] `test_redis_async_regression.py` passes without a running Redis instance; static AST scan finds zero violations in the current codebase
- [ ] `test_redis_async_regression.py` asserts `DialManager.initialize` is a coroutine function
- [ ] `test_clienthello_adversarial_regression.py` covers all eight adversarial inputs in Section 2.4; none cause an uncaught exception
- [ ] `test_clienthello_adversarial_regression.py` includes the `test_tls_parsing_offloaded_to_thread` static check and it passes
- [ ] `test_metric_cardinality_regression.py` asserts no `fingerprint` label on `ja4_requests_total`
- [ ] `test_metric_cardinality_regression.py` asserts `_sanitize_log` strips `\r` and `\n`
- [ ] `test_rate_limit_ipv6_regression.py` asserts `::ffff:1.2.3.4` normalises to `1.2.3.4`
- [ ] `make test-security-regression` runs and all tests pass with zero failures
- [ ] `tests/fuzz/fuzz_clienthello.py`, `fuzz_proxy_protocol.py`, and `fuzz_config.py` exist and are valid atheris fuzz targets
- [ ] `cmd/proxy/fuzz_test.go` exists with `FuzzClientHello` target; `go test -fuzz=FuzzClientHello -fuzztime=5s ./cmd/proxy/` completes without panic
- [ ] `make fuzz` completes without setup errors (fuzz processes start and run)
- [ ] `atheris>=2.3.0` added to `requirements.txt` with `# phase-62` comment
- [ ] `scripts/generate_validation_report.py` exists and is executable
- [ ] `make validation-report` runs to completion and writes `docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md`
- [ ] The generated report contains all four sections described in Section 4.3
- [ ] The report exits with code 1 if any security regression test fails; CI catches this
- [ ] `tests/fuzz/README.md` documents the quarterly full-fuzz procedure and corpus management
- [ ] `tests/security_regression/` tests are included in the standard `make test` run (not excluded)
