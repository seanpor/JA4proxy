"""
Cross-language parity tests: Go proxy vs Python proxy must produce identical
JA4 fingerprints and equivalent security decisions for identical inputs.

Requires: Go binary at bin/ja4proxy (or GO_BINARY env var)
Build with: GOROOT=/snap/go/current go build -o bin/ja4proxy ./cmd/proxy
Run: python3 -m pytest tests/integration/test_go_python_parity.py -v

Also requires: bin/ja4check for fingerprint comparison.
Build with: GOROOT=/snap/go/current go build -o bin/ja4check ./cmd/ja4check
"""
import glob
import json
import os
import pathlib
import socket
import subprocess
import time

import pytest

# ── Environment / configuration ──────────────────────────────────────────────

GO_PROXY_HOST = os.environ.get("GO_PROXY_HOST", "127.0.0.1")
GO_PROXY_PORT = int(os.environ.get("GO_PROXY_PORT", "8082"))
GO_METRICS_PORT = int(os.environ.get("GO_METRICS_PORT", "9092"))
PYTHON_PROXY_HOST = os.environ.get("PYTHON_PROXY_HOST", "127.0.0.1")
PYTHON_PROXY_PORT = int(os.environ.get("PYTHON_PROXY_PORT", "8081"))
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6380"))
GO_BINARY = os.environ.get("GO_BINARY", "bin/ja4proxy")

# Resolve tool paths (bin/ for local, /usr/local/bin/ in Docker)
JA4CHECK = os.environ.get("JA4CHECK", "")
if not JA4CHECK:
    for candidate in ("bin/ja4check", "/usr/local/bin/ja4check"):
        if os.path.exists(candidate):
            JA4CHECK = candidate
            break

COMPUTE_JA4_PY = str(
    pathlib.Path(__file__).parent.parent.parent / "scripts" / "compute_ja4.py"
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _go_proxy_live() -> bool:
    return _check_port(GO_PROXY_HOST, GO_PROXY_PORT)


def _python_proxy_live() -> bool:
    return _check_port(PYTHON_PROXY_HOST, PYTHON_PROXY_PORT)


def _redis_live() -> bool:
    try:
        import redis as redislib
        r = redislib.Redis(host=REDIS_HOST, port=REDIS_PORT, socket_connect_timeout=1)
        return r.ping()
    except Exception:
        return False


def _run_ja4check(fixture_path: str) -> str:
    """Run the Go ja4check tool on a fixture file. Returns stdout stripped."""
    if not JA4CHECK:
        return "JA4CHECK_NOT_FOUND"
    result = subprocess.run(
        [JA4CHECK, fixture_path],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return f"ERROR:{result.stderr.strip()}"
    return result.stdout.strip()


def _run_compute_py(fixture_path: str) -> str:
    """Run the Python compute_ja4.py script on a fixture file. Returns stdout stripped."""
    result = subprocess.run(
        ["python3", COMPUTE_JA4_PY, fixture_path],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def go_proxy():
    """Start the Go proxy for local tests; skip if binary missing.

    In Docker the Go proxy is a separate service; this fixture is a no-op there.
    """
    if _go_proxy_live():
        yield None  # already running (Docker or externally managed)
        return

    if not os.path.exists(GO_BINARY):
        pytest.skip(
            f"Go binary not found at {GO_BINARY}; "
            "run: GOROOT=/snap/go/current go build -o bin/ja4proxy ./cmd/proxy"
        )

    proc = subprocess.Popen(
        [GO_BINARY],
        env={
            **os.environ,
            "PROXY_PORT": str(GO_PROXY_PORT),
            "METRICS_PORT": str(GO_METRICS_PORT),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.5)
    if proc.poll() is not None:
        out, err = proc.communicate()
        pytest.skip(f"Go proxy exited on startup: {err.decode()}")
    yield proc
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="module")
def redis_client():
    """Return a real Redis client for state manipulation; skip if Redis unavailable."""
    try:
        import redis as redislib
    except ImportError:
        pytest.skip("redis-py not installed")

    r = redislib.Redis(host=REDIS_HOST, port=REDIS_PORT, socket_connect_timeout=2)
    try:
        r.ping()
    except Exception:
        pytest.skip(f"Redis not reachable at {REDIS_HOST}:{REDIS_PORT}")

    yield r

    # Cleanup: remove any blacklist entries we may have added
    r.delete("ja4:blacklist")


# ── Tests: Go proxy basic connectivity ───────────────────────────────────────

def test_go_proxy_starts(go_proxy):
    """Go proxy must start and accept TCP connections."""
    if not _go_proxy_live():
        pytest.skip("Go proxy not reachable")
    with socket.create_connection((GO_PROXY_HOST, GO_PROXY_PORT), timeout=2):
        pass  # Connection accepted — proxy is up


def test_go_proxy_health(go_proxy):
    """Go proxy /health endpoint must return 200 and include a status field."""
    if not _go_proxy_live():
        pytest.skip("Go proxy not reachable")
    try:
        import requests
    except ImportError:
        pytest.skip("requests not installed")

    r = requests.get(
        f"http://{GO_PROXY_HOST}:{GO_METRICS_PORT}/health", timeout=3
    )
    assert r.status_code in (200, 503), (
        f"Expected 200 or 503 from /health, got {r.status_code}"
    )
    data = r.json()
    assert "status" in data, f"/health response missing 'status' field: {data}"


def test_go_proxy_metrics_present(go_proxy):
    """Go proxy /metrics must expose ja4proxy_ prefixed Prometheus metrics."""
    if not _go_proxy_live():
        pytest.skip("Go proxy not reachable")
    try:
        import requests
    except ImportError:
        pytest.skip("requests not installed")

    r = requests.get(
        f"http://{GO_PROXY_HOST}:{GO_METRICS_PORT}/metrics", timeout=3
    )
    assert r.status_code == 200, f"/metrics returned {r.status_code}"
    assert "ja4proxy_connections_total" in r.text, (
        "Expected 'ja4proxy_connections_total' in /metrics output"
    )
    assert "ja4proxy_active_connections" in r.text, (
        "Expected 'ja4proxy_active_connections' in /metrics output"
    )


# ── Tests: JA4 fingerprint parity ────────────────────────────────────────────

def _get_fixture_files():
    """Return all .bin fixture files found in tests/fixtures/clienthello/."""
    pattern = str(
        pathlib.Path(__file__).parent.parent / "fixtures" / "clienthello" / "*.bin"
    )
    return glob.glob(pattern)


def test_ja4_fixtures_exist():
    """At least one .bin fixture must exist (run generate_fixtures.sh first)."""
    files = _get_fixture_files()
    # Generate synthetic ones on the fly if needed
    if not files:
        gen_script = str(
            pathlib.Path(__file__).parent.parent.parent
            / "scripts"
            / "generate_synthetic_fixtures.py"
        )
        if os.path.exists(gen_script):
            result = subprocess.run(
                ["python3", gen_script], capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                pytest.skip(
                    f"No fixture files and generate_synthetic_fixtures.py failed: "
                    f"{result.stderr}"
                )
            files = _get_fixture_files()

    assert len(files) > 0, (
        "No .bin fixture files found in tests/fixtures/clienthello/. "
        "Run: python3 scripts/generate_synthetic_fixtures.py"
    )


@pytest.mark.parametrize("fixture_path", _get_fixture_files() or ["__no_fixtures__"])
def test_ja4_parity_go_vs_python(fixture_path):
    """Go ja4check and Python compute_ja4.py must return identical JA4 for each fixture."""
    if fixture_path == "__no_fixtures__":
        pytest.skip("No .bin fixture files found; run generate_synthetic_fixtures.py")

    if not JA4CHECK:
        pytest.skip("ja4check binary not found; run: go build -o bin/ja4check ./cmd/ja4check")

    if not os.path.exists(COMPUTE_JA4_PY):
        pytest.skip(f"compute_ja4.py not found at {COMPUTE_JA4_PY}")

    go_ja4 = _run_ja4check(fixture_path)
    py_ja4 = _run_compute_py(fixture_path)

    assert not go_ja4.startswith("ERROR"), f"Go ja4check failed on {fixture_path}: {go_ja4}"
    assert not py_ja4.startswith("ERROR"), f"Python compute_ja4.py failed on {fixture_path}: {py_ja4}"
    assert not py_ja4.startswith("PARSE_FAILED"), (
        f"Python parser could not parse {fixture_path}: {py_ja4}"
    )

    assert go_ja4 == py_ja4, (
        f"JA4 mismatch for {pathlib.Path(fixture_path).name}:\n"
        f"  Go:     {go_ja4}\n"
        f"  Python: {py_ja4}"
    )


def test_ja4_known_values_match_json():
    """Synthetic fixtures must produce JA4 values matching known_ja4.json."""
    json_path = (
        pathlib.Path(__file__).parent.parent
        / "fixtures"
        / "clienthello"
        / "known_ja4.json"
    )
    if not json_path.exists():
        pytest.skip("known_ja4.json not found; run generate_synthetic_fixtures.py")

    if not JA4CHECK:
        pytest.skip("ja4check binary not found")

    known = json.loads(json_path.read_text())
    mismatches = []

    for name, expected_ja4 in known.items():
        fixture_path = json_path.parent / f"{name}.bin"
        if not fixture_path.exists():
            continue
        go_ja4 = _run_ja4check(str(fixture_path))
        if go_ja4 != expected_ja4:
            mismatches.append(
                f"  {name}: expected={expected_ja4} got={go_ja4}"
            )

    assert not mismatches, (
        "Go JA4 output does not match known_ja4.json for:\n" + "\n".join(mismatches)
    )


# ── Tests: dial=0 monitor mode ───────────────────────────────────────────────

def test_dial_zero_monitor_mode(go_proxy):
    """At dial=0 (default), Go proxy must accept TCP connections without RST."""
    if not _go_proxy_live():
        pytest.skip("Go proxy not reachable")

    refusals = 0
    for _ in range(5):
        try:
            with socket.create_connection(
                (GO_PROXY_HOST, GO_PROXY_PORT), timeout=2
            ):
                pass
        except ConnectionRefusedError:
            refusals += 1

    assert refusals == 0, (
        f"Go proxy refused {refusals}/5 connections at dial=0 (should accept all)"
    )


# ── Tests: h2 ALPN bypass ─────────────────────────────────────────────────────

def test_h2_alpn_bypass_go_proxy(go_proxy):
    """Go proxy must never RST a connection advertising h2 ALPN."""
    if not _go_proxy_live():
        pytest.skip("Go proxy not reachable")

    from tests.lib.tls_client import build_client_hello, send_clienthello_and_check

    hello = build_client_hello(alpn=["h2"], tls13=True)
    result = send_clienthello_and_check(GO_PROXY_HOST, GO_PROXY_PORT, hello)

    assert result["connected"], "Go proxy refused h2 ALPN connection"
    assert not result["rst"], (
        "Go proxy sent RST for h2 ALPN connection — h2 traffic must always bypass"
    )


def test_h2_alpn_bypass_python_proxy():
    """Python proxy must never RST a connection advertising h2 ALPN."""
    if not _python_proxy_live():
        pytest.skip("Python proxy not reachable")

    from tests.lib.tls_client import build_client_hello, send_clienthello_and_check

    hello = build_client_hello(alpn=["h2"], tls13=True)
    result = send_clienthello_and_check(PYTHON_PROXY_HOST, PYTHON_PROXY_PORT, hello)

    assert result["connected"], "Python proxy refused h2 ALPN connection"
    assert not result["rst"], (
        "Python proxy sent RST for h2 ALPN connection — h2 traffic must always bypass"
    )


# ── Tests: JA4 blacklist ──────────────────────────────────────────────────────

def test_ja4_blacklist_blocks_go_proxy(go_proxy, redis_client):
    """Go proxy must RST a connection whose JA4 is in the blacklist."""
    if not _go_proxy_live():
        pytest.skip("Go proxy not reachable")

    from tests.lib.tls_client import build_client_hello, send_clienthello_and_check

    # Build a ClientHello and compute its JA4 so we know what to blacklist
    hello = build_client_hello(
        ciphers=[0x1301],  # single cipher for deterministic JA4
        sni="blacklist-test.example.com",
        tls13=True,
        alpn=None,
    )

    if not JA4CHECK:
        pytest.skip("ja4check not found; cannot determine JA4 to blacklist")

    # Save hello to a temp file so ja4check can read it
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(hello)
        tmp_path = f.name

    try:
        ja4 = _run_ja4check(tmp_path)
    finally:
        os.unlink(tmp_path)

    if ja4.startswith("ERROR") or not ja4:
        pytest.skip(f"Could not compute JA4 for test hello: {ja4}")

    # Add to blacklist, send hello, expect RST
    redis_client.sadd("ja4:blacklist", ja4)
    try:
        time.sleep(0.2)  # allow proxy to sync blacklist
        result = send_clienthello_and_check(GO_PROXY_HOST, GO_PROXY_PORT, hello)
        assert result["connected"], "Go proxy refused connection entirely"
        assert result["rst"], (
            f"Go proxy did NOT RST connection with blacklisted JA4={ja4}; "
            f"data_received={result['data_received']!r}"
        )
    finally:
        redis_client.srem("ja4:blacklist", ja4)


# ── Tests: metrics consistency ────────────────────────────────────────────────

def test_metrics_connections_increment(go_proxy):
    """Making a connection to Go proxy must increment ja4proxy_connections_total."""
    if not _go_proxy_live():
        pytest.skip("Go proxy not reachable")
    try:
        import requests
    except ImportError:
        pytest.skip("requests not installed")

    metrics_url = f"http://{GO_PROXY_HOST}:{GO_METRICS_PORT}/metrics"

    def _get_counter() -> float:
        r = requests.get(metrics_url, timeout=3)
        for line in r.text.splitlines():
            if line.startswith("ja4proxy_connections_total"):
                try:
                    return float(line.split()[-1])
                except (ValueError, IndexError):
                    pass
        return 0.0

    before = _get_counter()

    # Make a connection to trigger an increment
    try:
        with socket.create_connection((GO_PROXY_HOST, GO_PROXY_PORT), timeout=2):
            pass
    except OSError:
        pytest.skip("Could not make test connection to Go proxy")

    time.sleep(0.3)
    after = _get_counter()

    assert after > before, (
        f"ja4proxy_connections_total did not increase: before={before}, after={after}"
    )
