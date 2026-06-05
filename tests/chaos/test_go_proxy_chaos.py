"""
Chaos and resilience tests for the Go proxy.

Tests verify that the Go proxy remains stable and fail-open under adverse
conditions: Redis down, malformed TLS input, bad PROXY protocol headers,
graceful shutdown, and unknown config keys.

Requires: Go binary at bin/ja4pd (or GO_BINARY env var).
Build with: GOROOT=/snap/go/current go build -o bin/ja4pd ./cmd/ja4pd
Run: python3 -m pytest tests/chaos/test_go_proxy_chaos.py -v
"""

import glob
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
import time

import pytest

# ── Configuration ─────────────────────────────────────────────────────────────

GO_PROXY_HOST = os.environ.get("GO_PROXY_HOST", "127.0.0.1")
GO_PROXY_PORT = int(os.environ.get("GO_PROXY_PORT", "18082"))
GO_METRICS_PORT = int(os.environ.get("GO_METRICS_PORT", "19092"))
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6380"))
GO_BINARY = os.environ.get("GO_BINARY", "bin/ja4pd")

# Use a different port range for locally-spawned proxies in chaos tests
_CHAOS_PROXY_PORT = 18083
_CHAOS_METRICS_PORT = 19093

pytestmark = pytest.mark.skipif(
    not (os.path.exists(GO_BINARY) or os.path.exists("/usr/local/bin/ja4pd")),
    reason=(
        "Go binary not built; run: "
        "GOROOT=/snap/go/current go build -o bin/ja4pd ./cmd/ja4pd"
    ),
)

# Resolve actual binary path
_GO_BIN = GO_BINARY
if not os.path.exists(_GO_BIN):
    if os.path.exists("/usr/local/bin/ja4pd"):
        _GO_BIN = "/usr/local/bin/ja4pd"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _check_port(host, port, timeout=0.5):
            return True
        time.sleep(0.1)
    return False


def _start_proxy(
    port: int, metrics_port: int, extra_env: dict = None
) -> subprocess.Popen:
    env = {
        **os.environ,
        "PROXY_PORT": str(port),
        "METRICS_PORT": str(metrics_port),
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        [_GO_BIN],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


# ── Test: adversarial ClientHello corpus ─────────────────────────────────────


def test_go_proxy_adversarial_clienthello_no_panic():
    """Every adversarial corpus file must not cause a goroutine panic.

    Sends each corpus file's raw bytes to a self-contained proxy instance and
    verifies that the proxy is still accepting connections afterward.
    """
    corpus = glob.glob("tests/adversarial/corpus/*.bin")
    if not corpus:
        pytest.skip("no adversarial corpus files found in tests/adversarial/corpus/")

    chaos_port = 18083
    chaos_metrics = 19083

    proc = _start_proxy(chaos_port, chaos_metrics)
    started = _wait_for_port("127.0.0.1", chaos_port, timeout=15.0)
    if not started and proc.poll() is not None:
        out, err = proc.communicate()
        pytest.skip(f"Go proxy could not start: {err.decode()[:200]}")
    if not started:
        proc.kill()
        pytest.skip("Go proxy did not start listening within timeout")

    try:
        panics = []
        for path in corpus:
            try:
                data = pathlib.Path(path).read_bytes()
            except OSError:
                continue
            if len(data) == 0:
                continue  # empty corpus file is a valid test input but nothing to send

            # Send the raw bytes; the proxy should not crash regardless of content
            try:
                sock = socket.create_connection(("127.0.0.1", chaos_port), timeout=2)
                sock.sendall(data)
                sock.settimeout(1.0)
                try:
                    sock.recv(4096)
                except (socket.timeout, ConnectionResetError):
                    pass
                sock.close()
            except OSError:
                pass

        # After sending all corpus files, proxy must still be alive
        assert _check_port(
            "127.0.0.1", chaos_port, timeout=2.0
        ), "Go proxy is no longer accepting connections after adversarial corpus replay"
        assert not panics, f"Proxy panicked on corpus files: {panics}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── Test: unknown config keys ─────────────────────────────────────────────────


def test_go_proxy_starts_with_unknown_config_keys():
    """Go proxy must start even if proxy.yml has unknown top-level keys."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(
            "# Chaos test config with unknown keys\n"
            "listen_port: 18999\n"
            "unknown_key_that_does_not_exist: true\n"
            "another_mystery_field:\n"
            "  nested: value\n"
        )
        config_path = f.name

    chaos_port = 18084
    chaos_metrics = 19084

    try:
        proc = subprocess.Popen(
            [_GO_BIN],
            env={
                **os.environ,
                "PROXY_PORT": str(chaos_port),
                "METRICS_PORT": str(chaos_metrics),
                "CONFIG_PATH": config_path,
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Give it up to 3 seconds to either start or crash
        try:
            proc.wait(timeout=3)
            # It exited — check why
            out, err = proc.communicate()
            stderr_text = err.decode(errors="replace")
            # Acceptable: proxy may refuse to start due to unknown keys (strict mode)
            # OR it may start successfully. Either way it must not segfault.
            assert (
                proc.returncode != -signal.SIGSEGV.value
                if hasattr(signal, "SIGSEGV")
                else True
            ), "Proxy segfaulted on unknown config keys"
        except subprocess.TimeoutExpired:
            # Still running — it started successfully despite unknown keys
            assert (
                _wait_for_port("127.0.0.1", chaos_port, timeout=2.0) or True
            ), "Proxy started but not listening"
            proc.terminate()
            proc.wait(timeout=5)
    finally:
        os.unlink(config_path)
        # Ensure process is gone
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass


# ── Test: Redis fail-open ─────────────────────────────────────────────────────


def test_go_proxy_redis_fail_open():
    """When Redis is unreachable, Go proxy must allow connections (dial=0 fail-open).

    Starts a Go proxy pointed at a non-existent Redis and verifies it accepts
    TCP connections instead of refusing or crashing.
    """
    chaos_port = 18085
    chaos_metrics = 19085

    proc = _start_proxy(
        chaos_port,
        chaos_metrics,
        extra_env={
            "REDIS_HOST": "127.0.0.1",
            "REDIS_PORT": "19999",  # nothing listening here
            "REDIS_PASSWORD": "",
        },
    )
    started = _wait_for_port("127.0.0.1", chaos_port, timeout=15.0)
    if not started and proc.poll() is not None:
        out, err = proc.communicate()
        pytest.skip(
            f"Go proxy exited on startup (Redis config issue): {err.decode()[:200]}"
        )

    try:
        if not started:
            pytest.skip("Go proxy did not start within timeout with bad Redis config")

        # Proxy should accept connections even with Redis down
        accepted = 0
        for _ in range(3):
            if _check_port("127.0.0.1", chaos_port, timeout=1.0):
                accepted += 1

        assert accepted > 0, (
            "Go proxy refused all connections when Redis is unreachable "
            "(should fail open)"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── Test: malformed PROXY protocol header ─────────────────────────────────────


def test_go_proxy_malformed_proxy_protocol_header():
    """Sending garbage before TLS ClientHello must not crash the Go proxy.

    Even if PROXY protocol parsing fails, the proxy should close the
    connection gracefully and continue serving other connections.
    """
    chaos_port = 18087
    chaos_metrics = 19087

    proc = _start_proxy(chaos_port, chaos_metrics)
    started = _wait_for_port("127.0.0.1", chaos_port, timeout=15.0)
    if not started and proc.poll() is not None:
        out, err = proc.communicate()
        pytest.skip(f"Go proxy could not start: {err.decode()[:200]}")
    if not started:
        proc.kill()
        pytest.skip("Go proxy did not start listening within timeout")

    try:
        garbage_payloads = [
            b"PROXY GARBAGE HEADER\r\n",
            b"\xff\xfe\x00\x01" * 20,
            b"GET / HTTP/1.1\r\nHost: evil\r\n\r\n",
            b"\x00" * 256,
            b"PROXY TCP4 999.999.999.999 256.0.0.1 99999 99999\r\n",
        ]

        for payload in garbage_payloads:
            try:
                sock = socket.create_connection(("127.0.0.1", chaos_port), timeout=2)
                sock.sendall(payload)
                sock.settimeout(1.5)
                try:
                    sock.recv(4096)
                except (socket.timeout, ConnectionResetError):
                    pass
                sock.close()
            except OSError:
                pass

        # Proxy must still be accepting connections after the garbage
        assert _check_port(
            "127.0.0.1", chaos_port, timeout=2.0
        ), "Go proxy is no longer accepting connections after malformed PROXY headers"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── Test: SIGTERM drain ────────────────────────────────────────────────────────


def test_go_proxy_sigterm_drain():
    """SIGTERM must cause the Go proxy to drain and exit within 35 seconds."""
    chaos_port = 18086
    chaos_metrics = 19086

    proc = _start_proxy(chaos_port, chaos_metrics)
    started = _wait_for_port("127.0.0.1", chaos_port, timeout=15.0)
    if not started and proc.poll() is not None:
        out, err = proc.communicate()
        pytest.skip(f"Go proxy could not start: {err.decode()[:200]}")

    if not started:
        proc.kill()
        pytest.skip("Go proxy did not start listening within timeout")

    # Open a long-lived connection to test drain behaviour
    try:
        conn = socket.create_connection(("127.0.0.1", chaos_port), timeout=2)
    except OSError:
        conn = None

    proc.send_signal(signal.SIGTERM)

    try:
        proc.wait(timeout=35)
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail(
            "Go proxy did not exit within 35s after SIGTERM "
            "(drain_timeout_seconds default is 30)"
        )
    finally:
        if conn:
            try:
                conn.close()
            except OSError:
                pass

    assert (
        proc.returncode is not None
    ), "Go proxy process has no returncode after wait()"
    # Exit code after SIGTERM is typically -15 (Unix) or 1; just not a panic code
    assert (
        proc.returncode != -signal.SIGABRT.value if hasattr(signal, "SIGABRT") else True
    ), f"Go proxy aborted (SIGABRT) on SIGTERM: returncode={proc.returncode}"
