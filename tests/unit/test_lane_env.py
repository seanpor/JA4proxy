"""Phase-310: scripts/lane-env.sh assigns a collision-free, deterministic dev
lane and persists it into .env without clobbering secrets."""
import os
import re
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "lane-env.sh"

BASES = {
    "HOST_PORT_DIRECT": 8081,
    "HOST_PORT_METRICS": 9090,
    "HOST_PORT_GRAFANA": 3000,
    "HOST_PORT_MANAGEMENT": 8090,
    "HOST_PORT_PROMETHEUS": 9091,
}


def _run(cwd, env=None):
    e = {**os.environ, **(env or {})}
    return subprocess.run(["bash", str(SCRIPT)], cwd=cwd, env=e,
                          capture_output=True, text=True, check=True)


def _envmap(p: Path) -> dict:
    out = {}
    for line in p.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _mk_worktree(tmp_path) -> Path:
    wt = tmp_path / "checkout"
    wt.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=wt, check=True)
    (wt / ".env").write_text("REDIS_PASSWORD=secret123\nGRAFANA_PASSWORD=gpw\n")
    return wt


def test_assigns_lane_and_offsets_ports(tmp_path):
    wt = _mk_worktree(tmp_path)
    _run(wt)
    env = _envmap(wt / ".env")
    assert "JA4_LANE" in env
    lane = int(env["JA4_LANE"])
    assert 0 <= lane < 40
    assert env["COMPOSE_PROJECT_NAME"] == f"ja4proxy-lane{lane}"
    for var, base in BASES.items():
        assert int(env[var]) == base + lane * 100, var


def test_preserves_existing_secrets(tmp_path):
    wt = _mk_worktree(tmp_path)
    _run(wt)
    env = _envmap(wt / ".env")
    assert env["REDIS_PASSWORD"] == "secret123"
    assert env["GRAFANA_PASSWORD"] == "gpw"


def test_idempotent_same_lane(tmp_path):
    wt = _mk_worktree(tmp_path)
    _run(wt)
    first = _envmap(wt / ".env")["JA4_LANE"]
    _run(wt)
    assert _envmap(wt / ".env")["JA4_LANE"] == first


def test_deterministic_per_worktree(tmp_path):
    """Same worktree path → same lane (derivation is path-hash based)."""
    wt = _mk_worktree(tmp_path)
    _run(wt)
    lane1 = _envmap(wt / ".env")["JA4_LANE"]
    (wt / ".env").write_text("REDIS_PASSWORD=secret123\n")  # wipe the pin
    _run(wt, env={"JA4_LANE_REASSIGN": "1"})
    assert _envmap(wt / ".env")["JA4_LANE"] == lane1


def test_lane_ports_never_self_collide():
    """Within any lane, the five published ports are distinct."""
    for lane in range(40):
        ports = {base + lane * 100 for base in BASES.values()}
        assert len(ports) == len(BASES), f"lane {lane} self-collision"


# ── Pinned-lane port-collision warning ───────────────────────────────────────
#
# Probing is what picks a lane, and pinning deliberately skips it so the lane —
# and therefore COMPOSE_PROJECT_NAME and every named volume — stays stable
# across restarts. But a lane pinned while its ports were free can later
# collide when something else on the host claims one (observed: an unrelated
# container holding :3000, which is lane 0's Grafana). Nothing warned, and the
# first sign was `docker compose up` failing with EADDRINUSE.
#
# The fix is to CHECK on the pinned path but never reassign: reassigning would
# silently strand the existing lane's volumes and break a running stack.


def _listener(port: int):
    """Hold a real listening socket so lane-env's `ss` probe sees it."""
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    return s


def _pin(wt: Path, lane: int) -> None:
    (wt / ".env").write_text(
        f"REDIS_PASSWORD=secret123\nJA4_LANE={lane}\n"
        f"COMPOSE_PROJECT_NAME=ja4proxy-lane{lane}\n"
    )


def test_pinned_lane_warns_when_a_port_is_taken(tmp_path):
    wt = _mk_worktree(tmp_path)
    _run(wt)
    lane = int(_envmap(wt / ".env")["JA4_LANE"])
    victim = BASES["HOST_PORT_GRAFANA"] + lane * 100

    sock = _listener(victim)
    try:
        result = _run(wt)
    finally:
        sock.close()

    assert "WARNING" in result.stderr, (
        f"no warning when pinned lane {lane}'s port {victim} was occupied.\n"
        f"stderr={result.stderr!r}"
    )
    assert str(victim) in result.stderr, "warning must name the offending port"
    assert "HOST_PORT_GRAFANA" in result.stderr, "warning must name the variable"


def test_pinned_lane_does_not_reassign_on_collision(tmp_path):
    """The lane must stay pinned — reassigning would strand named volumes."""
    wt = _mk_worktree(tmp_path)
    _run(wt)
    lane = int(_envmap(wt / ".env")["JA4_LANE"])

    sock = _listener(BASES["HOST_PORT_GRAFANA"] + lane * 100)
    try:
        _run(wt)
    finally:
        sock.close()

    env = _envmap(wt / ".env")
    assert int(env["JA4_LANE"]) == lane, "collision must not trigger reassignment"
    assert env["COMPOSE_PROJECT_NAME"] == f"ja4proxy-lane{lane}"


def test_pinned_lane_collision_is_a_warning_not_an_error(tmp_path):
    """Must not break automation: warn on stderr, still exit 0."""
    wt = _mk_worktree(tmp_path)
    _run(wt)
    lane = int(_envmap(wt / ".env")["JA4_LANE"])

    sock = _listener(BASES["HOST_PORT_METRICS"] + lane * 100)
    try:
        # _run uses check=True, so a non-zero exit raises here.
        result = _run(wt)
    finally:
        sock.close()
    assert result.returncode == 0


def test_no_warning_when_pinned_lane_ports_are_free(tmp_path):
    """No false alarms — the common case must stay quiet."""
    wt = _mk_worktree(tmp_path)
    _run(wt)
    result = _run(wt)
    assert "WARNING" not in result.stderr, (
        f"spurious collision warning: {result.stderr!r}"
    )


def test_port_probe_does_not_silently_report_everything_free(tmp_path):
    """Regression: the probe must not degrade to "all free" without `ss`.

    The original `port_free` was `! ss -ltn | awk | grep -q`. Where `ss` is not
    installed the pipeline emits nothing, grep matches nothing, and EVERY port
    is reported free — lane selection silently stopped detecting collisions
    while still looking like it worked.

    This EXERCISES the fallback rather than grepping for it. An earlier version
    of this test asserted `"command -v ss" in src`, which would pass for
    `port_free() { return 0; }` with the string in a comment — the same
    unfalsifiable-assertion class this project has been bitten by before.
    """
    import socket

    # A PATH containing the tools the probe needs but NEITHER ss NOR netstat,
    # which forces the /dev/tcp branch. Symlinks rather than an empty dir —
    # an empty PATH hides `bash` itself.
    shim = tmp_path / "bin"
    shim.mkdir()
    for tool in ("bash", "timeout", "awk", "grep", "sed"):
        real = shutil.which(tool)
        if real:
            (shim / tool).symlink_to(real)
    assert shutil.which("ss", path=str(shim)) is None, "shim must not expose ss"
    assert shutil.which("netstat", path=str(shim)) is None
    probe = tmp_path / "probe.sh"
    probe.write_text(
        "#!/usr/bin/env bash\n"
        "set -uo pipefail\n"
        + _extract_port_free()
        + '\nport_free "$1" && echo FREE || echo BUSY\n'
    )
    probe.chmod(0o755)

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    busy_port = sock.getsockname()[1]
    try:
        env = {**os.environ, "PATH": str(shim)}  # no ss, no netstat
        got_busy = subprocess.run(
            ["bash", str(probe), str(busy_port)],
            capture_output=True, text=True, env=env, timeout=30,
        ).stdout.strip()
    finally:
        sock.close()

    free_port = _pick_closed_port()
    got_free = subprocess.run(
        ["bash", str(probe), str(free_port)],
        capture_output=True, text=True,
        env={**os.environ, "PATH": str(shim)}, timeout=30,
    ).stdout.strip()

    assert got_busy == "BUSY", (
        f"fallback probe reported port {busy_port} FREE while a listener was "
        "bound to it — this is the silent-degradation bug returning"
    )
    assert got_free == "FREE", f"fallback probe reported closed port {free_port} busy"


def _pick_closed_port() -> int:
    """A port nothing is listening on."""
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _extract_port_free() -> str:
    """Lift PROBE selection + port_free out of lane-env.sh so we run the real code."""
    src = SCRIPT.read_text(encoding="utf-8")
    start = src.index("if command -v ss >/dev/null 2>&1;")
    end = src.index("lane_ports_free()")
    return src[start:end]


def test_probe_has_a_timeout_on_the_connect_path():
    """A DROP rule would otherwise stall on SYN retries (~127s) per port."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "timeout 1 bash -c" in src, (
        "the /dev/tcp probe needs a timeout — without one a firewalled port "
        "stalls lane-env for the kernel's full SYN-retry budget, and the "
        "derivation path issues up to 240 probes"
    )


def test_probe_honours_agent_bind_ip():
    """Ports are published on AGENT_BIND_IP, so the probe must check there."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "PROBE_BIND=" in src and "AGENT_BIND_IP" in src, (
        "the connect probe hardcoded 127.0.0.1 while compose publishes on "
        "${AGENT_BIND_IP}"
    )


def test_warning_is_suppressed_when_our_own_lane_is_running():
    """The cry-wolf guard: our own stack holding its ports is not a collision.

    scripts/start-poc.sh runs lane-env.sh before every `compose up`, and
    `make open` depends on it. Warning whenever this lane's own containers hold
    its ports would fire on every restart — and the remedy it suggests
    (JA4_LANE_REASSIGN=1) strands that stack's volumes.
    """
    src = SCRIPT.read_text(encoding="utf-8")
    assert "lane_stack_is_up" in src, "no own-stack guard before the warning"
    assert "if ! lane_stack_is_up" in src, (
        "the busy-port scan must be skipped when this lane's own stack is up"
    )
