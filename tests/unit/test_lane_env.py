"""Phase-310: scripts/lane-env.sh assigns a collision-free, deterministic dev
lane and persists it into .env without clobbering secrets."""
import os
import re
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


def test_port_probe_does_not_silently_report_everything_free():
    """Regression: the probe must not degrade to "all free" without `ss`.

    The original `port_free` was `! ss -ltn | awk | grep -q`. Where `ss` is not
    installed — including this repo's own tools image, where the test suite
    runs — that pipeline emits nothing, grep matches nothing, and EVERY port is
    reported free. Lane selection then silently stopped detecting collisions
    while still looking like it worked.

    Asserts the fallback chain is present rather than exercising it, so the test
    is meaningful on hosts that DO have `ss`.
    """
    src = SCRIPT.read_text()
    assert "command -v ss" in src, (
        "port_free must check for `ss` rather than assuming it exists"
    )
    assert "/dev/tcp/" in src, (
        "port_free needs a probe that works with no external binary — "
        "otherwise it silently reports every port free where `ss` is absent"
    )
