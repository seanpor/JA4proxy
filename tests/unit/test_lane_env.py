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
