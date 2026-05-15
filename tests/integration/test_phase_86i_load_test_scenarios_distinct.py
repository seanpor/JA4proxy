"""Phase 86i reviewer blocker 1 — load test scenarios must drive
demonstrably different traffic.

Before the fix, ``scripts/load_test.py``'s ``run_benchmark`` ignored the
``--scenario`` argument and called the benchmark_comparison wrapper with
identical flags regardless. The reviewer flagged this as a blocker: the
four scenarios (``bypass-only``, ``full-signal``, ``attack-wave``,
``mixed``) were metadata-only and the load tests would report
indistinguishable behaviour for every scenario.

This module asserts, with subprocess mocked, that:

1. ``run_benchmark`` actually passes the scenario's fingerprint
   distribution to the underlying TLS traffic generator via
   ``--fingerprint-mix``.
2. Two different scenarios (``bypass-only`` vs ``full-signal``) produce
   two different ``--fingerprint-mix`` argument strings — proving the
   scenario is not a no-op.
3. The TLS traffic generator, when invoked with those mixes, resolves to
   two sets of ClientProfile objects with demonstrably different ALPN
   configurations (one advertises ``h2``, the other doesn't) — proving
   the distinction survives into actual TLS ClientHello bytes at the
   proxy.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LOAD_TEST_PY = REPO_ROOT / "scripts" / "load_test.py"
TLS_GEN_PY = REPO_ROOT / "scripts" / "tls-traffic-generator.py"


def _import(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def load_test_mod():
    return _import(LOAD_TEST_PY, "load_test")


@pytest.fixture()
def tls_gen_mod():
    return _import(TLS_GEN_PY, "tls_traffic_generator")


def _captured_cmd(run_benchmark, scenario: str):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_benchmark("127.0.0.1:1", duration=1, rps=1, scenario=scenario)
        assert mock_run.called, "run_benchmark must invoke subprocess.run"
        return mock_run.call_args[0][0]


class TestRunBenchmarkPassesMix:

    def test_fingerprint_mix_flag_is_present(self, load_test_mod):
        cmd = _captured_cmd(load_test_mod.run_benchmark, "bypass-only")
        assert (
            "--fingerprint-mix" in cmd
        ), "run_benchmark must pass --fingerprint-mix to the TLS generator"

    def test_bypass_only_and_full_signal_are_distinct(self, load_test_mod):
        bypass_cmd = _captured_cmd(load_test_mod.run_benchmark, "bypass-only")
        signal_cmd = _captured_cmd(load_test_mod.run_benchmark, "full-signal")
        bypass_mix = bypass_cmd[bypass_cmd.index("--fingerprint-mix") + 1]
        signal_mix = signal_cmd[signal_cmd.index("--fingerprint-mix") + 1]
        assert (
            bypass_mix != signal_mix
        ), f"bypass-only and full-signal produced identical mix: {bypass_mix!r}"
        # Sanity-check the specific distributions.
        assert "browser_alpn=100" in bypass_mix, bypass_mix
        assert "automation=100" in signal_mix, signal_mix

    def test_all_four_scenarios_are_distinct(self, load_test_mod):
        seen = {}
        for scenario in ("bypass-only", "full-signal", "attack-wave", "mixed"):
            cmd = _captured_cmd(load_test_mod.run_benchmark, scenario)
            mix = cmd[cmd.index("--fingerprint-mix") + 1]
            seen[scenario] = mix
        assert (
            len(set(seen.values())) == 4
        ), f"expected 4 distinct mix strings, got {seen}"

    def test_target_host_port_are_passed(self, load_test_mod):
        cmd = _captured_cmd(load_test_mod.run_benchmark, "bypass-only")
        assert "--target-host" in cmd
        assert "--target-port" in cmd


class TestMixParsesToDistinctProfiles:
    """The mix argument must actually produce distinct ClientProfiles so
    the proxy sees distinct ClientHello bytes."""

    def test_browser_vs_automation_have_different_alpn(self, tls_gen_mod):
        browser_mix = tls_gen_mod.parse_fingerprint_mix("browser_alpn=100")
        auto_mix = tls_gen_mod.parse_fingerprint_mix("automation=100")
        browser_profiles = tls_gen_mod.profiles_for_mix(browser_mix)
        auto_profiles = tls_gen_mod.profiles_for_mix(auto_mix)
        assert browser_profiles, "browser bucket must produce profiles"
        assert auto_profiles, "automation bucket must produce profiles"
        # Every browser profile advertises h2; no automation profile does.
        assert all(p.alpn and "h2" in p.alpn for p in browser_profiles)
        assert all(not p.alpn for p in auto_profiles), (
            f"automation profiles must not advertise ALPN, got "
            f"{[(p.name, p.alpn) for p in auto_profiles]}"
        )

    def test_parse_fingerprint_mix_validates_sum(self, tls_gen_mod):
        with pytest.raises(ValueError):
            tls_gen_mod.parse_fingerprint_mix("browser_alpn=50,automation=49")

    def test_parse_fingerprint_mix_rejects_unknown_bucket(self, tls_gen_mod):
        with pytest.raises(ValueError):
            tls_gen_mod.parse_fingerprint_mix("nope=100")

    def test_scanner_bucket_is_tls12_only(self, tls_gen_mod):
        import ssl

        profiles = tls_gen_mod.profiles_for_mix(
            tls_gen_mod.parse_fingerprint_mix("scanner=100")
        )
        assert profiles
        for p in profiles:
            assert (
                p.tls_max_version == ssl.TLSVersion.TLSv1_2
            ), f"scanner profile {p.name} must be TLS1.2 only"
