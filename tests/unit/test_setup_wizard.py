"""Phase-231b: unit tests for the single-host setup wizard.

Focus on the security-critical guarantees — strong, unique, never-echoed secrets
and a 0600 .env — plus input validation and the corrected port scheme.
"""
import importlib.util
import os
import stat
from pathlib import Path

# Load scripts/setup_wizard.py as a module (it lives outside the package tree).
_WIZ = Path(__file__).resolve().parents[2] / "scripts" / "setup_wizard.py"
_spec = importlib.util.spec_from_file_location("setup_wizard", _WIZ)
wiz = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wiz)


def test_secrets_strong_and_unique():
    pws = {wiz.gen_password() for _ in range(50)}
    assert len(pws) == 50, "passwords must be unique"
    assert all(len(p) >= 24 for p in pws)
    assert len(wiz.gen_hex_key()) == 64  # 32 bytes hex
    s = wiz.generate_secrets()
    assert set(s) == wiz.SECRET_KEYS
    assert len(set(s.values())) == len(s), "every secret distinct"
    assert all("REPLACE" not in v for v in s.values())


def test_validators():
    assert wiz.valid_hostname("backend")
    assert wiz.valid_hostname("api.example.com")
    assert wiz.valid_hostname("10.0.0.5")
    assert not wiz.valid_hostname("")
    assert not wiz.valid_hostname("bad host!")
    assert wiz.valid_port("443") and wiz.valid_port("8090")
    assert not wiz.valid_port("0") and not wiz.valid_port("70000") and not wiz.valid_port("x")
    assert wiz.valid_bind_ip("127.0.0.1") and not wiz.valid_bind_ip("not-an-ip")
    assert not wiz.valid_cert_path("/no/such/cert.pem")


def test_build_env_uses_real_port_scheme():
    env = wiz.build_env({"backend_host": "web", "backend_port": "8443"})
    assert env["HOST_PORT_MANAGEMENT"] == "8090"  # not the proposal's invented 8113
    assert env["HOST_PORT_METRICS"] == "9090"
    assert env["HOST_PORT_PROMETHEUS"] == "9091"
    assert env["HOST_PORT_GRAFANA"] == "3000"
    assert "8113" not in env.values() and "3023" not in env.values()
    assert env["BACKEND_HOST"] == "web" and env["BACKEND_PORT"] == "8443"
    for k in wiz.SECRET_KEYS:
        assert env[k] and "REPLACE" not in env[k]


def test_port_override_respected():
    env = wiz.build_env({"HOST_PORT_MANAGEMENT": "18090"})
    assert env["HOST_PORT_MANAGEMENT"] == "18090"  # not locked down
    env2 = wiz.build_env({"HOST_PORT_MANAGEMENT": "garbage"})
    assert env2["HOST_PORT_MANAGEMENT"] == "8090"  # invalid override ignored


def test_write_env_is_chmod_600(tmp_path):
    env = wiz.build_env({})
    p = tmp_path / ".env"
    wiz.write_env(p, env, timestamp="2026-06-11")
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600, "mode = %o, want 600" % mode
    assert "BACKEND_HOST=" in p.read_text()


def test_no_secret_is_ever_echoed():
    env = wiz.build_env({})
    summary = wiz.redacted_summary(env)
    for k in wiz.SECRET_KEYS:
        assert env[k] not in summary, "secret %s leaked into the summary" % k
        assert ("%s = [generated" % k) in summary
    # non-secret values are shown
    assert "HOST_PORT_MANAGEMENT = 8090" in summary


def test_collect_answers_injectable():
    answers_iter = iter(["web.local", "8443", "native", "127.0.0.1", "operator"])
    a = wiz.collect_answers(input_fn=lambda _prompt: next(answers_iter), getpass_fn=lambda _p: "")
    assert a["topology"] == "inline"
    assert a["backend_host"] == "web.local" and a["backend_port"] == "8443"
    assert a["mode"] == "native" and a["admin_user"] == "operator"
    assert "_admin_password_override" not in a  # blank password => generate


def test_collect_answers_password_not_in_returned_summary():
    answers_iter = iter(["web", "443", "container", "127.0.0.1", "admin"])
    a = wiz.collect_answers(input_fn=lambda _p: next(answers_iter), getpass_fn=lambda _p: "s3cret-typed")
    assert a["_admin_password_override"] == "s3cret-typed"
    env = wiz.build_env(a)
    env["MANAGEMENT_ADMIN_PASSWORD"] = a["_admin_password_override"]
    # The typed password must not appear in the redacted summary.
    assert "s3cret-typed" not in wiz.redacted_summary(env)


def test_systemd_unit_variants():
    native = wiz.build_systemd_unit("/opt/ja4proxy", "native")
    assert "bin/ja4pd" in native and "Type=simple" in native and "NoNewPrivileges=true" in native
    container = wiz.build_systemd_unit("/opt/ja4proxy", "container")
    assert "docker compose" in container and "down -t 30" in container
