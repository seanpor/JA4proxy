"""Tests for config/integrations/vector-interlink.yaml.

Validates that the Vector sidecar configuration for Interlink Service Watch:
  - Is valid YAML
  - Uses 'stdin' source (Docker pattern, not 'journald' systemd pattern)
  - Uses to_int() for CEF severity (integer 0–10, not a raw string)
  - Has TLS enabled on the sink
  - Uses syslog port 6514

Per Phase 81 §7.2 spec.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


# ---------------------------------------------------------------------------
# Path to the config file under test
# ---------------------------------------------------------------------------

CONFIG_PATH = (
    Path(__file__).parent.parent.parent
    / "config"
    / "integrations"
    / "vector-interlink.yaml"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def config() -> dict:
    """Load and parse the vector-interlink.yaml config file.

    Raises FileNotFoundError if the file doesn't exist (test fails — expected
    until Phase 81 implementation creates the file).
    """
    if not CONFIG_PATH.exists():
        pytest.fail(
            f"Config file not found: {CONFIG_PATH}\n"
            "Phase 81 implementation must create config/integrations/vector-interlink.yaml"
        )
    with open(CONFIG_PATH) as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def config_raw() -> str:
    """Return the raw YAML text for VRL source inspection."""
    if not CONFIG_PATH.exists():
        pytest.fail(f"Config file not found: {CONFIG_PATH}")
    return CONFIG_PATH.read_text()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestVectorInterlinkConfig:

    def test_interlink_config_is_valid_yaml(self):
        """File loads without YAML parse error."""
        if not CONFIG_PATH.exists():
            pytest.fail(
                f"Config file not found: {CONFIG_PATH}\n"
                "Phase 81 implementation must create this file."
            )
        with open(CONFIG_PATH) as fh:
            parsed = yaml.safe_load(fh)

        assert parsed is not None, "YAML file parsed to None — it may be empty"
        assert isinstance(parsed, dict), (
            f"Expected a YAML mapping at top level, got {type(parsed).__name__}"
        )

    def test_interlink_config_source_is_stdin(self, config: dict):
        """Source type must be 'stdin' (Docker pattern, not 'journald').

        Per Phase 81 §7.2: 'stdin' is the correct choice for Docker/container
        deployments. 'journald' is only for bare-metal systemd deployments.
        """
        sources = config.get("sources", {})
        assert sources, "No 'sources' section found in vector-interlink.yaml"

        # Find the JA4proxy log source (first source entry)
        source_names = list(sources.keys())
        assert source_names, "sources section is empty"

        # At least one source must be of type stdin
        source_types = [sources[name].get("type") for name in source_names]
        assert "stdin" in source_types, (
            f"Expected at least one source of type 'stdin' (Docker deployment pattern). "
            f"Found source types: {source_types}. "
            f"'journald' is only for bare-metal systemd deployments — not Docker."
        )

    def test_interlink_cef_severity_is_integer(self, config_raw: str):
        """VRL transform must use to_int() for CEF severity (integer 0–10).

        Phase 81 §7.2 spec: 'CEF severity must be an integer 0–10.
        risk_score is 0-100; divide by 10 and round to nearest integer.'

        The VRL source must contain 'to_int' to convert the float result
        to a proper integer — not just a string conversion.
        """
        assert "to_int" in config_raw, (
            "VRL transform must use 'to_int' to produce an integer CEF severity. "
            "A raw string conversion (e.g. string!(risk_score / 10)) produces "
            "a float string like '7.0', not an integer like '7'. "
            "CEF severity must be an integer 0-10."
        )

    def test_interlink_sink_uses_tls(self, config: dict):
        """Sink must have TLS enabled (syslog to Interlink is TLS-encrypted)."""
        sinks = config.get("sinks", {})
        assert sinks, "No 'sinks' section found in vector-interlink.yaml"

        # Find a socket-type sink
        socket_sinks = {
            name: sink
            for name, sink in sinks.items()
            if sink.get("type") == "socket"
        }
        assert socket_sinks, (
            f"Expected a sink of type 'socket' for syslog output, found sinks: "
            f"{list(sinks.keys())}"
        )

        # All socket sinks must have TLS enabled
        for sink_name, sink_cfg in socket_sinks.items():
            tls_section = sink_cfg.get("tls", {})
            tls_enabled = tls_section.get("enabled", False)
            assert tls_enabled is True, (
                f"Sink '{sink_name}' must have tls.enabled: true. "
                f"Syslog to Interlink Service Watch must be TLS-encrypted. "
                f"Current tls config: {tls_section!r}"
            )

    def test_interlink_sink_port_is_6514(self, config: dict):
        """Socket sink address must contain ':6514' (TLS syslog port).

        Per Phase 81 §7.2 spec: address contains ':6514'.
        """
        sinks = config.get("sinks", {})
        socket_sinks = {
            name: sink
            for name, sink in sinks.items()
            if sink.get("type") == "socket"
        }
        assert socket_sinks, (
            "No socket-type sinks found — cannot check port. "
            "Expected a socket sink with address containing ':6514'."
        )

        for sink_name, sink_cfg in socket_sinks.items():
            address = sink_cfg.get("address", "")
            assert ":6514" in address, (
                f"Sink '{sink_name}' address {address!r} does not contain ':6514'. "
                f"Interlink Service Watch uses TLS syslog on port 6514."
            )
