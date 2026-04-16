"""Tests for M24 — Pushgateway grouping_key in scripts/load_test.py.

TDD Tests — these define the contract. They will FAIL until the Coder
adds grouping_key to the push_to_gateway call in load_test.py.

Contract
--------
- push_to_gateway is called with grouping_key={"instance": <hostname>, "phase": <phase_name>}
- Two concurrent pushes with different instances don't overwrite each other
"""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

_LOAD_TEST_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "load_test.py"
)


@pytest.fixture(scope="module")
def load_test_module():
    """Import scripts/load_test.py via importlib."""
    spec = importlib.util.spec_from_file_location("load_test", _LOAD_TEST_PATH)
    mod = importlib.util.module_from_spec(spec)
    # We need prometheus_client to be available for the import
    spec.loader.exec_module(mod)
    return mod


# ── M24: grouping_key is passed ──────────────────────────────────────────────


class TestPushgatewayGroupingKey:
    """push_to_gateway must include grouping_key with instance and phase."""

    def test_push_includes_grouping_key(self, load_test_module):
        """push_to_gateway must be called with grouping_key containing
        'instance' and 'phase' keys."""
        mock_push = MagicMock()

        with patch.dict(sys.modules, {}), patch(
            "prometheus_client.push_to_gateway", mock_push
        ):
            # Re-patch inside the module's namespace
            # The function imports push_to_gateway lazily inside the function body,
            # so we need to patch it at the source.
            import prometheus_client

            original_push = prometheus_client.push_to_gateway
            prometheus_client.push_to_gateway = mock_push

            try:
                load_test_module.push_loadtest_metrics(
                    url="http://pushgateway:9091",
                    attempted=100,
                    completed=95,
                    errors={"timeout": 5},
                    latencies_seconds=[0.01, 0.02, 0.03],
                    throughput_cps=50.0,
                    job="test_job",
                )
            finally:
                prometheus_client.push_to_gateway = original_push

        # Verify push_to_gateway was called
        assert mock_push.called, "push_to_gateway was not called"

        # Extract the call kwargs
        _, kwargs = mock_push.call_args
        # Could also be positional — check both
        call_args = mock_push.call_args

        # Find grouping_key in the call
        grouping_key = kwargs.get("grouping_key") or (
            call_args.args[3] if len(call_args.args) > 3 else None
        )
        assert grouping_key is not None, (
            f"push_to_gateway called without grouping_key. "
            f"args={call_args.args}, kwargs={kwargs}"
        )
        assert "instance" in grouping_key, (
            f"grouping_key missing 'instance'. Got: {grouping_key}"
        )
        assert "phase" in grouping_key, (
            f"grouping_key missing 'phase'. Got: {grouping_key}"
        )

    def test_grouping_key_instance_is_hostname(self, load_test_module):
        """The 'instance' value in grouping_key should be the machine hostname."""
        mock_push = MagicMock()

        import prometheus_client

        original_push = prometheus_client.push_to_gateway
        prometheus_client.push_to_gateway = mock_push

        try:
            load_test_module.push_loadtest_metrics(
                url="http://pushgateway:9091",
                attempted=10,
                completed=10,
                errors={},
                latencies_seconds=[0.01],
                throughput_cps=10.0,
                job="test_job",
            )
        finally:
            prometheus_client.push_to_gateway = original_push

        assert mock_push.called, "push_to_gateway was not called"
        _, kwargs = mock_push.call_args
        grouping_key = kwargs.get("grouping_key")
        assert grouping_key is not None, "push_to_gateway called without grouping_key"
        assert "instance" in grouping_key, f"grouping_key missing 'instance': {grouping_key}"
        # Instance should be a non-empty string (typically hostname)
        assert isinstance(grouping_key["instance"], str)
        assert len(grouping_key["instance"]) > 0, (
            "grouping_key instance should not be empty"
        )

    def test_different_instances_produce_different_keys(self, load_test_module):
        """Two pushes with different hostnames must produce different grouping_keys,
        ensuring they don't overwrite each other in Pushgateway."""
        calls = []
        mock_push = MagicMock(side_effect=lambda *a, **kw: calls.append(kw))

        import prometheus_client

        original_push = prometheus_client.push_to_gateway
        prometheus_client.push_to_gateway = mock_push

        try:
            # Simulate first push with hostname "node-1"
            with patch("socket.gethostname", return_value="node-1"):
                load_test_module.push_loadtest_metrics(
                    url="http://pushgateway:9091",
                    attempted=10,
                    completed=10,
                    errors={},
                    latencies_seconds=[0.01],
                    throughput_cps=10.0,
                    job="test_job",
                )

            # Simulate second push with hostname "node-2"
            with patch("socket.gethostname", return_value="node-2"):
                load_test_module.push_loadtest_metrics(
                    url="http://pushgateway:9091",
                    attempted=20,
                    completed=18,
                    errors={},
                    latencies_seconds=[0.02],
                    throughput_cps=9.0,
                    job="test_job",
                )
        finally:
            prometheus_client.push_to_gateway = original_push

        assert len(calls) == 2, f"Expected 2 push_to_gateway calls, got {len(calls)}"

        gk1 = calls[0].get("grouping_key")
        gk2 = calls[1].get("grouping_key")

        assert gk1 is not None, "First push_to_gateway call missing grouping_key"
        assert gk2 is not None, "Second push_to_gateway call missing grouping_key"
        assert "instance" in gk1, f"First call grouping_key missing 'instance': {gk1}"
        assert "instance" in gk2, f"Second call grouping_key missing 'instance': {gk2}"
        assert gk1["instance"] != gk2["instance"], (
            f"Two different hosts should produce different instance keys: "
            f"{gk1} vs {gk2}"
        )
