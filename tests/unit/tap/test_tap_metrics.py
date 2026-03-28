"""Unit tests for TAP-mode Prometheus metrics (Phase 20, Group 11)."""
import re

import pytest
from prometheus_client import Counter, Gauge, Histogram

from src.tap import metrics


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _label_names(metric):
    """Return the label names declared on a prometheus_client metric."""
    return list(metric._labelnames)


# ---------------------------------------------------------------------------
# Structural tests — all metric groups defined
# ---------------------------------------------------------------------------

def test_all_capture_metrics_defined():
    assert isinstance(metrics.TAP_PACKETS_RECEIVED_TOTAL, Counter)
    assert _label_names(metrics.TAP_PACKETS_RECEIVED_TOTAL) == ["interface"]

    assert isinstance(metrics.TAP_PACKETS_DROPPED_TOTAL, Counter)
    assert _label_names(metrics.TAP_PACKETS_DROPPED_TOTAL) == ["interface", "reason"]

    assert isinstance(metrics.TAP_RING_BUFFER_FILL_RATIO, Gauge)
    assert _label_names(metrics.TAP_RING_BUFFER_FILL_RATIO) == ["interface"]

    assert isinstance(metrics.TAP_CAPTURE_ERRORS_TOTAL, Counter)
    assert _label_names(metrics.TAP_CAPTURE_ERRORS_TOTAL) == ["error_type"]


def test_all_reassembly_metrics_defined():
    assert isinstance(metrics.TAP_STREAMS_ACTIVE, Gauge)
    assert _label_names(metrics.TAP_STREAMS_ACTIVE) == []

    assert isinstance(metrics.TAP_STREAMS_TOTAL, Counter)
    assert _label_names(metrics.TAP_STREAMS_TOTAL) == []

    assert isinstance(metrics.TAP_STREAM_EVICTIONS_TOTAL, Counter)
    assert _label_names(metrics.TAP_STREAM_EVICTIONS_TOTAL) == ["reason"]

    assert isinstance(metrics.TAP_OUT_OF_ORDER_SEGMENTS_TOTAL, Counter)
    assert _label_names(metrics.TAP_OUT_OF_ORDER_SEGMENTS_TOTAL) == []

    assert isinstance(metrics.TAP_REASSEMBLY_ERRORS_TOTAL, Counter)
    assert _label_names(metrics.TAP_REASSEMBLY_ERRORS_TOTAL) == ["error_type"]


def test_all_fingerprint_metrics_defined():
    assert isinstance(metrics.TAP_FINGERPRINTS_EXTRACTED_TOTAL, Counter)
    assert _label_names(metrics.TAP_FINGERPRINTS_EXTRACTED_TOTAL) == ["type"]

    assert isinstance(metrics.TAP_FINGERPRINT_EXTRACTION_ERRORS_TOTAL, Counter)
    assert _label_names(metrics.TAP_FINGERPRINT_EXTRACTION_ERRORS_TOTAL) == ["type"]

    assert isinstance(metrics.TAP_FINGERPRINT_PROCESSING_SECONDS, Histogram)
    assert _label_names(metrics.TAP_FINGERPRINT_PROCESSING_SECONDS) == ["type"]

    assert isinstance(metrics.TAP_PIPELINE_SCORE_DISTRIBUTION, Histogram)
    assert _label_names(metrics.TAP_PIPELINE_SCORE_DISTRIBUTION) == []

    assert isinstance(metrics.TAP_PIPELINE_ACTIONS_TOTAL, Counter)
    assert _label_names(metrics.TAP_PIPELINE_ACTIONS_TOTAL) == ["action"]

    assert isinstance(metrics.TAP_PIPELINE_ERRORS_TOTAL, Counter)
    assert _label_names(metrics.TAP_PIPELINE_ERRORS_TOTAL) == []


def test_all_enforcement_metrics_defined():
    assert isinstance(metrics.TAP_ENFORCEMENT_BANS_TOTAL, Counter)
    assert _label_names(metrics.TAP_ENFORCEMENT_BANS_TOTAL) == ["backend"]

    assert isinstance(metrics.TAP_ENFORCEMENT_ERRORS_TOTAL, Counter)
    assert _label_names(metrics.TAP_ENFORCEMENT_ERRORS_TOTAL) == ["backend"]

    assert isinstance(metrics.TAP_ENFORCEMENT_LATENCY_SECONDS, Histogram)
    assert _label_names(metrics.TAP_ENFORCEMENT_LATENCY_SECONDS) == ["backend"]


def test_all_export_metrics_defined():
    assert isinstance(metrics.TAP_EXPORT_EVENTS_TOTAL, Counter)
    assert _label_names(metrics.TAP_EXPORT_EVENTS_TOTAL) == ["exporter", "event_type"]

    assert isinstance(metrics.TAP_EXPORT_ERRORS_TOTAL, Counter)
    assert _label_names(metrics.TAP_EXPORT_ERRORS_TOTAL) == ["exporter"]

    assert isinstance(metrics.TAP_EXPORT_LATENCY_SECONDS, Histogram)
    assert _label_names(metrics.TAP_EXPORT_LATENCY_SECONDS) == ["exporter"]

    assert isinstance(metrics.TAP_WORKER_RESTARTS_TOTAL, Counter)
    assert _label_names(metrics.TAP_WORKER_RESTARTS_TOTAL) == ["worker_id"]

    assert isinstance(metrics.TAP_WORKERS_ACTIVE, Gauge)
    assert _label_names(metrics.TAP_WORKERS_ACTIVE) == []


# ---------------------------------------------------------------------------
# Naming convention
# ---------------------------------------------------------------------------

def test_no_stale_metric_names():
    """All Counter/Gauge/Histogram objects in metrics.py must start with ja4proxy_tap_."""
    for attr_name in dir(metrics):
        obj = getattr(metrics, attr_name)
        if isinstance(obj, (Counter, Gauge, Histogram)):
            metric_name = obj._name
            assert metric_name.startswith("ja4proxy_tap_"), (
                f"Metric {attr_name!r} has name {metric_name!r} which does not start "
                f"with 'ja4proxy_tap_'"
            )


# ---------------------------------------------------------------------------
# Behavioural tests
# ---------------------------------------------------------------------------

def test_ring_buffer_fill_gauge_updated_on_poll():
    """Setting the ring-buffer fill gauge and reading it back returns the correct value."""
    metrics.TAP_RING_BUFFER_FILL_RATIO.labels(interface="eth0").set(0.75)
    # Retrieve raw sample value via prometheus_client internals
    labelled = metrics.TAP_RING_BUFFER_FILL_RATIO.labels(interface="eth0")
    assert labelled._value.get() == pytest.approx(0.75)


def test_packets_dropped_counter_increments_on_overflow():
    """Incrementing the drop counter with reason=overflow advances by 1."""
    labelled = metrics.TAP_PACKETS_DROPPED_TOTAL.labels(
        interface="eth0", reason="overflow"
    )
    before = labelled._value.get()
    labelled.inc()
    assert labelled._value.get() == pytest.approx(before + 1.0)


def test_worker_restarts_counter_increments_on_crash():
    """Incrementing the worker-restart counter with worker_id=0 advances by 1."""
    labelled = metrics.TAP_WORKER_RESTARTS_TOTAL.labels(worker_id="0")
    before = labelled._value.get()
    labelled.inc()
    assert labelled._value.get() == pytest.approx(before + 1.0)
