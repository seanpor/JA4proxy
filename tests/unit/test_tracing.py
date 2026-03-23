"""
tests/unit/test_tracing.py
Phase 16j — OpenTelemetry distributed tracing tests.

Covers:
- Noop path: tracing disabled → zero overhead, no OTEL imports needed
- Noop tracer: start_as_current_span() returns context manager; set_attribute() safe
- init_tracing_from_config: reads config; disabled by default
- OTEL unavailable: endpoint set but OTEL missing → warning logged
- OTEL available (mocked): spans emitted with correct attributes
- Pipeline integration: process() emits span with client.ip, ja4, action, risk.score
"""

import asyncio
import sys
import unittest
from contextlib import contextmanager
from typing import Any, Generator
from unittest.mock import MagicMock, patch

from src.security.models import ConnectionContext
from src.security.pipeline import Pipeline
from src.telemetry.tracing import Tracing, _NoopSpan, _NoopTracer, init_tracing_from_config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_minimal_pipeline(tracing: Any = None) -> Pipeline:
    config: dict = {"security_policy": {}, "static_allowlist": {"ips": []}}
    cache = MagicMock()
    cache.dial = 0
    cache.analytics_signals = MagicMock()
    cache.analytics_signals.get.return_value = None
    pipeline = Pipeline(config, cache, MagicMock(), tracing=tracing)
    scorer = MagicMock()
    scorer.score = MagicMock(
        side_effect=lambda sigs: MagicMock(
            total_score=sum(getattr(s, "score", 0) for s in sigs), signals=sigs
        )
    )
    decider = MagicMock()
    decider.decide = MagicMock(return_value="allow")
    decider.counterfactuals = MagicMock(return_value={})
    pipeline.update_scorer(scorer, decider)
    return pipeline


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Test: _NoopSpan and _NoopTracer
# ---------------------------------------------------------------------------


class TestNoopSpan(unittest.TestCase):
    """_NoopSpan must be safe to use in all contexts."""

    def test_noop_span_is_context_manager(self):
        """_NoopSpan works as a context manager."""
        with _NoopSpan() as span:
            self.assertIsInstance(span, _NoopSpan)

    def test_noop_span_set_attribute_is_safe(self):
        """set_attribute() accepts any key/value without error."""
        span = _NoopSpan()
        span.set_attribute("client.ip", "1.2.3.4")
        span.set_attribute("risk.score", 42)
        span.set_attribute("ja4", "t13d...")

    def test_noop_span_add_event_is_safe(self):
        """add_event() is a no-op."""
        span = _NoopSpan()
        span.add_event("pipeline.start")
        span.add_event("pipeline.end", {"key": "value"})

    def test_noop_span_record_exception_is_safe(self):
        """record_exception() is a no-op."""
        span = _NoopSpan()
        span.record_exception(ValueError("test"))


class TestNoopTracer(unittest.TestCase):
    """_NoopTracer must return _NoopSpan context managers."""

    def test_start_as_current_span_returns_noop_span(self):
        """start_as_current_span() yields a _NoopSpan."""
        tracer = _NoopTracer()
        with tracer.start_as_current_span("test.operation") as span:
            self.assertIsInstance(span, _NoopSpan)

    def test_start_as_current_span_accepts_kwargs(self):
        """start_as_current_span() accepts arbitrary kwargs (compatibility)."""
        tracer = _NoopTracer()
        with tracer.start_as_current_span("op", kind="client", attributes={"k": "v"}) as span:
            span.set_attribute("extra", True)

    def test_noop_tracer_is_reusable(self):
        """Multiple spans can be opened sequentially without error."""
        tracer = _NoopTracer()
        for i in range(5):
            with tracer.start_as_current_span(f"span_{i}") as span:
                span.set_attribute("idx", i)


# ---------------------------------------------------------------------------
# Test: Tracing class (noop mode)
# ---------------------------------------------------------------------------


class TestTracingNoopMode(unittest.TestCase):
    """Tracing with endpoint=None → noop, no OTEL interaction."""

    def test_disabled_is_not_enabled(self):
        """Tracing(endpoint=None).is_enabled() returns False."""
        t = Tracing(endpoint=None)
        self.assertFalse(t.is_enabled())

    def test_disabled_get_tracer_returns_noop(self):
        """get_tracer() returns _NoopTracer when disabled."""
        t = Tracing(endpoint=None)
        tracer = t.get_tracer()
        self.assertIsInstance(tracer, _NoopTracer)

    def test_disabled_noop_tracer_works(self):
        """Noop tracer from disabled Tracing instance is functional."""
        t = Tracing(endpoint=None)
        tracer = t.get_tracer("test")
        with tracer.start_as_current_span("op") as span:
            span.set_attribute("ip", "1.2.3.4")

    def test_endpoint_empty_string_is_noop(self):
        """Empty string endpoint → noop (not enabled)."""
        t = Tracing(endpoint="")
        self.assertFalse(t.is_enabled())


# ---------------------------------------------------------------------------
# Test: Tracing — OTEL unavailable warning
# ---------------------------------------------------------------------------


class TestTracingOTELUnavailable(unittest.TestCase):
    """Tracing logs WARNING when endpoint is set but OTEL not installed."""

    def test_endpoint_set_otel_unavailable_logs_warning(self):
        """Setting endpoint when OTEL unavailable → WARNING logged."""
        with patch("src.telemetry.tracing.OTEL_AVAILABLE", False):
            with self.assertLogs("src.telemetry.tracing", level="WARNING") as cm:
                t = Tracing(endpoint="http://jaeger:4317")
            self.assertFalse(t.is_enabled())
            self.assertTrue(
                any("otel_not_available" in line for line in cm.output)
            )


# ---------------------------------------------------------------------------
# Test: Tracing — OTEL available (mocked)
# ---------------------------------------------------------------------------


class _MockSpanExporter:
    """Simple in-memory span exporter for testing."""

    def __init__(self):
        self.spans: list = []

    def export(self, spans) -> int:
        self.spans.extend(spans)
        return 0  # SUCCESS

    def shutdown(self) -> None:
        pass


class _MockSpan:
    """Tracks set_attribute calls for assertion."""

    def __init__(self, name: str):
        self.name = name
        self.attributes: dict = {}
        self.events: list = []
        self.exceptions: list = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key: str, value: Any):
        self.attributes[key] = value

    def add_event(self, name: str, attributes=None):
        self.events.append(name)

    def record_exception(self, exc: Exception):
        self.exceptions.append(exc)


class _MockOtelTracer:
    """Records spans and attributes."""

    def __init__(self):
        self.started_spans: list[_MockSpan] = []

    @contextmanager
    def start_as_current_span(
        self, name: str, **kwargs
    ) -> Generator[_MockSpan, None, None]:
        span = _MockSpan(name)
        self.started_spans.append(span)
        yield span


class _MockTracing:
    """Tracing that injects a _MockOtelTracer."""

    def __init__(self):
        self._tracer = _MockOtelTracer()

    def is_enabled(self) -> bool:
        return True

    def get_tracer(self, name: str = "ja4proxy") -> _MockOtelTracer:
        return self._tracer


class TestTracingWithMockedOTEL(unittest.TestCase):
    """Tracing with OTEL SDK mocked — verifies span creation path."""

    def setUp(self):
        """Set up mocked OTEL SDK."""
        self.mock_provider = MagicMock()
        self.mock_trace_module = MagicMock()
        self.mock_trace_module.get_tracer.return_value = _MockOtelTracer()
        self.mock_trace_module.set_tracer_provider = MagicMock()

        self.mock_resource = MagicMock()
        self.mock_resource_cls = MagicMock(return_value=self.mock_resource)

        self.mock_tracer_provider_cls = MagicMock(return_value=self.mock_provider)
        self.mock_batch_processor = MagicMock()
        self.mock_batch_processor_cls = MagicMock(return_value=self.mock_batch_processor)
        self.mock_exporter = MagicMock()
        self.mock_exporter_cls = MagicMock(return_value=self.mock_exporter)

    def test_is_enabled_true_when_otel_available_and_endpoint_set(self):
        """is_enabled() returns True after successful init."""
        with (
            patch("src.telemetry.tracing.OTEL_AVAILABLE", True),
            patch("src.telemetry.tracing.trace", self.mock_trace_module),
            patch("src.telemetry.tracing.TracerProvider", self.mock_tracer_provider_cls),
            patch("src.telemetry.tracing.Resource", self.mock_resource_cls),
            patch("src.telemetry.tracing.BatchSpanProcessor", self.mock_batch_processor_cls),
            patch("src.telemetry.tracing.OTLPSpanExporter", self.mock_exporter_cls),
        ):
            t = Tracing(endpoint="http://jaeger:4317", service_name="test-svc")
            # is_enabled() must be checked inside the patch context
            self.assertTrue(t.is_enabled())

    def test_initialization_creates_provider_with_service_name(self):
        """TracerProvider and Resource.create() called with correct service name."""
        with (
            patch("src.telemetry.tracing.OTEL_AVAILABLE", True),
            patch("src.telemetry.tracing.trace", self.mock_trace_module),
            patch("src.telemetry.tracing.TracerProvider", self.mock_tracer_provider_cls),
            patch("src.telemetry.tracing.Resource", self.mock_resource_cls),
            patch("src.telemetry.tracing.BatchSpanProcessor", self.mock_batch_processor_cls),
            patch("src.telemetry.tracing.OTLPSpanExporter", self.mock_exporter_cls),
        ):
            Tracing(endpoint="http://collector:4317", service_name="my-proxy")
        # tracing.py calls Resource.create({"service.name": ...}), not Resource(...)
        self.mock_resource_cls.create.assert_called_once_with({"service.name": "my-proxy"})
        self.mock_tracer_provider_cls.assert_called_once()

    def test_get_tracer_returns_real_tracer_when_enabled(self):
        """get_tracer() delegates to OTEL trace.get_tracer() when enabled."""
        with (
            patch("src.telemetry.tracing.OTEL_AVAILABLE", True),
            patch("src.telemetry.tracing.trace", self.mock_trace_module),
            patch("src.telemetry.tracing.TracerProvider", self.mock_tracer_provider_cls),
            patch("src.telemetry.tracing.Resource", self.mock_resource_cls),
            patch("src.telemetry.tracing.BatchSpanProcessor", self.mock_batch_processor_cls),
            patch("src.telemetry.tracing.OTLPSpanExporter", self.mock_exporter_cls),
        ):
            t = Tracing(endpoint="http://jaeger:4317")
            t.get_tracer("my-service")
        self.mock_trace_module.get_tracer.assert_called_with("my-service")

    def test_init_exception_logs_warning_uses_noop(self):
        """Exception during init → WARNING logged; is_enabled() returns False."""
        failing_provider = MagicMock(side_effect=RuntimeError("init failed"))
        with (
            patch("src.telemetry.tracing.OTEL_AVAILABLE", True),
            patch("src.telemetry.tracing.trace", self.mock_trace_module),
            patch("src.telemetry.tracing.TracerProvider", failing_provider),
            patch("src.telemetry.tracing.Resource", self.mock_resource_cls),
            patch("src.telemetry.tracing.BatchSpanProcessor", self.mock_batch_processor_cls),
            patch("src.telemetry.tracing.OTLPSpanExporter", self.mock_exporter_cls),
        ):
            with self.assertLogs("src.telemetry.tracing", level="WARNING") as cm:
                t = Tracing(endpoint="http://jaeger:4317")
        self.assertFalse(t.is_enabled())
        self.assertTrue(any("init_failed" in line for line in cm.output))


# ---------------------------------------------------------------------------
# Test: init_tracing_from_config
# ---------------------------------------------------------------------------


class TestInitTracingFromConfig(unittest.TestCase):
    """init_tracing_from_config reads config dict."""

    def test_disabled_by_default(self):
        """Empty config → tracing disabled (noop)."""
        t = init_tracing_from_config({})
        self.assertFalse(t.is_enabled())

    def test_enabled_false_is_noop(self):
        """telemetry.tracing.enabled=false → noop."""
        config = {"telemetry": {"tracing": {"enabled": False, "endpoint": "http://x:4317"}}}
        t = init_tracing_from_config(config)
        self.assertFalse(t.is_enabled())

    def test_enabled_no_endpoint_is_noop(self):
        """enabled=true but no endpoint → noop."""
        config = {"telemetry": {"tracing": {"enabled": True, "endpoint": ""}}}
        t = init_tracing_from_config(config)
        self.assertFalse(t.is_enabled())

    def test_reads_service_name(self):
        """service_name read from config."""
        config = {
            "telemetry": {
                "tracing": {
                    "enabled": True,
                    "endpoint": "http://collector:4317",
                    "service_name": "my-proxy",
                    "sample_rate": 0.05,
                }
            }
        }
        with patch("src.telemetry.tracing.OTEL_AVAILABLE", False):
            with self.assertLogs("src.telemetry.tracing", level="WARNING"):
                t = init_tracing_from_config(config)
        self.assertEqual(t.service_name, "my-proxy")
        self.assertAlmostEqual(t.sample_rate, 0.05)

    def test_reads_sample_rate(self):
        """sample_rate read from config and stored."""
        config = {
            "telemetry": {
                "tracing": {
                    "enabled": True,
                    "endpoint": "http://x:4317",
                    "sample_rate": 0.1,
                }
            }
        }
        with patch("src.telemetry.tracing.OTEL_AVAILABLE", False):
            with self.assertLogs("src.telemetry.tracing", level="WARNING"):
                t = init_tracing_from_config(config)
        self.assertAlmostEqual(t.sample_rate, 0.1)


# ---------------------------------------------------------------------------
# Test: Pipeline integration with tracing
# ---------------------------------------------------------------------------


class TestPipelineTracingIntegration(unittest.TestCase):
    """Pipeline.process() emits spans when tracing is enabled."""

    def test_pipeline_without_tracing_works(self):
        """tracing=None → pipeline processes normally."""
        pipeline = _make_minimal_pipeline(tracing=None)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1516h2_abc_def")
        result = _run(pipeline.process(ctx))
        self.assertEqual(result.action, "allow")

    def test_pipeline_with_noop_tracing_works(self):
        """Noop Tracing instance → pipeline processes normally."""
        noop_tracing = Tracing(endpoint=None)
        pipeline = _make_minimal_pipeline(tracing=noop_tracing)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1516h2_abc_def")
        result = _run(pipeline.process(ctx))
        self.assertEqual(result.action, "allow")

    def test_pipeline_with_mock_tracing_emits_span(self):
        """Mock Tracing → pipeline.process() calls start_as_current_span."""
        mock_tracing = _MockTracing()
        pipeline = _make_minimal_pipeline(tracing=mock_tracing)
        ctx = ConnectionContext(client_ip="5.6.7.8", ja4="t13d1516h2_abc_def")
        result = _run(pipeline.process(ctx))

        tracer = mock_tracing._tracer
        self.assertEqual(len(tracer.started_spans), 1)
        span = tracer.started_spans[0]
        self.assertEqual(span.name, "pipeline.process")

    def test_span_has_correct_attributes(self):
        """Span attributes include client.ip, ja4, action."""
        mock_tracing = _MockTracing()
        pipeline = _make_minimal_pipeline(tracing=mock_tracing)
        ctx = ConnectionContext(client_ip="9.8.7.6", ja4="t13d1516h2_xyz_abc")
        _run(pipeline.process(ctx))

        span = mock_tracing._tracer.started_spans[0]
        self.assertEqual(span.attributes.get("client.ip"), "9.8.7.6")
        self.assertEqual(span.attributes.get("ja4"), "t13d1516h2_xyz_abc")
        self.assertIn("action", span.attributes)

    def test_span_includes_risk_score(self):
        """Span sets risk.score attribute when score is non-None."""
        mock_tracing = _MockTracing()
        pipeline = _make_minimal_pipeline(tracing=mock_tracing)
        # Use dial=100 so result.score is a real value
        pipeline._cache.dial = 100
        pipeline._decider.decide.return_value = "allow"

        ctx = ConnectionContext(client_ip="1.1.1.1", ja4="t13d_x")
        _run(pipeline.process(ctx))

        span = mock_tracing._tracer.started_spans[0]
        self.assertIn("risk.score", span.attributes)

    def test_span_includes_sni_when_present(self):
        """Span sets sni attribute when ctx.sni is set."""
        mock_tracing = _MockTracing()
        pipeline = _make_minimal_pipeline(tracing=mock_tracing)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d_x", sni="example.com")
        _run(pipeline.process(ctx))

        span = mock_tracing._tracer.started_spans[0]
        self.assertEqual(span.attributes.get("sni"), "example.com")

    def test_span_includes_ja4x_when_set(self):
        """Span sets ja4x attribute when ctx.ja4x is not None."""
        mock_tracing = _MockTracing()
        pipeline = _make_minimal_pipeline(tracing=mock_tracing)
        ja4x = "aabbccddeeff_112233445566_aabbcc112233"
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d_x", ja4x=ja4x)
        _run(pipeline.process(ctx))

        span = mock_tracing._tracer.started_spans[0]
        self.assertEqual(span.attributes.get("ja4x"), ja4x)

    def test_pipeline_exception_recorded_in_span(self):
        """Exception in _process_inner → span.record_exception called."""
        mock_tracing = _MockTracing()
        pipeline = _make_minimal_pipeline(tracing=mock_tracing)

        with patch.object(pipeline, "_process_inner", side_effect=RuntimeError("boom")):
            ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d_x")
            result = _run(pipeline.process(ctx))

        # Fail open
        self.assertEqual(result.action, "allow")
        span = mock_tracing._tracer.started_spans[0]
        self.assertEqual(len(span.exceptions), 1)
        self.assertIsInstance(span.exceptions[0], RuntimeError)


if __name__ == "__main__":
    unittest.main()
