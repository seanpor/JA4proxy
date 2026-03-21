"""
OpenTelemetry tracing wrapper for JA4Proxy (Phase 16).

This module provides optional distributed tracing with zero overhead when disabled.
Uses the OpenTelemetry Python SDK with automatic instrumentation.

When ``telemetry.tracing.enabled = false`` (the default), no OTEL provider is
initialised and the noop tracer has zero runtime cost. When enabled, each pipeline
stage emits a span with connection attributes.
"""

import logging
from contextlib import contextmanager
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)

# Optional imports — fail gracefully if OpenTelemetry SDK is not installed.
# All names are always bound (as None when unavailable) so tests can patch them.
try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    OTEL_AVAILABLE = True
except ImportError:
    trace = None  # type: ignore[assignment]
    OTLPSpanExporter = None  # type: ignore[assignment,misc]
    Resource = None  # type: ignore[assignment,misc]
    TracerProvider = None  # type: ignore[assignment,misc]
    BatchSpanProcessor = None  # type: ignore[assignment,misc]
    OTEL_AVAILABLE = False


class _NoopSpan:
    """Context manager that does nothing. Used when tracing is disabled."""

    def __enter__(self) -> "_NoopSpan":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> None:  # noqa: ARG002
        pass

    def add_event(self, name: str, attributes: Optional[dict] = None) -> None:  # noqa: ARG002
        pass

    def record_exception(self, exc: Exception) -> None:  # noqa: ARG002
        pass


class _NoopTracer:
    """Noop tracer returned when OTEL is disabled. Zero runtime cost."""

    @contextmanager
    def start_as_current_span(
        self, name: str, **kwargs: Any  # noqa: ARG002
    ) -> Generator[_NoopSpan, None, None]:
        yield _NoopSpan()


class Tracing:
    """OpenTelemetry tracing wrapper with zero-cost when disabled."""

    def __init__(
        self,
        endpoint: Optional[str] = None,
        service_name: str = "ja4proxy",
        sample_rate: float = 0.01,
    ) -> None:
        """
        Initialise tracing. If endpoint is None, tracing is disabled (noop).

        Args:
            endpoint: OTLP gRPC endpoint (e.g. ``http://jaeger:4317``).
                      Pass ``None`` (the default) for zero-overhead noop mode.
            service_name: Service name recorded in spans.
            sample_rate: Fraction of connections to trace (0.0–1.0). Default 1%.
        """
        self.endpoint = endpoint
        self.service_name = service_name
        self.sample_rate = sample_rate
        self._provider: Optional[Any] = None
        self._initialized = False

        if endpoint and OTEL_AVAILABLE:
            self._initialize_tracing()
        elif endpoint and not OTEL_AVAILABLE:
            logger.warning(
                "tracing | event=otel_not_available | "
                "hint=install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc"
            )

    def _initialize_tracing(self) -> None:
        """Initialise OpenTelemetry tracing pipeline."""
        if not OTEL_AVAILABLE or not self.endpoint:
            return  # pragma: no cover

        try:
            resource = Resource.create({"service.name": self.service_name})
            provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(provider)

            exporter = OTLPSpanExporter(endpoint=self.endpoint)
            span_processor = BatchSpanProcessor(exporter)
            provider.add_span_processor(span_processor)

            self._provider = provider
            self._initialized = True
            logger.info(
                "tracing | event=initialized | endpoint=%s | service=%s",
                self.endpoint,
                self.service_name,
            )
        except Exception as exc:
            logger.warning(
                "tracing | event=init_failed | endpoint=%s | error=%s — using noop",
                self.endpoint,
                exc,
            )

    def is_enabled(self) -> bool:
        """Return True if tracing was successfully initialised.

        ``_initialized`` is only set to True when OTEL was available and the
        provider was created without error, so checking it is sufficient.
        """
        return self._initialized

    def get_tracer(self, name: str = "ja4proxy") -> Any:
        """Return a real OTEL tracer or the noop tracer if disabled."""
        if self.is_enabled():
            return trace.get_tracer(name)  # type: ignore[union-attr]
        return _NoopTracer()


def init_tracing_from_config(config: dict) -> "Tracing":
    """Initialise tracing from ``config/proxy.yml`` ``telemetry.tracing`` block.

    Returns a :class:`Tracing` instance (noop when disabled or OTEL unavailable).

    Args:
        config: Full proxy config dict (from ConfigLoader).
    """
    tracing_cfg = config.get("telemetry", {}).get("tracing", {})
    if not tracing_cfg.get("enabled", False):
        return Tracing(endpoint=None)

    return Tracing(
        endpoint=tracing_cfg.get("endpoint") or None,
        service_name=tracing_cfg.get("service_name", "ja4proxy"),
        sample_rate=float(tracing_cfg.get("sample_rate", 0.01)),
    )
