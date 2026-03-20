"""
OpenTelemetry tracing wrapper for JA4Proxy (Phase 16).

This module provides optional distributed tracing with zero overhead when disabled.
Uses the OpenTelemetry Python SDK with automatic instrumentation.
"""

import os
from typing import Optional

# Optional imports - fail gracefully if OpenTelemetry not installed
try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


class Tracing:
    """OpenTelemetry tracing wrapper with zero-cost when disabled."""
    
    def __init__(self, endpoint: Optional[str] = None, service_name: str = "ja4proxy"):
        """
        Initialize tracing. If endpoint is None, tracing is disabled (noop).
        
        Args:
            endpoint: OTLP gRPC endpoint (e.g., 'http://jaeger:4317')
            service_name: Service name for tracing
        """
        self.endpoint = endpoint
        self.service_name = service_name
        self._initialized = False
        
        if endpoint and OTEL_AVAILABLE:
            self._initialize_tracing()
        else:
            # Noop provider - zero overhead
            if not OTEL_AVAILABLE:
                print("OpenTelemetry not available - install with: pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc")

    def _initialize_tracing(self):
        """Initialize OpenTelemetry tracing pipeline."""
        if not OTEL_AVAILABLE or not self.endpoint:
            return
            
        # Set up resource with service name
        resource = Resource.create({"service.name": self.service_name})
        
        # Create provider and set as global
        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)
        
        # Set up exporter - try OTLP first, fall back to console for debugging
        try:
            exporter = OTLPSpanExporter(endpoint=self.endpoint)
        except Exception:
            print(f"Warning: Could not connect to OTLP endpoint {self.endpoint}, using console exporter")
            exporter = ConsoleSpanExporter()
        
        # Add span processor
        span_processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(span_processor)
        
        self._initialized = True
        print(f"✓ OpenTelemetry tracing initialized - endpoint: {self.endpoint}")
    
    def is_enabled(self) -> bool:
        """Return True if tracing is enabled and initialized."""
        return self._initialized and OTEL_AVAILABLE
    
    def get_tracer(self, name: str = "ja4proxy"):
        """Get a tracer for the given name. Returns noop tracer if disabled."""
        if not self.is_enabled():
            # Return a noop tracer-like object
            class NoopTracer:
                def start_as_current_span(self, *args, **kwargs):
                    class NoopSpan:
                        def __enter__(self): return self
                        def __exit__(self, *args): pass
                        def set_attribute(self, *args): pass
                        def add_event(self, *args): pass
                    return NoopSpan()
                
                def __call__(self, *args, **kwargs):
                    return self
            
            return NoopTracer()
        
        return trace.get_tracer(name)


def init_tracing(endpoint: Optional[str] = None, service_name: str = "ja4proxy"):
    """
    Global tracing initialization helper.
    
    Args:
        endpoint: OTLP gRPC endpoint or None to disable
        service_name: Service name for tracing
        
    Returns:
        Tracing instance
    """
    return Tracing(endpoint, service_name)
