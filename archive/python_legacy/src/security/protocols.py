"""Shared protocols (structural interfaces) for the security pipeline.

Using ``typing.Protocol`` instead of abstract base classes keeps modules
decoupled — a class satisfies a protocol purely by having the right
methods, without inheriting from anything.

Usage
-----
Inject mock collectors in tests::

    class MockCollector:
        async def get_signal(self, ctx):
            return RiskSignal(name="test", score=50, reason="mock")
        async def initialize(self): pass
        async def shutdown(self): pass

    pipeline = Pipeline(config=..., local_cache=..., redis_client=...,
                        collectors=[MockCollector()])

Production wiring (in ``proxy.py``) passes ``collectors=None`` (default),
which causes Pipeline to build and own all signal modules itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .models import ConnectionContext, RiskSignal


@runtime_checkable
class SignalCollector(Protocol):
    """Structural interface for any object that produces a RiskSignal.

    All signal modules (ASNClassifier, DNSEnrichment, etc.) satisfy this
    protocol via duck typing — they do not need to inherit from it.

    ``get_signal`` must never raise.  On any failure it should log at
    WARNING and return ``None`` (fail open).
    """

    async def get_signal(self, ctx: "ConnectionContext") -> "RiskSignal | None":
        """Return a risk signal for this connection, or None on failure."""
        ...  # pragma: no cover

    async def initialize(self) -> None:
        """Start background workers / open connections.  Called once at startup."""
        ...  # pragma: no cover

    async def shutdown(self) -> None:
        """Cancel background workers / close connections.  Called once at shutdown."""
        ...  # pragma: no cover
