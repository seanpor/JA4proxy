"""Shared fail-closed environment classification for the management API.

JA4PROXY-2026-0094 (phase-520) fixed the Go proxy's fail-open-under-saturation
bug; this is the Python management API's counterpart, JA4PROXY-2026-0093
(phase-521).

Before this module existed, ``auth.py``, ``main.py``, and
``middleware/csrf.py`` each carried their own copy of:

    def _is_production() -> bool:
        env = os.environ.get("ENVIRONMENT", "").strip().lower()
        return env in {"production", "prod"}

Every test-only security escape hatch (hardcoded JWT signing secret, OIDC
signature-verification skip, CSRF disable, SAML strict-off) — and the startup
guard meant to catch them armed in production — gated on
``not _is_production()``. That means an **unset**, misspelled, or merely
unrecognised ``ENVIRONMENT`` value (``dmz``, ``staging``, a typo) was treated
as "not production," so the escape hatches activated. JA4proxy's core use
case is a DMZ security appliance, where ``ENVIRONMENT`` being unset or set to
something other than exactly ``production``/``prod`` is entirely plausible —
turning a common misconfiguration into an authentication bypass.

The fix inverts the default: only an *explicit*, known development/test value
disables production hardening. Unset or unrecognised always means
production.
"""

from __future__ import annotations

import os

# Explicit allowlist of non-production environments where test-only escape
# hatches (hardcoded JWT secret, OIDC/SAML/CSRF bypass) may activate. Anything
# NOT in this set — including unset, "dmz", "staging", or a typo — is treated
# as production so security features fail CLOSED.
_NONPROD_ENVIRONMENTS = frozenset({"dev", "development", "test", "testing", "local", "ci"})


def is_explicit_nonproduction() -> bool:
    """Return True ONLY when ENVIRONMENT is a known dev/test value.

    Unset or unrecognised values return False (treated as production), so
    callers that gate a security feature *off* on this predicate fail closed
    by default.
    """
    return os.environ.get("ENVIRONMENT", "").strip().lower() in _NONPROD_ENVIRONMENTS


def is_production() -> bool:
    """Return True for everything that is not an explicit non-production env.

    This is the inverse of :func:`is_explicit_nonproduction`, kept as a
    separate name because most call sites read more naturally as "if
    production, harden this" (disable API docs, force Secure cookies, refuse
    to boot with a test flag armed) rather than "if explicitly not
    production."
    """
    return not is_explicit_nonproduction()
