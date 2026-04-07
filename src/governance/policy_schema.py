"""Cerberus schema definition for the JA4proxy policy YAML.

Validates the structure of a parsed policy dict.  Import ``POLICY_SCHEMA`` and
pass it to a ``cerberus.Validator`` to check a policy document.

Valid JA4 fingerprint format:  ``^[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}$``
CIDR fields are validated separately in ``policy_validator`` using
``ipaddress.ip_network()``.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Field reuse helpers
# ---------------------------------------------------------------------------

_STRING_REQUIRED: dict = {"type": "string", "required": True}
_STRING_OPTIONAL: dict = {"type": "string", "required": False}
_BOOL_OPTIONAL: dict = {"type": "boolean", "required": False}

# JA4 fingerprint constraint used in both allowlist and blocklist schemas.
_JA4_PATTERN = r"^[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}$"

# ---------------------------------------------------------------------------
# Sub-schemas
# ---------------------------------------------------------------------------

_META_SCHEMA: dict = {
    "type": "dict",
    "required": False,
    "schema": {
        "version": _STRING_OPTIONAL,
        "environment": _STRING_OPTIONAL,
        "last_updated": _STRING_OPTIONAL,
        "last_updated_by": _STRING_OPTIONAL,
    },
    "allow_unknown": False,
}

_DIAL_SCHEMA: dict = {
    "type": "dict",
    "required": False,
    "schema": {
        "setting": {
            "type": "integer",
            "required": True,
            "min": 0,
            "max": 100,
        },
        "changed_by": _STRING_OPTIONAL,
        "ticket": _STRING_OPTIONAL,
        "notes": _STRING_OPTIONAL,
        "shadow_mode_approved": _BOOL_OPTIONAL,
    },
    "allow_unknown": False,
}

_ALLOWLIST_FINGERPRINT_SCHEMA: dict = {
    "type": "dict",
    "schema": {
        "ja4": {
            "type": "string",
            "required": True,
            "regex": _JA4_PATTERN,
        },
        "reason": _STRING_OPTIONAL,
        "added_by": _STRING_OPTIONAL,
        "ticket": _STRING_OPTIONAL,
        "expires": _STRING_OPTIONAL,
    },
    "allow_unknown": False,
}

_ALLOWLIST_IP_SCHEMA: dict = {
    "type": "dict",
    "schema": {
        # cidr is validated post-cerberus via ipaddress.ip_network()
        "cidr": {"type": "string", "required": True},
        "reason": _STRING_OPTIONAL,
        "added_by": _STRING_OPTIONAL,
        "ticket": _STRING_OPTIONAL,
        "expires": _STRING_OPTIONAL,
    },
    "allow_unknown": False,
}

_ALLOWLIST_SCHEMA: dict = {
    "type": "dict",
    "required": False,
    "schema": {
        "fingerprints": {
            "type": "list",
            "required": False,
            "schema": _ALLOWLIST_FINGERPRINT_SCHEMA,
        },
        "ips": {
            "type": "list",
            "required": False,
            "schema": _ALLOWLIST_IP_SCHEMA,
        },
    },
    "allow_unknown": False,
}

_BLOCKLIST_FINGERPRINT_SCHEMA: dict = {
    "type": "dict",
    "schema": {
        "ja4": {
            "type": "string",
            "required": True,
            "regex": _JA4_PATTERN,
        },
        "reason": _STRING_OPTIONAL,
        "source": _STRING_OPTIONAL,
        "added_by": _STRING_OPTIONAL,
        "ticket": _STRING_OPTIONAL,
        "expires": _STRING_OPTIONAL,
    },
    "allow_unknown": False,
}

_BLOCKLIST_IP_SCHEMA: dict = {
    "type": "dict",
    "schema": {
        "cidr": {"type": "string", "required": True},
        "reason": _STRING_OPTIONAL,
        "source": _STRING_OPTIONAL,
        "added_by": _STRING_OPTIONAL,
        "ticket": _STRING_OPTIONAL,
        "expires": _STRING_OPTIONAL,
    },
    "allow_unknown": False,
}

_BLOCKLIST_SCHEMA: dict = {
    "type": "dict",
    "required": False,
    "schema": {
        "fingerprints": {
            "type": "list",
            "required": False,
            "schema": _BLOCKLIST_FINGERPRINT_SCHEMA,
        },
        "ips": {
            "type": "list",
            "required": False,
            "schema": _BLOCKLIST_IP_SCHEMA,
        },
    },
    "allow_unknown": False,
}

_WATCHLIST_IP_SCHEMA: dict = {
    "type": "dict",
    "schema": {
        # ip field may be a single address or CIDR; validated post-cerberus
        "ip": {"type": "string", "required": True},
        "reason": _STRING_OPTIONAL,
        "added_by": _STRING_OPTIONAL,
        "ticket": _STRING_OPTIONAL,
        "expires": _STRING_OPTIONAL,
    },
    "allow_unknown": False,
}

_WATCHLIST_SCHEMA: dict = {
    "type": "dict",
    "required": False,
    "schema": {
        "ips": {
            "type": "list",
            "required": False,
            "schema": _WATCHLIST_IP_SCHEMA,
        },
    },
    "allow_unknown": False,
}

_VALID_BYPASS_KEYS = frozenset(
    {
        "alpn_browser_bypass",
        "ja4_whitelist_bypass",
        "mtls_bypass",
        "spamhaus_bypass",
        "tls_version_bypass",
        "ja4_blacklist_bypass",
        "country_blacklist_bypass",
        "static_ip_allowlist",
    }
)

_BYPASS_TOGGLES_SCHEMA: dict = {
    "type": "dict",
    "required": False,
    "keysrules": {
        "type": "string",
        "allowed": list(_VALID_BYPASS_KEYS),
    },
    "valuesrules": {"type": "boolean"},
}

# ---------------------------------------------------------------------------
# Top-level schema
# ---------------------------------------------------------------------------

POLICY_SCHEMA: dict = {
    "meta": _META_SCHEMA,
    "dial": _DIAL_SCHEMA,
    "allowlist": _ALLOWLIST_SCHEMA,
    "blocklist": _BLOCKLIST_SCHEMA,
    "watchlist": _WATCHLIST_SCHEMA,
    "bypass_toggles": _BYPASS_TOGGLES_SCHEMA,
}
"""Cerberus schema for a JA4proxy policy YAML document.

Pass to ``cerberus.Validator(POLICY_SCHEMA, allow_unknown=False)`` to validate
a parsed policy dict.
"""
