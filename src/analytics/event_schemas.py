# Event Schemas for Analytics Node
# Phase 12a: Foundation

EVENT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Analytics Event",
    "description": "Validated event from proxy instance",
    "type": "object",
    "required": ["timestamp", "src_ip", "ja4", "action", "score", "proxy_id"],
    "properties": {
        "timestamp": {"type": "number", "minimum": 0, "maximum": 9999999999},
        "src_ip": {
            "type": "string",
            "pattern": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$",
            "maxLength": 45,
        },
        "ja4": {
            "type": "string",
            "pattern": r"^[a-zA-Z0-9_\-]{1,64}$",
            "maxLength": 64,
        },
        # phase-826: the proxy's action decider also emits flag, rate_limit
        # and ban. Omitting them rejected exactly the events worth analysing —
        # rate_limit is the only non-allow action a monitor-mode deployment
        # produces in volume.
        "action": {
            "type": "string",
            "enum": [
                "allow",
                "block",
                "monitor",
                "tarpit",
                "flag",
                "rate_limit",
                "ban",
            ],
        },
        "score": {"type": "number", "minimum": 0, "maximum": 100},
        "proxy_id": {"type": "string", "pattern": r"^[a-zA-Z0-9\-]{1,32}$"},
    },
    "additionalProperties": True,  # Allow additional fields for future expansion
}
