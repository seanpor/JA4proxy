# Event Schemas for Analytics Node
# Phase 12a: Foundation

EVENT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Analytics Event",
    "description": "Validated event from proxy instance",
    "type": "object",
    "required": ["timestamp", "src_ip", "ja4", "action", "score", "proxy_id"],
    "properties": {
        "timestamp": {
            "type": "number",
            "minimum": 0,
            "maximum": 9999999999
        },
        "src_ip": {
            "type": "string",
            "pattern": "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$",
            "maxLength": 45
        },
        "ja4": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9_\-]{1,64}$",
            "maxLength": 64
        },
        "action": {
            "type": "string",
            "enum": ["allow", "block", "monitor", "tarpit"]
        },
        "score": {
            "type": "number",
            "minimum": 0,
            "maximum": 100
        },
        "proxy_id": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9\-]{1,32}$"
        }
    },
    "additionalProperties": True  # Allow additional fields for future expansion
}