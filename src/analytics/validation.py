# Event Validation for Analytics Node
# Phase 12a: Foundation

import ipaddress
import time
from typing import Any, Dict

from .ecs_envelope import VALID_ACTIONS


async def validate_event_comprehensive(
    event_data: Dict[str, Any], timestamp_tolerance: int = 300
) -> bool:
    """Comprehensive validation beyond JSON schema."""

    # 1. Temporal validation - timestamp should be recent
    current_time = time.time()
    if (
        abs(current_time - event_data["timestamp"]) > timestamp_tolerance
    ):  # Configurable window
        raise ValueError("Timestamp too old or in future")

    # 2. IP validation
    if not is_valid_ip(event_data["src_ip"]):
        raise ValueError("Invalid source IP address")

    # 3. Score validation
    if not (0 <= event_data["score"] <= 100):
        raise ValueError("Score must be between 0 and 100")

    # 4. Action validation
    # phase-826: kept in step with event_schemas.EVENT_SCHEMA; see VALID_ACTIONS.
    valid_actions = list(VALID_ACTIONS)
    if event_data["action"] not in valid_actions:
        raise ValueError(f"Invalid action: {event_data['action']}")

    # 5. Proxy ID validation
    if not is_valid_proxy_id(event_data["proxy_id"]):
        raise ValueError("Invalid proxy ID")

    # 6. JA4 validation
    if not is_valid_ja4(event_data["ja4"]):
        raise ValueError("Invalid JA4 fingerprint")

    return True


def is_valid_ip(ip_str: str) -> bool:
    """Validate IP address (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_proxy_id(proxy_id: str) -> bool:
    """Validate proxy ID format."""
    if not proxy_id:
        return False
    if len(proxy_id) > 32:
        return False
    # Allow alphanumeric, hyphens, and underscores
    return all(c.isalnum() or c == "-" or c == "_" for c in proxy_id)


def is_valid_ja4(ja4: str) -> bool:
    """Validate JA4 fingerprint format."""
    if not ja4:
        return False
    if len(ja4) > 64:
        return False
    # Allow alphanumeric, underscores, and hyphens
    return all(c.isalnum() or c == "_" or c == "-" for c in ja4)
