# HMAC Authentication for Analytics Node
# Phase 12a: Foundation

import hmac
import hashlib
import json
from typing import Dict, Any


def sign_event(event_data: Dict[str, Any], secret: str) -> str:
    """Sign event data with HMAC-SHA256."""
    # Create canonical message (sorted keys, no whitespace)
    message = json.dumps(event_data, sort_keys=True, separators=(",", ":"))
    
    # Create HMAC signature
    hmac_signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac_signature


def verify_hmac(event_data: Dict[str, Any], secret: str, signature: str) -> bool:
    """Verify HMAC signature for event data."""
    # Reconstruct message (without HMAC field)
    event_copy = event_data.copy()
    if "hmac" in event_copy:
        del event_copy["hmac"]
    
    message = json.dumps(event_copy, sort_keys=True, separators=(",", ":"))
    
    # Calculate expected signature
    expected_hmac = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Use compare_digest to prevent timing attacks
    return hmac.compare_digest(expected_hmac, signature)


class HMACAuthenticator:
    """HMAC authentication manager."""
    
    def __init__(self, secret: str, required: bool = True):
        self.secret = secret
        self.required = required
    
    def sign(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add HMAC signature to event data."""
        event_copy = event_data.copy()
        event_copy["hmac"] = sign_event(event_data, self.secret)
        return event_copy
    
    def verify(self, event_data: Dict[str, Any]) -> bool:
        """Verify HMAC signature of event data."""
        if not self.required:
            return True
        
        if "hmac" not in event_data:
            return False
        
        return verify_hmac(event_data, self.secret, event_data["hmac"])