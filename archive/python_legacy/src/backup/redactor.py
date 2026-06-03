"""
DSAR utility for redacting PII (IP addresses) from backup artifacts.

Phase 40: Initial implementation — key-name only redaction.
Phase 57e: Hardening — deep-scan JSON values; redact IP fields inside structured
           data (e.g. audit log entries) rather than only matching key names.

Ensures GDPR compliance by allowing removal of specific subject data from archives
before artifacts are uploaded to cloud storage.
"""

import json
import logging
from typing import List, Tuple

from prometheus_client import Counter
from src.backup.format import decode_entries, encode_entry

logger = logging.getLogger(__name__)

BACKUP_REDACTION_TOTAL = Counter(
    "ja4proxy_backup_redaction_total",
    "Total number of keys redacted from backup artifacts",
    ["status"],  # success, skipped
)


class BackupRedactor:
    """Redacts specific PII (IP addresses) from backup artifacts.

    By default performs two passes for each entry:

    1. **Key-name match** — if the Redis key name contains a target IP, the entry
       is excluded entirely (existing Phase 40 behaviour; preserves backward compat).

    2. **Value scan** (enabled when ``redact_values=True``, which is the default) —
       if the serialized value bytes contain a target IP string, the redactor attempts
       JSON field-level replacement.  Non-JSON values that contain an IP are excluded
       entirely (safe default).

    Args:
        redact_values: When ``True`` (default), scan entry values for IP strings and
                       perform field-level JSON redaction.  Set ``False`` to restore
                       Phase 40 key-name-only behaviour.
        redact_entire_entry: When ``True``, any entry whose *value* contains a target
                             IP is excluded entirely instead of field-redacted.  Key-name
                             matches are always excluded regardless of this flag.
    """

    def __init__(
        self,
        redact_values: bool = True,
        redact_entire_entry: bool = False,
    ) -> None:
        self.redact_values = redact_values
        self.redact_entire_entry = redact_entire_entry

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _redact_in_structure(self, obj: object, target_ips: List[str]) -> object:
        """Recursively walk a JSON-decoded structure, replacing matching IPs.

        Replacement is exact string-match within string values: if the string
        equals a target IP (or contains one), the whole string value is replaced
        with ``"[REDACTED]"``.  Non-string leaf nodes are returned unchanged.

        Args:
            obj:        A Python object decoded from JSON (dict, list, str, int, …).
            target_ips: IP strings to look for.

        Returns:
            A new object of the same type with matching strings replaced.
        """
        if isinstance(obj, dict):
            return {k: self._redact_in_structure(v, target_ips) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._redact_in_structure(item, target_ips) for item in obj]
        if isinstance(obj, str):
            for ip in target_ips:
                if ip in obj:
                    return "[REDACTED]"
            return obj
        return obj

    def _value_contains_ip(self, val: bytes, target_ips: List[str]) -> bool:
        """Return ``True`` if *val* bytes contain any of the target IP strings.

        Uses a simple substring search over the UTF-8 decoded representation.
        Decoding errors are silently ignored (``errors="ignore"``), so pure binary
        values that don't contain the IP string in their text representation return
        ``False`` correctly.

        Args:
            val:        Raw value bytes from the backup entry.
            target_ips: IP strings to look for.

        Returns:
            ``True`` if any target IP appears in the decoded text; ``False`` otherwise.
        """
        try:
            text = val.decode("utf-8", errors="ignore")
            return any(ip in text for ip in target_ips)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact(self, data: bytes, target_ips: List[str]) -> Tuple[bytes, int]:
        """Scan backup *data* and redact entries that contain any of *target_ips*.

        Processing per entry:

        1. If the **key name** contains a target IP → exclude entry entirely.
        2. Else if ``redact_values=True`` and the **value bytes** contain a target IP:
           a. If ``redact_entire_entry=True`` → exclude entry entirely.
           b. Else try JSON field-level redaction → keep entry with cleaned value.
           c. If value is not valid UTF-8 JSON → exclude entry entirely (safe default).
        3. Otherwise → keep entry unchanged.

        Args:
            data:       Raw bytes from a backup artifact (legacy or Phase-57a format).
            target_ips: List of IP address strings to redact.

        Returns:
            Tuple of ``(redacted_data, redacted_count)`` where *redacted_count* is the
            number of entries that were modified or excluded.
        """
        redacted_count = 0
        new_data = b""

        for key, val in decode_entries(data):
            # ── Pass 1: key-name match (always exclude entry entirely) ──
            key_match = any(ip in key for ip in target_ips)
            if key_match:
                redacted_count += 1
                BACKUP_REDACTION_TOTAL.labels(status="success").inc()
                logger.info(
                    "redactor | event=key_redacted | key=%s | reason=key_name", key
                )
                continue

            # ── Pass 2: value scan (only when enabled) ──
            if self.redact_values and self._value_contains_ip(val, target_ips):
                if self.redact_entire_entry:
                    # Caller wants entire entry dropped
                    redacted_count += 1
                    BACKUP_REDACTION_TOTAL.labels(status="success").inc()
                    logger.info(
                        "redactor | event=key_redacted | key=%s | reason=value_match_entire",
                        key,
                    )
                    continue
                else:
                    # Attempt JSON field-level redaction
                    try:
                        decoded_text = val.decode("utf-8")
                        parsed = json.loads(decoded_text)
                        cleaned = self._redact_in_structure(parsed, target_ips)
                        val = json.dumps(cleaned, separators=(",", ":")).encode("utf-8")
                        redacted_count += 1
                        BACKUP_REDACTION_TOTAL.labels(status="success").inc()
                        logger.info(
                            "redactor | event=value_field_redacted | key=%s", key
                        )
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # Non-JSON value containing IP → exclude entirely (safe default)
                        redacted_count += 1
                        BACKUP_REDACTION_TOTAL.labels(status="success").inc()
                        logger.info(
                            "redactor | event=key_redacted | key=%s | reason=non_json_value_match",
                            key,
                        )
                        continue

            new_data += encode_entry(key, val)

        return new_data, redacted_count
