"""
DSAR utility for redacting PII (IP addresses) from backup artifacts (Phase 40).
Ensures GDPR compliance by allowing removal of specific subject data from archives.
"""

import logging
from typing import List, Tuple
from prometheus_client import Counter
from src.backup.format import decode_entries, encode_entry

logger = logging.getLogger(__name__)

BACKUP_REDACTION_TOTAL = Counter(
    "ja4proxy_backup_redaction_total",
    "Total number of keys redacted from backup artifacts",
    ["status"] # success, skipped
)


class BackupRedactor:
    """
    Redacts specific PII (IP addresses) from backup artifacts.
    """

    def redact(self, data: bytes, target_ips: List[str]) -> Tuple[bytes, int]:
        """
        Scan backup data and remove any entries matching the target IPs.
        Only redacts based on key name (where IPs are typically stored).
        
        Returns: (redacted_data, redacted_count)
        """
        redacted_count = 0
        new_data = b""
        
        for key, val in decode_entries(data):
            match_found = False
            for ip in target_ips:
                if ip in key:
                    match_found = True
                    break
            
            if match_found:
                redacted_count += 1
                BACKUP_REDACTION_TOTAL.labels(status="success").inc()
                logger.info(f"redactor | event=key_redacted | key={key}")
            else:
                new_data += encode_entry(key, val)
                
        return new_data, redacted_count
