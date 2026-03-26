import json
import logging
import os
import sys
import time
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """
    Enterprise-grade JSON formatter for Loki/Splunk/ELK.
    Includes standard fields: timestamp, level, message, logger, and extra context.
    """

    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        
        # Add any extra fields passed in the 'extra' dict
        if hasattr(record, "extra"):
            log_record.update(record.extra)
        
        return json.dumps(log_record)


def setup_logging(level=logging.INFO, json_format=False):
    """
    Initialize global logging configuration.
    
    Args:
        level: Logging level (default: INFO)
        json_format: Whether to use JSON format (default: False, follows LOG_FORMAT env)
    """
    # Environment override
    env_format = os.environ.get("LOG_FORMAT", "text").lower()
    if env_format == "json":
        json_format = True
        
    env_level = os.environ.get("LOG_LEVEL", "").upper()
    if env_level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        level = getattr(logging, env_level)

    handler = logging.StreamHandler(sys.stdout)
    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        # Standard human-readable format
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)

    # Root logger configuration
    root = logging.getLogger()
    root.setLevel(level)
    
    # Remove existing handlers to avoid duplicates during re-config
    for h in root.handlers[:]:
        root.removeHandler(h)
    
    root.addHandler(handler)
    
    # Silent noisy libraries if needed
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    logging.info("Logging initialized (format=%s, level=%s)", 
                 "json" if json_format else "text", 
                 logging.getLevelName(level))
