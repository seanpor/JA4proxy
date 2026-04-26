# Configuration for Analytics Node
# Phase 12a: Foundation

import logging
import os
from typing import Any, Dict

import yaml

logger = logging.getLogger(__name__)


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from YAML file, with environment variable overrides.

    Environment variables take precedence over the YAML file:
      REDIS_HOST              — Redis hostname (default: localhost)
      REDIS_PORT              — Redis port (default: 6379)
      REDIS_PASSWORD          — Redis password (default: none)
      JA4PROXY_PROXY_YML      — phase-85: path to the proxy.yml that holds the
                                shared ``threat_intel:`` block (default:
                                ``config/proxy.yml``). Only the
                                ``threat_intel`` key is consumed.
      JA4PROXY_MGMT_BASE_URL  — phase-85: base URL of the MFA/SSO Hardening Management
                                API used by the threat-intel feed runner
                                (default: ``http://management:8090``).
    """
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)

    # phase-85: pull the `threat_intel` block out of proxy.yml so the analytics
    # container can run the feed runner without duplicating the operator-managed
    # feed list. Missing or unparseable file → empty block; the runner sees
    # ``enabled: false`` and short-circuits, no crash.
    proxy_yml_path = os.environ.get("JA4PROXY_PROXY_YML", "config/proxy.yml")
    try:
        with open(proxy_yml_path, "r") as f:
            proxy_cfg = yaml.safe_load(f) or {}
        ti_block = proxy_cfg.get("threat_intel") or {}
        if ti_block:
            config["threat_intel"] = ti_block
            logger.info(
                "analytics_config | event=threat_intel_loaded | source=%s | feeds=%d",
                proxy_yml_path,
                len(ti_block.get("feeds", []) or []),
            )
    except FileNotFoundError:
        logger.info(
            "analytics_config | event=threat_intel_skipped | reason=proxy_yml_missing | path=%s",
            proxy_yml_path,
        )
    except Exception as exc:  # noqa: BLE001 — fail open
        logger.warning(
            "analytics_config | event=threat_intel_load_failed | path=%s | error=%s",
            proxy_yml_path,
            exc,
        )

    config.setdefault(
        "management_api",
        {
            "base_url": os.environ.get(
                "JA4PROXY_MGMT_BASE_URL", "http://management:8090"
            )
        },
    )

    # Set defaults
    defaults = {
        "redis": {"host": "localhost", "port": 6379, "password": None},
        "stream": {
            "key": "ja4proxy:events",
            "consumer_group": "analytics",
            "consumer_name": "analytics-1",
            "batch_size": 100,
            "timeout_ms": 5000,
        },
        "security": {"hmac_secret": "default-secret-change-me", "hmac_required": True},
        "aggregation": {"window_seconds": 300},
    }

    # Merge defaults with loaded config
    for key, value in defaults.items():
        if key not in config:
            config[key] = value
        elif isinstance(value, dict):
            for subkey, subvalue in value.items():
                if subkey not in config[key]:
                    config[key][subkey] = subvalue

    # Environment variable overrides (docker-compose / container env)
    if os.environ.get("REDIS_HOST"):
        config["redis"]["host"] = os.environ["REDIS_HOST"]
    if os.environ.get("REDIS_PORT"):
        config["redis"]["port"] = int(os.environ["REDIS_PORT"])
    if os.environ.get("REDIS_PASSWORD"):
        config["redis"]["password"] = os.environ["REDIS_PASSWORD"]

    return config
