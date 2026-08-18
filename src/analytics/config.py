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
    # feed list. Missing or unparsable file → empty block; the runner sees
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
            "key": "events:connection",
            "consumer_group": "analytics",
            "consumer_name": "analytics-1",
            "batch_size": 100,
            "timeout_ms": 5000,
        },
        "security": {
            # phase-826: overridden by ANALYTICS_HMAC_SECRET below. The proxy
            # signs every connection event with the same secret; if these two
            # differ, nothing crashes — 100% of events are silently discarded
            # and the Intelligence panel stays empty while both services report
            # healthy. That is exactly how this bug survived undetected.
            "hmac_secret": "default-secret-change-me",
            "hmac_required": True,
        },
        "aggregation": {"window_seconds": 300},
        # phase-827: detection thresholds. These were hardcoded Python defaults
        # on the detector constructors and nothing ever passed a value, so the
        # only way to tune them was to edit source — in breach of the
        # config-driven requirement every other feature here follows.
        #
        # They are not one-size-fits-all. "campaign" means density >= 0.15 of a
        # /24, i.e. 39+ distinct IPs in one 256-address block: correct for a
        # site fronting many networks, far too coarse for a single-tenant
        # deployment. Defaults below are the historical hardcoded values, so
        # behaviour is unchanged until an operator opts in.
        "detection": {
            "campaign": {
                "min_unique_ips": 10,
                "density_threshold": 0.15,
                "block_rate_threshold": 0.70,
                "window_seconds": 300,
            },
            "slow_scan": {
                "min_unique_ips": 20,
                "max_requests_per_ip": 3,
                "window_seconds": 300,
            },
            "ja4_intelligence": {
                "min_observations": 10,
                "block_rate_threshold": 0.95,
                "window_seconds": 3600,
            },
        },
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
    # phase-826: must match the proxy's webhooks.stream_hmac_secret, which is
    # fed from the same ANALYTICS_HMAC_SECRET. Without this override the
    # container's env var is inert and the built-in placeholder is used, so
    # every signed event fails verification — which is precisely what happened
    # when the variable was plumbed into docker-compose but not into here.
    if os.environ.get("ANALYTICS_HMAC_SECRET"):
        config["security"]["hmac_secret"] = os.environ["ANALYTICS_HMAC_SECRET"]

    return config
