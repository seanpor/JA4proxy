# Configuration for Analytics Node
# Phase 12a: Foundation

import os
import yaml
from typing import Dict, Any


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from YAML file, with environment variable overrides.

    Environment variables take precedence over the YAML file:
      REDIS_HOST     — Redis hostname (default: localhost)
      REDIS_PORT     — Redis port (default: 6379)
      REDIS_PASSWORD — Redis password (default: none)
    """
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    # Set defaults
    defaults = {
        'redis': {
            'host': 'localhost',
            'port': 6379,
            'password': None
        },
        'stream': {
            'key': 'ja4proxy:events',
            'consumer_group': 'analytics',
            'consumer_name': 'analytics-1',
            'batch_size': 100,
            'timeout_ms': 5000
        },
        'security': {
            'hmac_secret': 'default-secret-change-me',
            'hmac_required': True
        },
        'aggregation': {
            'window_seconds': 300
        }
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