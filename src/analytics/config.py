# Configuration for Analytics Node
# Phase 12a: Foundation

import yaml
from typing import Dict, Any


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
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
    
    return config