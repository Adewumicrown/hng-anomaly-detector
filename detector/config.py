"""
config.py — Central config loader
Loads config.yaml and merges secrets from .env
All modules import this instead of reading files themselves.
"""

import yaml
import os
from dotenv import load_dotenv

# Load .env file if it exists (local dev)
# On the server you can set env vars directly instead
load_dotenv()

def load_config(path: str = None) -> dict:
    """Load config.yaml and inject secrets from environment."""

    if path is None:
        # Look for config.yaml in the same directory as this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base_dir, "config.yaml")

    with open(path, "r") as f:
        cfg = yaml.safe_load(f)

    # Override slack webhook from environment if set
    # This way the real URL never lives in config.yaml
    slack_from_env = os.getenv("SLACK_WEBHOOK_URL")
    if slack_from_env:
        cfg["slack_webhook_url"] = slack_from_env

    return cfg


# Single shared config object — import this everywhere
cfg = load_config()
