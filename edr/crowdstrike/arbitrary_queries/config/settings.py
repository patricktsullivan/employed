"""
arbitrary-queries Configuration (Python format)

This is an alternative configuration format using Python.
To use this file, you would need to modify config.py to support
loading Python configs via importlib.

For now, use settings.json or settings.yaml instead.
This file serves as documentation of the configuration structure.
"""

from pathlib import Path

# OnePassword references for CrowdStrike API credentials
# Edit these to match your 1Password vault structure
ONEPASSWORD = {
    "client_id_ref": "op://YourVault/CrowdStrike-Parent/client_id",
    "client_secret_ref": "op://YourVault/CrowdStrike-Parent/client_secret",
}

# CrowdStrike API configuration
CROWDSTRIKE = {
    # US-GOV-1 cloud base URL
    "base_url": "https://api.laggar.gcw.crowdstrike.com",
    # Repository for NG-SIEM queries
    "repository": "search-all",
}

# Default query parameters
QUERY_DEFAULTS = {
    # Time range for queries (e.g., -7d, -24h, -1h)
    "time_range": "-7d",
    # Polling interval in seconds when waiting for query completion
    "poll_interval_seconds": 60,
    # Maximum time to wait for a query to complete
    "timeout_seconds": 3600,
}

# Concurrency and retry settings
CONCURRENCY = {
    # Maximum number of concurrent queries (for iterative mode)
    "max_concurrent_queries": 50,
    # Number of retry attempts for failed queries
    "retry_attempts": 3,
    # Delay between retries in seconds
    "retry_delay_seconds": 5,
}

# File paths (relative to project root)
PATHS = {
    # JSON file mapping CIDs to customer names
    "cid_registry_path": Path("./data/cid_registry.json"),
    # Directory containing query files
    "queries_dir": Path("./queries"),
    # Directory for CSV output files
    "output_dir": Path("./output"),
}


def get_config() -> dict:
    """Return full configuration as a dictionary."""
    return {
        "onepassword": ONEPASSWORD,
        "crowdstrike": CROWDSTRIKE,
        "query_defaults": QUERY_DEFAULTS,
        "concurrency": CONCURRENCY,
        "paths": {k: str(v) for k, v in PATHS.items()},
    }


if __name__ == "__main__":
    import json
    print(json.dumps(get_config(), indent=2))
