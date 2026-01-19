# config.py
"""
Configuration for the Resolution Drift QA Framework.

Credentials are fetched from 1Password lazily (on first access) using the 1Password CLI.
This allows the module to be imported without triggering credential lookups,
which is essential for testing and environments where 1Password isn't available.

Non-sensitive settings are defined directly in this file.
"""

import datetime
import logging
import os
import pathlib
import subprocess
from dataclasses import dataclass


LOG_LEVEL = logging.INFO
LOG_DIR = pathlib.Path(__file__).parent.resolve() / "logs"
LOG_FILE = LOG_DIR / f"{datetime.datetime.now().strftime('%Y-%m-%d')}_qa_framework.log"

LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE)]
)


def op_read(reference: str) -> str:
    """
    Read a secret from 1Password using op:// URI.
    
    Args:
        reference: 1Password secret reference in format:
                   op://<vault-name>/<item-name>/[section-name/]<field-name>
    
    Returns:
        The secret value as a string.
    
    Raises:
        RuntimeError: If 1Password CLI fails or is not installed.
    """
    try:
        result = subprocess.run(
            ["op", "read", reference],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,  # Fail fast instead of hanging
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise RuntimeError("1Password CLI timed out. Is the CLI authenticated? Run 'op signin'")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"1Password error: {e.stderr.strip()}") from e
    except FileNotFoundError:
        raise RuntimeError("1Password CLI (op) not found. Install from https://1password.com/downloads/command-line/")


class LazyCrowdStrikeConfig:
    """
    CrowdStrike API configuration with lazy credential loading.
    
    Credentials are fetched from 1Password only when first accessed,
    not at import time. This enables:
    - Importing the module without 1Password being available
    - Testing with mocked credentials
    - Faster startup when credentials aren't immediately needed
    
    For testing, you can set credentials directly:
        config.CROWDSTRIKE._client_id = 'test_id'
        config.CROWDSTRIKE._client_secret = 'test_secret'
    
    Or set environment variables (useful for CI/CD):
        CROWDSTRIKE_CLIENT_ID
        CROWDSTRIKE_CLIENT_SECRET
    """
    
    def __init__(
        self,
        client_id_ref: str,
        client_secret_ref: str,
        base_url: str
    ):
        self._client_id_ref = client_id_ref
        self._client_secret_ref = client_secret_ref
        self._base_url = base_url
        
        # Cached values (None = not yet fetched)
        self._client_id: str | None = None
        self._client_secret: str | None = None
    
    @property
    def client_id(self) -> str:
        """Fetch client_id from 1Password on first access."""
        if self._client_id is None:
            # Check environment variable first (for CI/CD and testing)
            env_value = os.environ.get('CROWDSTRIKE_CLIENT_ID')
            if env_value:
                self._client_id = env_value
            else:
                self._client_id = op_read(self._client_id_ref)
        return self._client_id
    
    @client_id.setter
    def client_id(self, value: str):
        """Allow direct setting for tests."""
        self._client_id = value
    
    @property
    def client_secret(self) -> str:
        """Fetch client_secret from 1Password on first access."""
        if self._client_secret is None:
            # Check environment variable first (for CI/CD and testing)
            env_value = os.environ.get('CROWDSTRIKE_CLIENT_SECRET')
            if env_value:
                self._client_secret = env_value
            else:
                self._client_secret = op_read(self._client_secret_ref)
        return self._client_secret
    
    @client_secret.setter
    def client_secret(self, value: str):
        """Allow direct setting for tests."""
        self._client_secret = value
    
    @property
    def base_url(self) -> str:
        """Return the base URL (not a secret, no lazy loading needed)."""
        return self._base_url
    
    def reset(self):
        """Clear cached credentials. Useful for testing."""
        self._client_id = None
        self._client_secret = None


@dataclass
class QASettings:
    """QA framework settings for consensus detection."""
    lookback_days: int
    min_sample_size: int
    strong_consensus_threshold: float
    batch_hours: int


# =============================================================================
# CrowdStrike API Credentials
# =============================================================================
# Credentials are loaded lazily from 1Password when first accessed.
# Update these 1Password references to match your vault structure.
# Format: op://<vault-name>/<item-name>/[section-name/]<field-name>

CROWDSTRIKE = LazyCrowdStrikeConfig(
    client_id_ref="op://Credentials/CrowdStrike Primary Patrick/username",
    client_secret_ref="op://Credentials/CrowdStrike Primary Patrick/credential",
    
    # Base URL varies by CrowdStrike cloud region:
    #   US-1:     https://api.crowdstrike.com
    #   US-2:     https://api.us-2.crowdstrike.com
    #   EU-1:     https://api.eu-1.crowdstrike.com
    #   US-GOV-1: https://api.laggar.gcw.crowdstrike.com
    base_url="https://api.laggar.gcw.crowdstrike.com"
)


# =============================================================================
# QA Framework Settings
# =============================================================================

QA = QASettings(
    # How far back to look for historical consensus data
    lookback_days=90,
    
    # Minimum alerts needed before consensus is considered reliable
    min_sample_size=20,
    
    # Percentage threshold for "strong" consensus (0.0 to 1.0)
    strong_consensus_threshold=0.90,
    
    # How many hours of new alerts to process per run
    batch_hours=24,
)