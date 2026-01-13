# config.py
"""
Configuration for the Resolution Drift QA Framework.

Credentials are fetched from 1Password at runtime using the 1Password CLI.
Non-sensitive settings are defined directly in this file.
"""

import datetime
import logging
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
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"1Password error: {e.stderr.strip()}") from e
    except FileNotFoundError:
        raise RuntimeError("1Password CLI (op) not found. Install from https://1password.com/downloads/command-line/")


@dataclass
class CrowdStrikeConfig:
    """CrowdStrike API configuration."""
    client_id: str
    client_secret: str
    base_url: str


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
# Update these 1Password references to match your vault structure.
# Format: op://<vault-name>/<item-name>/[section-name/]<field-name>

CROWDSTRIKE = CrowdStrikeConfig(
    client_id=op_read("op://Credentials/CrowdStrike Primary Patrick/username"),
    client_secret=op_read("op://Credentials/CrowdStrike Primary Patrick/credential"),
    
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
