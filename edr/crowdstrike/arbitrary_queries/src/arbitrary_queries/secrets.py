"""
OnePassword CLI integration for secret retrieval.

Uses the 1Password CLI (op) to securely fetch credentials at runtime.
Secrets are never stored in configuration files or environment variables.
"""

import subprocess
from dataclasses import dataclass


class OnePasswordError(Exception):
    """Raised when OnePassword CLI operations fail."""
    pass


@dataclass
class Credentials:
    """
    CrowdStrike API credentials.
    
    Attributes:
        client_id: OAuth2 client ID.
        client_secret: OAuth2 client secret.
    """
    
    client_id: str
    client_secret: str
    
    def __repr__(self) -> str:
        return f"Credentials(client_id={self.client_id!r}, client_secret='***REDACTED***')"
    
    def __str__(self) -> str:
        return f"Credentials(client_id={self.client_id}, client_secret=***)"


def op_read(reference: str) -> str:
    """
    Read a secret from 1Password using op:// URI.
    
    Args:
        reference: 1Password secret reference in format:
                   op://<vault-name>/<item-name>/[section-name/]<field-name>
    
    Returns:
        The secret value as a string, with whitespace stripped.
    
    Raises:
        ValueError: If reference doesn't start with 'op://'.
        OnePasswordError: If the 1Password CLI fails or is not found.
    
    Example:
        >>> secret = op_read("op://MyVault/CrowdStrike/client_secret")
    """
    if not reference.startswith("op://"):
        raise ValueError(
            f"Invalid 1Password reference: {reference!r}. "
            "Reference must start with 'op://'"
        )
    
    try:
        result = subprocess.run(
            ["op", "read", reference],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else str(e)
        raise OnePasswordError(f"1Password error: {error_msg}") from e
    except FileNotFoundError:
        raise OnePasswordError(
            "1Password CLI (op) not found. "
            "Please install it from https://1password.com/downloads/command-line/"
        )


def get_credentials(client_id_ref: str, client_secret_ref: str) -> Credentials:
    """
    Fetch CrowdStrike credentials from 1Password.
    
    Args:
        client_id_ref: 1Password reference for client ID.
        client_secret_ref: 1Password reference for client secret.
    
    Returns:
        Credentials object with fetched values.
    
    Raises:
        OnePasswordError: If credential retrieval fails.
    
    Example:
        >>> creds = get_credentials(
        ...     client_id_ref="op://Vault/CrowdStrike/client_id",
        ...     client_secret_ref="op://Vault/CrowdStrike/client_secret",
        ... )
    """
    client_id = op_read(client_id_ref)
    client_secret = op_read(client_secret_ref)
    
    return Credentials(client_id=client_id, client_secret=client_secret)
