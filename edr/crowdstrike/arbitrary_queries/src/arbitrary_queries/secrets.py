"""
OnePassword CLI integration for secret retrieval.

Uses the 1Password CLI (op) to securely fetch credentials at runtime.
Secrets are never stored in configuration files or environment variables.
"""

import subprocess
from dataclasses import dataclass

# Default timeout for 1Password CLI operations (seconds)
OP_CLI_TIMEOUT_SECONDS = 30


class OnePasswordError(Exception):
    """Raised when OnePassword CLI operations fail."""

    pass


@dataclass(frozen=True)
class Credentials:
    """
    CrowdStrike API credentials.

    This is an immutable dataclass - credentials cannot be modified after creation.

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


def op_read(reference: str, timeout: float = OP_CLI_TIMEOUT_SECONDS) -> str:
    """
    Read a secret from 1Password using op:// URI.

    Args:
        reference: 1Password secret reference in format:
                   op://<vault-name>/<item-name>/[section-name/]<field-name>
        timeout: Maximum seconds to wait for CLI response (default: 30).

    Returns:
        The secret value as a string, with whitespace stripped.

    Raises:
        ValueError: If reference is empty or doesn't start with 'op://'.
        OnePasswordError: If the 1Password CLI fails, times out, or is not found.

    Example:
        >>> secret = op_read("op://MyVault/CrowdStrike/client_secret")
    """
    if not reference:
        raise ValueError("1Password reference cannot be empty")

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
            timeout=timeout,
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise OnePasswordError(
            f"1Password CLI timed out after {timeout} seconds. "
            "Check your network connection or 1Password service status."
        )
    except subprocess.CalledProcessError as e:
        # Sanitize error message - avoid exposing full stderr which may contain
        # sensitive vault/item names in some error scenarios
        error_msg = e.stderr.strip() if e.stderr else "Unknown error"
        # Only include generic error info, not full paths
        if "not found" in error_msg.lower():
            raise OnePasswordError("1Password error: item or vault not found") from e
        elif "not signed in" in error_msg.lower():
            raise OnePasswordError(
                "1Password error: not signed in. Run 'op signin' first."
            ) from e
        else:
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
        ValueError: If either reference is invalid.
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
