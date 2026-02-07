"""
Tests for secrets module.

Tests OnePassword CLI integration for secret retrieval.
"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess

from secrets import (
    op_read,
    get_credentials,
    OnePasswordError,
    Credentials,
    OP_CLI_TIMEOUT_SECONDS,
)


class TestOpRead:
    """Tests for op_read function."""

    def test_op_read_success(self):
        """op_read should return secret value on success."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="my-secret-value\n",
                stderr="",
                returncode=0,
            )

            result = op_read("op://vault/item/field")

            assert result == "my-secret-value"
            mock_run.assert_called_once()

    def test_op_read_strips_whitespace(self):
        """op_read should strip whitespace from secret."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="  secret-with-spaces  \n",
                stderr="",
                returncode=0,
            )

            result = op_read("op://vault/item/field")

            assert result == "secret-with-spaces"

    def test_op_read_command_structure(self):
        """op_read should call op CLI with correct arguments."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="secret",
                stderr="",
                returncode=0,
            )

            op_read("op://MyVault/MyItem/password")

            call_args = mock_run.call_args
            assert call_args[0][0] == ["op", "read", "op://MyVault/MyItem/password"]
            assert call_args[1]["capture_output"] is True
            assert call_args[1]["text"] is True
            assert call_args[1]["check"] is True
            assert call_args[1]["timeout"] == OP_CLI_TIMEOUT_SECONDS

    def test_op_read_custom_timeout(self):
        """op_read should accept custom timeout value."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="secret",
                stderr="",
                returncode=0,
            )

            op_read("op://vault/item/field", timeout=60)

            call_args = mock_run.call_args
            assert call_args[1]["timeout"] == 60

    def test_op_read_raises_on_cli_error(self):
        """op_read should raise OnePasswordError on CLI failure."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                returncode=1,
                cmd=["op", "read"],
                stderr="[ERROR] item not found",
            )

            with pytest.raises(OnePasswordError) as exc_info:
                op_read("op://vault/nonexistent/field")

            assert "not found" in str(exc_info.value).lower()

    def test_op_read_raises_when_cli_not_found(self):
        """op_read should raise OnePasswordError when op CLI is missing."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            with pytest.raises(OnePasswordError) as exc_info:
                op_read("op://vault/item/field")

            assert "not found" in str(exc_info.value).lower()
            assert "install" in str(exc_info.value).lower()

    def test_op_read_raises_on_timeout(self):
        """op_read should raise OnePasswordError when CLI times out."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd=["op", "read"],
                timeout=30,
            )

            with pytest.raises(OnePasswordError) as exc_info:
                op_read("op://vault/item/field")

            assert "timed out" in str(exc_info.value).lower()

    def test_op_read_validates_reference_format(self):
        """op_read should validate op:// URI format."""
        with pytest.raises(ValueError) as exc_info:
            op_read("invalid-reference")

        assert "op://" in str(exc_info.value)

    def test_op_read_rejects_empty_reference(self):
        """op_read should reject empty string."""
        with pytest.raises(ValueError) as exc_info:
            op_read("")

        assert "empty" in str(exc_info.value).lower()

    def test_op_read_accepts_section_in_path(self):
        """op_read should accept references with section names."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="secret",
                stderr="",
                returncode=0,
            )

            result = op_read("op://vault/item/section/field")

            assert result == "secret"

    def test_op_read_handles_not_signed_in_error(self):
        """op_read should provide helpful message when not signed in."""
        with patch("secrets.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                returncode=1,
                cmd=["op", "read"],
                stderr="[ERROR] not signed in",
            )

            with pytest.raises(OnePasswordError) as exc_info:
                op_read("op://vault/item/field")

            assert "not signed in" in str(exc_info.value).lower()
            assert "signin" in str(exc_info.value).lower()

    def test_op_read_handles_empty_stderr(self):
        """op_read should handle CalledProcessError with empty stderr."""
        with patch("secrets.subprocess.run") as mock_run:
            error = subprocess.CalledProcessError(
                returncode=1,
                cmd=["op", "read"],
            )
            error.stderr = ""
            mock_run.side_effect = error

            with pytest.raises(OnePasswordError) as exc_info:
                op_read("op://vault/item/field")

            # Should not raise AttributeError, should have some error message
            assert "1Password error" in str(exc_info.value)


class TestCredentials:
    """Tests for Credentials data class."""

    def test_create_credentials(self):
        """Credentials should store client_id and client_secret."""
        creds = Credentials(
            client_id="my-client-id",
            client_secret="my-client-secret",
        )

        assert creds.client_id == "my-client-id"
        assert creds.client_secret == "my-client-secret"

    def test_credentials_repr_hides_secret(self):
        """Credentials repr should not expose secret value."""
        creds = Credentials(
            client_id="my-client-id",
            client_secret="super-secret-value",
        )

        repr_str = repr(creds)

        assert "super-secret-value" not in repr_str
        assert "my-client-id" in repr_str
        assert "REDACTED" in repr_str

    def test_credentials_str_hides_secret(self):
        """Credentials str should not expose secret value."""
        creds = Credentials(
            client_id="my-client-id",
            client_secret="super-secret-value",
        )

        str_repr = str(creds)

        assert "super-secret-value" not in str_repr
        assert "***" in str_repr

    def test_credentials_is_immutable(self):
        """Credentials should be immutable (frozen dataclass)."""
        creds = Credentials(
            client_id="my-client-id",
            client_secret="my-client-secret",
        )

        with pytest.raises(AttributeError):
            creds.client_id = "new-client-id"

        with pytest.raises(AttributeError):
            creds.client_secret = "new-secret"

    def test_credentials_is_hashable(self):
        """Frozen credentials should be hashable (can be used in sets/dicts)."""
        creds1 = Credentials(
            client_id="client-id",
            client_secret="secret",
        )
        creds2 = Credentials(
            client_id="client-id",
            client_secret="secret",
        )

        # Should be hashable
        creds_set = {creds1, creds2}
        assert len(creds_set) == 1  # Equal credentials should dedupe

    def test_credentials_equality(self):
        """Credentials with same values should be equal."""
        creds1 = Credentials(
            client_id="client-id",
            client_secret="secret",
        )
        creds2 = Credentials(
            client_id="client-id",
            client_secret="secret",
        )

        assert creds1 == creds2

    def test_credentials_not_in_error_messages(self):
        """Credentials should be safe to include in exception messages."""
        creds = Credentials(
            client_id="my-client-id",
            client_secret="super-secret-value",
        )

        # Simulate what might happen if creds ends up in an error message
        error_msg = f"Failed to authenticate with {creds}"

        assert "super-secret-value" not in error_msg


class TestGetCredentials:
    """Tests for get_credentials function."""

    def test_get_credentials_fetches_both_secrets(self):
        """get_credentials should fetch client_id and client_secret."""
        with patch("secrets.op_read") as mock_op_read:
            mock_op_read.side_effect = [
                "fetched-client-id",
                "fetched-client-secret",
            ]

            creds = get_credentials(
                client_id_ref="op://vault/item/client_id",
                client_secret_ref="op://vault/item/client_secret",
            )

            assert creds.client_id == "fetched-client-id"
            assert creds.client_secret == "fetched-client-secret"
            assert mock_op_read.call_count == 2

    def test_get_credentials_calls_with_correct_refs(self):
        """get_credentials should pass correct references to op_read."""
        with patch("secrets.op_read") as mock_op_read:
            mock_op_read.return_value = "secret"

            get_credentials(
                client_id_ref="op://Vault1/CrowdStrike/client_id",
                client_secret_ref="op://Vault1/CrowdStrike/client_secret",
            )

            calls = mock_op_read.call_args_list
            assert calls[0][0][0] == "op://Vault1/CrowdStrike/client_id"
            assert calls[1][0][0] == "op://Vault1/CrowdStrike/client_secret"

    def test_get_credentials_propagates_onepassword_error(self):
        """get_credentials should propagate OnePasswordError."""
        with patch("secrets.op_read") as mock_op_read:
            mock_op_read.side_effect = OnePasswordError("vault locked")

            with pytest.raises(OnePasswordError) as exc_info:
                get_credentials(
                    client_id_ref="op://vault/item/client_id",
                    client_secret_ref="op://vault/item/client_secret",
                )

            assert "vault locked" in str(exc_info.value)

    def test_get_credentials_propagates_value_error(self):
        """get_credentials should propagate ValueError from invalid refs."""
        with pytest.raises(ValueError):
            get_credentials(
                client_id_ref="invalid-ref",
                client_secret_ref="op://vault/item/client_secret",
            )

    def test_get_credentials_returns_immutable_credentials(self):
        """get_credentials should return immutable Credentials object."""
        with patch("secrets.op_read") as mock_op_read:
            mock_op_read.return_value = "secret"

            creds = get_credentials(
                client_id_ref="op://vault/item/client_id",
                client_secret_ref="op://vault/item/client_secret",
            )

            with pytest.raises(AttributeError):
                creds.client_id = "modified"
