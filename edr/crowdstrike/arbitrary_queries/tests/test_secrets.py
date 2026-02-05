"""
Tests for arbitrary_queries.secrets module.

Tests OnePassword CLI integration for secret retrieval.
"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess

from arbitrary_queries.secrets import (
    op_read,
    get_credentials,
    OnePasswordError,
    Credentials,
)


class TestOpRead:
    """Tests for op_read function."""

    def test_op_read_success(self):
        """op_read should return secret value on success."""
        with patch("subprocess.run") as mock_run:
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
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="  secret-with-spaces  \n",
                stderr="",
                returncode=0,
            )
            
            result = op_read("op://vault/item/field")
            
            assert result == "secret-with-spaces"

    def test_op_read_command_structure(self):
        """op_read should call op CLI with correct arguments."""
        with patch("subprocess.run") as mock_run:
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

    def test_op_read_raises_on_cli_error(self):
        """op_read should raise OnePasswordError on CLI failure."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                returncode=1,
                cmd=["op", "read"],
                stderr="[ERROR] item not found",
            )
            
            with pytest.raises(OnePasswordError) as exc_info:
                op_read("op://vault/nonexistent/field")
            
            assert "item not found" in str(exc_info.value)

    def test_op_read_raises_when_cli_not_found(self):
        """op_read should raise OnePasswordError when op CLI is missing."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            
            with pytest.raises(OnePasswordError) as exc_info:
                op_read("op://vault/item/field")
            
            assert "not found" in str(exc_info.value).lower()

    def test_op_read_validates_reference_format(self):
        """op_read should validate op:// URI format."""
        with pytest.raises(ValueError) as exc_info:
            op_read("invalid-reference")
        
        assert "op://" in str(exc_info.value)

    def test_op_read_accepts_section_in_path(self):
        """op_read should accept references with section names."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="secret",
                stderr="",
                returncode=0,
            )
            
            result = op_read("op://vault/item/section/field")
            
            assert result == "secret"


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
        assert "***" in repr_str or "REDACTED" in repr_str

    def test_credentials_str_hides_secret(self):
        """Credentials str should not expose secret value."""
        creds = Credentials(
            client_id="my-client-id",
            client_secret="super-secret-value",
        )
        
        str_repr = str(creds)
        
        assert "super-secret-value" not in str_repr


class TestGetCredentials:
    """Tests for get_credentials function."""

    def test_get_credentials_fetches_both_secrets(self):
        """get_credentials should fetch client_id and client_secret."""
        with patch("arbitrary_queries.secrets.op_read") as mock_op_read:
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
        with patch("arbitrary_queries.secrets.op_read") as mock_op_read:
            mock_op_read.return_value = "secret"
            
            get_credentials(
                client_id_ref="op://Vault1/CrowdStrike/client_id",
                client_secret_ref="op://Vault1/CrowdStrike/client_secret",
            )
            
            calls = mock_op_read.call_args_list
            assert calls[0][0][0] == "op://Vault1/CrowdStrike/client_id"
            assert calls[1][0][0] == "op://Vault1/CrowdStrike/client_secret"

    def test_get_credentials_propagates_error(self):
        """get_credentials should propagate OnePasswordError."""
        with patch("arbitrary_queries.secrets.op_read") as mock_op_read:
            mock_op_read.side_effect = OnePasswordError("vault locked")
            
            with pytest.raises(OnePasswordError):
                get_credentials(
                    client_id_ref="op://vault/item/client_id",
                    client_secret_ref="op://vault/item/client_secret",
                )
