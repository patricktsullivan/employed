"""
Tests for arbitrary_queries.client module.

Tests CrowdStrike API client wrapper using FalconPy.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone

from arbitrary_queries.client import (
    CrowdStrikeClient,
    CrowdStrikeError,
    AuthenticationError,
    QuerySubmissionError,
    QueryStatusError,
)
from arbitrary_queries.secrets import Credentials
from arbitrary_queries.config import CrowdStrikeConfig


@pytest.fixture
def mock_credentials():
    """Mock CrowdStrike credentials."""
    return Credentials(
        client_id="test-client-id",
        client_secret="test-client-secret",
    )


@pytest.fixture
def mock_cs_config():
    """Mock CrowdStrike configuration."""
    return CrowdStrikeConfig(
        base_url="https://api.laggar.gcw.crowdstrike.com",
        repository="search-all",
    )


@pytest.fixture
def client(mock_credentials, mock_cs_config):
    """Create a CrowdStrikeClient for testing."""
    with patch("arbitrary_queries.client.OAuth2") as mock_oauth:
        mock_oauth.return_value.token.return_value = {
            "status_code": 201,
            "body": {"access_token": "test-token", "expires_in": 1800},
        }
        return CrowdStrikeClient(
            credentials=mock_credentials,
            config=mock_cs_config,
        )


class TestCrowdStrikeClientInit:
    """Tests for CrowdStrikeClient initialization."""

    def test_client_init_with_credentials(self, mock_credentials, mock_cs_config):
        """Client should initialize with credentials and config."""
        with patch("arbitrary_queries.client.OAuth2") as mock_oauth:
            mock_oauth.return_value.token.return_value = {
                "status_code": 201,
                "body": {"access_token": "token", "expires_in": 1800},
            }
            
            client = CrowdStrikeClient(
                credentials=mock_credentials,
                config=mock_cs_config,
            )
            
            assert client.base_url == "https://api.laggar.gcw.crowdstrike.com"
            assert client.repository == "search-all"

    def test_client_init_authenticates(self, mock_credentials, mock_cs_config):
        """Client should authenticate on initialization."""
        with patch("arbitrary_queries.client.OAuth2") as mock_oauth:
            mock_instance = MagicMock()
            mock_instance.token.return_value = {
                "status_code": 201,
                "body": {"access_token": "my-token", "expires_in": 1800},
            }
            mock_oauth.return_value = mock_instance
            
            client = CrowdStrikeClient(
                credentials=mock_credentials,
                config=mock_cs_config,
            )
            
            mock_oauth.assert_called_once()
            assert client._access_token == "my-token"

    def test_client_init_auth_failure(self, mock_credentials, mock_cs_config):
        """Client should raise AuthenticationError on auth failure."""
        with patch("arbitrary_queries.client.OAuth2") as mock_oauth:
            mock_instance = MagicMock()
            mock_instance.token.return_value = {
                "status_code": 401,
                "body": {"errors": [{"message": "Invalid credentials"}]},
            }
            mock_oauth.return_value = mock_instance
            
            with pytest.raises(AuthenticationError) as exc_info:
                CrowdStrikeClient(
                    credentials=mock_credentials,
                    config=mock_cs_config,
                )
            
            assert "authentication" in str(exc_info.value).lower()


class TestSubmitQuery:
    """Tests for submit_query method."""

    def test_submit_query_success(self, client):
        """submit_query should return job ID on success."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {
                "id": "job-12345",
            }
            
            job_id = client.submit_query(
                query='#event_simpleName="ProcessRollup2"',
                start_time="-7d",
            )
            
            assert job_id == "job-12345"

    def test_submit_query_with_cid_filter(self, client):
        """submit_query should include CID filter when provided."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {"id": "job-123"}
            
            client.submit_query(
                query='#event_simpleName="ProcessRollup2"',
                start_time="-7d",
                cids=["cid1", "cid2"],
            )
            
            call_args = mock_request.call_args
            payload = call_args[1]["json"]
            # Should have CID filter prepended
            assert "cid" in payload["queryString"].lower()

    def test_submit_query_request_structure(self, client):
        """submit_query should send correct request structure."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {"id": "job-123"}
            
            client.submit_query(
                query='#event_simpleName="Test"',
                start_time="-24h",
                end_time="now",
            )
            
            call_args = mock_request.call_args
            assert call_args[1]["method"] == "POST"
            assert "queryjobs" in call_args[1]["endpoint"]
            
            payload = call_args[1]["json"]
            assert "queryString" in payload
            assert "start" in payload
            assert "end" in payload

    def test_submit_query_failure(self, client):
        """submit_query should raise QuerySubmissionError on failure."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.side_effect = CrowdStrikeError("API error")
            
            with pytest.raises(QuerySubmissionError):
                client.submit_query(
                    query='#event_simpleName="Test"',
                    start_time="-7d",
                )


class TestGetQueryStatus:
    """Tests for get_query_status method."""

    def test_get_query_status_running(self, client):
        """get_query_status should return status for running query."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {
                "done": False,
                "metaData": {
                    "eventCount": 500,
                    "processedEvents": 10000,
                },
            }
            
            status = client.get_query_status("job-123")
            
            assert status["done"] is False
            assert status["metaData"]["eventCount"] == 500

    def test_get_query_status_completed(self, client):
        """get_query_status should return done=True when complete."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {
                "done": True,
                "metaData": {
                    "eventCount": 1500,
                    "processedEvents": 50000,
                },
            }
            
            status = client.get_query_status("job-123")
            
            assert status["done"] is True
            assert status["metaData"]["eventCount"] == 1500

    def test_get_query_status_failure(self, client):
        """get_query_status should raise QueryStatusError on failure."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.side_effect = CrowdStrikeError("Job not found")
            
            with pytest.raises(QueryStatusError):
                client.get_query_status("nonexistent-job")


class TestGetQueryResults:
    """Tests for get_query_results method."""

    def test_get_query_results_success(self, client, sample_events):
        """get_query_results should return events."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {
                "done": True,
                "events": sample_events,
                "metaData": {"eventCount": len(sample_events)},
            }
            
            result = client.get_query_results("job-123")
            
            assert result["events"] == sample_events
            assert len(result["events"]) == 3

    def test_get_query_results_empty(self, client):
        """get_query_results should handle empty results."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {
                "done": True,
                "events": [],
                "metaData": {"eventCount": 0},
            }
            
            result = client.get_query_results("job-123")
            
            assert result["events"] == []

    def test_get_query_results_with_pagination(self, client):
        """get_query_results should handle paginated results."""
        with patch.object(client, "_make_request") as mock_request:
            # First call returns partial results
            mock_request.return_value = {
                "done": True,
                "events": [{"id": 1}, {"id": 2}],
                "metaData": {"eventCount": 100},
            }
            
            result = client.get_query_results("job-123")
            
            # Should return what's available
            assert len(result["events"]) == 2


class TestCancelQuery:
    """Tests for cancel_query method."""

    def test_cancel_query_success(self, client):
        """cancel_query should successfully cancel a running query."""
        with patch.object(client, "_make_request") as mock_request:
            mock_request.return_value = {}
            
            # Should not raise
            client.cancel_query("job-123")
            
            call_args = mock_request.call_args
            assert call_args[1]["method"] == "DELETE"

    def test_cancel_query_already_complete(self, client):
        """cancel_query should handle already-complete queries gracefully."""
        with patch.object(client, "_make_request") as mock_request:
            # Even if the query is done, cancel should not raise
            mock_request.return_value = {}
            
            client.cancel_query("completed-job")


class TestBuildCIDFilter:
    """Tests for _build_cid_filter helper."""

    def test_build_cid_filter_single_cid(self, client):
        """_build_cid_filter should handle single CID."""
        filter_str = client._build_cid_filter(["abc123"])
        
        assert "cid" in filter_str.lower()
        assert "abc123" in filter_str

    def test_build_cid_filter_multiple_cids(self, client):
        """_build_cid_filter should handle multiple CIDs."""
        filter_str = client._build_cid_filter(["cid1", "cid2", "cid3"])
        
        assert "cid1" in filter_str
        assert "cid2" in filter_str
        assert "cid3" in filter_str

    def test_build_cid_filter_empty_list(self, client):
        """_build_cid_filter should return empty string for empty list."""
        filter_str = client._build_cid_filter([])
        
        assert filter_str == ""


class TestTokenRefresh:
    """Tests for token refresh handling."""

    def test_token_refresh_on_expiry(self, mock_credentials, mock_cs_config):
        """Client should refresh token when expired."""
        with patch("arbitrary_queries.client.OAuth2") as mock_oauth:
            mock_instance = MagicMock()
            mock_instance.token.return_value = {
                "status_code": 201,
                "body": {"access_token": "initial-token", "expires_in": 1800},
            }
            mock_oauth.return_value = mock_instance
            
            client = CrowdStrikeClient(
                credentials=mock_credentials,
                config=mock_cs_config,
            )
            
            # Simulate token expiry and refresh
            mock_instance.token.return_value = {
                "status_code": 201,
                "body": {"access_token": "refreshed-token", "expires_in": 1800},
            }
            
            client._refresh_token()
            
            assert client._access_token == "refreshed-token"
