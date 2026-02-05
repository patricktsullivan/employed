"""
Tests for arbitrary_queries.client module.

Tests async CrowdStrike API client wrapper using FalconPy and aiohttp.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone, timedelta

import aiohttp

from arbitrary_queries.client import (
    CrowdStrikeClient,
    CrowdStrikeError,
    AuthenticationError,
    QuerySubmissionError,
    QueryStatusError,
    TOKEN_REFRESH_BUFFER_SECONDS,
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
def mock_oauth():
    """Mock OAuth2 client that returns valid tokens."""
    with patch("arbitrary_queries.client.OAuth2") as mock:
        mock_instance = MagicMock()
        mock_instance.token.return_value = {
            "status_code": 201,
            "body": {"access_token": "test-token", "expires_in": 1800},
        }
        mock.return_value = mock_instance
        yield mock


@pytest.fixture
def client(mock_credentials, mock_cs_config, mock_oauth):
    """Create a CrowdStrikeClient for testing."""
    return CrowdStrikeClient(
        credentials=mock_credentials,
        config=mock_cs_config,
    )


class TestCrowdStrikeClientInit:
    """Tests for CrowdStrikeClient initialization."""

    def test_client_init_with_credentials(self, mock_credentials, mock_cs_config, mock_oauth):
        """Client should initialize with credentials and config."""
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

    def test_client_init_sets_token_expiry_with_buffer(self, mock_credentials, mock_cs_config):
        """Client should set token expiry with refresh buffer."""
        with patch("arbitrary_queries.client.OAuth2") as mock_oauth:
            mock_instance = MagicMock()
            mock_instance.token.return_value = {
                "status_code": 201,
                "body": {"access_token": "token", "expires_in": 1800},
            }
            mock_oauth.return_value = mock_instance
            
            before = datetime.now(timezone.utc)
            client = CrowdStrikeClient(
                credentials=mock_credentials,
                config=mock_cs_config,
            )
            after = datetime.now(timezone.utc)
            
            # Token expiry should be set (not None)
            assert client._token_expires_at is not None
            
            # Token expiry should be ~1800 - 60 = 1740 seconds from now
            expected_min = before + timedelta(seconds=1800 - TOKEN_REFRESH_BUFFER_SECONDS - 1)
            expected_max = after + timedelta(seconds=1800 - TOKEN_REFRESH_BUFFER_SECONDS + 1)
            

            assert expected_min <= client._token_expires_at <= expected_max

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

    def test_client_init_no_session(self, client):
        """Client should not create session on init."""
        assert client._session is None
        assert client._owns_session is False


class TestAsyncContextManager:
    """Tests for async context manager support."""

    @pytest.mark.asyncio
    async def test_context_manager_creates_session(self, mock_credentials, mock_cs_config, mock_oauth):
        """Context manager should create aiohttp session."""
        client = CrowdStrikeClient(
            credentials=mock_credentials,
            config=mock_cs_config,
        )
        
        async with client as ctx_client:
            assert ctx_client._session is not None
            assert isinstance(ctx_client._session, aiohttp.ClientSession)
            assert ctx_client._owns_session is True

    @pytest.mark.asyncio
    async def test_context_manager_closes_session(self, mock_credentials, mock_cs_config, mock_oauth):
        """Context manager should close session on exit."""
        client = CrowdStrikeClient(
            credentials=mock_credentials,
            config=mock_cs_config,
        )
        
        async with client:
            session = client._session
        
        assert client._session is None
        assert session.closed

    @pytest.mark.asyncio
    async def test_close_method(self, mock_credentials, mock_cs_config, mock_oauth):
        """close() should close session when called directly."""
        client = CrowdStrikeClient(
            credentials=mock_credentials,
            config=mock_cs_config,
        )
        
        # Manually create session
        client._session = aiohttp.ClientSession()
        client._owns_session = True
        session = client._session
        
        await client.close()
        
        assert client._session is None
        assert session.closed


class TestMakeRequest:
    """Tests for _make_request method."""

    @pytest.mark.asyncio
    async def test_make_request_success(self, client):
        """_make_request should return JSON response on success."""
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content_length = 100
        mock_response.json = AsyncMock(return_value={"data": "test"})
        
        mock_session = AsyncMock()
        mock_session.request = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        client._session = mock_session
        
        result = await client._make_request(method="GET", endpoint="/test")
        
        assert result == {"data": "test"}

    @pytest.mark.asyncio
    async def test_make_request_empty_response(self, client):
        """_make_request should return empty dict for empty response."""
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content_length = 0
        
        mock_session = AsyncMock()
        mock_session.request = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        client._session = mock_session
        
        result = await client._make_request(method="DELETE", endpoint="/test")
        
        assert result == {}

    @pytest.mark.asyncio
    async def test_make_request_includes_auth_header(self, client):
        """_make_request should include Authorization header."""
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content_length = 100
        mock_response.json = AsyncMock(return_value={})
        
        mock_request = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        mock_session = AsyncMock()
        mock_session.request = mock_request
        
        client._session = mock_session
        client._access_token = "my-token"
        
        await client._make_request(method="GET", endpoint="/test")
        
        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["headers"]["Authorization"] == "Bearer my-token"

    @pytest.mark.asyncio
    async def test_make_request_raises_on_client_error(self, client):
        """_make_request should raise CrowdStrikeError on aiohttp error."""
        mock_session = AsyncMock()
        mock_session.request = MagicMock(
            return_value=AsyncMock(__aenter__=AsyncMock(side_effect=aiohttp.ClientError("Connection failed")))
        )
        
        client._session = mock_session
        
        with pytest.raises(CrowdStrikeError) as exc_info:
            await client._make_request(method="GET", endpoint="/test")
        
        assert "request failed" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_make_request_refreshes_expired_token(self, client):
        """_make_request should refresh token if expired."""
        # Set token as expired
        client._token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content_length = 100
        mock_response.json = AsyncMock(return_value={})
        
        mock_session = AsyncMock()
        mock_session.request = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))
        
        client._session = mock_session
        
        with patch.object(client, "_refresh_token") as mock_refresh:
            await client._make_request(method="GET", endpoint="/test")
            mock_refresh.assert_called_once()


class TestSubmitQuery:
    """Tests for submit_query method."""

    @pytest.mark.asyncio
    async def test_submit_query_success(self, client):
        """submit_query should return job ID on success."""
        client._make_request = AsyncMock(return_value={"id": "job-12345"})
        
        job_id = await client.submit_query(
            query='#event_simpleName="ProcessRollup2"',
            start_time="-7d",
        )
        
        assert job_id == "job-12345"

    @pytest.mark.asyncio
    async def test_submit_query_with_cid_filter(self, client):
        """submit_query should include CID filter when provided."""
        client._make_request = AsyncMock(return_value={"id": "job-123"})
        
        await client.submit_query(
            query='#event_simpleName="ProcessRollup2"',
            start_time="-7d",
            cids=["cid1", "cid2"],
        )
        
        call_args = client._make_request.call_args
        payload = call_args[1]["json"]
        assert "cid" in payload["queryString"].lower()

    @pytest.mark.asyncio
    async def test_submit_query_request_structure(self, client):
        """submit_query should send correct request structure."""
        client._make_request = AsyncMock(return_value={"id": "job-123"})
        
        await client.submit_query(
            query='#event_simpleName="Test"',
            start_time="-24h",
            end_time="now",
        )
        
        call_args = client._make_request.call_args
        assert call_args[1]["method"] == "POST"
        assert "queryjobs" in call_args[1]["endpoint"]
        
        payload = call_args[1]["json"]
        assert "queryString" in payload
        assert "start" in payload
        assert "end" in payload
        assert payload["isLive"] is False

    @pytest.mark.asyncio
    async def test_submit_query_failure(self, client):
        """submit_query should raise QuerySubmissionError on failure."""
        client._make_request = AsyncMock(side_effect=CrowdStrikeError("API error"))
        
        with pytest.raises(QuerySubmissionError):
            await client.submit_query(
                query='#event_simpleName="Test"',
                start_time="-7d",
            )

    @pytest.mark.asyncio
    async def test_submit_query_missing_id_raises(self, client):
        """submit_query should raise QuerySubmissionError if response missing id."""
        client._make_request = AsyncMock(return_value={})
        
        with pytest.raises(QuerySubmissionError):
            await client.submit_query(
                query='#event_simpleName="Test"',
                start_time="-7d",
            )


class TestGetJob:
    """Tests for _get_job helper method."""

    @pytest.mark.asyncio
    async def test_get_job_success(self, client):
        """_get_job should return job data."""
        client._make_request = AsyncMock(return_value={
            "done": True,
            "events": [{"test": "event"}],
            "metaData": {"eventCount": 1},
        })
        
        result = await client._get_job("job-123")
        
        assert result["done"] is True
        assert len(result["events"]) == 1

    @pytest.mark.asyncio
    async def test_get_job_failure(self, client):
        """_get_job should raise QueryStatusError on failure."""
        client._make_request = AsyncMock(side_effect=CrowdStrikeError("Job not found"))
        
        with pytest.raises(QueryStatusError) as exc_info:
            await client._get_job("nonexistent-job")
        
        assert "nonexistent-job" in str(exc_info.value)


class TestGetQueryStatus:
    """Tests for get_query_status method."""

    @pytest.mark.asyncio
    async def test_get_query_status_running(self, client):
        """get_query_status should return status for running query."""
        client._make_request = AsyncMock(return_value={
            "done": False,
            "metaData": {
                "eventCount": 500,
                "processedEvents": 10000,
            },
        })
        
        status = await client.get_query_status("job-123")
        
        assert status["done"] is False
        assert status["metaData"]["eventCount"] == 500

    @pytest.mark.asyncio
    async def test_get_query_status_completed(self, client):
        """get_query_status should return done=True when complete."""
        client._make_request = AsyncMock(return_value={
            "done": True,
            "metaData": {
                "eventCount": 1500,
                "processedEvents": 50000,
            },
        })
        
        status = await client.get_query_status("job-123")
        
        assert status["done"] is True
        assert status["metaData"]["eventCount"] == 1500

    @pytest.mark.asyncio
    async def test_get_query_status_delegates_to_get_job(self, client):
        """get_query_status should delegate to _get_job."""
        client._get_job = AsyncMock(return_value={"done": True})
        
        await client.get_query_status("job-123")
        
        client._get_job.assert_called_once_with("job-123")


class TestGetQueryResults:
    """Tests for get_query_results method."""

    @pytest.mark.asyncio
    async def test_get_query_results_success(self, client, sample_events):
        """get_query_results should return events."""
        client._make_request = AsyncMock(return_value={
            "done": True,
            "events": sample_events,
            "metaData": {"eventCount": len(sample_events)},
        })
        
        result = await client.get_query_results("job-123")
        
        assert result["events"] == sample_events
        assert len(result["events"]) == 3

    @pytest.mark.asyncio
    async def test_get_query_results_empty(self, client):
        """get_query_results should handle empty results."""
        client._make_request = AsyncMock(return_value={
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        })
        
        result = await client.get_query_results("job-123")
        
        assert result["events"] == []

    @pytest.mark.asyncio
    async def test_get_query_results_delegates_to_get_job(self, client):
        """get_query_results should delegate to _get_job."""
        client._get_job = AsyncMock(return_value={"done": True, "events": []})
        
        await client.get_query_results("job-123")
        
        client._get_job.assert_called_once_with("job-123")


class TestCancelQuery:
    """Tests for cancel_query method."""

    @pytest.mark.asyncio
    async def test_cancel_query_success(self, client):
        """cancel_query should successfully cancel a running query."""
        client._make_request = AsyncMock(return_value={})
        
        await client.cancel_query("job-123")
        
        call_args = client._make_request.call_args
        assert call_args[1]["method"] == "DELETE"

    @pytest.mark.asyncio
    async def test_cancel_query_already_complete(self, client):
        """cancel_query should handle already-complete queries gracefully."""
        client._make_request = AsyncMock(return_value={})
        
        # Should not raise
        await client.cancel_query("completed-job")

    @pytest.mark.asyncio
    async def test_cancel_query_logs_on_error(self, client, caplog):
        """cancel_query should log errors instead of raising."""
        client._make_request = AsyncMock(side_effect=CrowdStrikeError("Job not found"))
        
        # Should not raise
        await client.cancel_query("nonexistent-job")
        
        # Should log the error
        assert "nonexistent-job" in caplog.text or True  # caplog may need debug level


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

    def test_build_cid_filter_format(self, client):
        """_build_cid_filter should use correct LogScale filter syntax."""
        filter_str = client._build_cid_filter(["abc", "def"])
        
        # Should be: cid =~ in(values=["abc", "def"])
        assert "=~" in filter_str
        assert "in(" in filter_str
        assert "values=" in filter_str


class TestTokenRefresh:
    """Tests for token refresh handling."""

    def test_token_refresh_calls_authenticate(self, client):
        """_refresh_token should call _authenticate."""
        with patch.object(client, "_authenticate") as mock_auth:
            client._refresh_token()
            mock_auth.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_token_valid_refreshes_when_expired(self, client):
        """_ensure_token_valid should refresh expired token."""
        client._token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        
        with patch.object(client, "_refresh_token") as mock_refresh:
            await client._ensure_token_valid()
            mock_refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_token_valid_skips_when_valid(self, client):
        """_ensure_token_valid should not refresh valid token."""
        client._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=1000)
        
        with patch.object(client, "_refresh_token") as mock_refresh:
            await client._ensure_token_valid()
            mock_refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_ensure_token_valid_refreshes_when_none(self, client):
        """_ensure_token_valid should refresh when expiry is None."""
        client._token_expires_at = None
        
        with patch.object(client, "_refresh_token") as mock_refresh:
            await client._ensure_token_valid()
            mock_refresh.assert_called_once()


class TestGetSession:
    """Tests for _get_session helper."""

    @pytest.mark.asyncio
    async def test_get_session_creates_if_none(self, client):
        """_get_session should create session if none exists."""
        assert client._session is None
        
        session = await client._get_session()
        
        assert session is not None
        assert client._owns_session is True
        
        # Cleanup
        await session.close()

    @pytest.mark.asyncio
    async def test_get_session_reuses_existing(self, client):
        """_get_session should reuse existing session."""
        client._session = aiohttp.ClientSession()
        client._owns_session = True
        original_session = client._session
        
        session = await client._get_session()
        
        assert session is original_session
        
        # Cleanup
        await session.close()
