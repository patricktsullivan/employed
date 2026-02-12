"""
Tests for arbitrary_queries.client module.

Tests the async CrowdStrike API client wrapper built on FalconPy's NGSIEM
service class. All FalconPy calls are mocked — no network access required.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from arbitrary_queries.client import (
    CrowdStrikeClient,
    CrowdStrikeError,
    AuthenticationError,
    QuerySubmissionError,
    QueryStatusError,
)
from arbitrary_queries.secrets import Credentials
from arbitrary_queries.config import CrowdStrikeConfig


# =============================================================================
# Fixtures
# =============================================================================


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
def mock_falcon():
    """Mock FalconPy NGSIEM service class."""
    with patch("arbitrary_queries.client.NGSIEM") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def client(mock_credentials, mock_cs_config, mock_falcon):
    """Create a CrowdStrikeClient with mocked FalconPy backend."""
    return CrowdStrikeClient(
        credentials=mock_credentials,
        config=mock_cs_config,
    )


# =============================================================================
# Helpers
# =============================================================================


def falcon_response(status_code: int, body: dict) -> dict:
    """Build a FalconPy-style response dict."""
    return {"status_code": status_code, "headers": {}, "body": body}


# =============================================================================
# CrowdStrikeClient Init
# =============================================================================


class TestCrowdStrikeClientInit:
    """Tests for CrowdStrikeClient initialization."""

    def test_init_stores_base_url_and_repository(
        self, mock_credentials, mock_cs_config, mock_falcon
    ):
        """Client should store base_url and repository from config."""
        client = CrowdStrikeClient(
            credentials=mock_credentials,
            config=mock_cs_config,
        )

        assert client.base_url == "https://api.laggar.gcw.crowdstrike.com"
        assert client.repository == "search-all"

    def test_init_creates_ngsiem_instance(self, mock_credentials, mock_cs_config):
        """Client should create NGSIEM instance with credentials."""
        with patch("arbitrary_queries.client.NGSIEM") as mock_cls:
            CrowdStrikeClient(
                credentials=mock_credentials,
                config=mock_cs_config,
            )

            mock_cls.assert_called_once_with(
                client_id="test-client-id",
                client_secret="test-client-secret",
                base_url="https://api.laggar.gcw.crowdstrike.com",
            )

    def test_init_defers_authentication(self, client, mock_falcon):
        """Client should not call any API methods during init."""
        mock_falcon.start_search.assert_not_called()
        mock_falcon.get_search_status.assert_not_called()
        mock_falcon.stop_search.assert_not_called()


# =============================================================================
# _as_dict
# =============================================================================


class TestAsDict:
    """Tests for _as_dict static method."""

    def test_as_dict_passthrough_for_dict(self):
        """_as_dict should return a dict unchanged."""
        resp = {"status_code": 200, "body": {"id": "abc"}}

        assert CrowdStrikeClient._as_dict(resp) is resp

    def test_as_dict_extracts_full_return_from_result(self):
        """_as_dict should use full_return for non-dict responses."""
        mock_result = MagicMock()
        mock_result.full_return = {"status_code": 200, "body": {"id": "abc"}}

        result = CrowdStrikeClient._as_dict(mock_result)

        assert result == {"status_code": 200, "body": {"id": "abc"}}


# =============================================================================
# _check_response
# =============================================================================


class TestCheckResponse:
    """Tests for _check_response method."""

    def test_check_response_returns_body_on_200(self, client):
        """_check_response should return body dict on HTTP 200."""
        resp = falcon_response(200, {"id": "job-123", "done": False})

        body = client._check_response(resp, "Test operation")

        assert body == {"id": "job-123", "done": False}

    def test_check_response_returns_body_on_201(self, client):
        """_check_response should return body dict on HTTP 201."""
        resp = falcon_response(201, {"id": "job-456"})

        body = client._check_response(resp, "Test operation")

        assert body == {"id": "job-456"}

    def test_check_response_raises_auth_error_on_401(self, client):
        """_check_response should raise AuthenticationError on HTTP 401."""
        resp = falcon_response(
            401,
            {"errors": [{"message": "access denied"}]},
        )

        with pytest.raises(AuthenticationError) as exc_info:
            client._check_response(resp, "Query submission")

        assert "401" in str(exc_info.value)
        assert "access denied" in str(exc_info.value)

    def test_check_response_raises_auth_error_on_403(self, client):
        """_check_response should raise AuthenticationError on HTTP 403."""
        resp = falcon_response(
            403,
            {"errors": [{"message": "insufficient scope"}]},
        )

        with pytest.raises(AuthenticationError) as exc_info:
            client._check_response(resp, "Query submission")

        assert "403" in str(exc_info.value)
        assert "insufficient scope" in str(exc_info.value)

    def test_check_response_includes_http_status_in_auth_error(self, client):
        """_check_response should include HTTP status code in AuthenticationError."""
        resp = falcon_response(403, {"errors": [{"message": "forbidden"}]})

        with pytest.raises(AuthenticationError) as exc_info:
            client._check_response(resp, "Query submission")

        assert "HTTP 403" in str(exc_info.value)

    def test_check_response_raises_crowdstrike_error_on_500(self, client):
        """_check_response should raise CrowdStrikeError on HTTP 500."""
        resp = falcon_response(
            500,
            {"errors": [{"message": "internal server error"}]},
        )

        with pytest.raises(CrowdStrikeError) as exc_info:
            client._check_response(resp, "Query status")

        assert "500" in str(exc_info.value)

    def test_check_response_handles_empty_body(self, client):
        """_check_response should produce readable error for empty body."""
        resp = falcon_response(401, {})

        with pytest.raises(AuthenticationError) as exc_info:
            client._check_response(resp, "Query submission")

        # Should NOT be just "Query submission: {}"
        assert "Empty response body" in str(exc_info.value)

    def test_check_response_handles_empty_errors_list(self, client):
        """_check_response should fall back to str(body) when errors list is empty."""
        resp = falcon_response(429, {"errors": [], "message": "rate limited"})

        with pytest.raises(CrowdStrikeError) as exc_info:
            client._check_response(resp, "Query submission")

        assert "rate limited" in str(exc_info.value)

    def test_check_response_handles_missing_status_code(self, client):
        """_check_response should treat missing status_code as failure."""
        resp = {"body": {"id": "abc"}}

        with pytest.raises(CrowdStrikeError):
            client._check_response(resp, "Test operation")

    def test_check_response_logs_debug_on_success(self, client, caplog):
        """_check_response should log response at DEBUG level."""
        resp = falcon_response(200, {"id": "job-123"})

        import logging

        with caplog.at_level(logging.DEBUG, logger="arbitrary_queries.client"):
            client._check_response(resp, "Test operation")

        assert "200" in caplog.text
        assert "Test operation" in caplog.text

    def test_check_response_logs_error_on_auth_failure(self, client, caplog):
        """_check_response should log at ERROR level on auth failure."""
        resp = falcon_response(
            403, {"errors": [{"message": "forbidden"}]}
        )

        import logging

        with caplog.at_level(logging.ERROR, logger="arbitrary_queries.client"):
            with pytest.raises(AuthenticationError):
                client._check_response(resp, "Query submission")

        assert "authorization failure" in caplog.text.lower()


# =============================================================================
# _normalize_time
# =============================================================================


class TestNormalizeTime:
    """Tests for _normalize_time static method."""

    def test_strips_dash_from_relative_days(self):
        """_normalize_time should strip leading dash from '-7d'."""
        assert CrowdStrikeClient._normalize_time("-7d") == "7d"

    def test_strips_dash_from_relative_hours(self):
        """_normalize_time should strip leading dash from '-24h'."""
        assert CrowdStrikeClient._normalize_time("-24h") == "24h"

    def test_strips_dash_from_relative_minutes(self):
        """_normalize_time should strip leading dash from '-30m'."""
        assert CrowdStrikeClient._normalize_time("-30m") == "30m"

    def test_strips_dash_from_relative_seconds(self):
        """_normalize_time should strip leading dash from '-300s'."""
        assert CrowdStrikeClient._normalize_time("-300s") == "300s"

    def test_strips_dash_from_relative_weeks(self):
        """_normalize_time should strip leading dash from '-2w'."""
        assert CrowdStrikeClient._normalize_time("-2w") == "2w"

    def test_passes_through_positive_relative(self):
        """_normalize_time should not modify already-correct '7d'."""
        assert CrowdStrikeClient._normalize_time("7d") == "7d"

    def test_passes_through_now(self):
        """_normalize_time should not modify 'now'."""
        assert CrowdStrikeClient._normalize_time("now") == "now"

    def test_passes_through_iso_timestamp(self):
        """_normalize_time should not modify ISO 8601 timestamps."""
        ts = "2024-01-01T00:00:00Z"
        assert CrowdStrikeClient._normalize_time(ts) == ts

    def test_passes_through_empty_string(self):
        """_normalize_time should return empty string unchanged."""
        assert CrowdStrikeClient._normalize_time("") == ""

    def test_passes_through_iso_with_negative_offset(self):
        """_normalize_time should not strip dash from ISO timestamps with negative offset."""
        ts = "2024-01-01T00:00:00-05:00"
        assert CrowdStrikeClient._normalize_time(ts) == ts


# =============================================================================
# _build_cid_filter
# =============================================================================


class TestBuildCIDFilter:
    """Tests for _build_cid_filter static method."""

    def test_single_cid(self):
        """_build_cid_filter should handle single CID."""
        result = CrowdStrikeClient._build_cid_filter(["abc123"])

        assert "abc123" in result
        assert "cid" in result.lower()

    def test_multiple_cids(self):
        """_build_cid_filter should include all CIDs."""
        result = CrowdStrikeClient._build_cid_filter(["cid1", "cid2", "cid3"])

        assert "cid1" in result
        assert "cid2" in result
        assert "cid3" in result

    def test_empty_list(self):
        """_build_cid_filter should return empty string for empty list."""
        assert CrowdStrikeClient._build_cid_filter([]) == ""

    def test_logscale_syntax(self):
        """_build_cid_filter should use LogScale in() filter syntax."""
        result = CrowdStrikeClient._build_cid_filter(["abc", "def"])

        assert "=~" in result
        assert "in(" in result
        assert "values=" in result


# =============================================================================
# submit_query
# =============================================================================


class TestSubmitQuery:
    """Tests for submit_query method."""

    @pytest.mark.asyncio
    async def test_submit_query_success(self, client, mock_falcon):
        """submit_query should return job ID on success."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"id": "job-12345"}
        )

        job_id = await client.submit_query(
            query='#event_simpleName="ProcessRollup2"',
            start_time="-7d",
        )

        assert job_id == "job-12345"

    @pytest.mark.asyncio
    async def test_submit_query_passes_correct_args(self, client, mock_falcon):
        """submit_query should pass correct arguments to FalconPy."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"id": "job-123"}
        )

        await client.submit_query(
            query='#event_simpleName="Test"',
            start_time="24h",
            end_time="1h",
        )

        mock_falcon.start_search.assert_called_once_with(
            repository="search-all",
            query_string='#event_simpleName="Test"',
            start="24h",
            end="1h",
            is_live=False,
        )

    @pytest.mark.asyncio
    async def test_submit_query_normalizes_dashed_start(self, client, mock_falcon):
        """submit_query should strip leading dash from relative start time."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"id": "job-123"}
        )

        await client.submit_query(
            query='#event_simpleName="Test"',
            start_time="-7d",
            end_time="now",
        )

        call_kwargs = mock_falcon.start_search.call_args[1]
        assert call_kwargs["start"] == "7d"
        assert call_kwargs["end"] == "now"

    @pytest.mark.asyncio
    async def test_submit_query_normalizes_dashed_end(self, client, mock_falcon):
        """submit_query should strip leading dash from relative end time."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"id": "job-123"}
        )

        await client.submit_query(
            query='#event_simpleName="Test"',
            start_time="7d",
            end_time="-1h",
        )

        call_kwargs = mock_falcon.start_search.call_args[1]
        assert call_kwargs["end"] == "1h"

    @pytest.mark.asyncio
    async def test_submit_query_preserves_absolute_timestamps(
        self, client, mock_falcon
    ):
        """submit_query should not modify ISO 8601 timestamps."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"id": "job-123"}
        )

        await client.submit_query(
            query='#event_simpleName="Test"',
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-07T23:59:59Z",
        )

        call_kwargs = mock_falcon.start_search.call_args[1]
        assert call_kwargs["start"] == "2024-01-01T00:00:00Z"
        assert call_kwargs["end"] == "2024-01-07T23:59:59Z"

    @pytest.mark.asyncio
    async def test_submit_query_with_cid_filter(self, client, mock_falcon):
        """submit_query should prepend CID filter when CIDs provided."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"id": "job-123"}
        )

        await client.submit_query(
            query='#event_simpleName="Test"',
            start_time="-7d",
            cids=["cid1", "cid2"],
        )

        call_kwargs = mock_falcon.start_search.call_args[1]
        query_string = call_kwargs["query_string"]

        assert "cid" in query_string.lower()
        assert "cid1" in query_string
        assert "cid2" in query_string
        assert '#event_simpleName="Test"' in query_string

    @pytest.mark.asyncio
    async def test_submit_query_no_cid_filter_without_cids(self, client, mock_falcon):
        """submit_query should not add CID filter when cids is None."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"id": "job-123"}
        )

        await client.submit_query(
            query='#event_simpleName="Test"',
            start_time="-7d",
        )

        call_kwargs = mock_falcon.start_search.call_args[1]
        assert call_kwargs["query_string"] == '#event_simpleName="Test"'

    @pytest.mark.asyncio
    async def test_submit_query_auth_error_propagates(self, client, mock_falcon):
        """submit_query should propagate AuthenticationError from _check_response."""
        mock_falcon.start_search.return_value = falcon_response(
            401, {"errors": [{"message": "invalid token"}]}
        )

        with pytest.raises(AuthenticationError):
            await client.submit_query(
                query='#event_simpleName="Test"',
                start_time="-7d",
            )

    @pytest.mark.asyncio
    async def test_submit_query_wraps_non_auth_error(self, client, mock_falcon):
        """submit_query should wrap non-auth CrowdStrikeError as QuerySubmissionError."""
        mock_falcon.start_search.return_value = falcon_response(
            500, {"errors": [{"message": "internal error"}]}
        )

        with pytest.raises(QuerySubmissionError):
            await client.submit_query(
                query='#event_simpleName="Test"',
                start_time="-7d",
            )

    @pytest.mark.asyncio
    async def test_submit_query_missing_job_id(self, client, mock_falcon):
        """submit_query should raise QuerySubmissionError if response has no id."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"status": "ok"}
        )

        with pytest.raises(QuerySubmissionError) as exc_info:
            await client.submit_query(
                query='#event_simpleName="Test"',
                start_time="-7d",
            )

        assert "no job id" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_submit_query_empty_body(self, client, mock_falcon):
        """submit_query should raise QuerySubmissionError for empty body."""
        mock_falcon.start_search.return_value = falcon_response(200, {})

        with pytest.raises(QuerySubmissionError):
            await client.submit_query(
                query='#event_simpleName="Test"',
                start_time="-7d",
            )

    @pytest.mark.asyncio
    async def test_submit_query_default_end_time(self, client, mock_falcon):
        """submit_query should default end_time to 'now'."""
        mock_falcon.start_search.return_value = falcon_response(
            200, {"id": "job-123"}
        )

        await client.submit_query(
            query='#event_simpleName="Test"',
            start_time="-7d",
        )

        call_kwargs = mock_falcon.start_search.call_args[1]
        assert call_kwargs["end"] == "now"


# =============================================================================
# get_query_status
# =============================================================================


class TestGetQueryStatus:
    """Tests for get_query_status method."""

    @pytest.mark.asyncio
    async def test_get_query_status_running(self, client, mock_falcon):
        """get_query_status should return status for running query."""
        mock_falcon.get_search_status.return_value = falcon_response(
            200,
            {
                "done": False,
                "events": [],
                "metaData": {"eventCount": 500, "processedEvents": 10000},
            },
        )

        status = await client.get_query_status("job-123")

        assert status["done"] is False
        assert status["metaData"]["eventCount"] == 500

    @pytest.mark.asyncio
    async def test_get_query_status_completed(self, client, mock_falcon, sample_events):
        """get_query_status should return events when complete."""
        mock_falcon.get_search_status.return_value = falcon_response(
            200,
            {
                "done": True,
                "events": sample_events,
                "metaData": {"eventCount": len(sample_events)},
            },
        )

        status = await client.get_query_status("job-123")

        assert status["done"] is True
        assert len(status["events"]) == 3

    @pytest.mark.asyncio
    async def test_get_query_status_passes_correct_args(self, client, mock_falcon):
        """get_query_status should pass job_id and repository to FalconPy."""
        mock_falcon.get_search_status.return_value = falcon_response(
            200, {"done": True, "events": []}
        )

        await client.get_query_status("job-abc")

        mock_falcon.get_search_status.assert_called_once_with(
            repository="search-all",
            search_id="job-abc",
        )

    @pytest.mark.asyncio
    async def test_get_query_status_raises_query_status_error(
        self, client, mock_falcon
    ):
        """get_query_status should raise QueryStatusError on failure."""
        mock_falcon.get_search_status.return_value = falcon_response(
            500, {"errors": [{"message": "internal error"}]}
        )

        with pytest.raises(QueryStatusError):
            await client.get_query_status("job-123")


# =============================================================================
# get_query_results
# =============================================================================


class TestGetQueryResults:
    """Tests for get_query_results method."""

    @pytest.mark.asyncio
    async def test_get_query_results_delegates_to_get_query_status(
        self, client, mock_falcon
    ):
        """get_query_results should delegate to get_query_status."""
        mock_falcon.get_search_status.return_value = falcon_response(
            200,
            {"done": True, "events": [{"a": 1}]},
        )

        result = await client.get_query_results("job-123")

        assert result["events"] == [{"a": 1}]
        mock_falcon.get_search_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_query_results_empty(self, client, mock_falcon):
        """get_query_results should handle empty results."""
        mock_falcon.get_search_status.return_value = falcon_response(
            200,
            {"done": True, "events": [], "metaData": {"eventCount": 0}},
        )

        result = await client.get_query_results("job-123")

        assert result["events"] == []


# =============================================================================
# cancel_query
# =============================================================================


class TestCancelQuery:
    """Tests for cancel_query method."""

    @pytest.mark.asyncio
    async def test_cancel_query_success(self, client, mock_falcon):
        """cancel_query should call stop_search with correct args."""
        mock_falcon.stop_search.return_value = falcon_response(200, {})

        await client.cancel_query("job-123")

        mock_falcon.stop_search.assert_called_once_with(
            repository="search-all",
            id="job-123",
        )

    @pytest.mark.asyncio
    async def test_cancel_query_logs_warning_on_non_success(
        self, client, mock_falcon, caplog
    ):
        """cancel_query should log warning for non-200/204 status."""
        mock_falcon.stop_search.return_value = falcon_response(
            404, {"errors": [{"message": "not found"}]}
        )

        import logging

        with caplog.at_level(logging.WARNING, logger="arbitrary_queries.client"):
            await client.cancel_query("job-999")

        assert "job-999" in caplog.text
        assert "404" in caplog.text

    @pytest.mark.asyncio
    async def test_cancel_query_does_not_raise(self, client, mock_falcon):
        """cancel_query should not raise even on error responses."""
        mock_falcon.stop_search.return_value = falcon_response(
            500, {"errors": [{"message": "server error"}]}
        )

        # Should not raise
        await client.cancel_query("job-123")

    @pytest.mark.asyncio
    async def test_cancel_query_accepts_204(self, client, mock_falcon, caplog):
        """cancel_query should accept HTTP 204 without warning."""
        mock_falcon.stop_search.return_value = falcon_response(204, {})

        import logging

        with caplog.at_level(logging.WARNING, logger="arbitrary_queries.client"):
            await client.cancel_query("job-123")

        assert "Cancel query" not in caplog.text


# =============================================================================
# close
# =============================================================================


class TestClose:
    """Tests for close method."""

    @pytest.mark.asyncio
    async def test_close_is_noop(self, client):
        """close should complete without error (FalconPy manages its own session)."""
        await client.close()
