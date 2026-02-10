"""
Tests for arbitrary_queries.query_executor module.

Tests async query execution, polling, and result collection.
"""

import pytest
import asyncio
from dataclasses import FrozenInstanceError
from typing import Any
from unittest.mock import MagicMock, AsyncMock

from arbitrary_queries.query_executor import (
    QueryExecutor,
    execute_query,
    poll_until_complete,
    QueryTimeoutError,
)
from arbitrary_queries.models import (
    QueryResult,
    CIDInfo,
)
from arbitrary_queries.config import QueryDefaults, ConcurrencyConfig
from arbitrary_queries.client import QuerySubmissionError, QueryStatusError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_events():
    """Sample event data for testing."""
    return [
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "event_simpleName": "ProcessRollup2",
            "aid": "agent-001",
        },
        {
            "timestamp": "2024-01-01T00:01:00Z",
            "event_simpleName": "NetworkConnect",
            "aid": "agent-002",
        },
        {
            "timestamp": "2024-01-01T00:02:00Z",
            "event_simpleName": "FileWrite",
            "aid": "agent-001",
        },
    ]


@pytest.fixture
def mock_client() -> Any:
    """Create a mock CrowdStrike client with async methods."""
    client = MagicMock()
    # All client methods are async, so use AsyncMock
    client.submit_query = AsyncMock(return_value="job-12345")
    client.get_query_status = AsyncMock(
        return_value={
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }
    )
    client.get_query_results = AsyncMock(
        return_value={
            "done": True,
            "events": [{"test": "event"}],
            "metaData": {"eventCount": 1},
        }
    )
    client.cancel_query = AsyncMock()
    client.close = AsyncMock()
    return client


@pytest.fixture
def query_defaults():
    """Query defaults for testing."""
    return QueryDefaults(
        time_range="-7d",
        poll_interval_seconds=0.01,  # Fast polling for tests
        timeout_seconds=10.0,
    )


@pytest.fixture
def concurrency_config():
    """Concurrency config for testing."""
    return ConcurrencyConfig(
        max_concurrent_queries=5,
        retry_attempts=2,
        retry_delay_seconds=0.01,  # Fast retries for tests
    )


@pytest.fixture
def executor(mock_client, query_defaults, concurrency_config) -> Any:
    """Create a QueryExecutor for testing."""
    return QueryExecutor(
        client=mock_client,
        query_defaults=query_defaults,
        concurrency_config=concurrency_config,
    )


@pytest.fixture
def sample_cid_infos():
    """Sample CID info list."""
    return [
        CIDInfo(cid="cid1", name="Customer 1"),
        CIDInfo(cid="cid2", name="Customer 2"),
        CIDInfo(cid="cid3", name="Customer 3"),
    ]


# =============================================================================
# QueryExecutor Initialization Tests
# =============================================================================


class TestQueryExecutorInit:
    """Tests for QueryExecutor initialization."""

    def test_executor_init(self, mock_client, query_defaults, concurrency_config):
        """QueryExecutor should initialize with client and config objects."""
        executor = QueryExecutor(
            client=mock_client,
            query_defaults=query_defaults,
            concurrency_config=concurrency_config,
        )

        assert executor.client is mock_client
        assert executor.query_defaults is query_defaults
        assert executor.concurrency_config is concurrency_config

    def test_executor_accesses_config_values(self, mock_client):
        """QueryExecutor should access config values through config objects."""
        query_defaults = QueryDefaults(
            time_range="-24h",
            poll_interval_seconds=30,
            timeout_seconds=1800,
        )
        concurrency_config = ConcurrencyConfig(
            max_concurrent_queries=100,
            retry_attempts=5,
            retry_delay_seconds=10,
        )

        executor = QueryExecutor(
            client=mock_client,
            query_defaults=query_defaults,
            concurrency_config=concurrency_config,
        )

        # Values accessed through config objects
        assert executor.query_defaults.time_range == "-24h"
        assert executor.query_defaults.poll_interval_seconds == 30
        assert executor.query_defaults.timeout_seconds == 1800
        assert executor.concurrency_config.max_concurrent_queries == 100
        assert executor.concurrency_config.retry_attempts == 5
        assert executor.concurrency_config.retry_delay_seconds == 10


# =============================================================================
# execute_query Tests
# =============================================================================


class TestExecuteQuery:
    """Tests for execute_query function."""

    @pytest.mark.asyncio
    async def test_execute_query_success(self, executor, sample_events):
        """execute_query should return QueryResult on success."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": sample_events,
            "metaData": {"eventCount": len(sample_events)},
        }

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="test-cid", name="Test Customer"),
            query='#event_simpleName="ProcessRollup2"',
        )

        assert isinstance(result, QueryResult)
        assert result.cid == "test-cid"
        assert result.cid_name == "Test Customer"
        assert result.record_count == 3
        assert not result.has_error

    @pytest.mark.asyncio
    async def test_execute_query_tracks_timing(self, executor):
        """execute_query should record per-query execution time."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="Name"),
            query="test",
        )

        # Execution time should be positive (even if very small)
        assert result.execution_time_seconds >= 0.0

    @pytest.mark.asyncio
    async def test_execute_query_with_time_range(self, executor):
        """execute_query should use provided time range."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }

        await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="Name"),
            query="test",
            start_time="-24h",
            end_time="-1h",
        )

        call_kwargs = executor.client.submit_query.call_args.kwargs
        assert call_kwargs["start_time"] == "-24h"
        assert call_kwargs["end_time"] == "-1h"

    @pytest.mark.asyncio
    async def test_execute_query_uses_defaults(self, executor):
        """execute_query should use default time range when not specified."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }

        await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="Name"),
            query="test",
        )

        call_kwargs = executor.client.submit_query.call_args.kwargs
        assert call_kwargs["start_time"] == "-7d"

    @pytest.mark.asyncio
    async def test_execute_query_passes_cid(self, executor):
        """execute_query should pass CID to client."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }

        await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="specific-cid", name="Name"),
            query="test",
        )

        call_kwargs = executor.client.submit_query.call_args.kwargs
        assert call_kwargs["cids"] == ["specific-cid"]


# =============================================================================
# poll_until_complete Tests
# =============================================================================


class TestPollUntilComplete:
    """Tests for poll_until_complete function."""

    @pytest.mark.asyncio
    async def test_poll_completes_immediately(self, executor):
        """poll_until_complete should return immediately if done."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [{"test": "data"}],
            "metaData": {"eventCount": 1},
        }

        result = await poll_until_complete(
            executor=executor,
            job_id="job-123",
        )

        assert result["done"] is True
        executor.client.get_query_status.assert_called_once_with("job-123")

    @pytest.mark.asyncio
    async def test_poll_waits_for_completion(self, executor):
        """poll_until_complete should poll until done."""
        # First two calls return running, third returns done
        executor.client.get_query_status.side_effect = [
            {"done": False, "metaData": {"eventCount": 0}},
            {"done": False, "metaData": {"eventCount": 50}},
            {"done": True, "events": [], "metaData": {"eventCount": 100}},
        ]

        result = await poll_until_complete(
            executor=executor,
            job_id="job-123",
        )

        assert result["done"] is True
        assert executor.client.get_query_status.call_count == 3

    @pytest.mark.asyncio
    async def test_poll_timeout(self, mock_client, concurrency_config):
        """poll_until_complete should raise QueryTimeoutError on timeout."""
        # Create executor with very short timeout
        short_timeout_defaults = QueryDefaults(
            time_range="-7d",
            poll_interval_seconds=0.02,
            timeout_seconds=0.05,
        )
        executor = QueryExecutor(
            client=mock_client,
            query_defaults=short_timeout_defaults,
            concurrency_config=concurrency_config,
        )

        # Always return not done
        mock_client.get_query_status.return_value = {
            "done": False,
            "metaData": {"eventCount": 0},
        }

        with pytest.raises(QueryTimeoutError) as exc_info:
            await poll_until_complete(
                executor=executor,
                job_id="job-123",
            )

        assert "job-123" in str(exc_info.value)
        assert "timed out" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_poll_timeout_attempts_cancel(self, mock_client, concurrency_config):
        """poll_until_complete should try to cancel query on timeout."""
        short_timeout_defaults = QueryDefaults(
            time_range="-7d",
            poll_interval_seconds=0.02,
            timeout_seconds=0.05,
        )
        executor = QueryExecutor(
            client=mock_client,
            query_defaults=short_timeout_defaults,
            concurrency_config=concurrency_config,
        )

        mock_client.get_query_status.return_value = {
            "done": False,
            "metaData": {"eventCount": 0},
        }

        with pytest.raises(QueryTimeoutError):
            await poll_until_complete(
                executor=executor,
                job_id="job-cancel-test",
            )

        mock_client.cancel_query.assert_called_once_with("job-cancel-test")


# =============================================================================
# Batch Mode Tests
# =============================================================================


class TestRunBatch:
    """Tests for run_batch method."""

    @pytest.mark.asyncio
    async def test_run_batch_success(self, executor, sample_cid_infos, sample_events):
        """run_batch should consolidate events into a single QueryResult."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": sample_events,
            "metaData": {"eventCount": len(sample_events)},
        }

        result = await executor.run_batch(
            cid_infos=sample_cid_infos,
            query="test",
        )

        assert isinstance(result, QueryResult)
        assert result.cid == "batch"
        assert result.record_count == 3
        assert not result.has_error
        assert result.execution_time_seconds >= 0.0

    @pytest.mark.asyncio
    async def test_run_batch_submits_all_cids(self, executor, sample_cid_infos):
        """run_batch should include all CIDs in the query."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }

        await executor.run_batch(
            cid_infos=sample_cid_infos,
            query="test",
        )

        call_kwargs = executor.client.submit_query.call_args.kwargs
        assert call_kwargs["cids"] == ["cid1", "cid2", "cid3"]


# =============================================================================
# Iterative Mode Tests
# =============================================================================


class TestRunIterative:
    """Tests for run_iterative method."""

    @pytest.mark.asyncio
    async def test_run_iterative_success(self, executor, sample_cid_infos, sample_events):
        """run_iterative should return one QueryResult per CID."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": sample_events,
            "metaData": {"eventCount": len(sample_events)},
        }

        results = await executor.run_iterative(
            cid_infos=sample_cid_infos,
            query="test",
        )

        assert len(results) == 3
        assert all(isinstance(r, QueryResult) for r in results)

    @pytest.mark.asyncio
    async def test_run_iterative_partial_failure(self, executor, sample_cid_infos):
        """run_iterative should return error results for failed CIDs."""
        call_count = 0

        async def mock_submit(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            cids = kwargs.get("cids", [])
            if cids and cids[0] == "cid1":
                raise QuerySubmissionError("Rate limited")
            return f"job-{call_count}"

        executor.client.submit_query = mock_submit
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }

        results = await executor.run_iterative(
            cid_infos=sample_cid_infos,
            query="test",
        )

        # Should have 3 results total
        assert len(results) == 3

        # Identify failed and successful results using the unified QueryResult
        errors = [r for r in results if r.has_error]
        successes = [r for r in results if not r.has_error]

        assert len(errors) == 1
        assert len(successes) == 2
        assert errors[0].cid == "cid1"
        assert errors[0].error is not None
        assert "Rate limited" in errors[0].error

    @pytest.mark.asyncio
    async def test_run_iterative_empty_cids(self, executor):
        """run_iterative should handle empty CID list."""
        results = await executor.run_iterative(
            cid_infos=[],
            query="test",
        )

        assert results == []
        executor.client.submit_query.assert_not_called()


# =============================================================================
# Retry Logic Tests
# =============================================================================


class TestRetryLogic:
    """Tests for retry logic in query execution."""

    @pytest.mark.asyncio
    async def test_retry_on_transient_failure(self, executor):
        """Executor should retry on transient failures."""
        # Fail twice, then succeed
        executor.client.submit_query.side_effect = [
            QuerySubmissionError("Temporary error"),
            QuerySubmissionError("Temporary error"),
            "job-123",
        ]
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="Name"),
            query="test",
        )

        # Should have succeeded after retries
        assert isinstance(result, QueryResult)
        assert not result.has_error
        assert executor.client.submit_query.call_count == 3

    @pytest.mark.asyncio
    async def test_retry_exhausted(self, executor):
        """Executor should give up after max retries."""
        # Always fail
        executor.client.submit_query.side_effect = QuerySubmissionError("Permanent error")

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="Name"),
            query="test",
        )

        # Should have failed result with error — using unified QueryResult
        assert isinstance(result, QueryResult)
        assert result.has_error
        assert result.error is not None
        assert "Permanent error" in result.error
        assert result.record_count == 0

        # Should have tried retry_attempts + 1 times
        expected_attempts = executor.concurrency_config.retry_attempts + 1
        assert executor.client.submit_query.call_count == expected_attempts

    @pytest.mark.asyncio
    async def test_retry_on_status_error(self, executor):
        """Executor should retry on QueryStatusError."""
        executor.client.submit_query.return_value = "job-123"
        # Fail status check twice, then succeed
        executor.client.get_query_status.side_effect = [
            QueryStatusError("Status check failed"),
            QueryStatusError("Status check failed"),
            {"done": True, "events": [], "metaData": {"eventCount": 0}},
        ]

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="Name"),
            query="test",
        )

        assert isinstance(result, QueryResult)
        assert not result.has_error

    @pytest.mark.asyncio
    async def test_retry_on_timeout(self, mock_client):
        """Executor should retry on QueryTimeoutError."""
        # Very short timeout to trigger timeout on first attempt
        short_timeout_defaults = QueryDefaults(
            time_range="-7d",
            poll_interval_seconds=0.02,
            timeout_seconds=0.05,
        )
        fast_retry_config = ConcurrencyConfig(
            max_concurrent_queries=5,
            retry_attempts=2,
            retry_delay_seconds=0.01,
        )
        executor = QueryExecutor(
            client=mock_client,
            query_defaults=short_timeout_defaults,
            concurrency_config=fast_retry_config,
        )

        call_count = 0

        async def mock_status(job_id):
            nonlocal call_count
            call_count += 1
            # First few calls timeout, then complete
            if call_count <= 3:
                return {"done": False}
            return {"done": True, "events": [], "metaData": {"eventCount": 0}}

        mock_client.get_query_status = mock_status

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="Name"),
            query="test",
        )

        # Should have eventually succeeded after retry
        assert isinstance(result, QueryResult)


# =============================================================================
# Error Result Tests (formerly ErrorQueryResult)
# =============================================================================


class TestErrorResults:
    """Tests for error results using the unified QueryResult.
    
    Previously, error results used a separate ErrorQueryResult class.
    Now they use QueryResult with the error field set. This keeps the
    type system clean and avoids duck-typing in downstream code.
    """

    @pytest.mark.asyncio
    async def test_error_result_has_error_field(self, executor):
        """Failed queries should populate the error field on QueryResult."""
        executor.client.submit_query.side_effect = QuerySubmissionError("Connection refused")

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="test-cid", name="Test Customer"),
            query="test",
        )

        assert result.has_error
        assert result.error is not None
        assert "Connection refused" in result.error
        assert result.cid == "test-cid"
        assert result.cid_name == "Test Customer"
        assert result.record_count == 0
        assert result.events == ()

    @pytest.mark.asyncio
    async def test_error_result_is_frozen(self, executor):
        """Error QueryResults should be immutable (same as success results)."""
        executor.client.submit_query.side_effect = QuerySubmissionError("Error")

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="name"),
            query="test",
        )

        with pytest.raises(FrozenInstanceError):
            setattr(result, "error", "new error")

    @pytest.mark.asyncio
    async def test_error_result_tracks_timing(self, executor):
        """Error results should still track execution time."""
        executor.client.submit_query.side_effect = QuerySubmissionError("Timeout")

        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="name"),
            query="test",
        )

        assert result.has_error
        assert result.execution_time_seconds >= 0.0

    def test_successful_result_has_no_error(self):
        """Successful QueryResult should have error=None."""
        result = QueryResult(
            cid="cid", cid_name="name",
            events=({"data": "test"},), record_count=1,
        )

        assert not result.has_error
        assert result.error is None
