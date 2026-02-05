"""
Tests for arbitrary_queries.query_executor module.

Tests async query execution, polling, and result collection.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone

from arbitrary_queries.query_executor import (
    QueryExecutor,
    execute_query,
    poll_until_complete,
    QueryTimeoutError,
)
from arbitrary_queries.models import (
    QueryJob,
    QueryJobStatus,
    QueryResult,
    CIDInfo,
)
from arbitrary_queries.config import QueryDefaults, ConcurrencyConfig


@pytest.fixture
def mock_client():
    """Create a mock CrowdStrike client."""
    client = MagicMock()
    client.submit_query = MagicMock(return_value="job-12345")
    client.get_query_status = MagicMock(return_value={
        "done": True,
        "events": [],
        "metaData": {"eventCount": 0},
    })
    client.get_query_results = MagicMock(return_value={
        "done": True,
        "events": [{"test": "event"}],
        "metaData": {"eventCount": 1},
    })
    client.cancel_query = MagicMock()
    return client


@pytest.fixture
def query_defaults():
    """Query defaults for testing."""
    return QueryDefaults(
        time_range="-7d",
        poll_interval_seconds=1,  # Fast polling for tests
        timeout_seconds=10,
    )


@pytest.fixture
def concurrency_config():
    """Concurrency config for testing."""
    return ConcurrencyConfig(
        max_concurrent_queries=5,
        retry_attempts=2,
        retry_delay_seconds=0.1,
    )


@pytest.fixture
def executor(mock_client, query_defaults, concurrency_config):
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


class TestQueryExecutorInit:
    """Tests for QueryExecutor initialization."""

    def test_executor_init(self, mock_client, query_defaults, concurrency_config):
        """QueryExecutor should initialize with client and config."""
        executor = QueryExecutor(
            client=mock_client,
            query_defaults=query_defaults,
            concurrency_config=concurrency_config,
        )
        
        assert executor.client == mock_client
        assert executor.poll_interval == 1
        assert executor.timeout == 10
        assert executor.max_concurrent == 5


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
        executor.client.get_query_results.return_value = {
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
        
        call_args = executor.client.submit_query.call_args
        assert call_args[1]["start_time"] == "-24h"
        assert call_args[1]["end_time"] == "-1h"

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
        
        call_args = executor.client.submit_query.call_args
        assert call_args[1]["start_time"] == "-7d"


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

    @pytest.mark.asyncio
    async def test_poll_waits_for_completion(self, executor):
        """poll_until_complete should poll until done."""
        # First call returns running, second returns done
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
    async def test_poll_timeout(self, executor):
        """poll_until_complete should raise QueryTimeoutError on timeout."""
        # Always return not done
        executor.client.get_query_status.return_value = {
            "done": False,
            "metaData": {"eventCount": 0},
        }
        
        # Override timeout to be very short
        executor.timeout = 0.5
        executor.poll_interval = 0.2
        
        with pytest.raises(QueryTimeoutError):
            await poll_until_complete(
                executor=executor,
                job_id="job-123",
            )


class TestQueryExecutorRunBatch:
    """Tests for QueryExecutor.run_batch method."""

    @pytest.mark.asyncio
    async def test_run_batch_single_query(self, executor, sample_cid_infos, sample_events):
        """run_batch should execute single query for all CIDs."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": sample_events,
            "metaData": {"eventCount": len(sample_events)},
        }
        executor.client.get_query_results.return_value = {
            "done": True,
            "events": sample_events,
            "metaData": {"eventCount": len(sample_events)},
        }
        
        result = await executor.run_batch(
            cid_infos=sample_cid_infos,
            query='#event_simpleName="Test"',
        )
        
        # Batch mode returns single QueryResult
        assert isinstance(result, QueryResult)
        # Query should have been submitted with all CIDs
        call_args = executor.client.submit_query.call_args
        assert len(call_args[1]["cids"]) == 3


class TestQueryExecutorRunIterative:
    """Tests for QueryExecutor.run_iterative method."""

    @pytest.mark.asyncio
    async def test_run_iterative_multiple_queries(self, executor, sample_cid_infos):
        """run_iterative should execute separate query per CID."""
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [{"test": "event"}],
            "metaData": {"eventCount": 1},
        }
        
        results = await executor.run_iterative(
            cid_infos=sample_cid_infos,
            query='#event_simpleName="Test"',
        )
        
        # Iterative mode returns list of QueryResults
        assert isinstance(results, list)
        assert len(results) == 3
        # Each result should have different CID
        cids = {r.cid for r in results}
        assert cids == {"cid1", "cid2", "cid3"}

    @pytest.mark.asyncio
    async def test_run_iterative_respects_concurrency(self, executor, sample_cid_infos):
        """run_iterative should respect max_concurrent limit."""
        call_count = 0
        max_concurrent_seen = 0
        current_concurrent = 0
        
        async def mock_submit(*args, **kwargs):
            nonlocal call_count, max_concurrent_seen, current_concurrent
            call_count += 1
            current_concurrent += 1
            max_concurrent_seen = max(max_concurrent_seen, current_concurrent)
            await asyncio.sleep(0.1)
            current_concurrent -= 1
            return f"job-{call_count}"
        
        executor.client.submit_query = mock_submit
        executor.client.get_query_status.return_value = {
            "done": True,
            "events": [],
            "metaData": {"eventCount": 0},
        }
        
        # Create more CIDs than max_concurrent
        many_cids = [CIDInfo(cid=f"cid{i}", name=f"Customer {i}") for i in range(10)]
        executor.max_concurrent = 3
        
        await executor.run_iterative(
            cid_infos=many_cids,
            query="test",
        )
        
        # Should have limited concurrency
        assert max_concurrent_seen <= 3

    @pytest.mark.asyncio
    async def test_run_iterative_handles_partial_failures(self, executor, sample_cid_infos):
        """run_iterative should continue on partial failures."""
        from arbitrary_queries.client import QuerySubmissionError
        
        call_count = {"value": 0}
        
        def mock_submit(*args, **kwargs):
            call_count["value"] += 1
            cids = kwargs.get("cids", [])
            if cids and cids[0] == "cid1":
                raise QuerySubmissionError("Rate limited")
            return f"job-{call_count['value']}"
        
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
        
        # Should have 3 results (1 failed after retries, 2 succeeded)
        assert len(results) == 3
        # One should have error
        errors = [r for r in results if hasattr(r, 'error') and r.error]
        successes = [r for r in results if not (hasattr(r, 'error') and r.error)]
        assert len(errors) == 1
        assert len(successes) == 2


class TestRetryLogic:
    """Tests for retry logic in query execution."""

    @pytest.mark.asyncio
    async def test_retry_on_transient_failure(self, executor):
        """Executor should retry on transient failures."""
        from arbitrary_queries.client import QuerySubmissionError
        
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
        assert executor.client.submit_query.call_count == 3

    @pytest.mark.asyncio
    async def test_retry_exhausted(self, executor):
        """Executor should give up after max retries."""
        from arbitrary_queries.client import QuerySubmissionError
        
        # Always fail
        executor.client.submit_query.side_effect = QuerySubmissionError("Permanent error")
        
        result = await execute_query(
            executor=executor,
            cid_info=CIDInfo(cid="cid", name="Name"),
            query="test",
        )
        
        # Should have failed result with error
        assert result.error is not None
        assert result.record_count == 0
