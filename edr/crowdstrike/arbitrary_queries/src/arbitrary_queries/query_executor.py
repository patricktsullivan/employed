"""
Async query execution and polling for Arbitrary Queries.

Handles concurrent query execution with configurable limits,
polling with timeout handling, and retry logic for transient failures.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from arbitrary_queries.client import (
    CrowdStrikeClient,
    QuerySubmissionError,
    QueryStatusError,
)
from arbitrary_queries.config import QueryDefaults, ConcurrencyConfig
from arbitrary_queries.models import (
    CIDInfo,
    QueryResult,
)


logger = logging.getLogger(__name__)


class QueryTimeoutError(Exception):
    """Raised when a query exceeds the configured timeout."""

    pass


@dataclass
class QueryExecutor:
    """
    Async query executor for NG-SIEM queries.

    Handles concurrent query execution, polling, and result collection.
    Supports both batch mode (single query for all CIDs) and iterative
    mode (separate query per CID).

    Attributes:
        client: CrowdStrike API client.
        query_defaults: Default query settings (time range, polling, timeout).
        concurrency_config: Concurrency and retry settings.
    """

    client: CrowdStrikeClient
    query_defaults: QueryDefaults
    concurrency_config: ConcurrencyConfig

    async def run_batch(
        self,
        cid_infos: list[CIDInfo],
        query: str,
        start_time: str | None = None,
        end_time: str = "now",
    ) -> QueryResult:
        """
        Execute a single query across all CIDs (batch mode).

        Submits one query with a CID filter for all provided CIDs.
        Results are consolidated into a single QueryResult.

        Args:
            cid_infos: List of CIDs to query.
            query: The query string.
            start_time: Start time (uses default if not specified).
            end_time: End time (default "now").

        Returns:
            QueryResult with consolidated events from all CIDs.
        """
        query_start = datetime.now(timezone.utc)
        start = start_time or self.query_defaults.time_range
        cids = [info.cid for info in cid_infos]

        # Submit single query for all CIDs
        job_id = await self.client.submit_query(
            query=query,
            start_time=start,
            end_time=end_time,
            cids=cids,
        )

        # Poll until complete
        result = await poll_until_complete(
            executor=self,
            job_id=job_id,
        )

        events = result.get("events", [])
        elapsed = (datetime.now(timezone.utc) - query_start).total_seconds()

        return QueryResult(
            cid="batch",
            cid_name=f"Batch ({len(cid_infos)} CIDs)",
            events=events,
            record_count=len(events),
            execution_time_seconds=elapsed,
        )

    async def run_iterative(
        self,
        cid_infos: list[CIDInfo],
        query: str,
        start_time: str | None = None,
        end_time: str = "now",
    ) -> list[QueryResult]:
        """
        Execute separate queries per CID (iterative mode).

        Submits individual queries for each CID with controlled concurrency.
        Returns a list of QueryResults, one per CID. Failed queries are
        represented as QueryResult instances with the ``error`` field set.

        Args:
            cid_infos: List of CIDs to query.
            query: The query string.
            start_time: Start time (uses default if not specified).
            end_time: End time (default "now").

        Returns:
            List of QueryResults, one per CID (check ``has_error`` for failures).
        """
        semaphore = asyncio.Semaphore(self.concurrency_config.max_concurrent_queries)

        async def run_with_semaphore(cid_info: CIDInfo) -> QueryResult:
            async with semaphore:
                return await execute_query(
                    executor=self,
                    cid_info=cid_info,
                    query=query,
                    start_time=start_time,
                    end_time=end_time,
                )

        tasks = [run_with_semaphore(cid_info) for cid_info in cid_infos]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        return list(results)


async def execute_query(
    executor: QueryExecutor,
    cid_info: CIDInfo,
    query: str,
    start_time: str | None = None,
    end_time: str = "now",
) -> QueryResult:
    """
    Execute a single query for one CID with retry logic.

    Args:
        executor: The QueryExecutor instance.
        cid_info: CID information.
        query: The query string.
        start_time: Start time (uses default if not specified).
        end_time: End time.

    Returns:
        QueryResult with events on success, or with error field set on failure.
    """
    query_start = datetime.now(timezone.utc)
    start = start_time or executor.query_defaults.time_range
    last_error: Exception | None = None
    retry_attempts = executor.concurrency_config.retry_attempts
    retry_delay = executor.concurrency_config.retry_delay_seconds

    for attempt in range(retry_attempts + 1):
        try:
            # Submit query
            job_id = await executor.client.submit_query(
                query=query,
                start_time=start,
                end_time=end_time,
                cids=[cid_info.cid],
            )

            # Poll until complete
            result = await poll_until_complete(
                executor=executor,
                job_id=job_id,
            )

            events = result.get("events", [])
            elapsed = (datetime.now(timezone.utc) - query_start).total_seconds()

            return QueryResult(
                cid=cid_info.cid,
                cid_name=cid_info.name,
                events=events,
                record_count=len(events),
                execution_time_seconds=elapsed,
            )

        except (QuerySubmissionError, QueryStatusError, QueryTimeoutError) as e:
            last_error = e
            if attempt < retry_attempts:
                logger.warning(
                    f"Query attempt {attempt + 1} failed for CID {cid_info.cid}: {e}. "
                    f"Retrying in {retry_delay}s..."
                )
                await asyncio.sleep(retry_delay)

    # All retries exhausted, return error result
    elapsed = (datetime.now(timezone.utc) - query_start).total_seconds()
    logger.error(
        f"Query failed for CID {cid_info.cid} after {retry_attempts + 1} attempts: {last_error}"
    )
    return _create_error_result(cid_info, last_error, elapsed)


async def poll_until_complete(
    executor: QueryExecutor,
    job_id: str,
) -> dict[str, Any]:
    """
    Poll query status until completion or timeout.

    Args:
        executor: The QueryExecutor instance.
        job_id: The job ID to poll.

    Returns:
        Final status/results dictionary.

    Raises:
        QueryTimeoutError: If query exceeds timeout.
    """
    start_time = datetime.now(timezone.utc)
    timeout = executor.query_defaults.timeout_seconds
    poll_interval = executor.query_defaults.poll_interval_seconds

    while True:
        # Check timeout
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > timeout:
            # Try to cancel the query (best effort)
            try:
                await executor.client.cancel_query(job_id)
            except Exception as e:
                logger.warning(f"Failed to cancel timed-out query {job_id}: {e}")

            raise QueryTimeoutError(
                f"Query {job_id} timed out after {elapsed:.1f} seconds"
            )

        # Get status
        status = await executor.client.get_query_status(job_id)

        if status.get("done", False):
            return status

        # Wait before next poll
        await asyncio.sleep(poll_interval)


def _create_error_result(
    cid_info: CIDInfo,
    error: Exception | None,
    execution_time_seconds: float = 0.0,
) -> QueryResult:
    """
    Create a QueryResult representing a failed query.

    Uses the unified QueryResult with the error field set, rather than a
    separate error class. This keeps the type system clean and avoids
    duck-typing with getattr() in downstream code.

    Args:
        cid_info: The CID information for the failed query.
        error: The exception that caused the failure.
        execution_time_seconds: Wall-clock time spent on this query.

    Returns:
        QueryResult with error details and an empty event tuple.
    """
    return QueryResult(
        cid=cid_info.cid,
        cid_name=cid_info.name,
        events=(),
        record_count=0,
        error=str(error) if error else "Unknown error",
        execution_time_seconds=execution_time_seconds,
    )
