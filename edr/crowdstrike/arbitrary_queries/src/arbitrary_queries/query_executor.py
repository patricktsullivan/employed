"""
Async query execution and polling for NG-SIEM Hunter.

Handles concurrent query execution with configurable limits,
polling with timeout handling, and retry logic for transient failures.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from arbitrary_queries.client import CrowdStrikeClient, QuerySubmissionError, QueryStatusError
from arbitrary_queries.config import QueryDefaults, ConcurrencyConfig
from arbitrary_queries.models import (
    CIDInfo,
    QueryJob,
    QueryJobStatus,
    QueryResult,
)


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
        poll_interval: Seconds between status polls.
        timeout: Maximum seconds to wait for query completion.
        max_concurrent: Maximum concurrent queries.
        retry_attempts: Number of retry attempts on failure.
        retry_delay: Seconds to wait between retries.
    """
    
    client: CrowdStrikeClient
    poll_interval: int = 60
    timeout: int = 3600
    max_concurrent: int = 50
    retry_attempts: int = 3
    retry_delay: float = 5.0
    default_time_range: str = "-7d"
    
    def __init__(
        self,
        client: CrowdStrikeClient,
        query_defaults: QueryDefaults,
        concurrency_config: ConcurrencyConfig,
    ):
        """
        Initialize QueryExecutor.
        
        Args:
            client: CrowdStrike API client.
            query_defaults: Default query settings.
            concurrency_config: Concurrency and retry settings.
        """
        self.client = client
        self.poll_interval = query_defaults.poll_interval_seconds
        self.timeout = query_defaults.timeout_seconds
        self.default_time_range = query_defaults.time_range
        self.max_concurrent = concurrency_config.max_concurrent_queries
        self.retry_attempts = concurrency_config.retry_attempts
        self.retry_delay = concurrency_config.retry_delay_seconds
    
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
        start = start_time or self.default_time_range
        cids = [info.cid for info in cid_infos]
        
        # Submit single query for all CIDs
        job_id = self.client.submit_query(
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
        
        return QueryResult(
            cid="batch",
            cid_name=f"Batch ({len(cid_infos)} CIDs)",
            events=events,
            record_count=len(events),
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
        Returns a list of QueryResults, one per CID.
        
        Args:
            cid_infos: List of CIDs to query.
            query: The query string.
            start_time: Start time (uses default if not specified).
            end_time: End time (default "now").
        
        Returns:
            List of QueryResults, one per CID.
        """
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
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
        QueryResult with events or error information.
    """
    start = start_time or executor.default_time_range
    last_error: Exception | None = None
    
    for attempt in range(executor.retry_attempts + 1):
        try:
            # Submit query
            job_id = executor.client.submit_query(
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
            
            return QueryResult(
                cid=cid_info.cid,
                cid_name=cid_info.name,
                events=events,
                record_count=len(events),
            )
        
        except (QuerySubmissionError, QueryStatusError, QueryTimeoutError) as e:
            last_error = e
            if attempt < executor.retry_attempts:
                await asyncio.sleep(executor.retry_delay)
    
    # All retries exhausted, return error result
    return _create_error_result(cid_info, last_error)


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
    
    while True:
        # Check timeout
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > executor.timeout:
            # Try to cancel the query
            try:
                executor.client.cancel_query(job_id)
            except Exception:
                pass
            raise QueryTimeoutError(
                f"Query {job_id} timed out after {elapsed:.1f} seconds"
            )
        
        # Get status
        status = executor.client.get_query_status(job_id)
        
        if status.get("done", False):
            return status
        
        # Wait before next poll
        await asyncio.sleep(executor.poll_interval)


def _create_error_result(cid_info: CIDInfo, error: Exception | None) -> QueryResult:
    """
    Create a QueryResult representing a failed query.
    
    Note: QueryResult is frozen, so we use a subclass or wrapper for errors.
    For simplicity, we'll add error info to a modified result.
    """
    # Create a result-like object with error
    # Since QueryResult is frozen, we'll create a new class dynamically
    # or use composition. For now, return a QueryResult with a special marker.
    
    @dataclass(frozen=True)
    class ErrorQueryResult(QueryResult):
        """QueryResult with error information."""
        error: str | None = None
    
    return ErrorQueryResult(
        cid=cid_info.cid,
        cid_name=cid_info.name,
        events=[],
        record_count=0,
        error=str(error) if error else "Unknown error",
    )
