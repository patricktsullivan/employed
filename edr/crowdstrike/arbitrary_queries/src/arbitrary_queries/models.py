"""
Data models for NG-SIEM Hunter.

Contains data classes for query results, job tracking, and execution summaries.

Thread Safety:
    Most models are immutable (frozen) for thread safety during concurrent execution.
    The exception is QueryJob, which requires mutable state for status updates during
    query polling. When sharing QueryJob instances across threads, external
    synchronization is required.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ExecutionMode(Enum):
    """Query execution mode."""
    
    BATCH = "batch"
    ITERATIVE = "iterative"


class QueryJobStatus(Enum):
    """Status of a query job."""
    
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    
    @property
    def is_terminal(self) -> bool:
        """Return True if this is a final state (no more transitions)."""
        return self in (
            QueryJobStatus.COMPLETED,
            QueryJobStatus.FAILED,
            QueryJobStatus.TIMEOUT,
        )


@dataclass(frozen=True, slots=True)
class CIDInfo:
    """
    Information about a CrowdStrike Customer ID (CID).
    
    Attributes:
        cid: The CrowdStrike Customer ID.
        name: Human-readable customer name.
    """
    
    cid: str
    name: str
    
    def __str__(self) -> str:
        """Return user-friendly string representation."""
        return f"{self.name} ({self.cid})"


@dataclass(slots=True)
class QueryJob:
    """
    Tracks an in-flight NG-SIEM query job.
    
    Note:
        This class is intentionally NOT frozen to allow status updates during
        query polling. When sharing instances across threads, use external
        synchronization.
    
    Attributes:
        job_id: The unique job ID returned by CrowdStrike.
        cid: The CID this job is querying.
        query: The query string being executed.
        status: Current status of the job.
        started_at: When the job was submitted.
        completed_at: When the job finished (if terminal).
        error: Error message if the job failed.
    """
    
    job_id: str
    cid: str
    query: str
    status: QueryJobStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    
    @property
    def duration_seconds(self) -> float:
        """
        Calculate job duration in seconds.
        
        If job is still running, calculates from start to now.
        If job is complete, calculates from start to completion.
        Returns 0.0 if start time is not set.
        """
        if self.started_at is None:
            return 0.0
        
        end_time = self.completed_at or datetime.now(timezone.utc)
        delta = end_time - self.started_at
        return delta.total_seconds()


@dataclass(frozen=True, slots=True)
class QueryResult:
    """
    Results from a completed query for a single CID.
    
    Attributes:
        cid: The CID that was queried.
        cid_name: Human-readable customer name.
        events: List of event dictionaries returned by the query.
        record_count: Total number of records returned.
    
    Raises:
        ValueError: If record_count doesn't match len(events).
    """
    
    cid: str
    cid_name: str
    events: tuple[dict[str, Any], ...]  # Tuple for true immutability
    record_count: int
    
    def __post_init__(self) -> None:
        """Validate that record_count matches events length."""
        if self.record_count != len(self.events):
            raise ValueError(
                f"record_count ({self.record_count}) must match "
                f"len(events) ({len(self.events)})"
            )
    
    @property
    def is_empty(self) -> bool:
        """Return True if no events were returned."""
        return len(self.events) == 0
    
    def preview(self, count: int = 10) -> tuple[dict[str, Any], ...]:
        """
        Return first N events for preview display.
        
        Args:
            count: Maximum number of events to return. Must be non-negative.
            
        Returns:
            Tuple of up to `count` events.
        
        Raises:
            ValueError: If count is negative.
        """
        if count < 0:
            raise ValueError(f"count must be non-negative, got {count}")
        return self.events[:count]


@dataclass(frozen=True, slots=True)
class QuerySummary:
    """
    Execution summary for a single CID query.
    
    Attributes:
        cid: The CID that was queried.
        cid_name: Human-readable customer name.
        record_count: Number of records returned.
        execution_time_seconds: How long the query took.
        status: Final status of the query.
        error: Error message if query failed.
        warnings: Tuple of warning messages (immutable).
    
    Raises:
        ValueError: If record_count or execution_time_seconds is negative.
    """
    
    cid: str
    cid_name: str
    record_count: int
    execution_time_seconds: float
    status: QueryJobStatus
    error: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)  # Tuple for true immutability
    
    def __post_init__(self) -> None:
        """Validate non-negative numeric fields."""
        if self.record_count < 0:
            raise ValueError(f"record_count must be non-negative, got {self.record_count}")
        if self.execution_time_seconds < 0:
            raise ValueError(
                f"execution_time_seconds must be non-negative, got {self.execution_time_seconds}"
            )
    
    @property
    def has_error(self) -> bool:
        """Return True if the query failed with an error."""
        return self.error is not None


@dataclass(frozen=True, slots=True)
class OverallSummary:
    """
    Aggregated summary across all queried CIDs.
    
    Attributes:
        total_cids: Total number of CIDs queried.
        successful_cids: Number of CIDs with successful queries.
        failed_cids: Number of CIDs with failed queries.
        total_records: Total records across all queries.
        total_execution_time_seconds: Total time for all queries.
        mode: Whether this was batch or iterative execution.
        cid_summaries: Per-CID summaries (immutable tuple).
    
    Raises:
        ValueError: If successful_cids + failed_cids != total_cids,
                   or if any count is negative.
    """
    
    total_cids: int
    successful_cids: int
    failed_cids: int
    total_records: int
    total_execution_time_seconds: float
    mode: ExecutionMode
    cid_summaries: tuple[QuerySummary, ...] = field(default_factory=tuple)  # Tuple for true immutability
    
    def __post_init__(self) -> None:
        """Validate summary arithmetic and non-negative fields."""
        # Validate non-negative values
        if self.total_cids < 0:
            raise ValueError(f"total_cids must be non-negative, got {self.total_cids}")
        if self.successful_cids < 0:
            raise ValueError(f"successful_cids must be non-negative, got {self.successful_cids}")
        if self.failed_cids < 0:
            raise ValueError(f"failed_cids must be non-negative, got {self.failed_cids}")
        if self.total_records < 0:
            raise ValueError(f"total_records must be non-negative, got {self.total_records}")
        if self.total_execution_time_seconds < 0:
            raise ValueError(
                f"total_execution_time_seconds must be non-negative, "
                f"got {self.total_execution_time_seconds}"
            )
        
        # Validate arithmetic consistency
        if self.successful_cids + self.failed_cids != self.total_cids:
            raise ValueError(
                f"successful_cids ({self.successful_cids}) + failed_cids ({self.failed_cids}) "
                f"must equal total_cids ({self.total_cids})"
            )
    
    @property
    def success_rate(self) -> float:
        """
        Calculate percentage of successful CID queries.
        
        Returns:
            Success rate as a percentage (0.0 to 100.0).
            Returns 0.0 if no CIDs were queried.
        """
        if self.total_cids == 0:
            return 0.0
        return (self.successful_cids / self.total_cids) * 100.0


# Factory functions for easier construction with lists
def create_query_result(
    cid: str,
    cid_name: str,
    events: list[dict[str, Any]],
) -> QueryResult:
    """
    Create a QueryResult from a list of events.
    
    Convenience factory that converts the events list to a tuple
    and sets record_count automatically.
    
    Args:
        cid: The CID that was queried.
        cid_name: Human-readable customer name.
        events: List of event dictionaries.
    
    Returns:
        QueryResult with events as a tuple.
    """
    events_tuple = tuple(events)
    return QueryResult(
        cid=cid,
        cid_name=cid_name,
        events=events_tuple,
        record_count=len(events_tuple),
    )


def create_query_summary(
    cid: str,
    cid_name: str,
    record_count: int,
    execution_time_seconds: float,
    status: QueryJobStatus,
    error: str | None = None,
    warnings: list[str] | None = None,
) -> QuerySummary:
    """
    Create a QuerySummary with optional list-based warnings.
    
    Convenience factory that converts the warnings list to a tuple.
    
    Args:
        cid: The CID that was queried.
        cid_name: Human-readable customer name.
        record_count: Number of records returned.
        execution_time_seconds: How long the query took.
        status: Final status of the query.
        error: Error message if query failed.
        warnings: List of warning messages (will be converted to tuple).
    
    Returns:
        QuerySummary with warnings as a tuple.
    """
    return QuerySummary(
        cid=cid,
        cid_name=cid_name,
        record_count=record_count,
        execution_time_seconds=execution_time_seconds,
        status=status,
        error=error,
        warnings=tuple(warnings) if warnings else (),
    )


def create_overall_summary(
    total_cids: int,
    successful_cids: int,
    failed_cids: int,
    total_records: int,
    total_execution_time_seconds: float,
    mode: ExecutionMode,
    cid_summaries: list[QuerySummary] | None = None,
) -> OverallSummary:
    """
    Create an OverallSummary with optional list-based cid_summaries.
    
    Convenience factory that converts the cid_summaries list to a tuple.
    
    Args:
        total_cids: Total number of CIDs queried.
        successful_cids: Number of CIDs with successful queries.
        failed_cids: Number of CIDs with failed queries.
        total_records: Total records across all queries.
        total_execution_time_seconds: Total time for all queries.
        mode: Whether this was batch or iterative execution.
        cid_summaries: List of per-CID summaries (will be converted to tuple).
    
    Returns:
        OverallSummary with cid_summaries as a tuple.
    """
    return OverallSummary(
        total_cids=total_cids,
        successful_cids=successful_cids,
        failed_cids=failed_cids,
        total_records=total_records,
        total_execution_time_seconds=total_execution_time_seconds,
        mode=mode,
        cid_summaries=tuple(cid_summaries) if cid_summaries else (),
    )
