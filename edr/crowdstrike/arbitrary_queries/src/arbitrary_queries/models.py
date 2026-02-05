"""
Data models for NG-SIEM Hunter.

Contains data classes for query results, job tracking, and execution summaries.
All models are immutable (frozen) for thread safety during concurrent execution.
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


@dataclass(frozen=True)
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
        return f"CIDInfo(cid={self.cid}, name={self.name})"


@dataclass
class QueryJob:
    """
    Tracks an in-flight NG-SIEM query job.
    
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


@dataclass(frozen=True)
class QueryResult:
    """
    Results from a completed query for a single CID.
    
    Attributes:
        cid: The CID that was queried.
        cid_name: Human-readable customer name.
        events: List of event dictionaries returned by the query.
        record_count: Total number of records returned.
    """
    
    cid: str
    cid_name: str
    events: list[dict[str, Any]]
    record_count: int
    
    @property
    def is_empty(self) -> bool:
        """Return True if no events were returned."""
        return self.record_count == 0
    
    def preview(self, count: int = 10) -> list[dict[str, Any]]:
        """
        Return first N events for preview display.
        
        Args:
            count: Maximum number of events to return.
            
        Returns:
            List of up to `count` events.
        """
        return self.events[:count]


@dataclass(frozen=True)
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
        warnings: List of warning messages.
    """
    
    cid: str
    cid_name: str
    record_count: int
    execution_time_seconds: float
    status: QueryJobStatus
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    
    @property
    def has_error(self) -> bool:
        """Return True if the query failed with an error."""
        return self.error is not None


@dataclass(frozen=True)
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
        cid_summaries: Per-CID summaries (optional).
    """
    
    total_cids: int
    successful_cids: int
    failed_cids: int
    total_records: int
    total_execution_time_seconds: float
    mode: ExecutionMode
    cid_summaries: list[QuerySummary] = field(default_factory=list)
    
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
