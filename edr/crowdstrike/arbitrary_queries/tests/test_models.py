"""
Tests for arbitrary_queries.models module.

Tests data classes for query results, summaries, and configuration.
"""

import pytest
from datetime import datetime, timezone, timedelta
from dataclasses import FrozenInstanceError

from arbitrary_queries.models import (
    CIDInfo,
    QueryJob,
    QueryJobStatus,
    QueryResult,
    QuerySummary,
    OverallSummary,
    ExecutionMode,
)


class TestCIDInfo:
    """Tests for CIDInfo data class."""

    def test_create_cid_info(self, sample_cid, sample_cid_name):
        """CIDInfo should store CID and customer name."""
        cid_info = CIDInfo(cid=sample_cid, name=sample_cid_name)
        
        assert cid_info.cid == sample_cid
        assert cid_info.name == sample_cid_name

    def test_cid_info_is_frozen(self, sample_cid, sample_cid_name):
        """CIDInfo should be immutable."""
        cid_info = CIDInfo(cid=sample_cid, name=sample_cid_name)
        
        with pytest.raises(FrozenInstanceError):
            cid_info.cid = "new_cid"

    def test_cid_info_equality(self, sample_cid, sample_cid_name):
        """CIDInfo instances with same values should be equal."""
        cid1 = CIDInfo(cid=sample_cid, name=sample_cid_name)
        cid2 = CIDInfo(cid=sample_cid, name=sample_cid_name)
        
        assert cid1 == cid2

    def test_cid_info_string_representation(self, sample_cid, sample_cid_name):
        """CIDInfo should have useful string representation."""
        cid_info = CIDInfo(cid=sample_cid, name=sample_cid_name)
        
        assert sample_cid in str(cid_info)
        assert sample_cid_name in str(cid_info)


class TestQueryJobStatus:
    """Tests for QueryJobStatus enum."""

    def test_status_values_exist(self):
        """QueryJobStatus should have expected status values."""
        assert QueryJobStatus.PENDING
        assert QueryJobStatus.RUNNING
        assert QueryJobStatus.COMPLETED
        assert QueryJobStatus.FAILED
        assert QueryJobStatus.TIMEOUT

    def test_status_is_terminal(self):
        """is_terminal should return True for final states."""
        assert QueryJobStatus.COMPLETED.is_terminal is True
        assert QueryJobStatus.FAILED.is_terminal is True
        assert QueryJobStatus.TIMEOUT.is_terminal is True
        assert QueryJobStatus.PENDING.is_terminal is False
        assert QueryJobStatus.RUNNING.is_terminal is False


class TestQueryJob:
    """Tests for QueryJob data class."""

    def test_create_query_job(self, sample_cid, sample_query):
        """QueryJob should track job ID and metadata."""
        job = QueryJob(
            job_id="job-12345",
            cid=sample_cid,
            query=sample_query,
            status=QueryJobStatus.PENDING,
        )
        
        assert job.job_id == "job-12345"
        assert job.cid == sample_cid
        assert job.query == sample_query
        assert job.status == QueryJobStatus.PENDING

    def test_query_job_with_timestamps(self, sample_cid, sample_query, mock_utc_now):
        """QueryJob should track start and end times."""
        job = QueryJob(
            job_id="job-12345",
            cid=sample_cid,
            query=sample_query,
            status=QueryJobStatus.RUNNING,
            started_at=mock_utc_now,
        )
        
        assert job.started_at == mock_utc_now
        assert job.completed_at is None

    def test_query_job_duration_while_running(self, sample_cid, sample_query):
        """Duration should be calculated from start to now while running."""
        start = datetime.now(timezone.utc) - timedelta(seconds=30)
        job = QueryJob(
            job_id="job-12345",
            cid=sample_cid,
            query=sample_query,
            status=QueryJobStatus.RUNNING,
            started_at=start,
        )
        
        # Duration should be approximately 30 seconds (allow some tolerance)
        assert 29 <= job.duration_seconds <= 35

    def test_query_job_duration_when_completed(self, sample_cid, sample_query):
        """Duration should be calculated from start to completion."""
        start = datetime(2026, 2, 4, 12, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 2, 4, 12, 0, 45, tzinfo=timezone.utc)
        
        job = QueryJob(
            job_id="job-12345",
            cid=sample_cid,
            query=sample_query,
            status=QueryJobStatus.COMPLETED,
            started_at=start,
            completed_at=end,
        )
        
        assert job.duration_seconds == 45.0

    def test_query_job_error_tracking(self, sample_cid, sample_query):
        """QueryJob should store error message on failure."""
        job = QueryJob(
            job_id="job-12345",
            cid=sample_cid,
            query=sample_query,
            status=QueryJobStatus.FAILED,
            error="Rate limit exceeded",
        )
        
        assert job.error == "Rate limit exceeded"


class TestQueryResult:
    """Tests for QueryResult data class."""

    def test_create_query_result(self, sample_cid, sample_cid_name, sample_events):
        """QueryResult should contain events and metadata."""
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=sample_events,
            record_count=len(sample_events),
        )
        
        assert result.cid == sample_cid
        assert result.cid_name == sample_cid_name
        assert result.events == sample_events
        assert result.record_count == 3

    def test_query_result_with_empty_events(self, sample_cid, sample_cid_name):
        """QueryResult should handle empty event lists."""
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=[],
            record_count=0,
        )
        
        assert result.events == []
        assert result.record_count == 0
        assert result.is_empty is True

    def test_query_result_is_empty_property(self, sample_cid, sample_cid_name, sample_events):
        """is_empty should return False when events exist."""
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=sample_events,
            record_count=len(sample_events),
        )
        
        assert result.is_empty is False

    def test_query_result_preview(self, sample_cid, sample_cid_name, sample_events):
        """preview should return first N events."""
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=sample_events,
            record_count=len(sample_events),
        )
        
        preview = result.preview(2)
        assert len(preview) == 2
        assert preview[0] == sample_events[0]
        assert preview[1] == sample_events[1]

    def test_query_result_preview_with_fewer_events(self, sample_cid, sample_cid_name, sample_events):
        """preview should return all events if fewer than requested."""
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=sample_events,
            record_count=len(sample_events),
        )
        
        preview = result.preview(10)
        assert len(preview) == 3


class TestQuerySummary:
    """Tests for QuerySummary data class."""

    def test_create_query_summary(self, sample_cid, sample_cid_name):
        """QuerySummary should contain per-CID execution metadata."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=150,
            execution_time_seconds=45.5,
            status=QueryJobStatus.COMPLETED,
        )
        
        assert summary.cid == sample_cid
        assert summary.cid_name == sample_cid_name
        assert summary.record_count == 150
        assert summary.execution_time_seconds == 45.5
        assert summary.status == QueryJobStatus.COMPLETED

    def test_query_summary_with_error(self, sample_cid, sample_cid_name):
        """QuerySummary should store error details."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=0,
            execution_time_seconds=5.0,
            status=QueryJobStatus.FAILED,
            error="Connection timeout",
        )
        
        assert summary.error == "Connection timeout"
        assert summary.has_error is True

    def test_query_summary_has_error_false_on_success(self, sample_cid, sample_cid_name):
        """has_error should be False on successful query."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=100,
            execution_time_seconds=30.0,
            status=QueryJobStatus.COMPLETED,
        )
        
        assert summary.has_error is False

    def test_query_summary_with_warnings(self, sample_cid, sample_cid_name):
        """QuerySummary should track warnings."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=10000,
            execution_time_seconds=60.0,
            status=QueryJobStatus.COMPLETED,
            warnings=["Results truncated to 10000 records"],
        )
        
        assert len(summary.warnings) == 1
        assert "truncated" in summary.warnings[0]


class TestOverallSummary:
    """Tests for OverallSummary data class."""

    def test_create_overall_summary(self):
        """OverallSummary should aggregate across all CIDs."""
        summary = OverallSummary(
            total_cids=5,
            successful_cids=4,
            failed_cids=1,
            total_records=5000,
            total_execution_time_seconds=120.5,
            mode=ExecutionMode.BATCH,
        )
        
        assert summary.total_cids == 5
        assert summary.successful_cids == 4
        assert summary.failed_cids == 1
        assert summary.total_records == 5000
        assert summary.total_execution_time_seconds == 120.5
        assert summary.mode == ExecutionMode.BATCH

    def test_overall_summary_success_rate(self):
        """success_rate should calculate percentage of successful CIDs."""
        summary = OverallSummary(
            total_cids=10,
            successful_cids=8,
            failed_cids=2,
            total_records=1000,
            total_execution_time_seconds=60.0,
            mode=ExecutionMode.ITERATIVE,
        )
        
        assert summary.success_rate == 80.0

    def test_overall_summary_success_rate_all_success(self):
        """success_rate should be 100% when all succeed."""
        summary = OverallSummary(
            total_cids=5,
            successful_cids=5,
            failed_cids=0,
            total_records=500,
            total_execution_time_seconds=30.0,
            mode=ExecutionMode.BATCH,
        )
        
        assert summary.success_rate == 100.0

    def test_overall_summary_success_rate_zero_cids(self):
        """success_rate should handle zero CIDs gracefully."""
        summary = OverallSummary(
            total_cids=0,
            successful_cids=0,
            failed_cids=0,
            total_records=0,
            total_execution_time_seconds=0.0,
            mode=ExecutionMode.BATCH,
        )
        
        assert summary.success_rate == 0.0

    def test_overall_summary_with_cid_summaries(self, sample_cid, sample_cid_name):
        """OverallSummary should include per-CID summaries."""
        cid_summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=100,
            execution_time_seconds=10.0,
            status=QueryJobStatus.COMPLETED,
        )
        
        summary = OverallSummary(
            total_cids=1,
            successful_cids=1,
            failed_cids=0,
            total_records=100,
            total_execution_time_seconds=10.0,
            mode=ExecutionMode.ITERATIVE,
            cid_summaries=[cid_summary],
        )
        
        assert len(summary.cid_summaries) == 1
        assert summary.cid_summaries[0].cid == sample_cid


class TestExecutionMode:
    """Tests for ExecutionMode enum."""

    def test_execution_modes_exist(self):
        """ExecutionMode should have BATCH and ITERATIVE."""
        assert ExecutionMode.BATCH
        assert ExecutionMode.ITERATIVE

    def test_execution_mode_values(self):
        """ExecutionMode values should be descriptive strings."""
        assert ExecutionMode.BATCH.value == "batch"
        assert ExecutionMode.ITERATIVE.value == "iterative"
