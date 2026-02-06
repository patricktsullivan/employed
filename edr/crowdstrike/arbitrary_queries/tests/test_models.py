"""
Tests for arbitrary_queries.models module.

Tests data classes for query results, summaries, and configuration.
"""

import pytest
from datetime import datetime, timezone, timedelta
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from arbitrary_queries.models import (
    CIDInfo,
    QueryJob,
    QueryJobStatus,
    QueryResult,
    QuerySummary,
    OverallSummary,
    ExecutionMode,
    create_query_result,
    create_query_summary,
    create_overall_summary,
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
            setattr(cid_info, "cid", "new_cid")

    def test_cid_info_equality(self, sample_cid, sample_cid_name):
        """CIDInfo instances with same values should be equal."""
        cid1 = CIDInfo(cid=sample_cid, name=sample_cid_name)
        cid2 = CIDInfo(cid=sample_cid, name=sample_cid_name)
        
        assert cid1 == cid2

    def test_cid_info_string_representation(self, sample_cid, sample_cid_name):
        """CIDInfo should have user-friendly string representation."""
        cid_info = CIDInfo(cid=sample_cid, name=sample_cid_name)
        
        # Test exact format: "Name (cid)"
        expected = f"{sample_cid_name} ({sample_cid})"
        assert str(cid_info) == expected

    def test_cid_info_repr(self, sample_cid, sample_cid_name):
        """CIDInfo repr should be different from str for debugging."""
        cid_info = CIDInfo(cid=sample_cid, name=sample_cid_name)
        
        # repr should include class name for debugging
        assert "CIDInfo" in repr(cid_info)
        assert sample_cid in repr(cid_info)

    def test_cid_info_hashable(self, sample_cid, sample_cid_name):
        """CIDInfo should be hashable for use in sets/dicts."""
        cid_info = CIDInfo(cid=sample_cid, name=sample_cid_name)
        
        # Should work in a set
        cid_set = {cid_info}
        assert cid_info in cid_set
        
        # Should work as dict key
        cid_dict = {cid_info: "test"}
        assert cid_dict[cid_info] == "test"


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

    def test_status_string_values(self):
        """Status values should be lowercase strings."""
        assert QueryJobStatus.PENDING.value == "pending"
        assert QueryJobStatus.RUNNING.value == "running"
        assert QueryJobStatus.COMPLETED.value == "completed"
        assert QueryJobStatus.FAILED.value == "failed"
        assert QueryJobStatus.TIMEOUT.value == "timeout"


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
        start = datetime(2026, 2, 4, 12, 0, 0, tzinfo=timezone.utc)
        mock_now = datetime(2026, 2, 4, 12, 0, 30, tzinfo=timezone.utc)
        
        job = QueryJob(
            job_id="job-12345",
            cid=sample_cid,
            query=sample_query,
            status=QueryJobStatus.RUNNING,
            started_at=start,
        )
        
        # Mock datetime.now to avoid flaky tests
        with patch('arbitrary_queries.models.datetime') as mock_datetime:
            mock_datetime.now.return_value = mock_now
            mock_datetime.timezone = timezone
            
            assert job.duration_seconds == 30.0

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

    def test_query_job_duration_without_start_time(self, sample_cid, sample_query):
        """Duration should be 0 if started_at is not set."""
        job = QueryJob(
            job_id="job-12345",
            cid=sample_cid,
            query=sample_query,
            status=QueryJobStatus.PENDING,
        )
        
        assert job.duration_seconds == 0.0

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

    def test_query_job_is_mutable(self, sample_cid, sample_query):
        """QueryJob should allow status updates (not frozen)."""
        job = QueryJob(
            job_id="job-12345",
            cid=sample_cid,
            query=sample_query,
            status=QueryJobStatus.PENDING,
        )
        
        # Should be able to update status
        job.status = QueryJobStatus.RUNNING
        assert job.status == QueryJobStatus.RUNNING
        
        # Should be able to set timestamps
        job.started_at = datetime.now(timezone.utc)
        assert job.started_at is not None


class TestQueryResult:
    """Tests for QueryResult data class."""

    def test_create_query_result(self, sample_cid, sample_cid_name, sample_events):
        """QueryResult should contain events and metadata."""
        events_tuple = tuple(sample_events)
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events_tuple,
            record_count=len(events_tuple),
        )
        
        assert result.cid == sample_cid
        assert result.cid_name == sample_cid_name
        assert result.events == events_tuple
        assert result.record_count == 3

    def test_query_result_with_empty_events(self, sample_cid, sample_cid_name):
        """QueryResult should handle empty event tuples."""
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=(),
            record_count=0,
        )
        
        assert result.events == ()
        assert result.record_count == 0
        assert result.is_empty is True

    def test_query_result_is_empty_property(self, sample_cid, sample_cid_name, sample_events):
        """is_empty should return False when events exist."""
        events_tuple = tuple(sample_events)
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events_tuple,
            record_count=len(events_tuple),
        )
        
        assert result.is_empty is False

    def test_query_result_preview(self, sample_cid, sample_cid_name, sample_events):
        """preview should return first N events."""
        events_tuple = tuple(sample_events)
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events_tuple,
            record_count=len(events_tuple),
        )
        
        preview = result.preview(2)
        assert len(preview) == 2
        assert preview[0] == sample_events[0]
        assert preview[1] == sample_events[1]

    def test_query_result_preview_with_fewer_events(self, sample_cid, sample_cid_name, sample_events):
        """preview should return all events if fewer than requested."""
        events_tuple = tuple(sample_events)
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events_tuple,
            record_count=len(events_tuple),
        )
        
        preview = result.preview(10)
        assert len(preview) == 3

    def test_query_result_preview_zero_count(self, sample_cid, sample_cid_name, sample_events):
        """preview(0) should return empty tuple."""
        events_tuple = tuple(sample_events)
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events_tuple,
            record_count=len(events_tuple),
        )
        
        preview = result.preview(0)
        assert preview == ()

    def test_query_result_preview_negative_count_raises(self, sample_cid, sample_cid_name, sample_events):
        """preview with negative count should raise ValueError."""
        events_tuple = tuple(sample_events)
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events_tuple,
            record_count=len(events_tuple),
        )
        
        with pytest.raises(ValueError, match="non-negative"):
            result.preview(-1)

    def test_query_result_mismatched_record_count_raises(self, sample_cid, sample_cid_name, sample_events):
        """QueryResult should raise if record_count doesn't match events length."""
        events_tuple = tuple(sample_events)
        
        with pytest.raises(ValueError, match="record_count"):
            QueryResult(
                cid=sample_cid,
                cid_name=sample_cid_name,
                events=events_tuple,
                record_count=100,  # Doesn't match len(events)
            )

    def test_query_result_is_frozen(self, sample_cid, sample_cid_name, sample_events):
        """QueryResult should be immutable."""
        events_tuple = tuple(sample_events)
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events_tuple,
            record_count=len(events_tuple),
        )
        
        with pytest.raises(FrozenInstanceError):
            setattr(result, "cid", "new_cid")

    def test_query_result_events_immutable(self, sample_cid, sample_cid_name, sample_events):
        """QueryResult events should be a tuple (truly immutable)."""
        events_tuple = tuple(sample_events)
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events_tuple,
            record_count=len(events_tuple),
        )
        
        # Verify it's a tuple, not a list
        assert isinstance(result.events, tuple)
        
        # Tuples don't have append
        assert not hasattr(result.events, 'append')


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
        """QuerySummary should track warnings as tuple."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=10000,
            execution_time_seconds=60.0,
            status=QueryJobStatus.COMPLETED,
            warnings=("Results truncated to 10000 records",),
        )
        
        assert len(summary.warnings) == 1
        assert "truncated" in summary.warnings[0]
        # Verify it's a tuple
        assert isinstance(summary.warnings, tuple)

    def test_query_summary_warnings_default_empty_tuple(self, sample_cid, sample_cid_name):
        """QuerySummary warnings should default to empty tuple."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=100,
            execution_time_seconds=10.0,
            status=QueryJobStatus.COMPLETED,
        )
        
        assert summary.warnings == ()
        assert isinstance(summary.warnings, tuple)

    def test_query_summary_negative_record_count_raises(self, sample_cid, sample_cid_name):
        """QuerySummary should raise if record_count is negative."""
        with pytest.raises(ValueError, match="record_count.*non-negative"):
            QuerySummary(
                cid=sample_cid,
                cid_name=sample_cid_name,
                record_count=-1,
                execution_time_seconds=10.0,
                status=QueryJobStatus.COMPLETED,
            )

    def test_query_summary_negative_execution_time_raises(self, sample_cid, sample_cid_name):
        """QuerySummary should raise if execution_time_seconds is negative."""
        with pytest.raises(ValueError, match="execution_time_seconds.*non-negative"):
            QuerySummary(
                cid=sample_cid,
                cid_name=sample_cid_name,
                record_count=100,
                execution_time_seconds=-5.0,
                status=QueryJobStatus.COMPLETED,
            )

    def test_query_summary_is_frozen(self, sample_cid, sample_cid_name):
        """QuerySummary should be immutable."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=100,
            execution_time_seconds=10.0,
            status=QueryJobStatus.COMPLETED,
        )
        
        with pytest.raises(FrozenInstanceError):
            setattr(summary, "record_count", 200)


class TestOverallSummary:
    """Tests for OverallSummary data class."""

    def test_create_overall_summary(self):
        """OverallSummary should aggregate across all CIDs."""
        summary = OverallSummary(
            total_cids=10,
            successful_cids=8,
            failed_cids=2,
            total_records=5000,
            total_execution_time_seconds=300.0,
            mode=ExecutionMode.BATCH,
        )
        
        assert summary.total_cids == 10
        assert summary.successful_cids == 8
        assert summary.failed_cids == 2
        assert summary.total_records == 5000
        assert summary.total_execution_time_seconds == 300.0
        assert summary.mode == ExecutionMode.BATCH

    def test_overall_summary_success_rate(self):
        """success_rate should calculate percentage correctly."""
        summary = OverallSummary(
            total_cids=10,
            successful_cids=8,
            failed_cids=2,
            total_records=5000,
            total_execution_time_seconds=300.0,
            mode=ExecutionMode.BATCH,
        )
        
        assert summary.success_rate == 80.0

    def test_overall_summary_success_rate_zero_cids(self):
        """success_rate should return 0.0 when no CIDs queried."""
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
        """OverallSummary should include per-CID summaries as tuple."""
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
            cid_summaries=(cid_summary,),
        )
        
        assert len(summary.cid_summaries) == 1
        assert summary.cid_summaries[0].cid == sample_cid
        assert isinstance(summary.cid_summaries, tuple)

    def test_overall_summary_default_cid_summaries(self):
        """cid_summaries should default to empty tuple."""
        summary = OverallSummary(
            total_cids=0,
            successful_cids=0,
            failed_cids=0,
            total_records=0,
            total_execution_time_seconds=0.0,
            mode=ExecutionMode.BATCH,
        )
        
        assert summary.cid_summaries == ()
        assert isinstance(summary.cid_summaries, tuple)

    def test_overall_summary_arithmetic_validation(self):
        """OverallSummary should raise if successful + failed != total."""
        with pytest.raises(ValueError, match="must equal total_cids"):
            OverallSummary(
                total_cids=10,
                successful_cids=8,
                failed_cids=3,  # 8 + 3 != 10
                total_records=5000,
                total_execution_time_seconds=300.0,
                mode=ExecutionMode.BATCH,
            )

    def test_overall_summary_negative_total_cids_raises(self):
        """OverallSummary should raise if total_cids is negative."""
        with pytest.raises(ValueError, match="total_cids.*non-negative"):
            OverallSummary(
                total_cids=-1,
                successful_cids=0,
                failed_cids=0,
                total_records=0,
                total_execution_time_seconds=0.0,
                mode=ExecutionMode.BATCH,
            )

    def test_overall_summary_negative_successful_cids_raises(self):
        """OverallSummary should raise if successful_cids is negative."""
        with pytest.raises(ValueError, match="successful_cids.*non-negative"):
            OverallSummary(
                total_cids=0,
                successful_cids=-1,
                failed_cids=0,
                total_records=0,
                total_execution_time_seconds=0.0,
                mode=ExecutionMode.BATCH,
            )

    def test_overall_summary_negative_total_records_raises(self):
        """OverallSummary should raise if total_records is negative."""
        with pytest.raises(ValueError, match="total_records.*non-negative"):
            OverallSummary(
                total_cids=0,
                successful_cids=0,
                failed_cids=0,
                total_records=-100,
                total_execution_time_seconds=0.0,
                mode=ExecutionMode.BATCH,
            )

    def test_overall_summary_is_frozen(self):
        """OverallSummary should be immutable."""
        summary = OverallSummary(
            total_cids=10,
            successful_cids=8,
            failed_cids=2,
            total_records=5000,
            total_execution_time_seconds=300.0,
            mode=ExecutionMode.BATCH,
        )
        
        with pytest.raises(FrozenInstanceError):
            setattr(summary, "total_cids", 20)


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


class TestFactoryFunctions:
    """Tests for convenience factory functions."""

    def test_create_query_result_from_list(self, sample_cid, sample_cid_name, sample_events):
        """create_query_result should convert list to tuple."""
        result = create_query_result(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=sample_events,  # Pass list
        )
        
        assert isinstance(result.events, tuple)
        assert len(result.events) == len(sample_events)
        assert result.record_count == len(sample_events)

    def test_create_query_summary_from_list(self, sample_cid, sample_cid_name):
        """create_query_summary should convert warnings list to tuple."""
        warnings_list = ["Warning 1", "Warning 2"]
        
        summary = create_query_summary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=100,
            execution_time_seconds=10.0,
            status=QueryJobStatus.COMPLETED,
            warnings=warnings_list,
        )
        
        assert isinstance(summary.warnings, tuple)
        assert summary.warnings == ("Warning 1", "Warning 2")

    def test_create_query_summary_none_warnings(self, sample_cid, sample_cid_name):
        """create_query_summary should handle None warnings."""
        summary = create_query_summary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=100,
            execution_time_seconds=10.0,
            status=QueryJobStatus.COMPLETED,
            warnings=None,
        )
        
        assert summary.warnings == ()

    def test_create_overall_summary_from_list(self, sample_cid, sample_cid_name):
        """create_overall_summary should convert cid_summaries list to tuple."""
        cid_summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=100,
            execution_time_seconds=10.0,
            status=QueryJobStatus.COMPLETED,
        )
        
        summary = create_overall_summary(
            total_cids=1,
            successful_cids=1,
            failed_cids=0,
            total_records=100,
            total_execution_time_seconds=10.0,
            mode=ExecutionMode.BATCH,
            cid_summaries=[cid_summary],  # Pass list
        )
        
        assert isinstance(summary.cid_summaries, tuple)
        assert len(summary.cid_summaries) == 1

    def test_create_overall_summary_none_cid_summaries(self):
        """create_overall_summary should handle None cid_summaries."""
        summary = create_overall_summary(
            total_cids=0,
            successful_cids=0,
            failed_cids=0,
            total_records=0,
            total_execution_time_seconds=0.0,
            mode=ExecutionMode.BATCH,
            cid_summaries=None,
        )
        
        assert summary.cid_summaries == ()
