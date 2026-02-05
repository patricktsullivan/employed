"""
Tests for ngsiem_hunter.output module.

Tests CSV generation and summary report formatting.
"""

import pytest
import csv
import json
from pathlib import Path
from datetime import datetime, timezone

from ngsiem_hunter.output import (
    write_csv,
    write_csv_per_cid,
    format_summary,
    format_overall_summary,
    generate_output_filename,
)
from ngsiem_hunter.models import (
    QueryResult,
    QuerySummary,
    OverallSummary,
    QueryJobStatus,
    ExecutionMode,
)


@pytest.fixture
def sample_result(sample_events, sample_cid, sample_cid_name):
    """Sample QueryResult for testing."""
    return QueryResult(
        cid=sample_cid,
        cid_name=sample_cid_name,
        events=sample_events,
        record_count=len(sample_events),
    )


@pytest.fixture
def sample_results(sample_events):
    """Multiple QueryResults for testing."""
    return [
        QueryResult(
            cid="cid1",
            cid_name="Customer 1",
            events=sample_events[:1],
            record_count=1,
        ),
        QueryResult(
            cid="cid2",
            cid_name="Customer 2",
            events=sample_events[1:2],
            record_count=1,
        ),
        QueryResult(
            cid="cid3",
            cid_name="Customer 3",
            events=sample_events[2:],
            record_count=1,
        ),
    ]


@pytest.fixture
def sample_summary(sample_cid, sample_cid_name):
    """Sample QuerySummary for testing."""
    return QuerySummary(
        cid=sample_cid,
        cid_name=sample_cid_name,
        record_count=150,
        execution_time_seconds=45.5,
        status=QueryJobStatus.COMPLETED,
    )


class TestWriteCsv:
    """Tests for write_csv function."""

    def test_write_csv_creates_file(self, sample_result, tmp_path):
        """write_csv should create CSV file."""
        output_file = tmp_path / "output.csv"
        
        write_csv(sample_result, output_file)
        
        assert output_file.exists()

    def test_write_csv_contains_events(self, sample_result, tmp_path):
        """write_csv should write all events to CSV."""
        output_file = tmp_path / "output.csv"
        
        write_csv(sample_result, output_file)
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 3

    def test_write_csv_has_headers(self, sample_result, tmp_path):
        """write_csv should include column headers."""
        output_file = tmp_path / "output.csv"
        
        write_csv(sample_result, output_file)
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
        
        assert "@timestamp" in headers
        assert "event_simpleName" in headers

    def test_write_csv_adds_cid_column(self, sample_result, tmp_path):
        """write_csv should add CID and customer name columns."""
        output_file = tmp_path / "output.csv"
        
        write_csv(sample_result, output_file, include_cid=True)
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            row = next(reader)
        
        assert "_cid" in row
        assert "_cid_name" in row

    def test_write_csv_empty_results(self, tmp_path, sample_cid, sample_cid_name):
        """write_csv should handle empty results."""
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=[],
            record_count=0,
        )
        output_file = tmp_path / "empty.csv"
        
        write_csv(result, output_file)
        
        assert output_file.exists()
        content = output_file.read_text()
        # Should have at least headers or be empty
        assert content == "" or "," in content


class TestWriteCsvPerCid:
    """Tests for write_csv_per_cid function."""

    def test_write_csv_per_cid_creates_files(self, sample_results, tmp_path):
        """write_csv_per_cid should create one file per CID."""
        write_csv_per_cid(sample_results, tmp_path)
        
        files = list(tmp_path.glob("*.csv"))
        assert len(files) == 3

    def test_write_csv_per_cid_filenames(self, sample_results, tmp_path):
        """write_csv_per_cid should use CID in filenames."""
        write_csv_per_cid(sample_results, tmp_path)
        
        filenames = [f.stem for f in tmp_path.glob("*.csv")]
        assert any("cid1" in name for name in filenames)
        assert any("cid2" in name for name in filenames)

    def test_write_csv_per_cid_content(self, sample_results, tmp_path):
        """write_csv_per_cid should write correct events to each file."""
        write_csv_per_cid(sample_results, tmp_path)
        
        # Find file for cid1
        cid1_files = [f for f in tmp_path.glob("*.csv") if "cid1" in f.name]
        assert len(cid1_files) == 1
        
        with open(cid1_files[0]) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 1


class TestFormatSummary:
    """Tests for format_summary function."""

    def test_format_summary_includes_cid(self, sample_summary):
        """format_summary should include CID info."""
        output = format_summary(sample_summary)
        
        assert sample_summary.cid in output
        assert sample_summary.cid_name in output

    def test_format_summary_includes_record_count(self, sample_summary):
        """format_summary should include record count."""
        output = format_summary(sample_summary)
        
        assert "150" in output

    def test_format_summary_includes_execution_time(self, sample_summary):
        """format_summary should include execution time."""
        output = format_summary(sample_summary)
        
        assert "45" in output or "45.5" in output

    def test_format_summary_includes_status(self, sample_summary):
        """format_summary should include status."""
        output = format_summary(sample_summary)
        
        assert "COMPLETED" in output.upper() or "success" in output.lower()

    def test_format_summary_with_error(self, sample_cid, sample_cid_name):
        """format_summary should show error details."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=0,
            execution_time_seconds=5.0,
            status=QueryJobStatus.FAILED,
            error="Connection timeout",
        )
        
        output = format_summary(summary)
        
        assert "Connection timeout" in output or "error" in output.lower()


class TestFormatOverallSummary:
    """Tests for format_overall_summary function."""

    def test_format_overall_summary_includes_totals(self):
        """format_overall_summary should include total counts."""
        summary = OverallSummary(
            total_cids=10,
            successful_cids=8,
            failed_cids=2,
            total_records=5000,
            total_execution_time_seconds=120.5,
            mode=ExecutionMode.BATCH,
        )
        
        output = format_overall_summary(summary)
        
        assert "10" in output
        assert "5,000" in output or "5000" in output  # May be formatted

    def test_format_overall_summary_includes_success_rate(self):
        """format_overall_summary should include success rate."""
        summary = OverallSummary(
            total_cids=10,
            successful_cids=8,
            failed_cids=2,
            total_records=1000,
            total_execution_time_seconds=60.0,
            mode=ExecutionMode.ITERATIVE,
        )
        
        output = format_overall_summary(summary)
        
        assert "80" in output  # 80% success rate

    def test_format_overall_summary_includes_mode(self):
        """format_overall_summary should include execution mode."""
        summary = OverallSummary(
            total_cids=5,
            successful_cids=5,
            failed_cids=0,
            total_records=500,
            total_execution_time_seconds=30.0,
            mode=ExecutionMode.BATCH,
        )
        
        output = format_overall_summary(summary)
        
        assert "batch" in output.lower()


class TestGenerateOutputFilename:
    """Tests for generate_output_filename function."""

    def test_generate_filename_with_timestamp(self):
        """generate_output_filename should include timestamp."""
        filename = generate_output_filename(
            prefix="results",
            extension="csv",
        )
        
        # Should contain date-like pattern
        assert "202" in filename  # Year

    def test_generate_filename_with_cid(self):
        """generate_output_filename should include CID when provided."""
        filename = generate_output_filename(
            prefix="results",
            cid="abc123",
            extension="csv",
        )
        
        assert "abc123" in filename

    def test_generate_filename_extension(self):
        """generate_output_filename should use correct extension."""
        filename = generate_output_filename(
            prefix="results",
            extension="json",
        )
        
        assert filename.endswith(".json")

    def test_generate_filename_is_filesystem_safe(self):
        """generate_output_filename should produce safe filenames."""
        filename = generate_output_filename(
            prefix="results",
            cid="cid/with:special*chars",
            extension="csv",
        )
        
        # Should not contain filesystem-unsafe characters
        assert "/" not in filename
        assert ":" not in filename
        assert "*" not in filename
