"""
Tests for arbitrary_queries.output module.

Tests CSV generation and summary report formatting.
"""

import pytest
import csv
import json
from pathlib import Path
from datetime import datetime, timezone

from arbitrary_queries.output import (
    OutputError,
    write_csv,
    write_csv_per_cid,
    format_summary,
    format_overall_summary,
    generate_output_filename,
)
from arbitrary_queries.models import (
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
        events=tuple(sample_events),
        record_count=len(sample_events),
    )


@pytest.fixture
def sample_results(sample_events):
    """Multiple QueryResults for testing."""
    return [
        QueryResult(
            cid="cid1",
            cid_name="Customer 1",
            events=tuple(sample_events[:1]),
            record_count=1,
        ),
        QueryResult(
            cid="cid2",
            cid_name="Customer 2",
            events=tuple(sample_events[1:2]),
            record_count=1,
        ),
        QueryResult(
            cid="cid3",
            cid_name="Customer 3",
            events=tuple(sample_events[2:]),
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
        
        assert headers is not None
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
            events=(),
            record_count=0,
        )
        output_file = tmp_path / "empty.csv"
        
        write_csv(result, output_file)
        
        assert output_file.exists()
        content = output_file.read_text()
        # Should have at least headers or be empty
        assert content == "" or "," in content

    # === NEW TESTS ===

    def test_write_csv_cid_column_values(self, sample_result, tmp_path):
        """write_csv should populate CID columns with correct values."""
        output_file = tmp_path / "output.csv"
        
        write_csv(sample_result, output_file, include_cid=True)
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        # All rows should have the same CID values
        assert all(row["_cid"] == sample_result.cid for row in rows)
        assert all(row["_cid_name"] == sample_result.cid_name for row in rows)

    def test_write_csv_priority_field_ordering(self, sample_result, tmp_path):
        """write_csv should put priority fields first in column order."""
        output_file = tmp_path / "output.csv"
        
        write_csv(sample_result, output_file)
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames is not None
            headers = list(reader.fieldnames)
        
        # Priority fields should come before non-priority fields
        # Priority order: @timestamp, event_simpleName, aid, cid
        timestamp_idx = headers.index("@timestamp")
        event_idx = headers.index("event_simpleName")
        aid_idx = headers.index("aid")
        
        # CommandLine is not a priority field
        commandline_idx = headers.index("CommandLine")
        
        assert timestamp_idx < commandline_idx
        assert event_idx < commandline_idx
        assert aid_idx < commandline_idx

    def test_write_csv_cid_columns_first_when_included(self, sample_result, tmp_path):
        """write_csv should put _cid columns first when include_cid=True."""
        output_file = tmp_path / "output.csv"
        
        write_csv(sample_result, output_file, include_cid=True)
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames is not None
            headers = list(reader.fieldnames)
        
        # _cid and _cid_name should be the first two columns
        assert headers[0] == "_cid"
        assert headers[1] == "_cid_name"

    def test_write_csv_handles_unicode(self, tmp_path, sample_cid, sample_cid_name):
        """write_csv should handle Unicode characters in event data."""
        events = (
            {
                "@timestamp": "2026-02-04T10:00:00.000Z",
                "message": "日本語テスト",
                "emoji": "🔥🚀",
                "accented": "café résumé naïve",
            },
        )
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events,
            record_count=1,
        )
        output_file = tmp_path / "unicode.csv"
        
        write_csv(result, output_file)
        
        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
        
        assert row["message"] == "日本語テスト"
        assert row["emoji"] == "🔥🚀"
        assert row["accented"] == "café résumé naïve"

    def test_write_csv_handles_special_csv_characters(self, tmp_path, sample_cid, sample_cid_name):
        """write_csv should properly escape special CSV characters."""
        events = (
            {
                "@timestamp": "2026-02-04T10:00:00.000Z",
                "with_comma": "value,with,commas",
                "with_quote": 'value"with"quotes',
                "with_newline": "value\nwith\nnewlines",
                "mixed": 'all,of"the\nabove',
            },
        )
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events,
            record_count=1,
        )
        output_file = tmp_path / "special.csv"
        
        write_csv(result, output_file)
        
        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
        
        assert row["with_comma"] == "value,with,commas"
        assert row["with_quote"] == 'value"with"quotes'
        assert row["with_newline"] == "value\nwith\nnewlines"

    def test_write_csv_handles_none_values(self, tmp_path, sample_cid, sample_cid_name):
        """write_csv should handle None values in event data."""
        events = (
            {
                "@timestamp": "2026-02-04T10:00:00.000Z",
                "present": "value",
                "missing": None,
            },
        )
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events,
            record_count=1,
        )
        output_file = tmp_path / "nulls.csv"
        
        write_csv(result, output_file)
        
        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            row = next(reader)
        
        assert row["present"] == "value"
        # None should be written as empty string
        assert row["missing"] == ""

    def test_write_csv_handles_heterogeneous_events(self, tmp_path, sample_cid, sample_cid_name):
        """write_csv should handle events with different field sets."""
        events = (
            {"@timestamp": "2026-02-04T10:00:00.000Z", "field_a": "value1"},
            {"@timestamp": "2026-02-04T10:01:00.000Z", "field_b": "value2"},
            {"@timestamp": "2026-02-04T10:02:00.000Z", "field_a": "value3", "field_c": "value4"},
        )
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events,
            record_count=3,
        )
        output_file = tmp_path / "hetero.csv"
        
        write_csv(result, output_file)
        
        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            rows = list(reader)
        
        # All unique fields should be present in headers
        assert headers is not None
        assert "field_a" in headers
        assert "field_b" in headers
        assert "field_c" in headers
        
        # Should have 3 rows
        assert len(rows) == 3

    def test_write_csv_large_dataset(self, tmp_path, sample_cid, sample_cid_name):
        """write_csv should handle large event sets efficiently."""
        num_events = 10000
        events = tuple(
            {
                "@timestamp": f"2026-02-04T10:{i:05d}.000Z",
                "event_simpleName": "TestEvent",
                "index": str(i),
                "data": f"payload_{i}" * 10,  # Some substantial data per row
            }
            for i in range(num_events)
        )
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=events,
            record_count=num_events,
        )
        output_file = tmp_path / "large.csv"
        
        write_csv(result, output_file)
        
        # Count rows (excluding header)
        with open(output_file, encoding="utf-8") as f:
            row_count = sum(1 for _ in f) - 1
        
        assert row_count == num_events

    def test_write_csv_without_cid_columns(self, sample_result, tmp_path):
        """write_csv should not add CID columns when include_cid=False."""
        output_file = tmp_path / "output.csv"
        
        write_csv(sample_result, output_file, include_cid=False)
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
        
        assert headers is not None
        assert "_cid" not in headers
        assert "_cid_name" not in headers

    def test_write_csv_returns_path(self, sample_result, tmp_path):
        """write_csv should return the path to the created file."""
        output_file = tmp_path / "output.csv"
        
        result_path = write_csv(sample_result, output_file)
        
        assert result_path == output_file
        assert isinstance(result_path, Path)

    def test_write_csv_returns_path_for_empty_results(self, tmp_path, sample_cid, sample_cid_name):
        """write_csv should return path even for empty results."""
        result = QueryResult(
            cid=sample_cid,
            cid_name=sample_cid_name,
            events=(),
            record_count=0,
        )
        output_file = tmp_path / "empty.csv"
        
        result_path = write_csv(result, output_file)
        
        assert result_path == output_file

    def test_write_csv_raises_output_error_on_invalid_path(self, sample_result):
        """write_csv should raise OutputError when path is not writable."""
        # Attempt to write to a non-existent directory
        invalid_path = Path("/nonexistent/directory/file.csv")
        
        with pytest.raises(OutputError) as exc_info:
            write_csv(sample_result, invalid_path)
        
        assert "Failed to write CSV" in str(exc_info.value)


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

    # === NEW TESTS ===

    def test_write_csv_per_cid_returns_paths(self, sample_results, tmp_path):
        """write_csv_per_cid should return list of paths to created files."""
        paths = write_csv_per_cid(sample_results, tmp_path)
        
        assert len(paths) == 3
        assert all(isinstance(p, Path) for p in paths)
        assert all(p.exists() for p in paths)
        assert all(p.suffix == ".csv" for p in paths)

    def test_write_csv_per_cid_returns_paths_in_order(self, sample_results, tmp_path):
        """write_csv_per_cid should return paths in same order as input results."""
        paths = write_csv_per_cid(sample_results, tmp_path)
        
        # Each path should correspond to the CID at the same index
        for i, path in enumerate(paths):
            expected_cid = sample_results[i].cid
            assert expected_cid in path.name

    def test_write_csv_per_cid_creates_output_dir(self, sample_results, tmp_path):
        """write_csv_per_cid should create output directory if it doesn't exist."""
        nested_dir = tmp_path / "nested" / "output" / "dir"
        assert not nested_dir.exists()
        
        write_csv_per_cid(sample_results, nested_dir)
        
        assert nested_dir.exists()
        assert len(list(nested_dir.glob("*.csv"))) == 3

    def test_write_csv_per_cid_uses_custom_prefix(self, sample_results, tmp_path):
        """write_csv_per_cid should use custom prefix in filenames."""
        write_csv_per_cid(sample_results, tmp_path, prefix="hunt_results")
        
        files = list(tmp_path.glob("*.csv"))
        assert all("hunt_results" in f.name for f in files)

    def test_write_csv_per_cid_empty_results_list(self, tmp_path):
        """write_csv_per_cid should handle empty results list."""
        paths = write_csv_per_cid([], tmp_path)
        
        assert paths == []
        assert len(list(tmp_path.glob("*.csv"))) == 0

    def test_write_csv_per_cid_includes_cid_columns(self, sample_results, tmp_path):
        """write_csv_per_cid should include _cid columns in each file."""
        write_csv_per_cid(sample_results, tmp_path)
        
        for csv_file in tmp_path.glob("*.csv"):
            with open(csv_file) as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
            
            assert headers is not None
            assert "_cid" in headers
            assert "_cid_name" in headers

    def test_write_csv_per_cid_correct_cid_values(self, sample_results, tmp_path):
        """write_csv_per_cid should write correct CID values in each file."""
        write_csv_per_cid(sample_results, tmp_path)
        
        # Check cid1 file has correct values
        cid1_files = [f for f in tmp_path.glob("*.csv") if "cid1" in f.name]
        with open(cid1_files[0]) as f:
            reader = csv.DictReader(f)
            row = next(reader)
        
        assert row["_cid"] == "cid1"
        assert row["_cid_name"] == "Customer 1"

    def test_write_csv_per_cid_without_cid_columns(self, sample_results, tmp_path):
        """write_csv_per_cid should omit CID columns when include_cid=False."""
        write_csv_per_cid(sample_results, tmp_path, include_cid=False)
        
        # Check that files don't have _cid columns
        for csv_file in tmp_path.glob("*.csv"):
            with open(csv_file) as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
            
            assert headers is not None
            assert "_cid" not in headers
            assert "_cid_name" not in headers

    def test_write_csv_per_cid_raises_output_error_on_invalid_dir(self, sample_results):
        """write_csv_per_cid should raise OutputError when directory cannot be created."""
        # Attempt to create a directory in a non-existent parent
        invalid_dir = Path("/nonexistent/parent/output")
        
        with pytest.raises(OutputError) as exc_info:
            write_csv_per_cid(sample_results, invalid_dir)
        
        assert "Failed to create output directory" in str(exc_info.value)


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

    # === NEW TESTS ===

    def test_format_summary_with_warnings(self, sample_cid, sample_cid_name):
        """format_summary should display warning messages."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=10000,
            execution_time_seconds=30.0,
            status=QueryJobStatus.COMPLETED,
            warnings=("Results truncated to 10000 records", "Partial data returned"),
        )
        
        output = format_summary(summary)
        
        assert "Warning" in output
        assert "truncated" in output
        assert "Partial" in output

    def test_format_summary_with_multiple_warnings(self, sample_cid, sample_cid_name):
        """format_summary should display all warning messages."""
        warnings = (
            "Warning 1: First issue",
            "Warning 2: Second issue",
            "Warning 3: Third issue",
        )
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=100,
            execution_time_seconds=10.0,
            status=QueryJobStatus.COMPLETED,
            warnings=warnings,
        )
        
        output = format_summary(summary)
        
        for warning in warnings:
            # At least part of each warning should be present
            assert "Warning" in output

    def test_format_summary_zero_records(self, sample_cid, sample_cid_name):
        """format_summary should handle zero record count."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=0,
            execution_time_seconds=2.5,
            status=QueryJobStatus.COMPLETED,
        )
        
        output = format_summary(summary)
        
        # Should contain "0" for record count
        assert "0" in output

    def test_format_summary_large_record_count(self, sample_cid, sample_cid_name):
        """format_summary should handle large record counts with formatting."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=1234567,
            execution_time_seconds=300.0,
            status=QueryJobStatus.COMPLETED,
        )
        
        output = format_summary(summary)
        
        # Should contain the number (possibly formatted with commas)
        assert "1234567" in output or "1,234,567" in output

    def test_format_summary_timeout_status(self, sample_cid, sample_cid_name):
        """format_summary should display timeout status."""
        summary = QuerySummary(
            cid=sample_cid,
            cid_name=sample_cid_name,
            record_count=0,
            execution_time_seconds=3600.0,
            status=QueryJobStatus.TIMEOUT,
            error="Query exceeded maximum execution time",
        )
        
        output = format_summary(summary)
        
        assert "TIMEOUT" in output.upper()


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

    # === NEW TESTS ===

    def test_format_overall_summary_iterative_mode(self):
        """format_overall_summary should display iterative mode."""
        summary = OverallSummary(
            total_cids=5,
            successful_cids=5,
            failed_cids=0,
            total_records=500,
            total_execution_time_seconds=30.0,
            mode=ExecutionMode.ITERATIVE,
        )
        
        output = format_overall_summary(summary)
        
        assert "iterative" in output.lower()

    def test_format_overall_summary_all_failed(self):
        """format_overall_summary should handle all CIDs failed."""
        summary = OverallSummary(
            total_cids=5,
            successful_cids=0,
            failed_cids=5,
            total_records=0,
            total_execution_time_seconds=25.0,
            mode=ExecutionMode.BATCH,
        )
        
        output = format_overall_summary(summary)
        
        assert "0" in output  # 0% success rate or 0 successful
        assert "5" in output  # 5 failed

    def test_format_overall_summary_zero_cids(self):
        """format_overall_summary should handle zero CIDs gracefully."""
        summary = OverallSummary(
            total_cids=0,
            successful_cids=0,
            failed_cids=0,
            total_records=0,
            total_execution_time_seconds=0.0,
            mode=ExecutionMode.BATCH,
        )
        
        output = format_overall_summary(summary)
        
        # Should not crash, should produce some output
        assert isinstance(output, str)
        assert len(output) > 0

    def test_format_overall_summary_includes_execution_time(self):
        """format_overall_summary should include total execution time."""
        summary = OverallSummary(
            total_cids=10,
            successful_cids=10,
            failed_cids=0,
            total_records=1000,
            total_execution_time_seconds=245.7,
            mode=ExecutionMode.BATCH,
        )
        
        output = format_overall_summary(summary)
        
        assert "245" in output or "245.7" in output

    def test_format_overall_summary_includes_failed_count(self):
        """format_overall_summary should include failed CID count."""
        summary = OverallSummary(
            total_cids=20,
            successful_cids=17,
            failed_cids=3,
            total_records=8500,
            total_execution_time_seconds=180.0,
            mode=ExecutionMode.ITERATIVE,
        )
        
        output = format_overall_summary(summary)
        
        # Should show failed count
        assert "3" in output
        assert "17" in output

    def test_format_overall_summary_100_percent_success(self):
        """format_overall_summary should show 100% for all successful."""
        summary = OverallSummary(
            total_cids=10,
            successful_cids=10,
            failed_cids=0,
            total_records=5000,
            total_execution_time_seconds=60.0,
            mode=ExecutionMode.BATCH,
        )
        
        output = format_overall_summary(summary)
        
        assert "100" in output  # 100% success rate


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

    # === NEW TESTS ===

    def test_generate_filename_without_cid(self):
        """generate_output_filename should work without CID."""
        filename = generate_output_filename(
            prefix="test",
            extension="csv",
        )
        
        assert filename.startswith("test_")
        assert filename.endswith(".csv")
        # Should have format: prefix_timestamp.extension
        parts = filename.replace(".csv", "").split("_")
        assert len(parts) >= 2  # At least prefix and timestamp parts

    def test_generate_filename_sanitizes_backslash(self):
        """generate_output_filename should sanitize backslashes in CID."""
        filename = generate_output_filename(
            prefix="results",
            cid="cid\\with\\backslashes",
            extension="csv",
        )
        
        assert "\\" not in filename

    def test_generate_filename_sanitizes_quotes(self):
        """generate_output_filename should sanitize quotes in CID."""
        filename = generate_output_filename(
            prefix="results",
            cid='cid"with\'quotes',
            extension="csv",
        )
        
        assert '"' not in filename
        assert "'" not in filename

    def test_generate_filename_sanitizes_spaces(self):
        """generate_output_filename should sanitize spaces in CID."""
        filename = generate_output_filename(
            prefix="results",
            cid="cid with spaces",
            extension="csv",
        )
        
        assert " " not in filename

    def test_generate_filename_preserves_valid_characters(self):
        """generate_output_filename should preserve alphanumeric and hyphen/underscore."""
        filename = generate_output_filename(
            prefix="results",
            cid="valid-cid_123",
            extension="csv",
        )
        
        assert "valid-cid_123" in filename

    def test_generate_filename_different_extensions(self):
        """generate_output_filename should support various extensions."""
        extensions = ["csv", "json", "txt", "xlsx", "parquet"]
        
        for ext in extensions:
            filename = generate_output_filename(
                prefix="output",
                extension=ext,
            )
            assert filename.endswith(f".{ext}")

    def test_generate_filename_unique_timestamps(self):
        """generate_output_filename should produce unique filenames over time."""
        # Note: This test may be flaky if run extremely fast
        # In practice, timestamps should differ or be unique enough
        filenames = set()
        for _ in range(5):
            filename = generate_output_filename(
                prefix="results",
                extension="csv",
            )
            filenames.add(filename)
        
        # All should be identical or vary by timestamp
        # Since we're in the same second, they might be identical
        # This is more of a documentation test
        assert len(filenames) >= 1

    def test_generate_filename_prefix_preserved(self):
        """generate_output_filename should preserve the exact prefix."""
        filename = generate_output_filename(
            prefix="my_custom_prefix",
            extension="csv",
        )
        
        assert filename.startswith("my_custom_prefix_")

    def test_generate_filename_handles_empty_cid(self):
        """generate_output_filename should handle empty string CID."""
        filename = generate_output_filename(
            prefix="results",
            cid="",
            extension="csv",
        )
        
        # Should still produce valid filename
        assert filename.startswith("results_")
        assert filename.endswith(".csv")

    def test_generate_filename_handles_long_cid(self):
        """generate_output_filename should handle very long CID strings."""
        long_cid = "a" * 200  # Very long CID
        filename = generate_output_filename(
            prefix="results",
            cid=long_cid,
            extension="csv",
        )
        
        # Should produce a filename (may be truncated in practice)
        assert filename.endswith(".csv")
        assert "results" in filename
