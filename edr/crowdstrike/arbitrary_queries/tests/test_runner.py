"""
Tests for arbitrary_queries.runner module.

Tests the orchestration layer that ties configuration, client setup,
query execution, and output generation together. Orchestration code is
where integration bugs hide, so these tests verify that the glue logic
correctly coordinates the individual modules.
"""

import json
import pytest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

from arbitrary_queries.runner import (
    CIDFilterResult,
    load_cid_registry,
    load_cid_filter,
    load_cid_filter_with_details,
    load_query,
    get_all_cids,
    _build_summaries,
    _write_outputs,
    run,
)
from arbitrary_queries.models import (
    CIDInfo,
    ExecutionMode,
    QueryJobStatus,
    QueryResult,
    QuerySummary,
    OverallSummary,
)


# =============================================================================
# CIDFilterResult Tests
# =============================================================================


class TestCIDFilterResult:
    """Tests for CIDFilterResult dataclass.
    
    CIDFilterResult is frozen for consistency with the project's other
    data containers. These tests verify the dataclass contract.
    """

    def test_create_cid_filter_result(self):
        """CIDFilterResult should store matched and unmatched entries."""
        matched = (CIDInfo(cid="abc", name="Acme"),)
        unmatched = ((3, "unknown-cid"),)
        
        result = CIDFilterResult(matched=matched, unmatched=unmatched)
        
        assert len(result.matched) == 1
        assert result.matched[0].cid == "abc"
        assert len(result.unmatched) == 1
        assert result.unmatched[0] == (3, "unknown-cid")

    def test_cid_filter_result_is_frozen(self):
        """CIDFilterResult should be immutable."""
        result = CIDFilterResult(matched=(), unmatched=())
        
        with pytest.raises(FrozenInstanceError):
            setattr(result, "matched", ())

    def test_cid_filter_result_empty(self):
        """CIDFilterResult should handle empty tuples."""
        result = CIDFilterResult(matched=(), unmatched=())
        
        assert result.matched == ()
        assert result.unmatched == ()


# =============================================================================
# load_cid_registry Tests
# =============================================================================


class TestLoadCIDRegistry:
    """Tests for load_cid_registry function.
    
    Verifies JSON loading, error handling for missing/invalid files,
    and correct dictionary structure.
    """

    def test_load_registry_success(self, tmp_path):
        """load_cid_registry should parse JSON and return dict."""
        registry_data = {
            "abc123": "Acme Corporation",
            "def456": "Beta Industries",
        }
        registry_file = tmp_path / "registry.json"
        registry_file.write_text(json.dumps(registry_data))
        
        result = load_cid_registry(registry_file)
        
        assert result == registry_data
        assert result["abc123"] == "Acme Corporation"

    def test_load_registry_missing_file(self, tmp_path):
        """load_cid_registry should raise FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            load_cid_registry(tmp_path / "nonexistent.json")

    def test_load_registry_invalid_json(self, tmp_path):
        """load_cid_registry should raise JSONDecodeError for malformed JSON."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json content")
        
        with pytest.raises(json.JSONDecodeError):
            load_cid_registry(bad_file)

    def test_load_registry_empty_dict(self, tmp_path):
        """load_cid_registry should handle empty registry."""
        registry_file = tmp_path / "empty.json"
        registry_file.write_text("{}")
        
        result = load_cid_registry(registry_file)
        
        assert result == {}


# =============================================================================
# load_cid_filter Tests
# =============================================================================


class TestLoadCIDFilter:
    """Tests for load_cid_filter function.
    
    CID filter files allow analysts to target specific customers.
    These tests verify matching by CID, matching by name,
    comment/blank line handling, and case-insensitive lookups.
    """

    @pytest.fixture
    def registry(self):
        """Registry for CID filter tests."""
        return {
            "abc123def456": "Acme Corporation",
            "xyz789ghi012": "Globex Industries",
            "mno345pqr678": "Initech LLC",
        }

    def test_filter_by_cid(self, tmp_path, registry):
        """load_cid_filter should match entries by CID."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text("abc123def456\n")
        
        result = load_cid_filter(filter_file, registry)
        
        assert len(result) == 1
        assert result[0].cid == "abc123def456"
        assert result[0].name == "Acme Corporation"

    def test_filter_by_name(self, tmp_path, registry):
        """load_cid_filter should match entries by customer name."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text("Globex Industries\n")
        
        result = load_cid_filter(filter_file, registry)
        
        assert len(result) == 1
        assert result[0].cid == "xyz789ghi012"

    def test_filter_case_insensitive(self, tmp_path, registry):
        """load_cid_filter should match case-insensitively."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text("ABC123DEF456\nacme corporation\n")
        
        result = load_cid_filter(filter_file, registry)
        
        assert len(result) == 2

    def test_filter_skips_comments(self, tmp_path, registry):
        """load_cid_filter should skip lines starting with #."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text(
            "# This is a comment\n"
            "abc123def456\n"
            "# Another comment\n"
        )
        
        result = load_cid_filter(filter_file, registry)
        
        assert len(result) == 1

    def test_filter_skips_blank_lines(self, tmp_path, registry):
        """load_cid_filter should skip blank and whitespace-only lines."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text(
            "\n"
            "abc123def456\n"
            "   \n"
            "xyz789ghi012\n"
            "\n"
        )
        
        result = load_cid_filter(filter_file, registry)
        
        assert len(result) == 2

    def test_filter_warns_unmatched(self, tmp_path, registry, caplog):
        """load_cid_filter should warn about unmatched entries by default."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text("nonexistent-cid\n")
        
        import logging
        with caplog.at_level(logging.WARNING):
            result = load_cid_filter(filter_file, registry, warn_unmatched=True)
        
        assert len(result) == 0
        assert "nonexistent-cid" in caplog.text

    def test_filter_suppresses_warnings(self, tmp_path, registry, caplog):
        """load_cid_filter should suppress warnings when warn_unmatched=False."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text("nonexistent-cid\n")
        
        import logging
        with caplog.at_level(logging.WARNING):
            result = load_cid_filter(filter_file, registry, warn_unmatched=False)
        
        assert len(result) == 0
        assert "nonexistent-cid" not in caplog.text

    def test_filter_mixed_matches_and_misses(self, tmp_path, registry):
        """load_cid_filter should return only matched CIDs."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text(
            "abc123def456\n"
            "does-not-exist\n"
            "Initech LLC\n"
        )
        
        result = load_cid_filter(filter_file, registry, warn_unmatched=False)
        
        assert len(result) == 2
        cids = {r.cid for r in result}
        assert "abc123def456" in cids
        assert "mno345pqr678" in cids

    def test_filter_empty_file(self, tmp_path, registry):
        """load_cid_filter should return empty list for empty file."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text("")
        
        result = load_cid_filter(filter_file, registry)
        
        assert result == []


# =============================================================================
# load_cid_filter_with_details Tests
# =============================================================================


class TestLoadCIDFilterWithDetails:
    """Tests for load_cid_filter_with_details function.
    
    Returns a CIDFilterResult with both matched and unmatched entries,
    useful for reporting which filter lines were resolved.
    """

    @pytest.fixture
    def registry(self):
        """Registry for detailed filter tests."""
        return {
            "abc123def456": "Acme Corporation",
            "xyz789ghi012": "Globex Industries",
        }

    def test_details_includes_matched(self, tmp_path, registry):
        """load_cid_filter_with_details should populate matched tuple."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text("abc123def456\n")
        
        result = load_cid_filter_with_details(filter_file, registry)
        
        assert len(result.matched) == 1
        assert result.matched[0].cid == "abc123def456"

    def test_details_includes_unmatched_with_line_numbers(self, tmp_path, registry):
        """load_cid_filter_with_details should track unmatched entries with line numbers."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text(
            "# comment\n"          # line 1 — skipped
            "abc123def456\n"       # line 2 — matched
            "unknown-entry\n"      # line 3 — unmatched
            "\n"                   # line 4 — blank, skipped
            "also-unknown\n"       # line 5 — unmatched
        )
        
        result = load_cid_filter_with_details(filter_file, registry)
        
        assert len(result.matched) == 1
        assert len(result.unmatched) == 2
        assert result.unmatched[0] == (3, "unknown-entry")
        assert result.unmatched[1] == (5, "also-unknown")

    def test_details_returns_frozen_dataclass(self, tmp_path, registry):
        """load_cid_filter_with_details should return an immutable CIDFilterResult."""
        filter_file = tmp_path / "cids.txt"
        filter_file.write_text("abc123def456\n")
        
        result = load_cid_filter_with_details(filter_file, registry)
        
        assert isinstance(result, CIDFilterResult)
        with pytest.raises(FrozenInstanceError):
            setattr(result, "matched", ())


# =============================================================================
# load_query Tests
# =============================================================================


class TestLoadQuery:
    """Tests for load_query function."""

    def test_load_query_reads_file(self, tmp_path):
        """load_query should read and return file contents."""
        query_file = tmp_path / "hunt.txt"
        query_file.write_text('#event_simpleName="ProcessRollup2"')
        
        result = load_query(query_file)
        
        assert result == '#event_simpleName="ProcessRollup2"'

    def test_load_query_strips_whitespace(self, tmp_path):
        """load_query should strip leading/trailing whitespace."""
        query_file = tmp_path / "hunt.txt"
        query_file.write_text("  \n  test query  \n  ")
        
        result = load_query(query_file)
        
        assert result == "test query"


# =============================================================================
# get_all_cids Tests
# =============================================================================


class TestGetAllCIDs:
    """Tests for get_all_cids function."""

    def test_converts_registry_to_cid_infos(self, sample_cid_registry):
        """get_all_cids should convert registry dict to CIDInfo list."""
        result = get_all_cids(sample_cid_registry)
        
        assert len(result) == 3
        assert all(isinstance(r, CIDInfo) for r in result)

    def test_preserves_cid_name_mapping(self, sample_cid_registry):
        """get_all_cids should preserve CID-to-name mapping."""
        result = get_all_cids(sample_cid_registry)
        
        mapping = {r.cid: r.name for r in result}
        assert mapping == sample_cid_registry

    def test_empty_registry(self):
        """get_all_cids should return empty list for empty registry."""
        result = get_all_cids({})
        
        assert result == []


# =============================================================================
# _build_summaries Tests
# =============================================================================


class TestBuildSummaries:
    """Tests for _build_summaries helper function.
    
    This helper converts raw QueryResult objects into QuerySummary objects
    and computes aggregate counts. It's the bridge between execution and
    reporting.
    """

    def test_successful_results(self):
        """_build_summaries should count successful queries."""
        results = [
            QueryResult(
                cid="cid1", cid_name="Customer 1",
                events=({"event": "data"},), record_count=1,
                execution_time_seconds=5.0,
            ),
            QueryResult(
                cid="cid2", cid_name="Customer 2",
                events=(), record_count=0,
                execution_time_seconds=3.0,
            ),
        ]
        
        summaries, total_records, successful, failed = _build_summaries(results, 10.0)
        
        assert len(summaries) == 2
        assert total_records == 1
        assert successful == 2
        assert failed == 0

    def test_failed_results(self):
        """_build_summaries should count failed queries via error field."""
        results = [
            QueryResult(
                cid="cid1", cid_name="Customer 1",
                events=(), record_count=0,
                error="Connection timeout",
                execution_time_seconds=2.0,
            ),
        ]
        
        summaries, total_records, successful, failed = _build_summaries(results, 5.0)
        
        assert len(summaries) == 1
        assert total_records == 0
        assert successful == 0
        assert failed == 1
        assert summaries[0].status == QueryJobStatus.FAILED
        assert summaries[0].error == "Connection timeout"

    def test_mixed_results(self):
        """_build_summaries should handle mix of successes and failures."""
        results = [
            QueryResult(
                cid="cid1", cid_name="OK",
                events=({"a": 1},), record_count=1,
                execution_time_seconds=1.0,
            ),
            QueryResult(
                cid="cid2", cid_name="Failed",
                events=(), record_count=0,
                error="Timeout", execution_time_seconds=10.0,
            ),
            QueryResult(
                cid="cid3", cid_name="Also OK",
                events=({"b": 2}, {"c": 3}), record_count=2,
                execution_time_seconds=2.5,
            ),
        ]
        
        summaries, total_records, successful, failed = _build_summaries(results, 15.0)
        
        assert total_records == 3
        assert successful == 2
        assert failed == 1

    def test_preserves_execution_time(self):
        """_build_summaries should carry per-query timing into summaries."""
        results = [
            QueryResult(
                cid="cid1", cid_name="Timed",
                events=(), record_count=0,
                execution_time_seconds=42.5,
            ),
        ]
        
        summaries, _, _, _ = _build_summaries(results, 50.0)
        
        assert summaries[0].execution_time_seconds == 42.5

    def test_empty_results(self):
        """_build_summaries should handle empty result list."""
        summaries, total_records, successful, failed = _build_summaries([], 0.0)
        
        assert summaries == []
        assert total_records == 0
        assert successful == 0
        assert failed == 0


# =============================================================================
# _write_outputs Tests
# =============================================================================


class TestWriteOutputs:
    """Tests for _write_outputs helper function."""

    def test_batch_mode_creates_one_file(self, tmp_path):
        """_write_outputs in batch mode should create exactly one CSV."""
        results = [
            QueryResult(
                cid="batch", cid_name="Batch (2 CIDs)",
                events=({"data": "test"},), record_count=1,
            ),
        ]
        
        _write_outputs(ExecutionMode.BATCH, results, tmp_path, verbose=False)
        
        files = list(tmp_path.glob("*.csv"))
        assert len(files) == 1
        assert "batch_results" in files[0].name

    def test_iterative_mode_creates_per_cid_files(self, tmp_path):
        """_write_outputs in iterative mode should create one file per CID."""
        results = [
            QueryResult(
                cid="cid1", cid_name="Customer 1",
                events=({"data": "test"},), record_count=1,
            ),
            QueryResult(
                cid="cid2", cid_name="Customer 2",
                events=(), record_count=0,
            ),
        ]
        
        _write_outputs(ExecutionMode.ITERATIVE, results, tmp_path, verbose=False)
        
        files = list(tmp_path.glob("*.csv"))
        assert len(files) == 2

    def test_creates_output_directory(self, tmp_path):
        """_write_outputs should create the output directory if needed."""
        output_dir = tmp_path / "nested" / "output"
        results = [
            QueryResult(
                cid="batch", cid_name="Batch",
                events=(), record_count=0,
            ),
        ]
        
        _write_outputs(ExecutionMode.BATCH, results, output_dir, verbose=False)
        
        assert output_dir.exists()

    def test_batch_mode_asserts_single_result(self, tmp_path):
        """_write_outputs should raise AssertionError if batch has multiple results."""
        results = [
            QueryResult(cid="a", cid_name="A", events=(), record_count=0),
            QueryResult(cid="b", cid_name="B", events=(), record_count=0),
        ]
        
        with pytest.raises(AssertionError, match="Batch mode expected 1 result"):
            _write_outputs(ExecutionMode.BATCH, results, tmp_path, verbose=False)


# =============================================================================
# run() Integration Tests
# =============================================================================


class TestRun:
    """Integration tests for the main run() orchestration function.
    
    These tests mock external dependencies (1Password, CrowdStrike API)
    to verify that run() correctly wires together config loading, CID
    resolution, query execution, output writing, and summary building.
    """

    @pytest.fixture
    def mock_config_file(self, tmp_path):
        """Create a minimal valid config file."""
        config = {
            "onepassword": {
                "client_id_ref": "op://vault/item/client_id",
                "client_secret_ref": "op://vault/item/client_secret",
            },
            "crowdstrike": {
                "base_url": "https://api.example.com",
                "repository": "test-repo",
            },
            "paths": {
                "cid_registry_path": str(tmp_path / "registry.json"),
                "output_dir": str(tmp_path / "output"),
            },
        }
        config_path = tmp_path / "settings.json"
        config_path.write_text(json.dumps(config))
        return config_path

    @pytest.fixture
    def mock_registry_file(self, tmp_path):
        """Create a CID registry file."""
        registry = {
            "cid001": "Test Customer 1",
            "cid002": "Test Customer 2",
        }
        registry_path = tmp_path / "registry.json"
        registry_path.write_text(json.dumps(registry))
        return registry_path

    @pytest.fixture
    def mock_query_file(self, tmp_path):
        """Create a query file."""
        query_path = tmp_path / "hunt.txt"
        query_path.write_text('#event_simpleName="ProcessRollup2"')
        return query_path

    @pytest.mark.asyncio
    async def test_run_returns_overall_summary(
        self, mock_config_file, mock_registry_file, mock_query_file, tmp_path
    ):
        """run() should return an OverallSummary."""
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_client.submit_query = AsyncMock(return_value="job-1")
        mock_client.get_query_status = AsyncMock(return_value={
            "done": True, "events": [], "metaData": {"eventCount": 0},
        })
        
        with patch("arbitrary_queries.runner.get_credentials") as mock_creds, \
             patch("arbitrary_queries.runner.CrowdStrikeClient", return_value=mock_client):
            mock_creds.return_value = MagicMock()
            
            result = await run(
                config_path=mock_config_file,
                query_path=mock_query_file,
                mode=ExecutionMode.BATCH,
            )
        
        assert isinstance(result, OverallSummary)
        assert result.mode == ExecutionMode.BATCH

    @pytest.mark.asyncio
    async def test_run_no_cids_returns_empty_summary(
        self, tmp_path, mock_query_file
    ):
        """run() should return zero-CID summary when registry is empty."""
        # Empty registry
        registry_path = tmp_path / "registry.json"
        registry_path.write_text("{}")
        
        config = {
            "onepassword": {
                "client_id_ref": "op://vault/item/client_id",
                "client_secret_ref": "op://vault/item/client_secret",
            },
            "paths": {
                "cid_registry_path": str(registry_path),
                "output_dir": str(tmp_path / "output"),
            },
        }
        config_path = tmp_path / "settings.json"
        config_path.write_text(json.dumps(config))
        
        result = await run(
            config_path=config_path,
            query_path=mock_query_file,
            mode=ExecutionMode.BATCH,
        )
        
        assert result.total_cids == 0
        assert result.successful_cids == 0
        assert result.failed_cids == 0

    @pytest.mark.asyncio
    async def test_run_with_cid_filter(
        self, mock_config_file, mock_registry_file, mock_query_file, tmp_path
    ):
        """run() should filter CIDs when a filter file is provided."""
        filter_path = tmp_path / "filter.txt"
        filter_path.write_text("cid001\n")
        
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_client.submit_query = AsyncMock(return_value="job-1")
        mock_client.get_query_status = AsyncMock(return_value={
            "done": True, "events": [], "metaData": {"eventCount": 0},
        })
        
        with patch("arbitrary_queries.runner.get_credentials") as mock_creds, \
             patch("arbitrary_queries.runner.CrowdStrikeClient", return_value=mock_client):
            mock_creds.return_value = MagicMock()
            
            result = await run(
                config_path=mock_config_file,
                query_path=mock_query_file,
                mode=ExecutionMode.BATCH,
                cid_filter_path=filter_path,
            )
        
        # Only 1 CID was in the filter
        assert result.total_cids == 1

    @pytest.mark.asyncio
    async def test_run_iterative_mode(
        self, mock_config_file, mock_registry_file, mock_query_file, tmp_path
    ):
        """run() in iterative mode should produce per-CID results."""
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_client.submit_query = AsyncMock(return_value="job-1")
        mock_client.get_query_status = AsyncMock(return_value={
            "done": True, "events": [{"test": "data"}],
            "metaData": {"eventCount": 1},
        })
        
        with patch("arbitrary_queries.runner.get_credentials") as mock_creds, \
             patch("arbitrary_queries.runner.CrowdStrikeClient", return_value=mock_client):
            mock_creds.return_value = MagicMock()
            
            result = await run(
                config_path=mock_config_file,
                query_path=mock_query_file,
                mode=ExecutionMode.ITERATIVE,
            )
        
        assert result.mode == ExecutionMode.ITERATIVE
        assert result.total_cids == 2  # Two CIDs in mock registry
        assert result.total_execution_time_seconds > 0

    @pytest.mark.asyncio
    async def test_run_batch_success_counts_all_cids_successful(
        self, mock_config_file, mock_registry_file, mock_query_file, tmp_path
    ):
        """In batch mode, a successful query should mark all CIDs as successful."""
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_client.submit_query = AsyncMock(return_value="job-1")
        mock_client.get_query_status = AsyncMock(return_value={
            "done": True, "events": [{"data": "test"}],
            "metaData": {"eventCount": 1},
        })

        with patch("arbitrary_queries.runner.get_credentials") as mock_creds, \
             patch("arbitrary_queries.runner.CrowdStrikeClient", return_value=mock_client):
            mock_creds.return_value = MagicMock()

            result = await run(
                config_path=mock_config_file,
                query_path=mock_query_file,
                mode=ExecutionMode.BATCH,
            )

        assert result.total_cids == 2
        assert result.successful_cids == 2
        assert result.failed_cids == 0

    @pytest.mark.asyncio
    async def test_run_batch_failure_counts_all_cids_failed(
        self, mock_config_file, mock_registry_file, mock_query_file, tmp_path
    ):
        """In batch mode, a failed query should mark all CIDs as failed."""
        mock_client = MagicMock()
        mock_client.close = AsyncMock()

        # Mock run_batch to return a QueryResult with an error
        failed_result = QueryResult(
            cid="batch",
            cid_name="Batch (2 CIDs)",
            events=(),
            record_count=0,
            error="Query timed out after 3600s",
            execution_time_seconds=3600.0,
        )

        with patch("arbitrary_queries.runner.get_credentials") as mock_creds, \
             patch("arbitrary_queries.runner.CrowdStrikeClient", return_value=mock_client), \
             patch("arbitrary_queries.runner.QueryExecutor") as mock_executor_cls:
            mock_creds.return_value = MagicMock()
            mock_executor = MagicMock()
            mock_executor.run_batch = AsyncMock(return_value=failed_result)
            mock_executor_cls.return_value = mock_executor

            result = await run(
                config_path=mock_config_file,
                query_path=mock_query_file,
                mode=ExecutionMode.BATCH,
            )

        assert result.total_cids == 2
        assert result.successful_cids == 0
        assert result.failed_cids == 2

    @pytest.mark.asyncio
    async def test_run_iterative_counts_match_individual_outcomes(
        self, mock_config_file, mock_registry_file, mock_query_file, tmp_path
    ):
        """In iterative mode, successful/failed counts should reflect per-CID outcomes."""
        mock_client = MagicMock()
        mock_client.close = AsyncMock()

        # One CID succeeds, one fails
        iterative_results = [
            QueryResult(
                cid="cid001",
                cid_name="Test Customer 1",
                events=({"data": "test"},),
                record_count=1,
                execution_time_seconds=5.0,
            ),
            QueryResult(
                cid="cid002",
                cid_name="Test Customer 2",
                events=(),
                record_count=0,
                error="Query submission failed",
                execution_time_seconds=2.0,
            ),
        ]

        with patch("arbitrary_queries.runner.get_credentials") as mock_creds, \
             patch("arbitrary_queries.runner.CrowdStrikeClient", return_value=mock_client), \
             patch("arbitrary_queries.runner.QueryExecutor") as mock_executor_cls:
            mock_creds.return_value = MagicMock()
            mock_executor = MagicMock()
            mock_executor.run_iterative = AsyncMock(return_value=iterative_results)
            mock_executor_cls.return_value = mock_executor

            result = await run(
                config_path=mock_config_file,
                query_path=mock_query_file,
                mode=ExecutionMode.ITERATIVE,
            )

        assert result.total_cids == 2
        assert result.successful_cids == 1
        assert result.failed_cids == 1
