"""
Tests for arbitrary_queries.cli module.

Tests command-line argument parsing, path validation, and main entry point.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, AsyncMock

from arbitrary_queries.cli import parse_args, validate_paths, main
from arbitrary_queries.models import ExecutionMode


@pytest.fixture
def tmp_config(tmp_path):
    """Create a temporary config file."""
    config_file = tmp_path / "settings.json"
    config_file.write_text('{"onepassword": {}}')
    return config_file


@pytest.fixture
def tmp_query(tmp_path):
    """Create a temporary query file."""
    query_file = tmp_path / "query.txt"
    query_file.write_text('#event_simpleName="ProcessRollup2"')
    return query_file


@pytest.fixture
def tmp_cids(tmp_path):
    """Create a temporary CID filter file."""
    cid_file = tmp_path / "cids.txt"
    cid_file.write_text("cid1\ncid2\ncid3")
    return cid_file


class TestParseArgs:
    """Tests for parse_args function."""

    def test_parse_args_minimal(self, tmp_query):
        """parse_args should accept just required --query flag."""
        args = parse_args(["-q", str(tmp_query)])
        
        assert args.query == tmp_query
        assert args.config == Path("./config/settings.json")
        assert args.mode == "batch"
        assert args.cids is None
        assert args.start is None
        assert args.end == "now"
        assert args.verbose is False

    def test_parse_args_all_options(self, tmp_path):
        """parse_args should accept all options."""
        config = tmp_path / "config.yaml"
        query = tmp_path / "hunt.txt"
        cids = tmp_path / "targets.txt"
        
        args = parse_args([
            "-c", str(config),
            "-q", str(query),
            "-m", "iterative",
            "--cids", str(cids),
            "-s", "-24h",
            "-e", "-1h",
            "-v",
        ])
        
        assert args.config == config
        assert args.query == query
        assert args.mode == "iterative"
        assert args.cids == cids
        assert args.start == "-24h"
        assert args.end == "-1h"
        assert args.verbose is True

    def test_parse_args_long_options(self, tmp_path):
        """parse_args should accept long option names."""
        query = tmp_path / "query.txt"
        
        args = parse_args([
            "--query", str(query),
            "--mode", "batch",
            "--start", "-7d",
            "--end", "now",
            "--verbose",
        ])
        
        assert args.query == query
        assert args.mode == "batch"
        assert args.start == "-7d"
        assert args.end == "now"
        assert args.verbose is True

    def test_parse_args_query_required(self):
        """parse_args should require --query flag."""
        with pytest.raises(SystemExit) as exc_info:
            parse_args([])
        
        assert exc_info.value.code == 2  # argparse error exit code

    def test_parse_args_mode_choices(self, tmp_path):
        """parse_args should reject invalid mode choices."""
        query = tmp_path / "query.txt"
        
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["-q", str(query), "-m", "invalid"])
        
        assert exc_info.value.code == 2

    def test_parse_args_mode_batch(self, tmp_path):
        """parse_args should accept 'batch' mode."""
        query = tmp_path / "query.txt"
        
        args = parse_args(["-q", str(query), "-m", "batch"])
        
        assert args.mode == "batch"

    def test_parse_args_mode_iterative(self, tmp_path):
        """parse_args should accept 'iterative' mode."""
        query = tmp_path / "query.txt"
        
        args = parse_args(["-q", str(query), "-m", "iterative"])
        
        assert args.mode == "iterative"

    def test_parse_args_paths_are_path_objects(self, tmp_path):
        """parse_args should convert path strings to Path objects."""
        config = tmp_path / "settings.json"
        query = tmp_path / "query.txt"
        cids = tmp_path / "cids.txt"
        
        args = parse_args([
            "-c", str(config),
            "-q", str(query),
            "--cids", str(cids),
        ])
        
        assert isinstance(args.config, Path)
        assert isinstance(args.query, Path)
        assert isinstance(args.cids, Path)

    def test_parse_args_accepts_argv_list(self, tmp_path):
        """parse_args should accept explicit argv for testing."""
        query = tmp_path / "query.txt"
        
        # Should not read from sys.argv
        args = parse_args(["-q", str(query)])
        
        assert args.query == query

    def test_parse_args_default_config_path(self, tmp_path):
        """parse_args should use default config path."""
        query = tmp_path / "query.txt"
        
        args = parse_args(["-q", str(query)])
        
        assert args.config == Path("./config/settings.json")

    def test_parse_args_default_end_time(self, tmp_path):
        """parse_args should default end time to 'now'."""
        query = tmp_path / "query.txt"
        
        args = parse_args(["-q", str(query)])
        
        assert args.end == "now"


class TestValidatePaths:
    """Tests for validate_paths function."""

    def test_validate_paths_all_exist(self, tmp_config, tmp_query):
        """validate_paths should return empty list when all paths exist."""
        args = parse_args([
            "-c", str(tmp_config),
            "-q", str(tmp_query),
        ])
        
        errors = validate_paths(args)
        
        assert errors == []

    def test_validate_paths_all_exist_with_cids(self, tmp_config, tmp_query, tmp_cids):
        """validate_paths should validate optional cids path when provided."""
        args = parse_args([
            "-c", str(tmp_config),
            "-q", str(tmp_query),
            "--cids", str(tmp_cids),
        ])
        
        errors = validate_paths(args)
        
        assert errors == []

    def test_validate_paths_missing_config(self, tmp_query):
        """validate_paths should report missing config file."""
        args = parse_args([
            "-c", "/nonexistent/config.json",
            "-q", str(tmp_query),
        ])
        
        errors = validate_paths(args)
        
        assert len(errors) == 1
        assert "config" in errors[0].lower()

    def test_validate_paths_missing_query(self, tmp_config):
        """validate_paths should report missing query file."""
        args = parse_args([
            "-c", str(tmp_config),
            "-q", "/nonexistent/query.txt",
        ])
        
        errors = validate_paths(args)
        
        assert len(errors) == 1
        assert "query" in errors[0].lower()

    def test_validate_paths_missing_cids(self, tmp_config, tmp_query):
        """validate_paths should report missing cids file when specified."""
        args = parse_args([
            "-c", str(tmp_config),
            "-q", str(tmp_query),
            "--cids", "/nonexistent/cids.txt",
        ])
        
        errors = validate_paths(args)
        
        assert len(errors) == 1
        assert "cid" in errors[0].lower()

    def test_validate_paths_cids_none_ok(self, tmp_config, tmp_query):
        """validate_paths should not require cids when not specified."""
        args = parse_args([
            "-c", str(tmp_config),
            "-q", str(tmp_query),
        ])
        
        errors = validate_paths(args)
        
        assert errors == []

    def test_validate_paths_multiple_missing(self, tmp_path):
        """validate_paths should report all missing files."""
        args = parse_args([
            "-c", "/nonexistent/config.json",
            "-q", "/nonexistent/query.txt",
            "--cids", "/nonexistent/cids.txt",
        ])
        
        errors = validate_paths(args)
        
        assert len(errors) == 3


class TestMain:
    """Tests for main entry point."""

    def test_main_success(self, tmp_config, tmp_query):
        """main should return 0 on successful execution."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            exit_code = main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
            ])
        
        assert exit_code == 0
        mock_run.assert_called_once()

    def test_main_calls_run_with_correct_args(self, tmp_config, tmp_query, tmp_cids):
        """main should pass parsed arguments to run()."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
                "-m", "iterative",
                "--cids", str(tmp_cids),
                "-s", "-24h",
                "-e", "-1h",
                "-v",
            ])
        
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        
        assert call_kwargs["config_path"] == tmp_config
        assert call_kwargs["query_path"] == tmp_query
        assert call_kwargs["mode"] == ExecutionMode.ITERATIVE
        assert call_kwargs["cid_filter_path"] == tmp_cids
        assert call_kwargs["start_time"] == "-24h"
        assert call_kwargs["end_time"] == "-1h"
        assert call_kwargs["verbose"] is True

    def test_main_batch_mode(self, tmp_config, tmp_query):
        """main should convert 'batch' to ExecutionMode.BATCH."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
                "-m", "batch",
            ])
        
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["mode"] == ExecutionMode.BATCH

    def test_main_iterative_mode(self, tmp_config, tmp_query):
        """main should convert 'iterative' to ExecutionMode.ITERATIVE."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
                "-m", "iterative",
            ])
        
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["mode"] == ExecutionMode.ITERATIVE

    def test_main_missing_config_returns_1(self, tmp_query, capsys):
        """main should return 1 when config file is missing."""
        exit_code = main([
            "-c", "/nonexistent/config.json",
            "-q", str(tmp_query),
        ])
        
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "config" in captured.err.lower()

    def test_main_missing_query_returns_1(self, tmp_config, capsys):
        """main should return 1 when query file is missing."""
        exit_code = main([
            "-c", str(tmp_config),
            "-q", "/nonexistent/query.txt",
        ])
        
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "query" in captured.err.lower()

    def test_main_keyboard_interrupt_returns_130(self, tmp_config, tmp_query, capsys):
        """main should return 130 on KeyboardInterrupt (SIGINT convention)."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = KeyboardInterrupt()
            
            exit_code = main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
            ])
        
        assert exit_code == 130
        captured = capsys.readouterr()
        assert "aborted" in captured.err.lower()

    def test_main_exception_returns_1(self, tmp_config, tmp_query, capsys):
        """main should return 1 on exception."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = RuntimeError("Something went wrong")
            
            exit_code = main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
            ])
        
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "something went wrong" in captured.err.lower()

    def test_main_verbose_shows_traceback(self, tmp_config, tmp_query, capsys):
        """main should show traceback when verbose and exception occurs."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = RuntimeError("Verbose error")
            
            exit_code = main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
                "-v",
            ])
        
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Traceback" in captured.err

    def test_main_non_verbose_hides_traceback(self, tmp_config, tmp_query, capsys):
        """main should hide traceback when not verbose."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = RuntimeError("Non-verbose error")
            
            exit_code = main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
            ])
        
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err

    def test_main_cids_none_when_not_specified(self, tmp_config, tmp_query):
        """main should pass None for cid_filter_path when not specified."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
            ])
        
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["cid_filter_path"] is None

    def test_main_start_none_when_not_specified(self, tmp_config, tmp_query):
        """main should pass None for start_time when not specified."""
        with patch("arbitrary_queries.cli.run", new_callable=AsyncMock) as mock_run:
            main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
            ])
        
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["start_time"] is None


class TestMainIntegration:
    """Integration tests for main entry point."""

    def test_main_missing_required_arg_exits_2(self, capsys):
        """main should exit with code 2 when required arg missing."""
        with pytest.raises(SystemExit) as exc_info:
            main([])
        
        assert exc_info.value.code == 2

    def test_main_invalid_mode_exits_2(self, tmp_config, tmp_query):
        """main should exit with code 2 for invalid mode."""
        with pytest.raises(SystemExit) as exc_info:
            main([
                "-c", str(tmp_config),
                "-q", str(tmp_query),
                "-m", "invalid_mode",
            ])
        
        assert exc_info.value.code == 2

    def test_main_help_exits_0(self, capsys):
        """main --help should exit with code 0."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "NG-SIEM Hunter" in captured.out

    def test_main_help_shows_examples(self, capsys):
        """main --help should show usage examples."""
        with pytest.raises(SystemExit):
            main(["--help"])
        
        captured = capsys.readouterr()
        assert "Examples:" in captured.out
        assert "arbitrary-queries" in captured.out
