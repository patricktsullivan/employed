# Testing Guide — arbitrary-queries

This document describes the testing architecture, conventions, and practical details for running and writing tests in this project.

## Quick Start

```bash
# From the project root, install dev dependencies
pip install -e ".[dev]"

# Verify test dependencies are available
python -m pytest --version

# Run the full suite
pytest

# Run with verbose output and coverage
pytest --cov=arbitrary_queries --cov-report=html -v
```

### Required Dev Dependencies

The test suite depends on packages listed under `[project.optional-dependencies] dev` in `pyproject.toml`:

| Package | Purpose |
|---------|---------|
| `pytest>=8.0.0` | Test runner and assertion framework |
| `pytest-asyncio>=0.23.0` | Async test support (`@pytest.mark.asyncio`, auto mode) |
| `pytest-mock>=3.12.0` | `mocker` fixture for convenient mocking |
| `pytest-cov>=4.1.0` | Coverage measurement and reporting |

If any import fails when running tests, re-run `pip install -e ".[dev]"` to ensure all dev extras are installed.

## Architecture

### Design Principles

The test suite is built around two priorities from the project's inception: **test-driven development** and **safe concurrent execution**.

1. **No external dependencies at test time.** Every test runs without a 1Password CLI, CrowdStrike API credentials, or network access. All external interactions are mocked.

2. **Isolated and deterministic.** Tests use `tmp_path` fixtures for filesystem operations, `AsyncMock` for async API calls, and fixed timestamps via `mock_utc_now`. No test depends on another test's side effects.

3. **Structure mirrors source.** Each `src/arbitrary_queries/<module>.py` has a corresponding `tests/test_<module>.py`. Test classes group related scenarios (e.g., `TestParseArgs`, `TestValidatePaths`, `TestMain`).

4. **Fast feedback.** Polling intervals and retry delays are set to near-zero in test fixtures (`poll_interval_seconds=0.01`, `retry_delay_seconds=0.01`) so async tests complete in milliseconds, not seconds.

### pytest Configuration

Configured in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
addopts = "-v --tb=short"
```

- `asyncio_mode = "auto"` means any `async def test_*` function is automatically treated as an asyncio test — no need for `@pytest.mark.asyncio` on every test (though some files include it explicitly for clarity).
- `addopts = "-v --tb=short"` provides verbose test names with concise tracebacks by default.

### Coverage Configuration

```toml
[tool.coverage.run]
source = ["src/arbitrary_queries"]
branch = true

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "if __name__ == .__main__.:",
    "raise NotImplementedError",
]
```

Branch coverage is enabled, so both sides of conditionals are tracked. View the HTML report after running:

```bash
pytest --cov=arbitrary_queries --cov-report=html
# Open htmlcov/index.html in a browser
```

## Test Files

### `conftest.py` — Shared Fixtures

Provides reusable fixtures available to all test files without importing:

| Fixture | Type | Description |
|---------|------|-------------|
| `sample_cid` | `str` | A sample CID string (`"abc123def456"`) |
| `sample_cid_name` | `str` | A sample customer name (`"Acme Corporation"`) |
| `sample_query` | `str` | A sample NG-SIEM query string |
| `sample_events` | `list[dict]` | Three sample event dictionaries with realistic fields |
| `sample_cid_registry` | `dict[str, str]` | Three-entry CID-to-name mapping |
| `mock_utc_now` | `datetime` | Fixed UTC timestamp (`2026-02-04T12:00:00Z`) for deterministic time assertions |

### `test_models.py` — Data Classes

Tests all frozen dataclasses in `models.py`: `CIDInfo`, `QueryJob`, `QueryJobStatus`, `QueryResult`, `QuerySummary`, `OverallSummary`, `ExecutionMode`, and the convenience factory functions (`create_query_result`, `create_query_summary`, `create_overall_summary`).

Key areas covered:
- Immutability enforcement (`FrozenInstanceError` on mutation attempts)
- `__post_init__` validation (negative values, arithmetic consistency like `successful + failed == total`)
- Hashability (frozen dataclasses can be used in sets and as dict keys)
- String representations (`__str__`, `__repr__`)
- Property methods (`is_terminal`, `is_empty`, `success_rate`, `duration_seconds`, `has_error`)
- Factory functions converting lists to tuples for true immutability

### `test_secrets.py` — 1Password Integration

Tests `op_read`, `Credentials`, and `get_credentials` from `secrets.py`.

All 1Password CLI calls are mocked via `unittest.mock.patch("arbitrary_queries.secrets.subprocess.run")`. No real `op` binary is ever invoked.

Key areas covered:
- Successful secret retrieval and whitespace stripping
- CLI command structure verification (correct args, timeout, flags)
- Error handling: CLI not found (`FileNotFoundError`), timeout (`TimeoutExpired`), not signed in, generic failures
- `Credentials` immutability and secret redaction in `__repr__`/`__str__`
- `get_credentials` orchestration of two `op_read` calls

### `test_config.py` — Configuration Loading

Tests `load_config`, `load_config_from_json`, `load_config_from_yaml`, and all config dataclasses.

Uses `tmp_path` to write temporary JSON and YAML config files, then loads them.

Key areas covered:
- Successful loading from both JSON and YAML formats
- Auto-detection of format by file extension
- Default values when optional sections are omitted
- Validation: missing required `onepassword` section, invalid `op://` references
- Error handling: missing file, malformed JSON/YAML, unsupported file extension
- All config dataclass defaults match the documented values

### `test_client.py` — CrowdStrike API Client

Tests `CrowdStrikeClient` from `client.py`.

The FalconPy `OAuth2` client and `aiohttp.ClientSession` are mocked. No network calls are made.

Key areas covered:
- Client initialization and authentication
- Token refresh logic (including the 60-second buffer before expiry)
- Query submission, status polling, and result retrieval
- Error classes: `AuthenticationError`, `QuerySubmissionError`, `QueryStatusError`
- Async context manager (`async with`) lifecycle

### `test_query_executor.py` — Async Query Execution

Tests `QueryExecutor`, `execute_query`, and `poll_until_complete` from `query_executor.py`.

All client methods are `AsyncMock` instances. Polling and retry delays are set to near-zero for fast execution.

Key areas covered:
- Single query execution success and failure paths
- Polling loop behavior: completion detection, timeout (`QueryTimeoutError`), cancellation
- Batch mode: single query across all CIDs
- Iterative mode: concurrent per-CID queries with semaphore-based concurrency control
- Retry logic: transient failures, retry exhaustion
- `ErrorQueryResult` construction for failed queries

### `test_output.py` — CSV and Summary Formatting

Tests `write_csv`, `write_csv_per_cid`, `format_summary`, `format_overall_summary`, and `generate_output_filename` from `output.py`.

Uses `tmp_path` for all file I/O. CSV files are read back and verified.

Key areas covered:
- CSV creation, headers, row counts, and field values
- CID columns (`_cid`, `_cid_name`) added in batch mode
- Per-CID file generation in iterative mode
- Empty result handling
- Output filename generation with timestamps and CID identifiers
- Summary formatting for console display

### `test_cli.py` — Command-Line Interface

Tests `parse_args`, `validate_paths`, and `main` from `cli.py`.

Uses temporary files for config, query, and CID filter paths. The `run` function (from `runner.py`) is patched with `AsyncMock` so no actual queries execute.

Key areas covered:
- Argument parsing: required vs. optional flags, defaults, type conversion to `Path` objects
- Mode validation: `batch` and `iterative` accepted, invalid modes rejected with exit code 2
- Path validation: missing config/query/CID files reported as errors
- `main` orchestration: correct arguments passed to `run()`, `ExecutionMode` enum conversion
- Exit codes: `0` on success, `1` on error, `2` on argument parsing failure, `130` on `KeyboardInterrupt`
- Verbose mode: tracebacks shown on error; hidden when not verbose
- Help output: `--help` exits with code `0` and displays usage examples

## Writing New Tests

### Conventions

- Test files are named `test_<module>.py` matching the source module.
- Test classes are named `Test<Subject>` (e.g., `TestParseArgs`, `TestWriteCsv`).
- Test methods are named `test_<behavior>` with a docstring stating the expected behavior in the format `"<function> should <expected behavior>."`.
- Use fixtures from `conftest.py` where possible. Add new shared fixtures there; add test-file-specific fixtures at the top of the relevant test file.

### Async Tests

Because `asyncio_mode = "auto"` is set, simply define your test as `async def`:

```python
async def test_something_async(self, mock_client):
    """something_async should return results."""
    result = await something_async(mock_client)
    assert result is not None
```

### Mocking External Dependencies

The project's external boundaries are well-defined, making them straightforward to mock:

| Boundary | What to mock | Example |
|----------|-------------|---------|
| 1Password CLI | `subprocess.run` | `patch("arbitrary_queries.secrets.subprocess.run")` |
| CrowdStrike API | Client methods | `client.submit_query = AsyncMock(return_value="job-123")` |
| File system | Use `tmp_path` | `config_file = tmp_path / "settings.json"` |
| Time | `datetime.now` | `patch("arbitrary_queries.runner.datetime")` or `mock_utc_now` fixture |

### Adding a New Module

1. Create `src/arbitrary_queries/new_module.py`
2. Create `tests/test_new_module.py`
3. Add shared fixtures to `conftest.py` if they'll be reused
4. Run `pytest tests/test_new_module.py -v` during development
5. Verify full suite still passes: `pytest`
6. Check coverage: `pytest --cov=arbitrary_queries --cov-report=term-missing`
