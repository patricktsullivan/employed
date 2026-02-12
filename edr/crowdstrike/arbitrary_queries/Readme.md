# arbitrary-queries

A Python CLI tool for running CrowdStrike NG-SIEM queries across multiple tenant environments (CIDs). Designed for MSSPs managing 200+ CrowdStrike environments through a parent-child hierarchy.

## Features

- **Multi-tenant Queries**: Run NG-SIEM queries across all or selected customer environments
- **Two Execution Modes**:
  - **Batch**: Single query with CID filter, produces one combined CSV
  - **Iterative**: Separate query per CID with async concurrency control, produces per-CID CSVs
- **Secure Credential Management**: Uses 1Password CLI for API credentials — secrets are never stored in config files or environment variables
- **Async Execution**: Efficient polling with configurable concurrency (up to 50 parallel queries) using `asyncio` and `aiohttp`
- **Automatic Retries**: Configurable retry logic for transient failures
- **Rich Output**: CSV exports with execution summaries

## Prerequisites

1. **Python 3.10+**
2. **1Password CLI** (`op`) installed and configured
   ```bash
   # macOS
   brew install 1password-cli

   # Linux — see https://developer.1password.com/docs/cli/get-started/
   ```
3. **CrowdStrike API Credentials** stored in 1Password:
   - API Client ID with NG-SIEM read permissions
   - API Client Secret
   - Credentials must be for the parent MSSP environment

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/arbitrary-queries.git
cd arbitrary-queries

# Install with pip (editable mode for development)
pip install -e ".[dev]"

# Or install core dependencies only
pip install -e .
```

## Configuration

### 1. Configure 1Password References

Edit `config/settings.json` (or `config/settings.yaml`) with your 1Password secret references:

```json
{
  "onepassword": {
    "client_id_ref": "op://YourVault/CrowdStrike-Parent/client_id",
    "client_secret_ref": "op://YourVault/CrowdStrike-Parent/client_secret"
  }
}
```

### 2. Set Up CID Registry

Create `data/cid_registry.json` mapping CID identifiers to customer names:

```json
{
  "abc123def456abc123def456abc12345": "Acme Corporation",
  "def456abc123def456abc123def45678": "Beta Industries"
}
```

### 3. Create Query Files

Place NG-SIEM query files in the `queries/` directory:

```
// queries/suspicious_powershell.txt
#event_simpleName=/ProcessRollup2/
| ImageFileName=/powershell\.exe$/i
| CommandLine=/(-enc|bypass|hidden)/i
| groupBy([cid, ComputerName, CommandLine], function=count())
```

## Usage

### Basic Usage

```bash
# Run a query across all CIDs in batch mode (default)
arbitrary-queries -q queries/suspicious_powershell.txt

# Run in iterative mode (separate query per CID)
arbitrary-queries -q queries/hunt.txt -m iterative

# Verbose output
arbitrary-queries -q queries/hunt.txt -v
```

### Filtering CIDs

Create a filter file with CID identifiers or names (one per line):

```
# targets.txt — Comments start with #
abc123def456abc123def456abc12345
Acme Corporation
Beta Industries
```

```bash
arbitrary-queries -q queries/hunt.txt --cids data/targets.txt
```

### Custom Time Range

```bash
# Last 24 hours
arbitrary-queries -q queries/hunt.txt -s "-24h"

# Specific range
arbitrary-queries -q queries/hunt.txt -s "-7d" -e "-1d"

# Absolute timestamps
arbitrary-queries -q queries/hunt.txt -s "2024-01-01T00:00:00Z" -e "2024-01-07T23:59:59Z"
```

### Custom Configuration

```bash
arbitrary-queries -q queries/hunt.txt -c config/production.yaml
```

## CLI Reference

```
usage: arbitrary-queries [-h] [-c PATH] -q PATH [-m {batch,iterative}]
                         [--cids PATH] [-s TIME] [-e TIME] [-v]
```

### Required Arguments

| Flag | Description |
|------|-------------|
| `-q`, `--query PATH` | Path to the NG-SIEM query file |

### Optional Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `-c`, `--config PATH` | `./config/settings.json` | Path to configuration file (JSON or YAML) |
| `-m`, `--mode {batch,iterative}` | `batch` | Execution mode: `batch` runs a single query with CID filter; `iterative` runs a separate query per CID with concurrency control |
| `--cids PATH` | *(all CIDs)* | Path to CID filter file; if omitted, queries all CIDs in the registry |
| `-s`, `--start TIME` | *(from config, typically `-7d`)* | Query start time (e.g., `-7d`, `-24h`, or an absolute timestamp) |
| `-e`, `--end TIME` | `now` | Query end time |
| `-v`, `--verbose` | `false` | Enable verbose output with per-CID details and tracebacks on error |
| `--help` | | Show help message and exit |

### Examples

```bash
# Minimal — just a query file (uses all defaults)
arbitrary-queries -q queries/hunt.txt

# Full options
arbitrary-queries \
  -c config/settings.yaml \
  -q queries/hunt.txt \
  -m iterative \
  --cids data/target_cids.txt \
  -s "-24h" \
  -e "-1h" \
  -v
```

## Output

### CSV Files

- **Batch mode**: Single CSV at `output/batch_results_YYYYMMDD_HHMMSS.csv`
- **Iterative mode**: Per-CID CSVs at `output/<prefix>_YYYYMMDD_HHMMSS_<cid>.csv`

CSV columns include all event fields from query results. In batch mode, `_cid` and `_cid_name` columns are appended for filtering.

### Console Summary

```
=== Execution Summary ===
Mode: BATCH
Total CIDs: 15
Successful: 14
Failed: 1
Total Records: 2,847
Success Rate: 93.3%
Total Execution Time: 245.67s

Per-CID Results:
  [SUCCESS] Acme Corporation (abc123...): 523 records in 12.3s
  [SUCCESS] Beta Industries (def456...): 0 records in 8.1s
  [FAILED]  Gamma Healthcare (789abc...): Query timeout
  ...
```

## Configuration Reference

### settings.json / settings.yaml

| Section | Field | Default | Description |
|---------|-------|---------|-------------|
| `onepassword` | `client_id_ref` | **(required)** | 1Password `op://` reference for API client ID |
| `onepassword` | `client_secret_ref` | **(required)** | 1Password `op://` reference for API client secret |
| `crowdstrike` | `base_url` | `https://api.laggar.gcw.crowdstrike.com` | CrowdStrike API base URL (cloud-specific) |
| `crowdstrike` | `repository` | `search-all` | NG-SIEM repository name |
| `query_defaults` | `time_range` | `-7d` | Default query time range |
| `query_defaults` | `poll_interval_seconds` | `60` | Polling interval for query status (seconds) |
| `query_defaults` | `timeout_seconds` | `3600` | Maximum query wait time (seconds) |
| `concurrency` | `max_concurrent_queries` | `50` | Max parallel queries (iterative mode) |
| `concurrency` | `retry_attempts` | `3` | Retry count for failed queries |
| `concurrency` | `retry_delay_seconds` | `5` | Delay between retries (seconds) |
| `paths` | `cid_registry_path` | `./data/cid_registry.json` | CID-to-name mapping file |
| `paths` | `queries_dir` | `./queries` | Query files directory |
| `paths` | `output_dir` | `./output` | CSV output directory |

## Development

### Project Structure

```
arbitrary-queries/
├── src/
│   └── arbitrary_queries/
│       ├── __init__.py         # Package version
│       ├── models.py           # Frozen dataclasses (CIDInfo, QueryResult, etc.)
│       ├── secrets.py          # 1Password CLI integration
│       ├── config.py           # Configuration loading (JSON/YAML)
│       ├── client.py           # CrowdStrike NG-SIEM async API client
│       ├── query_executor.py   # Async query execution with concurrency control
│       ├── output.py           # CSV generation and summary formatting
│       ├── runner.py           # Main orchestration
│       └── cli.py              # CLI entry point (argparse)
├── tests/                      # Test suite — see tests/README.md
│   ├── conftest.py             # Shared pytest fixtures
│   ├── test_models.py
│   ├── test_secrets.py
│   ├── test_config.py
│   ├── test_client.py
│   ├── test_query_executor.py
│   ├── test_output.py
│   ├── test_cli.py
│   └── README.md               # Testing architecture and guide
├── config/                     # Configuration templates
│   ├── settings.json
│   └── settings.yaml
├── queries/                    # NG-SIEM query files
├── data/                       # CID registry
│   └── cid_registry.json
├── output/                     # Generated CSVs (gitignored)
├── pyproject.toml              # Project metadata and dependencies
└── README.md
```

### Running Tests

Install the dev dependencies first, then run the test suite:

```bash
# Install with dev dependencies (pytest, coverage, etc.)
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage report
pytest --cov=arbitrary_queries --cov-report=html

# Run a specific test file
pytest tests/test_client.py -v

# Run a specific test class or method
pytest tests/test_models.py::TestCIDInfo -v
pytest tests/test_cli.py::TestMain::test_main_success -v
```

For details on the testing architecture, fixtures, and what each test file covers, see [`tests/README.md`](tests/README.md).

## Troubleshooting

### 1Password CLI Not Found

```bash
# Verify installation
op --version

# Sign in (if not using biometrics)
eval $(op signin)
```

### Authentication Errors

- Verify API credentials have NG-SIEM read permissions
- Ensure credentials are for the parent MSSP environment
- Check 1Password references match your vault structure

### Query Timeouts

- Increase `timeout_seconds` in configuration
- Narrow time range with `-s` flag
- Add more specific filters to your query

### Rate Limiting

- Reduce `max_concurrent_queries` in configuration
- Increase `retry_delay_seconds`

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
