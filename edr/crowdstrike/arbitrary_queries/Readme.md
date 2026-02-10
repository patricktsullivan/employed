# Arbitrary Queries

A Python CLI tool for running CrowdStrike NG-SIEM queries across multiple tenant environments (CIDs). Designed for MSSPs managing 200+ CrowdStrike environments through a parent-child hierarchy.

## Features

- **Multi-tenant Queries**: Run NG-SIEM queries across all or selected customer environments
- **Two Execution Modes**:
  - **Batch**: Single query with CID filter, produces one combined CSV
  - **Iterative**: Separate query per CID with concurrency control, produces per-CID CSVs
- **Secure Credential Management**: Uses 1Password CLI for API credentials
- **Async Execution**: Efficient polling with configurable concurrency (up to 50 parallel queries)
- **Automatic Retries**: Configurable retry logic for transient failures
- **Rich Output**: CSV exports with execution summaries

## Design Decisions

This section explains *why* the project is structured the way it is. If you're learning Python and want to understand the rationale behind the patterns used here, start here.

**`src/` layout** — The project uses a `src/arbitrary_queries/` layout rather than putting modules at the repository root. This prevents accidental imports from the working directory and forces you to install the package (via `pip install -e .`) before running it, which mirrors how real-world packages work.

**Dataclasses for models** — All data containers (`CIDInfo`, `QueryResult`, `QuerySummary`, etc.) use `@dataclass(frozen=True, slots=True)`. `frozen=True` makes instances immutable, which is critical because query results are shared across concurrent async tasks — mutation would cause race conditions. `slots=True` reduces memory overhead, which matters when tracking 200+ CIDs.

**Async for queries** — CrowdStrike NG-SIEM queries are I/O-bound: you submit a query, then poll repeatedly until it completes. `asyncio` lets us poll dozens of queries concurrently without threads. The `Semaphore` in `run_iterative()` caps concurrency to avoid overwhelming the API.

**1Password for secrets** — API credentials never touch config files, environment variables, or command-line arguments. The `op://` URI scheme lets us reference secrets by vault path. This is a best practice for security tooling: credentials exist only in memory for the duration of the process.

**Tuples over lists for immutability** — Query result events are stored as `tuple[dict, ...]` rather than `list[dict]`. Lists are mutable, so a caller could accidentally `.append()` to results. Tuples enforce the contract that results are read-only after construction.

**JSON as the default config format** — While YAML config is supported (and includes helpful inline comments), JSON is currently the default because our team is more familiar with it. YAML support was added as a learning exercise and will become the default in a future release, since YAML supports inline comments that make configuration self-documenting.

## Prerequisites

1. **Python 3.10+**
2. **1Password CLI** (`op`) installed and configured
   ```bash
   # macOS
   brew install 1password-cli

   # Linux - see https://developer.1password.com/docs/cli/get-started/
   ```
3. **CrowdStrike API Credentials** stored in 1Password:
   - API Client ID with NG-SIEM read permissions
   - API Client Secret
   - Credentials must be for the parent MSSP environment

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/arbitrary-queries.git
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

> **Tip:** If you prefer inline comments in your config, use `config/settings.yaml` instead. Pass it with `-c config/settings.yaml`.

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
# targets.txt - Comments start with #
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

# Custom format
arbitrary-queries -q queries/hunt.txt -s "2024-01-01T00:00:00Z" -e "2024-01-07T23:59:59Z"
```

### Custom Configuration

```bash
arbitrary-queries -q queries/hunt.txt -c config/production.yaml
```

## CLI Reference

```
Usage: arbitrary-queries [OPTIONS]

Options:
  -c, --config PATH    Configuration file path [default: ./config/settings.json]
  -q, --query PATH     Query file path (required)
  -m, --mode TEXT      Execution mode: batch or iterative [default: batch]
  --cids PATH          CID filter file (optional, runs all CIDs if not specified)
  -s, --start TEXT     Query start time [default: from config, typically -7d]
  -e, --end TEXT       Query end time [default: now]
  -v, --verbose        Enable verbose output
```

## Configuration Reference

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `onepassword` | `client_id_ref` | *(required)* | `op://` reference for CrowdStrike client ID |
| `onepassword` | `client_secret_ref` | *(required)* | `op://` reference for CrowdStrike client secret |
| `crowdstrike` | `base_url` | `https://api.laggar.gcw.crowdstrike.com` | CrowdStrike API base URL |
| `crowdstrike` | `repository` | `search-all` | NG-SIEM repository name |
| `query_defaults` | `time_range` | `-7d` | Default time range for queries |
| `query_defaults` | `poll_interval_seconds` | `60` | Seconds between status polls |
| `query_defaults` | `timeout_seconds` | `3600` | Max wait time per query |
| `concurrency` | `max_concurrent_queries` | `50` | Max parallel queries (iterative mode) |
| `concurrency` | `retry_attempts` | `3` | Retry count for transient failures |
| `concurrency` | `retry_delay_seconds` | `5` | Delay between retries |
| `paths` | `cid_registry_path` | `./data/cid_registry.json` | CID to name mapping file |
| `paths` | `queries_dir` | `./queries` | Query files directory |
| `paths` | `output_dir` | `./output` | CSV output directory |

## Development

### Running Tests

```bash
# Run all tests
pytest

# With coverage
pytest --cov=arbitrary_queries --cov-report=html

# Run specific test file
pytest tests/test_client.py -v
```

### Project Structure

```
arbitrary-queries/
├── src/
│   └── arbitrary_queries/
│       ├── __init__.py       # Package version
│       ├── models.py         # Data classes (CIDInfo, QueryResult, etc.)
│       ├── secrets.py        # 1Password CLI integration
│       ├── config.py         # Configuration loading (JSON/YAML)
│       ├── client.py         # CrowdStrike API wrapper (async)
│       ├── query_executor.py # Async query execution and polling
│       ├── output.py         # CSV and summary generation
│       ├── runner.py         # Main orchestration
│       └── cli.py            # CLI entry point (argparse)
├── tests/                    # Test suite (pytest)
│   ├── conftest.py           # Shared fixtures
│   ├── test_models.py
│   ├── test_secrets.py
│   ├── test_config.py
│   ├── test_client.py
│   ├── test_query_executor.py
│   ├── test_output.py
│   ├── test_runner.py
│   └── test_cli.py
├── config/                   # Configuration files
│   ├── settings.json         # Default config (JSON)
│   └── settings.yaml         # Alternative config (YAML, with comments)
├── queries/                  # Query files
├── data/                     # CID registry
└── output/                   # Generated CSVs (gitignored)
```

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
- Add more specific filters to query

### Rate Limiting

- Reduce `max_concurrent_queries` in configuration
- Increase `retry_delay_seconds`

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request. All code should include tests and follow the existing PEP 8 conventions used throughout the project.
