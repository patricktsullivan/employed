# ngsiem-hunter

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
git clone <repository-url>
cd ngsiem-hunter

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
ngsiem-hunter -q queries/suspicious_powershell.txt

# Run in iterative mode (separate query per CID)
ngsiem-hunter -q queries/hunt.txt -m iterative

# Verbose output
ngsiem-hunter -q queries/hunt.txt -v
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
ngsiem-hunter -q queries/hunt.txt --cids data/targets.txt
```

### Custom Time Range

```bash
# Last 24 hours
ngsiem-hunter -q queries/hunt.txt -s "-24h"

# Specific range
ngsiem-hunter -q queries/hunt.txt -s "-7d" -e "-1d"

# Custom format
ngsiem-hunter -q queries/hunt.txt -s "2024-01-01T00:00:00Z" -e "2024-01-07T23:59:59Z"
```

### Custom Configuration

```bash
ngsiem-hunter -q queries/hunt.txt -c config/production.yaml
```

## CLI Reference

```
Usage: ngsiem-hunter [OPTIONS]

Options:
  -c, --config PATH    Configuration file path [default: ./config/settings.json]
  -q, --query PATH     Query file path (required)
  -m, --mode TEXT      Execution mode: batch or iterative [default: batch]
  --cids PATH          CID filter file (optional, runs all CIDs if not specified)
  -s, --start TEXT     Query start time [default: from config, typically -7d]
  -e, --end TEXT       Query end time [default: now]
  -v, --verbose        Enable verbose output
  --help               Show this message and exit
```

## Output

### CSV Files

- **Batch mode**: Single CSV at `output/hunt_YYYYMMDD_HHMMSS.csv`
- **Iterative mode**: Per-CID CSVs at `output/hunt_YYYYMMDD_HHMMSS_<cid>.csv`

CSV columns include:
- All event fields from query results
- `_cid` and `_cid_name` columns (in batch mode) for easy filtering

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
| `onepassword` | `client_id_ref` | (required) | 1Password reference for API client ID |
| `onepassword` | `client_secret_ref` | (required) | 1Password reference for API client secret |
| `crowdstrike` | `base_url` | `https://api.laggar.gcw.crowdstrike.com` | CrowdStrike API base URL (US-GOV-1) |
| `crowdstrike` | `repository` | `search-all` | NG-SIEM repository name |
| `query_defaults` | `time_range` | `-7d` | Default query time range |
| `query_defaults` | `poll_interval_seconds` | `60` | Polling interval for query status |
| `query_defaults` | `timeout_seconds` | `3600` | Maximum query wait time |
| `concurrency` | `max_concurrent_queries` | `50` | Max parallel queries (iterative mode) |
| `concurrency` | `retry_attempts` | `3` | Retry count for failed queries |
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
pytest --cov=ngsiem_hunter --cov-report=html

# Run specific test file
pytest tests/test_client.py -v
```

### Project Structure

```
ngsiem-hunter/
├── src/ngsiem_hunter/
│   ├── __init__.py       # Package version
│   ├── models.py         # Data classes
│   ├── secrets.py        # 1Password integration
│   ├── config.py         # Configuration loading
│   ├── client.py         # CrowdStrike API wrapper
│   ├── query_executor.py # Async query execution
│   ├── output.py         # CSV and summary generation
│   ├── runner.py         # Main orchestration
│   └── cli.py            # Click CLI
├── tests/                # Test suite (111 tests)
├── config/               # Configuration files
├── queries/              # Query files
├── data/                 # CID registry
└── output/               # Generated CSVs (gitignored)
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

[Your License Here]

## Contributing

[Contribution Guidelines]