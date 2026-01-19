# Resolution Drift QA Framework

A Python application that compares recent CrowdStrike alert resolutions against historical consensus to identify inconsistent analyst decisions.

## Table of Contents

1. [What This Project Does](#what-this-project-does)
2. [The Problem It Solves](#the-problem-it-solves)
3. [How It Works](#how-it-works)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Running the Application](#running-the-application)
8. [Understanding the Output](#understanding-the-output)
9. [Project Structure](#project-structure)
10. [Testing](#testing)
11. [Tuning and Maintenance](#tuning-and-maintenance)
12. [Glossary](#glossary)

## What This Project Does

This application fetches closed alerts from the CrowdStrike Falcon API, groups them by behavioral pattern, and compares each alert's resolution against historical data. When an analyst resolves an alert differently than similar alerts have been resolved in the past, the application flags this as a "contradiction" for review.

The goal is to ensure consistency across the SOC team. If one analyst marks a certain type of alert as a True Positive, but another analyst marks an identical pattern as a False Positive, that disagreement could indicate either a training gap or a mistake that needs correction.

## The Problem It Solves

Security Operations Centers face a consistency challenge. When different analysts resolve identical threat patterns differently, two problems emerge:

1. Security Exposure: If a genuine threat gets dismissed as a False Positive, it escapes remediation. An attacker technique that should be blocked might slip through.

2. Operational Waste: If benign activity repeatedly gets marked as a True Positive, analysts waste time investigating the same harmless patterns over and over.

This application creates a feedback loop. By comparing today's decisions against the historical record, it surfaces contradictions so the SOC lead can review them and either correct mistakes or update the consensus.

## How It Works

The application follows a seven-step pipeline:

### Step 1: Fetch Recent Alerts

The application queries the CrowdStrike Alerts API for all alerts that were closed in the last 24 hours (this timeframe is configurable). These are the alerts that will be checked for consistency.

### Step 2: Generate Behavioral Templates

For each alert, the application creates a "template" that represents the alert's behavior. The template combines:

- The `pattern_id` (the CrowdStrike detection rule that triggered)
- The sanitized command line (with variable data replaced by tokens)
- The filename of the process that triggered the detection
- The parent process filename

Sanitization replaces things like IP addresses, GUIDs, timestamps, and Base64-encoded data with placeholder tokens. This allows the application to group alerts that are behaviorally identical even if they have different specific values.

For example, these two command lines:

```
powershell.exe -enc SGVsbG8gV29ybGQ= -ExecutionPolicy Bypass
powershell.exe -enc V29ybGQgSGVsbG8= -ExecutionPolicy Bypass
```

Would both sanitize to:

```
powershell.exe -enc <DATA> -ExecutionPolicy Bypass
```

This means they would be grouped together for consensus calculation.

### Step 3: Identify Unique Patterns

The application collects all the unique `pattern_id` values from the daily batch. These IDs tell CrowdStrike what type of detection rule triggered. The application needs these to fetch the relevant historical data.

### Step 4: Fetch Historical Data

Using the pattern IDs from Step 3, the application fetches all closed alerts with those same pattern IDs from the last 90 days (configurable). This historical data forms the baseline for consensus calculation.

### Step 5: Build Consensus Baseline

The application processes the historical alerts the same way it processed the daily alerts: generating templates and hashing them. For each unique template hash, it calculates the consensus resolution based on how analysts resolved similar alerts in the past.

The consensus calculation considers:

- What resolution occurred most often (True Positive, False Positive, or Ignored)
- What percentage of alerts received that resolution
- How confident we can be in that percentage given the sample size

The application uses Wilson score confidence intervals to account for sample size. A template with 9 out of 10 alerts marked True Positive is not as reliable as one with 900 out of 1000. The confidence interval math prevents the application from declaring "strong consensus" when the sample size is too small to be reliable.

### Step 6: Detect Contradictions

For each alert in the daily batch, the application looks up the historical consensus for that template hash. If the analyst's resolution differs from the historical consensus, that is a contradiction.

Contradictions are assigned severity levels:

- **CRITICAL**: The analyst marked an alert as False Positive, but historical consensus is True Positive (potential missed threat)
- **HIGH**: The analyst marked an alert as True Positive, but historical consensus is False Positive (potential overreaction)
- **MEDIUM**: The analyst marked an alert as Ignored, but historical consensus is True Positive (inconsistent priority)
- **LOW**: Contradictions against weak consensus or less severe combinations
- **INFO**: Novel patterns with no historical data to compare against

### Step 7: Generate Reports

The application generates two report files in the `reports/` directory:

1. An HTML report designed for human review by the SOC lead
2. A JSON report for machine processing, archival, and downstream automation

Both files include the date in their filename, such as `2025-01-08_qa_findings.html` and `2025-01-08_qa_findings.json`. High-priority findings (CRITICAL and HIGH) are also printed to the console so they can be addressed immediately.

## Prerequisites

Before you can run this application, you need:

### 1. Python 3.9 or Later

Check your Python version:

```bash
python3 --version
```

If you need to install Python, visit https://www.python.org/downloads/

### 2. CrowdStrike API Credentials

You need a CrowdStrike API client with the `alerts:read` scope. No write permissions are required. Contact your CrowdStrike administrator to create these credentials.

You will need:

- Client ID
- Client Secret
- Base URL for your CrowdStrike cloud region

The base URL depends on your region:

| Region   | Base URL                                  |
|----------|-------------------------------------------|
| US-1     | https://api.crowdstrike.com               |
| US-2     | https://api.us-2.crowdstrike.com          |
| EU-1     | https://api.eu-1.crowdstrike.com          |
| US-GOV-1 | https://api.laggar.gcw.crowdstrike.com    |

### 3. 1Password CLI (for credential management)

This application retrieves CrowdStrike credentials from 1Password at runtime using the 1Password CLI. This keeps sensitive credentials out of source code and environment variables.

Install the 1Password CLI from: https://1password.com/downloads/command-line/

After installation, sign in:

```bash
op signin
```

You must have the credentials stored in 1Password before running the application.

### 4. Network Access

The machine running this application must be able to reach the CrowdStrike API endpoint for your region.

## Installation

### 1. Clone or Copy the Project

Get the project files onto your machine. If using git:

```bash
git clone <repository-url>
cd qa-framework
```

### 2. Create a Virtual Environment (Recommended)

A virtual environment keeps this project's dependencies separate from other Python projects on your machine:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:

- `falconpy`: The official CrowdStrike Python SDK for API access
- `pandas`: For data processing and DataFrame operations
- `scipy`: For statistical calculations (confidence intervals)

## Configuration

All configuration lives in `config.py`. You need to update two sections:

### 1. CrowdStrike API Credentials

Update the 1Password references to match your vault structure:

```python
CROWDSTRIKE = CrowdStrikeConfig(
    client_id=op_read("op://YourVault/CrowdStrike/client_id"),
    client_secret=op_read("op://YourVault/CrowdStrike/client_secret"),
    base_url="https://api.laggar.gcw.crowdstrike.com"  # Change for your region
)
```

The format for 1Password references is:

```
op://<vault-name>/<item-name>/[section-name/]<field-name>
```

### 2. QA Framework Settings

Adjust these values based on your environment:

```python
QA = QASettings(
    lookback_days=90,              # How far back to look for historical data
    min_sample_size=20,            # Minimum alerts before consensus is reliable
    strong_consensus_threshold=0.90,  # Percentage for "strong" consensus
    batch_hours=24,                # How many hours of new alerts to process
)
```

Explanation of each setting:

**lookback_days**: The historical window for consensus calculation. A longer window gives more data but may include outdated decisions. 90 days is a reasonable starting point. If your detection rules or environment change frequently, consider reducing this.

**min_sample_size**: The minimum number of alerts required before the application considers the consensus reliable. With fewer than this many alerts, the application marks the data as "insufficient" rather than flagging contradictions. Set this higher if you want to be more conservative about surfacing findings.

**strong_consensus_threshold**: The percentage of alerts that must have the same resolution for the consensus to be considered "strong." At 0.90, if 90% or more of historical alerts have the same resolution, it is a strong consensus. Contradictions against strong consensus are given higher severity.

**batch_hours**: How many hours of recent alerts to process in each run. If you run the application once per day, set this to 24. If you run it twice per day, set it to 12.

### Logging Configuration

Logs are written to the `logs/` directory. The log level is set to INFO by default. If you need more detail for debugging, change `LOG_LEVEL` in `config.py`:

```python
LOG_LEVEL = logging.DEBUG  # For verbose output
```

## Running the Application

### Manual Execution

With your virtual environment activated:

```bash
python main.py
```

The application will:

1. Authenticate to the CrowdStrike API
2. Fetch recent closed alerts
3. Fetch historical data for comparison
4. Analyze for contradictions
5. Generate a report

Progress is logged to the console and to the log file.

### Scheduled Execution

For production use, schedule the application to run automatically. For example, using cron on Linux:

```bash
# Edit crontab
crontab -e

# Add this line to run daily at 6 AM
0 6 * * * cd /path/to/qa-framework && /path/to/venv/bin/python main.py
```

On Windows, use Task Scheduler to run `python main.py` at your desired interval.

### Exit Codes

The application returns these exit codes:

- **0**: Success (including when there are no alerts to process)
- **1**: Error (check logs for details)
- **130**: Interrupted by user (Ctrl+C)

## Understanding the Output

### Console Output

When the application finds high-priority contradictions, it prints a summary:

```
============================================================
ATTENTION: 3 high-priority findings require review
============================================================

  [CRITICAL] Alert: abc123
    Resolution: false_positive vs historical: true_positive
    Analyst: jsmith
    Link: https://falcon.crowdstrike.com/...

  [HIGH] Alert: def456
    Resolution: true_positive vs historical: false_positive
    Analyst: mjones
    Link: https://falcon.crowdstrike.com/...
```

### HTML Report

The HTML report is saved to `reports/YYYY-MM-DD_qa_findings.html`. This is the primary report for human review. Open it in any web browser.

The HTML report is organized into three sections:

**Executive Summary**

At the top of the report, you will find:

- Total alerts processed
- Number of contradictions found
- Number of alerts that matched consensus
- Number of novel patterns (no historical data)
- A visual breakdown of findings by severity level
- An analyst leaderboard showing which analysts have the most contradictions

The analyst leaderboard helps identify if a particular analyst needs additional training or if there is a systematic issue with how certain alert types are being handled.

**Finding Cards**

The main body of the report contains one card for each finding, sorted by severity (CRITICAL first, then HIGH, MEDIUM, LOW, and INFO).

Each finding card displays:

- Detection name and hostname with a color-coded severity badge
- MITRE ATT&CK context showing the tactic and technique
- CrowdStrike's own severity rating and confidence score
- The contradiction details: what the analyst marked versus what the historical consensus says, including the consensus strength, the historical ratio, and the sample size
- A process chain visualization showing the execution path (grandparent process to parent process to the process that triggered the detection)
- The command line in a dark code block for easy reading
- The analyst who resolved the alert and how long it took them
- A collapsible "Related Patterns" section showing similar templates with their historical consensus, similarity scores, and the tokens that differentiate them
- A direct link to the alert in the Falcon console

The related patterns section is particularly useful for novel patterns or edge cases. It shows how similar alerts were resolved historically, which can help the SOC lead decide whether the current resolution is correct or needs to be changed.

**Internal Identifiers**

The HTML report intentionally hides internal identifiers like `alert_id`, `composite_id`, and `template_hash` because these are noise for human readers. If you need these values, use the JSON report.

### JSON Report

The JSON report is saved to `reports/YYYY-MM-DD_qa_findings.json`. This report contains all fields, including the internal identifiers that are hidden in the HTML report. Use this report for:

- Archival purposes
- Automated processing or alerting
- Integration with other tools or SIEMs
- Debugging or detailed analysis

The JSON structure looks like this:

```json
{
  "generated_at": "2025-01-08T06:00:00.000000",
  "summary": {
    "total_processed": 847,
    "matches_consensus": 798,
    "contradictions": 44,
    "novel_patterns": 5,
    "insufficient_data": 0,
    "by_severity": {
      "CRITICAL": 12,
      "HIGH": 18,
      "MEDIUM": 9,
      "LOW": 5,
      "INFO": 5
    }
  },
  "findings": [
    {
      "alert_id": "ldt:abc123:456",
      "composite_id": "abc123:ind:456",
      "template_hash": "a1b2c3d4...",
      "display_name": "Suspicious PowerShell Download Cradle",
      "hostname": "WKSTN-FINANCE-042",
      "pattern_id": 50007,
      "tactic": "Execution",
      "technique": "PowerShell",
      "technique_id": "T1059.001",
      "severity": "CRITICAL",
      "new_resolution": "false_positive",
      "historical_resolution": "true_positive",
      "consensus_strength": "strong",
      "historical_ratio": 0.94,
      "sample_size": 127,
      "analyst": "jsmith@example.com",
      "falcon_link": "https://falcon.crowdstrike.com/...",
      "cmdline": "powershell.exe -NoP -NonI -W Hidden ...",
      "filename": "powershell.exe",
      "parent_filename": "cmd.exe",
      "grandparent_filename": "outlook.exe",
      "related_patterns": [
        {
          "template_hash": "x9y8z7...",
          "similarity": 0.87,
          "historical_consensus": "true_positive",
          "sample_size": 89,
          "strength": "strong",
          "differentiating_tokens": ["bypass", "hidden"],
          "shared_tokens": ["powershell", "enc", "nop"]
        }
      ]
    }
  ]
}
```

The `summary` object contains the same statistics shown in the HTML executive summary. The `findings` array contains all the finding objects with every available field.

### Log Files

Logs are written to `logs/YYYY-MM-DD_qa_framework.log`. These contain:

- Timing information
- Alert counts at each stage
- Error messages and stack traces
- Summary statistics

## Project Structure

```
qa-framework/
├── main.py              # Entry point and pipeline orchestration
├── config.py            # Configuration and credential management
├── alerts_client.py     # CrowdStrike API client
├── sanitizer.py         # Command line sanitization and template generation
├── consensus.py         # Consensus calculation and contradiction detection
├── similarity.py        # Fuzzy matching for related patterns
├── report_generator.py  # HTML and JSON report generation
├── requirements.txt     # Runtime dependencies
├── requirements-dev.txt # Development and testing dependencies
├── pytest.ini           # Test configuration
├── conftest.py          # Shared test fixtures
├── test_*.py            # Test files
├── logs/                # Log files (created at runtime)
└── reports/             # HTML and JSON reports (created at runtime)
```

### Module Descriptions

**main.py**: This is the entry point. It orchestrates the entire pipeline by calling the other modules in sequence. It handles initialization, error handling, and report generation.

**config.py**: Contains all configuration settings. It also handles reading credentials from 1Password at runtime. You should not need to modify any other file to configure the application.

**alerts_client.py**: Wraps the CrowdStrike FalconPy SDK. It provides two main methods: one to fetch recent closed alerts, and one to fetch historical alerts by pattern ID. It handles pagination automatically.

**sanitizer.py**: Contains the Sanitizer class that transforms command lines into behavioral templates. It replaces variable data (IPs, GUIDs, timestamps, etc.) with placeholder tokens so that behaviorally identical alerts can be grouped together. It also provides the `extract_qa_fields()` function that pulls the relevant fields from raw alert data.

**consensus.py**: Contains the ConsensusCalculator class. It calculates consensus from a list of historical resolutions and determines contradiction severity. It uses Wilson score confidence intervals to account for sample size uncertainty.

**similarity.py**: Contains the SimilarityAnalyzer class. This provides a secondary matching layer using Jaccard similarity on token sets. When an alert does not have an exact template match, this module can find similar templates that might inform the analyst's decision.

**report_generator.py**: Contains the `generate_reports()` function that produces both HTML and JSON output files. The HTML report is built with embedded CSS styling and JavaScript for collapsible sections. All user-provided content is escaped to prevent XSS vulnerabilities.

## Testing

The project includes a comprehensive test suite. To run tests:

### Install Development Dependencies

```bash
pip install -r requirements-dev.txt
```

### Run All Tests

```bash
pytest
```

### Run Tests with Coverage Report

```bash
pytest --cov=. --cov-report=term-missing
```

### Run a Specific Test File

```bash
pytest test_sanitizer.py
```

### Run a Specific Test

```bash
pytest test_sanitizer.py::test_sanitize_ip_address
```

The test files include:

- **test_sanitizer.py**: Tests for command line sanitization and template generation
- **test_consensus.py**: Tests for consensus calculation and contradiction detection
- **test_similarity.py**: Tests for fuzzy template matching
- **test_alerts_client.py**: Tests for CrowdStrike API interactions (mocked)
- **test_report_generator.py**: Tests for HTML and JSON report generation

## Tuning and Maintenance

### Adjusting Sanitization Rules

The sanitization rules in `sanitizer.py` determine which parts of command lines are replaced with tokens. If you find that alerts are being grouped incorrectly (either too broadly or too narrowly), you may need to adjust these rules.

To see what rules match a given command line:

```python
from sanitizer import debug_sanitization

debug_sanitization("powershell.exe -enc SGVsbG8= -ep bypass")
```

This prints each rule that matches and what it replaces.

### Adjusting Consensus Thresholds

If you are getting too many findings, consider:

- Increasing `min_sample_size` to require more historical data before flagging contradictions
- Increasing `strong_consensus_threshold` to require higher agreement for "strong" consensus

If you are getting too few findings, consider:

- Decreasing `min_sample_size` to flag contradictions earlier
- Decreasing `strong_consensus_threshold` to be more sensitive to disagreement

### Reviewing High-Volume Patterns

Some pattern IDs may generate many alerts. If a particular pattern is causing noise in your reports, work with your Security Engineering team to determine if:

1. The detection rule needs tuning in CrowdStrike
2. A baseline exception should be created
3. The historical consensus needs to be corrected

### Handling Novel Patterns

Alerts with no historical match are marked as INFO severity with reason "novel_pattern". These are not contradictions, but you may want to review them to establish initial consensus.

### Performance Considerations

The application fetches all closed alerts for the batch period and all historical alerts for matching pattern IDs. For environments with very high alert volumes, this could result in long execution times.

If performance is a concern:

- Reduce `lookback_days` to fetch less historical data
- Reduce `batch_hours` and run the application more frequently
- Consider filtering to specific pattern IDs if you only care about certain detection types

## Glossary

**pattern_id**: An integer that identifies which CrowdStrike detection rule triggered the alert. Alerts with the same pattern_id were triggered by the same rule.

**resolution**: The analyst's classification of the alert: `true_positive` (confirmed threat), `false_positive` (benign activity), or `ignored` (not investigated).

**status**: The workflow state of the alert: `new`, `in_progress`, `closed`, or `reopened`. This application only processes alerts with status `closed`.

**template**: A sanitized representation of an alert's behavior. Created by combining the pattern_id with the sanitized command line, filename, and parent filename.

**template_hash**: A SHA-256 hash of the template string. Used as a unique identifier for grouping behaviorally identical alerts.

**consensus**: The historical majority resolution for a given template hash. If 90% of historical alerts with the same template were marked True Positive, the consensus is True Positive.

**contradiction**: When a new alert's resolution differs from the historical consensus.

**Wilson score confidence interval**: A statistical method for calculating confidence intervals that works well with small sample sizes and proportions near 0 or 1. Used to determine how reliable the consensus calculation is given the amount of historical data.

**Jaccard similarity**: A measure of how similar two sets are, calculated as the size of their intersection divided by the size of their union. Used for fuzzy template matching.

**sanitization**: The process of replacing variable data in command lines with placeholder tokens. This allows behaviorally identical alerts to be grouped together even if they have different specific values.