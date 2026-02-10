"""
Shared pytest fixtures for Arbitrary Queries tests.

These fixtures provide realistic sample data used across multiple test modules.
They follow the fixture-composition pattern: simple fixtures (sample_cid,
sample_events) are combined into more complex ones (sample_result) in
individual test files.
"""

import pytest
from datetime import datetime, timezone


@pytest.fixture
def sample_cid():
    """Sample CID for testing.
    
    Uses a shortened format for readability. Real CrowdStrike CIDs are
    32-character lowercase hex strings (e.g., 'abc123def456abc123def456abc12345').
    """
    return "abc123def456"


@pytest.fixture
def sample_cid_name():
    """Sample customer name for testing.
    
    Represents a human-readable customer name as stored in the CID registry.
    """
    return "Acme Corporation"


@pytest.fixture
def sample_query():
    """Sample NG-SIEM query for testing.
    
    Uses real CrowdStrike LogScale query syntax. ProcessRollup2 is one of
    the most common event types in CrowdStrike telemetry — it records
    process execution details.
    """
    return '#event_simpleName="ProcessRollup2" | head(10)'


@pytest.fixture
def sample_events():
    """Sample event data returned from a query.
    
    Mimics the structure of real NG-SIEM query results. Each event dict
    contains fields like @timestamp, event_simpleName, aid (agent ID),
    and detection-specific fields like CommandLine.
    
    Returns a list (not tuple) so test files can slice it and convert
    as needed for their fixtures.
    """
    return [
        {
            "@timestamp": "2026-02-04T10:00:00.000Z",
            "event_simpleName": "ProcessRollup2",
            "aid": "host001",
            "CommandLine": "cmd.exe /c whoami",
        },
        {
            "@timestamp": "2026-02-04T10:01:00.000Z",
            "event_simpleName": "ProcessRollup2",
            "aid": "host002",
            "CommandLine": "powershell.exe -enc base64data",
        },
        {
            "@timestamp": "2026-02-04T10:02:00.000Z",
            "event_simpleName": "ProcessRollup2",
            "aid": "host003",
            "CommandLine": "notepad.exe",
        },
    ]


@pytest.fixture
def sample_cid_registry():
    """Sample CID registry data.
    
    Maps CID hex strings to human-readable customer names, matching
    the format of data/cid_registry.json. Used by runner.py to resolve
    CIDs to names for output and summaries.
    """
    return {
        "abc123def456": "Acme Corporation",
        "xyz789ghi012": "Globex Industries",
        "mno345pqr678": "Initech LLC",
    }


@pytest.fixture
def mock_utc_now():
    """Fixed UTC timestamp for testing.
    
    Provides a deterministic datetime for tests that need to assert on
    time-dependent behavior (e.g., token expiry, execution timing).
    """
    return datetime(2026, 2, 4, 12, 0, 0, tzinfo=timezone.utc)
