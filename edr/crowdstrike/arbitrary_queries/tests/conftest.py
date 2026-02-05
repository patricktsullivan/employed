"""
Shared pytest fixtures for arbitrary-queries tests.
"""

import pytest
from datetime import datetime, timezone


@pytest.fixture
def sample_cid():
    """Sample CID for testing."""
    return "abc123def456"


@pytest.fixture
def sample_cid_name():
    """Sample customer name for testing."""
    return "Acme Corporation"


@pytest.fixture
def sample_query():
    """Sample NG-SIEM query for testing."""
    return '#event_simpleName="ProcessRollup2" | head(10)'


@pytest.fixture
def sample_events():
    """Sample event data returned from a query."""
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
    """Sample CID registry data."""
    return {
        "abc123def456": "Acme Corporation",
        "xyz789ghi012": "Globex Industries",
        "mno345pqr678": "Initech LLC",
    }


@pytest.fixture
def mock_utc_now():
    """Fixed UTC timestamp for testing."""
    return datetime(2026, 2, 4, 12, 0, 0, tzinfo=timezone.utc)
