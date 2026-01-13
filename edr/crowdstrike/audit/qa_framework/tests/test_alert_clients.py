# test_alerts_client.py

"""
Tests for the AlertsClient class.

These tests use mocking to avoid actual API calls. They verify that:
1. API calls are constructed correctly
2. Pagination is handled properly
3. Errors are handled appropriately
4. Response data is parsed correctly

Note: These tests require falconpy to be installed. If falconpy is not
available, tests are skipped.
"""

import sys
import pytest
from unittest.mock import Mock, patch, MagicMock

# Check if falconpy is available
try:
    import falconpy
    FALCONPY_AVAILABLE = True
except ImportError:
    FALCONPY_AVAILABLE = False

# Skip all tests in this module if falconpy is not installed
pytestmark = pytest.mark.skipif(
    not FALCONPY_AVAILABLE,
    reason="falconpy not installed - alerts_client tests require the CrowdStrike SDK"
)


class TestValidateApiResponse:
    """Tests for the validate_api_response helper function."""

    def test_valid_response(self, mock_api_response_query):
        """Valid 200 response should not raise."""
        from alerts_client import validate_api_response
        
        # Should not raise
        validate_api_response(mock_api_response_query)

    def test_error_response(self, mock_api_error_response):
        """Non-200 response should raise Exception."""
        from alerts_client import validate_api_response
        
        with pytest.raises(Exception) as excinfo:
            validate_api_response(mock_api_error_response)
        
        assert "API error" in str(excinfo.value)

    def test_missing_status_code(self):
        """Missing status_code should raise."""
        from alerts_client import validate_api_response
        
        with pytest.raises(Exception):
            validate_api_response({'body': {}})


class TestAlertsClientInit:
    """Tests for AlertsClient initialization."""

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_init_creates_client(self, mock_alerts_class, mock_config):
        """Should create Alerts client with config credentials."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.crowdstrike.com'
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        
        mock_alerts_class.assert_called_once_with(
            client_id='test_id',
            client_secret='test_secret',
            base_url='https://api.crowdstrike.com'
        )


class TestFetchAlertsFromLastDay:
    """Tests for fetch_alerts_from_last_day method."""

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_default_hours(self, mock_alerts_class, mock_config):
        """Default should query last 24 hours."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        # Setup mock responses
        mock_client.query_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {'pagination': {'total': 0}}
            }
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        client.fetch_alerts_from_last_day()
        
        # Check that query was called with correct filter
        call_args = mock_client.query_alerts_v2.call_args
        filter_arg = call_args.kwargs.get('filter') or call_args[1].get('filter')
        assert 'now-24h' in filter_arg
        assert "status:'closed'" in filter_arg

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_custom_hours(self, mock_alerts_class, mock_config):
        """Should respect custom hours parameter."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        mock_client.query_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {'pagination': {'total': 0}}
            }
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        client.fetch_alerts_from_last_day(hours=48)
        
        call_args = mock_client.query_alerts_v2.call_args
        filter_arg = call_args.kwargs.get('filter') or call_args[1].get('filter')
        assert 'now-48h' in filter_arg


class TestFetchHistoricalAlertsByPatternId:
    """Tests for fetch_historical_alerts_by_pattern_id method."""

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_empty_pattern_ids(self, mock_alerts_class, mock_config):
        """Empty pattern_ids list should return None."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        
        result = client.fetch_historical_alerts_by_pattern_id([])
        
        assert result is None

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_none_pattern_ids(self, mock_alerts_class, mock_config):
        """None pattern_ids should return None."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        
        result = client.fetch_historical_alerts_by_pattern_id(None)
        
        assert result is None

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_builds_correct_fql_filter(self, mock_alerts_class, mock_config):
        """Should build FQL filter with pattern_id list."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        mock_client.query_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {'pagination': {'total': 0}}
            }
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        client.fetch_historical_alerts_by_pattern_id([50007, 50102], days=90)
        
        call_args = mock_client.query_alerts_v2.call_args
        filter_arg = call_args.kwargs.get('filter') or call_args[1].get('filter')
        
        assert "pattern_id:" in filter_arg
        assert "'50007'" in filter_arg
        assert "'50102'" in filter_arg
        assert "now-90d" in filter_arg


class TestFetchAlertsHelper:
    """Tests for the fetch_alerts_helper pagination logic."""

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_single_page_results(self, mock_alerts_class, mock_config):
        """Single page of results should be returned correctly."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        # Query returns 3 IDs
        mock_client.query_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': ['id1', 'id2', 'id3'],
                'meta': {'pagination': {'total': 3}}
            }
        }
        
        # Get details returns 3 alerts
        mock_client.get_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': [
                    {'id': 'id1', 'pattern_id': 50007},
                    {'id': 'id2', 'pattern_id': 50007},
                    {'id': 'id3', 'pattern_id': 50102},
                ]
            }
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        alerts = client.fetch_alerts_from_last_day()
        
        assert len(alerts) == 3
        assert alerts[0]['id'] == 'id1'

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_pagination_multiple_pages(self, mock_alerts_class, mock_config):
        """Should paginate through multiple pages of results."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        # First query returns 500 IDs, second returns empty (end of results)
        mock_client.query_alerts_v2.side_effect = [
            {
                'status_code': 200,
                'body': {
                    'resources': [f'id_{i}' for i in range(500)],
                    'meta': {'pagination': {'total': 500}}
                }
            },
            {
                'status_code': 200,
                'body': {
                    'resources': [],
                    'meta': {'pagination': {'total': 500}}
                }
            }
        ]
        
        mock_client.get_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': [{'id': f'id_{i}'} for i in range(500)]
            }
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        alerts = client.fetch_alerts_from_last_day()
        
        # Should have called query twice (pagination)
        assert mock_client.query_alerts_v2.call_count == 2

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_uses_composite_ids(self, mock_alerts_class, mock_config):
        """Should use composite_ids parameter for get_alerts_v2."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        mock_client.query_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': ['comp:id:1', 'comp:id:2'],
                'meta': {'pagination': {'total': 2}}
            }
        }
        
        mock_client.get_alerts_v2.return_value = {
            'status_code': 200,
            'body': {'resources': [{'id': '1'}, {'id': '2'}]}
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        client.fetch_alerts_from_last_day()
        
        # Should use composite_ids, not ids
        mock_client.get_alerts_v2.assert_called_with(
            composite_ids=['comp:id:1', 'comp:id:2']
        )

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_empty_results(self, mock_alerts_class, mock_config):
        """Empty results should return empty list."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        mock_client.query_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': [],
                'meta': {'pagination': {'total': 0}}
            }
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        alerts = client.fetch_alerts_from_last_day()
        
        assert alerts == []
        # get_alerts_v2 should not be called if no IDs returned
        mock_client.get_alerts_v2.assert_not_called()


class TestErrorHandling:
    """Tests for error handling in API calls."""

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_query_error_raises(self, mock_alerts_class, mock_config):
        """API error during query should raise exception."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        mock_client.query_alerts_v2.return_value = {
            'status_code': 401,
            'body': {'errors': [{'message': 'Unauthorized'}]}
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        
        with pytest.raises(Exception) as excinfo:
            client.fetch_alerts_from_last_day()
        
        assert "API error" in str(excinfo.value)

    @patch('alerts_client.CROWDSTRIKE')
    @patch('alerts_client.Alerts')
    def test_details_error_raises(self, mock_alerts_class, mock_config):
        """API error during get_alerts_v2 should raise exception."""
        mock_config.client_id = 'test_id'
        mock_config.client_secret = 'test_secret'
        mock_config.base_url = 'https://api.test.com'
        
        mock_client = MagicMock()
        mock_alerts_class.return_value = mock_client
        
        mock_client.query_alerts_v2.return_value = {
            'status_code': 200,
            'body': {
                'resources': ['id1'],
                'meta': {'pagination': {'total': 1}}
            }
        }
        
        mock_client.get_alerts_v2.return_value = {
            'status_code': 500,
            'body': {'errors': [{'message': 'Internal Server Error'}]}
        }
        
        from alerts_client import AlertsClient
        client = AlertsClient()
        
        with pytest.raises(Exception) as excinfo:
            client.fetch_alerts_from_last_day()
        
        assert "API error" in str(excinfo.value)