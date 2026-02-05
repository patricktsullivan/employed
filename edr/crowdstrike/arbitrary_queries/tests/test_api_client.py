import unittest
from unittest.mock import MagicMock, patch
from src.api_client import FalconSearchClient

class TestFalconSearchClient(unittest.TestCase):
    def setUp(self):
        # We mock the entire FalconPy LogScale class
        self.mock_service = MagicMock()
        self.client_id = "test_id"
        self.client_secret = "test_secret"
        
        # Initialize our client with the mock
        with patch('src.api_client.LogScale', return_value=self.mock_service):
            self.client = FalconSearchClient(self.client_id, self.client_secret)

    def test_start_search_success(self):
        """Test that we can successfully initiate a search job."""
        # Setup the mock to return a Job ID
        self.mock_service.start_search.return_value = {
            "status_code": 200,
            "body": {"id": "job-123", "query": "test query"}
        }

        job_id = self.client.start_query("event_simpleName=ProcessRollup2")
        
        self.assertEqual(job_id, "job-123")
        # Verify we targeted the correct repository
        self.mock_service.start_search.assert_called_with(
            repository="search-all",
            query={"queryString": "event_simpleName=ProcessRollup2", "start": "7d"}
        )

    def test_poll_results_success(self):
        """Test the polling loop handles a 'DONE' status correctly."""
        # Simulation: 1st call -> RUNNING, 2nd call -> DONE
        self.mock_service.get_search_status.side_effect = [
            {"status_code": 200, "body": {"done": False, "events": []}}, # Poll 1
            {"status_code": 200, "body": {"done": True, "events": [{"field": "value"}]}}  # Poll 2
        ]

        results = self.client.wait_for_results("job-123", poll_interval=0.1)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['field'], "value")
        # Ensure we polled exactly twice
        self.assertEqual(self.mock_service.get_search_status.call_count, 2)

    def test_search_error_handling(self):
        """Test that API errors raise exceptions."""
        self.mock_service.start_search.return_value = {
            "status_code": 400,
            "body": {"error": "Bad Query"}
        }
        
        with self.assertRaises(Exception):
            self.client.start_query("bad query")

if __name__ == '__main__':
    unittest.main()