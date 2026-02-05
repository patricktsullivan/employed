# tests/test_executor.py
import unittest
from unittest.mock import MagicMock
from src.executor import QueryExecutor

class TestQueryExecutor(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock()
        # Initialize executor with 2 workers for testing
        self.executor = QueryExecutor(self.mock_client, max_workers=2)

    def test_query_prep(self):
        """Ensure CID filter is prepended correctly."""
        q = self.executor._prepare_query_for_cid("123", "stats count")
        self.assertEqual(q, 'cid="123" | stats count')

    def test_run_concurrent_searches(self):
        """Test that multiple CIDs generate multiple results."""
        # Setup mock client to return dummy data
        self.mock_client.start_query.return_value = "job-X"
        self.mock_client.wait_for_results.return_value = [{"event": 1}]

        cids = ["cid1", "cid2", "cid3"]
        results = self.executor.run_concurrent_searches(cids, "test query")

        self.assertEqual(len(results), 3)
        # Verify start_query was called 3 times (once per CID)
        self.assertEqual(self.mock_client.start_query.call_count, 3)
        
        # Check structure of result
        success_result = [r for r in results if r['cid'] == 'cid1'][0]
        self.assertEqual(success_result['status'], 'success')
        self.assertEqual(success_result['event_count'], 1)

    def test_run_aggregate_search(self):
        """Test the single-query multi-cid logic."""
        self.mock_client.start_query.return_value = "job-agg"
        self.mock_client.wait_for_results.return_value = []

        cids = ["cid1", "cid2"]
        self.executor.run_aggregate_search(cids, "test query")

        # Verify the query string format
        # Call args[0][0] is the first positional argument of the first call
        executed_query = self.mock_client.start_query.call_args[0][0]
        self.assertIn('cid =~ in(values=["cid1", "cid2"])', executed_query)

if __name__ == '__main__':
    unittest.main()