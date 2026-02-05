import unittest
import json
import os
from src.config import ConfigLoader

class TestConfigLoader(unittest.TestCase):
    def setUp(self):
        # Create dummy config files for testing
        self.test_config_data = {
            "max_concurrent_searches": 5,
            "default_repository": "test-repo"
        }
        self.test_customer_data = {
            "test_cid": "Test Customer"
        }
        
        with open("test_settings.json", "w") as f:
            json.dump(self.test_config_data, f)
            
        with open("test_customers.json", "w") as f:
            json.dump(self.test_customer_data, f)

    def tearDown(self):
        # Clean up files after test
        if os.path.exists("test_settings.json"):
            os.remove("test_settings.json")
        if os.path.exists("test_customers.json"):
            os.remove("test_customers.json")

    def test_load_config(self):
        """Ensure settings are loaded correctly."""
        loader = ConfigLoader(settings_path="test_settings.json", customers_path="test_customers.json")
        config = loader.load_settings()
        
        self.assertEqual(config["max_concurrent_searches"], 5)
        self.assertEqual(config["default_repository"], "test-repo")

    def test_load_customers(self):
        """Ensure customer map is loaded correctly."""
        loader = ConfigLoader(settings_path="test_settings.json", customers_path="test_customers.json")
        customers = loader.load_customers()
        
        self.assertIn("test_cid", customers)
        self.assertEqual(customers["test_cid"], "Test Customer")

if __name__ == '__main__':
    unittest.main()