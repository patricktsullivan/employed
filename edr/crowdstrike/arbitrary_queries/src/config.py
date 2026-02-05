import json
import os
from typing import Dict, Any

class ConfigLoader:
    def __init__(self, settings_path: str, customers_path: str):
        self.settings_path = settings_path
        self.customers_path = customers_path

    def load_settings(self) -> Dict[str, Any]:
        """Loads the main application settings."""
        if not os.path.exists(self.settings_path):
            raise FileNotFoundError(f"Settings file not found: {self.settings_path}")
            
        with open(self.settings_path, 'r') as f:
            return json.load(f)

    def load_customers(self) -> Dict[str, str]:
        """Loads the CID to Customer Name mapping."""
        if not os.path.exists(self.customers_path):
            raise FileNotFoundError(f"Customer file not found: {self.customers_path}")

        with open(self.customers_path, 'r') as f:
            return json.load(f)
