# alerts_client.py

from falconpy import Alerts
from typing import Any
from config import CROWDSTRIKE


class AlertsClient:
    def __init__(self):
        self.client = Alerts(
            client_id=CROWDSTRIKE.client_id,
            client_secret=CROWDSTRIKE.client_secret,
            base_url=CROWDSTRIKE.base_url,
        )

    def fetch_alerts_helper(self, fql_filter: str) -> list:
        alerts = []

        offset = 0
        limit = 500
        sorter = "updated_timestamp.desc"

        while True:
            response: Any = self.client.query_alerts_v2(
                filter = fql_filter,
                limit = limit,
                offset = offset,
                sort = sorter
            )
        
            validate_api_response(response)
            
            alert_ids = response.get('body', {}).get('resources', [])

            if not alert_ids:
                break

            details: Any = self.client.get_alerts_v2(composite_ids=alert_ids)

            validate_api_response(details)

            alerts.extend(details.get('body', {}).get('resources', []))

            offset += limit
            total_records = response.get('body', {}).get('meta', {}).get('pagination', {}).get('total', 0)

            if offset > total_records:
                break

        return alerts

    def fetch_alerts_from_last_day(self, hours: int = 24) -> list[dict]:
        """Fetch all alerts closed in the last N hours."""
        
        fql_filter = f"status:'closed'+updated_timestamp:>'now-{hours}h'"

        return self.fetch_alerts_helper(fql_filter)
    
    def fetch_historical_alerts_by_pattern_id(self, pattern_ids: list, days: int = 90) -> list[dict] | None:
        """Fetch historical closed alerts for given pattern IDs."""
        
        if not pattern_ids:
            return None

        alerts = []

        fql_filter = (
            f"status:'closed'"
            f"+pattern_id:[{','.join(f"'{p}'" for p in pattern_ids)}]"
            f"+updated_timestamp:>'now-{days}d'"
        )

        after = None
        limit = 1000
        sorter = "updated_timestamp.desc"

        while True:
            details: Any = self.client.get_alerts_combined(
                after = after,
                filter = fql_filter,
                limit = limit,
                sort = sorter
            )

            after = details.get('body', {}).get('meta', {}).get('pagination', {}).get('after', None)

            alerts.extend(details.get('body', {}).get('resources', []))
        
            if after is None:
                break
            
        return alerts
    
    

def validate_api_response(response: dict) -> None:
    if not response.get('status_code') == 200:
        raise Exception(f"API error: {response.get('body', {})}")
