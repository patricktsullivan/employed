import time
import logging
from typing import List, Dict, Any, Optional
# Ensure falconpy is installed: pip install crowdstrike-falconpy
from falconpy import NGSIEM

class FalconSearchClient:
    def __init__(self, client_id: str, client_secret: str, base_url: str = "usgov1"):
        """
        Initializes the NG-SIEM client.
        """
        self.falcon = NGSIEM(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )
        self.repository = "search-all"

    def start_query(self, query_string: str, start_time: str = "7d") -> str:
        """
        Starts a search job on the 'search-all' repository.
        Returns the Job ID.
        """
        #  POST /humio/api/v1/repositories/{repository}/queryjobs
        response = self.falcon.start_search(
            repository      = self.repository,
            is_live         = False,
            start           = start_time,
            query_string    = query_string
        )
            

        if response["status_code"] != 200:
            error_msg = response.get("body", {}).get("detail", "Unknown Error")
            raise Exception(f"Failed to start search: {response['status_code']} - {error_msg}")

        return response["body"]["id"]

    def wait_for_results(self, job_id: str, poll_interval: float = 5.0) -> List[Dict[str, Any]]:
        """
        Polls the search job until completion to prevent timeout.
        CrowdStrike NG-SIEM jobs expire after 90s of inactivity.
        """
        is_done = False
        final_events = []

        while not is_done:
            #  GET /humio/api/v1/repositories/{repository}/queryjobs/{id}
            response = self.falcon.get_search_status(
                repository=self.repository,
                id=job_id
            )

            if response["status_code"] != 200:
                # If 404, the job likely timed out or was deleted
                raise Exception(f"Error polling job {job_id}: {response['status_code']}")

            data = response["body"]
            is_done = data.get("done", False)
            
            # If done, grab the final event list
            # Note: For massive result sets, we might need pagination logic here later.
            if is_done:
                final_events = data.get("events", [])
            else:
                # Wait before polling again to keep the job alive
                time.sleep(poll_interval)

        return final_events

    def close(self):
        """Cleanup if necessary (e.g. revoking tokens)."""
        # FalconPy handles token refresh automatically, but we can revoke if needed.
        pass