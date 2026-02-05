#
import concurrent.futures
from typing import List, Dict, Any
from src.api_client import FalconSearchClient

class QueryExecutor:
    def __init__(self, client: FalconSearchClient, max_workers: int = 10):
        self.client = client
        self.max_workers = max_workers

    def _prepare_query_for_cid(self, cid: str, base_query: str) -> str:
        """
        Prepends the CID filter to the query.
        Example: cid="12345" | event_simpleName=ProcessRollup2
        """
        clean_query = base_query.strip()
        # LogScale uses pipes '|' to separate commands. 
        # We ensure a pipe exists between the CID filter and the query.
        if clean_query.startswith("|"):
            return f'cid="{cid}" {clean_query}'
        return f'cid="{cid}" | {clean_query}'

    def run_single_cid_search(self, cid: str, base_query: str) -> Dict[str, Any]:
        """
        Executes a search for a single CID and returns the results.
        Designed to be the target function for a thread.
        """
        full_query = self._prepare_query_for_cid(cid, base_query)
        result_payload = {
            "cid": cid,
            "status": "pending",
            "events": [],
            "error": None,
            "event_count": 0
        }

        try:
            job_id = self.client.start_query(full_query)
            events = self.client.wait_for_results(job_id)
            result_payload["status"] = "success"
            result_payload["events"] = events
            result_payload["event_count"] = len(events)
        except Exception as e:
            result_payload["status"] = "failed"
            result_payload["error"] = str(e)
            
        return result_payload

    def run_concurrent_searches(self, cids: List[str], base_query: str) -> List[Dict[str, Any]]:
        """
        Runs the base_query against all provided CIDs in parallel batches.
        """
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_cid = {
                executor.submit(self.run_single_cid_search, cid, base_query): cid 
                for cid in cids
            }
            
            for future in concurrent.futures.as_completed(future_to_cid):
                cid = future_to_cid[future]
                try:
                    data = future.result()
                    results.append(data)
                except Exception as exc:
                    results.append({
                        "cid": cid,
                        "status": "crashed",
                        "error": str(exc),
                        "events": [],
                        "event_count": 0
                    })
                    
        return results

    def run_aggregate_search(self, cids: List[str], base_query: str) -> Dict[str, Any]:
        """
        Runs a SINGLE query filtering for ALL CIDs provided.
        Query: cid =~ in(values=[cid1, cid2]) | ...
        """
        # Format: cid =~ in(values=["cid1", "cid2"])
        cid_list_str = ", ".join([f'"{c}"' for c in cids])
        full_query = f'cid =~ in(values=[{cid_list_str}]) | {base_query}'
        
        # We reuse run_single_cid_search logic but pass a dummy CID identifier.
        # We perform a small hack: we pass the complex filter as the "CID", 
        # so _prepare_query needs to handle it or we override it.
        # Cleaner approach: Directly call client here.
        
        result_payload = {
            "cid": "AGGREGATE_BATCH",
            "status": "pending",
            "events": [],
            "error": None,
            "event_count": 0
        }
        
        try:
            job_id = self.client.start_query(full_query)
            events = self.client.wait_for_results(job_id)
            result_payload["status"] = "success"
            result_payload["events"] = events
            result_payload["event_count"] = len(events)
        except Exception as e:
            result_payload["status"] = "failed"
            result_payload["error"] = str(e)

        return result_payload