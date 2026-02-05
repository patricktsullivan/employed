"""
CrowdStrike API client wrapper.

Provides a high-level async interface to the CrowdStrike NG-SIEM API
using the FalconPy SDK for authentication and aiohttp for async requests.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import aiohttp
from falconpy import OAuth2

from arbitrary_queries.secrets import Credentials
from arbitrary_queries.config import CrowdStrikeConfig


logger = logging.getLogger(__name__)

# Refresh token 60 seconds before actual expiry to prevent mid-request expiration
TOKEN_REFRESH_BUFFER_SECONDS = 60


class CrowdStrikeError(Exception):
    """Base exception for CrowdStrike API errors."""
    pass


class AuthenticationError(CrowdStrikeError):
    """Raised when authentication fails."""
    pass


class QuerySubmissionError(CrowdStrikeError):
    """Raised when query submission fails."""
    pass


class QueryStatusError(CrowdStrikeError):
    """Raised when getting query status fails."""
    pass


class CrowdStrikeClient:
    """
    CrowdStrike NG-SIEM async API client.
    
    Uses FalconPy for OAuth2 authentication and aiohttp for async HTTP requests.
    Provides methods for submitting queries, polling status, and retrieving results.
    
    Attributes:
        base_url: CrowdStrike API base URL.
        repository: NG-SIEM repository name.
    
    Example:
        async with CrowdStrikeClient(credentials, config) as client:
            job_id = await client.submit_query(query, start_time="-7d")
            status = await client.get_query_status(job_id)
    """
    
    def __init__(
        self,
        credentials: Credentials,
        config: CrowdStrikeConfig,
    ):
        """
        Initialize CrowdStrike client.
        
        Args:
            credentials: OAuth2 credentials.
            config: CrowdStrike API configuration.
        
        Raises:
            AuthenticationError: If authentication fails.
        """
        self.base_url = config.base_url
        self.repository = config.repository
        self._credentials = credentials
        
        # Initialize FalconPy OAuth2 client
        self._oauth = OAuth2(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            base_url=config.base_url,
        )
        
        # Token state
        self._access_token: str | None = None
        self._token_expires_at: datetime | None = None
        
        # aiohttp session (created on first request or via context manager)
        self._session: aiohttp.ClientSession | None = None
        self._owns_session: bool = False
        
        # Get initial token (sync, runs once at init)
        self._authenticate()
    
    async def __aenter__(self) -> "CrowdStrikeClient":
        """Async context manager entry."""
        self._session = aiohttp.ClientSession()
        self._owns_session = True
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._session and self._owns_session:
            await self._session.close()
            self._session = None
    
    def _authenticate(self) -> None:
        """
        Authenticate and obtain access token.
        
        Raises:
            AuthenticationError: If authentication fails.
        """
        response = self._oauth.token()
        
        if response["status_code"] not in (200, 201):
            errors = response.get("body", {}).get("errors", [])
            error_msg = errors[0].get("message", "Unknown error") if errors else "Unknown error"
            raise AuthenticationError(f"Authentication failed: {error_msg}")
        
        body = response["body"]
        self._access_token = body["access_token"]
        expires_in = body.get("expires_in", 1800)
        self._token_expires_at = (
            datetime.now(timezone.utc) 
            + timedelta(seconds=expires_in - TOKEN_REFRESH_BUFFER_SECONDS)
        )
        logger.debug("Authentication successful, token expires at %s", self._token_expires_at)
    
    def _refresh_token(self) -> None:
        """Refresh the access token if expired or about to expire."""
        self._authenticate()
    
    async def _ensure_token_valid(self) -> None:
        """Ensure the access token is valid, refreshing if necessary."""
        if self._token_expires_at is None or datetime.now(timezone.utc) >= self._token_expires_at:
            # Run sync FalconPy auth in thread pool to avoid blocking
            await asyncio.to_thread(self._refresh_token)
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the aiohttp session."""
        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._owns_session = True
        return self._session
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Make an async HTTP request to the CrowdStrike API.
        
        Args:
            method: HTTP method (GET, POST, DELETE).
            endpoint: API endpoint path.
            json: JSON body for POST requests.
            params: Query parameters.
        
        Returns:
            Response JSON as dictionary.
        
        Raises:
            CrowdStrikeError: If the request fails.
        """
        await self._ensure_token_valid()
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }
        
        session = await self._get_session()
        
        try:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                json=json,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                response.raise_for_status()
                if response.content_length == 0:
                    return {}
                return await response.json()
        except aiohttp.ClientError as e:
            raise CrowdStrikeError(f"API request failed: {e}")
    
    def _build_cid_filter(self, cids: list[str]) -> str:
        """
        Build CID filter string for query.
        
        Args:
            cids: List of CIDs to filter on.
        
        Returns:
            CID filter string to prepend to query.
        """
        if not cids:
            return ""
        
        cid_list = ", ".join(f'"{cid}"' for cid in cids)
        return f'cid =~ in(values=[{cid_list}])'
    
    async def submit_query(
        self,
        query: str,
        start_time: str,
        end_time: str = "now",
        cids: list[str] | None = None,
    ) -> str:
        """
        Submit a query to NG-SIEM.
        
        Args:
            query: The query string.
            start_time: Start time (e.g., "-7d", "2024-01-01T00:00:00Z").
            end_time: End time (default "now").
            cids: Optional list of CIDs to filter on.
        
        Returns:
            The job ID for polling status.
        
        Raises:
            QuerySubmissionError: If query submission fails.
        """
        full_query = query
        if cids:
            cid_filter = self._build_cid_filter(cids)
            full_query = f"{cid_filter} | {query}"
        
        payload = {
            "queryString": full_query,
            "start": start_time,
            "end": end_time,
            "isLive": False,
        }
        
        endpoint = f"/humio/api/v1/repositories/{self.repository}/queryjobs"
        
        try:
            response = await self._make_request(
                method="POST",
                endpoint=endpoint,
                json=payload,
            )
            return response["id"]
        except (CrowdStrikeError, KeyError) as e:
            raise QuerySubmissionError(f"Failed to submit query: {e}")
    
    async def _get_job(self, job_id: str) -> dict[str, Any]:
        """
        Get job state from the API.
        
        Args:
            job_id: The job ID to retrieve.
        
        Returns:
            Job state dictionary with status, events, and metadata.
        
        Raises:
            QueryStatusError: If retrieval fails.
        """
        endpoint = f"/humio/api/v1/repositories/{self.repository}/queryjobs/{job_id}"
        
        try:
            return await self._make_request(method="GET", endpoint=endpoint)
        except CrowdStrikeError as e:
            raise QueryStatusError(f"Failed to get job {job_id}: {e}")
    
    async def get_query_status(self, job_id: str) -> dict[str, Any]:
        """
        Get the status of a query job.
        
        Args:
            job_id: The job ID returned from submit_query.
        
        Returns:
            Status dictionary with 'done' flag and metadata.
        
        Raises:
            QueryStatusError: If status retrieval fails.
        """
        return await self._get_job(job_id)
    
    async def get_query_results(self, job_id: str) -> dict[str, Any]:
        """
        Get the results of a completed query.
        
        Args:
            job_id: The job ID returned from submit_query.
        
        Returns:
            Results dictionary with 'events' list and metadata.
        
        Raises:
            QueryStatusError: If result retrieval fails.
        """
        return await self._get_job(job_id)
    
    async def cancel_query(self, job_id: str) -> None:
        """
        Cancel a running query job.
        
        Args:
            job_id: The job ID to cancel.
        """
        endpoint = f"/humio/api/v1/repositories/{self.repository}/queryjobs/{job_id}"
        
        try:
            await self._make_request(method="DELETE", endpoint=endpoint)
        except CrowdStrikeError as e:
            # Log but don't raise - job may already be complete or cancelled
            logger.debug("Cancel request for job %s failed (may already be complete): %s", job_id, e)
    
    async def close(self) -> None:
        """Close the client session. Call this if not using context manager."""
        if self._session and self._owns_session:
            await self._session.close()
            self._session = None
