"""
CrowdStrike NG-SIEM API client wrapper.

Provides an async interface to the CrowdStrike NG-SIEM API using
FalconPy's NGSIEM service class. FalconPy handles authentication,
token refresh, and HTTP session management internally.

Async bridge: Since FalconPy is synchronous (built on ``requests``),
all API calls are dispatched via ``asyncio.to_thread()`` to avoid
blocking the event loop. This enables concurrent query execution
across multiple CIDs while leveraging FalconPy's battle-tested
HTTP and auth handling.

Thread safety note: FalconPy uses ``requests.Session`` internally,
which is not officially thread-safe. At typical concurrency levels
(≤50 concurrent queries), this works reliably in practice. If issues
arise at higher concurrency, consider per-thread NGSIEM instances
or a threading lock around API calls.
"""

import asyncio
import logging
from typing import Any

from falconpy import NGSIEM

from arbitrary_queries.secrets import Credentials
from arbitrary_queries.config import CrowdStrikeConfig


logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class CrowdStrikeError(Exception):
    """Base exception for CrowdStrike API errors."""

    pass


class AuthenticationError(CrowdStrikeError):
    """Raised when authentication or authorization fails (HTTP 401/403)."""

    pass


class QuerySubmissionError(CrowdStrikeError):
    """Raised when query submission fails."""

    pass


class QueryStatusError(CrowdStrikeError):
    """Raised when getting query status fails."""

    pass


# =============================================================================
# Client
# =============================================================================


class CrowdStrikeClient:
    """
    CrowdStrike NG-SIEM async API client.

    Wraps FalconPy's NGSIEM service class with an async interface.
    FalconPy handles OAuth2 authentication, automatic token refresh,
    and HTTP session management. All API calls run on the thread pool
    via ``asyncio.to_thread()`` to keep the event loop non-blocking.

    Attributes:
        base_url: CrowdStrike API base URL.
        repository: NG-SIEM repository name.

    Example:
        client = CrowdStrikeClient(credentials, config)
        try:
            job_id = await client.submit_query(query, start_time="-7d")
            status = await client.get_query_status(job_id)
        finally:
            await client.close()
    """

    def __init__(
        self,
        credentials: Credentials,
        config: CrowdStrikeConfig,
    ):
        """
        Initialize CrowdStrike client.

        Creates a FalconPy NGSIEM service class instance. Authentication
        is deferred until the first API call (FalconPy's default behavior).

        Args:
            credentials: OAuth2 credentials (client_id, client_secret).
            config: CrowdStrike API configuration (base_url, repository).
        """
        self.base_url = config.base_url
        self.repository = config.repository
        self._falcon = NGSIEM(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            base_url=config.base_url,
        )

    # -------------------------------------------------------------------------
    # Response Handling
    # -------------------------------------------------------------------------

    @staticmethod
    def _as_dict(response: dict[str, Any] | Any) -> dict[str, Any]:
        """
        Ensure a FalconPy response is a plain dict.

        FalconPy's return type is ``Union[dict, Result]``. We always use
        default (non-pythonic) mode which returns dicts, but Pylance can't
        know that statically. This method narrows the type.

        Note: We intentionally avoid ``pythonic=True`` / ``Result`` because
        the ``Result`` class normalizes response bodies into CrowdStrike's
        standard envelope (meta/resources/errors), which strips NGSIEM-
        specific fields like ``id``, ``done``, ``events``, and ``metaData``.

        Args:
            response: FalconPy response (always a dict in default mode).

        Returns:
            The response as a plain dict.
        """
        if isinstance(response, dict):
            return response
        # Fallback: Result objects have a full_return property
        return response.full_return  # type: ignore[union-attr]

    def _check_response(
        self, response: dict[str, Any] | Any, operation: str
    ) -> dict[str, Any]:
        """
        Validate a FalconPy response and extract the body.

        FalconPy returns dicts with ``status_code``, ``headers``, and ``body``.
        This method checks the status and returns the body on success, or
        raises an appropriate exception on failure.

        Args:
            response: FalconPy response (dict or Result object).
            operation: Human-readable operation name for error messages.

        Returns:
            The response body dictionary.

        Raises:
            AuthenticationError: On HTTP 401 or 403.
            CrowdStrikeError: On any other non-2xx status.
        """
        resp = self._as_dict(response)
        status = resp.get("status_code", 0)
        body = resp.get("body", {})

        logger.debug(
            "%s response: HTTP %s, body keys=%s",
            operation,
            status,
            list(body.keys()) if isinstance(body, dict) else type(body).__name__,
        )

        if status in (200, 201):
            return body

        # Extract error message from standard CrowdStrike error envelope
        errors = body.get("errors", []) if isinstance(body, dict) else []
        if errors:
            msg = errors[0].get("message", "Unknown error")
        else:
            msg = str(body) if body else "Empty response body"

        if status in (401, 403):
            logger.error(
                "%s authorization failure (HTTP %s): %s", operation, status, msg
            )
            raise AuthenticationError(f"{operation} (HTTP {status}): {msg}")

        logger.error("%s failed (HTTP %s): %s", operation, status, msg)
        raise CrowdStrikeError(f"{operation} failed (HTTP {status}): {msg}")

    # -------------------------------------------------------------------------
    # Time Normalization
    # -------------------------------------------------------------------------

    @staticmethod
    def _normalize_time(value: str) -> str:
        """
        Normalize a time string for the LogScale API.

        LogScale uses positive relative times: ``"7d"`` means "7 days ago",
        ``"24h"`` means "24 hours ago". A leading dash (e.g., ``"-7d"``) is
        common in other tools but causes an HTTP 400 from LogScale.

        This method strips the leading dash from relative times while leaving
        absolute timestamps (ISO 8601) and keywords (``"now"``) unchanged.

        Args:
            value: Time string, e.g. "-7d", "7d", "now", "2024-01-01T00:00:00Z".

        Returns:
            Normalized time string safe for the LogScale API.
        """
        if not value:
            return value

        # Relative times: optional dash, digits, then a unit letter (s/m/h/d/w)
        stripped = value.lstrip("-")
        if stripped and stripped[-1] in "smhdw" and stripped[:-1].isdigit():
            return stripped

        # Absolute timestamps, "now", or anything else — pass through unchanged
        return value

    # -------------------------------------------------------------------------
    # CID Filter
    # -------------------------------------------------------------------------

    @staticmethod
    def _build_cid_filter(cids: list[str]) -> str:
        """
        Build a LogScale CID filter string.

        Args:
            cids: List of CIDs to filter on.

        Returns:
            CID filter string to prepend to a query, or empty string
            if the list is empty.
        """
        if not cids:
            return ""

        cid_list = ", ".join(f'"{cid}"' for cid in cids)
        return f"cid =~ in(values=[{cid_list}])"

    # -------------------------------------------------------------------------
    # API Methods
    # -------------------------------------------------------------------------

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
            query: The LogScale query string.
            start_time: Search start (e.g., "-7d", "2024-01-01T00:00:00Z").
            end_time: Search end (default "now").
            cids: Optional list of CIDs to filter on.

        Returns:
            The job ID for polling status.

        Raises:
            AuthenticationError: If credentials are invalid.
            QuerySubmissionError: If query submission fails.
        """
        full_query = query
        if cids:
            cid_filter = self._build_cid_filter(cids)
            full_query = f"{cid_filter} | {query}"

        # LogScale uses positive relative times ("7d", not "-7d")
        normalized_start = self._normalize_time(start_time)
        normalized_end = self._normalize_time(end_time)

        logger.debug(
            "Submitting query to %s/%s (start=%s, end=%s): %s",
            self.base_url,
            self.repository,
            normalized_start,
            normalized_end,
            full_query[:200],
        )

        response = await asyncio.to_thread(
            self._falcon.start_search,
            repository=self.repository,
            query_string=full_query,
            start=normalized_start,
            end=normalized_end,
            is_live=False,
        )

        try:
            body = self._check_response(response, "Query submission")
        except AuthenticationError:
            raise
        except CrowdStrikeError as e:
            raise QuerySubmissionError(str(e)) from e

        job_id = body.get("id")
        if not job_id:
            logger.error("No job ID in response body: %s", body)
            raise QuerySubmissionError("No job ID in response")

        logger.debug("Submitted query, job_id=%s", job_id)
        return job_id

    async def get_query_status(self, job_id: str) -> dict[str, Any]:
        """
        Get the status of a query job.

        The NG-SIEM API returns status and results in the same call.
        The response includes ``done`` (bool), ``events`` (list), and
        ``metaData`` (dict with ``eventCount``, etc.).

        Args:
            job_id: The job ID returned from submit_query.

        Returns:
            Status dictionary with 'done' flag, events, and metadata.

        Raises:
            QueryStatusError: If status retrieval fails.
        """
        response = await asyncio.to_thread(
            self._falcon.get_search_status,
            repository=self.repository,
            search_id=job_id,
        )

        try:
            return self._check_response(response, "Query status")
        except CrowdStrikeError as e:
            raise QueryStatusError(str(e)) from e

    async def get_query_results(self, job_id: str) -> dict[str, Any]:
        """
        Get the results of a completed query.

        Delegates to ``get_query_status`` — the NG-SIEM API returns
        status and results from the same endpoint.

        Args:
            job_id: The job ID returned from submit_query.

        Returns:
            Results dictionary with 'events' list and metadata.

        Raises:
            QueryStatusError: If result retrieval fails.
        """
        return await self.get_query_status(job_id)

    async def cancel_query(self, job_id: str) -> None:
        """
        Cancel a running query job (best-effort).

        Logs a warning on failure rather than raising, since the job
        may already be complete or cancelled.

        Args:
            job_id: The job ID to cancel.
        """
        response = await asyncio.to_thread(
            self._falcon.stop_search,
            repository=self.repository,
            id=job_id,
        )

        resp = self._as_dict(response)
        status = resp.get("status_code", 0)
        if status not in (200, 204):
            logger.warning(
                "Cancel query %s returned HTTP %s (may already be complete)",
                job_id,
                status,
            )

    async def close(self) -> None:
        """
        Clean up resources.

        FalconPy manages its own HTTP session internally, so this is
        a no-op. Provided for interface compatibility with callers
        that expect a cleanup method (e.g., runner.py).
        """
        pass
