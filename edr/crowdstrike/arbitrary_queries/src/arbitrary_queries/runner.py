"""
Main orchestration for NG-SIEM Hunter.

Coordinates configuration loading, client setup, query execution,
and output generation.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from arbitrary_queries.client import CrowdStrikeClient
from arbitrary_queries.config import CrowdStrikeConfig, load_config
from arbitrary_queries.models import (
    CIDInfo,
    ExecutionMode,
    QueryJobStatus,
    QueryResult,
    QuerySummary,
    OverallSummary,
)
from arbitrary_queries.output import (
    write_csv,
    write_csv_per_cid,
    format_summary,
    format_overall_summary,
    generate_output_filename,
)
from arbitrary_queries.query_executor import QueryExecutor
from arbitrary_queries.secrets import Credentials, get_credentials

logger = logging.getLogger(__name__)


class CIDFilterResult:
    """Result of loading a CID filter file."""
    
    def __init__(
        self,
        matched: list[CIDInfo],
        unmatched: list[tuple[int, str]],
    ):
        self.matched = matched
        self.unmatched = unmatched  # List of (line_number, value) tuples


def load_cid_registry(path: Path) -> dict[str, str]:
    """
    Load CID registry from JSON file.
    
    Args:
        path: Path to CID registry JSON file.
    
    Returns:
        Dictionary mapping CID to customer name.
    
    Raises:
        FileNotFoundError: If registry file doesn't exist.
        json.JSONDecodeError: If file contains invalid JSON.
    """
    with open(path) as f:
        return json.load(f)


def load_cid_filter(
    path: Path,
    registry: dict[str, str],
    warn_unmatched: bool = True,
) -> list[CIDInfo]:
    """
    Load CID filter from file.
    
    File should contain one CID or customer name per line.
    Lines starting with # are treated as comments.
    
    Args:
        path: Path to filter file.
        registry: Full CID registry for name lookups.
        warn_unmatched: If True, log warnings for unmatched entries.
    
    Returns:
        List of CIDInfo for matching CIDs.
    """
    result = load_cid_filter_with_details(path, registry)
    
    if warn_unmatched and result.unmatched:
        for line_num, value in result.unmatched:
            logger.warning(
                f"CID filter line {line_num}: '{value}' not found in registry"
            )
    
    return result.matched


def load_cid_filter_with_details(
    path: Path,
    registry: dict[str, str],
) -> CIDFilterResult:
    """
    Load CID filter from file with detailed matching information.
    
    Args:
        path: Path to filter file.
        registry: Full CID registry for name lookups.
    
    Returns:
        CIDFilterResult with matched CIDs and unmatched entries.
    """
    # Build lookups (case-insensitive for both CID and name)
    cid_lower_to_cid = {cid.lower(): cid for cid in registry.keys()}
    name_lower_to_cid = {name.lower(): cid for cid, name in registry.items()}
    
    matched: list[CIDInfo] = []
    unmatched: list[tuple[int, str]] = []
    
    with open(path) as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            line_lower = line.lower()
            
            # Try exact CID match first (case-insensitive)
            if line_lower in cid_lower_to_cid:
                actual_cid = cid_lower_to_cid[line_lower]
                matched.append(CIDInfo(cid=actual_cid, name=registry[actual_cid]))
            # Then try name match (case-insensitive)
            elif line_lower in name_lower_to_cid:
                cid = name_lower_to_cid[line_lower]
                matched.append(CIDInfo(cid=cid, name=registry[cid]))
            else:
                unmatched.append((line_num, line))
    
    return CIDFilterResult(matched=matched, unmatched=unmatched)


def load_query(path: Path) -> str:
    """
    Load query from file.
    
    Args:
        path: Path to query file.
    
    Returns:
        Query string with whitespace trimmed.
    """
    return path.read_text().strip()


def get_all_cids(registry: dict[str, str]) -> list[CIDInfo]:
    """
    Convert full registry to list of CIDInfo.
    
    Args:
        registry: CID registry dictionary.
    
    Returns:
        List of all CIDInfo entries.
    """
    return [CIDInfo(cid=cid, name=name) for cid, name in registry.items()]


def _get_result_error(result: QueryResult) -> str | None:
    """
    Safely extract error from QueryResult.
    
    Args:
        result: Query result to check.
    
    Returns:
        Error message if present, None otherwise.
    """
    return getattr(result, 'error', None) or None


@asynccontextmanager
async def _create_client(
    credentials: Credentials,
    config: CrowdStrikeConfig,
) -> AsyncIterator[CrowdStrikeClient]:
    """
    Create CrowdStrike client with proper resource management.
    
    Args:
        credentials: CrowdStrike API credentials.
        config: CrowdStrike configuration.
    
    Yields:
        Configured CrowdStrikeClient instance.
    """
    client = CrowdStrikeClient(
        credentials=credentials,
        config=config,
    )
    try:
        yield client
    finally:
        # Clean up client resources if it has a close method
        if hasattr(client, 'close'):
            close_method = getattr(client, 'close')
            if callable(close_method):
                result = close_method()
                # Handle async close methods
                if asyncio.iscoroutine(result):
                    await result


async def run(
    config_path: Path,
    query_path: Path,
    mode: ExecutionMode,
    cid_filter_path: Path | None = None,
    start_time: str | None = None,
    end_time: str = "now",
    verbose: bool = False,
) -> OverallSummary:
    """
    Run the NG-SIEM query workflow.
    
    Args:
        config_path: Path to configuration file.
        query_path: Path to query file.
        mode: Execution mode (batch or iterative).
        cid_filter_path: Optional path to CID filter file.
        start_time: Query start time (uses default if not specified).
        end_time: Query end time.
        verbose: Enable verbose output.
    
    Returns:
        OverallSummary with execution results.
    """
    start_timestamp = datetime.now(timezone.utc)
    
    # Load configuration
    config = load_config(config_path)
    
    # Load CID registry
    registry = load_cid_registry(config.cid_registry_path)
    
    # Determine which CIDs to query
    if cid_filter_path:
        cid_infos = load_cid_filter(cid_filter_path, registry, warn_unmatched=True)
    else:
        cid_infos = get_all_cids(registry)
    
    if not cid_infos:
        logger.warning("No CIDs to query.")
        return OverallSummary(
            total_cids=0,
            successful_cids=0,
            failed_cids=0,
            total_records=0,
            total_execution_time_seconds=0,
            mode=mode,
        )
    
    if verbose:
        logger.info(f"Querying {len(cid_infos)} CID(s) in {mode.value} mode...")
    
    # Load query
    query = load_query(query_path)
    
    if verbose:
        query_preview = query[:100] + "..." if len(query) > 100 else query
        logger.info(f"Query: {query_preview}")
    
    # Get credentials
    credentials = get_credentials(
        client_id_ref=config.onepassword.client_id_ref,
        client_secret_ref=config.onepassword.client_secret_ref,
    )
    
    # Initialize client with proper resource management
    async with _create_client(credentials, config.crowdstrike) as client:
        # Initialize executor
        executor = QueryExecutor(
            client=client,
            query_defaults=config.query_defaults,
            concurrency_config=config.concurrency,
        )
        
        # Execute query
        results: list[QueryResult]
        if mode == ExecutionMode.BATCH:
            result = await executor.run_batch(
                cid_infos=cid_infos,
                query=query,
                start_time=start_time,
                end_time=end_time,
            )
            results = [result]
        else:
            # run_iterative may return ErrorQueryResult for failed queries
            results = await executor.run_iterative(  # type: ignore[assignment]
                cid_infos=cid_infos,
                query=query,
                start_time=start_time,
                end_time=end_time,
            )
    
    # Generate output
    config.output_dir.mkdir(parents=True, exist_ok=True)
    
    if mode == ExecutionMode.BATCH:
        output_filename = generate_output_filename("batch_results", "csv")
        output_path = config.output_dir / output_filename
        write_csv(results[0], output_path, include_cid=True)
        if verbose:
            logger.info(f"Results written to: {output_path}")
    else:
        output_files = write_csv_per_cid(results, config.output_dir)
        if verbose:
            logger.info(
                f"Results written to {len(output_files)} files in: {config.output_dir}"
            )
    
    # Build summaries
    end_timestamp = datetime.now(timezone.utc)
    total_time = (end_timestamp - start_timestamp).total_seconds()
    
    cid_summaries: list[QuerySummary] = []
    total_records = 0
    successful = 0
    failed = 0
    
    for result in results:
        error = _get_result_error(result)
        has_error = error is not None
        status = QueryJobStatus.FAILED if has_error else QueryJobStatus.COMPLETED
        
        if has_error:
            failed += 1
        else:
            successful += 1
        
        total_records += result.record_count
        
        # Get execution time if available, otherwise 0.0
        # Note: Accurate per-query timing requires job-level tracking
        exec_time = getattr(result, 'execution_time_seconds', 0.0)
        if not isinstance(exec_time, (int, float)):
            exec_time = 0.0
        
        summary = QuerySummary(
            cid=result.cid,
            cid_name=result.cid_name,
            record_count=result.record_count,
            execution_time_seconds=float(exec_time),
            status=status,
            error=error,
        )
        cid_summaries.append(summary)
        
        if verbose:
            logger.info(format_summary(summary))
    
    # total_cids reflects actual CIDs queried, regardless of mode
    overall = OverallSummary(
        total_cids=len(cid_infos),
        successful_cids=successful,
        failed_cids=failed,
        total_records=total_records,
        total_execution_time_seconds=total_time,
        mode=mode,
        cid_summaries=tuple(cid_summaries),
    )
    
    logger.info(format_overall_summary(overall))
    
    return overall