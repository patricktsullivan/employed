"""
Main orchestration for Arbitrary Queries.

Coordinates configuration loading, client setup, query execution,
and output generation. This is the "glue" module that ties every other
module together into a single end-to-end workflow.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class CIDFilterResult:
    """
    Result of loading a CID filter file.
    
    Frozen dataclass for consistency with the rest of the project's data
    containers (CIDInfo, QueryResult, QuerySummary, etc.).
    
    Attributes:
        matched: CIDInfo entries that were found in the registry.
        unmatched: Tuples of (line_number, value) for entries not in the registry.
    """
    
    matched: tuple[CIDInfo, ...]
    unmatched: tuple[tuple[int, str], ...]


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
    
    return list(result.matched)


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
    
    return CIDFilterResult(
        matched=tuple(matched),
        unmatched=tuple(unmatched),
    )


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


@asynccontextmanager
async def _create_client(
    credentials: Credentials,
    config: CrowdStrikeConfig,
) -> AsyncIterator[CrowdStrikeClient]:
    """
    Create CrowdStrike client with proper resource management.
    
    Uses the client's own async context manager (__aenter__/__aexit__)
    for session lifecycle. No defensive hasattr/getattr needed because
    CrowdStrikeClient is defined in this project with a known interface.
    
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
        await client.close()


def _build_summaries(
    results: list[QueryResult],
    total_time: float,
) -> tuple[list[QuerySummary], int, int, int]:
    """
    Build per-CID summaries from query results.
    
    Args:
        results: List of QueryResult from execution.
        total_time: Wall-clock time for the entire run.
    
    Returns:
        Tuple of (cid_summaries, total_records, successful_count, failed_count).
    """
    cid_summaries: list[QuerySummary] = []
    total_records = 0
    successful = 0
    failed = 0
    
    for result in results:
        has_error = result.has_error
        status = QueryJobStatus.FAILED if has_error else QueryJobStatus.COMPLETED
        
        if has_error:
            failed += 1
        else:
            successful += 1
        
        total_records += result.record_count
        
        summary = QuerySummary(
            cid=result.cid,
            cid_name=result.cid_name,
            record_count=result.record_count,
            execution_time_seconds=result.execution_time_seconds,
            status=status,
            error=result.error,
        )
        cid_summaries.append(summary)
    
    return cid_summaries, total_records, successful, failed


def _write_outputs(
    mode: ExecutionMode,
    results: list[QueryResult],
    output_dir: Path,
    verbose: bool,
) -> None:
    """
    Write query results to CSV files.
    
    Args:
        mode: Execution mode (batch writes one file, iterative writes per-CID).
        results: List of QueryResult from execution.
        output_dir: Directory for output files.
        verbose: Whether to log output paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if mode == ExecutionMode.BATCH:
        output_filename = generate_output_filename("batch_results", "csv")
        output_path = output_dir / output_filename
        # Batch mode produces exactly one result; if run_batch ever returns
        # multiple results this assertion will catch the change early.
        assert len(results) == 1, f"Batch mode expected 1 result, got {len(results)}"
        write_csv(results[0], output_path, include_cid=True)
        if verbose:
            logger.info(f"Results written to: {output_path}")
    else:
        output_files = write_csv_per_cid(results, output_dir)
        if verbose:
            logger.info(
                f"Results written to {len(output_files)} files in: {output_dir}"
            )


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
    Run the Arbitrary Queries workflow.
    
    High-level orchestrator that coordinates:
    1. Configuration and CID registry loading
    2. CID filtering (if a filter file is provided)
    3. Query loading and credential retrieval
    4. Query execution via the appropriate mode
    5. CSV output generation
    6. Summary building and reporting
    
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
    
    # Execute queries
    async with _create_client(credentials, config.crowdstrike) as client:
        executor = QueryExecutor(
            client=client,
            query_defaults=config.query_defaults,
            concurrency_config=config.concurrency,
        )
        
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
            results = await executor.run_iterative(
                cid_infos=cid_infos,
                query=query,
                start_time=start_time,
                end_time=end_time,
            )
    
    # Write output files
    _write_outputs(mode, results, config.output_dir, verbose)
    
    # Build summaries
    end_timestamp = datetime.now(timezone.utc)
    total_time = (end_timestamp - start_timestamp).total_seconds()
    
    cid_summaries, total_records, successful, failed = _build_summaries(
        results, total_time
    )
    
    if verbose:
        for summary in cid_summaries:
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
