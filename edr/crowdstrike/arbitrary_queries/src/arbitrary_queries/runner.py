"""
Main orchestration for NG-SIEM Hunter.

Coordinates configuration loading, client setup, query execution,
and output generation.
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arbitrary_queries.client import CrowdStrikeClient
from arbitrary_queries.config import Config, load_config
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
from arbitrary_queries.secrets import get_credentials


def load_cid_registry(path: Path) -> dict[str, str]:
    """
    Load CID registry from JSON file.
    
    Args:
        path: Path to CID registry JSON file.
    
    Returns:
        Dictionary mapping CID to customer name.
    """
    with open(path) as f:
        return json.load(f)


def load_cid_filter(path: Path, registry: dict[str, str]) -> list[CIDInfo]:
    """
    Load CID filter from file.
    
    File should contain one CID or customer name per line.
    
    Args:
        path: Path to filter file.
        registry: Full CID registry for name lookups.
    
    Returns:
        List of CIDInfo for matching CIDs.
    """
    # Build reverse lookup (name -> CID)
    name_to_cid = {name.lower(): cid for cid, name in registry.items()}
    
    cid_infos: list[CIDInfo] = []
    
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Check if it's a CID or name
            if line in registry:
                cid_infos.append(CIDInfo(cid=line, name=registry[line]))
            elif line.lower() in name_to_cid:
                cid = name_to_cid[line.lower()]
                cid_infos.append(CIDInfo(cid=cid, name=registry[cid]))
    
    return cid_infos


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
        cid_infos = load_cid_filter(cid_filter_path, registry)
    else:
        cid_infos = get_all_cids(registry)
    
    if not cid_infos:
        print("No CIDs to query.")
        return OverallSummary(
            total_cids=0,
            successful_cids=0,
            failed_cids=0,
            total_records=0,
            total_execution_time_seconds=0,
            mode=mode,
        )
    
    if verbose:
        print(f"Querying {len(cid_infos)} CID(s) in {mode.value} mode...")
    
    # Load query
    query = load_query(query_path)
    
    if verbose:
        print(f"Query: {query[:100]}...")
    
    # Get credentials
    credentials = get_credentials(
        client_id_ref=config.onepassword.client_id_ref,
        client_secret_ref=config.onepassword.client_secret_ref,
    )
    
    # Initialize client
    client = CrowdStrikeClient(
        credentials=credentials,
        config=config.crowdstrike,
    )
    
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
        results = await executor.run_iterative(
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
            print(f"Results written to: {output_path}")
    else:
        output_files = write_csv_per_cid(results, config.output_dir)
        if verbose:
            print(f"Results written to {len(output_files)} files in: {config.output_dir}")
    
    # Build summaries
    end_timestamp = datetime.now(timezone.utc)
    total_time = (end_timestamp - start_timestamp).total_seconds()
    
    cid_summaries: list[QuerySummary] = []
    total_records = 0
    successful = 0
    failed = 0
    
    for result in results:
        has_error = hasattr(result, 'error') and result.error
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
            execution_time_seconds=0,  # Would need job tracking for accurate times
            status=status,
            error=result.error if has_error else None,
        )
        cid_summaries.append(summary)
        
        if verbose:
            print(format_summary(summary))
    
    overall = OverallSummary(
        total_cids=len(cid_infos) if mode == ExecutionMode.ITERATIVE else 1,
        successful_cids=successful,
        failed_cids=failed,
        total_records=total_records,
        total_execution_time_seconds=total_time,
        mode=mode,
        cid_summaries=cid_summaries,
    )
    
    print(format_overall_summary(overall))
    
    return overall
