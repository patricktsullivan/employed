"""
Output generation for NG-SIEM Hunter.

Handles CSV file creation and summary report formatting.
"""

import csv
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arbitrary_queries.models import (
    QueryResult,
    QuerySummary,
    OverallSummary,
    QueryJobStatus,
)


__all__ = [
    "OutputError",
    "write_csv",
    "write_csv_per_cid",
    "format_summary",
    "format_overall_summary",
    "generate_output_filename",
]


class OutputError(Exception):
    """Raised when output generation fails."""

    pass


def write_csv(
    result: QueryResult,
    output_path: Path,
    include_cid: bool = False,
) -> Path:
    """
    Write query results to a CSV file.

    Args:
        result: QueryResult containing events to write.
        output_path: Path to output CSV file.
        include_cid: Whether to add CID columns to each row.

    Returns:
        Path to the created CSV file.

    Raises:
        OutputError: If file cannot be written.
    """
    events = result.events

    if not events:
        # Create empty file for empty results
        try:
            output_path.write_text("")
        except OSError as e:
            raise OutputError(f"Failed to write empty CSV to {output_path}: {e}") from e
        return output_path

    # Collect all unique field names across all events
    fieldnames: set[str] = set()
    for event in events:
        fieldnames.update(event.keys())

    # Sort fieldnames for consistent output, with common fields first
    priority_fields = ["@timestamp", "event_simpleName", "aid", "cid"]
    sorted_fields: list[str] = []
    for field in priority_fields:
        if field in fieldnames:
            sorted_fields.append(field)
            fieldnames.discard(field)
    sorted_fields.extend(sorted(fieldnames))

    # Add CID columns if requested
    if include_cid:
        sorted_fields = ["_cid", "_cid_name"] + sorted_fields

    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=sorted_fields, extrasaction="ignore"
            )
            writer.writeheader()

            for event in events:
                row = dict(event)
                if include_cid:
                    row["_cid"] = result.cid
                    row["_cid_name"] = result.cid_name
                writer.writerow(row)
    except OSError as e:
        raise OutputError(f"Failed to write CSV to {output_path}: {e}") from e

    return output_path


def write_csv_per_cid(
    results: list[QueryResult],
    output_dir: Path,
    prefix: str = "results",
    include_cid: bool = True,
) -> list[Path]:
    """
    Write separate CSV files for each CID result.

    Args:
        results: List of QueryResults, one per CID.
        output_dir: Directory to write CSV files.
        prefix: Prefix for output filenames.
        include_cid: Whether to add CID columns to each row.

    Returns:
        List of paths to created files.

    Raises:
        OutputError: If output directory cannot be created or files cannot be written.
    """
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise OutputError(f"Failed to create output directory {output_dir}: {e}") from e

    created_files: list[Path] = []

    for result in results:
        filename = generate_output_filename(
            prefix=prefix,
            cid=result.cid,
            extension="csv",
        )
        output_path = output_dir / filename
        write_csv(result, output_path, include_cid=include_cid)
        created_files.append(output_path)

    return created_files


def format_summary(summary: QuerySummary) -> str:
    """
    Format a per-CID summary for display.

    Args:
        summary: QuerySummary to format.

    Returns:
        Formatted summary string.
    """
    lines = [
        f"CID: {summary.cid} ({summary.cid_name})",
        f"  Status: {summary.status.value.upper()}",
        f"  Records: {summary.record_count:,}",
        f"  Execution Time: {summary.execution_time_seconds:.1f}s",
    ]

    if summary.error:
        lines.append(f"  Error: {summary.error}")

    if summary.warnings:
        for warning in summary.warnings:
            lines.append(f"  Warning: {warning}")

    return "\n".join(lines)


def format_overall_summary(summary: OverallSummary) -> str:
    """
    Format the overall execution summary for display.

    Args:
        summary: OverallSummary to format.

    Returns:
        Formatted summary string.
    """
    lines = [
        "=" * 60,
        "EXECUTION SUMMARY",
        "=" * 60,
        f"Mode: {summary.mode.value}",
        f"Total CIDs: {summary.total_cids}",
        f"Successful: {summary.successful_cids}",
        f"Failed: {summary.failed_cids}",
        f"Success Rate: {summary.success_rate:.1f}%",
        "-" * 60,
        f"Total Records: {summary.total_records:,}",
        f"Total Execution Time: {summary.total_execution_time_seconds:.1f}s",
        "=" * 60,
    ]

    return "\n".join(lines)


def generate_output_filename(
    prefix: str,
    extension: str,
    cid: str | None = None,
) -> str:
    """
    Generate a timestamped output filename.

    Args:
        prefix: Filename prefix.
        extension: File extension (without dot).
        cid: Optional CID to include in filename.

    Returns:
        Safe filename string.
    """
    # Include microseconds to avoid collisions when generating multiple files quickly
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

    # Sanitize CID for filesystem safety (ASCII alphanumeric, underscore, hyphen only)
    if cid:
        safe_cid = re.sub(r"[^a-zA-Z0-9_-]", "_", cid)
        # Collapse multiple underscores and strip leading/trailing
        safe_cid = re.sub(r"_+", "_", safe_cid).strip("_")
        if safe_cid:
            return f"{prefix}_{safe_cid}_{timestamp}.{extension}"

    return f"{prefix}_{timestamp}.{extension}"
