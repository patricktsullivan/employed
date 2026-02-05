"""
Command-line interface for NG-SIEM Hunter.

Provides a CLI for running queries across multiple CrowdStrike environments.
"""

import asyncio
from pathlib import Path

import click

from arbitrary_queries.models import ExecutionMode
from arbitrary_queries.runner import run


@click.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    default="./config/settings.json",
    help="Path to configuration file (JSON or YAML).",
)
@click.option(
    "--query", "-q",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to query file.",
)
@click.option(
    "--mode", "-m",
    type=click.Choice(["batch", "iterative"]),
    default="batch",
    help="Execution mode: 'batch' for single query across all CIDs, "
         "'iterative' for separate query per CID.",
)
@click.option(
    "--cids",
    type=click.Path(exists=True, path_type=Path),
    help="Path to CID filter file. If not provided, queries all CIDs.",
)
@click.option(
    "--start", "-s",
    default=None,
    help="Query start time (e.g., '-7d', '-24h'). Uses config default if not specified.",
)
@click.option(
    "--end", "-e",
    default="now",
    help="Query end time (default: 'now').",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output.",
)
def main(
    config: Path,
    query: Path,
    mode: str,
    cids: Path | None,
    start: str | None,
    end: str,
    verbose: bool,
):
    """
    NG-SIEM Hunter - Multi-tenant CrowdStrike NG-SIEM query tool.
    
    Run arbitrary NG-SIEM queries across multiple CrowdStrike environments
    for incident response and threat hunting.
    
    Examples:
    
        # Run a batch query across all CIDs
        arbitrary-queries -q queries/hunt.txt
        
        # Run iterative queries with specific CIDs
        arbitrary-queries -q queries/hunt.txt -m iterative --cids data/target_cids.txt
        
        # Query with custom time range
        arbitrary-queries -q queries/hunt.txt -s "-24h" -e "-1h"
    """
    execution_mode = ExecutionMode.BATCH if mode == "batch" else ExecutionMode.ITERATIVE
    
    try:
        asyncio.run(
            run(
                config_path=config,
                query_path=query,
                mode=execution_mode,
                cid_filter_path=cids,
                start_time=start,
                end_time=end,
                verbose=verbose,
            )
        )
    except KeyboardInterrupt:
        click.echo("\nAborted.")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
