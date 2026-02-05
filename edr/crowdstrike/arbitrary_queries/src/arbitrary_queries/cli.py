"""
Command-line interface for Arbitrary Queries.

Provides a CLI for running queries across multiple CrowdStrike environments.
Uses only stdlib (argparse) for minimal dependencies.
"""

import argparse
import asyncio
import sys
from pathlib import Path

from arbitrary_queries.models import ExecutionMode
from arbitrary_queries.runner import run


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Args:
        argv: Argument list (defaults to sys.argv[1:] if None).
              Accepts explicit argv for testing.
    
    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        prog="arbitrary-queries",
        description="Arbitrary Queries - Multi-tenant CrowdStrike NG-SIEM query tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Run a batch query across all CIDs
  %(prog)s -q queries/hunt.txt

  # Run iterative queries with specific CIDs
  %(prog)s -q queries/hunt.txt -m iterative --cids data/target_cids.txt

  # Query with custom time range
  %(prog)s -q queries/hunt.txt -s "-24h" -e "-1h"

  # Use YAML config with verbose output
  %(prog)s -c config/settings.yaml -q queries/hunt.txt -v
""",
    )
    
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=Path("./config/settings.json"),
        metavar="PATH",
        help="Path to configuration file, JSON or YAML (default: ./config/settings.json)",
    )
    parser.add_argument(
        "-q", "--query",
        type=Path,
        required=True,
        metavar="PATH",
        help="Path to query file",
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["batch", "iterative"],
        default="batch",
        help="Execution mode: 'batch' for single query across all CIDs, "
             "'iterative' for separate query per CID (default: batch)",
    )
    parser.add_argument(
        "--cids",
        type=Path,
        metavar="PATH",
        help="Path to CID filter file; if omitted, queries all CIDs",
    )
    parser.add_argument(
        "-s", "--start",
        default=None,
        metavar="TIME",
        help="Query start time, e.g. '-7d', '-24h' (default: from config)",
    )
    parser.add_argument(
        "-e", "--end",
        default="now",
        metavar="TIME",
        help="Query end time (default: 'now')",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    return parser.parse_args(argv)


def validate_paths(args: argparse.Namespace) -> list[str]:
    """
    Validate that required paths exist.
    
    Args:
        args: Parsed arguments namespace.
    
    Returns:
        List of error messages (empty if all paths valid).
    """
    errors = []
    
    if not args.config.exists():
        errors.append(f"Config file not found: {args.config}")
    if not args.query.exists():
        errors.append(f"Query file not found: {args.query}")
    if args.cids and not args.cids.exists():
        errors.append(f"CID filter file not found: {args.cids}")
    
    return errors


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point.
    
    Args:
        argv: Argument list (defaults to sys.argv[1:] if None).
              Accepts explicit argv for testing.
    
    Returns:
        Exit code: 0 for success, 1 for error.
    """
    args = parse_args(argv)
    
    # Validate paths exist
    errors = validate_paths(args)
    if errors:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        return 1
    
    # Convert mode string to enum
    mode = ExecutionMode.BATCH if args.mode == "batch" else ExecutionMode.ITERATIVE
    
    try:
        asyncio.run(
            run(
                config_path=args.config,
                query_path=args.query,
                mode=mode,
                cid_filter_path=args.cids,
                start_time=args.start,
                end_time=args.end,
                verbose=args.verbose,
            )
        )
        return 0
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
