"""Command-line interface for AutoSeal."""

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from autoseal.execution import run_command


def _non_negative_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autoseal",
        description="Inspect command execution as structured evidence.",
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="Run one command and print process evidence as JSON.",
    )
    run_parser.add_argument(
        "--max-output-bytes",
        type=_non_negative_integer,
        default=64 * 1024,
        help="Maximum stdout and stderr bytes retained separately.",
    )
    run_parser.add_argument(
        "--cwd",
        type=Path,
        default=None,
        help="Working directory for child process.",
    )
    run_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to execute. Place it after --.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)

    command = list(arguments.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("run requires a command after --")

    result = run_command(
        command,
        cwd=arguments.cwd,
        max_output_bytes=arguments.max_output_bytes,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))

    # The CLI successfully produced evidence even when the child failed.
    # Consumers must inspect status and exit_code instead of the CLI exit code.
    return 0
