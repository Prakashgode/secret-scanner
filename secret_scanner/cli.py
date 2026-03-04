import argparse
import os
import sys
from typing import List

from . import __version__
from .output import format_results
from .scanner import Finding, SecretScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan codebases for hardcoded secrets, API keys, and credentials.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Scan for secrets")
    scan_parser.add_argument(
        "--path",
        required=True,
        help="Path to file or directory to scan",
    )
    scan_parser.add_argument(
        "--output",
        choices=["console", "json", "sarif"],
        default="console",
        help="Output format (default: console)",
    )
    scan_parser.add_argument(
        "--config",
        help="Path to custom rules YAML file",
    )
    scan_parser.add_argument(
        "--git-history",
        action="store_true",
        help="Also scan git commit history",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        sys.exit(1)

    scanner = SecretScanner(config_path=args.config)

    findings: List[Finding] = []

    if os.path.isfile(args.path):
        findings = scanner.scan_file(args.path)
    elif os.path.isdir(args.path):
        findings = scanner.scan_directory(args.path)
    else:
        print(f"Error: path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    if args.git_history:
        findings.extend(scanner.scan_git_history(args.path))

    output = format_results(findings, args.output)
    print(output)

    # non-zero exit so CI fails on findings
    if findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
