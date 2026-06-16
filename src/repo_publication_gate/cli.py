from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .config import STARTER_CONFIG, VALID_SEVERITIES, load_config
from .models import SEVERITY_ORDER
from .report import render_json, render_markdown
from .scanner import scan_repository


RULE_SUMMARY = """\
RPG001 high     Environment file
RPG002 high     Private key/certificate container
RPG003 high     Local database, dump, or backup
RPG004 high+    Secret-like content
RPG005 medium   Absolute local workstation path
RPG006 medium   Oversized file
RPG007 medium   Generated/runtime directory
RPG008 high     Nested Git metadata
RPG009 low      Missing governance document
RPG010 medium   Missing .gitignore protection
RPG011 medium   Symlink requiring manual review
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-gate",
        description="Audit a repository before public release.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository directory to scan. Defaults to the current directory.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Explicit TOML configuration path.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Report format.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Write the report to a file instead of stdout.",
    )
    parser.add_argument(
        "--fail-on",
        choices=sorted(VALID_SEVERITIES, key=SEVERITY_ORDER.get),
        help="Exit with code 1 when a finding meets this severity threshold.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Create .repo-publication-gate.toml in the target directory.",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List implemented rules and exit.",
    )
    return parser


def _write_report(payload: str, output: Path | None) -> None:
    if output is None:
        print(payload, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        print(RULE_SUMMARY, end="")
        return 0

    root = Path(args.path).resolve()

    if args.init:
        if not root.exists():
            print(f"error: target path does not exist: {root}", file=sys.stderr)
            return 2
        config_path = root / ".repo-publication-gate.toml"
        if config_path.exists():
            print(f"error: configuration already exists: {config_path}", file=sys.stderr)
            return 2
        config_path.write_text(STARTER_CONFIG, encoding="utf-8")
        print(f"created: {config_path}")
        return 0

    try:
        config = load_config(root, args.config)
    except (OSError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    if args.fail_on:
        config.fail_on = args.fail_on

    result = scan_repository(root, config)

    if result.operational_errors and result.scanned_files == 0:
        payload = render_json(result) if args.format == "json" else render_markdown(result)
        _write_report(payload, args.output)
        return 2

    payload = render_json(result) if args.format == "json" else render_markdown(result)
    _write_report(payload, args.output)

    threshold = SEVERITY_ORDER[config.fail_on]
    should_fail = any(
        SEVERITY_ORDER[finding.severity] >= threshold for finding in result.findings
    )
    return 1 if should_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
