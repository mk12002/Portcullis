"""Portcullis CLI.

    portcullis scan <path> [--format json|html|sarif|md|all] [--out DIR]
                           [--fail-on P0|P1|P2|P3] [--platforms LIST]
                           [--trusted-actions PREFIX]... [--quiet]
    portcullis rules list
    portcullis version

Exit codes: 0 success, 1 findings at/above the --fail-on threshold,
2 usage or fatal error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from portcullis import TOOL_NAME, __version__
from portcullis.core.engine import scan
from portcullis.core.models import Priority, ScanConfig, Severity
from portcullis.emitters import EMITTERS
from portcullis.rules import all_rule_metas

VALID_PLATFORMS = {"github", "gitlab", "jenkins"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Static security analyzer for CI/CD pipeline definitions.",
    )
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a directory for pipeline security issues")
    p_scan.add_argument("path", nargs="?", default=".", help="directory to scan (default: cwd)")
    p_scan.add_argument(
        "--format",
        choices=["json", "html", "sarif", "md", "all"],
        default="html",
        help="report format; md is a PR-comment-sized summary (default: html)",
    )
    p_scan.add_argument(
        "--out", default="./portcullis-report", help="output directory (default: ./portcullis-report)"
    )
    p_scan.add_argument(
        "--fail-on",
        choices=["P0", "P1", "P2", "P3"],
        default=None,
        help="exit non-zero if any finding is at or above this priority",
    )
    p_scan.add_argument(
        "--platforms",
        default="github,gitlab,jenkins",
        help="comma-separated subset of: github,gitlab,jenkins",
    )
    p_scan.add_argument(
        "--trusted-actions",
        action="append",
        default=[],
        metavar="PREFIX",
        help="treat uses: references with this prefix as first-party (repeatable)",
    )
    p_scan.add_argument("--quiet", action="store_true", help="suppress the console summary")

    p_rules = sub.add_parser("rules", help="rule catalog")
    p_rules.add_argument("action", choices=["list"], help="list all rules")

    sub.add_parser("version", help="print version")
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    platforms = frozenset(p.strip() for p in args.platforms.split(",") if p.strip())
    unknown = platforms - VALID_PLATFORMS
    if unknown:
        print(f"error: unknown platform(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: not a directory: {args.path}", file=sys.stderr)
        return 2

    config = ScanConfig(
        platforms=platforms,
        trusted_action_prefixes=tuple(args.trusted_actions),
        quiet=args.quiet,
    )
    report = scan(root, config)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = ["json", "html", "sarif", "md"] if args.format == "all" else [args.format]
    written = []
    for fmt in formats:
        path = out_dir / f"report.{fmt}"
        path.write_text(EMITTERS[fmt](report), encoding="utf-8", newline="\n")
        written.append(path)

    if not args.quiet:
        counts = report.priority_counts
        print(f"portcullis v{__version__} — scanned {len(report.files_scanned)} pipeline file(s)")
        print(
            f"score: {report.score}/100 · "
            + " ".join(f"{p}:{counts[p]}" for p in ("P0", "P1", "P2", "P3"))
        )
        if report.findings:
            top = report.findings[0]
            sev = top.severity or top.base_severity
            print(
                f"top finding: [{top.priority.name if top.priority is not None else '—'}/{sev.name}] "
                f"{top.rule_id} {top.kind} at {top.file_path}:{top.line}"
            )
        for entry in report.skipped:
            print(f"warning: {entry['file']}: {entry['reason']}", file=sys.stderr)
        for path in written:
            print(f"wrote {path}")

    if args.fail_on is not None:
        threshold = Priority[args.fail_on]
        tripped = [
            f
            for f in report.findings
            if f.priority is not None
            and f.priority <= threshold
            and f.severity != Severity.INFO
        ]
        if tripped:
            if not args.quiet:
                print(
                    f"gate: {len(tripped)} finding(s) at or above {threshold.name} — failing",
                    file=sys.stderr,
                )
            return 1
    return 0


def cmd_rules_list() -> int:
    for meta in all_rule_metas():
        print(f"{meta.rule_id}  {meta.name}")
        print(f"    {meta.summary}")
        print(f"    FP note: {meta.fp_note}")
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "rules":
        return cmd_rules_list()
    if args.command == "version":
        print(f"{TOOL_NAME} {__version__}")
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
