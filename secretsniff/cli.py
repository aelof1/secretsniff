"""secretsniff command line."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .scanner import scan_git_history, scan_path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[90m"}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secretsniff",
                                description="Find API keys, passwords and private keys left in source code.")
    p.add_argument("path", nargs="?", default=".", help="folder or file to scan (default: current folder)")
    p.add_argument("--git", action="store_true", help="also scan the whole git history")
    p.add_argument("--no-entropy", action="store_true", help="disable the high-entropy detector (less noise)")
    p.add_argument("--min-severity", choices=list(SEV_ORDER), default="low", help="hide less severe findings")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--reveal", action="store_true", help="show secrets in clear (careful!)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    findings = scan_path(args.path, entropy=not args.no_entropy)
    if args.git:
        findings += scan_git_history(args.path, entropy=not args.no_entropy)
    limit = SEV_ORDER[args.min_severity]
    findings = sorted((f for f in findings if SEV_ORDER[f.severity] <= limit),
                      key=lambda f: (SEV_ORDER[f.severity], f.file, f.line))

    if args.json:
        print(json.dumps([f.to_dict(args.reveal) for f in findings], indent=2))
    else:
        color = not args.no_color and sys.stdout.isatty()
        for f in findings:
            c, r = (SEV_COLOR[f.severity], "\033[0m") if color else ("", "")
            where = f"{f.file}:{f.line}" + (f" (commit {f.commit})" if f.commit else "")
            secret = f.secret if args.reveal else f.masked
            print(f"{c}[{f.severity.upper():<8}]{r} {where}\n           {f.description}: {secret}")
        print(f"\n{len(findings)} potential secret(s) found." if findings else "No secrets found.")
        if findings:
            print("Tip: a secret pushed to GitHub must be revoked, not just deleted from the code.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
