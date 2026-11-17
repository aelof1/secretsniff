"""Walk files (or git history) and apply the rules."""

from __future__ import annotations

import fnmatch
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .rules import PLACEHOLDERS, RULES, high_entropy_strings

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".idea", ".vscode"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".7z", ".exe", ".dll",
            ".so", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".lock", ".min.js", ".pyc"}
MAX_FILE_SIZE = 2 * 1024 * 1024
INLINE_IGNORE = "secretsniff:ignore"


@dataclass
class Finding:
    rule: str
    description: str
    severity: str
    file: str
    line: int
    secret: str
    commit: str = ""

    @property
    def masked(self) -> str:
        s = self.secret
        return s[:4] + "*" * min(12, max(4, len(s) - 6)) + s[-2:] if len(s) > 8 else "****"

    def to_dict(self, reveal: bool = False) -> dict:
        return {"rule": self.rule, "description": self.description, "severity": self.severity,
                "file": self.file, "line": self.line, "commit": self.commit,
                "secret": self.secret if reveal else self.masked}


def load_ignore(root: Path) -> list[str]:
    f = root / ".secretsniffignore"
    if not f.exists():
        return []
    return [l.strip() for l in f.read_text().splitlines() if l.strip() and not l.startswith("#")]


def is_ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(rel), p) for p in patterns)


def scan_text(text: str, filename: str, entropy: bool = True, commit: str = "") -> list[Finding]:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if INLINE_IGNORE in line or len(line) > 5000:
            continue
        matched_here = set()
        for rule in RULES:
            for m in rule.regex.finditer(line):
                secret = m.group(m.lastindex or 0) if m.lastindex else m.group(0)
                if PLACEHOLDERS.search(secret) or PLACEHOLDERS.search(m.group(0)):
                    continue
                matched_here.add(secret)
                findings.append(Finding(rule.id, rule.description, rule.severity, filename, lineno, secret, commit))
        if entropy:
            for token in high_entropy_strings(line):
                if any(token in s or s in token for s in matched_here) or PLACEHOLDERS.search(token):
                    continue
                findings.append(Finding("high-entropy", "High-entropy string (possible key)", "low",
                                        filename, lineno, token, commit))
    return findings


def iter_files(root: Path, ignore: list[str]):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            rel = str(path.relative_to(root))
            if any(name.endswith(ext) for ext in SKIP_EXT) or is_ignored(rel, ignore):
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield path


def scan_path(target: str, entropy: bool = True) -> list[Finding]:
    root = Path(target)
    base = root if root.is_dir() else root.parent
    ignore = load_ignore(base)
    findings = []
    for path in iter_files(root, ignore):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue  # binary file
        findings += scan_text(raw.decode("utf-8", errors="replace"), str(path.relative_to(base)), entropy)
    return findings


def scan_git_history(repo: str, entropy: bool = False, max_commits: int = 1000) -> list[Finding]:
    """Look at every added line in the git history - deleted secrets are still in there!"""
    try:
        out = subprocess.run(
            ["git", "-C", repo, "log", "-p", "--all", f"--max-count={max_commits}",
             "--no-color", "--unified=0", "--format=COMMIT %H"],
            capture_output=True, text=True, errors="replace", check=True,
        ).stdout
    except FileNotFoundError:
        raise SystemExit("git is not installed")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"git error: {exc.stderr.strip()}")

    findings: list[Finding] = []
    commit, filename, lineno = "", "", 0
    for line in out.splitlines():
        if line.startswith("COMMIT "):
            commit = line[7:15]
        elif line.startswith("+++ "):
            filename = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("@@"):
            try:
                lineno = int(line.split("+")[1].split(",")[0].split()[0])
            except (IndexError, ValueError):
                lineno = 0
        elif line.startswith("+") and not line.startswith("+++"):
            for f in scan_text(line[1:], filename, entropy, commit):
                f.line = lineno
                findings.append(f)
            lineno += 1

    # keep one entry per (rule, file, secret)
    unique = {}
    for f in findings:
        unique.setdefault((f.rule, f.file, f.secret), f)
    return list(unique.values())
