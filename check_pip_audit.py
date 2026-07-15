#!/usr/bin/env python3
"""
Runs pip-audit against all three requirement files, honoring a small
expiring ignore-list (pip_audit_ignores.toml) for findings that have no
fix released yet.

Why an ignore list at all: a vulnerability disclosed for an
already-pinned dependency with no fixed version yet would otherwise fail
CI with nothing anyone can immediately do about it - exactly the kind of
failure a team learns to ignore, which defeats the point of gating on
this in the first place. But an ignore without an expiry would just as
easily be forgotten forever, so every entry must have one: past that
date, this script refuses to run pip-audit at all and instead fails with
a clear message pointing at what needs re-evaluating.
"""
import datetime
import subprocess
import sys
import tomllib
from pathlib import Path

IGNORE_FILE = Path(__file__).resolve().parent / "pip_audit_ignores.toml"
REQUIREMENTS = ["requirements.txt", "requirements-dashboard.txt", "requirements-dev.txt"]


def load_ignores(path=IGNORE_FILE):
    """Return the list of {id, expires, reason} ignore entries, or []
    if the file is missing (nothing to suppress yet)."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return []
    entries = data.get("ignore", [])
    return entries if isinstance(entries, list) else []


def expired_ignores(ignores, today=None):
    """Entries whose expiry date has already passed."""
    today = today or datetime.date.today()
    return [
        entry for entry in ignores
        if datetime.date.fromisoformat(entry["expires"]) < today
    ]


def main():
    ignores = load_ignores()
    expired = expired_ignores(ignores)
    if expired:
        print("The following pip-audit suppressions have expired and need review:", file=sys.stderr)
        for entry in expired:
            print(f"  - {entry['id']} (expired {entry['expires']}): {entry.get('reason', '')}", file=sys.stderr)
        print(f"\nUpdate or remove them in {IGNORE_FILE}", file=sys.stderr)
        return 1

    cmd = ["pip-audit"]
    for requirements_file in REQUIREMENTS:
        cmd += ["-r", requirements_file]
    for entry in ignores:
        cmd += ["--ignore-vuln", entry["id"]]

    return subprocess.run(cmd).returncode


if __name__ == "__main__":
    sys.exit(main())
