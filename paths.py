#!/usr/bin/env python3
"""Shared helper for validating user-supplied output file paths."""

import os


def safe_output_path(filename):
    """Resolve filename and ensure it stays within the current working directory.

    A plain substring check for ".." can still be bypassed with absolute
    paths (e.g. "/etc/cron.d/x") or symlinks. Resolving the path and
    confirming it is contained in the cwd closes both gaps.
    """
    cwd = os.path.realpath(os.getcwd())
    resolved = os.path.realpath(os.path.join(cwd, filename))

    if os.path.commonpath([resolved, cwd]) != cwd:
        raise ValueError(f"Refusing to write outside the working directory: {filename}")

    return resolved
