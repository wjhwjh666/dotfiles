#!/usr/bin/env python3
"""PostToolUse hook: format a file right after Claude edits it.

Design constraints (deliberate, do not relax without thinking):

1. FAIL-OPEN. Any unexpected condition exits 0 silently. A formatter hook must
   never block the workflow -- it is a convenience, not a guard. The L3 guards
   are what block; this is not one of them.

2. OPT-IN PER PROJECT. A file is only formatted when its repository declares a
   formatter config (pyproject.toml / ruff.toml / .prettierrc / ...). Without
   that signal the project has not asked to be reformatted, and rewriting its
   files would be an unrequested change.

3. NEVER WIDEN THE BLAST RADIUS. Only the single file named by the tool call is
   touched. No directory-wide runs, no --fix of lint rules, formatting only.

Protocol: input is JSON on stdin (not argv); tool_input.file_path names the file.
"""

import json
import os
import shutil
import subprocess
import sys

TIMEOUT = 10

# extension -> (formatter command builder, marker files that opt the repo in)
PY_MARKERS = ("pyproject.toml", "ruff.toml", ".ruff.toml", "setup.cfg")
JS_MARKERS = (
    ".prettierrc",
    ".prettierrc.json",
    ".prettierrc.yml",
    ".prettierrc.yaml",
    ".prettierrc.js",
    "prettier.config.js",
    "prettier.config.mjs",
)

PY_EXT = {".py", ".pyi"}
JS_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".json", ".css", ".scss", ".less", ".html", ".md", ".yaml", ".yml",
}


def find_marker(start_dir, markers):
    """Walk up from start_dir looking for any marker file. Stops at the
    filesystem root or after 25 levels, whichever comes first."""
    cur = os.path.abspath(start_dir)
    for _ in range(25):
        for m in markers:
            if os.path.isfile(os.path.join(cur, m)):
                return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return None


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        return 0

    data = json.loads(raw)
    path = (data.get("tool_input") or {}).get("file_path")
    if not path or not os.path.isfile(path):
        return 0

    ext = os.path.splitext(path)[1].lower()
    directory = os.path.dirname(os.path.abspath(path))

    if ext in PY_EXT:
        if not find_marker(directory, PY_MARKERS):
            return 0
        exe = shutil.which("ruff")
        if not exe:
            return 0
        cmd = [exe, "format", "--", path]
    elif ext in JS_EXT:
        if not find_marker(directory, JS_MARKERS):
            return 0
        exe = shutil.which("prettier")
        if not exe:
            return 0
        # `--` for the same reason the ruff branch has it: a filename that
        # starts with a dash is otherwise parsed as a flag.
        cmd = [exe, "--write", "--log-level", "warn", "--", path]
    else:
        return 0

    subprocess.run(
        cmd,
        timeout=TIMEOUT,
        capture_output=True,
        cwd=directory,
        check=False,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Fail-open by design: see constraint 1 above.
        sys.exit(0)
