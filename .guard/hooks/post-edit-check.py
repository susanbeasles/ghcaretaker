#!/usr/bin/python3 -I
"""Compatibility entrypoint: only the installed host executor may run checks.
Configure host-managed hooks directly; never load hook code from a mutable tree.
"""
import subprocess
import sys

try:
    result = subprocess.run(
        ["/opt/agent-guard/bin/agent-guard", "check", "post-edit"],
        input=sys.stdin.buffer.read(2097153), close_fds=True, check=False,
    )
    sys.exit(result.returncode)
except OSError:
    sys.stderr.write("agent-guard: required isolated host executor is unavailable; checks did not run.\n")
    sys.exit(2)
