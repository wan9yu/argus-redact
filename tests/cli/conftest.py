"""Shared CLI test helpers."""

import subprocess
import sys


def run_cli(*args, stdin=None):
    """Invoke ``argus-redact`` as a subprocess and return ``(returncode, stdout, stderr)``.

    UTF-8 encoding is pinned on the subprocess pipes — Windows CI defaults to
    cp1252, which can't encode CJK input or decode CJK output.
    """
    result = subprocess.run(
        [sys.executable, "-m", "argus_redact.cli.main", *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.returncode, result.stdout, result.stderr
