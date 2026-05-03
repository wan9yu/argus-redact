#!/usr/bin/env python3
"""Run mutmut with setproctitle no-op'd.

setproctitle 1.3.x segfaults after ``os.fork()`` on macOS when the parent has
loaded a PyO3 / Tokio-using extension. mutmut calls ``setproctitle`` in every
forked child to label the process — every child crashes before pytest even
runs, and mutmut categorises the result as ``segfault`` rather than the
test outcome we actually want.

This wrapper neutralises ``setproctitle`` *before* mutmut imports it, so
process titles aren't updated but the workers run to completion.
"""

from __future__ import annotations

import importlib
import sys


def _install_noop_setproctitle() -> None:
    """Replace ``setproctitle.setproctitle`` with a no-op shim.

    Pre-imports the real module, then overrides the function in place so any
    later ``from setproctitle import setproctitle`` sees the shim.
    """
    try:
        mod = importlib.import_module("setproctitle")
    except Exception:
        # If the package isn't installed, mutmut will fail anyway when it
        # tries to import; let that be the user-visible error.
        return

    def _noop(*_args, **_kwargs) -> None:  # pragma: no cover
        return None

    mod.setproctitle = _noop  # type: ignore[attr-defined]


def main() -> int:
    _install_noop_setproctitle()
    from mutmut.__main__ import cli

    cli()  # click dispatches based on sys.argv
    return 0


if __name__ == "__main__":
    sys.exit(main())
