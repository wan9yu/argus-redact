"""Meta-guard for the CI ``integration`` / ``integration-presidio`` jobs.

The server, MCP, and Presidio suites are gated behind ``skipif(not HAS_X)`` /
``pytest.mark.slow`` (see test_server*.py, test_mcp*.py, test_presidio.py) so the
base `test` job's venv (``.[dev]``) never has to carry starlette/mcp/presidio-analyzer.
That gating is exactly how a false green can happen: a CI job installs the extras
and runs this suite, but if the install silently fails (or a packaging change drops
the dependency), every gated test just skips again and pytest still exits 0 — the
job looks green while testing nothing.

The two extras-installing CI jobs set ``ARGUS_REQUIRE_INTEGRATION_EXTRAS`` to a
comma-separated list of the modules they expect to be importable (e.g.
``starlette,mcp`` or ``presidio_analyzer``). When set, this hook fails the run
loudly if any of them are missing. Unset (the default everywhere else — local
dev, the base `test` job), it is a no-op.
"""

from __future__ import annotations

import importlib.util
import os

import pytest

_REQUIRE_ENV = "ARGUS_REQUIRE_INTEGRATION_EXTRAS"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    required = os.environ.get(_REQUIRE_ENV, "").strip()
    if not required:
        return  # inert unless a CI job explicitly opts in

    missing = [mod for mod in required.split(",") if mod and importlib.util.find_spec(mod) is None]
    if not missing:
        return

    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    message = (
        f"{_REQUIRE_ENV}={required!r} but missing: {', '.join(missing)} — the "
        "gated integration tests would silently skip instead of running. Failing "
        "loudly instead of reporting a false green."
    )
    if reporter is not None:
        reporter.write_line(message, red=True, bold=True)
    session.exitstatus = 1
