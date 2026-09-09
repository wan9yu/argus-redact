"""Shared test fixtures and data loading for argus-redact."""

import importlib.util
import json
import os
import sys
from pathlib import Path

# ── mutmut: block argus_redact._core (PyO3 .so) BEFORE any package import ──
# mutmut runs every mutant in an os.fork()-ed child. If the parent already
# imported _core during baseline / clean-test phases the child inherits
# stale PyO3 / Tokio runtime state and segfaults the moment any Rust
# function is called. Blocking the .so for the whole mutmut run keeps the
# Python-only fallback path active (every consumer wraps the import in
# try/except ImportError) and the test suite still passes end-to-end.
# Gated on MUTANT_UNDER_TEST so it's a no-op outside mutmut.
if os.environ.get("MUTANT_UNDER_TEST"):
    import importlib.abc

    class _BlockArgusCoreFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path, target=None):
            if fullname == "argus_redact._core" or fullname.startswith("argus_redact._core."):
                raise ImportError("argus_redact._core blocked under mutmut")
            return None

    for _cached in [
        n for n in sys.modules if n == "argus_redact._core" or n.startswith("argus_redact._core.")
    ]:
        sys.modules.pop(_cached, None)
    sys.meta_path.insert(0, _BlockArgusCoreFinder())

import pytest

from argus_redact._types import PatternMatch
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS

# ── False-green meta-guard for the extras-installing CI jobs ──
#
# The server, MCP, and Presidio suites are gated behind ``skipif(not HAS_X)`` /
# ``pytest.mark.slow`` (see tests/integration/test_server*.py, test_mcp*.py,
# test_presidio.py) so the base ``test`` job's venv (``.[dev]``) never has to
# carry starlette/mcp/presidio-analyzer. That gating is exactly how a false green
# can happen: a CI job installs the extras and runs the suite, but if the install
# silently fails (or a packaging change drops the dependency), every gated test
# just skips again and pytest still exits 0 — the job looks green while testing
# nothing.
#
# The extras-installing CI jobs set ``ARGUS_REQUIRE_INTEGRATION_EXTRAS`` to a
# comma-separated list of the modules they expect to be importable (e.g.
# ``starlette,mcp`` or ``presidio_analyzer``). When set, this hook fails the run
# loudly if any of them are missing. Unset (the default everywhere else — local
# dev, the base ``test`` job), it is a no-op. It lives in this rootmost conftest
# so it applies to any opted-in session regardless of which directory it collects.

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


# ── Fixture data directory ──

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_examples(filename: str) -> list[dict]:
    """Load test examples from a JSON fixture file."""
    with open(FIXTURES_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


def parametrize_examples(filename: str):
    """Create pytest parametrize decorator from a JSON fixture file.

    Each example must have an 'id' field (used as test ID)
    and a 'description' field (shown on failure).
    """
    examples = load_examples(filename)
    return pytest.mark.parametrize(
        "example",
        examples,
        ids=[e["id"] for e in examples],
    )


# ── Pattern fixtures ──


@pytest.fixture
def zh_patterns():
    """Chinese regex patterns + shared patterns."""
    return ZH_PATTERNS + SHARED_PATTERNS


@pytest.fixture
def shared_patterns():
    """Shared (cross-language) patterns only."""
    return list(SHARED_PATTERNS)


# ── Key fixtures ──


@pytest.fixture
def sample_key():
    """A typical key mapping pseudonyms to originals."""
    return {
        "P-037": "王五",
        "P-012": "张三",
        "[咖啡店]": "星巴克",
        "[某公司]": "阿里",
        "[手机号已脱敏]": "13812345678",
    }


# ── Helpers ──


def assert_pattern_match(results: list[PatternMatch], example: dict, pii_type: str | None = None):
    """Shared assertion logic for pattern-matching test classes.

    If pii_type is None, reads from example["type"].
    """
    t = pii_type or example["type"]
    typed = [r for r in results if r.type == t]

    if example["should_match"]:
        assert len(typed) >= 1, f"Expected match: {example['description']}"
        if "expected_text" in example:
            assert any(r.text == example["expected_text"] for r in typed)
    else:
        assert len(typed) == 0, f"Should NOT match: {example['description']}"


def make_match(text, entity_type, start, end=None):
    """Helper to create a PatternMatch with less boilerplate."""
    if end is None:
        end = start + len(text)
    return PatternMatch(text=text, type=entity_type, start=start, end=end)
