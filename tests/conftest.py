"""Shared test fixtures and data loading for argus-redact."""

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
            if fullname == "argus_redact._core" or fullname.startswith(
                "argus_redact._core."
            ):
                raise ImportError("argus_redact._core blocked under mutmut")
            return None

    for _cached in [n for n in sys.modules if n == "argus_redact._core" or n.startswith("argus_redact._core.")]:
        sys.modules.pop(_cached, None)
    sys.meta_path.insert(0, _BlockArgusCoreFinder())

import pytest

from argus_redact._types import PatternMatch
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS

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
