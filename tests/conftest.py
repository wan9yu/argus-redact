"""Shared test fixtures and data loading for argus-redact."""

import json
from pathlib import Path

import pytest
from argus_redact._types import PatternMatch
from argus_redact.lang.shared.patterns import PATTERNS as SHARED_PATTERNS
from argus_redact.lang.zh.patterns import PATTERNS as ZH_PATTERNS

# ── Fixture data directory ──

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_examples(filename: str) -> list[dict]:
    """Load test examples from a JSON fixture file."""
    with open(FIXTURES_DIR / filename) as f:
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


def make_match(text, entity_type, start, end=None):
    """Helper to create a PatternMatch with less boilerplate."""
    if end is None:
        end = start + len(text)
    return PatternMatch(text=text, type=entity_type, start=start, end=end)
