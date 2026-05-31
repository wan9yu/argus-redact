"""Pin README ```python``` code blocks marked with <!-- pin --> to actual runtime output.

Mechanism: every block immediately preceded by `<!-- pin -->` in README.md or
README.zh.md is exec'd in an isolated namespace; stdout is compared against the
block's `# expected:` comment lines (in order). Mismatch → fail with diff.

This is the long-term guard for the "every claim a stranger reads must
reproduce" contract introduced in v0.6.6.
"""
from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parents[1]
_README_PATHS = [_REPO_ROOT / "README.md", _REPO_ROOT / "README.zh.md"]

_PIN_BLOCK = re.compile(
    r"<!--\s*pin\s*-->\s*\n```python\n(.*?)\n```",
    re.DOTALL,
)
_EXPECTED = re.compile(r"^\s*#\s*expected:\s*(.*?)\s*$", re.MULTILINE)


def _extract_pinned(md_path: Path) -> list[tuple[str, str, int]]:
    """Return list of (code, file_label, line_in_md)."""
    text = md_path.read_text(encoding="utf-8")
    out: list[tuple[str, str, int]] = []
    for m in _PIN_BLOCK.finditer(text):
        line = text[: m.start()].count("\n") + 1
        out.append((m.group(1), md_path.name, line))
    return out


def _run_block(code: str) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(code, {"__name__": "__doctest_pinned__"})
    return buf.getvalue()


def _actual_lines(stdout: str) -> list[str]:
    return [ln for ln in stdout.splitlines() if ln.strip()]


def _expected_lines(code: str) -> list[str]:
    return [m.group(1) for m in _EXPECTED.finditer(code)]


_PARAMS = [
    (code, label, line)
    for md in _README_PATHS
    for code, label, line in _extract_pinned(md)
]


@pytest.mark.parametrize(
    "code,label,line",
    _PARAMS,
    ids=[f"{label}:L{line}" for (_, label, line) in _PARAMS],
)
def test_pinned_readme_example(code, label, line):
    actual = _actual_lines(_run_block(code))
    expected = _expected_lines(code)
    assert actual == expected, (
        f"\n{label}:L{line} pinned example mismatch\n"
        f"expected:\n  " + "\n  ".join(expected) + "\n"
        "actual:\n  " + "\n  ".join(actual)
    )
