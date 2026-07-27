"""Documented language-pack counts must match the shipping registries.

`_LANG_PATTERNS` (which packs ship L1 regex) and `_LANG_NER_ADAPTERS` (which of
those also ship a Layer-2 NER adapter) are the SSOT. The "N languages" and
"regex-only" claims in the READMEs, the benchmark report and the demo badge were
hand-maintained and drifted; this pins them to the code.

The version-sync script deliberately does not import `argus_redact` (it must
stay free of the native `_core` import), so this parity check lives here, where
importing the package is free.
"""

import pathlib

from argus_redact.glue.redact import _LANG_NER_ADAPTERS, _LANG_PATTERNS

_ROOT = pathlib.Path(__file__).resolve().parents[2]

_PACK_COUNT = len(_LANG_PATTERNS)
_PACK_CODES = "/".join(_LANG_PATTERNS)
_REGEX_ONLY = sorted(set(_LANG_PATTERNS) - set(_LANG_NER_ADAPTERS))


def _text(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


def test_documented_pack_count_matches_registry():
    claims = [
        ("README.md", f"{_PACK_COUNT} langs"),
        ("README.zh.md", f"{_PACK_COUNT} 种语言"),
        ("README.zh.md", f"{_PACK_COUNT} 语言跨层 hints"),
        ("docs/benchmark-report.md", f"{_PACK_COUNT} languages"),
        ("demo/js/strings.js", f"{_PACK_COUNT} 种语言"),
    ]
    missing = [f"{rel}: {claim!r}" for rel, claim in claims if claim not in _text(rel)]
    assert not missing, (
        f"_LANG_PATTERNS ships {_PACK_COUNT} packs; these surfaces claim otherwise "
        f"(update the doc, or the claim list here if a surface was reworded): {missing}"
    )


def test_documented_pack_codes_match_registry():
    for rel in ("README.md", "README.zh.md"):
        assert _PACK_CODES in _text(rel), (
            f"{rel} does not spell the shipped pack codes as {_PACK_CODES!r}"
        )


def test_regex_only_packs_are_documented_as_such():
    assert _REGEX_ONLY == ["br"], (
        "the set of packs with no NER adapter changed; update the README sentences "
        f"and this expectation together (now: {_REGEX_ONLY})"
    )
    assert len(_LANG_NER_ADAPTERS) == _PACK_COUNT - len(_REGEX_ONLY)
    only = _REGEX_ONLY[0]
    assert f"`{only}` is regex-only" in _text("README.md")
    assert f"`{only}` 只有 regex" in _text("README.zh.md")
