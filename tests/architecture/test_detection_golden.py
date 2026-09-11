"""Per-input detection golden — the safety net for detection-changing work.

`tests/benchmark/test_detection_baseline.py` compares aggregate recall/precision
with a tolerance band, so a single newly-opened leak can hide under a
net-positive change. This test freezes the EXACT `(redacted_text, sorted key)`
that `redact(salt=42)` produces for every fixture input, so any detection change
surfaces as a per-input diff the reviewer must classify as leak-closed or
regression before regenerating the golden.

Regenerate after an INTENDED detection change (and review the diff entry by
entry): `PYTHONPATH=src python tests/architecture/test_detection_golden.py --write`.
"""

from __future__ import annotations

import json
from pathlib import Path

from argus_redact import redact

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_GOLDEN = _FIXTURES / "detection_golden.json"
_SALT = 42


def _samples() -> list[tuple[str, str, str]]:
    """(label, input_text, lang) for every list-of-dict fixture carrying `input`."""
    out: list[tuple[str, str, str]] = []
    for f in sorted(_FIXTURES.glob("*.json")):
        if f.name == _GOLDEN.name:
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(data, list):
            continue
        for i, row in enumerate(data):
            if not isinstance(row, dict):
                continue
            text = row.get("input")
            if not isinstance(text, str) or not text:
                continue
            lang = row.get("lang")
            if not isinstance(lang, str) or not lang:
                lang = "zh"
            out.append((f"{f.name}:{row.get('id', i)}", text, lang))
    return out


def _current() -> dict[str, dict]:
    result: dict[str, dict] = {}
    for label, text, lang in _samples():
        try:
            r = redact(text, lang=lang, mode="fast", salt=_SALT, report=True)
        except Exception as exc:  # a fixture that legitimately raises is pinned as such
            result[label] = {"error": type(exc).__name__}
            continue
        result[label] = {"redacted": r.redacted_text, "key": dict(sorted(r.key.items()))}
    return result


def test_detection_output_should_match_the_frozen_golden() -> None:
    assert _GOLDEN.exists(), f"missing golden {_GOLDEN}; run this file with --write"
    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    current = _current()

    changed = sorted(k for k in golden.keys() | current.keys() if golden.get(k) != current.get(k))
    assert not changed, (
        f"{len(changed)} inputs changed detection output vs the frozen golden. If this is an "
        "intended detection change, review each diff (leak-closed vs regression) then regenerate "
        "with `python tests/architecture/test_detection_golden.py --write`. Changed labels:\n  "
        + "\n  ".join(changed[:40])
    )


if __name__ == "__main__":
    _GOLDEN.write_text(
        json.dumps(_current(), ensure_ascii=False, sort_keys=True, indent=1) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {_GOLDEN} ({len(_current())} inputs)")
