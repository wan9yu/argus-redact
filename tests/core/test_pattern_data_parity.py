"""Behavioral parity: Layer-1 detections must not change across the v0.7.1 migration.

The corpus is every built-in PII type's examples + counterexamples (from the spec
registry). We freeze the v0.7.0 detection set; every migration step must reproduce it
byte-for-byte. This is the tripwire — structural pattern-dict comparison is unusable
because `validate` callables become `validator` name strings.
"""

import json
from pathlib import Path

from argus_redact.glue.redact import _load_patterns
from argus_redact.pure.patterns import match_patterns
from argus_redact.specs.registry import list_types

FIXTURE = Path(__file__).parent / "fixtures" / "pattern_detections_v070.json"
LANGS = ["zh", "en", "ja", "ko", "de", "uk", "in", "br"]


def _corpus_for_lang(lang: str) -> list[str]:
    """All example/counterexample strings for types in this lang (+ shared)."""
    strings: list[str] = []
    for td in list_types():
        if td.lang not in (lang, "shared"):
            continue
        strings.extend(td.examples)
        strings.extend(td.counterexamples)
    seen, out = set(), []
    for s in strings:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _detect(lang: str, text: str) -> list[dict]:
    results, near = match_patterns(text, _load_patterns(lang))

    def dump(ms, kind):
        return [
            {"kind": kind, "type": m.type, "text": m.text, "start": m.start, "end": m.end}
            for m in ms
        ]

    rows = dump(results, "hit") + dump(near, "near")
    rows.sort(key=lambda r: (r["start"], r["end"], r["type"], r["kind"]))
    return rows


def _build_snapshot() -> dict:
    snap = {}
    for lang in LANGS:
        try:
            corpus = _corpus_for_lang(lang)
            snap[lang] = {text: _detect(lang, text) for text in corpus}
        except ValueError:
            continue  # lang pack not available in this env
    return snap


def test_freeze_or_compare_detection_snapshot():
    """If the fixture is absent, write it (one-time, on v0.7.0). Otherwise assert equal."""
    current = _build_snapshot()
    if not FIXTURE.exists():
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(
            json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        raise AssertionError(
            "Wrote v0.7.0 detection snapshot — re-run to compare. COMMIT the fixture."
        )
    frozen = json.loads(FIXTURE.read_text(encoding="utf-8"))
    # A lang that silently drops out of `current` must FAIL, not pass vacuously.
    missing = set(frozen) - set(current)
    assert not missing, f"frozen langs absent from this env, cannot verify parity: {missing}"
    for lang in frozen:
        assert current[lang] == frozen[lang], f"detection drift in lang={lang}"


def test_named_validator_near_miss_via_rust():
    results, near = match_patterns("ssn 000-12-3456", _load_patterns("en"))
    assert any(n.type == "ssn" for n in near)
    assert not any(r.type == "ssn" for r in results)
