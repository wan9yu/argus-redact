"""Structural + non-vacuous guard for the streaming≡batch equivalence benchmark.

Pins the design guarantee (no stream-only leak + restore round-trips, in EVERY
chunk regime) and that the corpus actually contains removable PII (so the
equivalence is not vacuously true).
"""

import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import streaming_equivalence as se  # noqa: E402


def test_streaming_equals_batch_all_regimes():
    res = se.evaluate(seeds=(1, 2))
    assert res["corpus_docs"] >= 5
    assert res["carry_window_chars"] == 256
    for label, r in res["regimes"].items():
        assert r["cases"] > 0, label
        # hard design guarantees — must hold in every chunk regime
        assert r["leak_equiv_pct"] == 100.0, (label, r)
        assert r["restore_recovers_pct"] == 100.0, (label, r)


def test_corpus_is_non_vacuous():
    # every doc must contain PII that batch actually removes — else the
    # equivalence guarantee above would be vacuously satisfied.
    for lang, text in se._CORPUS:
        _res, removed = se._batch(text, lang)
        assert removed, f"no removable PII in corpus doc: {text[:40]!r}"
