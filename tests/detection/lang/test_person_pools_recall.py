"""Recall + precision guard for the grown en/zh surname pools.

The embedded person-name pools were extended for non-Anglo recall (a fairness
finding from the v0.7.9 audit). This file pins the recall GAIN — names that the
pre-growth pools missed must now detect — and guards the precision side: a
common word that shares a leading char with an ADDED surname must NOT be
redacted as a name.

Recall for accented English names is asserted through the real ``redact()``
pipeline. Detection runs on accent-folded text (``Müller`` -> ``Muller``), so
the pools store the DE-ACCENTED form; the match span maps back to the original
accented text, which is what lands in the restore key.
"""

from __future__ import annotations

from argus_redact import redact


def _redacted_names(text: str, lang: str) -> list[str]:
    """The originals redact() pulled out as person entities (the key values)."""
    _, key = redact(text, mode="fast", lang=lang, salt=42)
    return list(key.values())


# ── English recall: non-Anglo surnames + given names now detect ──


class TestEnRecall:
    def test_accented_renee_muller(self):
        # Müller (surname) + Renée (given). redact() folds the accents before the
        # pool lookup, so the de-accented pool entry matches and the span maps
        # back to the ORIGINAL accented text in the restore key.
        out, key = redact("Renée Müller", mode="fast", lang="en", salt=42)
        assert "Müller" not in out
        assert any("Müller" in v for v in key.values())

    def test_hyphen_jean_paul_sartre(self):
        # Sartre (surname) + Jean-Paul (hyphenated given token).
        assert any("Sartre" in t for t in _redacted_names("Jean-Paul Sartre", "en"))

    def test_japanese_hiro_suzuki(self):
        assert any("Suzuki" in t for t in _redacted_names("Hiro Suzuki", "en"))

    def test_italian_marco_rossi(self):
        assert any("Rossi" in t for t in _redacted_names("Marco Rossi", "en"))

    def test_south_asian_priya_sharma(self):
        assert any("Sharma" in t for t in _redacted_names("Priya Sharma", "en"))


# ── Chinese recall: added surnames now detect (with evidence context) ──
#
# Fast-mode zh requires an evidence signal (context prefix / honorific / PII
# proximity) before a candidate scores above threshold, so each positive carries
# a minimal context prefix — the same shape the golden surname sweep uses.


class TestZhRecall:
    def test_mo_yan_detects(self):
        # 莫言 (Mo Yan) — the required added-surname recall case.
        assert "莫言" in _redacted_names("我叫莫言", "zh")

    def test_teng_added_surname_detects(self):
        # 滕 — a second added surname, confirming the growth is not a one-off.
        assert any("滕" in v for v in _redacted_names("联系人滕华", "zh"))


# ── Precision guard: common words sharing a char with an added surname ──


class TestZhPrecisionGuard:
    def test_mo_ming_plain_not_a_name(self):
        # 莫名其妙 (the idiom) — 莫名 must NOT be redacted as a name in plain
        # prose. 莫 was added for 莫言, and its only common 2-char word (莫名) must
        # stay clear absent an evidence prefix.
        assert _redacted_names("这件事真让人莫名其妙", "zh") == []

    def test_mo_ming_with_context_prefix_not_a_name(self):
        # 莫 is a real surname (莫言) but 莫名(其妙) is a common idiom; a glued
        # context-prefix must NOT make 莫名 a name.
        assert _redacted_names("负责人莫名其妙地拒绝了", "zh") == []
        assert _redacted_names("客户莫名担心", "zh") == []

    def test_weng_idiom_not_a_name(self):
        # 翁 was added (e.g. 翁帆); 塞翁失马 and 富翁 must not redact as names.
        assert _redacted_names("塞翁失马焉知非福", "zh") == []
        assert _redacted_names("他是个亿万富翁", "zh") == []

    def test_chou_mou_not_a_name(self):
        # 缪 was added (e.g. 缪斯/绸缪 surname is 2nd char); 未雨绸缪 must not redact.
        assert _redacted_names("我们应该未雨绸缪", "zh") == []


class TestEnPrecisionGuard:
    def test_dropped_ferrari_not_a_surname(self):
        # Ferrari was DROPPED for FP risk (ubiquitous car brand). It must NOT be
        # in the surname pool, so "the Ferrari" never anchors a person match.
        from argus_redact.lang.en.person import detect_person_names as d

        assert d("Today the Ferrari arrived.") == []
