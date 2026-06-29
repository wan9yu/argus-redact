"""Behavioral parity for detection-side normalization across the v0.7.2 port.

The existing detection-parity test bypasses normalize (it calls match_patterns
directly). This freezes v0.7.1 output of normalize_text (str + offset_map) and
detect_languages over a tricky-Unicode corpus; the Rust port must reproduce it.
"""

import json
from pathlib import Path

from argus_redact.pure.lang_detect import detect_languages
from argus_redact.pure.normalize import normalize_text

FIXTURE = Path(__file__).parent / "fixtures" / "normalize_v071.json"

# Corpus: confusables, NFKC (fullwidth/superscript/ligature/compat), Chinese-digit
# sequences, invisible-char injection, mixed scripts, ASCII, empty.
NORMALIZE_CORPUS = [
    "",
    "plain ascii text",
    "Кириллица аеор",  # Cyrillic confusables
    "ѕсаm еmаіl",  # Cyrillic-spoofed latin
    "ｆｕｌｌｗｉｄｔｈ １２３４５６７８９０",  # fullwidth (NFKC)
    "x²³ super",  # superscripts (NFKC)
    "ﬁle ﬂag",  # ligatures (NFKC)
    "一三八零零一三八零零零",  # Chinese-digit phone (11)
    "电话一三八 零零一 三八零零零",  # Chinese digits with separators
    "三月三日",  # short CN — must NOT convert
    "一二三٤五六七",  # Arabic-Indic digit in a CN run (isdigit, not ascii)
    "zero​width‍join",  # invisible chars
    "ＡＢＣ-１２３-４５６７",  # fullwidth alnum + digits
    "日本語ですよ",  # ja
    "한국어입니다",  # ko
    "中文测试",  # zh
    "mixed 中文 and English",  # mixed
    "café münchen",  # precomposed accents (é, ü) — fold to ASCII
    "áé",  # decomposed combining acute (NFD) — fold to ASCII
    "José",  # precomposed é at token end — folds to "Jose"
]
LANG_CORPUS = [
    "",
    "hello world",
    "ab",
    "中文",
    "日本語",
    "한국어",
    "中文 with english",
    "日本語 and 中文",
    "한국어 中文",
    "ＡＢＣ",
    "123 456",
    "こんにちは",
    "カタカナ",
    "こんにちは 中文",  # hiragana/katakana → exercise the ja path
]


def _norm(s: str):
    out, omap = normalize_text(s)
    return [out, omap]  # omap is list[int] | None


def _build():
    return {
        "normalize": {s: _norm(s) for s in NORMALIZE_CORPUS},
        "detect": {s: detect_languages(s) for s in LANG_CORPUS},
    }


def test_normalize_and_detect_parity():
    current = _build()
    if not FIXTURE.exists():
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(
            json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        raise AssertionError(
            "Wrote v0.7.1 normalize snapshot — re-run to compare. COMMIT the fixture."
        )
    frozen = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert current == frozen, "normalize/detect drift vs frozen v0.7.1 output"
