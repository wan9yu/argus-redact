"""Parity gate for the v0.7.7 jwt/organization/school validator port.

Before v0.7.7 these 3 types ran their regex via Python ``re`` and their
validator via a Python ``validate`` callback (re-attached by
``lang/_loader.py:_DEFERRED``). After the port they carry a Rust ``validator``
named in the RON and NO Python ``validate``, so ``match_patterns`` routes them
to ``_core.match_patterns`` — running BOTH the regex (fancy_regex) and the
validator entirely in Rust.

This test freezes the pre-port detected spans/types/confidence as the expected
spec and asserts the live full ``match_patterns`` path (now Rust) reproduces
them byte-for-byte over a corpus of valid + invalid + embedded-in-text strings.
A pass proves cross-engine regex parity (Python ``re`` ⇄ fancy_regex) AND
validator parity (accept/reject identical) for these 3 types.

The expected values below were captured from the pre-port pipeline (the path
re-attaching the Python validators) — the same behavior the T1 golden froze for
its jwt/org/school cases.
"""

from __future__ import annotations

import pytest

from argus_redact.glue.redact import _load_patterns
from argus_redact.pure.patterns import match_patterns

# A real, validator-accepted JWT: header {"alg":"HS256"} . payload {"sub":"123"} . sig
_JWT_VALID = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
# 3 segments, header {"typ":"JWT"} → object but lacks "alg" → validator rejects.
_JWT_NOALG = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjMifQ.sig"
# 2 segments → the regex itself needs 3, so it never matches at all.
_JWT_2SEG = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ"
# NON-CANONICAL header: base64url('{"alg":"none"}') is canonically
# "eyJhbGciOiJub25lIn0"; this flips the last char to '1', which carries non-zero
# trailing bits (len%4==3). Pre-port Python `base64.urlsafe_b64decode` (binascii)
# is LENIENT → decodes to {"alg":"none"} → object with "alg" → ACCEPTS → REDACTED.
# The default strict URL_SAFE engine returned InvalidLastSymbol → REJECTED → the
# JWT LEAKED (near-miss, dropped in fast mode). The lenient JWT_B64 engine in
# validators.rs restores parity: this is now a clean result, matching pre-port.
_JWT_NONCANON = "eyJhbGciOiJub25lIn1.eyJzdWIiOiIxMjMifQ.sig"
# A JSON-array header is unreachable: the regex anchors every segment to ``eyJ``
# (= base64url of ``{"``), so a matched header always decodes to an object-ish
# start. The array-vs-object distinction is covered by the Rust unit tests
# (validators.rs::jwt_validator); here we exercise only regex-reachable inputs.


def _detect(text: str, lang: str):
    """Run the full match_patterns path; return (results, near_misses) as
    comparable (text, type, start, end, confidence) tuples."""
    results, near_misses = match_patterns(text, _load_patterns(lang))

    def to_tup(ms):
        return sorted((m.text, m.type, m.start, m.end, m.confidence) for m in ms)

    return to_tup(results), to_tup(near_misses)


def _types(results):
    return {t for _, t, _, _, _ in results}


# ── (label, text, lang, expected_results, expected_near_misses) ──────────────
# expected_* are restricted to the jwt/organization/school types via the
# assertions below (other builtin patterns may also fire on a given text; we
# only gate the 3 ported types here). Each tuple: (text, type, start, end, conf).
# NOTE: the org/school spans below are NOT the trimmed name — the regex's group
# ``[一-鿿]{2,12}`` matches CJK greedily, so a leading particle (我/在/
# 他就职于/我毕业于/我考入) is captured INTO the span. The validator nonetheless
# accepts, because ``has_name_before_suffix`` strips that leading noise before
# the suffix check. This frozen capture-the-particle behavior is exactly what the
# T1 golden pins; the Rust port must reproduce it byte-for-byte.
CASES = [
    # jwt: valid → detected as a clean result (confidence 1.0)
    ("jwt_valid", f"token is {_JWT_VALID}", "en", [(_JWT_VALID, "jwt", 9, 52, 1.0)], []),
    # jwt: header object but no "alg" → near-miss (confidence 0.3), not a result
    ("jwt_noalg", f"token is {_JWT_NOALG}", "en", [], [(_JWT_NOALG, "jwt", 9, 50, 0.3)]),
    # jwt: 2 segments → regex requires 3 → no match at all (no result, no near-miss)
    ("jwt_2seg", f"token is {_JWT_2SEG}", "en", [], []),
    # jwt: NON-CANONICAL header (trailing bits set) → pre-port Python's lenient
    # base64 ACCEPTED → clean result at 1.0 (no near-miss). PARITY-RESTORING: under
    # the old strict engine this was a 0.3 near-miss that leaked in fast mode.
    ("jwt_noncanon", f"token is {_JWT_NONCANON}", "en", [(_JWT_NONCANON, "jwt", 9, 51, 1.0)], []),
    # organization: valid → detected; span includes the greedily-captured "我在"
    (
        "org_valid",
        "我在阿里巴巴有限公司上班",
        "zh",
        [("我在阿里巴巴有限公司", "organization", 0, 10, 1.0)],
        [],
    ),
    # organization near-miss: "这是公司" matched whole; after stripping "这是"
    # nothing precedes "公司" → validator rejects → near-miss
    ("org_nearmiss", "这是公司", "zh", [], [("这是公司", "organization", 0, 4, 0.3)]),
    # organization embedded with a verb prefix → detected, prefix in span
    (
        "org_verbprefix",
        "他就职于腾讯科技有限公司",
        "zh",
        [("他就职于腾讯科技有限公司", "organization", 0, 12, 1.0)],
        [],
    ),
    # school: valid → detected; span includes "我毕业于"
    ("school_valid", "我毕业于北京大学", "zh", [("我毕业于北京大学", "school", 0, 8, 1.0)], []),
    # school near-miss: "这是大学" → after stripping "这是", nothing before "大学"
    ("school_nearmiss", "这是大学", "zh", [], [("这是大学", "school", 0, 4, 0.3)]),
    # school embedded → detected; "我考入清华大学" (trailing 读书 not CJK-captured)
    (
        "school_verbprefix",
        "我考入清华大学读书",
        "zh",
        [("我考入清华大学", "school", 0, 7, 1.0)],
        [],
    ),
]

_PORTED_TYPES = {"jwt", "organization", "school"}
_IDS = [c[0] for c in CASES]


@pytest.mark.parametrize("label,text,lang,exp_results,exp_near", CASES, ids=_IDS)
def test_deferred_validator_parity(label, text, lang, exp_results, exp_near):
    """The Rust regex+validator path reproduces the pre-port detection exactly."""
    results, near_misses = _detect(text, lang)
    # Filter to the 3 ported types: other builtin patterns may co-fire on the
    # same text, but this gate is specifically about jwt/organization/school.
    got_results = sorted(r for r in results if r[1] in _PORTED_TYPES)
    got_near = sorted(n for n in near_misses if n[1] in _PORTED_TYPES)
    assert got_results == sorted(exp_results), f"results drift for {label!r}"
    assert got_near == sorted(exp_near), f"near-miss drift for {label!r}"


def test_jwt_routes_through_rust_not_python():
    """Sanity: the loaded jwt/org/school patterns carry a Rust `validator` and
    NO Python `validate` callback (so match_patterns dispatches them to Rust)."""
    for lang in ("en", "zh"):
        for p in _load_patterns(lang):
            if p.get("type") in _PORTED_TYPES:
                assert p.get("validator") == p["type"], f"{p['type']} must name a Rust validator"
                assert "validate" not in p, f"{p['type']} must not carry a Python validate callback"
