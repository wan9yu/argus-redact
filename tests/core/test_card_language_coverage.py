"""Card numbers must be redacted in every language, not just en/zh.

A payment-card PAN is the same digits regardless of the script around it. Before
v0.7.19 the only card patterns lived in `en` (credit_card) and `zh` (bank_card)
and neither was language-neutral, so a full PAN sitting in Japanese-kana or
Korean-hangul text passed through `mode="fast"` VERBATIM.

The en `credit_card` pattern (Luhn-validated, 13-19 digits) is now
`language_neutral`, so it cross-loads into every other language. The controls in
this module pin the two type labels that must NOT change: a card in en text is
still `credit_card`, a card in zh text is still `bank_card` (the zh pattern is
loaded first for zh and wins the overlap on span length / order).
"""

import pytest

from argus_redact import redact
from argus_redact.glue.redact import _LANG_PATTERNS

# Canonical Visa test PAN (Luhn-valid, never issued).
PAN = "4111-1111-1111-1111"
PAN_DIGITS = "4111111111111111"

# Every shipped language pack — the SSOT, so a 9th pack is covered the day it lands
# rather than the day someone remembers to add it to a literal list here.
_SHIPPED_LANGS = set(_LANG_PATTERNS)


class TestCardRedactedInNonEnZhScripts:
    @pytest.mark.parametrize(
        "text",
        [
            "カード番号: 4111-1111-1111-1111",  # ja, kana
            "카드번호 4111-1111-1111-1111",  # ko, hangul
        ],
    )
    def test_pan_redacted_under_auto(self, text):
        redacted, _ = redact(text, lang="auto", mode="fast", salt=42)
        assert PAN not in redacted
        assert PAN_DIGITS not in redacted.replace("-", "")

    @pytest.mark.parametrize("lang", sorted(_SHIPPED_LANGS))
    def test_pan_redacted_in_every_shipped_pack(self, lang):
        """Iterates the ACTUAL pack list, not a literal.

        A PAN is the same digits in any script, so every pack must redact one — either
        from its own pattern or via the cross-load of the `language_neutral` en pattern.
        A 9th pack would silently depend on that cross-load without anyone deciding to.
        Driving this off `_LANG_PATTERNS` turns "remember to think about the card
        pattern" into a CI failure, which is the only thing that makes the invariant
        survive a new pack landing.

        (Through v0.7.19 this also guarded a hand-maintained `neutral_except` denylist,
        which v0.7.20 deleted; this test passing UNEDITED across that deletion is the
        evidence the denylist was never load-bearing for entity correctness.)
        """
        redacted, _ = redact(f"card {PAN}", lang=[lang], mode="fast", salt=42)
        assert PAN not in redacted, f"pack {lang!r} leaks a Luhn-valid PAN in plaintext"

    def test_undashed_pan_redacted_in_kana(self):
        redacted, _ = redact(f"カード番号 {PAN_DIGITS}", lang="auto", mode="fast", salt=42)
        assert PAN_DIGITS not in redacted

    def test_ja_card_type_resolves_in_specs_ssot(self):
        # The emitted type must resolve a strategy/label/sensitivity — `lookup()`
        # is NOT language-filtered, so the en typedef serves the ja detection.
        from argus_redact.specs.registry import lookup

        _redacted, _key, types = redact(
            f"カード番号: {PAN}", lang="auto", mode="fast", salt=42, with_types=True
        )
        assert set(types.values()) == {"credit_card"}
        defs = lookup("credit_card")
        assert defs and defs[0].strategy == "mask"

    def test_realistic_strategy_produces_a_fake_card_in_kana(self):
        # Faker resolution is (type, lang) → falls back across langs, so the en
        # card faker must serve a ja-detected card (no crash, no passthrough).
        redacted, key = redact(
            f"カード番号: {PAN}",
            lang="auto",
            mode="fast",
            salt=42,
            config={"credit_card": {"strategy": "realistic"}},
        )
        assert PAN not in redacted
        assert key  # reversible: the fake maps back to the original


class TestEnZhTypeLabelsUnchanged:
    def test_en_card_still_typed_credit_card(self):
        _redacted, _key, types = redact(
            f"My card is {PAN}", lang="en", mode="fast", salt=42, with_types=True
        )
        assert set(types.values()) == {"credit_card"}

    def test_zh_card_still_typed_bank_card(self):
        _redacted, _key, types = redact(
            f"卡号 {PAN_DIGITS}", lang="zh", mode="fast", salt=42, with_types=True
        )
        assert set(types.values()) == {"bank_card"}

    def test_zh_unionpay_19_digit_still_typed_bank_card(self):
        # 19-digit UnionPay: the zh pattern spans all 19 digits, the (now neutral)
        # en pattern only 16 — the longer span must keep winning.
        pan19 = "6217000000000000000"
        _redacted, _key, types = redact(
            f"卡号 {pan19}", lang="zh", mode="fast", salt=42, with_types=True
        )
        assert set(types.values()) == {"bank_card"}

    def test_en_card_not_duplicated(self):
        redacted, key, types = redact(
            f"My card is {PAN}", lang="en", mode="fast", salt=42, with_types=True
        )
        assert len(types) == 1
        assert len(key) == 1
        assert PAN not in redacted
