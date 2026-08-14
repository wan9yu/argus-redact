"""Checksum/structural national IDs must be redacted regardless of the document's
routed language, not only when their home language pack is requested.

Before v0.8.10, `cpf`/`cnpj` (br), `my_number` (ja) and `pan` (in) only loaded
when their own language was requested: a CPF sitting in an `en`-routed email
passed through `mode="fast"` verbatim. Each of these four is now flagged
`language_neutral` in its RON pattern data — the same characters are valid
regardless of the surrounding script, so they cross-load into every other
language pack (mirrors the pre-existing `credit_card` / CN-numeric treatment,
see `test_card_language_coverage.py`).

`aadhaar` (bare 12-digit run, no checksum) and the German `tax_id`
(format-only) are deliberately NOT flagged — too collision-prone to widen —
and stay language-scoped.
"""

import pytest

from argus_redact import redact, restore

# Known-valid examples (checksum/format verified), reused from the home-lang
# fixtures (tests/fixtures/br_patterns.json, ja_my_number.json, in_patterns.json).
CPF = "529.982.247-25"
CNPJ = "11.222.333/0001-81"
MY_NUMBER = "1234 5678 9018"
PAN = "ABCPD1234E"


class TestChecksumIdsRedactedOutsideHomeLang:
    @pytest.mark.parametrize(
        "value,type_",
        [
            (CPF, "cpf"),
            (CNPJ, "cnpj"),
            (MY_NUMBER, "my_number"),
            (PAN, "pan"),
        ],
    )
    def test_id_redacted_in_en_document(self, value, type_):
        text = f"Reference number: {value}"
        redacted, _key, types = redact(text, lang="en", mode="fast", salt=42, with_types=True)
        assert value not in redacted, f"{type_} leaked in an en-routed document"
        assert type_ in types.values(), f"{type_} was not the type assigned to the match"

    def test_all_four_detected_together_in_one_en_document(self):
        # The regression this guards: before the flag, an en-routed doc loaded
        # NONE of these four patterns, so all four passed through verbatim.
        text = (
            f"My CPF is {CPF} and our company CNPJ is {CNPJ}. "
            f"My Number is {MY_NUMBER} and my PAN card is {PAN}."
        )
        redacted, key, types = redact(text, lang="en", mode="fast", salt=42, with_types=True)
        for value in (CPF, CNPJ, MY_NUMBER, PAN):
            assert value not in redacted
        assert set(types.values()) == {"cpf", "cnpj", "my_number", "pan"}
        assert len(key) == 4

    @pytest.mark.parametrize(
        "value,type_",
        [
            (CPF, "cpf"),
            (CNPJ, "cnpj"),
            (MY_NUMBER, "my_number"),
            (PAN, "pan"),
        ],
    )
    def test_id_round_trips_when_detected_outside_home_lang(self, value, type_):
        text = f"Reference number: {value}"
        redacted, key = redact(text, lang="en", mode="fast", salt=42)
        assert value not in redacted
        restored = restore(redacted, key, guard=False)
        assert value in restored


class TestFormatOnlyIdsStayLanguageScoped:
    """aadhaar and the German tax_id are deliberately excluded from the
    language_neutral widening (no checksum / format-only — too collision-prone).
    A bare 12-digit or 11-digit run must NOT be redacted as a foreign ID just
    because it sits in an en-routed document."""

    def test_aadhaar_shaped_digits_not_redacted_as_aadhaar_in_en(self):
        aadhaar_like = "2345 6789 0123"
        text = f"Order number {aadhaar_like} confirmed."
        redacted, _key, types = redact(text, lang="en", mode="fast", salt=42, with_types=True)
        assert "aadhaar" not in types.values()
        # Digits may or may not be redacted by an unrelated en pattern; the
        # invariant under test is only that `aadhaar` itself did not fire.

    def test_de_tax_id_shaped_digits_not_redacted_as_tax_id_in_en(self):
        tax_id_like = "26 953 417 121"  # 11 digits, de tax_id shape
        text = f"Order number {tax_id_like} confirmed."
        redacted, _key, types = redact(text, lang="en", mode="fast", salt=42, with_types=True)
        assert "tax_id" not in types.values()


class TestHomeLangTypeLabelsUnchanged:
    """The flag only ADDS cross-language recall; detection within the home
    language pack must keep emitting the same type label as before."""

    @pytest.mark.parametrize(
        "lang,value,type_",
        [
            ("br", CPF, "cpf"),
            ("br", CNPJ, "cnpj"),
            ("ja", MY_NUMBER, "my_number"),
            ("in", PAN, "pan"),
        ],
    )
    def test_home_lang_still_typed_correctly(self, lang, value, type_):
        _redacted, _key, types = redact(
            f"{value}", lang=lang, mode="fast", salt=42, with_types=True
        )
        assert set(types.values()) == {type_}
