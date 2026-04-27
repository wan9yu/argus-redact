"""Tests for v0.5.8 faker tuple return: (fake, aliases).

Reserved-range fakers all share the new signature:
    (value: str, rng: random.Random) -> tuple[str, list[str]]

Person fakers (zh + en) fill aliases with cross-language transliterations.
All other fakers return (fake, []) — uniform shape, empty alias for the
non-name types where transliteration has no semantic meaning.
"""

import random

from argus_redact.specs.fakers_en_reserved import (
    RESERVED_PERSON_NAMES_EN,
    fake_address_en_reserved,
    fake_credit_card_en_reserved,
    fake_person_en_reserved,
    fake_phone_en_reserved,
    fake_ssn_en_reserved,
)
from argus_redact.specs.fakers_shared_reserved import (
    fake_email_reserved,
    fake_ip_reserved,
    fake_mac_reserved,
)
from argus_redact.specs.fakers_zh_reserved import (
    RESERVED_PERSON_NAMES,
    fake_address_reserved,
    fake_bank_card_reserved,
    fake_id_number_reserved,
    fake_license_plate_reserved,
    fake_passport_reserved,
    fake_person_reserved,
    fake_phone_landline_reserved,
    fake_phone_reserved,
)


def _rng():
    return random.Random(42)


class TestPersonAliases:
    def test_zh_person_returns_pinyin_alias(self):
        fake, aliases = fake_person_reserved("王建国", _rng())
        assert fake in RESERVED_PERSON_NAMES
        assert isinstance(aliases, list)
        assert aliases, f"zh person fake {fake!r} should have at least one alias"
        # The alias is a pinyin/Latin form of the fake name
        assert all(any(c.isalpha() and c.isascii() for c in a) for a in aliases)

    def test_en_person_returns_zh_alias(self):
        fake, aliases = fake_person_en_reserved("John Smith", _rng())
        assert fake in RESERVED_PERSON_NAMES_EN
        assert isinstance(aliases, list)
        assert aliases, f"en person fake {fake!r} should have at least one zh alias"
        # The alias is a CJK transliteration
        assert all(any("一" <= c <= "鿿" for c in a) for a in aliases)


class TestNonPersonFakersReturnEmptyAliases:
    def test_zh_phone_empty_aliases(self):
        fake, aliases = fake_phone_reserved("13912345678", _rng())
        assert fake.startswith("19999")
        assert aliases == []

    def test_zh_phone_landline_empty_aliases(self):
        _, aliases = fake_phone_landline_reserved("010-12345678", _rng())
        assert aliases == []

    def test_zh_id_number_empty_aliases(self):
        _, aliases = fake_id_number_reserved("110101199001011234", _rng())
        assert aliases == []

    def test_zh_bank_card_empty_aliases(self):
        _, aliases = fake_bank_card_reserved("4111111111111111", _rng())
        assert aliases == []

    def test_zh_passport_empty_aliases(self):
        _, aliases = fake_passport_reserved("E12345678", _rng())
        assert aliases == []

    def test_zh_license_plate_empty_aliases(self):
        _, aliases = fake_license_plate_reserved("京A12345", _rng())
        assert aliases == []

    def test_zh_address_empty_aliases(self):
        # Address aliases out of scope for v0.5.8 (address transliteration is
        # noisy — defer to v0.6+).
        _, aliases = fake_address_reserved("北京市", _rng())
        assert aliases == []

    def test_en_phone_empty_aliases(self):
        _, aliases = fake_phone_en_reserved("(415) 555-1234", _rng())
        assert aliases == []

    def test_en_ssn_empty_aliases(self):
        _, aliases = fake_ssn_en_reserved("123-45-6789", _rng())
        assert aliases == []

    def test_en_credit_card_empty_aliases(self):
        _, aliases = fake_credit_card_en_reserved("4111111111111111", _rng())
        assert aliases == []

    def test_en_address_empty_aliases(self):
        _, aliases = fake_address_en_reserved("1234 Main St", _rng())
        assert aliases == []

    def test_email_empty_aliases(self):
        _, aliases = fake_email_reserved("user@example.com", _rng())
        assert aliases == []

    def test_ip_empty_aliases(self):
        _, aliases = fake_ip_reserved("192.168.1.1", _rng())
        assert aliases == []

    def test_mac_empty_aliases(self):
        _, aliases = fake_mac_reserved("aa:bb:cc:dd:ee:ff", _rng())
        assert aliases == []


class TestReplaceAttachesAliasesToKeyEntries:
    def test_person_zh_alias_in_key_entries(self):
        from argus_redact import redact_pseudonym_llm

        r = redact_pseudonym_llm("联系王建国", lang="zh", salt=b"x")
        # Find the realistic-pass entry for 王建国
        person_entries = [e for e in r.key_entries.values() if e.original == "王建国"]
        assert person_entries, f"missing person entry: {dict(r.key_entries)}"
        # At least one entry has aliases (the realistic fake; audit placeholder has none)
        assert any(e.aliases for e in person_entries), (
            f"expected aliases on realistic person fake, got {[(e.original, e.aliases) for e in person_entries]}"
        )

    def test_phone_no_aliases(self):
        from argus_redact import redact_pseudonym_llm

        r = redact_pseudonym_llm("电话13912345678", lang="zh", salt=b"x")
        phone_entries = [e for e in r.key_entries.values() if e.original == "13912345678"]
        # All phone fakes have empty aliases
        assert phone_entries
        assert all(e.aliases == () for e in phone_entries)
