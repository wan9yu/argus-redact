"""Tests for v0.5.8 faker tuple return: (fake, aliases).

Reserved-range fakers all share the new signature:
    (value: str, rng: random.Random) -> tuple[str, list[str]]

Person and address fakers (zh + en) fill aliases with cross-language
transliterations. All other fakers return (fake, []) — uniform shape,
empty alias for the structural-PII types where transliteration has no
semantic meaning.
"""

import argus_redact._core as _core

_SALT = _core.resolve_salt(b"test-faker-aliases-salt-32!!!!!")


def _fake(faker_name: str, value: str, type_: str) -> tuple[str, list]:
    return _core.generate_unique_fake(faker_name, value, type_, _SALT, set())


class TestPersonAliases:
    def test_zh_person_returns_pinyin_alias(self):
        fake, aliases = _fake("fake_person_reserved", "王建国", "person")
        assert fake in _core.reserved_person_names_zh()
        assert isinstance(aliases, list)
        assert aliases, f"zh person fake {fake!r} should have at least one alias"
        # The alias is a pinyin/Latin form of the fake name
        assert all(any(c.isalpha() and c.isascii() for c in a) for a in aliases)

    def test_en_person_returns_zh_alias(self):
        fake, aliases = _fake("fake_person_en_reserved", "John Smith", "person")
        assert fake in _core.reserved_person_names_en()
        assert isinstance(aliases, list)
        assert aliases, f"en person fake {fake!r} should have at least one zh alias"
        # The alias is a CJK transliteration
        assert all(any("一" <= c <= "鿿" for c in a) for a in aliases)


class TestNonPersonFakersReturnEmptyAliases:
    def test_zh_phone_empty_aliases(self):
        fake, aliases = _fake("fake_phone_reserved", "13912345678", "phone")
        assert fake.startswith("19999")
        assert aliases == []

    def test_zh_phone_landline_empty_aliases(self):
        _, aliases = _fake("fake_phone_landline_reserved", "010-12345678", "phone_landline")
        assert aliases == []

    def test_zh_id_number_empty_aliases(self):
        _, aliases = _fake("fake_id_number_reserved", "110101199001011234", "id_number")
        assert aliases == []

    def test_zh_bank_card_empty_aliases(self):
        _, aliases = _fake("fake_bank_card_reserved", "4111111111111111", "bank_card")
        assert aliases == []

    def test_zh_passport_empty_aliases(self):
        _, aliases = _fake("fake_passport_reserved", "E12345678", "passport")
        assert aliases == []

    def test_zh_license_plate_empty_aliases(self):
        _, aliases = _fake("fake_license_plate_reserved", "京A12345", "license_plate")
        assert aliases == []

    def test_en_phone_empty_aliases(self):
        _, aliases = _fake("fake_phone_en_reserved", "(415) 555-1234", "phone")
        assert aliases == []

    def test_en_ssn_empty_aliases(self):
        _, aliases = _fake("fake_ssn_en_reserved", "123-45-6789", "ssn")
        assert aliases == []

    def test_en_credit_card_empty_aliases(self):
        _, aliases = _fake("fake_credit_card_en_reserved", "4111111111111111", "credit_card")
        assert aliases == []

    def test_email_empty_aliases(self):
        _, aliases = _fake("fake_email_reserved", "user@example.com", "email")
        assert aliases == []

    def test_ip_empty_aliases(self):
        _, aliases = _fake("fake_ip_reserved", "192.168.1.1", "ip_address")
        assert aliases == []

    def test_mac_empty_aliases(self):
        _, aliases = _fake("fake_mac_reserved", "aa:bb:cc:dd:ee:ff", "mac_address")
        assert aliases == []


class TestAddressAliases:
    """v0.5.10: address fakers now emit cross-language transliteration aliases."""

    def test_zh_address_returns_en_alias_with_number(self):
        fake, aliases = _fake("fake_address_reserved", "北京市朝阳区某路1号", "address")
        assert fake.startswith("滨海市")
        assert aliases, f"zh address fake {fake!r} should have at least one en alias"
        # The fake ends in "<num>号"; the alias prepends that same number
        # in en convention (e.g. "42 Bahuang Street, Dongjiang District, Binhai City").
        for alias in aliases:
            assert alias[0].isdigit(), f"alias {alias!r} should start with the street number"
            assert any(c.isalpha() and c.isascii() for c in alias)

    def test_en_address_returns_zh_alias(self):
        fake, aliases = _fake("fake_address_en_reserved", "1234 Main St", "address")
        assert "," in fake  # Sanity: picked from the table
        assert aliases, f"en address fake {fake!r} should have at least one zh alias"
        # Alias should contain CJK characters
        assert all(any("一" <= c <= "鿿" for c in a) for a in aliases)


class TestReplaceAttachesAliasesToResult:
    def test_person_zh_alias_in_result_aliases(self):
        from argus_redact import redact_pseudonym_llm

        r = redact_pseudonym_llm("联系王建国", lang="zh", salt=b"x")
        # Find any fake whose original is 王建国 with aliases attached
        person_fakes_with_aliases = [
            f for f, orig in r.key.items()
            if orig == "王建国" and r.aliases.get(f)
        ]
        assert person_fakes_with_aliases, (
            f"expected aliases on realistic person fake; key={r.key}, aliases={r.aliases}"
        )

    def test_phone_no_aliases(self):
        from argus_redact import redact_pseudonym_llm

        r = redact_pseudonym_llm("电话13912345678", lang="zh", salt=b"x")
        phone_fakes = [f for f, orig in r.key.items() if orig == "13912345678"]
        # All phone fakes have no alias entries (skipped in unified_aliases)
        assert phone_fakes
        for f in phone_fakes:
            assert f not in r.aliases or r.aliases[f] == ()
