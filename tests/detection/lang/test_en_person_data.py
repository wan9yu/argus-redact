"""Data integrity tests for English surname + given-name lists."""


class TestSurnameData:
    def test_should_have_at_least_500_surnames(self):
        from argus_redact.lang.en.surnames import SURNAMES

        assert len(SURNAMES) >= 500

    def test_should_have_no_duplicates(self):
        from argus_redact.lang.en.surnames import SURNAMES

        assert len(set(SURNAMES)) == len(SURNAMES)

    def test_should_be_capitalized(self):
        from argus_redact.lang.en.surnames import SURNAMES

        for name in SURNAMES[:20]:  # spot-check first 20
            assert name[0].isupper(), f"Surname {name!r} not capitalized"

    def test_set_form_is_frozenset(self):
        from argus_redact.lang.en.surnames import SURNAME_SET

        assert isinstance(SURNAME_SET, frozenset)


class TestGivenNameData:
    def test_should_have_at_least_150_names(self):
        from argus_redact.lang.en.given_names import GIVEN_NAMES

        assert len(GIVEN_NAMES) >= 150

    def test_should_have_no_duplicates(self):
        from argus_redact.lang.en.given_names import GIVEN_NAMES

        assert len(set(GIVEN_NAMES)) == len(GIVEN_NAMES)

    def test_set_form_is_frozenset(self):
        from argus_redact.lang.en.given_names import GIVEN_NAME_SET

        assert isinstance(GIVEN_NAME_SET, frozenset)
