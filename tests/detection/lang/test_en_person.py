"""Tests for English fast-mode person detection."""

from argus_redact.lang.en.person import detect_person_names


class TestDetectPersonNames:
    def test_should_detect_known_surname_with_given_name(self):
        results = detect_person_names("Call John Smith at 555-1234")
        assert any(r.text == "John Smith" and r.type == "person" for r in results)

    def test_should_boost_confidence_when_given_in_top_list(self):
        # "John" is in GIVEN_NAMES → confidence 1.0
        results = detect_person_names("Email John Smith today.")
        smith = next(r for r in results if r.text == "John Smith")
        assert smith.confidence == 1.0

    def test_should_use_lower_confidence_when_given_not_in_top_list(self):
        # "Quincy" not in GIVEN_NAMES, but "Smith" is a known surname → 0.9
        results = detect_person_names("Quincy Smith arrived.")
        smith = next(r for r in results if "Smith" in r.text)
        assert smith.confidence == 0.9

    def test_should_skip_unknown_surname(self):
        # "Xeoplux" not in SURNAMES
        results = detect_person_names("John Xeoplux arrived.")
        assert not results

    def test_should_match_known_names_exact(self):
        results = detect_person_names("O'Brien filed the report.", known_names=["O'Brien"])
        assert any(r.text == "O'Brien" and r.confidence == 1.0 for r in results)

    def test_should_handle_middle_initial(self):
        results = detect_person_names("John A. Smith joined.")
        assert any(r.text.startswith("John") and "Smith" in r.text for r in results)

    def test_should_detect_first_middle_last(self):
        # Mary Ann Johnson — Mary in given, Ann is middle, Johnson is surname
        results = detect_person_names("Mary Ann Johnson called.")
        assert any("Johnson" in r.text for r in results)

    def test_should_return_empty_for_no_capitalized_pattern(self):
        results = detect_person_names("call them later")
        assert not results

    def test_should_not_match_lowercase_surname(self):
        # surname lowercased — shouldn't match
        results = detect_person_names("john smith called.")
        assert not results
