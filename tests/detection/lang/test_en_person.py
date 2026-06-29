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

    def test_should_suppress_uncorroborated_common_word_pair(self):
        # "Central Park" — "Park" is a pooled surname, but the leading token
        # "Central" IS a common / place word, so the pool-independent name-like
        # signal does NOT fire and, with no title / nearby PII, the bare pair
        # scores below threshold and is SUPPRESSED (the evidence gate; left to L2
        # NER). This is the precision guard — it must not over-redact place pairs.
        results = detect_person_names("Central Park is large.")
        assert not results

    def test_should_emit_name_like_bare_surname(self):
        # "Quincy" is NOT in the SSA given-name pool, but it is name-like (not a
        # common word), so the pool-independent signal corroborates the bare pair
        # → emitted at 0.8 with no title / PII. This recovers real Given+Surname
        # names the Anglo-biased pool would otherwise drop (fairness fix).
        results = detect_person_names("Quincy Smith arrived.")
        assert any(r.text == "Quincy Smith" and r.confidence == 0.8 for r in results)

    def test_should_emit_bare_surname_with_title(self):
        # A title immediately before the surname corroborates the bare pair, so it
        # is emitted (base 0.3 + title 0.6).
        results = detect_person_names("Dr. Smith arrived.")
        assert any("Smith" in r.text for r in results)

    def test_should_emit_bare_surname_near_pii(self):
        # PII proximity corroborates a bare pair. "Quincy Smith" alone is
        # suppressed; an adjacent phone entity lifts it above threshold.
        from argus_redact._types import PatternMatch

        phone = PatternMatch(text="4155551234", type="phone", start=14, end=24)
        results = detect_person_names("Quincy Smith, 4155551234", pii_entities=[phone])
        assert any("Quincy Smith" in r.text for r in results)

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
