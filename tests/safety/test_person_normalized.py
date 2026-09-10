"""Person names obfuscated via fullwidth/confusable must be detected after normalization."""

from argus_redact import redact


def test_redact_should_detect_the_name_when_it_uses_fullwidth_characters():
    # Ｊohn (fullwidth J U+FF2A) Smith — normalization folds to ASCII so person detection fires.
    out, key = redact("Contact Ｊohn Smith today", lang="en", mode="fast", salt=42)
    assert len(key) >= 1
    assert "John Smith" not in out


def test_redact_should_detect_the_name_when_it_is_plain_ascii():
    # Sanity: a plain ASCII name still detects (no regression).
    out, key = redact("Contact John Smith today", lang="en", mode="fast", salt=42)
    assert len(key) >= 1
