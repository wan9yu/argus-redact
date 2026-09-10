"""HIPAA profile must redact >= default (no under-redaction)."""

from argus_redact import redact

_CORPUS = "card 4111111111111111 medical record MRN-77 passport G12345678 plate 京A12345"


def test_hipaa_profile_should_redact_at_least_as_many_entities_as_default_profile():
    out_default, key_default = redact(_CORPUS, lang="zh", mode="fast", salt=42)
    out_hipaa, key_hipaa = redact(_CORPUS, lang="zh", mode="fast", salt=42, profile="hipaa")
    # HIPAA must redact at least as many entities as the default profile.
    assert len(key_hipaa) >= len(key_default)
