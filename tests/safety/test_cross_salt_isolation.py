"""Cross-salt restore isolation.

The per-message salt isolates **pseudonymized** values: pseudonym codes
(`P-NNNNN`, faker/realistic values) are salt-derived, so a key produced under
salt A cannot reconstruct a pseudonymized value redacted under salt B.

KNOWN LIMITATION (documented; a dedicated isolation design is deferred to a later
release). **Masked** values (e.g. a phone partial-masked to ``138****8000``) use
deterministic, content-derived, salt-INDEPENDENT codes. Two redactions of the
same masked value under different salts therefore produce the *same* code, so a
key from one redaction can reconstruct that value in the other. The exposure is
narrow: it only reveals a value the holder of key A already possesses (a
cross-message *linkage* of already-known values, not new PII), and the mask is
partially self-revealing by design. A salt-independent code is also the only form
that survives the LLM round-trip (redact -> LLM -> restore the LLM's fresh reply),
so the fix (LLM-compatible salt-keyed codes for masked strategies) is a core
output-format change designed separately, not shoehorned into v0.7.9. The
``xfail`` below pins the desired property and will surface (as ``xpass``) once
that lands. See docs/security-model.md for the scoped guarantee.
"""

import pytest

from argus_redact import redact, restore


def test_pseudonym_cross_salt_isolation_holds():
    """Salt isolates pseudonymized values: key A cannot restore the name under salt B."""
    text = "我叫张三"
    red_a, key_a = redact(text, lang="zh", mode="fast", salt=11111)
    red_b, key_b = redact(text, lang="zh", mode="fast", salt=22222)

    # Pseudonym codes are salt-derived -> the two redactions differ.
    assert red_a != red_b
    # A salt-A key must NOT reconstruct the name redacted under salt B.
    assert "张三" not in restore(red_b, key_a)
    # Sanity: each key restores its own redaction exactly.
    assert restore(red_a, key_a) == text
    assert restore(red_b, key_b) == text


@pytest.mark.xfail(
    reason="known limitation: masked codes are salt-independent; LLM-roundtrip-"
    "compatible salt-keyed codes for masked strategies are a deferred, separately-"
    "designed output-format change",
    strict=False,
)
def test_masked_cross_salt_isolation_known_limitation():
    """DESIRED (not yet held): a salt-A key must not reconstruct a MASKED value
    redacted under salt B."""
    text = "电话13800138000"
    _red_a, key_a = redact(text, lang="zh", mode="fast", salt=11111)
    red_b, _key_b = redact(text, lang="zh", mode="fast", salt=22222)
    assert "13800138000" not in restore(red_b, key_a)
