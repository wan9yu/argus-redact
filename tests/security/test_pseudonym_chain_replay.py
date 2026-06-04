"""KDF chain replay vectors — v1.0 freeze candidate (v0.6.10).

The crypto path (SHAKE-256 + HMAC over salt + value + entity_type) is the
security root: it derives pseudonyms deterministically so the same input
always produces the same output. Any accidental change to byte layout, hash
inputs, or stream consumption silently changes derivations across releases,
which breaks every downstream cache and may re-identify previously-redacted
data.

These vectors were generated from v0.6.10 source. A future major-version
bump that intentionally changes the chain should regenerate this dict and
note it in the migration doc.

Each vector is a tuple of:

    (salt, input_text, target_value, lang, entity_type, expected_placeholder)

``input_text`` carries the value (sometimes with surrounding context the
detector needs to fire). The test looks up ``target_value`` in the result
``key`` dict and asserts the deterministic placeholder still matches.
"""
import pytest

from argus_redact import redact_pseudonym_llm

# (salt, input_text, target_value, lang, entity_type, expected_placeholder)
REPLAY_VECTORS = [
    (b"a" * 32, "客户黄芳来访", "黄芳", "zh", "person", "P-24813"),
    (b"\x00" * 32, "13912345678", "13912345678", "zh", "phone", "PHON-61048"),
    (b"email-replay-salt!!!!!!!!!!!!!!!", "alice@acme.io", "alice@acme.io", "en", "email", "EMAI-26776"),
    (b"deterministic-salt!!!!!!!!!!!!!!", "John Smith", "John Smith", "en", "person", "P-07850"),
    (b"compound-surname!!!!!!!!!!!!!!!!", "客户欧阳锋来访", "欧阳锋", "zh", "person", "P-07038"),
    (b"id-number-test!!!!!!!!!!!!!!!!!!", "110101199003074610", "110101199003074610", "zh", "id_number", "ID-39097"),
    (b"license-plate!!!!!!!!!!!!!!!!!!!", "京A12345", "京A12345", "zh", "license_plate", "PLATE-15042"),
    (b"passport-salt!!!!!!!!!!!!!!!!!!!", "护照E12345678号", "E12345678", "zh", "passport", "PASS-20713"),
    (b"bank-card-salt!!!!!!!!!!!!!!!!!!", "6217001234567890", "6217001234567890", "zh", "bank_card", "BANK-59244"),
    (b"address-salt!!!!!!!!!!!!!!!!!!!!", "北京市朝阳区建国路100号", "北京市朝阳区建国路100号", "zh", "address", "ADDR-25695"),
    (b"compound-3char!!!!!!!!!!!!!!!!!!", "客户司马懿来访", "司马懿", "zh", "person", "P-07038"),
    (b"edge-mid-initial!!!!!!!!!!!!!!!!", "John F. Smith", "John F. Smith", "en", "person", "P-67822"),
    # v0.6.11 edge vectors: full-FF salt (formerly OverflowError) + 10KB single-entity input (locks HMAC-input-length stability)
    (b"\xff" * 32, "user@acme.io", "user@acme.io", "en", "email", "EMAI-54564"),
    (b"long-input-salt-32-byte-padding!", "a" * 9992 + "@acme.io", "a" * 9992 + "@acme.io", "en", "email", "EMAI-62284"),
]


@pytest.mark.parametrize(
    "salt,input_text,target_value,lang,etype,expected",
    REPLAY_VECTORS,
    ids=[f"{etype}-{lang}-{i}" for i, (_, _, _, lang, etype, _) in enumerate(REPLAY_VECTORS)],
)
def test_kdf_chain_replay(salt, input_text, target_value, lang, etype, expected):
    """The same (salt, input, lang) must produce the same placeholder across
    the v0.6.10 -> v1.0 lifecycle. Divergence here = cryptographic chain
    change requiring a major-version bump."""
    result = redact_pseudonym_llm(input_text, salt=salt, lang=lang)
    inverted = {v: k for k, v in result.key.items()}
    actual = inverted.get(target_value)
    assert actual == expected, (
        f"KDF derivation changed for ({target_value!r}, {lang}, {etype}).\n"
        f"  expected: {expected!r}\n"
        f"  actual:   {actual!r}\n"
        f"  full key: {result.key}\n"
        f"If intentional: this is a major version (v2.0+) change - all "
        f"downstream caches need rebuilding."
    )


def test_full_ff_salt_no_longer_overflows():
    """v0.6.11: full-FF salt (32 bytes 0xFF) was OverflowError before — must work now.

    Root cause: pseudo_seed_int packs first 8 bytes BE → 0xFFFFFFFFFFFFFFFF
    (max u64). When _type_seed_offset (up to 9999) was added, the sum
    exceeded u64 and the Rust _core.PseudonymGenerator's PyO3 conversion
    raised. Fix: modular arithmetic on the sum keeps it in u64.
    """
    from argus_redact import redact_pseudonym_llm
    result = redact_pseudonym_llm("user@acme.io", salt=b"\xff" * 32, lang="en")
    assert result.key, "should produce a non-empty key dict"
    # Confirm the entity was detected and got a placeholder
    found = any(v == "user@acme.io" for v in result.key.values())
    assert found, "user@acme.io should appear in the key dict"
