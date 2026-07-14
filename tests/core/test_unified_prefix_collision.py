"""R1: generators sharing a prefix must not mint the same code for different originals."""

from argus_redact import redact
from argus_redact.pure.restore import restore


def test_unified_prefix_no_cross_generator_collision():
    # Person (pseudo_gen) + phone-as-remove (a type_gen) both under prefix "U".
    # Pre-fix (salt=63467): both minted U-87217, so the key lost 王明.
    red, key = redact(
        "我叫王明，电话13800138000",
        salt=63467,
        unified_prefix="U",
        config={"person": {"strategy": "pseudonym"}, "phone": {"strategy": "remove"}},
    )
    # No code maps two different originals:
    assert len(set(key.values())) == len(key), f"collision in key: {key}"
    # Round-trip is lossless:
    assert restore(red, dict(key), guard=False) == "我叫王明，电话13800138000"


def test_passport_us_passport_share_prefix_no_collision():
    # passport (zh) + us_passport (en) both default to prefix PASS. lang=en alone
    # never triggers the zh "passport" type, so both must be loaded together to
    # actually exercise the cross-generator collision.
    # Pre-fix (salt=165221): both minted PASS-19209, so the key lost E12345678
    # (only A12345678, inserted second, survived).
    red, key = redact(
        "护照E12345678 passport number A12345678",
        lang=["zh", "en"],
        salt=165221,
        config={"passport": {"strategy": "remove"}, "us_passport": {"strategy": "remove"}},
    )
    # No code maps two different originals:
    assert len(set(key.values())) == len(key), f"collision in key: {key}"
    # Both originals survive in the key (this is what the vacuous version above
    # missed: a lost entry also keeps set(values) unique):
    assert set(key.values()) == {"E12345678", "A12345678"}, f"an original was lost: {key}"
    assert len(key) == 2
    # Round-trip is lossless:
    from argus_redact.pure.restore import restore

    assert restore(red, dict(key), guard=False) == "护照E12345678 passport number A12345678"
