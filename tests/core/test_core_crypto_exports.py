import argus_redact._core as _core
from argus_redact.pure import replacer  # primitives still present at this task


def test_seed_from_value_matches_python():
    salt = b"v0.7.5-seed-parity-salt-0000-0001"
    assert _core.seed_from_value("13800138000", "phone", salt) == replacer._seed_from_value("13800138000", "phone", salt)


def test_type_seed_offset_matches_python():
    for t in ("phone", "id_number", "person", "email", "ssn"):
        assert _core.type_seed_offset(t) == replacer._type_seed_offset(t)


def test_resolve_salt_int_and_bytes_and_error():
    assert _core.resolve_salt(42) == replacer._resolve_salt(42)
    assert _core.resolve_salt(b"x" * 32) == replacer._resolve_salt(b"x" * 32)
    import pytest
    with pytest.raises(ValueError):
        _core.resolve_salt(None)  # no env var set → both raise
