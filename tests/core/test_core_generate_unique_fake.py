import argus_redact._core as _core


def test_generate_unique_fake_builtin_reroll():
    salt = _core.resolve_salt(42)  # added in Task 1
    fake, aliases = _core.generate_unique_fake(
        "fake_phone_reserved", "13800138000", "phone", salt, set()
    )
    assert isinstance(fake, str) and isinstance(aliases, list)
    assert fake == "19999402223"  # golden: reserved zh-phone range, salt=42
    # collision → re-roll to a different unique fake when the first is already used
    fake2, _ = _core.generate_unique_fake(
        "fake_phone_reserved", "13800138000", "phone", salt, {fake}
    )
    assert fake2 == "19999555007"  # golden: re-roll attempt #1, salt=42


def test_generate_unique_fake_unknown_name_raises():
    import pytest

    salt = _core.resolve_salt(42)
    with pytest.raises(ValueError):
        _core.generate_unique_fake("fake_DOES_NOT_EXIST", "x", "phone", salt, set())
