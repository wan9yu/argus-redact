"""Fail-closed semantics — unknown lang / missing layers must not silently under-redact."""

import pytest

from argus_redact import redact


def test_unknown_lang_raises():
    with pytest.raises(ValueError, match="Unknown language"):
        redact("电话13800138000", lang="cn", mode="fast", salt=42)


def test_known_lang_still_works():
    out, key = redact("电话13800138000", lang="zh", mode="fast", salt=42)
    assert len(key) >= 1
