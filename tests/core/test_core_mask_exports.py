"""Parity tests: _core mask/collision exports vs pure Python equivalents."""

from __future__ import annotations

import argus_redact._core as _core
from argus_redact.pure import replacer


def test_mask_value_matches_python():
    assert _core.mask_value("13812345678", "phone", 0, 0) == replacer._mask_value(
        "13812345678", "phone", visible_prefix=0, visible_suffix=0
    )
    assert _core.mask_value("a@example.com", "email", 0, 0) == replacer._mask_value(
        "a@example.com", "email", visible_prefix=0, visible_suffix=0
    )
    assert _core.mask_value(
        "110101199001011234", "id_number", 0, 0
    ) == replacer._mask_value(
        "110101199001011234", "id_number", visible_prefix=0, visible_suffix=0
    )


def test_mask_name_matches_python():
    for n in ("张三", "李小明", "欧阳明"):
        assert _core.mask_name(n) == replacer._mask_name(n)


def test_mask_landline_matches_python():
    assert _core.mask_landline("075512345678") == replacer._mask_landline(
        "075512345678"
    )


def test_resolve_collision_matches_python():
    used = {"X", "X①"}
    assert _core.resolve_collision("X", used) == replacer._resolve_collision(
        "X", used
    )
