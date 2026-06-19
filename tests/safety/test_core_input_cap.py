"""Rust core enforces MAX_INPUT_SIZE on direct PyO3 entry points."""

import pytest

from argus_redact._core_loader import _core


def test_detect_l1_rejects_oversized_input():
    big = "a" * (1024 * 1024 + 1)
    with pytest.raises(ValueError, match="input too large|MAX_INPUT_SIZE|exceeds"):
        _core.detect_l1(big, ["en"], [])
