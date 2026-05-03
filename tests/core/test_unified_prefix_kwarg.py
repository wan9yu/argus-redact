"""v0.6.0: unified_prefix is a real kwarg, not a config-dict sentinel."""
import pytest

from argus_redact import redact


def test_unified_prefix_kwarg_works():
    out, key = redact(
        "员工张三，身份证110101199003074610",
        lang="zh",
        mode="fast",
        seed=42,
        unified_prefix="R",
    )
    assert "R-" in out
    # Per-type prefixes (P-, ID-) should NOT appear when unified
    assert "P-" not in out
    assert "ID-" not in out


def test_legacy_config_underscore_unified_prefix_raises():
    with pytest.raises(ValueError, match="_unified_prefix"):
        redact(
            "x",
            config={"_unified_prefix": "R", "phone": {"strategy": "remove"}},
        )
