"""v0.6.0: unified_prefix is a real kwarg, not a config-dict sentinel."""

import pytest

from argus_redact import redact


def test_redact_should_use_unified_prefix_for_all_types():
    out, key = redact(
        "员工张三，身份证110101199003074610",
        lang="zh",
        mode="fast",
        salt=42,
        unified_prefix="R",
    )

    assert "R-" in out
    # Per-type prefixes (P-, ID-) should NOT appear when unified
    assert "P-" not in out
    assert "ID-" not in out


def test_redact_should_raise_when_legacy_underscore_unified_prefix_config_used():
    with pytest.raises(ValueError, match="_unified_prefix"):
        redact(
            "x",
            config={"_unified_prefix": "R", "phone": {"strategy": "remove"}},
        )
