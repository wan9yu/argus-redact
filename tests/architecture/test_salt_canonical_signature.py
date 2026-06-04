"""v0.6.8: public entry points use canonical `salt` parameter, not `seed`.

Hard-break enforcement: passing salt= to any public entry point must
raise TypeError (Python's default for unexpected keyword arguments).
"""
from __future__ import annotations

import inspect

import pytest

from argus_redact import (
    redact,
    redact_pseudonym_llm,
)
from argus_redact.compose import StreamingRedactor
from argus_redact.integrations.fastapi_middleware import redact_body
from argus_redact.integrations.langchain import RedactRunnable
from argus_redact.integrations.llamaindex import RedactTransform
from argus_redact.integrations.presidio import PresidioBridge
from argus_redact.structured import redact_csv, redact_json

ENTRY_POINTS = [
    (redact, "argus_redact.redact"),
    (redact_pseudonym_llm, "argus_redact.redact_pseudonym_llm"),
    (StreamingRedactor.__init__, "StreamingRedactor.__init__"),
    (redact_json, "argus_redact.structured.redact_json"),
    (redact_csv, "argus_redact.structured.redact_csv"),
    (RedactRunnable.__init__, "RedactRunnable.__init__"),
    (RedactTransform.__init__, "RedactTransform.__init__"),
    (PresidioBridge.redact, "PresidioBridge.redact"),
    (redact_body, "redact_body"),
]


@pytest.mark.parametrize(
    "fn,label",
    ENTRY_POINTS,
    ids=[lbl for _, lbl in ENTRY_POINTS],
)
def test_entry_point_uses_salt_not_seed(fn, label):
    sig = inspect.signature(fn)
    assert "salt" in sig.parameters, (
        f"{label} missing 'salt' parameter (v0.6.8 canonical name)"
    )
    assert "seed" not in sig.parameters, (
        f"{label} still has 'seed' parameter. v0.6.8 hard-break: use 'salt'."
    )


def test_seed_kwarg_raises_typeerror():
    """Passing seed= must raise TypeError (Python's default for unknown kwargs)."""
    with pytest.raises(TypeError):
        redact("test text", seed=42, lang="en")
