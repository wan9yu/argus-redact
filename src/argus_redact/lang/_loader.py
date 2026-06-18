"""Read Layer-1 pattern data from the Rust core.

As of v0.7.7 all builtin validators (incl. the formerly-deferred
jwt/organization/school) carry a Rust ``validator`` named in the RON, so the
regex AND the validation run entirely in the Rust core. No builtin pattern needs
a Python ``validate`` callback re-attached here. The compiled ``_core`` is
required. (Adapter / non-builtin patterns may still carry a Python ``validate``;
those are handled by ``pure/patterns.py``, not here.)"""
from __future__ import annotations


def core_patterns(lang: str) -> list[dict]:
    from argus_redact._core_loader import HAS_CORE, _core

    if not HAS_CORE:
        raise ImportError(
            "argus-redact requires the compiled _core extension for Layer-1 "
            "pattern detection (the pure-Python pattern data was retired in v0.7.1)."
        )
    return [dict(p) for p in _core.builtin_patterns(lang)]
