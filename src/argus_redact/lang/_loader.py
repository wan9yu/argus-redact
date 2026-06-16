"""Read Layer-1 pattern data from the Rust core, re-attaching the 3 deferred
Python validators (jwt/organization/school) that intentionally stay on the
Python validate path. The compiled `_core` is required."""
from __future__ import annotations

import importlib

# type -> (module, function name). Imported LAZILY, per-type, only when a
# pattern of that type is present, to avoid circular imports during lang module load.
_DEFERRED = {
    "jwt": ("argus_redact.lang.shared.patterns", "_validate_jwt"),
    "organization": ("argus_redact.lang.zh.patterns", "_validate_organization"),
    "school": ("argus_redact.lang.zh.patterns", "_validate_school"),
}


def core_patterns(lang: str) -> list[dict]:
    from argus_redact._core_loader import HAS_CORE, _core

    if not HAS_CORE:
        raise ImportError(
            "argus-redact requires the compiled _core extension for Layer-1 "
            "pattern detection (the pure-Python pattern data was retired in v0.7.1)."
        )
    out: list[dict] = []
    for p in _core.builtin_patterns(lang):
        d = dict(p)
        t = d.get("type")
        if t in _DEFERRED and not d.get("validator"):
            mod_name, fn_name = _DEFERRED[t]
            d["validate"] = getattr(importlib.import_module(mod_name), fn_name)
        out.append(d)
    return out
