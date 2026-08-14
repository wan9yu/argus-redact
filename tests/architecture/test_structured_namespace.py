"""Top-level namespace contract for the structured (JSON / CSV) redaction API.

`redact_json` / `restore_json` / `redact_csv` / `restore_csv` were promoted to
the top-level `argus_redact` package in v0.8.10 so downstream consumers (the
gateway wire-face in particular) have ONE canonical import path — see
`docs/stability-contract.md`.

Two things are pinned here:

1. The **circular-import shape**. `argus_redact.structured` imports `redact`
   from the package top, so `__init__.py` can only pull the structured names in
   AFTER `redact` is bound — an earlier insert is a circular ImportError that a
   plain `import argus_redact` would surface. `test_import_argus_redact_smoke`
   guards that ordering.
2. The **frozen signatures**. Per `docs/stability-contract.md`, the function
   signatures + wire-face key sets are the stable contract; a change needs the
   loud CHANGELOG + gateway notice. These are the signatures at v0.8.10.
"""

import inspect
import subprocess
import sys

import pytest

import argus_redact

STRUCTURED_NAMES = ("redact_json", "restore_json", "redact_csv", "restore_csv")

# Additive optional keyword-only params are minor-compatible; only
# removals/renames/required-additions break the contract.
FROZEN_SIGNATURES = {
    "redact_json": "(data: 'dict | list', *, mode: 'str' = 'fast', lang: 'str | list[str]' = 'zh', salt: 'int | bytes | None' = None, config: 'dict | None' = None, key: 'dict | None' = None, paths: 'list[str | list[str]] | None' = None, with_types: 'bool' = False, with_aliases: 'bool' = False, on_unscannable: 'str' = 'warn') -> 'tuple[dict | list, dict] | tuple[dict | list, dict, dict] | tuple[dict | list, dict, dict, dict]'",  # noqa: E501
    "restore_json": "(data: 'dict | list', key: 'dict', *, aliases: 'dict[str, tuple[str, ...]] | None' = None) -> 'dict | list'",  # noqa: E501
    "redact_csv": "(csv_text: 'str', *, mode: 'str' = 'fast', lang: 'str | list[str]' = 'zh', salt: 'int | bytes | None' = None, config: 'dict | None' = None, has_header: 'bool' = True, with_aliases: 'bool' = False) -> 'tuple[str, dict] | tuple[str, dict, dict]'",  # noqa: E501
    "restore_csv": "(csv_text: 'str', key: 'dict', *, aliases: 'dict[str, tuple[str, ...]] | None' = None) -> 'str'",  # noqa: E501
}


def test_import_argus_redact_smoke():
    """A clean `import argus_redact` in a FRESH interpreter must succeed and
    resolve the structured names — guards the circular-import shape between
    __init__.py and argus_redact.structured (an earlier structured insert is a
    circular ImportError). A subprocess is the only way to test import order
    from scratch; an in-process reload keeps modules cached and hides a cycle."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import argus_redact; "
            "from argus_redact import redact_json, restore_json, redact_csv, restore_csv",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"fresh `import argus_redact` failed:\n{result.stderr}"


@pytest.mark.parametrize("name", STRUCTURED_NAMES)
def test_structured_name_present_and_callable(name):
    assert name in argus_redact.__all__, f"{name} missing from argus_redact.__all__"
    assert hasattr(argus_redact, name), f"argus_redact has no attribute {name!r}"
    assert callable(getattr(argus_redact, name)), f"{name} is not callable"


@pytest.mark.parametrize("name", STRUCTURED_NAMES)
def test_structured_name_is_the_structured_module_object(name):
    """The top-level export is the SAME object as argus_redact.structured.<name>
    — a re-export, not a shadowing rebind."""
    import argus_redact.structured as structured

    assert getattr(argus_redact, name) is getattr(structured, name)


def test_structured_module_dunder_all():
    """argus_redact.structured owns its own __all__ = exactly the 4 public names."""
    import argus_redact.structured as structured

    assert set(structured.__all__) == set(STRUCTURED_NAMES)


@pytest.mark.parametrize("name,expected", list(FROZEN_SIGNATURES.items()))
def test_structured_signatures_frozen(name, expected):
    fn = getattr(argus_redact, name)
    actual = str(inspect.signature(fn))
    assert actual == expected, (
        f"{name} signature changed — structured wire-face contract violation.\n"
        f"  expected: {expected}\n"
        f"  actual:   {actual}\n"
        f"If intentional: it needs the loud CHANGELOG + gateway notice per "
        f"docs/stability-contract.md, then update FROZEN_SIGNATURES."
    )
