"""Anti-rot gate for prose claims that drifted from the code (the v0.8.10 truth-pass).

Each check pins a single false or self-contradictory statement the truth-pass removed,
so a future edit that reintroduces it fails loudly. Every ban is ANCHORED to the
offending phrase and must not trip on the accurate lines kept nearby:

- ``performance.md`` legitimately describes the Rust-port PRIMITIVE as "string
  replacement" (no "pure") — kept; only the caller-facing "pure string replacement"
  claim is banned.
- ``sensitive-info.md`` legitimately carries the PRvL P=100% / reference 100% /
  creative 0% numbers (scoped to the reference suite) — kept; only the unscoped
  absolute "PII leak 0%" is banned.
- ``architecture.md`` RETAINS ``qwen2.5:3b`` as a lower Layer-3 option — kept; only its
  stale ``(default)`` marker is banned.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


# --- D2: restore() does NOT return plaintext unconditionally --------------------
# Since v0.8.0 restore() defaults to guard=True; a bare restore fails closed without an
# anchor. The `restore(...) → plaintext` arrow (unicode →) claimed the opposite.
_RESTORE_PLAINTEXT = re.compile(r"restore\([^)]*\)\s*(?:→|->)\s*plaintext")


@pytest.mark.parametrize(
    "rel", ["docs/README.md", "docs/security-model.md", "docs/architecture.md"]
)
def test_no_bare_restore_returns_plaintext(rel):
    hits = _RESTORE_PLAINTEXT.findall(_read(rel))
    assert not hits, (
        f"{rel} still claims `restore(...) -> plaintext`; since v0.8.0 a bare restore "
        f"fails closed without an anchor. Annotate the guard instead. Found: {hits}"
    )


# --- D2: restore() is not "pure string replacement" -----------------------------
# The phrase omits the provenance/scope guard. Anchored to "pure string replacement"
# so it does NOT trip on performance.md's accurate Rust-primitive "string replacement"
# row (which carries no "pure").
_PURE_STRING = re.compile(r"pure string replacement", re.IGNORECASE)


@pytest.mark.parametrize(
    "rel", ["docs/architecture.md", "docs/performance.md", "docs/api-reference.md"]
)
def test_no_pure_string_replacement_claim(rel):
    assert not _PURE_STRING.search(_read(rel)), (
        f"{rel} calls restore() 'pure string replacement', which omits the guard. "
        "Annotate restore as guarded-by-default (v0.8.0+)."
    )


def test_performance_rust_primitive_string_replacement_line_is_kept():
    # Non-vacuity guard for the anchor above: the accurate Rust-primitive row that
    # legitimately says 'string replacement' (no 'pure') must survive the ban.
    perf = _read("docs/performance.md")
    assert "string replacement" in perf.lower()
    assert not _PURE_STRING.search(perf)


# --- D6: the documented Layer-3 default is qwen3:8b, backed by Ollama -----------
_ARCH = "docs/architecture.md"


def test_layer3_default_is_qwen3_8b_not_qwen25_3b():
    arch = _read(_ARCH)
    assert not re.search(r"qwen2\.5:3b\*\*\s*\(default\)", arch), (
        "architecture.md still marks qwen2.5:3b as the Layer-3 default; the real "
        "OLLAMA_MODEL fallback is qwen3:8b — move the (default) marker."
    )
    assert re.search(r"qwen3:8b\*\*\s*\(default\)", arch), (
        "architecture.md should list qwen3:8b as the (default) Layer-3 model row."
    )
    # qwen2.5:3b is RETAINED as a lower option — do not delete the row.
    assert "qwen2.5:3b" in arch


def test_layer3_backend_is_ollama_not_llama_cpp():
    arch = _read(_ARCH)
    assert "llama.cpp" not in arch, (
        "architecture.md says Layer 3 runs via llama.cpp; it runs via Ollama "
        "(OLLAMA_MODEL / OLLAMA_HOST). Fix the backend claim."
    )


# --- D8: the PII-leak claim is scoped, not an unscoped absolute -----------------
def test_no_unscoped_pii_leak_absolute():
    si = _read("docs/sensitive-info.md")
    assert "PII leak 0%" not in si, (
        "sensitive-info.md states an unscoped 'PII leak 0%'. Scope it to the PRvL "
        "reference suite plus the not-a-guarantee caveat."
    )
    # Non-vacuity: the legitimate scoped PRvL numbers stay.
    assert "PRvL" in si


# --- D9 / D3-gate: reason-code categories stay in sync with the code ------------
# The restore + guarded_restore flow surfaces four caller-facing reason codes, all
# documented together in api-reference.md. Assert per-CATEGORY coverage against the 9
# defined constants (NOT a scalar count), so adding a 10th code or dropping a
# documented one fails loudly and prompts a doc update.
_RESTORE_SURFACE_CODES = {
    "guard_no_anchor",
    "provenance_failed",
    "out_of_scope_pseudonym",
    "injection_suspected",
}


def _defined_reason_codes() -> set[str]:
    import argus_redact.pure.security_events as se
    from argus_redact.pure.security_events import BLOCKED, COMPLETE, PARTIAL

    outcomes = {BLOCKED, PARTIAL, COMPLETE}
    return {
        v
        for k, v in vars(se).items()
        if k.isupper() and isinstance(v, str) and not k.startswith("_") and v not in outcomes
    }


def test_nine_reason_codes_defined():
    assert len(_defined_reason_codes()) == 9, (
        "The reason-code vocabulary changed; update the api-reference guard docs and "
        "this gate's restore-surface set."
    )


def test_restore_surface_codes_are_defined_and_documented():
    defined = _defined_reason_codes()
    api = _read("docs/api-reference.md")
    for code in _RESTORE_SURFACE_CODES:
        assert code in defined, f"{code} is no longer a defined reason code"
        assert code in api, f"api-reference.md no longer documents reason code {code}"
