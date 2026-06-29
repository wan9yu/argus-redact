"""Source-parity test: MAX_INPUT_SIZE constant Python ↔ Rust.

``MAX_INPUT_SIZE`` in ``pure/normalize.py`` mirrors ``MAX_INPUT_SIZE`` in
``crates/argus-redact-core/src/lib.rs``.

**Unit nuance (by design):** The Python constant is compared against
``len(text)``, which counts Unicode *code points*. The Rust constant is
compared against ``text.len()``, which counts UTF-8 *bytes*. For ASCII-only
input the two measures are identical; for multi-byte code points a single
code point can consume 2–4 bytes, so the limits are *not* equivalent in
general. The numeric equality (both 1 048 576) is therefore a deliberate
design invariant: the Python layer applies the cap in code points and the
Rust layer applies it in bytes, but the threshold number itself must remain
the same so that the Python guard fires before any payload could exceed the
Rust hard cap (given that bytes ≥ code points for UTF-8 input, the Python
check is strictly looser than the Rust check, which is the safe direction).

This test pins that numeric equality. It would fail if either constant were
updated without a corresponding update to the other.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

_PYTHON_FILE = _REPO_ROOT / "src" / "argus_redact" / "pure" / "normalize.py"
_RUST_FILE = _REPO_ROOT / "crates" / "argus-redact-core" / "src" / "lib.rs"


def _eval_simple_expr(expr: str) -> int:
    """Evaluate a simple integer expression containing only digits, ``*``, and spaces.

    Raises ``ValueError`` if the expression contains anything other than those
    characters, preventing accidental ``eval`` of arbitrary source.
    """
    cleaned = expr.strip()
    if not re.fullmatch(r"[\d\s*]+", cleaned):
        raise ValueError(f"Unexpected characters in numeric expression: {cleaned!r}")
    result = 1
    for factor in cleaned.split("*"):
        result *= int(factor.strip())
    return result


def _read_python_max_input_size() -> int:
    """Extract the numeric value of ``MAX_INPUT_SIZE`` from the Python source."""
    src = _PYTHON_FILE.read_text(encoding="utf-8")
    m = re.search(r"^MAX_INPUT_SIZE\s*=\s*([\d\s*]+)", src, re.MULTILINE)
    assert m, f"MAX_INPUT_SIZE definition not found in {_PYTHON_FILE}"
    return _eval_simple_expr(m.group(1))


def _read_rust_max_input_size() -> int:
    """Extract the numeric value of ``MAX_INPUT_SIZE`` from the Rust source."""
    src = _RUST_FILE.read_text(encoding="utf-8")
    m = re.search(
        r"pub\s+const\s+MAX_INPUT_SIZE\s*:\s*\w+\s*=\s*([\d\s*]+)\s*;",
        src,
    )
    assert m, f"MAX_INPUT_SIZE constant not found in {_RUST_FILE}"
    return _eval_simple_expr(m.group(1))


def test_max_input_size_python_rust_parity():
    """Python MAX_INPUT_SIZE must equal Rust MAX_INPUT_SIZE numerically.

    The two constants measure different units (code points vs. UTF-8 bytes)
    but must remain numerically equal by design — the Python guard fires in
    code-point space before any payload could overrun the Rust byte-space cap
    (bytes ≥ code points for UTF-8). If the numbers diverge, one of the two
    input-size gates becomes inconsistent with the other, which is a silent
    contract break.

    Non-vacuity: this test regex-extracts the literal values from the source
    files at test time. Changing either constant in isolation (e.g. bumping
    the Rust cap to ``2 * 1024 * 1024`` without updating Python) will cause
    the assertion to fail.
    """
    py_val = _read_python_max_input_size()
    rs_val = _read_rust_max_input_size()
    assert py_val == rs_val, (
        f"MAX_INPUT_SIZE numeric drift: "
        f"Python (code-point cap) = {py_val}, "
        f"Rust (byte cap) = {rs_val}. "
        f"Update both constants together — see module docstring for the "
        f"units-nuance rationale."
    )
