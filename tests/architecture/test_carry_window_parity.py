"""Source-parity test: carry-window constant Python ↔ Rust.

``_CARRY_WINDOW`` in ``glue/_detect_partial.py`` mirrors ``CARRY_WINDOW`` in
``crates/argus-redact-core/src/streaming.rs``.

If they drift, the Python wheel path and the Rust core disagree on how many
chars to retain at a boundary-less force-flush: the wheel may carry too few
chars, letting a ~150-char bounded entity (e.g. an API key) straddle the
carry boundary and emit its head as unredacted plaintext.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

_PYTHON_FILE = _REPO_ROOT / "src" / "argus_redact" / "glue" / "_detect_partial.py"
_RUST_FILE = _REPO_ROOT / "crates" / "argus-redact-core" / "src" / "streaming.rs"


def _parse_int_const(path: Path, pattern: str) -> int:
    """Read the first integer constant matched by *pattern* in *path*."""
    src = path.read_text(encoding="utf-8")
    m = re.search(pattern, src)
    assert m, f"pattern {pattern!r} not found in {path}"
    return int(m.group(1).replace("_", ""))


def _read_python_value() -> int:
    return _parse_int_const(_PYTHON_FILE, r"_CARRY_WINDOW\s*=\s*([\d_]+)")


def _read_rust_value() -> int:
    return _parse_int_const(_RUST_FILE, r"pub const CARRY_WINDOW\s*:\s*\w+\s*=\s*([\d_]+)")


def test_carry_window_python_rust_parity():
    """_CARRY_WINDOW in Python must equal Rust CARRY_WINDOW.

    If they diverge, the Python wheel path carries a different trailing window
    than the Rust core at each boundary-less force-flush.  A bounded entity
    (e.g. a ~150-char API key) whose span straddles the carry boundary may
    then fall outside the carried region and have its head emitted as raw
    plaintext — a PII leak.
    """
    py_val = _read_python_value()
    rs_val = _read_rust_value()
    assert py_val == rs_val, (
        f"Carry-window drift: Python _CARRY_WINDOW={py_val} "
        f"!= Rust CARRY_WINDOW={rs_val}. "
        f"Update one to match the other."
    )
