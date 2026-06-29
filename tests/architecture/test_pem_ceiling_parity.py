"""Source-parity test: PEM opener ceiling constant Python ↔ Rust.

``_PEM_OPENER_CEILING_EXTRA`` in ``glue/_detect_partial.py`` mirrors
``PEM_OPENER_CEILING_EXTRA`` in ``crates/argus-redact-core/src/streaming.rs``.

If they drift, the Python wheel and the Rust core pick different max_buffer
ceilings when a PEM private-key block is in the buffer: the wheel may
force-flush-split a key whose byte length falls between the two values,
emitting the header of a complete private key as raw plaintext.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

_PYTHON_FILE = (
    _REPO_ROOT / "src" / "argus_redact" / "glue" / "_detect_partial.py"
)
_RUST_FILE = (
    _REPO_ROOT / "crates" / "argus-redact-core" / "src" / "streaming.rs"
)


def _read_python_value() -> int:
    """Parse _PEM_OPENER_CEILING_EXTRA from the Python source."""
    src = _PYTHON_FILE.read_text(encoding="utf-8")
    m = re.search(r"_PEM_OPENER_CEILING_EXTRA\s*=\s*([\d_]+)", src)
    assert m, f"_PEM_OPENER_CEILING_EXTRA not found in {_PYTHON_FILE}"
    return int(m.group(1).replace("_", ""))


def _read_rust_value() -> int:
    """Parse PEM_OPENER_CEILING_EXTRA from the Rust source."""
    src = _RUST_FILE.read_text(encoding="utf-8")
    m = re.search(r"const\s+PEM_OPENER_CEILING_EXTRA\s*:\s*\w+\s*=\s*([\d_]+)", src)
    assert m, f"PEM_OPENER_CEILING_EXTRA not found in {_RUST_FILE}"
    return int(m.group(1).replace("_", ""))


def test_pem_opener_ceiling_extra_python_rust_parity():
    """_PEM_OPENER_CEILING_EXTRA in Python must equal Rust PEM_OPENER_CEILING_EXTRA.

    If they diverge, the Python wheel and the Rust WASM core pick different
    effective max_buffer ceilings for PEM-private-key blocks, causing the wheel
    path to force-flush-split a complete key and emit its BEGIN header as raw
    plaintext.
    """
    py_val = _read_python_value()
    rs_val = _read_rust_value()
    assert py_val == rs_val, (
        f"PEM opener ceiling drift: Python _PEM_OPENER_CEILING_EXTRA={py_val} "
        f"!= Rust PEM_OPENER_CEILING_EXTRA={rs_val}. "
        f"Update one to match the other."
    )
