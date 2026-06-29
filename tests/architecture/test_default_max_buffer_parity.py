"""Source-parity test: DEFAULT_MAX_BUFFER constant Python ↔ Rust.

``DEFAULT_MAX_BUFFER`` in ``glue/_detect_partial.py`` mirrors
``DEFAULT_MAX_BUFFER`` in ``crates/argus-redact-core/src/streaming.rs``.

If they drift, the Python wheel and the Rust core use different default
streaming buffer sizes: callers that rely on the default would silently get
different chunking behaviour from the wheel versus the WASM/native-Rust path,
potentially splitting tokens at different boundaries.
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
    return _parse_int_const(_PYTHON_FILE, r"DEFAULT_MAX_BUFFER\s*=\s*([\d_]+)")


def _read_rust_value() -> int:
    return _parse_int_const(
        _RUST_FILE, r"pub\s+const\s+DEFAULT_MAX_BUFFER\s*:\s*\w+\s*=\s*([\d_]+)"
    )


def test_default_max_buffer_python_rust_parity():
    """DEFAULT_MAX_BUFFER in Python must equal Rust DEFAULT_MAX_BUFFER.

    If they diverge, the Python wheel and the Rust WASM/native-core use
    different default streaming buffer sizes, causing silent behavioural
    differences between the two execution paths for any caller that relies on
    the default value.
    """
    py_val = _read_python_value()
    rs_val = _read_rust_value()
    assert py_val == rs_val, (
        f"DEFAULT_MAX_BUFFER drift: Python DEFAULT_MAX_BUFFER={py_val} "
        f"!= Rust DEFAULT_MAX_BUFFER={rs_val}. "
        f"Update one to match the other."
    )
