"""Source-parity test: the wheel ceiling comes from one Rust binding.

``glue/_detect_partial.py`` must not keep a second PEM or JWT extra. Core
still owns ``PEM_OPENER_CEILING_EXTRA``. The wheel calls
``streaming_effective_max_buffer`` and passes that one result to both cuts,
and appends the JWT pending span from ``streaming_unclosed_jwt_opener_start``.
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


def _read_rust_value() -> int:
    return _parse_int_const(
        _RUST_FILE, r"const\s+PEM_OPENER_CEILING_EXTRA\s*:\s*\w+\s*=\s*([\d_]+)"
    )


def test_pem_opener_ceiling_extra_should_match_between_python_and_rust():
    """Rust still adds 11000 for a PEM opener; the wheel must not copy it.

    A second Python constant would drift from core and force-flush-split a
    key the wasm path still carries. The wheel ceiling is the binding.
    """
    rs_val = _read_rust_value()
    assert rs_val == 11_000, (
        f"PEM opener ceiling changed: Rust PEM_OPENER_CEILING_EXTRA={rs_val}, "
        "expected 11000"
    )
    src = _PYTHON_FILE.read_text(encoding="utf-8")
    assert "_PEM_OPENER_CEILING_EXTRA" not in src
    assert not re.search(r"\b(?:11_000|11000|8_192|8192)\b", src), (
        "glue must not add a local 11000 or 8192 ceiling extra"
    )


def test_glue_cut_path_passes_one_effective_max_buffer_to_both_cuts():
    """``_context_cut`` must take the ceiling from one binding call.

    ``streaming_emit_possible`` and ``streaming_context_cut`` have to see that
    same result. A local PEM-only addition drops the JWT extra on one path.
    """
    src = _PYTHON_FILE.read_text(encoding="utf-8")
    fn = src.split("def _context_cut(", 1)[1]
    fn = fn.split("\ndef ", 1)[0]
    bound = re.search(
        r"(\w+)\s*=\s*_core\.streaming_effective_max_buffer\(",
        fn,
    )
    assert bound, (
        "glue _context_cut must call streaming_effective_max_buffer and bind "
        "that one result; a local PEM extra is not the shared ceiling"
    )
    name = bound.group(1)
    assert fn.count("streaming_effective_max_buffer(") == 1, (
        "the cut path must call streaming_effective_max_buffer once"
    )
    emit = re.search(r"streaming_emit_possible\((.*?)\)", fn, re.S)
    cut = re.search(r"streaming_context_cut\((.*?)\)", fn, re.S)
    assert emit and name in emit.group(1), (
        f"streaming_emit_possible must receive {name}"
    )
    assert cut and name in cut.group(1), (
        f"streaming_context_cut must receive {name}"
    )


def test_glue_appends_jwt_span_from_binding_and_drops_local_pem_extra():
    """The wheel cut path must hold an unclosed JWT via the Rust opener.

    A local 11000/8192 addition, a second eyJ scan, or a still-registered
    ``streaming_pem_begin_present`` binding would let the wheel pick a
    different cut than core.
    """
    src = _PYTHON_FILE.read_text(encoding="utf-8")
    fn = src.split("def _context_cut(", 1)[1]
    fn = fn.split("\ndef ", 1)[0]

    jwt = re.search(
        r"(\w+)\s*=\s*_core\.streaming_unclosed_jwt_opener_start\(",
        fn,
    )
    assert jwt, (
        "glue _context_cut must call streaming_unclosed_jwt_opener_start "
        "and bind that offset; it must not re-scan"
    )
    name = jwt.group(1)
    assert re.search(
        rf"spans\.append\(\(\s*{name}\s*,\s*len\(combined\)\s*\+\s*1\s*,"
        rf"\s*[\"']jwt[\"']\s*\)\)",
        fn,
    ), f"must append ({name}, len(combined) + 1, jwt) from the binding"
    assert "streaming_effective_max_buffer(" in fn

    # The binding is the scan. A local walk would be a second implementation.
    assert "eyJ" not in src
    assert "validate_jwt" not in src
    assert not re.search(r"\[A-Za-z0-9_\-\.\]", src)
    assert "streaming_pem_begin_present" not in src
    assert "_PEM_OPENER_CEILING_EXTRA" not in src
    assert not re.search(r"\b(?:11_000|11000|8_192|8192)\b", src), (
        "glue must not add a local 11000 or 8192 ceiling extra"
    )

    lib = (_REPO_ROOT / "crates/argus-redact-py/src/lib.rs").read_text(encoding="utf-8")
    assert "streaming_pem_begin_present" not in lib, (
        "streaming_pem_begin_present must be unregistered"
    )
    assert "wrap_pyfunction!(streaming::streaming_unclosed_jwt_opener_start" in lib
    assert "wrap_pyfunction!(streaming::streaming_effective_max_buffer" in lib

    py_rs = (_REPO_ROOT / "crates/argus-redact-py/src/streaming.rs").read_text(
        encoding="utf-8"
    )
    assert "fn streaming_unclosed_jwt_opener_start" in py_rs
    assert "fn streaming_pem_begin_present" not in py_rs
    # Orphan gate scans src/ and tests/. The glue call is the src consumer.
    assert "streaming_unclosed_jwt_opener_start" in src
    assert "streaming_effective_max_buffer" in src
