"""Every PyO3 binding registered in `_core` must have a Python-side consumer.

Neither toolchain catches an orphan on its own: rustc's `dead_code` lint sees a
`pub` item passed to `wrap_pyfunction!` as used, and ruff/pyflakes has no notion
of a name that crosses the FFI boundary. So a binding can keep compiling,
keep shipping in the wheel, and be called from nowhere.

A test-only consumer counts — several bindings exist purely so a parity test can
compare the Rust pool against its Python expectation. The failure condition is
"referenced in NEITHER `src/argus_redact/` nor `tests/`".
"""

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_LIB_RS = _ROOT / "crates/argus-redact-py/src/lib.rs"
_PY_CRATE_SRC = _ROOT / "crates/argus-redact-py/src"

_WRAP_PYFUNCTION = re.compile(r"wrap_pyfunction!\(\s*(?:[\w:]+::)?(\w+)\s*,")
_ADD_CLASS = re.compile(r"add_class::<\s*(?:[\w:]+::)?(\w+)\s*>")
# `#[pyclass(name = "X")]` renames the Python-visible symbol; the Rust struct
# name is then invisible to Python and searching for it would false-positive.
_PYCLASS_DECL = re.compile(
    r"#\[pyclass(?P<args>\([^)]*\))?\][^;{]*?\bstruct\s+(?P<ident>\w+)",
    re.DOTALL,
)
_PYCLASS_NAME_ARG = re.compile(r'name\s*=\s*"([^"]+)"')


def _exported_class_names() -> dict[str, str]:
    """Rust struct ident → the name Python actually sees."""
    mapping: dict[str, str] = {}
    for rs in sorted(_PY_CRATE_SRC.rglob("*.rs")):
        text = rs.read_text(encoding="utf-8")
        for m in _PYCLASS_DECL.finditer(text):
            args = m.group("args") or ""
            renamed = _PYCLASS_NAME_ARG.search(args)
            mapping[m.group("ident")] = renamed.group(1) if renamed else m.group("ident")
    return mapping


def _python_sources() -> list[str]:
    roots = [_ROOT / "src/argus_redact", _ROOT / "tests"]
    return [
        p.read_text(encoding="utf-8", errors="ignore")
        for root in roots
        for p in sorted(root.rglob("*.py"))
    ]


def test_every_registered_core_binding_has_a_consumer():
    lib_rs = _LIB_RS.read_text(encoding="utf-8")
    class_names = _exported_class_names()

    registered = {name: name for name in _WRAP_PYFUNCTION.findall(lib_rs)}
    for ident in _ADD_CLASS.findall(lib_rs):
        registered[ident] = class_names.get(ident, ident)
    assert registered, f"no PyO3 registrations parsed out of {_LIB_RS.name} — regex rotted"

    sources = _python_sources()
    orphans = sorted(
        f"{ident} (exported as {exported})" if ident != exported else ident
        for ident, exported in registered.items()
        if not any(re.search(rf"\b{re.escape(exported)}\b", src) for src in sources)
    )
    assert not orphans, (
        "PyO3 bindings registered in _core but referenced from neither "
        f"src/argus_redact/ nor tests/ — delete them or use them: {orphans}"
    )
