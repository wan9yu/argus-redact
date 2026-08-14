"""Shared helpers for the RON spec generators.

Used by ``gen_risk_data`` / ``gen_confusables`` / ``gen_en_common_words`` so the
RON serialisation and the ``--check``/write scaffold live once instead of being
copied per generator:

* RON literal formatting — ``ron_str`` / ``ron_opt_str`` / ``ron_char`` render
  the serde string / option / char escaping used to emit registry data.
* ``emit_or_check`` — the ``--check`` (drift-compare, exit 1) vs default
  (write + report) ``main()`` body. One implementation means the drift gate and
  the write behaviour cannot skew between generators.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path

# Repo root: specs/_gen_ron.py → specs → argus_redact → src → <root>. Identical
# to the value each generator computes from its own __file__ (all live in specs/),
# so ``Wrote <relpath>`` renders the same path as before.
_REPO_ROOT = Path(__file__).resolve().parents[3]


def core_data_path(name: str) -> Path:
    """Absolute path to a generated RON file under the core crate's data dir.

    ``name`` is the bare filename (e.g. ``"risk_data.ron"``). Identical to the
    inline ``parents[3] / "crates" / "argus-redact-core" / "data" / name`` each
    generator computed from its own __file__ (all live in specs/).
    """
    return _REPO_ROOT / "crates" / "argus-redact-core" / "data" / name


def ron_str(s: str) -> str:
    """RON/serde string literal — double-quoted, backslash + quote escaped."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def ron_opt_str(s: str | None) -> str:
    """RON ``Option<String>`` literal — ``None`` or ``Some("...")``."""
    return "None" if s is None else f"Some({ron_str(s)})"


def ron_char(cp_or_str: int | str) -> str:
    """RON char literal. An ``int`` codepoint renders as a ``\\u{XXXX}`` escape; a
    single ASCII letter renders bare. Neither confusable source (alphabetic
    non-ASCII) nor target (ASCII letter) can be a quote or backslash, so no
    further escaping is needed."""
    if isinstance(cp_or_str, int):
        return f"'\\u{{{cp_or_str:04X}}}'"
    # single ASCII letter target
    return f"'{cp_or_str}'"


def emit_or_check(
    out_path: Path,
    ron_text: str,
    argv: list[str],
    *,
    human_name: str,
    out_of_sync_msg: str,
    extra_write_lines: Iterable[str] = (),
) -> int:
    """Shared generator ``main()`` body.

    With ``--check`` in ``argv``: compare ``ron_text`` to the committed
    ``out_path``; on drift print ``out_of_sync_msg`` to stderr and return 1,
    otherwise print ``f"{human_name} is in sync"`` and return 0. Without
    ``--check``: write ``ron_text`` to ``out_path`` and print ``Wrote <relpath>``
    followed by each of ``extra_write_lines``. Returns the process exit code.
    """
    if "--check" in argv:
        current = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
        if current != ron_text:
            print(out_of_sync_msg, file=sys.stderr)
            return 1
        print(f"{human_name} is in sync")
        return 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(ron_text, encoding="utf-8")
    print(f"Wrote {out_path.relative_to(_REPO_ROOT)}")
    for line in extra_write_lines:
        print(line)
    return 0
