"""restore.rs's alias-merge iterates a HashMap<String, Vec<String>> with no
defined order. When two distinct fakes (-> two distinct originals) alias to
the SAME string, the merge winner previously depended on which fake the
process's HashMap iteration visited first — nondeterministic across process
runs, and silent (no signal that the loser's identity may come back wrong on
restore). Mirrors the mask-collision fix: sort the iteration for a
deterministic winner, and record + warn on every collision.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from argus_redact.compose.anchor import make_anchor
from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.restore import restore

# Two distinct fakes, two distinct originals, one shared alias string.
_KEY = {"P-1": "Alice", "P-2": "Bob"}
_ALIASES = {"P-1": ["Shared"], "P-2": ["Shared"]}
_TEXT = "hello Shared"

# Three distinct fakes, three distinct originals, all aliasing to the SAME
# string — the core pushes "Shared" onto alias_collisions once per losing
# claim (2 entries), which must still count as 1 DISTINCT collided alias.
_KEY_3WAY = {"P-1": "Alice", "P-2": "Bob", "P-3": "Carol"}
_ALIASES_3WAY = {"P-1": ["Shared"], "P-2": ["Shared"], "P-3": ["Shared"]}

_REPO_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
_SUBPROCESS_CODE = (
    "import warnings; warnings.simplefilter('ignore');"
    "from argus_redact.pure.restore import restore;"
    "print(restore('hello Shared', {'P-1': 'Alice', 'P-2': 'Bob'}, "
    "aliases={'P-1': ['Shared'], 'P-2': ['Shared']}, guard=False))"
)


def test_restore_should_be_deterministic_across_process_hash_seeds():
    """The alias-merge winner must not depend on the process's HashMap
    iteration order — two separate process runs must restore "Shared" to the
    SAME original every time."""
    base_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": _REPO_SRC,
        "PYTHONUTF8": "1",
    }

    out1 = subprocess.check_output(
        [sys.executable, "-c", _SUBPROCESS_CODE],
        env={**base_env, "PYTHONHASHSEED": "1"},
        encoding="utf-8",
    )
    out2 = subprocess.check_output(
        [sys.executable, "-c", _SUBPROCESS_CODE],
        env={**base_env, "PYTHONHASHSEED": "2"},
        encoding="utf-8",
    )

    assert out1 == out2, "alias-merge winner depends on HashMap iteration order — not deterministic"


def test_restore_should_emit_security_warning_when_aliases_collide():
    """Two fakes aliasing to the same string must fire a SecurityWarning
    naming the collision — the restored identity for the loser may be wrong."""
    with pytest.warns(SecurityWarning, match="alias"):
        restore(_TEXT, _KEY, aliases=_ALIASES, guard=False)


def test_restore_should_not_emit_security_warning_when_aliases_dont_collide():
    """A single alias with no collision fires no alias-collision warning."""
    key = {"P-1": "Alice"}
    aliases = {"P-1": ["Al"]}
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", SecurityWarning)
        result = restore("hello Al", key, aliases=aliases, guard=False)
    assert result == "hello Alice"


def test_restore_should_suppress_security_warning_when_warn_is_false():
    """``_warn=False`` must suppress the alias_collision SecurityWarning too —
    the same suppression contract every other restore() warning already
    respects (see restore()'s ``_warn`` docstring)."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", SecurityWarning)
        restore(_TEXT, _KEY, aliases=_ALIASES, guard=False, _warn=False)


def test_restore_should_dedup_collision_count_when_three_fakes_collide():
    """A 3-way collision on the SAME alias string is 1 DISTINCT collided alias,
    not 2 — the Rust core pushes "Shared" onto alias_collisions once per
    losing claim (2 entries for a 3-way collision), so the Python-side count
    must dedup before reporting, mirroring mask_collision_event's set()-based
    count."""
    with pytest.warns(SecurityWarning, match=r"^1 alias\(es\)"):
        restore("hello Shared", _KEY_3WAY, aliases=_ALIASES_3WAY, guard=False)


def test_restore_detailed_should_include_alias_collision_event():
    """``restore(guard=True, detailed=True)`` must surface an
    ``alias_collision`` security_event — mirroring the out-param idiom that
    wires ``mask_collision`` into ``redact(detailed=True)``'s security_events
    (glue/redact.py's ``_mask_collisions``)."""
    import warnings

    anchor = make_anchor(_KEY)
    text = f"{_TEXT}\n{anchor.nonce}"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        _result, details = restore(
            text, _KEY, aliases=_ALIASES, guard=True, anchor=anchor, detailed=True
        )

    events = [e for e in details["security_events"] if e["reason_code"] == "alias_collision"]
    assert len(events) == 1
    assert events[0]["count"] == 1
