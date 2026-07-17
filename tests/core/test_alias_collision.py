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

from argus_redact.exceptions import SecurityWarning
from argus_redact.pure.restore import restore

# Two distinct fakes, two distinct originals, one shared alias string.
_KEY = {"P-1": "Alice", "P-2": "Bob"}
_ALIASES = {"P-1": ["Shared"], "P-2": ["Shared"]}
_TEXT = "hello Shared"

_REPO_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
_SUBPROCESS_CODE = (
    "import warnings; warnings.simplefilter('ignore');"
    "from argus_redact.pure.restore import restore;"
    "print(restore('hello Shared', {'P-1': 'Alice', 'P-2': 'Bob'}, "
    "aliases={'P-1': ['Shared'], 'P-2': ['Shared']}, guard=False))"
)


def test_alias_collision_restore_is_deterministic_across_processes():
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


def test_alias_collision_emits_security_warning():
    """Two fakes aliasing to the same string must fire a SecurityWarning
    naming the collision — the restored identity for the loser may be wrong."""
    with pytest.warns(SecurityWarning, match="alias"):
        restore(_TEXT, _KEY, aliases=_ALIASES, guard=False)


def test_no_collision_no_alias_warning():
    """A single alias with no collision fires no alias-collision warning."""
    key = {"P-1": "Alice"}
    aliases = {"P-1": ["Al"]}
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", SecurityWarning)
        result = restore("hello Al", key, aliases=aliases, guard=False)
    assert result == "hello Alice"
