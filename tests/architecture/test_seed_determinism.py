"""Seed-sweep determinism canary.

Task 3 sorted the two ``HashMap`` iteration sites in the Rust core that
``restore()`` and ``check_restore_safety()`` depend on for a deterministic
outcome: the alias-merge winner in ``restore_full``
(``crates/argus-redact-core/src/restore.rs``) and the pseudonym iteration
order inside ``check_restore_safety``. Both were previously unsorted walks
whose visit order is randomized per process — nondeterministic across runs,
and silent (no signal which identity or which warning ordering you'd get).

This test retires that whole defect CLASS by machine: it runs the
determinism-sensitive paths in a fresh subprocess per ``PYTHONHASHSEED``
value and fails on ANY divergence across the sweep, so a future regression
that reintroduces an unsorted ``HashMap`` walk on one of these paths fails
CI immediately instead of shipping a coin-flip.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parents[2] / "src"

_SEEDS = range(24)

# Self-contained subprocess script covering the three determinism-sensitive
# paths named in the task brief:
#   1. restore() with COLLIDING aliases (two fakes -> two originals sharing
#      one alias string) — the sorted-first fake must win every seed.
#   2. restore() with NON-colliding aliases across several fakes — the
#      alias-merge order must not affect the output.
#   3. A redact() -> check_restore_safety() -> restore() round trip, with
#      every pseudonym amplified so the sorted `key.keys()` iteration order
#      (and the order of the returned warnings) is actually exercised.
# The three outputs are concatenated with a separator and printed with no
# trailing newline so every seed's stdout is byte-for-byte comparable.
_SCRIPT = (
    f"import sys; sys.path.insert(0, {str(_SRC_DIR)!r})\n"
    "import warnings; warnings.simplefilter('ignore')\n"
    "from argus_redact import redact\n"
    "from argus_redact.pure.restore import restore, check_restore_safety\n"
    "key_collide = {'P-1': 'Alice', 'P-2': 'Bob', 'P-3': 'Carol'}\n"
    "aliases_collide = {'P-1': ['Shared'], 'P-2': ['Shared'], 'P-3': ['Shared']}\n"
    "out1 = restore('hello Shared', key_collide, aliases=aliases_collide, guard=False)\n"
    "key_plain = {'P-1': 'Alice', 'P-2': 'Bob', 'P-3': 'Carol', 'P-4': 'Dave', 'P-5': 'Eve'}\n"
    "aliases_plain = {'P-1': ['Ai'], 'P-2': ['Baob'], 'P-3': ['Karou'], "
    "'P-4': ['Daiwei'], 'P-5': ['Yifu']}\n"
    "out2 = restore('Ai Baob Karou Daiwei Yifu', key_plain, aliases=aliases_plain, guard=False)\n"
    "text = '请拨打 13912345678 联系王建国。王建国的电话是13911112222,请再次确认。'\n"
    "redacted, key3 = redact(text, salt=42, mode='fast', lang='zh')\n"
    "llm_output = redacted + ' ' + ' '.join(sorted(key3, reverse=True))\n"
    "warnings3 = check_restore_safety(redacted, llm_output, key3)\n"
    "out3 = restore(llm_output, key3, guard=False)\n"
    "print(out1 + '|' + out2 + '|' + chr(10).join(warnings3) + '|' + out3, end='')\n"
)


def test_restore_paths_are_identical_across_hash_seeds():
    """Sweep PYTHONHASHSEED over a fresh subprocess per value; the alias-merge
    winner, the non-colliding alias merge, and the check_restore_safety
    warning ordering must all be byte-for-byte identical across every seed.

    Pre-Task-3, the alias-collision winner in part 1 alternated between
    "Alice" and one of the other originals depending on the process's HashMap
    iteration order (see tests/core/test_alias_collision.py), and the
    check_restore_safety warning list in part 3 could come back in a
    different order — this canary would have failed on that sweep.
    """
    outputs: dict[str, list[int]] = {}
    failures: list[tuple[int, str]] = []
    for seed in _SEEDS:
        proc = subprocess.run(
            [sys.executable, "-c", _SCRIPT],
            # PYTHONUTF8=1 forces the child's stdout to UTF-8 so printing the
            # Chinese redacted/restored text doesn't hit a UnicodeEncodeError
            # on a Windows cp1252 console.
            env={**os.environ, "PYTHONHASHSEED": str(seed), "PYTHONUTF8": "1"},
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        if proc.returncode != 0:
            failures.append((seed, proc.stderr))
            continue
        outputs.setdefault(proc.stdout, []).append(seed)

    assert failures == [], f"subprocess failed for seeds: {failures}"
    assert len(outputs) == 1, f"nondeterministic output across seeds: {outputs}"
