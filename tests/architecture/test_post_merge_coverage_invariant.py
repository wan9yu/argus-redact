"""Every pipeline that drops entities after the merge must restore lost coverage.

The merge is absorbing: an overlapping loser is discarded because the winner
covers its bytes. A filter that then drops a winner un-covers everything that
winner absorbed. Four sites run merge-then-drop today:

  - `src/argus_redact/glue/redact.py` — TWO independent blocks in the same
    file: `redact()`'s internal `_detect` pipeline (merge, then
    `filter_self_reference`, then the type filter) and `redact()`'s own
    `_pre_detected` branch (merge, then the type filter only — it never runs
    `filter_self_reference`).
  - `src/argus_redact/glue/redact_pseudonym_llm.py` — its own `_pre_detected`
    branch, a separate copy of the same shape (merge, then the type filter),
    not a call-through to `redact.py`. This is the site a prior version of
    this gate could not see: it hardcoded `filter_self_reference` as the
    "this is a post-merge pipeline" anchor, and this file never calls that
    function, so the gate silently had no opinion about it while it leaked.
  - `crates/argus-redact-core/src/redact_l1.rs` — the Rust fast path (merge,
    `filter_self_reference`, type filter).
  - `crates/argus-redact-core/src/streaming.rs` — the Rust streaming path
    (same shape as `redact_l1.rs`).

This gate asserts every block above is followed by a `restore_lost_coverage`
call before the NEXT dropping block in the same file (or EOF, for the last
block) — not just "somewhere in the file" — so removing the restorer for one
block cannot hide behind a second block's restorer elsewhere in the same
file. A new dropping filter in an existing pipeline, or a fifth copy of the
pipeline anywhere else, should make this gate fail loudly rather than pass
silently.

A separate anti-rot check pins the per-file ANCHOR COUNT in `_PIPELINES`
(`redact.py` → 2, everything else → 1), not just the set of files present —
a file-set check alone would stay green if `redact.py`'s two independent
blocks were collapsed to one entry, silently un-guarding whichever block's
row was deleted.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

# (path, anchor substring that proves a post-merge drop happens at THIS call
# site). Each anchor is verified unique-per-file below (test_the_gate_is_not_vacuous
# also checks the ordering logic itself). `redact.py` appears twice — once per
# independent block — everything else appears once.
_PIPELINES: list[tuple[str, str]] = [
    ("src/argus_redact/glue/redact.py", "filter_self_reference(entities, hints)"),
    ("src/argus_redact/glue/redact.py", "_apply_type_filter(merged, types, types_exclude)"),
    (
        "src/argus_redact/glue/redact_pseudonym_llm.py",
        "_apply_type_filter(merged, types, types_exclude)",
    ),
    ("crates/argus-redact-core/src/redact_l1.rs", "filter_self_reference(merged, &hints)"),
    ("crates/argus-redact-core/src/streaming.rs", "filter_self_reference(merged, &hints)"),
]

# file -> expected number of independent _PIPELINES anchors in that file. A
# FILE-SET check alone is not enough: `redact.py` legitimately carries TWO
# independent anchors (its `_detect()` block and its separate `_pre_detected`
# block), and deleting just one of them leaves the file "covered" — the
# remaining anchor keeps `covered == {files}` true even though the deleted
# block's restorer is now completely unguarded. Pinning the per-file COUNT
# catches that; a file-only set does not (see test_the_gate_is_not_vacuous
# for a live demonstration in the same style as the rest of this file).
_KNOWN_ANCHOR_COUNTS = {
    "src/argus_redact/glue/redact.py": 2,
    "src/argus_redact/glue/redact_pseudonym_llm.py": 1,
    "crates/argus-redact-core/src/redact_l1.rs": 1,
    "crates/argus-redact-core/src/streaming.rs": 1,
}

_RESTORER = re.compile(r"restore_lost_coverage")


def test_every_post_merge_pipeline_restores_lost_coverage():
    by_file: dict[str, list[str]] = {}
    for rel, anchor in _PIPELINES:
        by_file.setdefault(rel, []).append(anchor)

    for rel, anchors in by_file.items():
        source = (_ROOT / rel).read_text(encoding="utf-8")

        positions = []
        for anchor in anchors:
            at = source.find(anchor)
            assert at != -1, (
                f"{rel} no longer contains {anchor!r} — this gate's premise "
                f"rotted; re-derive the pipeline list against the current source."
            )
            assert source.count(anchor) == 1, (
                f"{rel} contains {anchor!r} more than once — the anchor is no "
                f"longer specific enough to isolate one dropping block; pick a "
                f"more precise anchor."
            )
            positions.append((at, anchor))

        # Each anchor's restorer must appear in a WINDOW bounded by the next
        # anchor in the same file (or EOF for the last one). An unbounded
        # "restorer found anywhere after this anchor" check would let a
        # missing restorer for block N hide behind block N+1's restorer
        # later in the same file — this bounds the search so it cannot.
        ordered = sorted(positions)
        for i, (at, anchor) in enumerate(ordered):
            window_end = ordered[i + 1][0] if i + 1 < len(ordered) else len(source)
            window = source[at:window_end]
            assert _RESTORER.search(window), (
                f"{rel} drops entities after the merge (at {anchor!r}) but "
                f"never calls restore_lost_coverage before the next dropping "
                f"site (or end of file) — PII absorbed by a dropped winner "
                f"would be returned in plaintext."
            )


def test_the_pipeline_list_still_covers_all_four_known_sites():
    """Anti-rot for the LIST itself, not just its contents: pins how many
    independent anchors `_PIPELINES` carries PER FILE, not merely which files
    appear at all. A file-set-only check would stay green if one of
    `redact.py`'s TWO independent blocks (its `_detect()` path — the one
    every plain `redact()` call uses — and its separate `_pre_detected`
    branch) were silently deleted while the other stayed: the file is still
    "covered", so a set comparison can't tell the difference, even though the
    deleted block's restorer call would now be completely unguarded — and the
    per-block windowing in the test above only checks anchors that are
    actually IN `_PIPELINES`, so a deleted anchor is invisible to it too.
    Pinning the per-file anchor COUNT closes that gap."""
    by_file: dict[str, int] = {}
    for rel, _anchor in _PIPELINES:
        by_file[rel] = by_file.get(rel, 0) + 1
    assert by_file == _KNOWN_ANCHOR_COUNTS, (
        f"_PIPELINES carries {by_file} anchor(s) per file, expected "
        f"{_KNOWN_ANCHOR_COUNTS} — an entry was silently deleted (fix: restore "
        f"it), or a new pipeline was added (fix: add it to _KNOWN_ANCHOR_COUNTS "
        f"too, deliberately, not as a side effect)."
    )


def test_the_gate_is_not_vacuous():
    """Positive control: the regex — and the ordering logic around it — must
    actually fail on a broken pipeline, so the gate cannot silently pass on
    an empty match or an out-of-order match."""
    # Bare presence: no restorer anywhere.
    no_restorer = "let merged = merge(entities);\nfilter_self_reference(merged, &hints)\n"
    assert not _RESTORER.search(no_restorer)

    # Ordering: a restorer that appears BEFORE the anchor (i.e. belongs to a
    # prior block) must not satisfy a search anchored AFTER it — proves the
    # `.search(window)` bound is doing real work, not just checking presence
    # anywhere in the string.
    restorer_before_anchor_only = "restore_lost_coverage(y)\nfilter_self_reference(x)\n"
    at = restorer_before_anchor_only.find("filter_self_reference(x)")
    assert not _RESTORER.search(restorer_before_anchor_only[at:])

    # The healthy shape passes.
    healthy = "filter_self_reference(x)\nrestore_lost_coverage(y)\n"
    at = healthy.find("filter_self_reference(x)")
    assert _RESTORER.search(healthy[at:])
