"""Every pipeline that drops entities after the merge must restore lost coverage.

The merge is absorbing: an overlapping loser is discarded because the winner
covers its bytes. A filter that then drops a winner un-covers everything that
winner absorbed. The merge-then-drop pipelines today are:

  - `src/argus_redact/glue/redact.py` — TWO independent blocks in the same
    file: `redact()`'s internal `_detect` pipeline (merge, then
    `filter_self_reference`, then the type filter) and `_pre_detected_pipeline`
    (merge, then the type filter only — it never runs `filter_self_reference`).
    Each restores coverage inline.
  - `crates/argus-redact-core/src/coverage.rs` — `finalize_entities`, the
    SINGLE Rust chokepoint: it merges, runs `filter_self_reference`, applies the
    optional type filter, and restores lost coverage. Both Rust faces — the
    `redact_l1.rs` fast path and `streaming.rs` — delegate their WHOLE post-merge
    sequence to it rather than carrying their own copy, so the invariant is
    enforced once, in one gated place, for both. (Before this was extracted, the
    two faces each carried a byte-identical inline copy — the exact drift risk a
    shared chokepoint removes.)

Two checks together enforce the invariant:

  1. `test_every_post_merge_pipeline_restores_lost_coverage` — for each inline
     merge-then-drop block in `_PIPELINES` (the two `redact.py` blocks + the
     `finalize_entities` chokepoint), a `restore_lost_coverage` call must appear
     in the WINDOW bounded by the next anchor in the same file (or EOF). An
     unbounded "restorer somewhere in the file" check would let a missing
     restorer for block N hide behind block N+1's restorer; the window forbids
     that.
  2. `test_rust_faces_route_through_the_finalize_chokepoint` — `redact_l1.rs`
     and `streaming.rs` must CALL `finalize_entities`, i.e. they carry no inline
     post-merge pipeline of their own and route through the gated chokepoint
     above. This is what lets check 1 guard both Rust faces by guarding
     `finalize_entities` alone.

`src/argus_redact/glue/redact_pseudonym_llm.py` used to be a fourth site with a
byte-identical copy of `redact()`'s `_pre_detected` block (that copy is why the
leak survived there after `redact()` was fixed). It now delegates, and
`test_pseudonym_llm_delegates_instead_of_copying_the_pipeline` asserts it still
has no pipeline of its own to guard.

What this gate does NOT do, stated plainly: it checks the hardcoded anchors in
`_PIPELINES` + the two chokepoint routers, nothing else. A brand-new
merge-then-drop pipeline in a file not listed here is invisible to it, and so is
a new dropping filter inlined into a listed file without a matching `_PIPELINES`
entry (or into a Rust face that also still calls `finalize_entities`). It is a
regression lock on today's known sites + the shared chokepoint, not a discovery
mechanism for tomorrow's. The anti-rot check pins the per-file anchor COUNT and
the router SET so the lists cannot quietly shrink; keeping them from quietly
falling BEHIND the code is a human review responsibility.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

# (path, anchor substring that proves a post-merge drop happens at THIS call
# site). Each anchor is verified unique-per-file below. `redact.py` appears
# twice (its two independent inline blocks); `coverage.rs` once (the
# `finalize_entities` chokepoint the two Rust faces share).
_PIPELINES: list[tuple[str, str]] = [
    ("src/argus_redact/glue/redact.py", "filter_self_reference(entities, hints)"),
    ("src/argus_redact/glue/redact.py", "_apply_type_filter(merged, types, types_exclude)"),
    ("crates/argus-redact-core/src/coverage.rs", "filter_self_reference(merged, hints)"),
]

# The Rust faces that must NOT carry their own inline post-merge pipeline: they
# route their whole merge -> filter -> restore through `finalize_entities`
# (coverage.rs), so guarding the chokepoint in `_PIPELINES` guards them too. If
# one grows an inline pipeline again, add it to `_PIPELINES` (with its own
# restorer window) and `_KNOWN_ANCHOR_COUNTS`, deliberately.
_CHOKEPOINT_ROUTERS: list[str] = [
    "crates/argus-redact-core/src/redact_l1.rs",
    "crates/argus-redact-core/src/streaming.rs",
]
_CHOKEPOINT_CALL = "finalize_entities("

# The one caller that must NOT grow a pipeline of its own. It had a
# byte-identical copy of `redact()`'s `_pre_detected` block, which is how the
# leak survived here after `redact()` was fixed; it now delegates instead.
_DELEGATOR = "src/argus_redact/glue/redact_pseudonym_llm.py"

# file -> expected number of independent _PIPELINES anchors in that file. A
# FILE-SET check alone is not enough: `redact.py` legitimately carries TWO
# independent anchors, and deleting just one leaves the file "covered" while
# the deleted block's restorer goes unguarded. Pinning the per-file COUNT
# catches that (see test_the_gate_is_not_vacuous).
_KNOWN_ANCHOR_COUNTS = {
    "src/argus_redact/glue/redact.py": 2,
    "crates/argus-redact-core/src/coverage.rs": 1,
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


def test_rust_faces_route_through_the_finalize_chokepoint():
    """The Rust fast path + streaming face must delegate their post-merge
    sequence to `finalize_entities`, not carry their own inline copy — so the
    single windowed check on the chokepoint (in `_PIPELINES`) guards both.

    If a face stops calling `finalize_entities`, it has either dropped the
    coverage restore (a PII leak) or inlined its own pipeline (drift risk) —
    either way the shared-chokepoint guarantee no longer covers it, so add it
    back to `_PIPELINES`/`_KNOWN_ANCHOR_COUNTS` with its own restorer window.
    """
    for rel in _CHOKEPOINT_ROUTERS:
        source = (_ROOT / rel).read_text(encoding="utf-8")
        assert _CHOKEPOINT_CALL in source, (
            f"{rel} no longer calls {_CHOKEPOINT_CALL!r} — it must route its "
            f"post-merge merge/filter/restore through the shared "
            f"`finalize_entities` chokepoint, or (if it grew its own inline "
            f"pipeline) be added to _PIPELINES with a restorer window so the "
            f"coverage invariant stays guarded. The invariant must not be "
            f"inlined un-gated."
        )


def test_pseudonym_llm_delegates_instead_of_copying_the_pipeline():
    """`redact_pseudonym_llm` must have NO merge-then-drop pipeline of its own.

    It used to carry a byte-identical copy of `redact()`'s `_pre_detected`
    block. A fix landing in `redact.py` and not in the copy is exactly how the
    post-merge coverage leak reached a public export unnoticed. Asserting the
    copy is absent is a stronger guarantee than asserting the copy calls the
    restorer: there is no second implementation left to drift.
    """
    source = (_ROOT / _DELEGATOR).read_text(encoding="utf-8")
    assert "_pre_detected_pipeline(" in source, (
        f"{_DELEGATOR} no longer delegates to _pre_detected_pipeline — if it "
        f"grew its own merge-then-drop block again, add it to _PIPELINES and "
        f"_KNOWN_ANCHOR_COUNTS so the restorer check covers it."
    )
    assert "merge_entities(" not in source, (
        f"{_DELEGATOR} calls merge_entities directly — it has grown a pipeline "
        f"of its own again. Either delegate to _pre_detected_pipeline, or add "
        f"this file back to _PIPELINES so its restorer call is guarded."
    )


def test_the_pipeline_list_still_covers_all_known_sites():
    """Anti-rot for the LISTS themselves, not just their contents: pins how many
    independent anchors `_PIPELINES` carries PER FILE (a file-set-only check
    would stay green if one of `redact.py`'s TWO independent blocks were silently
    deleted while the other stayed), AND pins the chokepoint-router SET so a Rust
    face cannot silently drop out of the routing check."""
    by_file: dict[str, int] = {}
    for rel, _anchor in _PIPELINES:
        by_file[rel] = by_file.get(rel, 0) + 1
    assert by_file == _KNOWN_ANCHOR_COUNTS, (
        f"_PIPELINES carries {by_file} anchor(s) per file, expected "
        f"{_KNOWN_ANCHOR_COUNTS} — an entry was silently deleted (fix: restore "
        f"it), or a new pipeline was added (fix: add it to _KNOWN_ANCHOR_COUNTS "
        f"too, deliberately, not as a side effect)."
    )
    assert set(_CHOKEPOINT_ROUTERS) == {
        "crates/argus-redact-core/src/redact_l1.rs",
        "crates/argus-redact-core/src/streaming.rs",
    }, (
        "the chokepoint-router set changed — a Rust face was added or removed "
        "from the finalize_entities routing check; update it deliberately."
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
