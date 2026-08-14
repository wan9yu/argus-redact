"""The restore session's concurrency guarantee, pinned against the binding.

The documented contract (``argus_redact.streaming.StreamingRestorer``,
``pure.restore.make_structured_restorer``, ``docs/api-reference.md``) is that a
SHARED restore session used concurrently from two threads raises
``Already borrowed`` at the runtime borrow check rather than silently splicing
one caller's restored PII into another's output.

That guarantee is only real if ``StructuredRestorer.restore_cell`` takes an
EXCLUSIVE PyO3 borrow (``&mut self``), matching the redact side's
``redact_cell``. Under a SHARED borrow (``&self``) PyO3 permits unlimited
concurrent shared borrows, so nothing ever raises and two threads corrupt each
other's output undetected. This test therefore FAILS on ``&self`` (no raise is
ever observed) and PASSES on ``&mut self``.

Determinism: ``restore_cell`` detaches the interpreter lock for its pure-Rust
substitution, so the exclusive borrow is held ACROSS a GIL-released window. A
large key makes that window long enough that a second thread sharing the
session reliably attempts its borrow while the first still holds it — the
losing thread's borrow is refused for the whole duration of the winner's call,
so a conflict is observed within the very first overlapping iterations rather
than depending on a tight timing coincidence.
"""

from __future__ import annotations

import threading

import argus_redact._core as _core

# Big enough that one restore_cell spends real time in its GIL-released Rust
# section (so the exclusive borrow is genuinely held while another thread tries
# to take it), and the text mentions many keys so each call does real work.
_KEY = {f"P-{i:05d}": f"Person Number {i}" for i in range(12000)}
_TEXT = " ".join(f"P-{i:05d}" for i in range(0, 12000, 3))
_ITERATIONS = 60


def _hammer(restore_one, iterations, errors, barrier):
    barrier.wait()
    for _ in range(iterations):
        try:
            restore_one()
        except Exception as exc:  # noqa: BLE001 — the message IS the contract
            errors.append(str(exc))


def _run_conflict_probe(restore_one) -> list[str]:
    """Two barrier-synchronised threads hammer the same session; collect every
    error string either thread saw."""
    errors: list[str] = []
    barrier = threading.Barrier(2)
    threads = [
        threading.Thread(target=_hammer, args=(restore_one, _ITERATIONS, errors, barrier))
        for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def test_shared_core_restorer_concurrent_restore_cell_raises_already_borrowed():
    """The raw ``_core.StructuredRestorer`` binding — the SSOT of the
    guarantee. Concurrent ``restore_cell`` on one shared instance must raise
    ``Already borrowed``, never restore both cells silently."""
    restorer = _core.StructuredRestorer(_KEY)
    restorer.restore_cell(_TEXT)  # warm lazy statics before the timed overlap

    errors = _run_conflict_probe(lambda: restorer.restore_cell(_TEXT))

    assert any("Already borrowed" in e for e in errors), (
        "a shared _core.StructuredRestorer used concurrently from two threads "
        "must raise `Already borrowed` (the exclusive-borrow backstop); saw "
        f"{len(errors)} error(s): {errors[:3]}"
    )
