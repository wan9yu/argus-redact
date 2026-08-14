"""Shared streaming loader for the ai4privacy/pii-masking-400k benchmark.

The dataset streams from the Hugging Face Hub over the network. When the
`datasets` package is absent, or the Hub is unreachable (offline runner, a
`ReadTimeoutError`, HF outage), the benchmark simply cannot run — that is a
SKIP condition, never a failure. A network outage must not masquerade as a
detection regression, and these benchmarks are `slow`-marked, so CI already
deselects them; the skip only matters to a manual/offline run.
"""

import importlib.util

import pytest

HAS_DATASETS = importlib.util.find_spec("datasets") is not None

_DATASET = "ai4privacy/pii-masking-400k"


def iter_examples(max_examples):
    """Yield up to ``max_examples`` rows from the streaming ``train`` split.

    Skips the calling test if `datasets` is not installed or the dataset cannot
    be reached. The network I/O for a streaming dataset happens lazily *during*
    iteration, so both the load and the pull are guarded here. Scoring and
    detection stay in the caller, so a genuine code error there still surfaces
    as a failure rather than being swallowed as a skip.
    """
    if not HAS_DATASETS:
        pytest.skip("datasets not installed")

    from datasets import load_dataset

    try:
        ds = load_dataset(_DATASET, split="train", streaming=True)
        for i, ex in enumerate(ds):
            if i >= max_examples:
                return
            yield ex
    except Exception as exc:  # noqa: BLE001 — any Hub/network failure is a skip, not a fail
        pytest.skip(f"ai4privacy dataset unreachable (network required): {exc!r}")
