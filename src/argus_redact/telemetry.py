"""Performance telemetry — opt-in timing logs for redact() calls.

Usage:
    # Via environment variable (writes JSONL file):
    ARGUS_PERF_LOG=perf.jsonl python my_app.py

    # Via hook API (custom sink):
    from argus_redact.telemetry import set_perf_hook
    set_perf_hook(lambda record: my_prometheus.observe(record.total_ms))

Configuration (env vars):
    ARGUS_PERF_LOG       — path to JSONL file (enables file logging)
    ARGUS_PERF_SLOW_MS   — slow call threshold in ms (default: 50)
    ARGUS_PERF_SAMPLE    — sampling rate for fast calls, 0.0-1.0 (default: 0.01)
"""

from __future__ import annotations

import json
import os
import random
import threading
from dataclasses import asdict, dataclass, field
from typing import Callable


@dataclass
class PerfRecord:
    """One redact() call's performance telemetry."""

    # Identity
    version: str
    timestamp: str

    # Input
    text_len: int
    text_ascii_ratio: float
    lang: list[str]
    mode: str

    # Pipeline timing (ms)
    normalize_ms: float
    layer_1_ms: float
    layer_1b_person_ms: float
    layer_2_ms: float
    layer_3_ms: float
    merge_ms: float
    replace_ms: float
    total_ms: float

    # Output
    entities_found: int
    entity_types: list[str]

    # Environment
    rust_core: bool

    # Sampling metadata
    slow: bool = False
    sampled: bool = False


# ── Hook management ──

_hook: Callable[[PerfRecord], None] | None = None
_hook_lock = threading.Lock()


def set_perf_hook(hook: Callable[[PerfRecord], None] | None) -> None:
    """Set a custom performance hook. Pass None to disable."""
    global _hook
    with _hook_lock:
        _hook = hook


def get_perf_hook() -> Callable[[PerfRecord], None] | None:
    return _hook


def emit(record: PerfRecord) -> None:
    """Emit a record to the current hook (if any). Called by redact()."""
    hook = _hook
    if hook is None:
        return

    slow_ms = float(os.environ.get("ARGUS_PERF_SLOW_MS", "50"))
    record.slow = record.total_ms >= slow_ms
    hook(record)


# ── Default file hook ──

_file_lock = threading.Lock()


def _file_hook(record: PerfRecord) -> None:
    """Write record as one JSON line to ARGUS_PERF_LOG file.

    Sampling: slow calls always logged, fast calls sampled at ARGUS_PERF_SAMPLE rate.
    """
    path = os.environ.get("ARGUS_PERF_LOG")
    if not path:
        return

    sample_rate = float(os.environ.get("ARGUS_PERF_SAMPLE", "0.01"))
    if not record.slow and not (sample_rate > 0 and random.random() < sample_rate):
        return
    if not record.slow:
        record.sampled = True

    line = json.dumps(asdict(record), ensure_ascii=False)
    with _file_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def _init_file_hook() -> None:
    """Initialize file hook if ARGUS_PERF_LOG is set."""
    if os.environ.get("ARGUS_PERF_LOG"):
        set_perf_hook(_file_hook)


# Auto-init on import
_init_file_hook()
