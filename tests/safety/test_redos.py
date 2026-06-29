"""Org/school (and other CJK-run) regexes must stay non-catastrophic.

We deliberately do NOT use wall-clock bounds. Those are flaky across CI runners
(a slow runner exceeds an arbitrary seconds budget on a large but perfectly
*linear* input) and are redundant: the real, DETERMINISTIC ReDoS guard is the
Rust core's ``BACKTRACK_LIMIT`` (a fixed step budget). A catastrophic-backtracking
regex exhausts that budget and aborts with a clean error (fail-closed) instead of
hanging, and the backtrack step count for a given (pattern, input) is
platform-independent. So we assert that realistic large / adversarial inputs
COMPLETE within the budget: if a pattern ever regresses to super-linear
backtracking, a large input exceeds the budget and raises here — the same way on
every platform. (Throughput/latency is covered separately by the perf-budget
gate; this file only guards against catastrophic backtracking.)
"""

import pytest

from argus_redact import redact


@pytest.mark.parametrize(
    "text",
    [
        "北京某某科技咨询管理有限公司，" * 8000,  # ~120 KB legit org-heavy
        "某" * 100000,  # long CJK run, no org suffix
        "北京" + "有限责任" * 30000,  # repeated partial suffix, never completes
    ],
    ids=["legit-orgs", "no-suffix", "partial-suffix"],
)
def test_org_school_patterns_complete_within_backtrack_budget(text):
    # Completing (not raising) means the scan stayed within BACKTRACK_LIMIT. A
    # super-linear regression would exhaust the budget and raise (fail-closed),
    # failing this test deterministically — no timing assertion needed.
    redact(text, lang="zh", mode="fast", salt=42)
