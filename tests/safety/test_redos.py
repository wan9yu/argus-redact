"""Org/school detection must stay ~linear (no catastrophic backtracking) and not hang."""
import time
from argus_redact import redact


def _elapsed(text):
    t0 = time.perf_counter()
    redact(text, lang="zh", mode="fast", salt=42)
    return time.perf_counter() - t0


def test_org_heavy_input_is_fast():
    text = "北京某某科技咨询管理有限公司，" * 8000  # ~120KB legit orgs
    assert _elapsed(text) < 5.0


def test_long_cjk_no_suffix_is_fast():
    text = "某" * 100000  # long CJK, no org suffix anywhere
    assert _elapsed(text) < 5.0


def test_near_suffix_adversarial_is_fast():
    text = "北京" + "有限责任" * 30000  # repeated partial suffix, never completes 公司
    assert _elapsed(text) < 5.0
