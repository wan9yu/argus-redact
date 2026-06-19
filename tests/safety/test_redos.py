"""Org/school detection must stay ~linear (no catastrophic backtracking) and not hang."""
import time

import pytest

from argus_redact import redact


def _elapsed(text):
    t0 = time.perf_counter()
    redact(text, lang="zh", mode="fast", salt=42)
    return time.perf_counter() - t0


def _elapsed_lang(text, lang):
    t0 = time.perf_counter()
    redact(text, lang=lang, mode="fast", salt=42)
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


# lang="shared" is not a valid standalone lang — use real langs with
# IP/email-shaped fillers that stress the shared pattern set instead.
@pytest.mark.parametrize(
    "lang,filler",
    [
        ("zh", "有限责任"),       # zh org-suffix partial, never completes
        ("en", "Aa1-"),           # alphanumeric filler, stresses en patterns
        ("en", "1.2.3."),         # IP-octet partial, stresses shared IP patterns
    ],
    ids=["zh-partial-suffix", "en-alnum", "en-ip-partial"],
)
def test_pattern_set_no_catastrophic_backtracking(lang, filler):
    text = filler * 40000  # ~160-200 KB pathological; never completes a match
    assert _elapsed_lang(text, lang) < 5.0
