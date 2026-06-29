"""Pin pi_perf's standalone corpora equal to the shared _corpus source.

pi_perf.py inlines the perf corpora on purpose (it runs on a repo-less aarch64
device with only the wheel). This guard makes that inline copy provably equal to
tests/benchmark/_corpus.py, so the standalone copy cannot silently drift from the
corpora the in-repo perf scripts (run_perf_budget / bench_l1 / perf_profile) use.
"""

import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import _corpus  # noqa: E402
import pi_perf  # noqa: E402


def test_pi_perf_corpora_match_shared_corpus():
    assert pi_perf._ZH_1KB == _corpus._ZH_1KB
    assert pi_perf._EN_1KB == _corpus._EN_1KB
    assert pi_perf._ZH_SHORT == _corpus._ZH_SHORT
    assert pi_perf._EN_SHORT == _corpus._EN_SHORT
    assert pi_perf._ZH_LONG == _corpus._ZH_LONG
    assert pi_perf._EN_LONG == _corpus._EN_LONG
    # the (lang, text) throughput map matches too
    assert pi_perf.CORPORA == _corpus._THROUGHPUT_CORPUS
