"""Tests for the perf-budget baseline comparator's provenance gate.

An untested gate is exactly the defect class the perf-budget hardening work
exists to remove: the platform/python/commit provenance refusal in
compare_baseline.py backs `.github/workflows/perf.yml` and, via the
`workflow_call` wiring in `release.yml`, the release publish gate itself. This
locks in the contract:

  - a mismatch on platform, on python (major.minor), or a missing/"unknown"
    commit on either side REFUSES the comparison (exit 2) before any
    measurement delta is computed;
  - once provenance passes, both sides' `commit` labels are PRINTED but never
    equality-compared (the baseline's commit is free-text provenance, not a
    SHA the current run could ever match);
  - with ARGUS_PERF_ADVISORY set (local `make perf-check`), a *platform*
    mismatch is downgraded to a printed warning instead of refusing — but a
    python-minor mismatch or a missing commit still refuses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tests.benchmark.compare_baseline import _check_provenance, main

_BASELINE = {
    "schema_version": 1,
    "platform": "ubuntu-latest",
    "python": "3.12",
    "commit": "baseline-commit-label",
    "measurements": {"import_time_ms": 80.0},
}


def _current(**overrides: object) -> dict:
    doc = {
        "schema_version": 1,
        "platform": "ubuntu-latest",
        "python": "3.12",
        "commit": "current-commit-sha",
        "measurements": {"import_time_ms": 80.0},
    }
    doc.update(overrides)
    return doc


def _write(tmp_path: Path, name: str, doc: dict) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


@pytest.fixture(autouse=True)
def _no_advisory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default every test to the strict (non-advisory) gate; the advisory tests
    opt back in explicitly, so a stray ARGUS_PERF_ADVISORY in the runner env
    can't silently soften the strict cases."""
    monkeypatch.delenv("ARGUS_PERF_ADVISORY", raising=False)


# ── _check_provenance unit tests (returns (problems, warnings)) ──


def test_matching_provenance_has_no_problems() -> None:
    problems, warnings = _check_provenance(_current(), _BASELINE)
    assert problems == []
    assert warnings == []


def test_platform_mismatch_is_a_problem() -> None:
    problems, warnings = _check_provenance(_current(platform="darwin"), _BASELINE)
    assert len(problems) == 1
    assert "platform mismatch" in problems[0]
    assert "darwin" in problems[0]
    assert "ubuntu-latest" in problems[0]
    assert warnings == []


def test_python_minor_mismatch_is_a_problem() -> None:
    problems, _warnings = _check_provenance(_current(python="3.11"), _BASELINE)
    assert len(problems) == 1
    assert "python mismatch" in problems[0]


@pytest.mark.parametrize("which", ["current", "baseline"])
@pytest.mark.parametrize("bad_commit", [None, "", "unknown"])
def test_missing_or_unknown_commit_on_either_side_is_a_problem(
    which: str, bad_commit: str | None
) -> None:
    current = _current()
    baseline = dict(_BASELINE)
    target = current if which == "current" else baseline
    if bad_commit is None:
        target.pop("commit", None)
    else:
        target["commit"] = bad_commit

    problems, _warnings = _check_provenance(current, baseline)

    assert problems == [f"{which} measurement has no commit/provenance label"]


def test_differing_but_present_commits_are_not_a_problem() -> None:
    """`commit` is a provenance label to print, never an equality check — the
    baseline's commit is free-text prose, not a SHA the current run could
    match."""
    problems, warnings = _check_provenance(_current(commit="totally-different-label"), _BASELINE)
    assert problems == []
    assert warnings == []


# ── advisory mode (ARGUS_PERF_ADVISORY) ──


def test_advisory_downgrades_platform_mismatch_to_a_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_PERF_ADVISORY", "1")
    problems, warnings = _check_provenance(_current(platform="darwin"), _BASELINE)
    assert problems == []  # no refusal
    assert len(warnings) == 1
    assert "ADVISORY" in warnings[0]
    assert "platform mismatch" in warnings[0]


def test_advisory_does_not_downgrade_python_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_PERF_ADVISORY", "1")
    problems, warnings = _check_provenance(_current(python="3.11"), _BASELINE)
    assert any("python mismatch" in p for p in problems)  # still refuses
    assert warnings == []


def test_advisory_does_not_downgrade_missing_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUS_PERF_ADVISORY", "1")
    problems, _warnings = _check_provenance(_current(commit="unknown"), _BASELINE)
    assert problems == ["current measurement has no commit/provenance label"]


# ── main() end-to-end (argv + stdout) ──


def test_main_refuses_on_platform_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    cur = _write(tmp_path, "current.json", _current(platform="darwin"))
    base = _write(tmp_path, "baseline.json", _BASELINE)
    monkeypatch.setattr(sys, "argv", ["compare_baseline.py", cur, base])

    exit_code = main()

    assert exit_code == 2
    out = capsys.readouterr().out
    assert "Refusing to compare" in out
    assert "platform mismatch" in out


def test_main_advisory_platform_mismatch_does_not_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setenv("ARGUS_PERF_ADVISORY", "1")
    cur = _write(tmp_path, "current.json", _current(platform="darwin"))
    base = _write(tmp_path, "baseline.json", _BASELINE)
    monkeypatch.setattr(sys, "argv", ["compare_baseline.py", cur, base])

    exit_code = main()

    assert exit_code in (0, 1)  # compared, not refused
    out = capsys.readouterr().out
    assert "ADVISORY" in out
    assert "Refusing to compare" not in out


def test_main_advisory_still_refuses_python_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setenv("ARGUS_PERF_ADVISORY", "1")
    cur = _write(tmp_path, "current.json", _current(python="3.11"))
    base = _write(tmp_path, "baseline.json", _BASELINE)
    monkeypatch.setattr(sys, "argv", ["compare_baseline.py", cur, base])

    assert main() == 2
    assert "python mismatch" in capsys.readouterr().out


def test_main_prints_both_commits_without_equality_comparing_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    cur = _write(tmp_path, "current.json", _current(commit="totally-different-label"))
    base = _write(tmp_path, "baseline.json", _BASELINE)
    monkeypatch.setattr(sys, "argv", ["compare_baseline.py", cur, base])

    exit_code = main()

    out = capsys.readouterr().out
    assert "current commit:  totally-different-label" in out
    assert "baseline commit: baseline-commit-label" in out
    # Provenance passed despite the differing commit labels — never refused
    # (exit 2) on that basis.
    assert exit_code in (0, 1)


def test_main_exits_zero_on_matching_measurements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    cur = _write(tmp_path, "current.json", _current())
    base = _write(tmp_path, "baseline.json", _BASELINE)
    monkeypatch.setattr(sys, "argv", ["compare_baseline.py", cur, base])

    assert main() == 0


def test_main_exits_one_on_a_real_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    cur = _write(
        tmp_path,
        "current.json",
        _current(measurements={"import_time_ms": 80.0 * 2}),  # +100%, past ±25%
    )
    base = _write(tmp_path, "baseline.json", _BASELINE)
    monkeypatch.setattr(sys, "argv", ["compare_baseline.py", cur, base])

    exit_code = main()

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Performance regressions detected" in out
