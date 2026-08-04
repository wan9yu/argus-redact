"""The coverage invariant must not move ordinary, unfiltered redaction output.

The invariant re-admits entities whose coverage a post-merge filter destroyed
(see `argus_redact.pure.coverage.restore_lost_coverage`). On the UNFILTERED
path — no `types=`/`types_exclude=` — it must never fire, because that is the
path the CI detection-recall gate (tests/benchmark/test_detection_baseline.py)
and the fast-mode benchmarks exercise: a never-fires guarantee there is what
let this ship as a security patch instead of behind a benchmark rebaseline.

It is NOT true that the invariant never fires at all, and this file does not
claim that. A `types=`/`types_exclude=` filter that legitimately drops a
merge winner is exactly the case this release fixed — those entities were
previously returned in plaintext, and re-admitting them is the fix working,
not a defect. Measured on the repo's own zh generator
(tests/benchmark/generators/zh.generate, count=200, seed=7, mode="fast",
salt=42):

    no filter                    0/200   (0.0%)
    types=["phone"]              0/200   (0.0%)
    types=["person"]            26/200  (13.0%)
    types_exclude=["address"]   56/200  (28.0%)

The middle two rows show firing is not simply "any type filter fires" — it
depends on whether the filtered-out type actually absorbed something else
during the merge (excluding "phone" never does on this corpus; excluding
"person" or "address" often does, because address/person spans are the ones
most often absorbing a neighboring phone/id_number during merge). This file
pins both properties: zero on the unfiltered path (checked against two
independent corpora), and the exact counts above on the type-filtered
regimes — so a future change that moves either is surfaced for review rather
than silently accepted.

Note the generator's own keyword is `seed`, not `salt` — that module's
`__main__` block passes `salt=` to `generate()`, which is a pre-existing bug
in that file (raises `TypeError`); do not copy that spelling here.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

from argus_redact import redact
from argus_redact.exceptions import SecurityWarning
from tests.benchmark.generators.zh import generate

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "realistic_scenarios.json"


def _coverage_warnings(text: str, lang, **redact_kwargs) -> list:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        redact(text, lang=lang, mode="fast", salt=42, **redact_kwargs)
    return [w for w in caught if "lost redaction coverage" in str(w.message)]


def _fired_ids(samples: list[dict], **redact_kwargs) -> list[str]:
    return [s["id"] for s in samples if _coverage_warnings(s["text"], s["lang"], **redact_kwargs)]


def test_never_fires_unfiltered_on_the_detection_baseline_corpus():
    """300 generated zh samples, seed=42 — the same corpus AND mode the CI
    detection-recall gate runs on (tests/benchmark/test_detection_baseline.py).
    This is the property that let the fix ship without a benchmark
    rebaseline: ordinary, unfiltered detection output is unchanged."""
    samples = generate(300, seed=42)
    fired = _fired_ids(samples)
    assert fired == [], (
        f"the coverage invariant fired on {len(fired)} benign UNFILTERED baseline "
        f"samples ({fired[:5]}); ordinary redaction output is moving and the "
        f"detection numbers must be re-measured before release"
    )


def test_never_fires_unfiltered_on_the_realistic_scenarios_fixture():
    """53 hand-written realistic documents, a second/independent corpus from
    the generated one above. Note the fixture's key is `input`, not `text`,
    and `lang` may be a list (e.g. `["en", "uk"]`) — both incompatible with
    `tests.conftest.parametrize_examples()`, so this loads the JSON directly."""
    scenarios = json.loads(_FIXTURES.read_text(encoding="utf-8"))
    fired = []
    for sc in scenarios:
        lang = sc.get("lang", "zh")
        if _coverage_warnings(sc["input"], lang):
            fired.append(sc["id"])
    assert fired == [], (
        f"the coverage invariant fired on {len(fired)} benign UNFILTERED realistic "
        f"scenarios ({fired[:5]}); see the baseline-corpus test above for what "
        f"this means"
    )


# Pinned type-filtered firing counts — see the module docstring for how these
# were measured. count=200/seed=7 is a corpus DISTINCT from the count=300/
# seed=42 CI detection-baseline corpus used above: pinning a different sample
# means a coincidental match to the baseline corpus's shape can't be mistaken
# for a real invariant.
_PINNED_COUNT = 200
_PINNED_SEED = 7


@pytest.mark.parametrize(
    "redact_kwargs,expected_fired",
    [
        pytest.param({}, 0, id="no_filter"),
        pytest.param({"types": ["phone"]}, 0, id="types_phone"),
        pytest.param({"types": ["person"]}, 26, id="types_person"),
        pytest.param({"types_exclude": ["address"]}, 56, id="types_exclude_address"),
    ],
)
def test_type_filtered_firing_rate_is_pinned(redact_kwargs, expected_fired):
    samples = generate(_PINNED_COUNT, seed=_PINNED_SEED)
    fired = _fired_ids(samples, **redact_kwargs)
    assert len(fired) == expected_fired, (
        f"coverage-invariant firing count for redact(**{redact_kwargs}) moved "
        f"from the pinned {expected_fired}/{_PINNED_COUNT} to "
        f"{len(fired)}/{_PINNED_COUNT} on the seed={_PINNED_SEED} zh corpus "
        f"(first few: {fired[:5]}). If this is an intentional detection or "
        f"invariant change, re-measure and update the pin (and the module "
        f"docstring); if not, something regressed."
    )


def test_the_lock_can_actually_observe_a_firing():
    """Positive control: a call that DOES lose coverage must be caught by the
    same detector these tests use, so a silent no-op could not pass them."""
    from unittest.mock import MagicMock, patch

    from argus_redact._types import NEREntity

    text = "Contact number 13800138000 for details"
    adapter = MagicMock()
    adapter.detect.return_value = [NEREntity(text[8:26], "medical", 8, 26, 0.75)]
    ner = MagicMock()
    ner.detect.return_value = []
    with (
        patch("argus_redact.glue.redact._get_ner_adapters", return_value=[ner]),
        patch("argus_redact.glue.redact._get_semantic_adapter", return_value=adapter),
        pytest.warns(SecurityWarning, match="lost redaction coverage"),
    ):
        redact(text, lang="en", mode="auto", salt=42, types=["phone"])
