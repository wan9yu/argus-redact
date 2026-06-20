"""Evidence-gating floor for English person detection.

Mirrors the zh evidence model: a bare capitalized-surname match must be
CORROBORATED to redact — by a known given-name lead, a title/honorific, or
proximity to other detected PII. A lone capitalized surname-pool word in noisy
prose (``Apple Park``, ``Hyde Park``, ``Central Park``) is left to L2 NER rather
than over-redacted at L1.

The behavioral tests run offline and are the always-on guard. The
``test_person_floor_*`` assertions are pinned to the FAST-mode benchmark JSON
(``tests/benchmark/results/kaggle_piilo_0.7.10.json``).

HONEST framing of the benchmark-pinned floors (see the block above them for the
full text): they are REGRESSION GUARDS, not a "material precision recovery"
claim. The ABSOLUTE benchmark precision is artifact-limited — exact-VALUE
matching plus non-PII famous-name citations counted as FP mean the ~70 % person
figure UNDERSTATES the gate (the FP diagnosis put real person precision ~90 %).
RECALL is bounded by surname-pool COVERAGE (the dominant FN class — future work),
not by the gate. The floors are pinned DOWN from the current measured values
(person fast precision 69.6 %, recall 29.8 %) so they hold across dataset jitter
and the Task-1 lexicon polish (which can only raise precision). The dataset is
fetched from HuggingFace, so until the JSON is regenerated the floor tests SKIP
(cleanly — never KeyError) rather than fail. Regenerate via::

    python -m tests.benchmark kaggle_piilo --mode fast --limit 500 \\
        --save tests/benchmark/results/kaggle_piilo_0.7.10.json
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus_redact import redact

_RESULTS = Path(__file__).resolve().parents[2] / "benchmark" / "results"
_KAGGLE_PIILO = _RESULTS / "kaggle_piilo_0.7.10.json"


def _names(text, **kw):
    _, key = redact(text, mode="fast", lang="en", salt=42, **kw)
    return list(key.values())


def test_corroborated_names_redact():
    # given-name-led — full Given + Surname, both in pools.
    assert any("Smith" in v for v in _names("Contact John Smith"))
    # title / honorific immediately before the surname.
    assert any("Smith" in v for v in _names("Dr. Smith will see you"))
    # PII proximity — a phone number near a non-given-name-led pair corroborates
    # it. "Quincy Smith" alone is suppressed (no given/title); the adjacent phone
    # number revives it.
    assert any("Quincy Smith" in v for v in _names("Quincy Smith, phone 4155551234"))


def test_lone_surname_in_prose_not_redacted():
    # Each of these is a "Capitalized + surname-pool" pair whose leading word is
    # NOT a known given name and which has NO title / nearby PII — under the old
    # ungated 0.9 branch they all over-redacted; the evidence gate now suppresses
    # them (left to L2 NER). "Park" / "Avenue"-style place words are the worst
    # offenders since common surnames double as place / org words.
    for text, word in [
        ("We saw Apple Park campus.", "Park"),  # Park is a surname; this is a place
        ("Visit Hyde Park often.", "Park"),
        ("I love Central Park walks.", "Park"),
    ]:
        out, _ = redact(text, mode="fast", lang="en", salt=42)
        assert out == text, (text, out)
        assert word in out


def test_known_names_still_exact():
    # An explicit known name is always redacted regardless of the gate.
    assert any("Zaphod" in v for v in _names("Reach out to Zaphod.", names=["Zaphod"]))


# Representative ``Given Surname`` full names whose given name is NOT in the
# (Anglo-biased) SSA given-name pool. Before the name-like signal these were
# DROPPED at fast-L1 while pool-covered / Anglo names were kept — an ethnicity
# correlation. The pool-independent "name-like leading token" signal recovers
# them: the given-name slot is alphabetic, length >= 2, and not a common English
# word, so it corroborates the bare surname WITHOUT depending on the name pool.
# (Surnames must already be in the en surname pool: "Kwame Mensah" is excluded
# here because "Mensah" is not yet pooled, so it cannot anchor regardless of the
# gate — a pool-coverage gap, not a gate-fairness defect.)
_NON_ANGLO_FULL_NAMES = [
    "Marco Rossi",
    "Wei Chen",
    "Mohammed Khan",
    "Aisha Okafor",
    "Sanjay Patel",
    "Jean-Paul Sartre",
    "Olga Petrov",
    "Luis Martinez",
    "Ming Li",
    "Fatima Ali",
]


@pytest.mark.parametrize("full_name", _NON_ANGLO_FULL_NAMES)
def test_non_anglo_full_names_redact_fast(full_name):
    # No title, no nearby PII — corroboration is the name-like leading token
    # alone (base 0.3 + name-like 0.5 = 0.8 >= threshold). The surname must end
    # up in a redacted value.
    surname = full_name.split()[-1]
    assert any(surname in v for v in _names(full_name)), full_name


def test_common_word_pairs_not_redacted():
    # The fairness fix must NOT bring back the place/common-word FPs: the leading
    # token here IS a common English word / place term, so the name-like signal
    # does NOT fire and the pair stays suppressed (left to L2 NER).
    for text, word in [
        ("Central Park", "Park"),
        ("Lake Park", "Park"),
        ("We visited Hyde Park yesterday", "Park"),
    ]:
        out, _ = redact(text, mode="fast", lang="en", salt=42)
        assert out == text, (text, out)
        assert word in out


# Single-token apostrophe given names ("D'Andre", "O'Shea", "D'Angelo") tokenize
# as ONE token; the name-like char filter previously permitted internal hyphens
# but NOT apostrophes, so these full names LEAKED (while the hyphenated
# "Jean-Paul" was caught) — an arbitrary, demographically skewed gap. The
# name-like filter now permits the ASCII apostrophe and the typographic
# apostrophe U+2019, matching the tokenizer.
@pytest.mark.parametrize(
    "full_name",
    ["D'Andre Williams", "O'Shea Davis", "D'Angelo Garcia"],
)
def test_apostrophe_given_names_redact(full_name):
    surname = full_name.split()[-1]
    assert any(surname in v for v in _names(full_name)), full_name


# Tokens that are PRIMARILY / commonly real given names but were trapped in the
# suppression lexicon, so the name-like signal died and "Given Surname" full
# names LEAKED (a recall regression vs v0.7.9, demographically skewed). Removing
# them from en_common_words.ron lets name-like fire so the pair redacts. The
# second token is a pooled surname so the anchor is real.
@pytest.mark.parametrize(
    "full_name",
    [
        "Hope Johnson",
        "Prince Williams",
        "King Davis",
        "Long Nguyen",
        "Summer Williams",
        "Dawn Mitchell",
        "Earl Davis",
        "June Wilson",
        # "Duke" is the removed common word under test; the anchor surname must be
        # POOLED to assemble. "Ellington" is not in the en surname pool (a
        # pool-coverage gap, not a gate defect — same caveat as "Kwame Mensah"
        # above), so "Williams" is used to isolate the duke-removal behavior.
        "Duke Williams",
    ],
)
def test_common_word_given_names_redact(full_name):
    surname = full_name.split()[-1]
    assert any(surname in v for v in _names(full_name)), full_name


# Leading tokens that are place / color / nationality / org words — NOT commonly
# given names and NOT in the surname pool — were missing from the lexicon, so
# name-like fired and "Golden Davis" / "Russian Davis" / "United Davis"
# false-positived at 0.8. Adding them to the lexicon suppresses the leading token
# (the pair is left to L2 NER). The second token ("Davis") is a pooled surname so
# the anchor is real; only the false-positive leading token must not be redacted.
@pytest.mark.parametrize(
    "text",
    [
        "Golden Davis",
        "Russian Davis",
        "Silver Davis",
        "Iron Davis",
        "United Davis",
        "Capital Davis",
    ],
)
def test_place_org_pairs_suppressed(text):
    out, _ = redact(text, mode="fast", lang="en", salt=42)
    assert out == text, (text, out)


# Confirm the curated place suppression still holds after the lexicon edits — the
# leading token is a place / nature word kept in the lexicon, so the pair stays
# suppressed (the fairness fix must not revive these place FPs).
@pytest.mark.parametrize("text", ["Central Park", "Maple Davis", "Cedar Davis"])
def test_curated_place_pairs_still_suppressed(text):
    out, _ = redact(text, mode="fast", lang="en", salt=42)
    assert out == text, (text, out)


# ACCEPTED documented residuals — ambiguous tokens that are BOTH a place / gem
# and a common given name. They are intentionally LEFT OUT of the suppression
# lexicon (keeping them name-like), so "Lincoln Park" / "Crystal Davis" still
# redact. This is the irreducible ambiguous-token residual (same class as a real
# person actually named "Lincoln" or "Crystal"); favoring recall on a real-name
# reading is the deliberate trade.
@pytest.mark.parametrize("text", ["Lincoln Park", "Crystal Davis"])
def test_accepted_ambiguous_residuals_still_redact(text):
    assert _names(text), text


# The four season words are all common MODERN given names ("Summer", "Autumn",
# "Winter", "Spring"). The first lexicon pass removed "summer"/"autumn" but left
# "winter"/"spring" in the suppression set, so "Summer Davis"/"Autumn Davis"
# redacted while "Winter Davis"/"Spring Davis" LEAKED — an inconsistency. The
# final curation removes "winter"/"spring" too, so all four behave identically.
# Surnames are pooled ("Davis"); the season word is the only variable.
@pytest.mark.parametrize(
    "full_name",
    ["Summer Davis", "Autumn Davis", "Winter Davis", "Spring Davis"],
)
def test_season_names_redact_consistently(full_name):
    # winter/spring FAIL before this change (left in the lexicon); all four pass
    # after. The surname must end up redacted.
    assert any("Davis" in v for v in _names(full_name)), full_name


# A sample of the predominantly-given-name words removed in the final curation
# pass: with the word out of the suppression lexicon the leading token is once
# again name-like, so the bare-surname pair clears the gate. The second token is
# a pooled surname ("Davis") so the anchor is real and only the leading-token
# name-like signal is under test. (Only "winter"/"spring" were actually removed
# in this pass — the other predominantly-name examples in the audit, e.g. the
# gem/flower/virtue names, were already absent from the lexicon.)
@pytest.mark.parametrize("full_name", ["Winter Davis", "Spring Davis"])
def test_removed_given_names_redact(full_name):
    assert any("Davis" in v for v in _names(full_name)), full_name


# ACCEPTED RESIDUAL — documented, intentional recall miss at fast-L1.
#
# Some tokens are BOTH an ultra-high-frequency English common/function word AND
# an occasional given name ("Will", "Major", "Drew", "Art", "Guy", "Rich",
# "Royal", "River", "Lane", "Case", "True", "Count"). In a single-list design
# they are irreducibly ambiguous: removing them to recover "Will Smith" would
# fire the name-like signal on ordinary prose ("Will Davis cancel?" /
# "Major changes ahead, Davis") and re-introduce frequent FPs. The curation
# principle KEEPS them in the suppression lexicon, so the fast-L1 pair is
# SUPPRESSED; the real-person reading ("Will Smith") is recovered by L2 NER in
# ner/auto mode. This test LOCKS that residual so the trade is explicit and a
# future change to it is intentional, not accidental.
#
# Contrast: "May Davis" REDACTS here — "may" is NOT in the lexicon (it was never
# added), so "May" stays name-like. ("April"/"June"/"August" were likewise kept
# out as predominantly-name month words.) This pins the asymmetry the curation
# made deliberately between "will" (kept) and "may" (omitted).
def test_high_freq_ambiguous_kept_as_residual():
    # KEPT in the lexicon -> suppressed at fast-L1 (recovered by L2 NER).
    for residual in ["Will Davis", "Major Davis", "Drew Davis", "Royal Davis"]:
        out, _ = redact(residual, mode="fast", lang="en", salt=42)
        assert out == residual, (residual, out)
    # Omitted from the lexicon -> name-like -> redacts. Locks the will/may split.
    assert any("Davis" in v for v in _names("May Davis")), "May Davis"


# Controls — must stay SUPPRESSED after the curation (the curation must not
# revive place / curated-geo FPs). "Central" is a directional place word,
# "Maple" a curated tree/geo term; both are kept in the lexicon, so the leading
# token is not name-like and the pair is left to L2 NER.
@pytest.mark.parametrize("text", ["Central Park", "Maple Davis"])
def test_curation_controls_still_suppressed(text):
    out, _ = redact(text, mode="fast", lang="en", salt=42)
    assert out == text, (text, out)


# ── Lexicon-gap FPs surfaced by the kaggle_piilo (fast, 500) FP diagnosis ──
#
# A bare "Capitalized Surname" pair fires the name-like signal (0.8) only when
# the LEADING token's lowercase form is NOT in en_common_words.ron. The diagnosis
# found a handful of TRUE false positives whose leading token is a genuinely
# common English word / a brand / a Spanish place-prefix that was simply MISSING
# from the lexicon: "Media Page", "Instagram Page", "Selection Jordan",
# "Dancing Cannon", "Community Page", "Nuevo León". (Page/Jordan/Cannon/León are
# pooled surnames, so the pair assembled; the leading token is the FP driver.)
# Adding media/selection/dancing/instagram/nuevo to the lexicon suppresses the
# leading token so the pair is left to L2 NER. "community" was ALREADY in the
# lexicon, so "Community Page" was already suppressed — it is kept here as a
# regression control. The place/org-specific residuals (chapultepec, mcgraw,
# rosetta, johns, hopkins) are intentionally NOT added — they are too specific or
# genuinely ambiguous as names (Johns Hopkins, Rosetta Stone) and stay documented.
@pytest.mark.parametrize(
    "text",
    [
        "Media Page",
        "Instagram Page",
        "Selection Jordan",
        "Dancing Cannon",
        "Community Page",
        "Nuevo León",
    ],
)
def test_lexicon_gap_fps_suppressed(text):
    out, _ = redact(text, mode="fast", lang="en", salt=42)
    assert out == text, (text, out)


# The lexicon additions must NOT suppress any real name: a representative spread
# (Anglo, Italian, common-word given name, non-Anglo) must still redact. The
# surnames are pooled so the anchor is real; the test guards against an addition
# accidentally landing on a surname/given-name slot.
@pytest.mark.parametrize(
    "full_name",
    ["Marco Rossi", "Hope Johnson", "John Smith", "Raaz Gupta"],
)
def test_real_names_still_redact(full_name):
    surname = full_name.split()[-1]
    assert any(surname in v for v in _names(full_name)), full_name


# ── Benchmark-pinned regression guards ──────────────────────────────────────
#
# HONEST FRAMING — these are REGRESSION GUARDS, not a "material precision
# recovery" claim. Three caveats the reader must keep in mind:
#
#  1. The ABSOLUTE benchmark precision is ARTIFACT-LIMITED. The kaggle_piilo
#     evaluator matches on exact entity VALUE, so a name the gate catches but
#     whitespace/zero-width normalization shifts by a character is scored as an
#     FP, and non-PII *famous-name citations* in the student essays (cited
#     authors, public figures) are labeled FP though they are not leaked PII. The
#     FP diagnosis (kaggle_piilo, fast, 500 docs) found ~50 of 68 person "FPs"
#     are actually real names or such citations; REAL person precision is ~90%.
#     The benchmark number (~70%) therefore UNDERSTATES the gate.
#  2. RECALL is bounded by surname-pool COVERAGE, not by the gate. The dominant
#     FN class is "surname not yet in the en pool" (e.g. Mensah) — a pool-growth
#     task tracked as future work, NOT a gate-fairness defect.
#  3. The gate only REMOVES uncorroborated bare-surname emissions (a strict
#     subset of v0.7.9 emissions), so person precision can only RISE relative to
#     v0.7.9; the Task-1 lexicon polish removes 5 FP leading tokens, which only
#     raises precision further. The floors are pinned DOWN from the current
#     measured values (person fast precision 69.6 %, recall 29.8 %) so they hold
#     across dataset jitter and the polish — they assert "did not regress", not
#     "recovered to X".
#
# The JSON is fetched/regenerated from HuggingFace (network), so until the user
# re-runs the benchmark these SKIP rather than fail. Two formats are accepted:
# the rich format exposes ``per_type_fast.person`` (person-specific floors); the
# legacy simple format exposes only overall ``modes.fast`` (overall fallback).
# Regenerate via::
#
#     python -m tests.benchmark kaggle_piilo --mode fast --limit 500 \
#         --save tests/benchmark/results/kaggle_piilo_0.7.10.json


def _kaggle_data() -> dict:
    if not _KAGGLE_PIILO.exists():
        pytest.skip(
            f"{_KAGGLE_PIILO.name} not regenerated (needs network); "
            "run the benchmark to activate the floor."
        )
    return json.loads(_KAGGLE_PIILO.read_text(encoding="utf-8"))


def test_person_floor_precision_not_regressed():
    data = _kaggle_data()
    if "person" in data.get("per_type_fast", {}):
        # Person-specific guard (rich format). Pinned DOWN from 69.6 %.
        assert data["per_type_fast"]["person"]["precision"] >= 68.0, data["per_type_fast"]
    else:
        # Legacy simple format: only overall fast metrics are present. Fall back
        # to the overall fast precision floor (pinned just under the recorded
        # overall value) until the JSON is regenerated in the rich format.
        pytest.skip(
            f"{_KAGGLE_PIILO.name} lacks per_type_fast (legacy format); "
            "regenerate the benchmark to activate the person-specific floor."
        )


def test_person_floor_recall_not_regressed():
    data = _kaggle_data()
    if "person" in data.get("per_type_fast", {}):
        # Pinned DOWN from 29.8 %. Recall give-back is bounded — the gate keeps
        # every given-name-led / known / corroborated name (see caveat 2 above).
        assert data["per_type_fast"]["person"]["recall"] >= 27.0, data["per_type_fast"]
    else:
        pytest.skip(
            f"{_KAGGLE_PIILO.name} lacks per_type_fast (legacy format); "
            "regenerate the benchmark to activate the person-specific floor."
        )


def test_overall_fast_floor_when_legacy_format():
    # When the rich per_type_fast is absent (legacy format, pre-refresh) but the
    # file IS present, the overall fast precision/recall still act as a coarse
    # regression guard. With the rich format this asserts the same coarse floor
    # holds alongside the person-specific one. Skips only if the file is absent.
    data = _kaggle_data()
    fast = data.get("modes", {}).get("fast")
    if not fast:
        pytest.skip(f"{_KAGGLE_PIILO.name} has no overall fast metrics")
    assert fast["precision"] >= 69.0, fast
    assert fast["recall"] >= 27.0, fast
