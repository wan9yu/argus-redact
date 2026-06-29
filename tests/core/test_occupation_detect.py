"""Evidence-gated occupation detector — precision + recall floors.

Occupation mentions are detected (type ``job_title``, default strategy ``remove``)
ONLY with occupation evidence (a cue, or a high-confidence multi-char lexicon
term), so honorific-person uses (李老师 / 王医生) and generic words don't get
over-redacted. Floors, not exact match (the gate is a heuristic). cf. the
region/person detector floors.
"""

from argus_redact import redact

_SALT = b"occupation-floor-test-salt-32byte"  # high-entropy; category output is salt-independent


def _detects_occupation(text: str) -> bool:
    # category strategy → a detected job_title renders as "[job_title]"; visible marker.
    out, _ = redact(
        text, mode="fast", lang=["zh"], salt=_SALT, config={"job_title": {"strategy": "category"}}
    )
    return "[job_title]" in out or "[JOB_TITLE]" in out


# Positives: a real occupation + evidence → SHOULD detect.
POSITIVES = [
    "他是一名数学老师，教高三。",
    "她从事软件工程师工作。",
    "我担任急诊科护士。",
    "他是带货主播。",
    "当程序员五年了。",
]
# Negatives: occupation-word fragments in non-occupation contexts → must NOT
# detect. These exercise the OCCUPATION detector's own guards. NB: the titles
# here (老师/师傅) are deliberately NOT among the surname+title honorifics that
# the pre-existing layer-1 job_title *regex* (data/zh.ron) already captures
# (医生/律师/经理/工程师/…) — so 王医生→job_title is the regex's call, not this
# detector's, and isn't asserted here.
NEGATIVES = [
    "李老师今天布置了作业。",  # surname + 老师 honorific → person, not occupation
    "张老师来了。",  # surname + 老师 honorific (different surname)
    "这道数学题很难。",  # 数学 fragment, no occupation
    "老师傅手艺好。",  # 师傅 generic address, no cue
    "工欲善其事，必先利其器。",  # idiom containing 工
]


def test_occupation_precision_floor():
    fps = [t for t in NEGATIVES if _detects_occupation(t)]
    assert fps == [], f"occupation false-positives (must be 0): {fps}"


def test_occupation_recall_floor():
    hits = sum(1 for t in POSITIVES if _detects_occupation(t))
    assert hits >= 4, f"occupation recall floor 4/5: only {hits}/{len(POSITIVES)} detected"


# ---------------------------------------------------------------------------
# Proximity-allowlist fix: technical PII must not corroborate an occupation
# ---------------------------------------------------------------------------


def test_occupation_technical_pii_only_not_corroborated():
    # github_token is technical/non-personal; it must not corroborate a bare
    # occupation title.  护士 (2-char, in honorific-title guard) does not fire
    # via the lexicon-weight path (W_OCC_LEXICON requires ≥ 3 chars) and has no
    # cue here, so proximity is the only possible signal.  The occupation
    # proximity weight (W_OCC_PII_PROX = 0.3) is below OCC_THRESHOLD (0.5) for
    # ANY PII type, so this test is a GUARD rather than a behavioral flip: the
    # fix pins that technical PII cannot accidentally become a corroborator even
    # if weights change.
    assert not _detects_occupation("护士 ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), (
        "github_token must not corroborate a bare occupation (no cue)"
    )


def test_occupation_cue_detection_still_works():
    # Cue-based detection (是一名 fires W_OCC_CUE = 0.6 ≥ 0.5) must still
    # work after the allowlist fix.  Uses 护士 with a cue and a phone in
    # context — the cue alone is the gating signal here.
    assert _detects_occupation("他是一名护士 13800138000"), (
        "cue must still fire occupation detection with personal PII in context"
    )


def test_occupation_cue_with_technical_pii():
    # Cue fires (0.6 ≥ 0.5) regardless of what other PII is present;
    # a github_token in context must not block or interfere with the cue path.
    assert _detects_occupation(
        "他是一名护士 ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 13800138000"
    ), "cue must still fire occupation detection even when technical PII is present"
