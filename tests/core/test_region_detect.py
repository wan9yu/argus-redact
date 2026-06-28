"""Evidence-gated region detector — precision + recall floors.

Bare admin regions are detected ONLY with address-context evidence, so location
quasi-identifiers are removed (the default `location` strategy) while region
names in non-PII contexts (time/org/food/landmark) are NOT over-redacted. Floors,
not exact match (the gate is a heuristic). cf. the person-detector floors.
"""
from argus_redact import redact


def _detects_region(text: str) -> bool:
    # category strategy → a detected location becomes "[location]"; visible marker.
    out, _ = redact(text, mode="fast", lang=["zh"], salt=42,
                    config={"location": {"strategy": "category"}})
    return "[location]" in out or "[LOCATION]" in out


# Positives: a real gazetteer region + an address-context cue → SHOULD detect.
POSITIVES = [
    "他住在上海浦东新区，平时挺忙的。",
    "我家住杭州西湖区，离公司很近。",
    "户籍地在广州天河区。",
    "我在深圳南山区租房，房租不便宜。",
    "老家是成都武侯区的。",
    # Residence/registration/birthplace cues added to _REGION_CUE: each carries
    # an explicit address-context cue (现居/户口/落户/出生), so the region is a
    # location quasi-identifier, not a bare mention.
    "现居北京市海淀区。",
    "户口在西安市雁塔区。",
    "落户深圳市福田区。",
    "出生在重庆市渝中区。",
]
# Negatives: a region name (or near-region) in a NON-PII context → must NOT detect.
NEGATIVES = [
    "现在是北京时间晚上八点。",
    "他考上了北京大学，全家很高兴。",
    "周末我们去吃北京烤鸭吧。",
    "上海合作组织今天举行会议。",
    "西湖醋鱼是杭州名菜。",
    "这家公司在朝阳群众的监督下整改。",
    "广州塔是地标建筑。",
    # self_reference (我/我们) must NOT corroborate a region: a `我 … <district>`
    # sentence with no address cue is a bare mention, not a location PII.
    "我很喜欢西湖区的风景。",
    "我觉得朝阳区的房价太高了。",
    "我昨天路过海淀区。",
    # `我们公司` is an organization + self_reference; an org co-occurring with a
    # region is not address evidence, so this must stay clean.
    "我们公司在黄浦区附近开会。",
    # region glued to a longer proper-noun/org run (`海淀区中关村科技园…`): the
    # org span mis-segments and leaves `海淀区` un-absorbed, but with no address
    # cue and only org proximity it must NOT fire (organization is excluded from
    # the proximity corroboration, same as self_reference).
    "海淀区中关村科技园聚集了大量互联网企业。",
]


def test_region_precision_floor():
    fps = [t for t in NEGATIVES if _detects_region(t)]
    assert fps == [], f"region detector false-positives (must be 0): {fps}"


def test_region_recall_floor():
    hits = sum(1 for t in POSITIVES if _detects_region(t))
    assert hits >= 8, f"region recall floor 8/9: only {hits}/{len(POSITIVES)} detected"


def test_parent_city_prefix_absorbed():
    # 上海浦东新区 must redact as ONE location, not leave bare 上海.
    out, _ = redact("我住在上海浦东新区，平时很忙。", mode="fast", lang=["zh"],
                    salt=42, config={"location": {"strategy": "category"}})
    assert "上海" not in out, f"bare parent city leaked: {out!r}"
    assert "[location]" in out or "[LOCATION]" in out


# ---------------------------------------------------------------------------
# Proximity-allowlist fix: technical PII must not corroborate a bare region
# ---------------------------------------------------------------------------

def test_region_technical_pii_only_not_corroborated():
    # url_token and ip_address are technical/non-personal PII; after the
    # proximity-allowlist fix they no longer corroborate a bare region.
    # A district with ONLY a url_token or ip_address nearby (no cue) must
    # NOT be redacted.  Before the fix both would fire via lexicon 0.3 +
    # (now-excluded) proximity 0.3 = 0.6 ≥ 0.5 threshold.
    assert not _detects_region(
        "西湖区 https://api.example.com/v1/资源?token=abc123def456"
    ), "url_token must not corroborate a bare region (no cue)"
    assert not _detects_region(
        "海淀区 192.168.10.20"
    ), "ip_address must not corroborate a bare region (no cue)"


def test_region_personal_pii_still_corroborates():
    # phone IS in the person-identifying allowlist; it must still promote a
    # bare region to redaction (lexicon 0.3 + phone-prox 0.3 = 0.6 ≥ 0.5).
    # Regression guard: the fix must not break the existing phone-proximity path.
    assert _detects_region(
        "西湖区 13800138000"
    ), "phone must still corroborate a bare region"


def test_region_mixed_technical_and_personal_pii():
    # When BOTH a url_token (excluded) and a phone (person-identifying) are
    # nearby, the phone corroborates and the region IS redacted.
    assert _detects_region(
        "西湖区 https://api.example.com/v1/资源?token=abc123def456 13800138000"
    ), "phone must still corroborate even when a url_token is also present"
