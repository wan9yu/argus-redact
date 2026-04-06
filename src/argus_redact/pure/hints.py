"""Cross-layer hints — produced by earlier layers, consumed by later layers."""

from __future__ import annotations

import re

from argus_redact._types import Hint, PatternMatch

# ── Kinship terms (always Tier 1) ──

_KINSHIP_ZH = {
    "我妈妈", "我爸爸", "我母亲", "我父亲", "我老公", "我老婆",
    "我丈夫", "我妻子", "我先生", "我太太", "我儿子", "我女儿",
    "我哥哥", "我姐姐", "我弟弟", "我妹妹", "我哥", "我姐", "我弟", "我妹",
    "我妈", "我爸", "我爷爷", "我奶奶", "我外公", "我外婆",
    "我叔叔", "我阿姨", "我舅舅", "我姑姑", "我家人", "我家里人", "我孩子",
}

# ── Interaction command patterns (Tier 3) ──

_COMMAND_PREFIXES_ZH = (
    "我想问", "我想知道", "我需要", "我要问", "帮我", "请帮我",
    "请告诉我", "告诉我", "我想让你", "我希望你", "我要你",
    "麻烦帮我", "能帮我", "可以帮我",
)
_COMMAND_PATTERNS_EN = re.compile(
    r"^(?:can you |could you |please |would you )"
    r"|\b(?:help me|tell me|show me|explain to me|let me know)\b"
    r"|^I (?:want to |need to |would like to )(?:know|ask|understand)",
    re.IGNORECASE,
)

# ── Default person name threshold ──

_DEFAULT_PERSON_THRESHOLD = 0.8


# ══════════════════════════════════════════════════════════════
# Producers: generate hints from detected entities
# ══════════════════════════════════════════════════════════════

def _is_kinship(entity: PatternMatch) -> bool:
    return entity.text in _KINSHIP_ZH or entity.text.startswith("my ")


def _is_interaction_command(text: str) -> bool:
    stripped = text.strip()
    if any(stripped.startswith(p) for p in _COMMAND_PREFIXES_ZH):
        return True
    if _COMMAND_PATTERNS_EN.search(stripped):
        return True
    return False


def produce_hints(
    entities: list[PatternMatch], text: str,
) -> list[Hint]:
    """Produce hints from L1 detection results.

    Returns hints that downstream layers (L1b person names, L2 NER,
    L3 LLM, tier filter) can consume.
    """
    hints: list[Hint] = []

    self_refs: list[PatternMatch] = []
    others: list[PatternMatch] = []
    for e in entities:
        (self_refs if e.type == "self_reference" else others).append(e)

    # PII density (always emitted, excludes self_reference)
    pii_count = len(others)
    if pii_count >= 3:
        density_level = "high"
    elif pii_count >= 1:
        density_level = "medium"
    else:
        density_level = "none"
    hints.append(Hint(type="pii_density", data={"level": density_level, "count": pii_count}))

    if not self_refs:
        intent = "narrative" if others else "neutral"
        hints.append(Hint(type="text_intent", data={"intent": intent}))
        return hints

    has_kinship = any(_is_kinship(e) for e in self_refs)
    has_other_pii = len(others) > 0
    is_command = _is_interaction_command(text)

    # Self-reference tier
    if is_command and not has_kinship and not has_other_pii:
        tier = 3
    elif has_other_pii or has_kinship:
        tier = 1
    else:
        tier = 2

    hints.append(Hint(
        type="self_reference_tier",
        data={"tier": tier, "has_kinship": has_kinship},
    ))

    # Text intent
    if is_command:
        intent = "instruction"
    elif has_other_pii:
        intent = "narrative"
    else:
        intent = "casual"

    hints.append(Hint(type="text_intent", data={"intent": intent}))

    return hints


# ══════════════════════════════════════════════════════════════
# Consumers: read hints to adjust behavior
# ══════════════════════════════════════════════════════════════

def get_person_threshold(hints: list[Hint]) -> float:
    """Adjust person name detection threshold based on hints.

    - instruction text → higher threshold (fewer false positives)
    - narrative with PII → default or lower threshold
    """
    for h in hints:
        if h.type == "text_intent":
            if h.data.get("intent") == "instruction":
                return 1.2  # effectively suppress most candidates
            elif h.data.get("intent") == "narrative":
                return _DEFAULT_PERSON_THRESHOLD
    return _DEFAULT_PERSON_THRESHOLD


def filter_self_reference(
    entities: list[PatternMatch], hints: list[Hint],
) -> list[PatternMatch]:
    """Filter self_reference entities based on tier hints.

    Tier 1: keep (replace along with other PII)
    Tier 2: drop (no replacement, only risk assessment sees them)
    Tier 3: drop (interaction command, ignore completely)
    """
    tier = _get_self_reference_tier(hints)

    if tier == 1:
        return entities  # keep all

    # Tier 2 or 3: drop self_reference pronoun entities, keep kinship for Tier 1
    return [e for e in entities if e.type != "self_reference"]


# ── Cross-layer agreement ──

_CROSS_LAYER_BOOST = 0.1
# Types that are considered "same concept" across layers
_COMPATIBLE_TYPES = {
    ("address", "location"),
    ("location", "address"),
    ("organization", "workplace"),
    ("workplace", "organization"),
    ("school", "organization"),
    ("organization", "school"),
}


def boost_cross_layer(
    merged: list[PatternMatch],
    pre_merge: list[PatternMatch],
) -> list[PatternMatch]:
    """Boost confidence of entities detected by multiple layers.

    If the same span (or overlapping span of compatible type) was detected
    by both L1 and L2, boost the merged entity's confidence.
    """
    if not merged or not pre_merge:
        return merged

    layers_present = {e.layer for e in pre_merge}
    if len(layers_present) < 2:
        return merged

    result = []
    for entity in merged:
        layers_agreeing = set()
        for e in pre_merge:
            # Check span overlap
            if e.start < entity.end and entity.start < e.end:
                # Same type or compatible types
                if e.type == entity.type or (e.type, entity.type) in _COMPATIBLE_TYPES:
                    layers_agreeing.add(e.layer)

        if len(layers_agreeing) >= 2:
            boosted = PatternMatch(
                text=entity.text, type=entity.type,
                start=entity.start, end=entity.end,
                confidence=min(entity.confidence + _CROSS_LAYER_BOOST, 1.0),
                layer=entity.layer,
            )
            result.append(boosted)
        else:
            result.append(entity)

    return result


def _get_self_reference_tier(hints: list[Hint]) -> int | None:
    for h in hints:
        if h.type == "self_reference_tier":
            return h.data.get("tier")
    return None


# ── L2 NER consumers ──

_DEFAULT_NER_CONFIDENCE = 0.5


def should_skip_ner(hints: list[Hint]) -> bool:
    """Decide whether to skip NER entirely based on hints.

    Skip when text is an instruction AND has no PII detected by L1.
    """
    intent = None
    pii_count = 0
    for h in hints:
        if h.type == "text_intent":
            intent = h.data.get("intent")
        elif h.type == "pii_density":
            pii_count = h.data.get("count", 0)

    return intent == "instruction" and pii_count == 0


def get_ner_min_confidence(hints: list[Hint]) -> float:
    """Adjust NER min_confidence based on PII density hints.

    High PII density → lower threshold (more aggressive NER, find more names)
    No PII → default threshold
    """
    for h in hints:
        if h.type == "pii_density":
            level = h.data.get("level")
            if level == "high":
                return 0.3
            elif level == "medium":
                return 0.4
    return _DEFAULT_NER_CONFIDENCE
