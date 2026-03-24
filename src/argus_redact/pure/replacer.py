"""replace() — convert pattern matches to redacted text + key."""

from argus_redact._types import PatternMatch
from argus_redact.pure.pseudonym import PseudonymGenerator


# Default strategies per entity type
DEFAULT_STRATEGIES = {
    "person": "pseudonym",
    "organization": "pseudonym",
    "location": "category",
    "phone": "mask",
    "id_number": "remove",
    "email": "mask",
    "bank_card": "mask",
    "passport": "remove",
}

# Default labels for remove strategy
DEFAULT_REMOVE_LABELS = {
    "id_number": "[身份证号已脱敏]",
    "passport": "[护照号已脱敏]",
}

# Default label for category strategy
DEFAULT_CATEGORY_LABEL = {
    "location": "[地点]",
}


def _mask_value(value: str, entity_type: str) -> str:
    """Apply mask strategy: show prefix + suffix, mask middle."""
    if entity_type == "email":
        at = value.find("@")
        if at > 0:
            local = value[:at]
            domain = value[at:]
            visible = local[0] if local else ""
            return f"{visible}{'*' * max(len(local) - 1, 3)}{domain}"
        return value

    # Default: show first 3 + last 4
    prefix_len = 3
    suffix_len = 4
    if len(value) <= prefix_len + suffix_len:
        return "*" * len(value)
    masked_len = len(value) - prefix_len - suffix_len
    return f"{value[:prefix_len]}{'*' * masked_len}{value[-suffix_len:]}"


def _resolve_collision(label: str, used_labels: set[str]) -> str:
    """Append circled number on collision: first=no suffix, second=①, third=②."""
    if label not in used_labels:
        return label
    circled = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"
    for i, c in enumerate(circled):
        candidate = f"{label}{c}"
        if candidate not in used_labels:
            return candidate
    raise RuntimeError(f"Too many collisions for label: {label}")


def replace(
    text: str,
    entities: list[PatternMatch],
    *,
    seed: int | None = None,
    key: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """Replace detected entities in text, producing (redacted_text, key).

    Entities are replaced right-to-left to preserve character offsets.
    """
    if not entities:
        return text, key if key is not None else {}

    result_key = dict(key) if key else {}
    used_labels = set(result_key.keys())

    # Build reverse index from existing key: original -> replacement
    reverse_index: dict[str, str] = {}
    for replacement, original in result_key.items():
        reverse_index[original] = replacement

    # Pseudonym generator for person/org types
    pseudo_gen = PseudonymGenerator(
        seed=seed,
        existing_key=result_key if result_key else None,
    )
    org_gen = PseudonymGenerator(
        prefix="O",
        seed=(seed + 1) if seed is not None else None,
        existing_key=result_key if result_key else None,
    )

    # Build replacement mapping for each unique entity
    entity_replacements: dict[str, str] = {}  # original text -> replacement

    for entity in entities:
        if entity.text in entity_replacements:
            continue
        if entity.text in reverse_index:
            entity_replacements[entity.text] = reverse_index[entity.text]
            continue

        strategy = DEFAULT_STRATEGIES.get(entity.type, "remove")

        if strategy == "pseudonym":
            if entity.type == "organization":
                replacement = org_gen.get(entity.text)
            else:
                replacement = pseudo_gen.get(entity.text)
        elif strategy == "mask":
            replacement = _mask_value(entity.text, entity.type)
            replacement = _resolve_collision(replacement, used_labels)
        elif strategy == "remove":
            label = DEFAULT_REMOVE_LABELS.get(entity.type, "[REDACTED]")
            replacement = _resolve_collision(label, used_labels)
        elif strategy == "category":
            label = DEFAULT_CATEGORY_LABEL.get(entity.type, f"[{entity.type}]")
            replacement = _resolve_collision(label, used_labels)
        else:
            replacement = _resolve_collision("[REDACTED]", used_labels)

        entity_replacements[entity.text] = replacement
        used_labels.add(replacement)
        result_key[replacement] = entity.text

    # Replace right-to-left (sort by start position descending)
    sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
    result = text
    seen_positions: set[tuple[int, int]] = set()

    for entity in sorted_entities:
        pos = (entity.start, entity.end)
        if pos in seen_positions:
            continue
        seen_positions.add(pos)
        replacement = entity_replacements[entity.text]
        result = result[:entity.start] + replacement + result[entity.end:]

    return result, result_key
