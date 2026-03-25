"""replace() — convert pattern matches to redacted text + key."""

from __future__ import annotations

from argus_redact._types import PatternMatch
from argus_redact.pure.pseudonym import PseudonymGenerator

VALID_STRATEGIES = ("pseudonym", "mask", "remove", "category")

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
    "license_plate": "remove",
    "address": "remove",
    "ssn": "remove",
    "credit_card": "mask",
    "my_number": "remove",
    "rrn": "remove",
    "tax_id": "remove",
    "iban": "remove",
    "postcode": "remove",
    "nino": "remove",
    "nhs_number": "remove",
    "aadhaar": "remove",
    "pan": "remove",
}

DEFAULT_PREFIXES = {
    "person": "P",
    "organization": "O",
}

# Default labels for remove strategy — per language
_REMOVE_LABELS_BY_LANG = {
    "zh": {
        "id_number": "[身份证号已脱敏]",
        "passport": "[护照号已脱敏]",
        "license_plate": "[车牌号已脱敏]",
        "address": "[地址已脱敏]",
    },
    "en": {
        "ssn": "[SSN REDACTED]",
        "credit_card": "[CARD REDACTED]",
    },
    "de": {
        "tax_id": "[Steuer-ID]",
        "iban": "[IBAN]",
    },
    "uk": {
        "postcode": "[POSTCODE]",
        "nino": "[NINO]",
        "nhs_number": "[NHS NUMBER]",
    },
    "in": {
        "aadhaar": "[AADHAAR]",
        "pan": "[PAN]",
    },
    "ja": {
        "my_number": "[マイナンバー]",
    },
    "ko": {
        "rrn": "[주민등록번호]",
    },
}

# Flattened default (all languages merged)
DEFAULT_REMOVE_LABELS: dict[str, str] = {}
for _labels in _REMOVE_LABELS_BY_LANG.values():
    DEFAULT_REMOVE_LABELS.update(_labels)

# Default label for category strategy
DEFAULT_CATEGORY_LABEL = {
    "location": "[LOCATION]",
}


def _get_entity_config(
    entity_type: str,
    config: dict | None,
) -> dict:
    """Get merged config for an entity type: user config over defaults."""
    if config and entity_type in config:
        return config[entity_type]
    return {}


def _validate_config(config: dict | None) -> None:
    """Validate user config, raise ValueError on invalid strategy."""
    if not config:
        return
    for entity_type, type_config in config.items():
        if not isinstance(type_config, dict):
            continue
        strategy = type_config.get("strategy")
        if strategy and strategy not in VALID_STRATEGIES:
            raise ValueError(
                f"Unknown strategy '{strategy}' for entity type "
                f"'{entity_type}'. Valid: {', '.join(VALID_STRATEGIES)}"
            )


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
    """Append circled number on collision."""
    if label not in used_labels:
        return label
    circled = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"
    for c in circled:
        candidate = f"{label}{c}"
        if candidate not in used_labels:
            return candidate
    # Fallback to numeric suffix beyond ⑳
    for i in range(21, 10000):
        candidate = f"{label}({i})"
        if candidate not in used_labels:
            return candidate
    raise RuntimeError(f"Too many collisions for label: {label}")


def replace(
    text: str,
    entities: list[PatternMatch],
    *,
    seed: int | None = None,
    key: dict[str, str] | None = None,
    config: dict | None = None,
) -> tuple[str, dict[str, str]]:
    """Replace detected entities in text, producing (redacted_text, key).

    config overrides default strategies per entity type. Example:
        {"phone": {"strategy": "remove", "replacement": "[TEL]"}}
    """
    _validate_config(config)

    if not entities:
        return text, key if key is not None else {}

    result_key = dict(key) if key else {}
    used_labels = set(result_key.keys())

    reverse_index: dict[str, str] = {}
    for replacement, original in result_key.items():
        reverse_index[original] = replacement

    # Pseudonym generators — prefix can be overridden by config
    person_prefix = DEFAULT_PREFIXES["person"]
    org_prefix = DEFAULT_PREFIXES["organization"]
    if config:
        person_prefix = config.get("person", {}).get("prefix", person_prefix)
        org_prefix = config.get("organization", {}).get("prefix", org_prefix)

    pseudo_gen = PseudonymGenerator(
        prefix=person_prefix,
        seed=seed,
        existing_key=result_key if result_key else None,
    )
    org_gen = PseudonymGenerator(
        prefix=org_prefix,
        seed=(seed + 1) if seed is not None else None,
        existing_key=result_key if result_key else None,
    )

    entity_replacements: dict[str, str] = {}

    for entity in entities:
        if entity.text in entity_replacements:
            continue
        if entity.text in reverse_index:
            entity_replacements[entity.text] = reverse_index[entity.text]
            continue

        ec = _get_entity_config(entity.type, config)
        strategy = ec.get("strategy", DEFAULT_STRATEGIES.get(entity.type, "remove"))

        if strategy == "pseudonym":
            prefix = ec.get("prefix", DEFAULT_PREFIXES.get(entity.type, "P"))
            if entity.type == "organization":
                if "prefix" in ec:
                    org_gen = PseudonymGenerator(
                        prefix=prefix,
                        seed=(seed + 1) if seed is not None else None,
                        existing_key=result_key if result_key else None,
                    )
                replacement = org_gen.get(entity.text)
            else:
                if "prefix" in ec:
                    pseudo_gen = PseudonymGenerator(
                        prefix=prefix,
                        seed=seed,
                        existing_key=result_key if result_key else None,
                    )
                replacement = pseudo_gen.get(entity.text)
        elif strategy == "mask":
            replacement = _mask_value(entity.text, entity.type)
            replacement = _resolve_collision(replacement, used_labels)
        elif strategy == "remove":
            label = ec.get(
                "replacement",
                DEFAULT_REMOVE_LABELS.get(entity.type, "[REDACTED]"),
            )
            replacement = _resolve_collision(label, used_labels)
        elif strategy == "category":
            label = ec.get(
                "label",
                DEFAULT_CATEGORY_LABEL.get(entity.type, f"[{entity.type}]"),
            )
            replacement = _resolve_collision(label, used_labels)
        else:
            replacement = _resolve_collision("[REDACTED]", used_labels)

        entity_replacements[entity.text] = replacement
        used_labels.add(replacement)
        result_key[replacement] = entity.text

    # Replace right-to-left
    sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
    result = text
    seen_positions: set[tuple[int, int]] = set()

    for entity in sorted_entities:
        pos = (entity.start, entity.end)
        if pos in seen_positions:
            continue
        seen_positions.add(pos)
        replacement = entity_replacements[entity.text]
        result = result[: entity.start] + replacement + result[entity.end :]

    return result, result_key
