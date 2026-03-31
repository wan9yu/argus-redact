"""replace() — convert pattern matches to redacted text + key."""

from __future__ import annotations

from argus_redact._types import PatternMatch
from argus_redact.pure.pseudonym import PseudonymGenerator

VALID_STRATEGIES = ("pseudonym", "mask", "remove", "category", "name_mask", "landline_mask")

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
    # Level 2
    "job_title": "remove",
    "school": "pseudonym",
    "ethnicity": "remove",
    "workplace": "remove",
    # Level 3
    "criminal_record": "remove",
    "financial": "remove",
    "biometric": "remove",
    "medical": "remove",
    "religion": "remove",
    "political": "remove",
    "sexual_orientation": "remove",
    # Level 4
    "ip_address": "remove",
    "mac_address": "remove",
    "imei": "remove",
    "url_token": "remove",
    "age": "remove",
    "gender": "remove",
    "date_of_birth": "remove",
    "military_id": "remove",
    "social_security": "remove",
    "credit_code": "remove",
    "us_passport": "remove",
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
        "military_id": "[军官证号已脱敏]",
        "social_security": "[社保号已脱敏]",
        "credit_code": "[信用代码已脱敏]",
        "date_of_birth": "[出生日期已脱敏]",
        "job_title": "[职务已脱敏]",
        "school": "[学校已脱敏]",
        "ethnicity": "[民族已脱敏]",
        "workplace": "[工作单位已脱敏]",
        "criminal_record": "[犯罪记录已脱敏]",
        "financial": "[财务信息已脱敏]",
        "biometric": "[生物特征已脱敏]",
        "medical": "[医疗信息已脱敏]",
        "religion": "[宗教信仰已脱敏]",
        "political": "[政治观点已脱敏]",
        "sexual_orientation": "[性取向已脱敏]",
    },
    "en": {
        "ssn": "[SSN REDACTED]",
        "credit_card": "[CARD REDACTED]",
        "address": "[ADDRESS REDACTED]",
        "us_passport": "[PASSPORT REDACTED]",
        "date_of_birth": "[DOB REDACTED]",
        "criminal_record": "[CRIMINAL REDACTED]",
        "financial": "[FINANCIAL REDACTED]",
        "biometric": "[BIOMETRIC REDACTED]",
        "medical": "[MEDICAL REDACTED]",
        "religion": "[RELIGION REDACTED]",
        "political": "[POLITICAL REDACTED]",
        "sexual_orientation": "[ORIENTATION REDACTED]",
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
    # Shared patterns (all languages)
    "shared": {
        "ip_address": "[IP REDACTED]",
        "mac_address": "[MAC REDACTED]",
        "imei": "[IMEI REDACTED]",
        "url_token": "[URL REDACTED]",
        "age": "[AGE REDACTED]",
        "gender": "[GENDER REDACTED]",
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


def _mask_value(
    value: str,
    entity_type: str,
    *,
    visible_prefix: int = 0,
    visible_suffix: int = 0,
) -> str:
    """Apply mask strategy: show prefix + suffix, mask middle.

    If visible_prefix/suffix are given via config, use those.
    Otherwise use per-type defaults.
    """
    if entity_type == "email":
        at = value.find("@")
        if at > 0:
            local = value[:at]
            domain = value[at:]
            visible = local[0] if local else ""
            return f"{visible}{'*' * max(len(local) - 1, 3)}{domain}"
        return value

    # Per-type defaults
    defaults = {
        "phone": (3, 4),
        "bank_card": (6, 4),
        "credit_card": (6, 4),
        "id_number": (4, 4),
    }
    prefix_len = visible_prefix or defaults.get(entity_type, (3, 4))[0]
    suffix_len = visible_suffix or defaults.get(entity_type, (3, 4))[1]

    if len(value) <= prefix_len + suffix_len:
        return "*" * len(value)
    masked_len = len(value) - prefix_len - suffix_len
    return f"{value[:prefix_len]}{'*' * masked_len}{value[-suffix_len:]}"


def _mask_name(value: str) -> str:
    """Chinese name mask: 张* / 李** / 欧阳**."""
    length = len(value)
    if length <= 1:
        return "*"
    if length <= 3:
        return value[0] + "*" * (length - 1)
    # 4+ chars: show first 2
    return value[:2] + "*" * (length - 2)


def _mask_landline(value: str) -> str:
    """Landline mask: keep area code + last 3, mask middle."""
    # Split area code (0xx or 0xxx) from number
    dash_pos = value.find("-")
    if dash_pos > 0:
        area = value[: dash_pos + 1]
        number = value[dash_pos + 1 :]
    elif value.startswith("0"):
        # Guess area code length: 3 for 010/02x, 4 for 0xxx
        area_len = 3 if value[1] in "12" else 4
        area = value[:area_len]
        number = value[area_len:]
    else:
        area = ""
        number = value

    if len(number) <= 3:
        return area + number
    masked = "*" * (len(number) - 3) + number[-3:]
    return area + masked


def _mask_phone_regional(value: str, *, region: str = "cn") -> str:
    """Phone mask with regional rules.

    cn (mainland): 137****5678 (3+4+4)
    hk (Hong Kong): 90****56 (2+4+2)
    tw (Taiwan): 90****567 (2+4+3)
    default: first 2 + **** + last 2
    """
    digits = value.replace("-", "").replace(" ", "")

    if region == "cn" or (region == "auto" and len(digits) == 11):
        p, s = 3, 4
    elif region == "hk" or (region == "auto" and len(digits) == 8):
        p, s = 2, 2
    elif region == "tw" or (region == "auto" and len(digits) == 9):
        p, s = 2, 3
    else:
        p, s = 2, 2

    if len(digits) <= p + s:
        return "*" * len(digits)
    masked_len = len(digits) - p - s
    return digits[:p] + "*" * masked_len + digits[-s:]


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
            replacement = _mask_value(
                entity.text,
                entity.type,
                visible_prefix=ec.get("visible_prefix", 0),
                visible_suffix=ec.get("visible_suffix", 0),
            )
            replacement = _resolve_collision(replacement, used_labels)
        elif strategy == "name_mask":
            replacement = _mask_name(entity.text)
            replacement = _resolve_collision(replacement, used_labels)
        elif strategy == "landline_mask":
            replacement = _mask_landline(entity.text)
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
