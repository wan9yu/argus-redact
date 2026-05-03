"""replace() — convert pattern matches to redacted text + key."""

from __future__ import annotations

import functools
import hashlib
import hmac
import os
from typing import Callable

from argus_redact._types import PatternMatch
from argus_redact.pure.pseudonym import PseudonymGenerator

VALID_STRATEGIES = (
    "pseudonym",
    "realistic",
    "mask",
    "remove",
    "category",
    "name_mask",
    "landline_mask",
    "keep",
)

# Strategies whose output can be mapped back to the original via the key dict.
# Adding a new strategy to VALID_STRATEGIES requires classifying it here.
_REVERSIBLE_STRATEGIES = frozenset({"pseudonym", "realistic", "remove", "keep"})


def is_strategy_reversible(strategy: str) -> bool:
    """Return True if ``strategy`` produces output that ``restore()`` can map
    back to the original value.

    Reversible: ``pseudonym`` / ``realistic`` / ``remove`` / ``keep``.
    Irreversible (lossy by design): ``mask`` / ``name_mask`` / ``landline_mask``
    / ``category``.

    Use in multi-turn dialog flows to fall through to a reversible strategy
    when the LLM response must be restored to original PII for follow-up.
    """
    if strategy not in VALID_STRATEGIES:
        raise ValueError(
            f"Unknown strategy '{strategy}'. Valid: {', '.join(VALID_STRATEGIES)}"
        )
    return strategy in _REVERSIBLE_STRATEGIES


_MAX_REROLL_ATTEMPTS = 10  # well above expected HMAC collision rate for practical batch sizes


def _seed_from_value(value: str, type_name: str, salt: bytes) -> bytes:
    """Stable HMAC-derived 32-byte master key for a (type, value) pair under a salt.

    Output drives a SHAKE-256 stream consumed by ``_ShakeRng``. v0.6.0 returned
    the first 8 bytes as an int seed for ``random.Random`` (Mersenne Twister) —
    that path is gone: MT-19937 is reconstructible from output and breaks the
    realistic strategy's privacy guarantees under chosen-plaintext analysis.
    """
    msg = f"{type_name}:{value}".encode("utf-8")
    return hmac.new(salt, msg, hashlib.sha256).digest()


def _resolve_salt(seed: int | bytes | None) -> bytes:
    """Determine effective salt for HMAC seeding.

    Priority (caller-explicit wins, per design doc):
    1. Caller-provided salt (bytes) → used verbatim (full entropy preserved)
    2. Caller-provided seed (int) → 8-byte big-endian (back-compat; 64-bit entropy)
    3. Env var ARGUS_REDACT_PSEUDONYM_SALT → encoded bytes

    Pre-v0.6.1 silently returned ``b""`` when none of the three were available,
    which collapsed HMAC to a deterministic public hash (de-anonymizable with
    one observed pair). v0.6.1+ raises ``ValueError`` instead.
    """
    if isinstance(seed, (bytes, bytearray)):
        return bytes(seed)
    if isinstance(seed, int):
        return seed.to_bytes(8, "big", signed=False) if seed >= 0 else seed.to_bytes(8, "big", signed=True)
    env = os.environ.get("ARGUS_REDACT_PSEUDONYM_SALT")
    if env:
        return env.encode("utf-8")
    raise ValueError(
        "realistic strategy requires an explicit salt. Pass `seed=<int>` or "
        "`salt=<bytes>` to redact() / redact_pseudonym_llm(), or set "
        "ARGUS_REDACT_PSEUDONYM_SALT env var. Pre-v0.6.1 silently used b'' "
        "which produced predictable mappings."
    )


def _pseudonym_seed_int(seed: int | bytes | None) -> int | None:
    """Coerce ``seed`` into an int for ``PseudonymGenerator`` (which uses
    ``random.Random`` to derive non-cryptographic ``P-NNNNN`` codes — int seed
    is sufficient there; bytes get truncated to first 8 bytes BE).
    """
    if seed is None:
        return None
    if isinstance(seed, int):
        return seed
    if isinstance(seed, (bytes, bytearray)):
        return int.from_bytes(bytes(seed)[:8].ljust(8, b"\x00"), "big")
    raise TypeError(f"seed must be int, bytes, or None, got {type(seed).__name__}")


@functools.lru_cache(maxsize=128)
def _type_seed_offset(entity_type: str) -> int:
    """Stable per-type integer offset for PseudonymGenerator seed derivation.

    Replaces ``hash(entity_type) % 10000`` whose output varies across processes
    via PYTHONHASHSEED — that broke "same salt → same fake" across multi-worker
    deployments. SHA-256 of the UTF-8 type name is stable everywhere.
    """
    digest = hashlib.sha256(entity_type.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % 10000


class _ShakeRng:
    """Cryptographically-keyed PRNG replacing ``random.Random`` on the realistic path.

    Drives reserved-range fakers from a SHAKE-256 stream keyed by an HMAC-SHA256
    master derived from (salt, type, value). Exposes only the subset of
    ``random.Random`` used by ``specs/fakers_*.py``: ``randint`` and ``choice``.
    Output is uniform via rejection sampling (no modulo bias).
    """

    # Pre-compute bytes lazily; 256 is a safe ceiling for any current faker
    # (worst case: ~30 randint calls each consuming ≤ 4 bytes).
    _PRECOMPUTE_BYTES = 256

    __slots__ = ("_seed", "_buf", "_pos")

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError(f"_ShakeRng seed must be bytes, got {type(seed).__name__}")
        self._seed = bytes(seed)
        self._buf = hashlib.shake_256(self._seed).digest(self._PRECOMPUTE_BYTES)
        self._pos = 0

    def _take(self, n: int) -> bytes:
        end = self._pos + n
        if end > len(self._buf):
            # Extend: re-derive the digest at the new (larger) length.
            # SHAKE-256.digest(N) is deterministic in N — bytes [0:M] of
            # digest(N) for N>M equal digest(M).
            new_len = max(end + self._PRECOMPUTE_BYTES, len(self._buf) * 2)
            self._buf = hashlib.shake_256(self._seed).digest(new_len)
        chunk = self._buf[self._pos : end]
        self._pos = end
        return chunk

    def randint(self, a: int, b: int) -> int:
        """Uniform integer in ``[a, b]``. Uses rejection sampling to avoid
        modulo bias when ``b - a + 1`` is not a power of 256."""
        if b < a:
            raise ValueError(f"randint: empty range [{a}, {b}]")
        rng = b - a + 1
        bytes_needed = max(1, ((rng - 1).bit_length() + 7) // 8)
        max_unbiased = (1 << (bytes_needed * 8)) - ((1 << (bytes_needed * 8)) % rng)
        while True:
            n = int.from_bytes(self._take(bytes_needed), "big")
            if n < max_unbiased:
                return a + (n % rng)

    def choice(self, seq):
        """Uniformly pick one element of ``seq``. Empty seq raises IndexError."""
        if len(seq) == 0:
            raise IndexError("Cannot choose from an empty sequence")
        return seq[self.randint(0, len(seq) - 1)]


def _find_faker_reserved(name: str, langs: list[str] | None) -> Callable | None:
    """Find faker_reserved for a type, preferring detected langs, then 'shared', then any.

    Lang-aware lookup is required when zh and en both register same-named types
    (e.g., `phone`, `address`, `person`); without preference order, the first
    registered lang silently wins regardless of the entity's actual language.

    Cached on (name, lang_tuple) — registry is built at import and frozen.
    """
    return _faker_reserved_cached(name, tuple(langs or ()))


@functools.lru_cache(maxsize=256)
def _faker_reserved_cached(name: str, langs: tuple[str, ...]) -> Callable | None:
    from argus_redact.specs.registry import lookup

    by_lang = {td.lang: td for td in lookup(name)}
    for lang in langs:
        if lang in by_lang and by_lang[lang].faker_reserved:
            return by_lang[lang].faker_reserved
    if "shared" in by_lang and by_lang["shared"].faker_reserved:
        return by_lang["shared"].faker_reserved
    for td in by_lang.values():
        if td.faker_reserved:
            return td.faker_reserved
    return None


def _generate_unique_fake(
    faker_reserved: Callable,
    value: str,
    type_name: str,
    salt: bytes,
    used: set[str],
) -> tuple[str, list[str]]:
    """Call faker_reserved with HMAC-seeded RNG, re-rolling until unique within `used`.

    Returns ``(fake, aliases)``. faker_reserved must return
    ``tuple[str, list[str]]``; bare-string returns raise TypeError on unpack.
    """
    seed_input = value
    last = None
    # Reject identity-pass: faker must never return the input value as the fake.
    # Pre-fix only checked ``fake not in used``; with small reserved-name pools,
    # the HMAC-seeded RNG could pick the input back with non-trivial probability,
    # producing a "redacted" output bit-identical to the input.
    used_with_input = used | {value}
    for attempt in range(_MAX_REROLL_ATTEMPTS):
        master_key = _seed_from_value(seed_input, type_name, salt)
        rng = _ShakeRng(seed=master_key)
        fake, aliases_raw = faker_reserved(value, rng)
        aliases = list(aliases_raw)
        if fake not in used_with_input:
            return fake, aliases
        last = fake
        seed_input = f"{seed_input}#{attempt}"
    raise RuntimeError(
        f"Could not generate unique fake for {type_name} "
        f"after {_MAX_REROLL_ATTEMPTS} attempts (last: {last!r})"
    )

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
    # Self-reference: preserve pronouns / kinship verbatim so the LLM gets
    # an intelligible prompt. Detection still runs (feeds the
    # self_reference_tier hint); only the replacement is skipped.
    "self_reference": "keep",
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
    # Credentials / secrets (cross-language)
    "openai_api_key": "remove",
    "anthropic_api_key": "remove",
    "aws_access_key": "remove",
    "github_token": "remove",
    "jwt": "remove",
    "ssh_private_key": "remove",
}

DEFAULT_PREFIXES = {
    "person": "P",
    "organization": "O",
    # Pseudonym prefixes for remove-as-pseudonym strategy (improves LLM survival rate)
    "id_number": "ID",
    "passport": "PASS",
    "license_plate": "PLATE",
    "address": "ADDR",
    "ssn": "SSN",
    "military_id": "MIL",
    "social_security": "SOC",
    "credit_code": "BIZ",
    "date_of_birth": "DOB",
    "us_passport": "PASS",
    "job_title": "TITLE",
    "school": "SCH",
    "ethnicity": "ETH",
    "workplace": "WORK",
    "criminal_record": "CRIM",
    "financial": "FIN",
    "biometric": "BIO",
    "medical": "MED",
    "religion": "REL",
    "political": "POL",
    "sexual_orientation": "ORI",
    "ip_address": "IP",
    "mac_address": "MAC",
    "imei": "IMEI",
    "url_token": "URL",
    "age": "AGE",
    "gender": "GEN",
    "self_reference": "S",
    # Credentials / secrets
    "openai_api_key": "OAI-KEY",
    "anthropic_api_key": "ANT-KEY",
    "aws_access_key": "AWS-KEY",
    "github_token": "GH-TOKEN",
    "jwt": "JWT",
    "ssh_private_key": "SSH-KEY",
}

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
    seed: int | bytes | None = None,
    key: dict[str, str] | None = None,
    config: dict | None = None,
    langs: list[str] | None = None,
    unified_prefix: str | None = None,
) -> tuple[str, dict[str, str], dict[str, list[str]]]:
    """Replace detected entities in text, producing ``(redacted_text, key, aliases)``.

    config overrides default strategies per entity type. Example:
        {"phone": {"strategy": "remove", "replacement": "[TEL]"}}

    `langs` provides language preference for the realistic strategy's
    faker_reserved lookup (e.g., en text prefers en/phone over zh/phone).

    `unified_prefix` (v0.6.0+): if provided, all reversible-strategy types
    collapse to a single ``<prefix>-NNNNN`` form, hiding PII type information
    from the output. Replaces the legacy ``config["_unified_prefix"]`` sentinel.

    Returns ``(redacted_text, key, aliases)`` where ``aliases`` is
    ``{fake: list_of_aliases}`` for entries whose realistic-strategy fakers
    emitted aliases (empty dict when no realistic-strategy fakers ran).
    """
    _validate_config(config)
    if config and "_unified_prefix" in config:
        raise ValueError(
            "_unified_prefix is no longer accepted as a config key in v0.6.0. "
            "Use the top-level `unified_prefix=` kwarg on redact() / "
            "redact_pseudonym_llm() instead."
        )

    aliases: dict[str, list[str]] = {}

    if not entities:
        return text, key if key is not None else {}, aliases

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

    # Unified prefix mode: all types use same prefix (hides PII type from output)
    pseudo_seed_int = _pseudonym_seed_int(seed)
    pseudo_gen = PseudonymGenerator(
        prefix=unified_prefix or person_prefix,
        seed=pseudo_seed_int,
        existing_key=result_key if result_key else None,
    )
    org_gen = PseudonymGenerator(
        prefix=unified_prefix or org_prefix,
        seed=(pseudo_seed_int + 1) if pseudo_seed_int is not None else None,
        existing_key=result_key if result_key else None,
    )
    # Per-type pseudonym generators for remove strategy (improves LLM survival)
    _type_gens: dict[str, PseudonymGenerator] = {}

    def _get_type_gen(entity_type: str) -> PseudonymGenerator:
        if entity_type not in _type_gens:
            prefix = unified_prefix or DEFAULT_PREFIXES.get(entity_type, entity_type.upper()[:4])
            _type_gens[entity_type] = PseudonymGenerator(
                prefix=prefix,
                seed=(_pseudonym_seed_int(seed) + _type_seed_offset(entity_type)) if seed is not None else None,
                existing_key=result_key if result_key else None,
            )
        return _type_gens[entity_type]

    entity_replacements: dict[str, str] = {}

    for entity in entities:
        if entity.text in entity_replacements:
            continue
        if entity.text in reverse_index:
            entity_replacements[entity.text] = reverse_index[entity.text]
            continue

        ec = _get_entity_config(entity.type, config)
        strategy = ec.get("strategy", DEFAULT_STRATEGIES.get(entity.type, "remove"))

        if strategy == "keep":
            # Preserve original text — no placeholder, no key dict entry.
            # The entity still flows through hints / risk assessment because
            # detection ran upstream of replace().
            entity_replacements[entity.text] = entity.text
            continue

        if strategy == "pseudonym":
            prefix = ec.get("prefix", DEFAULT_PREFIXES.get(entity.type, "P"))
            if entity.type == "organization":
                if "prefix" in ec:
                    org_gen = PseudonymGenerator(
                        prefix=prefix,
                        seed=(pseudo_seed_int + 1) if pseudo_seed_int is not None else None,
                        existing_key=result_key if result_key else None,
                    )
                replacement = org_gen.get(entity.text)
            else:
                if "prefix" in ec:
                    pseudo_gen = PseudonymGenerator(
                        prefix=prefix,
                        seed=pseudo_seed_int,
                        existing_key=result_key if result_key else None,
                    )
                replacement = pseudo_gen.get(entity.text)
        elif strategy == "realistic":
            faker_reserved = _find_faker_reserved(entity.type, langs)

            if faker_reserved is not None:
                salt = _resolve_salt(seed)
                replacement, alias_list = _generate_unique_fake(
                    faker_reserved, entity.text, entity.type, salt, used_labels
                )
                if alias_list:
                    aliases[replacement] = alias_list
            elif entity.type == "organization":
                replacement = org_gen.get(entity.text)
            else:
                replacement = _get_type_gen(entity.type).get(entity.text)
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
            if "replacement" in ec:
                # User explicitly configured a label — respect it
                replacement = _resolve_collision(ec["replacement"], used_labels)
            else:
                # Use pseudonym-style codes (MED-00123) for LLM survival
                replacement = _get_type_gen(entity.type).get(entity.text)
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

    return result, result_key, aliases
