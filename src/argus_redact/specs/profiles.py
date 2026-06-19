"""Compliance profiles — pre-configured type sets and strategy overrides.

Caveat — these are **strategy-override presets, not coverage guarantees.**
``gdpr`` and ``pipl`` change *how* detected types are redacted (forcing
``remove``/``realistic`` over the leaky ``mask`` default), not *which* types are
detected. Selecting one does not widen — or narrow — detection coverage, and it
does not by itself make a pipeline compliant: compliance depends on what the
detectors find, the review process, and legal review, not on the profile name.
(Unlike the old ``hipaa`` whitelist, which restricted the detected type set and
thereby under-redacted — fixed in v0.7.9 so that ``hipaa`` now applies strict
strategies over *all* detected identifiers rather than reducing coverage.)
"""

# Strategy overrides: compliance profiles force pseudonym/remove for types
# that default to mask, because mask leaks partial information (e.g., 138****5678
# reveals 3+4 digits, narrowing search space to ~10,000 numbers).
_STRICT_STRATEGIES = {
    "phone": {"strategy": "remove"},
    "email": {"strategy": "remove"},
    "bank_card": {"strategy": "remove"},
    "credit_card": {"strategy": "remove"},
}

_PSEUDONYM_LLM_STRATEGIES = {
    # zh + en (lang-aware faker_reserved lookup picks the right one)
    "person": {"strategy": "realistic"},
    "phone": {"strategy": "realistic"},
    "phone_landline": {"strategy": "realistic"},
    "address": {"strategy": "realistic"},
    "id_number": {"strategy": "realistic"},
    "bank_card": {"strategy": "realistic"},
    "license_plate": {"strategy": "realistic"},
    "passport": {"strategy": "realistic"},
    "age": {"strategy": "realistic"},
    "date_of_birth": {"strategy": "realistic"},
    # en-specific
    "ssn": {"strategy": "realistic"},
    "credit_card": {"strategy": "realistic"},
    # shared (RFC reserved)
    "email": {"strategy": "realistic"},
    "ip_address": {"strategy": "realistic"},
    "mac_address": {"strategy": "realistic"},
}

PROFILES = {
    "default": {
        "description": "All Level 1 direct identifiers",
    },
    "pipl": {
        "description": "China PIPL — all personal information types",
        "config": _STRICT_STRATEGIES,
    },
    "gdpr": {
        "description": "EU GDPR — personal data and special categories",
        "config": _STRICT_STRATEGIES,
    },
    "hipaa": {
        "description": "US HIPAA — strict strategies over all detected identifiers",
        "config": _STRICT_STRATEGIES,
    },
    "pseudonym-llm": {
        "description": "Realistic reserved-range fake data for LLM-friendly redaction",
        "config": _PSEUDONYM_LLM_STRATEGIES,
    },
}


def get_profile(name: str) -> dict:
    """Get a compliance profile by name. Raises ValueError if unknown."""
    if name not in PROFILES:
        raise ValueError(f"Unknown profile '{name}'. Available: {', '.join(PROFILES)}")
    return PROFILES[name]
