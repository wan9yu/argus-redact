"""Compliance profiles — pre-configured type sets and strategy overrides."""

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
        "description": "US HIPAA — 18 PHI identifiers",
        "types": [
            "phone",
            "id_number",
            "ssn",
            "date_of_birth",
            "email",
            "address",
            "person",
            "ip_address",
        ],
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
