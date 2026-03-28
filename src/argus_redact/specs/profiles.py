"""Compliance profiles — pre-configured type sets for different regulations."""

PROFILES = {
    "default": {
        "description": "All Level 1 direct identifiers",
    },
    "pipl": {
        "description": "China PIPL — all personal information types",
    },
    "gdpr": {
        "description": "EU GDPR — personal data and special categories",
    },
    "hipaa": {
        "description": "US HIPAA — 18 PHI identifiers",
        "types": [
            "phone", "id_number", "ssn", "date_of_birth", "email",
            "address", "person", "ip_address",
        ],
    },
}


def get_profile(name: str) -> dict:
    """Get a compliance profile by name. Raises ValueError if unknown."""
    if name not in PROFILES:
        raise ValueError(
            f"Unknown profile '{name}'. Available: {', '.join(PROFILES)}"
        )
    return PROFILES[name]
