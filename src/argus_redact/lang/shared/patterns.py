"""Cross-language regex patterns (email, etc.)."""

PATTERNS = [
    {
        "type": "email",
        "label": "[邮箱已脱敏]",
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "description": "Email address (RFC 5322 simplified)",
    },
]
