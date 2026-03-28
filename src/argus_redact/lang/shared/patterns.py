"""Cross-language regex patterns (email, etc.)."""

PATTERNS = [
    {
        "type": "email",
        "label": "[邮箱已脱敏]",
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "description": "Email address (RFC 5322 simplified)",
    },
    {
        "type": "ip_address",
        "label": "[IP已脱敏]",
        "pattern": (
            r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?!\d)"
        ),
        "check_context": True,
        "description": "IPv4 address",
    },
    {
        "type": "ip_address",
        "label": "[IP已脱敏]",
        "pattern": (
            r"(?<![:\w])"
            r"(?:"
            r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"    # full
            r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"  # middle ::
            r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                  # trailing ::
            r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}" # leading ::
            r"|::1"                                            # loopback
            r")"
        ),
        "description": "IPv6 address (full, collapsed, loopback)",
    },
]
