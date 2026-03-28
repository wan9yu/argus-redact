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
    {
        "type": "mac_address",
        "label": "[MAC已脱敏]",
        "pattern": r"(?<![0-9A-Fa-f:.-])[0-9A-Fa-f]{2}(?:[:.-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:.-])",
        "description": "MAC address (colon/dash/dot separated)",
    },
    {
        "type": "imei",
        "label": "[IMEI已脱敏]",
        "pattern": r"(?i:IMEI)\s*(?:号|[:：])?\s*(?P<imei>\d{15})(?!\d)",
        "group": "imei",
        # Luhn check deferred — keyword anchor sufficient for redaction
        "description": "IMEI device identifier (15 digits, keyword-triggered)",
    },
    {
        "type": "url_token",
        "label": "[URL已脱敏]",
        "pattern": (
            r"https?://[^\s]+[?&]"
            r"(?:token|api_key|access_token|secret|key|auth|session_id|password)"
            r"=[^\s&]+"
        ),
        "description": "URL with sensitive token/key parameter",
    },
    {
        "type": "age",
        "label": "[年龄已脱敏]",
        "pattern": (
            # Chinese: X岁, 年龄:X, 周岁X
            r"\d{1,3}岁"
            r"|(?:年龄|周岁)\s*[:：]?\s*\d{1,3}"
            r"|"
            # English: X years old, X-year-old, aged X
            r"\d{1,3}\s*[-‐]?\s*years?\s*[-‐]?\s*old"
            r"|aged\s+\d{1,3}"
        ),
        "description": "Age (Chinese 岁/年龄/周岁 + English years old/aged)",
    },
]
