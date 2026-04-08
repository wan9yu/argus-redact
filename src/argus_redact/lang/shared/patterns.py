"""Cross-language regex patterns (email, etc.)."""


import re as _re


def _validate_age(value: str) -> bool:
    """Reject unrealistic ages (>149)."""
    digits = _re.findall(r"\d+", value)
    if not digits:
        return False
    age = int(digits[0])
    return age <= 149


def _validate_email(value: str) -> bool:
    """Reject emails with consecutive dots or leading/trailing dots in local part."""
    local = value.split("@")[0] if "@" in value else ""
    if ".." in local or local.startswith(".") or local.endswith("."):
        return False
    return True


PATTERNS = [
    {
        "type": "email",
        "label": "[邮箱已脱敏]",
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "validate": _validate_email,
        "description": "Email address (ASCII local-part, no consecutive dots)",
    },
    {
        "type": "email",
        "label": "[邮箱已脱敏]",
        "pattern": r"[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]{1,10}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "validate": _validate_email,
        "description": "Email address (CJK-only local-part, RFC 6531 internationalized)",
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
        "type": "gender",
        "label": "[性别已脱敏]",
        "pattern": (
            # Chinese: 性别+男/女, 男性/女性
            r"性别\s*[:：]?\s*[男女]"
            r"|[男女]性"
            r"|"
            # English: gender/sex + value
            r"(?i:gender|sex)\s*[:.]?\s*(?:male|female|man|woman|M|F)"
        ),
        "description": "Gender (Chinese 性别/男性/女性 + English gender/sex)",
    },
    {
        "type": "age",
        "label": "[年龄已脱敏]",
        "validate": _validate_age,
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
