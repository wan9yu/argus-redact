"""Cross-language regex patterns (email, etc.)."""

import base64
import json
import re as _re


def validate_luhn(value: str) -> bool:
    """Luhn checksum — shared by all languages' bank/credit card validation."""
    digits = [int(d) for d in value if d.isdigit()]
    if len(digits) < 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


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


# ISO 13616 IBAN length per country (15-34 chars)
_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22,
    "VG": 24, "XK": 20,
}


def _validate_iban(value: str) -> bool:
    """ISO 13616 IBAN validation: country length table + mod 97 checksum."""
    iban = value.replace(" ", "").upper()
    expected_len = _IBAN_LENGTHS.get(iban[:2]) if len(iban) >= 2 else None
    if expected_len is None or len(iban) != expected_len:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(
        str(ord(c) - 55) if c.isalpha() else c
        for c in rearranged
    )
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _validate_jwt(value: str) -> bool:
    """JWT format validation: 3 base64url segments; header decodes to JSON with 'alg' field."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        header_b64 = parts[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        return isinstance(header, dict) and "alg" in header
    except (ValueError, UnicodeDecodeError):
        return False


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
        "type": "iban",
        "label": "[IBAN]",
        "pattern": (
            r"(?<![A-Z0-9])"
            r"[A-Z]{2}\d{2}"
            r"(?:\s?[A-Z0-9]{4}){2,7}"
            r"\s?[A-Z0-9]{1,4}"
            r"(?![A-Z0-9])"
        ),
        "validate": _validate_iban,
        "description": "IBAN (ISO 13616, 80+ countries, mod 97 checksum)",
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
    # ── Credentials / Secrets (cross-language) ──
    {
        "type": "openai_api_key",
        "label": "[OPENAI-API-KEY]",
        "pattern": r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}",
        "description": "OpenAI API key (sk- or sk-proj- prefix; negative lookahead excludes sk-ant- anthropic keys)",
    },
    {
        "type": "anthropic_api_key",
        "label": "[ANTHROPIC-API-KEY]",
        "pattern": r"sk-ant-[A-Za-z0-9_-]{32,}",
        "description": "Anthropic API key (sk-ant- prefix)",
    },
    {
        "type": "aws_access_key",
        "label": "[AWS-ACCESS-KEY]",
        "pattern": r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
        "description": "AWS Access Key ID (AKIA + 16 uppercase alphanumeric)",
    },
    {
        "type": "github_token",
        "label": "[GITHUB-TOKEN]",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}",
        "description": "GitHub token (ghp/gho/ghu/ghs/ghr classic or github_pat_ fine-grained)",
    },
    {
        "type": "jwt",
        "label": "[JWT]",
        "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "validate": _validate_jwt,
        "description": "JWT (3 base64url segments; header must decode to JSON with 'alg' field)",
    },
    {
        "type": "ssh_private_key",
        "label": "[SSH-PRIVATE-KEY]",
        "pattern": (
            r"-----BEGIN (?:RSA |OPENSSH |DSA |EC )?PRIVATE KEY-----"
            r"[\s\S]+?"
            r"-----END (?:RSA |OPENSSH |DSA |EC )?PRIVATE KEY-----"
        ),
        "description": "SSH private key PEM block (RSA/OPENSSH/DSA/EC variants)",
    },
]
