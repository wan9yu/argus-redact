"""Korean regex patterns for Layer 1 PII detection."""

PATTERNS = [
    {
        "type": "phone",
        "label": "[전화번호]",
        "pattern": r"01[016789]-?\d{3,4}-?\d{4}(?!\d)",
        "description": "Korean mobile phone (010/011/016/017/018/019)",
    },
    {
        "type": "phone",
        "label": "[전화번호]",
        "pattern": r"0[2-6]\d{0,1}-?\d{3,4}-?\d{4}(?!\d)",
        "description": "Korean landline phone",
    },
    {
        "type": "rrn",
        "label": "[주민등록번호]",
        "pattern": (
            r"(?<!\d)" r"\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])" r"-" r"[1-4]\d{6}" r"(?!\d)"
        ),
        "description": "Korean Resident Registration Number (YYMMDD-GXXXXXX)",
    },
]
