"""Chinese regex patterns for Layer 1 PII detection."""


def _validate_id_number(value: str) -> bool:
    """MOD 11-2 checksum for 18-digit Chinese national ID."""
    value = value.upper()
    if len(value) != 18:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_chars = "10X98765432"
    try:
        total = sum(int(value[i]) * weights[i] for i in range(17))
    except ValueError:
        return False
    return check_chars[total % 11] == value[17]


def _validate_luhn(value: str) -> bool:
    """Luhn checksum for bank card numbers."""
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


PATTERNS = [
    {
        "type": "phone",
        "label": "[手机号已脱敏]",
        "pattern": r"(?:\+86)?1[3-9]\d{9}(?!\d)",
        "description": "Chinese mobile phone number",
    },
    {
        "type": "phone",
        "label": "[电话号已脱敏]",
        "pattern": r"0[1-9]\d{1,2}-?\d{7,8}(?!\d)",
        "description": "Chinese landline phone number",
    },
    {
        "type": "id_number",
        "label": "[身份证号已脱敏]",
        "pattern": (
            r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}"
            r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
            r"\d{3}[\dXx](?!\d)"
        ),
        "validate": _validate_id_number,
        "description": "Chinese 18-digit national ID (MOD 11-2 checksum)",
    },
    {
        "type": "bank_card",
        "label": "[银行卡号已脱敏]",
        "pattern": r"(?<!\d)[3-6]\d{15,18}(?!\d)",
        "validate": _validate_luhn,
        "description": "Bank card number (16-19 digits, Luhn checksum)",
    },
    {
        "type": "passport",
        "label": "[护照号已脱敏]",
        "pattern": r"(?<![A-Za-z])[A-Z]\d{8}(?!\d)",
        "description": "Chinese passport number",
    },
    {
        "type": "license_plate",
        "label": "[车牌号已脱敏]",
        "pattern": (
            r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁]"
            r"[A-Z]"
            r"[·.]?"
            r"[A-Z0-9]{5,6}"
        ),
        "description": "Chinese license plate (normal + new energy)",
    },
    {
        "type": "address",
        "label": "[地址已脱敏]",
        "pattern": (
            r"(?:"
            # Branch 1: Province + city
            r"(?:(?:河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|"
            r"河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|台湾)省|"
            r"(?:内蒙古|广西|西藏|宁夏|新疆)(?:自治区)?)"
            r"[\u4e00-\u9fff]{2,6}(?:市|州)"
            r"|"
            # Branch 2: Municipality or standalone city (not preceded by CJK)
            r"(?:(?<![一-龥])(?:北京市|天津市|上海市|重庆市|[\u4e00-\u9fff]{2,5}(?:市|州)))"
            r")"
            # District
            r"[\u4e00-\u9fff]{1,8}(?:区|县|市|旗|新区)"
            # Street
            r"[\u4e00-\u9fff]{1,20}(?:路|街|道|巷|里|弄|村)"
            # Number / building / room (optional)
            r"(?:\d{1,5}(?:号|弄))?"
            r"(?:\d{1,3}(?:栋|幢|楼|座))?"
            r"(?:\d{1,4}(?:室|房))?"
        ),
        "description": "Chinese structured address (city+district+street+number)",
    },
]
