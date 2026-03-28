"""Chinese regex patterns for Layer 1 PII detection.

Person name detection is handled separately by person.py (candidate + scoring).
This module only contains structural PII patterns (phone, ID, bank card, etc.).
"""

from argus_redact.lang.zh.surnames import SURNAMES as _SURNAMES


def _validate_id_number(value: str) -> bool:
    """MOD 11-2 checksum for 18-digit Chinese national ID."""
    # Strip spaces (chat-style formatting)
    value = value.replace(" ", "").upper()
    if len(value) != 18:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_chars = "10X98765432"
    try:
        total = sum(int(value[i]) * weights[i] for i in range(17))
    except ValueError:
        return False
    return check_chars[total % 11] == value[17]


# Known Chinese bank BIN prefixes (6 digits)
_BANK_BINS = {
    "621700", "621660", "621662", "621663",  # 建设银行
    "622202", "622200", "622208", "621225",  # 工商银行
    "622848", "622849", "620059", "621282",  # 农业银行
    "622568", "622569", "625912", "625911",  # 中国银行
    "622588", "622598", "621483", "622575",  # 招商银行
    "622155", "622156", "622157", "621002",  # 交通银行
    "622689", "622688", "621691", "622622",  # 民生银行
    "622668", "622669", "622670", "622671",  # 中信银行
    "622630", "622631", "622632", "622633",  # 浦发银行
    "621283", "621285", "621286", "621484",  # 光大银行
    "622580", "622581", "622582", "622583",  # 兴业银行
    "622150", "622151", "622152", "622153",  # 平安银行
    "622700", "622701", "622690", "622692",  # 邮储银行
}


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


# GB 32100-2015 Unified Social Credit Code constants
_CREDIT_CODE_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_CREDIT_CODE_CHAR_TO_VAL = {c: i for i, c in enumerate(_CREDIT_CODE_CHARSET)}
_CREDIT_CODE_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)


def _validate_credit_code(value: str) -> bool:
    """MOD 31 checksum for 18-char Unified Social Credit Code (GB 32100-2015)."""
    value = value.upper()
    if len(value) != 18:
        return False
    if any(c not in _CREDIT_CODE_CHAR_TO_VAL for c in value):
        return False
    total = sum(_CREDIT_CODE_CHAR_TO_VAL[value[i]] * _CREDIT_CODE_WEIGHTS[i] for i in range(17))
    check = (31 - total % 31) % 31
    return _CREDIT_CODE_CHAR_TO_VAL[value[17]] == check


def _validate_bank_card(value: str) -> bool:
    """Validate bank card: Luhn OR known BIN prefix."""
    digits = "".join(d for d in value if d.isdigit())
    if len(digits) < 16:
        return False
    # Pass if Luhn valid
    if _validate_luhn(value):
        return True
    # Fallback: accept if starts with a known Chinese bank BIN
    return digits[:6] in _BANK_BINS


PATTERNS = [
    {
        "type": "phone",
        "label": "[手机号已脱敏]",
        "pattern": r"(?:\+86)?1[3-9]\d(?:[\s-]?\d){8}(?!\d)",
        "check_context": True,
        "description": "Chinese mobile phone number (with optional spaces/dashes)",
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
            r"(?<!\d)[1-9]\d{5}\s?(?:19|20)\d{2}"
            r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
            r"\s?\d{3}[\dXx](?!\d)"
        ),
        "validate": _validate_id_number,
        "description": "Chinese 18-digit national ID (MOD 11-2, optional spaces)",
    },
    {
        "type": "bank_card",
        "label": "[银行卡号已脱敏]",
        "pattern": r"(?<!\d)[3-6]\d{15,18}(?!\d)",
        "validate": _validate_bank_card,
        "check_context": True,
        "description": "Bank card number (16-19 digits, Luhn or BIN prefix)",
    },
    {
        "type": "passport",
        "label": "[护照号已脱敏]",
        "pattern": r"(?<![A-Za-z0-9])[A-Z]\d{8}(?!\d)",
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
    # Informal address: known district/area name + street (no province/city prefix)
    {
        "type": "address",
        "label": "[地址已脱敏]",
        "pattern": (
            r"(?:朝阳|海淀|东城|西城|丰台|通州|大兴|昌平|顺义|房山|"
            r"浦东|黄浦|徐汇|静安|长宁|虹口|杨浦|闵行|宝山|嘉定|"
            r"天河|越秀|海珠|白云|番禺|荔湾|黄埔|花都|增城|从化|"
            r"南山|福田|罗湖|宝安|龙岗|龙华|盐田|坪山|光明|"
            r"西湖|上城|拱墅|滨江|萧山|余杭|临平|钱塘|富阳|"
            r"武侯|锦江|青羊|金牛|成华|龙泉驿|新都|温江|双流|"
            r"鼓楼|玄武|建邺|秦淮|栖霞|江宁|雨花台|浦口|六合|"
            r"武昌|洪山|江汉|汉阳|青山|江岸|硚口|东西湖|蔡甸)"
            r"[\u4e00-\u9fff]{1,20}(?:路|街|道|大道|大街)"
            r"(?:\d{1,5}(?:号|弄))?"
            r"(?:\d{1,3}(?:栋|幢|楼|座))?"
            r"(?:\d{1,4}(?:室|房))?"
        ),
        "description": "Informal Chinese address (district+street, no city prefix)",
    },
    {
        "type": "qq",
        "label": "[QQ号已脱敏]",
        "pattern": r"[Qq]{2}\s*(?:[:：是]?\s*)(?P<qq>[1-9]\d{4,11})(?!\d)",
        "group": "qq",
        "description": "QQ number (5-12 digits, requires QQ keyword context)",
    },
    {
        "type": "wechat",
        "label": "[微信号已脱敏]",
        "pattern": (
            r"(?:微信|wx|WeChat|wechat)\s*(?:号)?\s*[:：]?\s*"
            r"(?P<wechat>[a-zA-Z][a-zA-Z0-9_\-]{5,19})"
        ),
        "group": "wechat",
        "description": "WeChat ID (letter-start, 6-20 chars, requires keyword context)",
    },
    {
        "type": "credit_code",
        "label": "[信用代码已脱敏]",
        "pattern": r"(?<![A-Za-z0-9])[0-9A-HJ-NP-RTUW-Ya-hj-np-rtuw-y]{2}\d{6}[0-9A-HJ-NP-RTUW-Ya-hj-np-rtuw-y]{10}(?![A-Za-z0-9])",
        "validate": _validate_credit_code,
        "description": "Unified Social Credit Code (GB 32100-2015, MOD 31)",
    },
    {
        "type": "date_of_birth",
        "label": "[出生日期已脱敏]",
        "pattern": (
            r"(?:出生日期|出生|生日|生于|born)\s*(?:[:：是]?\s*)"
            r"(?P<date_of_birth>"
            # YYYY年M月D日/号（Arabic numerals）
            r"(?:(?:19|20)\d{2}|[0-9]{2})年(?:0?[1-9]|1[0-2])月(?:(?:0?[1-9]|[12]\d|3[01])(?:日|号))?"
            r"|"
            # Chinese numeral month + day
            r"(?:十[一二]|[一二三四五六七八九十])月(?:(?:二?十)?[一二三四五六七八九](?:日|号))?"
            r"|"
            # YYYY-MM-DD / YYYY/MM/DD / YYYY.MM.DD
            r"(?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])"
            r"|"
            # MM/DD/YYYY
            r"(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}"
            r")"
        ),
        "group": "date_of_birth",
        "description": "Chinese date of birth (keyword-triggered, multiple formats)",
    },
    {
        "type": "military_id",
        "label": "[军官证号已脱敏]",
        "pattern": (
            r"(?:军字第|武字第|士兵证号?|义务兵证号?)\s*"
            r"(?P<military_id>\d{8})"
            r"(?:号)?"
        ),
        "group": "military_id",
        "description": "Chinese military ID number (keyword-triggered, 8 digits)",
    },
    {
        "type": "social_security",
        "label": "[社保号已脱敏]",
        "pattern": (
            r"(?:社保号|社保卡号|社会保障号)\s*(?:[:：]?\s*)"
            r"(?P<social_security>"
            r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]"
            r"|[A-Z]\d{8,12}"
            r")"
        ),
        "group": "social_security",
        "description": "Chinese social security number (18-digit ID or city-specific format, keyword-triggered)",
    },
]
