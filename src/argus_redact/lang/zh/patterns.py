"""Chinese regex patterns for Layer 1 PII detection."""

# ── Top 500 Chinese surnames (covers ~99% of population) ──
_SURNAMES = (
    "王李张刘陈杨赵黄周吴徐孙胡朱高林何郭马罗"
    "梁宋郑谢韩唐冯于董萧程曹袁邓许傅沈曾彭吕"
    "苏卢蒋蔡贾丁魏薛叶阎余潘杜戴夏钟汪田任姜"
    "范方石姚谭廖邹熊金陆郝孔白崔康毛邱秦江史顾"
    "侯邵孟龙万段漕钱汤尹黎易常武乔贺赖龚文庞"
    "樊兰殷施陶洪翟安颜倪严牛温芦季俞章鲁葛伍"
    "韦申尤毕聂丛焦向柳邢骆岳齐沿雷詹欧"
)

# Build set for O(1) lookup
_SURNAME_SET = set(_SURNAMES)

# Compound surnames (2 chars)
_COMPOUND_SURNAMES = {
    "欧阳", "司马", "上官", "诸葛", "东方", "皇甫", "令狐", "公孙",
    "慕容", "尉迟", "长孙", "宇文", "司徒", "端木", "南宫", "西门",
}


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
    # ── Person name (surname-prefix heuristic) ──
    # Uses named group "name" so match_patterns extracts just the name, not the context.
    # Pattern 1: context word + optional colon/space → surname + 1-2 CJK given name chars
    {
        "type": "person",
        "label": "[姓名已脱敏]",
        "group": "name",
        "pattern": (
            r"(?:客户|患者|用户|旅客|车主|联系人|收件人|寄件人|"
            r"登记人|开户人|申请人|报案人|委托人|当事人|嫌疑人|"
            r"负责人|经办人|签收人|担保人|受益人|借款人|"
            r"持卡人|被保险人|投保人|参会人员|"
            r"主治医生|医生|护士|教授|老板|同事|朋友|同学|"
            r"姓名|乘客|住户|业主|租户|房东)"
            r"[：:\s]?"
            r"(?P<name>[" + _SURNAMES + r"][\u4e00-\u9fff]{1,2}(?<!的)(?<!了)(?<!在)(?<!是)(?<!有)(?<!和)(?<!与)(?<!把)(?<!被)(?<!让)(?<!从)(?<!到)(?<!给)(?<!向)(?<!因)(?<!为)(?<!而)(?<!又)(?<!也)(?<!都)(?<!就)(?<!才)(?<!会)(?<!能)(?<!要)(?<!可)(?<!将)(?<!已)(?<!完)(?<!开)(?<!做))"
        ),
        "description": "Chinese person name after context prefix",
    },
    # Pattern 2: surname + 1-2 CJK → honorific suffix (lookahead OK — fixed width not needed)
    {
        "type": "person",
        "label": "[姓名已脱敏]",
        "pattern": (
            r"[" + _SURNAMES + r"][\u4e00-\u9fff]{1,2}"
            r"(?=(?:先生|女士|老师|教授|医生|同学|师傅|经理|总监|主任|院长|局长|部长|校长|董事长))"
        ),
        "description": "Chinese person name before honorific suffix",
    },
]
