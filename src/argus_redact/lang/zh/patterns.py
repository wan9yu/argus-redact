"""Chinese regex patterns for Layer 1 PII detection.

Person name detection is handled separately by person.py (candidate + scoring).
This module only contains structural PII patterns (phone, ID, bank card, etc.).
"""

from argus_redact.lang.zh.surnames import SURNAMES as _SURNAMES


def _validate_id_number(value: str) -> bool:
    """MOD 11-2 checksum for 18-digit Chinese national ID.

    Strict: rejects invalid checksums to avoid false positives on 18-digit
    order numbers, serial numbers, etc. Trade-off: a user who types one wrong
    digit in their ID number will not have it detected.
    """
    value = value.replace(" ", "").replace("-", "").upper()
    if len(value) != 18:
        return False
    if not value[:17].isdigit():
        return False
    if value[17] not in "0123456789X":
        return False
    if value[0] == "0":
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_chars = "10X98765432"
    total = sum(int(value[i]) * weights[i] for i in range(17))
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


# 56 ethnic groups — full list for use with 民族 keyword prefix
_ETHNIC_GROUPS_ALL = (
    r"(?:汉|蒙古|回|藏|维吾尔|苗|彝|壮|布依|朝鲜|满|侗|瑶|白|土家|"
    r"哈尼|哈萨克|傣|黎|傈僳|佤|畲|高山|拉祜|水|东乡|纳西|景颇|"
    r"柯尔克孜|土|达斡尔|仫佬|羌|布朗|撒拉|毛南|仡佬|锡伯|阿昌|"
    r"普米|塔吉克|怒|乌孜别克|俄罗斯|鄂温克|德昂|保安|裕固|京|"
    r"塔塔尔|独龙|鄂伦春|赫哲|门巴|珞巴|基诺)"
)
# Safe subset for standalone XX族 — excludes 高山 (common word) and 土 (ambiguous)
_ETHNIC_GROUPS_SAFE = (
    r"(?:汉|蒙古|回|藏|维吾尔|苗|彝|壮|布依|朝鲜|满|侗|瑶|白|土家|"
    r"哈尼|哈萨克|傣|黎|傈僳|佤|畲|拉祜|水|东乡|纳西|景颇|"
    r"柯尔克孜|达斡尔|仫佬|羌|布朗|撒拉|毛南|仡佬|锡伯|阿昌|"
    r"普米|塔吉克|怒|乌孜别克|俄罗斯|鄂温克|德昂|保安|裕固|京|"
    r"塔塔尔|独龙|鄂伦春|赫哲|门巴|珞巴|基诺)"
)

_DISEASE_KEYWORDS = (
    r"(?:乙肝|丙肝|艾滋病|癌症|肿瘤|白血病|糖尿病|高血压|"
    r"冠心病|抑郁症|精神分裂|癫痫|肺结核|梅毒|淋病|尿毒症)"
)

PATTERNS = [
    {
        "type": "phone",
        "label": "[手机号已脱敏]",
        "pattern": r"(?<!\d)(?:\+86)?1[3-9]\d(?:[\s-]?\d){8}(?!\d)",
        "check_context": True,
        "description": "Chinese mobile phone number (with optional spaces/dashes)",
    },
    {
        "type": "phone",
        "label": "[电话号已脱敏]",
        "pattern": r"(?<!\d)0[1-9]\d{1,2}-?\d{7,8}(?!\d)",
        "description": "Chinese landline phone number",
    },
    {
        "type": "id_number",
        "label": "[身份证号已脱敏]",
        "pattern": (
            r"(?<!\d)[1-9]\d{5}[\s-]?(?:19|20)\d{2}[\s-]?"
            r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
            r"[\s-]?\d{3}[\dXx](?!\d)"
        ),
        "validate": _validate_id_number,
        "description": "Chinese 18-digit national ID (MOD 11-2, optional spaces/dashes)",
    },
    {
        "type": "bank_card",
        "label": "[银行卡号已脱敏]",
        "pattern": r"(?<!\d)[3-6]\d{3}(?:[\s-]?\d{4}){2,3}[\s-]?\d{1,4}(?!\d)",
        "validate": _validate_bank_card,
        "check_context": True,
        "description": "Bank card number (16-19 digits, optional spaces/dashes, Luhn or BIN prefix)",
    },
    {
        "type": "passport",
        "label": "[护照号已脱敏]",
        "pattern": (
            r"(?:护照\s*(?:号[码]?\s*)?[:：]?\s*)"
            r"(?P<passport>[A-Z]\d{8})"
            r"(?!\d)"
        ),
        "group": "passport",
        "description": "Chinese passport number (keyword-triggered, reduces false positives)",
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
            r"(?:[\u4e00-\u9fff]?(?:住在|位于|在|去|从|到))?"
            r"(?P<address>"
            r"(?:"
            # Branch 1: Province + city
            r"(?:(?:河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|"
            r"河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|台湾)省|"
            r"(?:内蒙古|广西|西藏|宁夏|新疆)(?:自治区)?)"
            r"[\u4e00-\u9fff]{2,6}(?:市|州)"
            r"|"
            # Branch 2: Municipality or standalone city
            r"(?:北京市|天津市|上海市|重庆市|[\u4e00-\u9fff]{2,5}(?:市|州))"
            r")"
            # District
            r"[\u4e00-\u9fff]{1,8}(?:区|县|市|旗|新区)"
            # Street
            r"[\u4e00-\u9fff]{1,20}(?:路|街|道|巷|里|弄|村)"
            # Number / building / room (optional)
            r"(?:\d{1,5}(?:号|弄))?"
            r"(?:\d{1,3}(?:栋|幢|楼|座))?"
            r"(?:\d{1,4}(?:室|房))?"
            r")"
        ),
        "group": "address",
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
    {
        "type": "job_title",
        "label": "[职务已脱敏]",
        "pattern": (
            r"(?:[\u4e00-\u9fff]{1,4}[的了]|的|了|是|找|问|请|让|给|跟|和|与)?"
            r"(?P<job_title>[\u4e00-\u9fff]{0,4}"
            r"(?:董事长|副董事长|总裁|副总裁|总经理|副总经理|总监|副总监|"
            r"经理|副经理|主任|副主任|院长|副院长|局长|副局长|处长|科长|"
            r"部长|厅长|司长|校长|园长|所长|站长|队长|组长|班长|排长|连长|"
            r"教授|副教授|讲师|助教|研究员|工程师|高级工程师|"
            r"医生|主治医生|主任医师|副主任医师|护士长|药剂师|"
            r"会计师|审计师|律师|法官|检察官|"
            r"CEO|CTO|CFO|COO|CIO|CMO|VP))"
        ),
        "group": "job_title",
        "description": "Job title (Chinese suffix + English abbreviations)",
    },
    {
        "type": "organization",
        "label": "[机构已脱敏]",
        "pattern": (
            r"(?:就职于|供职于|任职于|在|去|从|到|被|给|让)?"
            r"(?P<organization>(?<!\d)[\u4e00-\u9fff]{2,12}"
            r"(?:股份有限公司|有限责任公司|有限公司|责任公司|"
            r"集团公司|集团|公司|企业|工厂|银行|保险|证券|基金|"
            r"医院|诊所|药房|事务所|研究院|研究所|实验室))"
        ),
        "group": "organization",
        "description": "Chinese organization name (CJK prefix + legal/industry suffix)",
    },
    {
        "type": "school",
        "label": "[学校已脱敏]",
        "pattern": (
            r"(?:毕业于|就读于?|考入|考上|在|去|从|到)?"
            r"(?P<school>(?<!\d)[\u4e00-\u9fff]{2,10}"
            r"(?:大学|学院|中学|小学|高中|初中|附中|附小|"
            r"实验学校|外国语学校|师范学校|职业学校|技术学校|"
            r"幼儿园|书院|学堂|党校))"
        ),
        "group": "school",
        "description": "Chinese school name (CJK prefix + educational suffix)",
    },
    {
        "type": "ethnicity",
        "label": "[民族已脱敏]",
        "pattern": (
            r"(?:民族\s*[:：]?\s*)" + _ETHNIC_GROUPS_ALL + r"族"
            r"|"
            # Standalone XX族 without 民族 keyword — excludes 高山/土 (ambiguous as common words)
            + _ETHNIC_GROUPS_SAFE + r"族"
        ),
        "description": "Chinese ethnicity (56 ethnic groups, keyword-triggered or standalone XX族)",
    },
    {
        "type": "workplace",
        "label": "[工作单位已脱敏]",
        "pattern": (
            r"(?:工作单位|单位|就职于|供职于|任职于)\s*[:：]?\s*"
            r"(?P<workplace>[\u4e00-\u9fff]{2,20})"
        ),
        "group": "workplace",
        "description": "Chinese workplace (keyword-triggered, CJK text after keyword)",
    },
    # ── Level 3 sensitive attributes (explicit keyword detection) ──
    {
        "type": "criminal_record",
        "label": "[犯罪记录已脱敏]",
        "pattern": (
            r"(?:有前科|犯罪记录|案底|刑事拘留|行政拘留|"
            r"判刑[\u4e00-\u9fff\d]+[年月天]|"
            r"拘留[\u4e00-\u9fff\d]+[天日]|"
            r"被判处|缓刑|假释|取保候审|逮捕|起诉|定罪|"
            r"服刑|入狱|坐牢|监禁)"
        ),
        "description": "Criminal record (explicit keywords: 前科/判刑/拘留/犯罪记录)",
    },
    {
        "type": "financial",
        "label": "[财务信息已脱敏]",
        "pattern": (
            r"(?:月薪|年薪|年收入|月收入|工资|底薪|税后收入|税前收入)"
            r"[\d.]+[万元千百]+"
            r"|(?:欠债|负债|欠款|贷款余额|房贷余额|车贷余额|信用卡欠款)"
            r"[\d.]+[万元千百]+"
            r"|信用评分\d+分?"
            r"|(?:房贷|车贷|消费贷|网贷|借款)[\d.]+[万元千百]+"
        ),
        "description": "Financial info (salary/debt/credit score/loan with amounts)",
    },
    {
        "type": "biometric",
        "label": "[生物特征已脱敏]",
        "pattern": (
            r"(?:指纹(?:信息|采集|录入|比对|识别)|"
            r"DNA(?:检测|鉴定|样本|比对|信息)|"
            r"人脸(?:识别|采集|比对|信息|图像)|"
            r"虹膜(?:扫描|识别|采集|信息)|"
            r"声纹(?:录入|识别|采集|信息)|"
            r"掌纹(?:采集|识别|信息)|"
            r"基因(?:检测|信息|序列|样本))"
        ),
        "description": "Biometric data (fingerprint/DNA/face/iris/voiceprint)",
    },
    {
        "type": "medical",
        "label": "[医疗信息已脱敏]",
        "pattern": (
            r"(?:确诊|诊断为|患有|患了|罹患|检出|得了|查出来是|查出)"
            r"(?P<medical>[\u4e00-\u9fff]{2,8})"
        ),
        "group": "medical",
        "description": "Medical diagnosis (keyword-triggered, preserves trigger verb)",
    },
    {
        "type": "medical",
        "label": "[医疗信息已脱敏]",
        "pattern": (
            r"(?:服用|注射|口服|吃的|吃了|开了)"
            r"(?P<medical>[\u4e00-\u9fff\w]{2,10})"
        ),
        "group": "medical",
        "description": "Medical medication (keyword-triggered, preserves trigger verb)",
    },
    {
        "type": "medical",
        "label": "[医疗信息已脱敏]",
        "pattern": (
            r"HIV[阳阴]性"
            r"|" + _DISEASE_KEYWORDS +
            r"|[\u4e00-\u9fff]{2,6}手术"
        ),
        "description": "Medical standalone (HIV/disease names/surgery)",
    },
    {
        "type": "religion",
        "label": "[宗教信仰已脱敏]",
        "pattern": (
            r"(?:基督徒|天主教徒|穆斯林|佛教徒|道教徒|印度教徒|犹太教徒|"
            r"新教徒|东正教徒|摩门教徒)"
            r"|(?:做礼拜|做弥撒|诵经|念佛|斋月|受洗入教|受洗|皈依|"
            r"朝圣|祷告|礼拜日|安息日)"
            r"|(?:信仰|信奉)[\u4e00-\u9fff]{2,6}"
        ),
        "description": "Religious belief (believer types/practices/declarations)",
    },
    {
        "type": "political",
        "label": "[政治观点已脱敏]",
        "pattern": (
            r"(?:政治面貌\s*[:：]?\s*[\u4e00-\u9fff]{2,6})"
            r"|(?:党员|团员|共青团员|民主党派|无党派|群众)"
            r"|(?:投票(?:给了?|支持)[\u4e00-\u9fff\w]{2,10})"
            r"|(?:抗议游行|示威游行|集会抗议|政治集会|罢工)"
        ),
        "description": "Political opinion (party membership/voting/protest)",
    },
    {
        "type": "sexual_orientation",
        "label": "[性取向已脱敏]",
        "pattern": (
            r"(?:同性恋|双性恋|异性恋|无性恋|泛性恋)"
            # 同志 excluded: too ambiguous (also means "comrade" in political context)
            r"|(?:出柜|LGBTQ?|酷儿|GAY|gay|彩虹旗)"
        ),
        "description": "Sexual orientation (explicit terms)",
    },
    # ── Self-reference (first-person pronouns + kinship) ──
    {
        "type": "self_reference",
        "label": "[自称已脱敏]",
        "pattern": (
            r"我(?:妈妈|爸爸|母亲|父亲|老公|老婆|丈夫|妻子|先生|太太"
            r"|儿子|女儿|哥哥|姐姐|弟弟|妹妹|哥|姐|弟|妹|妈|爸"
            r"|爷爷|奶奶|外公|外婆|叔叔|阿姨|舅舅|姑姑"
            r"|家人|家里人|孩子)"
        ),
        "description": "Self-reference with kinship (我妈/我爸/我老公/...)",
    },
    {
        "type": "self_reference",
        "label": "[自称已脱敏]",
        "pattern": r"我们的|我们|我的|我",
        "description": "Self-reference pronoun (我/我的/我们/我们的)",
    },
]
