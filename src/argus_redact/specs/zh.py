"""Chinese PII type definitions.

Each register() call defines a PII type AND attaches its regex pattern(s)
via the _patterns field. build_patterns() collects all of them into a single
list that can replace the hand-written PATTERNS in lang/zh/patterns.py.
"""

from argus_redact.lang.zh.patterns import (
    _SURNAMES,
    _validate_bank_card,
    _validate_credit_code,
    _validate_id_number,
)
from .fakers_zh import (
    fake_address,
    fake_bank_card,
    fake_credit_code,
    fake_date_of_birth,
    fake_email,
    fake_id_number,
    fake_license_plate,
    fake_military_id,
    fake_passport,
    fake_person,
    fake_phone,
    fake_phone_landline,
    fake_qq,
    fake_social_security,
    fake_wechat,
)
from .registry import PIITypeDef, register, list_types

# ── Phone ──

register(PIITypeDef(
    name="phone",
    lang="zh",
    format="1[3-9]XXXXXXXXX",
    length=11,
    charset="digits",
    structure={
        "prefix": "1[3-9] — mobile network code",
        "subscriber": "9 digits — subscriber number",
    },
    checksum=None,
    prefixes=("手机", "电话", "联系方式", "联系电话", "手机号", "号码", "打电话"),
    separators=("", " ", "-"),
    strategy="mask",
    label="[手机号已脱敏]",
    mask_rule={"visible_prefix": 3, "visible_suffix": 4},
    examples=(
        "13812345678",
        "138 1234 5678",
        "138-1234-5678",
        "+8613812345678",
    ),
    counterexamples=(
        "12012345678",
        "1381234567",
        "138123456789",
    ),
    _patterns=({
        "type": "phone",
        "label": "[手机号已脱敏]",
        "pattern": r"(?<!\d)(?:\+86)?1[3-9]\d(?:[\s-]?\d){8}(?!\d)",
        "check_context": True,
        "description": "Chinese mobile phone number (with optional spaces/dashes)",
    },),
    sensitivity=3,
    faker=fake_phone,
    source="工信部《电信网编号计划》(2017)",
    description="Chinese mobile phone number",
))

register(PIITypeDef(
    name="phone_landline",
    lang="zh",
    format="0XX-XXXXXXXX",
    length=(10, 12),
    charset="digits",
    structure={
        "area_code": "0 + 1-3 digits — city area code",
        "subscriber": "7-8 digits — subscriber number",
    },
    checksum=None,
    prefixes=("座机", "固话", "电话", "办公电话"),
    separators=("", "-"),
    strategy="mask",
    label="[电话号已脱敏]",
    examples=(
        "010-12345678",
        "021-87654321",
        "0755-12345678",
        "075512345678",
    ),
    counterexamples=(),
    _patterns=({
        "type": "phone",
        "label": "[电话号已脱敏]",
        "pattern": r"(?<!\d)0[1-9]\d{1,2}-?\d{7,8}(?!\d)",
        "description": "Chinese landline phone number",
    },),
    sensitivity=3,
    faker=fake_phone_landline,
    source="工信部《电信网编号计划》(2017)",
    description="Chinese landline phone number",
))

# ── ID Number ──

register(PIITypeDef(
    name="id_number",
    lang="zh",
    format="AAAAAA YYYYMMDD SSSV",
    length=18,
    charset="digits+X",
    structure={
        "area_code": "6 digits — administrative division code (GB/T 2260), first digit non-zero",
        "birth_date": "8 digits — YYYYMMDD, year 1900-2099",
        "sequence": "3 digits — sequence code, odd=male even=female",
        "check": "1 char — MOD 11-2 checksum, 0-9 or X",
    },
    checksum="MOD 11-2",
    validate=_validate_id_number,
    prefixes=("身份证", "证件号", "身份证号", "身份证号码", "证件号码"),
    separators=("", " "),
    strategy="remove",
    label="[身份证号已脱敏]",
    examples=(
        "110101199003074610",
        "11010119900307002X",
        "110101 19900307 4610",
    ),
    counterexamples=(
        "110101199003071235",  # checksum invalid
        "110101199013074610",  # month 13 invalid
        "000000199003074610",  # region 000000 invalid
    ),
    _patterns=({
        "type": "id_number",
        "label": "[身份证号已脱敏]",
        "pattern": (
            r"(?<!\d)[1-9]\d{5}\s?(?:19|20)\d{2}"
            r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
            r"\s?\d{3}[\dXx](?!\d)"
        ),
        "validate": _validate_id_number,
        "description": "Chinese 18-digit national ID (MOD 11-2, optional spaces)",
    },),
    sensitivity=4,
    faker=fake_id_number,
    source="GB 11643-1999《公民身份号码》",
    description="Chinese 18-digit national ID",
))

# ── Bank Card ──

register(PIITypeDef(
    name="bank_card",
    lang="zh",
    format="BBBBBBXXXXXXXXXX",
    length=(16, 19),
    charset="digits",
    structure={
        "bin": "6 digits — Bank Identification Number (issuer code)",
        "account": "6-9 digits — account number",
        "check": "1 digit — Luhn checksum (not always enforced by all issuers)",
    },
    checksum="Luhn (or BIN prefix)",
    validate=_validate_bank_card,
    prefixes=("银行卡", "卡号", "银行卡号", "转账", "打钱"),
    separators=("", " "),
    strategy="mask",
    label="[银行卡号已脱敏]",
    mask_rule={"visible_prefix": 4, "visible_suffix": 4},
    examples=(
        "6217001234567890",
        "6222021234567890",
        "4111111111111111",
    ),
    counterexamples=(
        "1234567890123456",
    ),
    _patterns=({
        "type": "bank_card",
        "label": "[银行卡号已脱敏]",
        "pattern": r"(?<!\d)[3-6]\d{15,18}(?!\d)",
        "validate": _validate_bank_card,
        "check_context": True,
        "description": "Bank card number (16-19 digits, Luhn or BIN prefix)",
    },),
    sensitivity=4,
    faker=fake_bank_card,
    source="ISO/IEC 7812, 中国银联BIN分配表",
    description="Chinese bank card number",
))

# ── Passport ──

register(PIITypeDef(
    name="passport",
    lang="zh",
    format="LXXXXXXXX",
    length=9,
    charset="alnum",
    structure={
        "prefix": "1 letter — E (regular) or G (diplomatic/service)",
        "number": "8 digits",
    },
    checksum=None,
    prefixes=("护照", "护照号", "护照号码", "证件号"),
    strategy="remove",
    label="[护照号已脱敏]",
    examples=(
        "护照号E12345678",
        "护照G87654321",
    ),
    counterexamples=(
        "编号G12345678的订单",
    ),
    _patterns=(),
    sensitivity=3,
    faker=fake_passport,
    source="中华人民共和国护照法",
    description="Chinese passport number",
))

# ── License Plate ──

register(PIITypeDef(
    name="license_plate",
    lang="zh",
    format="省A·XXXXX",
    length=(7, 8),
    charset="alnum+cjk",
    structure={
        "province": "1 CJK char — province abbreviation (京沪粤...)",
        "authority": "1 letter — issuing authority",
        "separator": "optional dot/middle dot",
        "code": "5-6 alphanumeric — plate code (6 for new energy)",
    },
    checksum=None,
    prefixes=("车牌", "车牌号", "牌照"),
    strategy="remove",
    label="[车牌号已脱敏]",
    examples=(
        "京A12345",
        "粤B·12345",
        "沪A12345F",
    ),
    counterexamples=(),
    _patterns=({
        "type": "license_plate",
        "label": "[车牌号已脱敏]",
        "pattern": (
            r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁]"
            r"[A-Z]"
            r"[·.]?"
            r"[A-Z0-9]{5,6}"
        ),
        "description": "Chinese license plate (normal + new energy)",
    },),
    sensitivity=2,
    faker=fake_license_plate,
    source="GA 36-2018《中华人民共和国机动车号牌》",
    description="Chinese license plate",
))

# ── Address ──

register(PIITypeDef(
    name="address",
    lang="zh",
    format="省市区街道门牌",
    length=None,
    charset="cjk+digits",
    structure={
        "province": "optional — province/municipality/autonomous region",
        "city": "optional — city/prefecture",
        "district": "区/县/旗 — district",
        "street": "路/街/道/巷 — street name",
        "number": "optional — 号/栋/楼/室",
    },
    checksum=None,
    prefixes=("地址", "住址", "住在", "送到", "寄到", "配送地址"),
    strategy="remove",
    label="[地址已脱敏]",
    examples=(
        "北京市朝阳区建国路100号",
        "广东省深圳市南山区科技路1号",
        "朝阳建国路100号",
    ),
    counterexamples=(
        "北京",
        "今天天气不错",
    ),
    _patterns=(
        {
            "type": "address",
            "label": "[地址已脱敏]",
            "pattern": (
                r"(?:"
                r"(?:(?:河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|"
                r"河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|台湾)省|"
                r"(?:内蒙古|广西|西藏|宁夏|新疆)(?:自治区)?)"
                r"[\u4e00-\u9fff]{2,6}(?:市|州)"
                r"|"
                r"(?:(?<![一-龥])(?:北京市|天津市|上海市|重庆市|[\u4e00-\u9fff]{2,5}(?:市|州)))"
                r")"
                r"[\u4e00-\u9fff]{1,8}(?:区|县|市|旗|新区)"
                r"[\u4e00-\u9fff]{1,20}(?:路|街|道|巷|里|弄|村)"
                r"(?:\d{1,5}(?:号|弄))?"
                r"(?:\d{1,3}(?:栋|幢|楼|座))?"
                r"(?:\d{1,4}(?:室|房))?"
            ),
            "description": "Chinese structured address (city+district+street+number)",
        },
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
    ),
    sensitivity=2,
    faker=fake_address,
    source="GB/T 2260《中华人民共和国行政区划代码》",
    description="Chinese structured address",
))

# ── Unified Social Credit Code ──

register(PIITypeDef(
    name="credit_code",
    lang="zh",
    format="AABBBBBBCCCCCCCCCV",
    length=18,
    charset="alnum",
    structure={
        "authority": "2 chars — registration authority + category",
        "area_code": "6 digits — administrative division code",
        "identifier": "9 chars — organization identifier (0-9, A-H, J-N, P-R, T-U, W-Y)",
        "check": "1 char — MOD 31 checksum",
    },
    checksum="MOD 31",
    validate=_validate_credit_code,
    prefixes=("统一社会信用代码", "信用代码", "营业执照", "企业代码", "组织机构代码"),
    strategy="remove",
    label="[信用代码已脱敏]",
    examples=(
        "91110108MA01YBNX62",
        "52100000500000784G",
    ),
    counterexamples=(
        "91110108MA01YBNX6A",
    ),
    _patterns=({
        "type": "credit_code",
        "label": "[信用代码已脱敏]",
        "pattern": r"(?<![A-Za-z0-9])[0-9A-HJ-NP-RTUW-Ya-hj-np-rtuw-y]{2}\d{6}[0-9A-HJ-NP-RTUW-Ya-hj-np-rtuw-y]{10}(?![A-Za-z0-9])",
        "validate": _validate_credit_code,
        "description": "Unified Social Credit Code (GB 32100-2015, MOD 31)",
    },),
    sensitivity=3,
    faker=fake_credit_code,
    source="GB 32100-2015《法人和其他组织统一社会信用代码编码规则》",
    description="Unified Social Credit Code for enterprises and organizations",
))

# ── QQ ──

register(PIITypeDef(
    name="qq",
    lang="zh",
    format="NNNNN-NNNNNNNNNNNN",
    length=(5, 12),
    charset="digits",
    structure={
        "number": "5-12 digits, first digit non-zero",
    },
    checksum=None,
    prefixes=("QQ", "qq", "企鹅号"),
    strategy="remove",
    label="[QQ号已脱敏]",
    examples=(
        "QQ12345678",
        "QQ 987654321",
        "qq:10001",
    ),
    counterexamples=(
        "1234",
        "0123456",
    ),
    _patterns=({
        "type": "qq",
        "label": "[QQ号已脱敏]",
        "pattern": r"[Qq]{2}\s*(?:[:：是]?\s*)(?P<qq>[1-9]\d{4,11})(?!\d)",
        "group": "qq",
        "description": "QQ number (5-12 digits, requires QQ keyword context)",
    },),
    sensitivity=2,
    faker=fake_qq,
    source="腾讯QQ号码规则",
    description="Tencent QQ number",
))

# ── WeChat ──

register(PIITypeDef(
    name="wechat",
    lang="zh",
    format="a[a-z0-9_-]{5,19}",
    length=(6, 20),
    charset="alnum",
    structure={
        "id": "6-20 chars, starts with letter, may contain letters/digits/underscore/hyphen",
    },
    checksum=None,
    prefixes=("微信", "微信号", "wx", "WeChat", "wechat"),
    strategy="remove",
    label="[微信号已脱敏]",
    examples=(
        "微信wxid_abc123",
        "微信号zhangsan_2024",
    ),
    counterexamples=(
        "123abc",
        "abcde",
    ),
    _patterns=({
        "type": "wechat",
        "label": "[微信号已脱敏]",
        "pattern": (
            r"(?:微信|wx|WeChat|wechat)\s*(?:号)?\s*[:：]?\s*"
            r"(?P<wechat>[a-zA-Z][a-zA-Z0-9_\-]{5,19})"
        ),
        "group": "wechat",
        "description": "WeChat ID (letter-start, 6-20 chars, requires keyword context)",
    },),
    sensitivity=2,
    faker=fake_wechat,
    source="微信号命名规则",
    description="WeChat ID",
))

# ── Date of Birth ──

register(PIITypeDef(
    name="date_of_birth",
    lang="zh",
    format="YYYY年M月D日",
    length=None,
    charset="cjk+digits",
    structure={
        "year": "4 or 2 digit year, or Chinese numeral implied",
        "month": "1-12, Arabic or Chinese numeral",
        "day": "1-31, Arabic or Chinese numeral, followed by 日/号",
    },
    checksum=None,
    prefixes=("出生日期", "出生", "生日", "生于", "born"),
    strategy="remove",
    label="[出生日期已脱敏]",
    examples=(
        "出生日期1990年3月7日",
        "生日是90年3月",
        "出生三月七号",
        "出生日期：1990-03-07",
    ),
    counterexamples=(
        "2024年3月7日开会",
        "会议时间2024-03-07",
    ),
    _patterns=({
        "type": "date_of_birth",
        "label": "[出生日期已脱敏]",
        "pattern": (
            r"(?:出生日期|出生|生日|生于|born)\s*(?:[:：是]?\s*)"
            r"(?P<date_of_birth>"
            r"(?:(?:19|20)\d{2}|[0-9]{2})年(?:0?[1-9]|1[0-2])月(?:(?:0?[1-9]|[12]\d|3[01])(?:日|号))?"
            r"|"
            r"(?:十[一二]|[一二三四五六七八九十])月(?:(?:二?十)?[一二三四五六七八九](?:日|号))?"
            r"|"
            r"(?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])"
            r"|"
            r"(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}"
            r")"
        ),
        "group": "date_of_birth",
        "description": "Chinese date of birth (keyword-triggered, multiple formats)",
    },),
    sensitivity=2,
    faker=fake_date_of_birth,
    source="GB/T 2261.1《个人基本信息分类与代码》",
    description="Chinese date of birth (keyword-triggered, multiple formats)",
))

# ── Military ID ──

register(PIITypeDef(
    name="military_id",
    lang="zh",
    format="军字第XXXXXXXX号",
    length=8,
    charset="digits",
    structure={
        "keyword": "军字第/武字第/士兵证/义务兵证",
        "number": "8 digits",
    },
    checksum=None,
    prefixes=("军字第", "武字第", "士兵证", "义务兵证", "军官证"),
    strategy="remove",
    label="[军官证号已脱敏]",
    examples=(
        "军字第12345678号",
        "武字第87654321号",
        "士兵证号12345678",
    ),
    counterexamples=(
        "军字第1234567号",
    ),
    _patterns=({
        "type": "military_id",
        "label": "[军官证号已脱敏]",
        "pattern": (
            r"(?:军字第|武字第|士兵证号?|义务兵证号?)\s*"
            r"(?P<military_id>\d{8})"
            r"(?:号)?"
        ),
        "group": "military_id",
        "description": "Chinese military ID number (keyword-triggered, 8 digits)",
    },),
    sensitivity=3,
    faker=fake_military_id,
    source="中国人民解放军军官证管理规定",
    description="Chinese military ID number",
))

# ── Social Security ──

register(PIITypeDef(
    name="social_security",
    lang="zh",
    format="社保号+18位身份证号",
    length=(9, 18),
    charset="alnum",
    structure={
        "keyword": "社保号/社保卡号/社会保障号",
        "number": "18-digit ID format or city-specific shorter format",
    },
    checksum=None,
    prefixes=("社保号", "社保卡号", "社会保障号"),
    strategy="remove",
    label="[社保号已脱敏]",
    examples=(
        "社保号110101199003074610",
        "社保卡号：A12345678",
    ),
    counterexamples=(
        "110101199003074610",
    ),
    _patterns=({
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
    },),
    sensitivity=4,
    faker=fake_social_security,
    source="人力资源和社会保障部社保卡管理规定",
    description="Chinese social security number (keyword-triggered)",
))

# ── Level 2: Quasi-Identifiers ──

register(PIITypeDef(
    name="job_title",
    lang="zh",
    format="CJK + 职务后缀",
    charset="cjk",
    structure={"prefix": "0-4 CJK chars", "suffix": "职务名称（主任/经理/医生等）"},
    prefixes=("职务", "职位", "头衔"),
    strategy="remove",
    label="[职务已脱敏]",
    examples=("项目经理说", "骨科医生建议", "张董事长出席"),
    counterexamples=("今天天气不错",),
    _patterns=(),
    sensitivity=2,
    source="常用中文职务名称",
    description="Chinese job title (suffix-based detection)",
))

register(PIITypeDef(
    name="organization",
    lang="zh",
    format="CJK + 法人后缀",
    charset="cjk",
    structure={"name": "2-12 CJK chars", "suffix": "法人后缀（公司/集团/银行/医院等）"},
    prefixes=("单位", "机构", "公司"),
    strategy="pseudonym",
    label="[机构已脱敏]",
    examples=("腾讯计算机系统有限公司", "阿里巴巴集团", "北京协和医院"),
    counterexamples=("去公司上班",),
    _patterns=(),
    sensitivity=2,
    source="中国法人组织命名规则",
    description="Chinese organization name (CJK prefix + legal/industry suffix)",
))

register(PIITypeDef(
    name="school",
    lang="zh",
    format="CJK + 教育后缀",
    charset="cjk",
    structure={"name": "2-10 CJK chars", "suffix": "教育后缀（大学/学院/中学/小学等）"},
    prefixes=("学校", "母校", "就读"),
    strategy="pseudonym",
    label="[学校已脱敏]",
    examples=("计算机学院很好", "人大附中的学生", "实验小学报名"),
    counterexamples=("上大学很重要",),
    _patterns=(),
    sensitivity=2,
    source="中国教育机构命名规则",
    description="Chinese school name (CJK prefix + educational suffix)",
))

register(PIITypeDef(
    name="ethnicity",
    lang="zh",
    format="民族 + 56民族名",
    charset="cjk",
    structure={"keyword": "民族", "value": "56个民族名称之一 + 族"},
    prefixes=("民族",),
    strategy="remove",
    label="[民族已脱敏]",
    examples=("民族：汉族", "他是藏族"),
    counterexamples=("家族企业",),
    _patterns=(),
    sensitivity=3,
    source="中华人民共和国民族区域自治法",
    description="Chinese ethnicity (56 ethnic groups)",
))

register(PIITypeDef(
    name="workplace",
    lang="zh",
    format="关键词 + CJK名称",
    charset="cjk",
    structure={"keyword": "工作单位/就职于/供职于", "value": "2-20 CJK chars"},
    prefixes=("工作单位", "单位", "就职于", "供职于"),
    strategy="remove",
    label="[工作单位已脱敏]",
    examples=("工作单位：中国电信", "就职于华为技术"),
    counterexamples=("在华为工作",),
    _patterns=(),
    sensitivity=2,
    source="个人信息登记表常见字段",
    description="Chinese workplace (keyword-triggered)",
))

# ── Level 3: Sensitive Attributes ──

register(PIITypeDef(
    name="criminal_record",
    lang="zh",
    format="犯罪相关关键词",
    charset="cjk",
    structure={"keywords": "前科/判刑/拘留/犯罪记录/逮捕/服刑等"},
    prefixes=("犯罪记录", "前科", "案底"),
    strategy="remove",
    label="[犯罪记录已脱敏]",
    examples=("此人有前科", "被判刑三年", "他有犯罪记录"),
    counterexamples=("今天天气不错",),
    _patterns=(),
    sensitivity=4,
    source="PIPL Art.28/51 敏感个人信息",
    description="Criminal record (explicit keywords)",
))

register(PIITypeDef(
    name="financial",
    lang="zh",
    format="财务关键词 + 金额",
    charset="cjk+digits",
    structure={"keyword": "月薪/年收入/欠债/信用评分等", "amount": "数字+单位"},
    prefixes=("月薪", "年收入", "年薪", "欠债"),
    strategy="remove",
    label="[财务信息已脱敏]",
    examples=("月薪2万元", "年收入50万", "信用评分680分"),
    counterexamples=("这个项目投资500万",),
    _patterns=(),
    sensitivity=3,
    source="PIPL Art.28/51 敏感个人信息",
    description="Financial info (salary/debt/credit score with amounts)",
))

register(PIITypeDef(
    name="biometric",
    lang="zh",
    format="生物特征关键词 + 动作",
    charset="cjk",
    structure={"keyword": "指纹/DNA/人脸/虹膜/声纹等", "action": "采集/识别/录入等"},
    prefixes=("指纹", "DNA", "人脸", "虹膜", "声纹"),
    strategy="remove",
    label="[生物特征已脱敏]",
    examples=("已采集指纹信息", "DNA检测结果", "人脸识别通过"),
    counterexamples=("今天天气不错",),
    _patterns=(),
    sensitivity=4,
    source="PIPL Art.28/51, GB/T 45574-2025",
    description="Biometric data (fingerprint/DNA/face/iris/voiceprint)",
))

register(PIITypeDef(
    name="medical",
    lang="zh",
    format="诊断/药物/疾病关键词",
    charset="cjk",
    structure={"trigger": "确诊/患有/服用等", "content": "疾病名/药物名"},
    prefixes=("确诊", "诊断", "患有", "服用"),
    strategy="remove",
    label="[医疗信息已脱敏]",
    examples=("确诊糖尿病", "患有高血压", "服用阿莫西林"),
    counterexamples=("今天天气不错",),
    _patterns=(),
    sensitivity=4,
    source="PIPL Art.28/51, HIPAA PHI",
    description="Medical/health info (diagnosis/medication/disease/surgery)",
))

register(PIITypeDef(
    name="religion",
    lang="zh",
    format="宗教信徒/活动关键词",
    charset="cjk",
    structure={"keywords": "信徒称呼/宗教活动/信仰声明"},
    prefixes=("信仰", "信奉"),
    strategy="remove",
    label="[宗教信仰已脱敏]",
    examples=("他是基督徒", "她是穆斯林", "每周做礼拜"),
    counterexamples=("今天天气不错",),
    _patterns=(),
    sensitivity=4,
    source="PIPL Art.28/51 敏感个人信息",
    description="Religious belief (believer types/practices/declarations)",
))

register(PIITypeDef(
    name="political",
    lang="zh",
    format="政治立场/党派关键词",
    charset="cjk",
    structure={"keywords": "党员/政治面貌/投票/抗议游行等"},
    prefixes=("政治面貌", "党派"),
    strategy="remove",
    label="[政治观点已脱敏]",
    examples=("他是党员", "政治面貌：群众", "参加了抗议游行"),
    counterexamples=("今天天气不错",),
    _patterns=(),
    sensitivity=4,
    source="PIPL Art.28/51 敏感个人信息",
    description="Political opinion (party membership/voting/protest)",
))

register(PIITypeDef(
    name="sexual_orientation",
    lang="zh",
    format="性取向关键词",
    charset="alnum",
    structure={"keywords": "同性恋/双性恋/出柜/LGBT等"},
    prefixes=(),
    strategy="remove",
    label="[性取向已脱敏]",
    examples=("他是同性恋", "她是双性恋", "他已经出柜"),
    counterexamples=("各位同志们好",),
    _patterns=(),
    sensitivity=4,
    source="PIPL Art.28/51 敏感个人信息",
    description="Sexual orientation (explicit terms)",
))

# ── Self-reference ──

register(PIITypeDef(
    name="self_reference",
    lang="zh",
    format="第一人称代词/亲属关系",
    charset="cjk",
    structure={"pronoun": "我/我们/我的", "kinship": "我妈/我爸/我老公等"},
    prefixes=(),
    strategy="pseudonym",
    label="[自称已脱敏]",
    examples=("我确诊了糖尿病", "我妈住院了", "我们公司裁员了"),
    counterexamples=("他确诊了糖尿病", "你住院了"),
    _patterns=(),
    sensitivity=2,
    source="Privacy-by-design: first-person binds all PII to user identity",
    description="Self-reference (first-person pronouns and kinship, links PII to user)",
))

# ── Person Name ──

register(PIITypeDef(
    name="person",
    lang="zh",
    format="姓+名",
    length=(2, 4),
    charset="cjk",
    structure={
        "surname": "1 char (common) or 2 chars (compound: 欧阳/司马/...)",
        "given_name": "1-2 CJK chars",
    },
    checksum=None,
    prefixes=(
        "客户", "患者", "用户", "旅客", "车主", "联系人", "收件人", "寄件人",
        "登记人", "开户人", "申请人", "报案人", "委托人", "当事人", "嫌疑人",
        "负责人", "经办人", "签收人", "担保人", "受益人", "借款人",
        "持卡人", "被保险人", "投保人", "参会人员",
        "主治医生", "医生", "护士", "教授", "老板", "同事", "朋友", "同学",
        "姓名", "乘客", "住户", "业主", "租户", "房东",
    ),
    suffixes=(
        "先生", "女士", "老师", "教授", "医生", "同学", "师傅",
        "经理", "总监", "主任", "院长", "局长", "部长", "校长", "董事长",
    ),
    strategy="pseudonym",
    label="[姓名已脱敏]",
    examples=(
        "客户张三",
        "联系人王小明",
        "赵敏女士",
    ),
    counterexamples=(
        "黄山风景区很漂亮",
        "华为公司发布",
        "唐朝是中国历史",
    ),
    _patterns=(),  # Person names are detected by lang/zh/person.py, not by regex PATTERNS
    sensitivity=3,
    faker=fake_person,
    source="公安部全国姓名统计, 百家姓",
    description="Chinese person name (candidate generation + evidence scoring, see person.py)",
))


# ── build_patterns() ──

def build_patterns() -> list[dict]:
    """Build the complete pattern list for Chinese from registered specs.

    This is a drop-in replacement for lang/zh/patterns.py PATTERNS.
    """
    patterns = []
    for typedef in list_types("zh"):
        patterns.extend(typedef.to_patterns())
    return patterns
