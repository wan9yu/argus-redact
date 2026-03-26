"""Chinese PII type definitions."""

from .registry import PIITypeDef, register

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
        "12012345678",   # prefix 12 invalid
        "1381234567",    # 10 digits
        "138123456789",  # 12 digits
    ),
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
        "110101199003071235",  # checksum wrong
        "110101199013074610",  # month 13
        "000000199003074610",  # area 000000
    ),
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
    prefixes=("银行卡", "卡号", "银行卡号", "转账", "打钱"),
    separators=("", " "),
    strategy="mask",
    label="[银行卡号已脱敏]",
    mask_rule={"visible_prefix": 4, "visible_suffix": 4},
    examples=(
        "6217001234567890",   # CCB BIN
        "6222021234567890",   # ICBC BIN
        "4111111111111111",   # Visa Luhn-valid
    ),
    counterexamples=(
        "1234567890123456",   # no known BIN, Luhn fails
    ),
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
        "E12345678",
        "G87654321",
    ),
    counterexamples=(),
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
        "沪A12345F",  # new energy
    ),
    counterexamples=(),
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
        "朝阳建国路100号",          # informal, no city prefix
    ),
    counterexamples=(
        "北京",           # city name alone
        "今天天气不错",    # plain text
    ),
    source="GB/T 2260《中华人民共和国行政区划代码》",
    description="Chinese structured address",
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
        "客户张三",        # prefix context
        "联系人王小明",     # prefix context
        "赵敏女士",        # suffix context
    ),
    counterexamples=(
        "黄山风景区很漂亮",  # place name
        "华为公司发布",      # company
        "唐朝是中国历史",    # dynasty
    ),
    source="公安部全国姓名统计, 百家姓",
    description="Chinese person name (surname + context heuristic)",
))
