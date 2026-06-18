"""Chinese PII type definitions.

Each register() call defines a PII type with its rich metadata (format,
checksum prose, sensitivity, examples, fakers, ...). The Layer-1 regex and
validators live in the Rust core (SSOT); PIITypeDef.to_patterns() derives the
pattern dict(s) from there. build_patterns() collects all of them into a single
list mirroring the runtime pattern set.
"""

from .registry import PIITypeDef, list_types, register

# ── Phone ──

register(
    PIITypeDef(
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
        sensitivity=3,
        source="工信部《电信网编号计划》(2017)",
        description="Chinese mobile phone number",
    )
)

register(
    PIITypeDef(
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
        sensitivity=3,
        source="工信部《电信网编号计划》(2017)",
        description="Chinese landline phone number",
    )
)

# ── ID Number ──

register(
    PIITypeDef(
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
            "110101199003071235",  # checksum invalid
            "110101199013074610",  # month 13 invalid
            "000000199003074610",  # region 000000 invalid
        ),
        sensitivity=4,
        source="GB 11643-1999《公民身份号码》",
        description="Chinese 18-digit national ID",
    )
)

# ── Hong Kong Identity Card ──

register(
    PIITypeDef(
        name="hk_id",
        lang="zh",
        format="L(L)NNNNNN(C)",
        length=(9, 11),
        charset="alpha + digits + parens",
        checksum="HKID mod-11",
        strategy="remove",
        label="[HKID-REDACTED]",
        examples=("A123456(9)", "Z684325(1)", "WX123456(8)"),
        counterexamples=("A123456(0)", "A12345(7)", "1A12345(7)"),
        sensitivity=4,
        source="Hong Kong Immigration Department; Wikipedia HKID",
        description="Hong Kong Identity Card — 1-2 letter + 6 digit + parenthesized check",
    )
)

# ── Taiwan Identity Card ──

register(
    PIITypeDef(
        name="tw_id",
        lang="zh",
        format="LNNNNNNNNN",
        length=10,
        charset="alpha + digits",
        checksum="TWID weighted mod-10",
        strategy="remove",
        label="[TWID-REDACTED]",
        examples=("A123456789", "B142536472", "F131011128"),
        counterexamples=("A123456780", "A12345678", "1A12345678"),
        sensitivity=4,
        source="ROC household registration; Wikipedia ROC ID",
        description="Republic of China (Taiwan) national ID",
    )
)

# ── Macau Resident Identity Card ──

register(
    PIITypeDef(
        name="macau_id",
        lang="zh",
        format="N/NNNNNN/N",
        length=10,
        charset="digits + slashes",
        strategy="remove",
        label="[MACAU-ID-REDACTED]",
        examples=("1/234567/8", "5/123456/0", "7/000001/2"),
        counterexamples=("0/234567/8", "1/234567"),
        sensitivity=4,
        source="Macau Identification Services Bureau",
        description="Macau Resident ID Card — format-only validation",
    )
)

# ── Taiwan Alien Resident Certificate (ARC, post-2020) ──

register(
    PIITypeDef(
        name="taiwan_arc",
        lang="zh",
        format="LLNNNNNNNN",
        length=10,
        charset="alpha + digits",
        strategy="remove",
        label="[ARC-REDACTED]",
        examples=("AB12345678", "AC98765432", "WX00000001"),
        counterexamples=("A123456789", "AB1234567"),
        sensitivity=4,
        source="ROC National Immigration Agency",
        description="Taiwan Alien Resident Certificate (post-2020)",
    )
)

# ── Exit-Entry Permit for Travelling to/from HK and Macao (EEP, 往来港澳通行证, 双程证) ──
# Mainland residents -> HK/Macao. C-prefix. Paired with hrp (回乡证), which is the
# DIRECTION-OPPOSITE permit; the prefix letter (C vs H/M) is the only discriminator,
# so the two stay as separate defs with separate regexes — never one alternation.

register(
    PIITypeDef(
        name="eep",
        lang="zh",
        format="C[0-9]{8} 或 C[A-HJ-NP-Z][0-9]{7}",
        length=9,
        charset="alnum",
        structure={
            "prefix": "C — 固定前缀",
            "body": "旧号段=8位数字；新号段(2018-12-03起)=1字母(排除I/O)+7位数字",
        },
        checksum=None,  # 无公开校验算法（官方文档未列校验位）
        prefixes=("往来港澳通行证", "电子往来港澳通行证", "港澳通行证", "双程证", "通行证号码", "证件号码", "EEP"),
        strategy="remove",
        label="[往来港澳通行证已脱敏]",
        examples=(
            "往来港澳通行证C12345678",
            "电子往来港澳通行证CA0000001",
            "港澳通行证号码：CB1234567",
            "双程证 C87654321",
        ),
        counterexamples=(
            "C12345678",            # 无锚点裸格式 -> 不应命中
            "往来港澳通行证CI1234567",  # 第二位 I 非法
            "往来港澳通行证CO1234567",  # 第二位 O 非法
            "往来港澳通行证C1234567",   # 总长不足 9
            "回乡证H12345678",         # H 前缀属于另一类型，绝不能命中此类型
            "订单号C12345678",         # 干扰前缀
        ),
        sensitivity=4,
        source="国家移民管理局《出入境证件简明手册》; 电子往来港澳通行证号码编制规则调整公告(2018)",
        description="往来港澳通行证 (Exit-Entry Permit for Travelling to/from HK and Macao, EEP) — 大陆居民赴港澳；C 前缀；无公开校验；须上下文锚点",
    )
)

# ── Mainland Travel Permit for HK/Macao Residents (HRP, 港澳居民来往内地通行证, 回乡证) ──
# HK/Macao residents -> mainland. H/M-prefix. Direction-opposite of eep; the prefix
# letter is the only discriminator, so it stays a separate def with its own regex.

register(
    PIITypeDef(
        name="hrp",
        lang="zh",
        format="[HM][0-9]{8}（可带2位换证次数后缀）",
        length=(9, 11),
        charset="alnum",
        structure={
            "prefix": "H=首次申请地香港 / M=澳门",
            "body": "8 位数字（终身不变身份号）",
            "renewal": "可选 2 位换证次数（卡面独立字段 / 1999版原生末2位）",
        },
        checksum=None,  # 无公开校验算法（官方文档未列校验位）
        prefixes=("港澳居民来往内地通行证", "来往内地通行证", "回乡证", "回乡卡", "港澳居民", "Home Return Permit"),
        strategy="remove",
        label="[回乡证已脱敏]",
        examples=(
            "港澳居民来往内地通行证H12345678",
            "回乡证 M87654321",
            "回乡卡H1234567801",        # 9位号 + 2位换证次数
            "Home Return Permit H00000001",
        ),
        counterexamples=(
            "H12345678",              # 无锚点裸格式 -> 不应命中
            "回乡证H1234567",          # 位数不足
            "往来港澳通行证C12345678",  # C 前缀属于另一类型，绝不能命中此类型
            "型号H12345678",          # 干扰前缀
        ),
        sensitivity=4,
        source="公安部《关于启用新版港澳居民来往内地通行证的公告》; 国家移民管理局《出入境证件简明手册》",
        description="港澳居民来往内地通行证 (Mainland Travel Permit for HK/Macao Residents / Home Return Permit / 回乡证) — 港澳居民来大陆；H/M 前缀；无公开校验；须上下文锚点",
    )
)

# ── Housing Provident Fund Account (住房公积金账号) ──
# No national format standard (varies by city) -> anchor-required. The anchor must
# include 账号/账户 (not bare "公积金") so it does not match 公积金余额/amounts.

register(
    PIITypeDef(
        name="housing_fund",
        lang="zh",
        format="公积金账号（各城市格式不一，无全国标准）",
        charset="digits",
        checksum=None,  # 无公开校验算法
        prefixes=("住房公积金账号", "公积金账号", "住房公积金账户", "公积金账户"),
        strategy="remove",
        label="[公积金账号已脱敏]",
        examples=(
            "公积金账号：110123456789",
            "住房公积金账户 123456789012",
            "公积金账号 6001234567",
        ),
        counterexamples=(
            "110123456789",   # 无锚点裸数字 -> 不应命中
            "公积金余额12000",  # 余额/金额，不是账号
        ),
        sensitivity=3,
        source="《住房公积金管理条例》（国务院令第350号）— 账号格式由各地公积金管理中心自定，无全国统一标准",
        description="住房公积金账号 (housing provident fund account) — 各城市格式不统一，无全国标准，无公开校验；须上下文锚点。理由是格式无全国标准，不是因为未来归集身份证号。",
    )
)

# ── Bank Card ──

register(
    PIITypeDef(
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
            "6217001234567890",
            "6222021234567890",
            "4111111111111111",
        ),
        counterexamples=("1234567890123456",),
        sensitivity=4,
        source="ISO/IEC 7812, 中国银联BIN分配表",
        description="Chinese bank card number",
    )
)

# ── Passport ──

register(
    PIITypeDef(
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
        counterexamples=("编号G12345678的订单",),
        sensitivity=3,
        source="中华人民共和国护照法",
        description="Chinese passport number",
    )
)

# ── License Plate ──

register(
    PIITypeDef(
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
        sensitivity=2,
        source="GA 36-2018《中华人民共和国机动车号牌》",
        description="Chinese license plate",
    )
)

# ── Address ──

register(
    PIITypeDef(
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
        sensitivity=2,
        source="GB/T 2260《中华人民共和国行政区划代码》",
        description="Chinese structured address",
    )
)

# ── Unified Social Credit Code ──

register(
    PIITypeDef(
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
        prefixes=("统一社会信用代码", "信用代码", "营业执照", "企业代码", "组织机构代码"),
        strategy="remove",
        label="[信用代码已脱敏]",
        examples=(
            "91110108MA01YBNX62",
            "52100000500000784G",
        ),
        counterexamples=("91110108MA01YBNX6A",),
        sensitivity=3,
        source="GB 32100-2015《法人和其他组织统一社会信用代码编码规则》",
        description="Unified Social Credit Code for enterprises and organizations",
    )
)

# ── QQ ──

register(
    PIITypeDef(
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
        sensitivity=2,
        source="腾讯QQ号码规则",
        description="Tencent QQ number",
    )
)

# ── WeChat ──

register(
    PIITypeDef(
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
        sensitivity=2,
        source="微信号命名规则",
        description="WeChat ID",
    )
)

# ── Date of Birth ──

register(
    PIITypeDef(
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
        sensitivity=2,
        source="GB/T 2261.1《个人基本信息分类与代码》",
        description="Chinese date of birth (keyword-triggered, multiple formats)",
    )
)

# ── Military ID ──

register(
    PIITypeDef(
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
        counterexamples=("军字第1234567号",),
        sensitivity=3,
        source="中国人民解放军军官证管理规定",
        description="Chinese military ID number",
    )
)

# ── Social Security ──

register(
    PIITypeDef(
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
        counterexamples=("110101199003074610",),
        sensitivity=4,
        source="人力资源和社会保障部社保卡管理规定",
        description="Chinese social security number (keyword-triggered)",
    )
)

# ── Level 2: Quasi-Identifiers ──

register(
    PIITypeDef(
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
        sensitivity=2,
        source="常用中文职务名称",
        description="Chinese job title (suffix-based detection)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=2,
        source="中国法人组织命名规则",
        description="Chinese organization name (CJK prefix + legal/industry suffix)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=2,
        source="中国教育机构命名规则",
        description="Chinese school name (CJK prefix + educational suffix)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=3,
        source="中华人民共和国民族区域自治法",
        description="Chinese ethnicity (56 ethnic groups)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=2,
        source="个人信息登记表常见字段",
        description="Chinese workplace (keyword-triggered)",
    )
)

# ── Level 3: Sensitive Attributes ──

register(
    PIITypeDef(
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
        sensitivity=4,
        source="PIPL Art.28/51 敏感个人信息",
        description="Criminal record (explicit keywords)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=3,
        source="PIPL Art.28/51 敏感个人信息",
        description="Financial info (salary/debt/credit score with amounts)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=4,
        source="PIPL Art.28/51, GB/T 45574-2025",
        description="Biometric data (fingerprint/DNA/face/iris/voiceprint)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=4,
        source="PIPL Art.28/51, HIPAA PHI",
        description="Medical/health info (diagnosis/medication/disease/surgery)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=4,
        source="PIPL Art.28/51 敏感个人信息",
        description="Religious belief (believer types/practices/declarations)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=4,
        source="PIPL Art.28/51 敏感个人信息",
        description="Political opinion (party membership/voting/protest)",
    )
)

register(
    PIITypeDef(
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
        sensitivity=4,
        source="PIPL Art.28/51 敏感个人信息",
        description="Sexual orientation (explicit terms)",
    )
)

# ── Self-reference ──

register(
    PIITypeDef(
        name="self_reference",
        lang="zh",
        format="第一人称代词/亲属关系",
        charset="cjk",
        structure={"pronoun": "我/我们/我的", "kinship": "我妈/我爸/我老公等"},
        prefixes=(),
        strategy="keep",
        label="[自称已脱敏]",
        examples=("我确诊了糖尿病", "我妈住院了", "我们公司裁员了"),
        counterexamples=("他确诊了糖尿病", "你住院了"),
        sensitivity=2,
        source="Privacy-by-design: first-person binds all PII to user identity",
        description="Self-reference (first-person pronouns and kinship, links PII to user)",
    )
)

# ── Person Name ──

register(
    PIITypeDef(
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
            "客户",
            "患者",
            "用户",
            "旅客",
            "车主",
            "联系人",
            "收件人",
            "寄件人",
            "登记人",
            "开户人",
            "申请人",
            "报案人",
            "委托人",
            "当事人",
            "嫌疑人",
            "负责人",
            "经办人",
            "签收人",
            "担保人",
            "受益人",
            "借款人",
            "持卡人",
            "被保险人",
            "投保人",
            "参会人员",
            "主治医生",
            "医生",
            "护士",
            "教授",
            "老板",
            "同事",
            "朋友",
            "同学",
            "姓名",
            "乘客",
            "住户",
            "业主",
            "租户",
            "房东",
        ),
        suffixes=(
            "先生",
            "女士",
            "老师",
            "教授",
            "医生",
            "同学",
            "师傅",
            "经理",
            "总监",
            "主任",
            "院长",
            "局长",
            "部长",
            "校长",
            "董事长",
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
          # Person names are detected by lang/zh/person.py, not by regex PATTERNS
        sensitivity=3,
        source="公安部全国姓名统计, 百家姓",
        description="Chinese person name (candidate generation + evidence scoring). The detection logic lives in the Rust core (`crates/argus-redact-core/src/person_zh.rs`, with English in `person_en.rs`); the `lang/zh/person.py` module is a thin `_core` FFI shim over it.",
    )
)


# ── Age ──

register(
    PIITypeDef(
        name="age",
        lang="zh",
        format="X岁 / 年龄: X / 周岁X / X years old",
        charset="digits",
        strategy="remove",
        label="[年龄已脱敏]",
        examples=("32岁", "年龄: 32", "32 years old"),
        counterexamples=("999岁",),
        sensitivity=2,
        source="GB/T 2261.1《个人基本信息分类与代码》",
        description="Age (Chinese 岁/年龄/周岁 + English years old/aged)",
    )
)


# ── build_patterns() ──


def build_patterns() -> list[dict]:
    """Build the complete pattern list for Chinese from registered specs.

    This is a drop-in replacement for lang/zh/patterns.py PATTERNS.
    """
    patterns = []
    for typedef in list_types("zh"):
        patterns.extend(typedef.to_patterns())
    return patterns
