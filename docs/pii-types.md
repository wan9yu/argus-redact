# PII Type Catalog

Auto-generated from `argus_redact.specs.list_types()`. Do not hand-edit.
Regenerate via: `make catalog`

Total: 52 types (28 zh / 15 en / 9 shared)

## Chinese (zh) — 28 types

### `address`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `geographic` |
| Examples | `北京市朝阳区建国路100号`, `广东省深圳市南山区科技路1号`, `朝阳建国路100号` |
| Source | GB/T 2260《中华人民共和国行政区划代码》 |

Chinese structured address

### `age`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `32岁`, `年龄: 32`, `32 years old` |
| Source | GB/T 2261.1《个人基本信息分类与代码》 |

Age (Chinese 岁/年龄/周岁 + English years old/aged)

### `bank_card`

| Field | Value |
|---|---|
| Default strategy | `mask` |
| Sensitivity | 4 |
| Reversible | ✗ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `account_numbers` |
| Checksum | Luhn (or BIN prefix) |
| Examples | `6217001234567890`, `6222021234567890`, `4111111111111111` |
| Source | ISO/IEC 7812, 中国银联BIN分配表 |

Chinese bank card number

### `biometric`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| HIPAA Safe Harbor | `biometric` |
| Examples | `已采集指纹信息`, `DNA检测结果`, `人脸识别通过` |
| Source | PIPL Art.28/51, GB/T 45574-2025 |

Biometric data (fingerprint/DNA/face/iris/voiceprint)

### `credit_code`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Checksum | MOD 31 |
| Examples | `91110108MA01YBNX62`, `52100000500000784G` |
| Source | GB 32100-2015《法人和其他组织统一社会信用代码编码规则》 |

Unified Social Credit Code for enterprises and organizations

### `criminal_record`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `此人有前科`, `被判刑三年`, `他有犯罪记录` |
| Source | PIPL Art.28/51 敏感个人信息 |

Criminal record (explicit keywords)

### `date_of_birth`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `dates` |
| Examples | `出生日期1990年3月7日`, `生日是90年3月`, `出生三月七号` |
| Source | GB/T 2261.1《个人基本信息分类与代码》 |

Chinese date of birth (keyword-triggered, multiple formats)

### `ethnicity`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `民族：汉族`, `他是藏族` |
| Source | 中华人民共和国民族区域自治法 |

Chinese ethnicity (56 ethnic groups)

### `financial`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| HIPAA Safe Harbor | `account_numbers` |
| Examples | `月薪2万元`, `年收入50万`, `信用评分680分` |
| Source | PIPL Art.28/51 敏感个人信息 |

Financial info (salary/debt/credit score with amounts)

### `id_number`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Checksum | MOD 11-2 |
| Examples | `110101199003074610`, `11010119900307002X`, `110101 19900307 4610` |
| Source | GB 11643-1999《公民身份号码》 |

Chinese 18-digit national ID

### `job_title`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `项目经理说`, `骨科医生建议`, `张董事长出席` |
| Source | 常用中文职务名称 |

Chinese job title (suffix-based detection)

### `license_plate`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `vehicle_identifier` |
| Examples | `京A12345`, `粤B·12345`, `沪A12345F` |
| Source | GA 36-2018《中华人民共和国机动车号牌》 |

Chinese license plate

### `medical`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| HIPAA Safe Harbor | `medical_record` |
| Examples | `确诊糖尿病`, `患有高血压`, `服用阿莫西林` |
| Source | PIPL Art.28/51, HIPAA PHI |

Medical/health info (diagnosis/medication/disease/surgery)

### `military_id`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Examples | `军字第12345678号`, `武字第87654321号`, `士兵证号12345678` |
| Source | 中国人民解放军军官证管理规定 |

Chinese military ID number

### `organization`

| Field | Value |
|---|---|
| Default strategy | `pseudonym` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `腾讯计算机系统有限公司`, `阿里巴巴集团`, `北京协和医院` |
| Source | 中国法人组织命名规则 |

Chinese organization name (CJK prefix + legal/industry suffix)

### `passport`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `certificate_number` |
| Examples | `护照号E12345678`, `护照G87654321` |
| Source | 中华人民共和国护照法 |

Chinese passport number

### `person`

| Field | Value |
|---|---|
| Default strategy | `pseudonym` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `names` |
| Examples | `客户张三`, `联系人王小明`, `赵敏女士` |
| Source | 公安部全国姓名统计, 百家姓 |

Chinese person name (candidate generation + evidence scoring, see person.py)

### `phone`

| Field | Value |
|---|---|
| Default strategy | `mask` |
| Sensitivity | 3 |
| Reversible | ✗ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `phone_numbers` |
| Examples | `13812345678`, `138 1234 5678`, `138-1234-5678` |
| Source | 工信部《电信网编号计划》(2017) |

Chinese mobile phone number

### `phone_landline`

| Field | Value |
|---|---|
| Default strategy | `mask` |
| Sensitivity | 3 |
| Reversible | ✗ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `phone_numbers` |
| Examples | `010-12345678`, `021-87654321`, `0755-12345678` |
| Source | 工信部《电信网编号计划》(2017) |

Chinese landline phone number

### `political`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `他是党员`, `政治面貌：群众`, `参加了抗议游行` |
| Source | PIPL Art.28/51 敏感个人信息 |

Political opinion (party membership/voting/protest)

### `qq`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `QQ12345678`, `QQ 987654321`, `qq:10001` |
| Source | 腾讯QQ号码规则 |

Tencent QQ number

### `religion`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `他是基督徒`, `她是穆斯林`, `每周做礼拜` |
| Source | PIPL Art.28/51 敏感个人信息 |

Religious belief (believer types/practices/declarations)

### `school`

| Field | Value |
|---|---|
| Default strategy | `pseudonym` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `计算机学院很好`, `人大附中的学生`, `实验小学报名` |
| Source | 中国教育机构命名规则 |

Chinese school name (CJK prefix + educational suffix)

### `self_reference`

| Field | Value |
|---|---|
| Default strategy | `keep` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `我确诊了糖尿病`, `我妈住院了`, `我们公司裁员了` |
| Source | Privacy-by-design: first-person binds all PII to user identity |

Self-reference (first-person pronouns and kinship, links PII to user)

### `sexual_orientation`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `他是同性恋`, `她是双性恋`, `他已经出柜` |
| Source | PIPL Art.28/51 敏感个人信息 |

Sexual orientation (explicit terms)

### `social_security`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `ssn` |
| Examples | `社保号110101199003074610`, `社保卡号：A12345678` |
| Source | 人力资源和社会保障部社保卡管理规定 |

Chinese social security number (keyword-triggered)

### `wechat`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `微信wxid_abc123`, `微信号zhangsan_2024` |
| Source | 微信号命名规则 |

WeChat ID

### `workplace`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `工作单位：中国电信`, `就职于华为技术` |
| Source | 个人信息登记表常见字段 |

Chinese workplace (keyword-triggered)

## English (en) — 15 types

### `address`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `geographic` |
| Examples | `1234 Main St, Anytown, USA` |
| Source | US/UK address conventions; faker uses fictional pop-culture addresses |

Street address — realistic faker uses fictional table

### `biometric`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| HIPAA Safe Harbor | `biometric` |
| Examples | `fingerprints collected`, `DNA sample` |
| Source | GDPR Article 9 special category |

Biometric identifier

### `credit_card`

| Field | Value |
|---|---|
| Default strategy | `mask` |
| Sensitivity | 3 |
| Reversible | ✗ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `account_numbers` |
| Checksum | Luhn |
| Examples | `4111111111111111` |
| Source | ISO/IEC 7812; faker uses 999999 BIN (unassigned globally) + Luhn |

Credit card — realistic faker uses 999999 BIN

### `criminal_record`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `convicted of fraud`, `felony record` |
| Source | GDPR special category / CCPA sensitive personal info |

Criminal record

### `date_of_birth`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `dates` |
| Examples | `DOB: 01/15/1990`, `Born on March 5, 1985` |
| Source | Common US/UK DOB formats; keyword-triggered for precision |

English date of birth — keyword-triggered, multiple formats

### `financial`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| HIPAA Safe Harbor | `account_numbers` |
| Examples | `salary of $75,000`, `credit score 720` |
| Source | GLBA/financial privacy categories |

Financial information (income/debt/credit/bankruptcy)

### `medical`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| HIPAA Safe Harbor | `medical_record` |
| Examples | `diagnosed with diabetes`, `HIV positive` |
| Source | HIPAA PHI category |

Medical/health information

### `person`

| Field | Value |
|---|---|
| Default strategy | `pseudonym` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `names` |
| Examples | `John Smith`, `Mary Johnson` |
| Source | Detection requires NER (spaCy en_core_web_sm). No fast-mode list fallback. Faker uses US legal placeholder names (John Doe etc.) |

Person name (en) — NER-only detection; realistic mode requires mode='ner' or names=[...] override

### `phone`

| Field | Value |
|---|---|
| Default strategy | `mask` |
| Sensitivity | 2 |
| Reversible | ✗ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `phone_numbers` |
| Examples | `(415) 555-1234`, `+1-415-555-1234` |
| Source | NANP; faker uses NANP 555-0100..0199 (FCC 47 CFR § 52.15(f)(1)(ii)) |

North American phone — realistic faker uses 555-01XX

### `political`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `registered Democrat`, `voted for Republican` |
| Source | GDPR Article 9 special category |

Political opinion

### `religion`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 3 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `Catholic`, `halal` |
| Source | GDPR Article 9 special category |

Religious belief

### `self_reference`

| Field | Value |
|---|---|
| Default strategy | `keep` |
| Sensitivity | 1 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| Examples | `my mother`, `my husband`, `I` |
| Source | proximity-hint signal for L1b person scoring |

First-person pronouns and kinship phrases — feeds self_reference_tier hint

### `sexual_orientation`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.55, PIPL Art.56 |
| GDPR Art.9 special category | ✓ |
| Examples | `gay`, `lesbian`, `came out` |
| Source | GDPR Article 9 special category |

Sexual orientation

### `ssn`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `ssn` |
| Examples | `123-45-6789` |
| Source | SSA SSN format; faker uses 999-XX-XXXX (SSA never assigns 9XX area) |

US Social Security Number — realistic faker uses 999-XX

### `us_passport`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| HIPAA Safe Harbor | `certificate_number` |
| Examples | `Passport: A12345678` |
| Source | US Department of State passport format |

US passport — keyword-triggered, letter + 8 digits

## Shared (cross-lang) — 9 types

### `anthropic_api_key`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Examples | `sk-ant-api03-FAKE0000000000000000000000000000abcdefghij`, `sk-ant-TEST0000000000000000000000000000000000fakekey` |
| Source | Anthropic platform key format |

Anthropic API key (sk-ant- prefix)

### `aws_access_key`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Examples | `AKIAIOSFODNN7EXAMPLE`, `AKIA0000TEST1234FAKE` |
| Source | AWS IAM access key ID format |

AWS IAM access key ID (does not cover the secret access key — that needs keyword context)

### `email`

| Field | Value |
|---|---|
| Default strategy | `mask` |
| Sensitivity | 2 |
| Reversible | ✗ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `email_addresses` |
| Examples | `alice@example.com`, `用户@example.org` |
| Source | RFC 5321 + RFC 6531 (faker uses RFC 2606 reserved domains) |

Email address — detection in lang/shared/patterns.py; realistic faker uses example.{com,org,net}

### `github_token`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Examples | `ghp_0000000000000000000000000000000000FAKE`, `github_pat_11ABCDEFG0000000000000_fakesuffix0000abcde`, `gho_0000000000000000000000000000000000FAKE` |
| Source | GitHub personal/OAuth/app token formats |

GitHub tokens: classic PAT (ghp_), OAuth (gho_), user (ghu_), server (ghs_), refresh (ghr_), fine-grained (github_pat_)

### `ip_address`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `ip_address` |
| Examples | `192.168.1.1`, `2001:db8::1` |
| Source | RFC 791 (v4) / RFC 4291 (v6); faker uses RFC 5737 / RFC 3849 documentation ranges |

IPv4 or IPv6 address — detection in lang/shared/patterns.py; realistic faker uses doc ranges

### `jwt`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Checksum | base64url decode + JSON.alg field |
| Examples | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.FakeSig123_-abcdef` |
| Source | RFC 7519 (JSON Web Token) |

JWT token (validated: 3 base64url segments, header decodes to JSON with 'alg' field)

### `mac_address`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 2 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.56 |
| HIPAA Safe Harbor | `device_identifier` |
| Examples | `aa:bb:cc:dd:ee:ff` |
| Source | IEEE 802 OUI; faker uses RFC 7042 documentation block 00:00:5E:00:53:xx |

MAC address — detection in lang/shared/patterns.py; realistic faker uses RFC 7042 doc block

### `openai_api_key`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Examples | `sk-TEST1234567890abcdefghij1234567890ABCDEFGHIJ`, `sk-proj-FAKE00000000000000000000000000000000000001test` |
| Source | OpenAI platform key format |

OpenAI API key (legacy sk- and project sk-proj- prefixes)

### `ssh_private_key`

| Field | Value |
|---|---|
| Default strategy | `remove` |
| Sensitivity | 4 |
| Reversible | ✓ |
| PIPL articles | PIPL Art.13, PIPL Art.28, PIPL Art.51, PIPL Art.29, PIPL Art.56 |
| Examples | `-----BEGIN OPENSSH PRIVATE KEY----- / FAKEKEYDATA / -----END OPENSSH PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY----- / FAKERSA / -----END RSA PRIVATE KEY-----` |
| Source | PEM format (RFC 7468) for SSH / TLS private keys |

SSH private key PEM block (RSA, OPENSSH, DSA, EC variants)

## Out of scope (v0.5.x)

Roadmapped for v0.6.x. Do not configure `lang="zh"` expecting these
types to redact. Use explicit `names=[...]` patterns or wait for v0.6.x.

- **`hk_id` — HKID 香港身份证**: 8 char `A123456(7)` format with check digit
- **`tw_id` — 台湾身份证**: `[A-Z]\d{9}` 1 letter + 9 digits
- **`macau_id` — 澳门身份证**: `\d/\d{6}/\d` format
- **`taiwan_arc` — 台湾居留证 (ARC)**: 1 letter + 9 chars

