"""Cross-language PII type specifications (credentials, secrets).

These types are not tied to a particular language pack — they appear in
source code, config files, and shell environments globally. Detection is
format-based (regex, with optional validate) and registered here with
sensitivity=4 (critical) so `risk.py` scores credential leaks appropriately.

Credentials are NOT added to risk.py's `_SENSITIVE_PI_TYPES` set: they are
not "sensitive personal information" under PIPL Art.29/51 — they're access
tokens. High risk, but distinct compliance category from medical/financial/etc.
"""

from __future__ import annotations

from .registry import PIITypeDef, register

# ── OpenAI API key ──
register(
    PIITypeDef(
        name="openai_api_key",
        lang="shared",
        format="sk-[alphanumeric 32+] or sk-proj-[alphanumeric 32+]",
        charset="alnum + _ + -",
        strategy="remove",
        label="[OPENAI-API-KEY]",
        examples=(
            "sk-TEST1234567890abcdefghij1234567890ABCDEFGHIJ",
            "sk-proj-FAKE00000000000000000000000000000000000001test",
        ),
        counterexamples=(
            "sk-short123",
            "sk-ant-TEST0000000000000000000000000000000000fakekey",
        ),
        sensitivity=4,
        source="OpenAI platform key format",
        description="OpenAI API key (legacy sk- and project sk-proj- prefixes)",
    )
)


# ── Anthropic API key ──
register(
    PIITypeDef(
        name="anthropic_api_key",
        lang="shared",
        format="sk-ant-[alphanumeric 32+]",
        charset="alnum + _ + -",
        strategy="remove",
        label="[ANTHROPIC-API-KEY]",
        examples=(
            "sk-ant-api03-FAKE0000000000000000000000000000abcdefghij",
            "sk-ant-TEST0000000000000000000000000000000000fakekey",
        ),
        counterexamples=(
            "sk-ant-shortone",
            "sk-anthropic-TEST000000000000000000000000000",
        ),
        sensitivity=4,
        source="Anthropic platform key format",
        description="Anthropic API key (sk-ant- prefix)",
    )
)


# ── AWS Access Key ──
register(
    PIITypeDef(
        name="aws_access_key",
        lang="shared",
        format="AKIA[A-Z0-9]{16}",
        length=20,
        charset="uppercase alnum",
        strategy="remove",
        label="[AWS-ACCESS-KEY]",
        examples=(
            "AKIAIOSFODNN7EXAMPLE",
            "AKIA0000TEST1234FAKE",
        ),
        counterexamples=(
            "akiaIOSFODNN7EXAMPLE",
            "AKIA0000TEST1234",
        ),
        sensitivity=4,
        source="AWS IAM access key ID format",
        description="AWS IAM access key ID (does not cover the secret access key — that needs keyword context)",
    )
)


# ── GitHub Token ──
register(
    PIITypeDef(
        name="github_token",
        lang="shared",
        format="ghp|gho|ghu|ghs|ghr_[alnum 36+] or github_pat_[alnum_ 22+]",
        charset="alnum + _",
        strategy="remove",
        label="[GITHUB-TOKEN]",
        examples=(
            "ghp_0000000000000000000000000000000000FAKE",
            "github_pat_11ABCDEFG0000000000000_fakesuffix0000abcde",
            "gho_0000000000000000000000000000000000FAKE",
        ),
        counterexamples=(
            "ghx_0000000000000000000000000000000000FAKE",
            "ghp_tooshort",
        ),
        sensitivity=4,
        source="GitHub personal/OAuth/app token formats",
        description="GitHub tokens: classic PAT (ghp_), OAuth (gho_), user (ghu_), server (ghs_), refresh (ghr_), fine-grained (github_pat_)",
    )
)


# ── JWT ──
register(
    PIITypeDef(
        name="jwt",
        lang="shared",
        format="eyJ<header-b64url>.eyJ<payload-b64url>.<sig-b64url>",
        charset="base64url (alnum + _ + -)",
        checksum="base64url decode + JSON.alg field",
        strategy="remove",
        label="[JWT]",
        examples=("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.FakeSig123_-abcdef",),
        counterexamples=(
            "eyJABC.eyJDEF.GHIJKL",
            "abc.def.ghi",
        ),
        sensitivity=4,
        source="RFC 7519 (JSON Web Token)",
        description="JWT token (validated: 3 base64url segments, header decodes to JSON with 'alg' field)",
    )
)


# ── SSH Private Key ──
register(
    PIITypeDef(
        name="ssh_private_key",
        lang="shared",
        format="-----BEGIN [type] PRIVATE KEY----- ... -----END [type] PRIVATE KEY-----",
        charset="PEM armored (base64 + newlines + dashes)",
        strategy="remove",
        label="[SSH-PRIVATE-KEY]",
        examples=(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA\n-----END OPENSSH PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nFAKERSA\n-----END RSA PRIVATE KEY-----",
        ),
        counterexamples=("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEDATA without closing marker",),
        sensitivity=4,
        source="PEM format (RFC 7468) for SSH / TLS private keys",
        description="SSH private key PEM block (RSA, OPENSSH, DSA, EC variants)",
    )
)


# ── Cross-language identifiers (detection regex stays in lang/shared/patterns.py) ──

register(
    PIITypeDef(
        name="email",
        lang="shared",
        format="local@domain",
        charset="ASCII / RFC 6531 internationalized",
        strategy="mask",
        label="[邮箱已脱敏]",
        examples=("alice@example.com", "用户@example.org"),
        counterexamples=("not-an-email",),
        sensitivity=2,
        source="RFC 5321 + RFC 6531 (faker uses RFC 2606 reserved domains)",
        description="Email address — detection in lang/shared/patterns.py; realistic faker uses example.{com,org,net}",
    )
)

register(
    PIITypeDef(
        name="ip_address",
        lang="shared",
        format="IPv4 dotted-quad or IPv6 hex-colon",
        charset="digits + : (v6) + . (v4)",
        strategy="remove",
        label="[IP已脱敏]",
        examples=("192.168.1.1", "2001:db8::1"),
        counterexamples=("999.999.999.999",),
        sensitivity=2,
        source="RFC 791 (v4) / RFC 4291 (v6); faker uses RFC 5737 / RFC 3849 documentation ranges",
        description="IPv4 or IPv6 address — detection in lang/shared/patterns.py; realistic faker uses doc ranges",
    )
)

register(
    PIITypeDef(
        name="mac_address",
        lang="shared",
        format="XX:XX:XX:XX:XX:XX (or - / . separators)",
        charset="hex + separator",
        strategy="remove",
        label="[MAC已脱敏]",
        examples=("aa:bb:cc:dd:ee:ff",),
        counterexamples=("not-a-mac",),
        sensitivity=2,
        source="IEEE 802 OUI; faker uses RFC 7042 documentation block 00:00:5E:00:53:xx",
        description="MAC address — detection in lang/shared/patterns.py; realistic faker uses RFC 7042 doc block",
    )
)


# ── Cross-language quasi-identifiers (no format-based detection; NER / downstream) ──

register(
    PIITypeDef(
        name="phone_landline",
        lang="shared",
        format="varies by region",
        charset="digits + separators",
        strategy="mask",
        label="[PHONE REDACTED]",
        examples=(),
        counterexamples=(),
        sensitivity=2,
        description=(
            "Landline phone number — detected via NER or Presidio; "
            "prefix LL avoids collision with mobile phone prefix"
        ),
    )
)

register(
    PIITypeDef(
        name="date",
        lang="shared",
        format="varies (ISO 8601, locale-specific, etc.)",
        charset="digits + separators",
        strategy="remove",
        label="[DATE REDACTED]",
        examples=(),
        counterexamples=(),
        sensitivity=1,
        description=(
            "Date / temporal identifier — detected via NER or Presidio; "
            "HIPAA shift-by-N is a v0.7+ candidate"
        ),
    )
)

register(
    PIITypeDef(
        name="url",
        lang="shared",
        format="scheme://host/path[?query]",
        charset="ASCII URL characters",
        strategy="remove",
        label="[URL REDACTED]",
        examples=(),
        counterexamples=(),
        sensitivity=1,
        description=(
            "URL / web address — detected via NER or Presidio; "
            "removed because query parameters may carry PII"
        ),
    )
)
