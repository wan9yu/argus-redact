"""Checksum-validated PII must not be suppressed by adjacent arithmetic/version text;
format-ambiguous no-validator types keep the false-positive heuristic."""

from argus_redact import redact


def test_ssn_before_arithmetic_redacted():
    out, _ = redact("SSN 123-45-6789 - 5 dollars", lang="en", mode="fast", salt=42)
    assert "123-45-6789" not in out


def test_credit_card_before_arithmetic_redacted():
    out, _ = redact("card 4111111111111111 - 0", lang="en", mode="fast", salt=42)
    assert "4111111111111111" not in out


def test_ip_version_string_still_not_redacted():
    # Precision guard intact: a dotted-quad software version is NOT an IP address.
    out, _ = redact("version 1.2.3.4 released", lang="en", mode="fast", salt=42)
    assert "1.2.3.4" in out


def test_valid_id_after_serial_keyword_redacted():
    # 110101199003074610 is a checksum-valid GB11643 id (gb11643_mod11 validator
    # passes; same value used in tests/fixtures). 编号 is a FALSE_POSITIVE_PREFIX
    # trigger, but a validator-confirmed value must not be suppressed by it.
    out, _ = redact("编号110101199003074610", lang="zh", mode="fast", salt=42)
    assert "110101199003074610" not in out


def test_two_same_type_values_split_by_slash_both_redacted():
    # A no-validator check_context type (zh mobile) followed by "/second-value" used
    # to fire the arithmetic-suffix heuristic on the SECOND value and silently drop
    # the FIRST — a plaintext leak. The operand after "/" is itself a same-type value
    # (a delimiter, not division), so BOTH must redact.
    out, _ = redact("电话：13800138000/13900139000", lang="zh", mode="fast", salt=42)
    assert "13800138000" not in out
    assert "13900139000" not in out


def test_two_same_type_values_split_by_spaced_delimiter_both_redacted():
    # Same leak in the spaced form "value / value" (whitespace on both sides of the
    # operator). The br phone type is also validator-free + check_context.
    out, _ = redact("11 98765-4321 / 21 91234-5678", lang="br", mode="fast", salt=42)
    assert "98765" not in out
    assert "91234" not in out


def test_ip_range_both_endpoints_redacted():
    # ip_address is validator-free + check_context; a "ip - ip" range is a delimiter,
    # not subtraction, so neither endpoint may be suppressed.
    out, _ = redact("IP 10.0.0.1-10.0.0.2", lang="zh", mode="fast", salt=42)
    assert "10.0.0.1" not in out
    assert "10.0.0.2" not in out


def test_single_arithmetic_operand_still_suppressed():
    # Precision control: a genuine single-operand arithmetic suffix whose operand is
    # NOT a same-type value ("* 5") must STILL suppress the leading number — the
    # same-type release must not broaden into arithmetic.
    out, _ = redact("账号余额 13800138000 * 5", lang="zh", mode="fast", salt=42)
    assert "13800138000" in out


def test_false_positive_prefix_still_suppressed():
    # Precision control: the PREFIX heuristic is untouched. A "版本" label before a
    # phone-shaped number keeps it suppressed (surfaced only as an L2/L3 near-miss).
    out, _ = redact("版本 13800138000", lang="zh", mode="fast", salt=42)
    assert "13800138000" in out


def test_itin_redacted_and_does_not_cannibalize_ssn():
    # ITINs share SSN digit shape but use area 900-999, which validate_ssn
    # rejects. Without a dedicated itin type these values leaked entirely.
    out, _ = redact("ITIN 912-70-1234", lang="en", salt=42)
    assert "912-70-1234" not in out

    # A group outside the IRS-assigned ranges (50-65, 70-88, 90-92, 94-99) is
    # not a valid ITIN, and its area (900+) is not a valid SSN either — so it
    # is correctly left unredacted rather than misclassified as either type.
    out, _ = redact("group 912-45-6789", lang="en", salt=42)
    assert "912-45-6789" in out

    # Regression guard: a genuine SSN must still redact as ssn.
    out, _ = redact("SSN 123-45-6789", lang="en", salt=42)
    assert "123-45-6789" not in out
