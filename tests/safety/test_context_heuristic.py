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
