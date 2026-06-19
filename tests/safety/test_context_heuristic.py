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
