"""Tests for shared (cross-language) RFC reserved-range fakers.

Each faker outputs values in officially-reserved ranges:
- email: RFC 2606 (example.com / .org / .net)
- IPv4: RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
- IPv6: RFC 3849 (2001:db8::/32)
- MAC:  RFC 7042 (00:00:5E:00:53:xx)
"""

import random
import re

from argus_redact.specs.fakers_shared_reserved import (
    fake_email_reserved,
    fake_ip_reserved,
    fake_mac_reserved,
)


class TestFakeEmailReserved:
    def test_should_use_example_dot_tld(self):
        result = fake_email_reserved("alice@company.com", random.Random(1))
        assert result.endswith(("@example.com", "@example.org", "@example.net")), result

    def test_should_be_deterministic(self):
        a = fake_email_reserved("orig", random.Random(7))
        b = fake_email_reserved("orig", random.Random(7))
        assert a == b


class TestFakeIpReserved:
    def test_should_use_rfc5737_for_ipv4_input(self):
        result = fake_ip_reserved("10.0.0.5", random.Random(1))
        # 192.0.2.0/24 | 198.51.100.0/24 | 203.0.113.0/24
        assert re.match(r"^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$", result), result

    def test_should_use_rfc3849_for_ipv6_input(self):
        result = fake_ip_reserved("fe80::1", random.Random(1))
        assert result.startswith("2001:db8:"), f"Expected 2001:db8 prefix, got {result}"

    def test_should_be_deterministic(self):
        a = fake_ip_reserved("10.0.0.5", random.Random(3))
        b = fake_ip_reserved("10.0.0.5", random.Random(3))
        assert a == b


class TestFakeMacReserved:
    def test_should_use_rfc7042_documentation_block(self):
        result = fake_mac_reserved("aa:bb:cc:dd:ee:ff", random.Random(1))
        assert re.match(r"^00:00:5E:00:53:[0-9A-Fa-f]{2}$", result), result

    def test_should_be_deterministic(self):
        a = fake_mac_reserved("orig", random.Random(2))
        b = fake_mac_reserved("orig", random.Random(2))
        assert a == b
