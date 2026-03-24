"""Tests for shared (cross-language) patterns."""

from argus_redact.pure.patterns import match_patterns
from argus_redact.lang.shared.patterns import PATTERNS


class TestEmailPattern:
    def test_simple(self):
        results = match_patterns("email: user@example.com ok", PATTERNS)
        assert len(results) == 1
        assert results[0].text == "user@example.com"
        assert results[0].type == "email"

    def test_with_subdomain(self):
        results = match_patterns("a]user@mail.example.co.uk[b", PATTERNS)
        assert len(results) == 1

    def test_with_plus(self):
        results = match_patterns("user+tag@example.com", PATTERNS)
        assert len(results) == 1

    def test_no_match(self):
        results = match_patterns("no email here", PATTERNS)
        assert len(results) == 0
