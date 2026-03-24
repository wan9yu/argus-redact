"""Tests for shared (cross-language) patterns."""

from argus_redact.pure.patterns import match_patterns
from tests.conftest import EMAIL_SIMPLE, EMAIL_PLUS


class TestEmailPattern:
    def test_simple(self, shared_patterns):
        results = match_patterns(f"email: {EMAIL_SIMPLE} ok", shared_patterns)
        assert len(results) == 1
        assert results[0].text == EMAIL_SIMPLE
        assert results[0].type == "email"

    def test_with_subdomain(self, shared_patterns):
        results = match_patterns("a]user@mail.example.co.uk[b", shared_patterns)
        assert len(results) == 1

    def test_with_plus(self, shared_patterns):
        results = match_patterns(EMAIL_PLUS, shared_patterns)
        assert len(results) == 1

    def test_no_match(self, shared_patterns):
        results = match_patterns("no email here", shared_patterns)
        assert len(results) == 0
