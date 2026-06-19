"""L3 egress guard — raw PII must not silently go off-box."""

import pytest

from argus_redact import SecurityWarning
from argus_redact.impure.ollama_adapter import OllamaAdapter


def test_loopback_ok():
    a = OllamaAdapter(base_url="http://localhost:11434")
    assert a._base_url.startswith("http://localhost")


def test_remote_denied_by_default():
    with pytest.raises(ValueError, match="non-loopback"):
        OllamaAdapter(base_url="http://evil.example.com:11434")


def test_remote_allowed_with_optin_warns(monkeypatch):
    monkeypatch.setenv("ARGUS_ALLOW_REMOTE_OLLAMA", "1")
    with pytest.warns(SecurityWarning, match="evil.example.com"):
        OllamaAdapter(base_url="http://evil.example.com:11434")


def test_bad_scheme_rejected():
    with pytest.raises(ValueError, match="scheme"):
        OllamaAdapter(base_url="ftp://localhost:11434")


def test_loopback_lookalike_hostname_denied():
    # A hostname that merely starts with '127.' is NOT loopback (it resolves
    # off-box). The IP-literal loopback check must reject it.
    with pytest.raises(ValueError, match="non-loopback"):
        OllamaAdapter(base_url="http://127.evil.com:11434")
