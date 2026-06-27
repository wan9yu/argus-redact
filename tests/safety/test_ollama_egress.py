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


def test_failed_request_does_not_log_raw_prompt(caplog):
    # Logging hygiene: the retry path logs the failure with exc_info=True. A
    # privacy tool must NOT leak the pre-redaction prompt into logs — the logged
    # traceback is stack frames + the requests ConnectionError message (host/port/
    # url only); the raw text is a local variable and never appears in a default
    # Python traceback. Loopback port with nothing listening → ConnectionError
    # exercises the exc_info branch. Pins this so a future change that logs the
    # payload (or switches to an exception type carrying the body) is caught.
    import logging

    secret = "我的电话是13800138000，张伟住在西湖区"
    adapter = OllamaAdapter(base_url="http://localhost:59999")  # loopback, no server
    with caplog.at_level(logging.DEBUG):
        result = adapter._call_ollama(secret)
    assert result is None  # request failed (and was retried)
    assert "Ollama request failed" in caplog.text  # precondition: exc_info path ran
    assert secret not in caplog.text
    assert "13800138000" not in caplog.text
    assert "文本：" not in caplog.text  # the prompt-prefix marker must not leak either
