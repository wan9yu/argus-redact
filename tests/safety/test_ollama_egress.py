"""L3 egress guard — raw PII must not silently go off-box."""

from unittest.mock import Mock, patch

import pytest
import requests

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
    # Python traceback. Mock requests.post to raise ConnectionError directly rather
    # than relying on a real socket connecting to nothing: an ambient HTTP_PROXY/
    # HTTPS_PROXY/ALL_PROXY env var (common on corporate networks and VPN clients)
    # makes requests route this "loopback" URL through the proxy instead, which
    # answers with a real HTTP response (e.g. a proxy error status) rather than
    # raising — so the exc_info branch this test targets would silently never run,
    # and the precondition below would fail while looking like an environment
    # problem instead of a lost safety guarantee. Mocking removes the network (and
    # the proxy) from the picture entirely.
    import logging

    secret = "我的电话是13800138000，张伟住在西湖区"
    adapter = OllamaAdapter(base_url="http://localhost:59999")  # loopback, no server
    with (
        patch("requests.post", side_effect=requests.exceptions.ConnectionError("refused")),
        caplog.at_level(logging.DEBUG),
    ):
        result = adapter._call_ollama(secret)
    assert result is None  # request failed (and was retried)
    assert "Ollama request failed" in caplog.text  # precondition: exc_info path ran
    assert secret not in caplog.text
    assert "13800138000" not in caplog.text
    assert "文本：" not in caplog.text  # the prompt-prefix marker must not leak either


def test_failed_request_status_code_does_not_log_raw_prompt(caplog):
    # Sibling of the exception test above, for the OTHER failure branch: a
    # non-200 response (no exception at all — the request succeeded at the
    # transport level, Ollama/a proxy just answered with an error status). This
    # is the branch that a proxy sitting between the adapter and "localhost"
    # actually drives in practice, so it needs the same three no-leak assertions
    # as the exception path, not just the exc_info one.
    import logging

    secret = "我的电话是13800138000，张伟住在西湖区"
    adapter = OllamaAdapter(base_url="http://localhost:59999")  # loopback, no server
    fake_response = Mock()
    fake_response.status_code = 503
    with (
        patch("requests.post", return_value=fake_response),
        caplog.at_level(logging.DEBUG),
    ):
        result = adapter._call_ollama(secret)
    assert result is None  # request failed (and was retried)
    assert "Ollama returned status" in caplog.text  # precondition: status-code path ran
    assert secret not in caplog.text
    assert "13800138000" not in caplog.text
    assert "文本：" not in caplog.text  # the prompt-prefix marker must not leak either
