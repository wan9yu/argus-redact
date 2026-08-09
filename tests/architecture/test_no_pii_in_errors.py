"""Architecture: error/exception/log/warning messages must never echo secrets or PII.

An error path that interpolates the user's text, a matched span, a key entry, the
salt, an entity's original value, or a credential-bearing URL leaks that content
into an HTTP body, a CLI stderr line, or a log — defeating the whole point of a
redaction tool. Each test here pins one known offender behaviourally: feed the
sensitive input, assert the raised/logged message excludes the sensitive
substring (and, where relevant, still contains the non-sensitive parts that make
the message useful).
"""

from __future__ import annotations

import importlib.util
import inspect
import warnings

import pytest

from argus_redact.impure.ollama_adapter import _validate_ollama_host

_HAS_STARLETTE = importlib.util.find_spec("starlette") is not None


class TestOllamaHostValidationDoesNotLeakCredentials:
    def test_bad_scheme_error_excludes_userinfo(self):
        # socks5:// is rejected by the scheme check before the loopback check
        # ever runs. The message must not carry the embedded user:s3cret
        # userinfo — only the scheme and hostname, which are enough to explain
        # the rejection.
        host = "socks5://user:s3cret@host:1080"

        try:
            _validate_ollama_host(host)
        except ValueError as exc:
            message = str(exc)
        else:
            raise AssertionError("expected _validate_ollama_host to raise ValueError")

        assert "s3cret" not in message
        assert "user" not in message
        assert "socks5" in message
        assert "host" in message

    def test_non_loopback_error_excludes_userinfo(self):
        # A non-loopback http(s) host with embedded credentials must also be
        # rejected (absent the remote opt-in) without echoing the userinfo.
        host = "http://user:s3cret@evil.example.com:11434"

        try:
            _validate_ollama_host(host)
        except ValueError as exc:
            message = str(exc)
        else:
            raise AssertionError("expected _validate_ollama_host to raise ValueError")

        assert "s3cret" not in message
        assert "user:" not in message
        assert "evil.example.com" in message


class TestOllamaHostValidatorSourceNeverInterpolatesRawBaseUrl:
    # Lightweight structural guard, narrowly scoped to the one function that
    # was fixed: `_validate_ollama_host` must never go back to interpolating
    # the raw `base_url` (which can carry userinfo) into a raised message. A
    # broad grep over every module would be brittle (see the module
    # docstring); pinning the source of the single known offender is not —
    # the source only changes when someone deliberately edits this function.
    def test_source_never_interpolates_base_url_into_a_message(self):
        source = inspect.getsource(_validate_ollama_host)
        assert "{base_url" not in source, (
            "_validate_ollama_host must not interpolate the raw base_url "
            "(may carry userinfo, e.g. socks5://user:pass@host) into any "
            "raised message — use parsed.scheme / host instead"
        )

    def test_guard_is_not_vacuous(self):
        # Positive control: the guard above only means something if the
        # function's raise messages actually reference SOMETHING derived from
        # the URL (scheme/host) — otherwise "no {base_url" could pass by
        # having removed all interpolation instead of narrowing it correctly.
        source = inspect.getsource(_validate_ollama_host)
        assert "{host" in source or "parsed.scheme" in source


@pytest.mark.skipif(not _HAS_STARLETTE, reason="starlette not installed")
class TestOllamaHostLeakDoesNotReachHttpBody:
    # mode='auto' is the only mode that constructs OllamaAdapter (a fast/default
    # request never does — see the module-level warning against a fast-mode
    # false green). `_get_ner_adapters` is mocked so this runs offline/CI-safe
    # with no real NER model installed (mirrors the pattern used against the
    # same false-green risk in test_layer3_log_scrub.py). `_get_semantic_adapter`
    # is NOT mocked — OllamaAdapter() constructs for real and _validate_ollama_host
    # raises before any network call, so the whole path stays offline.
    def test_bad_ollama_host_400_body_excludes_credentials(self, monkeypatch):
        import argus_redact.glue.redact as glue_redact
        from argus_redact.server import create_app

        monkeypatch.setenv("OLLAMA_HOST", "socks5://user:s3cret@host:1080")
        monkeypatch.setattr(glue_redact, "_get_ner_adapters", lambda lang, **_kw: [])

        with warnings.catch_warnings():
            # SecurityWarning for "no auth" (allow_no_auth=True, test-only) and
            # for the forced no-NER-model degradation above — neither is the
            # thing under test.
            warnings.simplefilter("ignore")
            from starlette.testclient import TestClient

            client = TestClient(create_app(allow_no_auth=True))

            resp = client.post(
                "/redact",
                json={"text": "老王住在北京", "lang": "zh", "mode": "auto"},
            )

        assert resp.status_code == 400
        body = resp.text
        assert "s3cret" not in body
        assert "user:" not in body
        assert "host" in body
