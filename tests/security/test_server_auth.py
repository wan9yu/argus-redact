"""HTTP server refuses to start without ARGUS_API_KEY (audit H7).

Pre-fix, ``create_app()`` returned an open server when the env var was unset
— anyone reaching the listening port could call ``/redact`` and the
restoration endpoint ``/restore``. The default host is ``127.0.0.1`` but
container deployments routinely override to ``0.0.0.0``.
"""

from __future__ import annotations

import os
import warnings

import pytest


# Skip this module if starlette isn't installed (server[serve] extra)
pytest.importorskip("starlette", reason="server tests require starlette")


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)


def test_create_app_without_api_key_raises_by_default():
    from argus_redact.server import create_app

    with pytest.raises(RuntimeError, match="ARGUS_API_KEY"):
        create_app()


def test_create_app_with_allow_no_auth_works():
    from argus_redact import SecurityWarning
    from argus_redact.server import create_app

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        app = create_app(allow_no_auth=True)
    assert app is not None
    assert any(
        issubclass(w.category, SecurityWarning) for w in captured
    ), "no SecurityWarning emitted when running without auth"


def test_create_app_with_api_key_set_works(monkeypatch):
    monkeypatch.setenv("ARGUS_API_KEY", "test-key-value")
    from argus_redact.server import create_app

    app = create_app()
    assert app is not None


def test_cli_serve_insecure_flag_parses():
    """The ``--insecure`` flag must be reachable from the CLI parser."""
    from argus_redact.cli.main import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["serve", "--insecure"])
    assert getattr(args, "insecure", False) is True


def test_cli_serve_no_insecure_flag_default():
    from argus_redact.cli.main import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["serve"])
    assert getattr(args, "insecure", False) is False
