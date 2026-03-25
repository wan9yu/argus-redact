"""Tests for HTTP API server.

Run with: pytest tests/integration/test_server.py -m slow -v
"""

import importlib.util
import threading
import time

import pytest
import requests as req

pytestmark = pytest.mark.slow

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None


@pytest.fixture(scope="module")
def server():
    if not HAS_STARLETTE:
        pytest.skip("starlette/uvicorn not installed")
    from argus_redact.server import create_app

    app = create_app()

    import uvicorn

    t = threading.Thread(
        target=uvicorn.run,
        kwargs={"app": app, "host": "127.0.0.1", "port": 19876, "log_level": "error"},
        daemon=True,
    )
    t.start()
    time.sleep(1)
    yield "http://127.0.0.1:19876"


class TestServerRedact:
    def test_should_redact_text(self, server):
        resp = req.post(
            f"{server}/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "13812345678" not in data["redacted"]
        assert "key" in data

    def test_should_redact_with_lang(self, server):
        resp = req.post(
            f"{server}/redact",
            json={
                "text": "SSN 123-45-6789",
                "mode": "fast",
                "lang": "en",
                "seed": 42,
            },
        )

        assert resp.status_code == 200
        assert "123-45-6789" not in resp.json()["redacted"]

    def test_should_redact_with_multi_lang(self, server):
        resp = req.post(
            f"{server}/redact",
            json={
                "text": "电话13812345678, SSN 123-45-6789",
                "mode": "fast",
                "lang": ["zh", "en"],
                "seed": 42,
            },
        )

        data = resp.json()
        assert "13812345678" not in data["redacted"]
        assert "123-45-6789" not in data["redacted"]


class TestServerRestore:
    def test_should_restore_text(self, server):
        # First redact
        r1 = req.post(
            f"{server}/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        data = r1.json()

        # Then restore
        r2 = req.post(
            f"{server}/restore",
            json={"text": data["redacted"], "key": data["key"]},
        )

        assert r2.status_code == 200
        assert "13812345678" in r2.json()["restored"]


class TestServerInfo:
    def test_should_return_info(self, server):
        resp = req.get(f"{server}/info")

        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "languages" in data


class TestServerHealth:
    def test_should_return_healthy(self, server):
        resp = req.get(f"{server}/health")

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
