"""Tests for HTTP API server — using Starlette TestClient (in-process, coverage tracked)."""

import importlib.util

import pytest

HAS_STARLETTE = importlib.util.find_spec("starlette") is not None

pytestmark = pytest.mark.skipif(not HAS_STARLETTE, reason="starlette not installed")


@pytest.fixture(scope="module")
def client():
    from argus_redact.server import create_app
    from starlette.testclient import TestClient

    return TestClient(create_app())


class TestServerRedact:
    def test_should_redact_text(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "13812345678" not in data["redacted"]
        assert "key" in data

    def test_should_redact_with_lang(self, client):
        resp = client.post(
            "/redact",
            json={"text": "SSN 123-45-6789", "mode": "fast", "lang": "en", "seed": 42},
        )

        assert resp.status_code == 200
        assert "123-45-6789" not in resp.json()["redacted"]

    def test_should_redact_with_multi_lang(self, client):
        resp = client.post(
            "/redact",
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

    def test_should_return_detailed_when_requested(self, client):
        resp = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42, "detailed": True},
        )

        data = resp.json()
        assert "details" in data
        assert data["details"]["stats"]["total"] >= 1

    def test_should_return_400_on_invalid_mode(self, client):
        resp = client.post(
            "/redact",
            json={"text": "test", "mode": "invalid"},
        )

        assert resp.status_code == 400


class TestServerRestore:
    def test_should_restore_text(self, client):
        r1 = client.post(
            "/redact",
            json={"text": "电话13812345678", "mode": "fast", "seed": 42},
        )
        data = r1.json()

        r2 = client.post(
            "/restore",
            json={"text": data["redacted"], "key": data["key"]},
        )

        assert r2.status_code == 200
        assert "13812345678" in r2.json()["restored"]


class TestServerInfo:
    def test_should_return_info(self, client):
        resp = client.get("/info")

        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "languages" in data
        assert "zh" in data["languages"]


class TestServerHealth:
    def test_should_return_healthy(self, client):
        resp = client.get("/health")

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
