"""Shared test fixtures for argus-redact."""

import pytest


@pytest.fixture
def sample_key():
    """A typical key mapping pseudonyms to originals."""
    return {
        "P-037": "王五",
        "P-012": "张三",
        "[咖啡店]": "星巴克",
        "[某公司]": "阿里",
        "[手机号已脱敏]": "13812345678",
    }


@pytest.fixture
def empty_key():
    return {}
