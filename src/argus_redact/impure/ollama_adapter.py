"""Ollama adapter for Layer 3 semantic PII detection."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import warnings
from urllib.parse import urlparse

import requests

from argus_redact._types import NEREntity
from argus_redact.exceptions import LayerUnavailableError, SecurityWarning
from argus_redact.impure.model_profiles import get_model_profile
from argus_redact.impure.semantic import SemanticAdapter

logger = logging.getLogger(__name__)


def _find_all(haystack: str, needle: str) -> list[tuple[int, int]]:
    """All non-overlapping (start, end) spans of needle in haystack."""
    spans: list[tuple[int, int]] = []
    if not needle:
        return spans
    i = haystack.find(needle)
    while i != -1:
        spans.append((i, i + len(needle)))
        i = haystack.find(needle, i + len(needle))
    return spans


# Named hosts treated as loopback (IP literals are checked via `ipaddress` below,
# which covers 127.0.0.0/8 + ::1 precisely and rejects look-alikes like 127.evil.com).
_LOOPBACK_NAMES = {"localhost"}


def _validate_ollama_host(base_url: str) -> None:
    """Reject non-http(s) schemes; default-deny non-loopback hosts.

    A non-loopback OLLAMA_HOST ships raw, pre-redaction PII off the box. Require
    explicit ARGUS_ALLOW_REMOTE_OLLAMA=1 opt-in and warn (naming the host).
    """
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"OLLAMA_HOST must use http/https scheme, got {parsed.scheme!r} for host {host!r}"
        )
    is_loopback = host in _LOOPBACK_NAMES
    if not is_loopback and host:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
    if not is_loopback:
        if os.environ.get("ARGUS_ALLOW_REMOTE_OLLAMA") != "1":
            raise ValueError(
                f"refusing to send raw PII to non-loopback OLLAMA_HOST '{host}'. "
                f"Set ARGUS_ALLOW_REMOTE_OLLAMA=1 to allow (Layer-3 sends pre-redaction text)."
            )
        warnings.warn(
            f"Layer-3 will send raw, pre-redaction text to remote host '{host}'.",
            SecurityWarning,
            stacklevel=2,
        )


SYSTEM_PROMPT = """你是隐私分析专家。分析文本中所有隐含的敏感个人信息。

检测类型（用英文返回 type）：
- medical: 暗示疾病、症状、就医、服药、身体状况
- financial: 暗示收入水平、债务、经济状况、消费能力
- religion: 暗示宗教信仰、宗教活动（周五请假→主麻日；不吃猪肉→伊斯兰饮食禁忌；特定节日→宗教节日）
- political: 暗示政治立场、党派倾向、政治活动
- sexual_orientation: 暗示性取向、亲密关系模式
- criminal: 暗示违法经历、服刑、释放后处境
- biometric: 暗示生物特征数据采集（刷脸、指纹等）
- gender: 通过生理特征推断性别。重要：怀孕/产假/预产期→female；前列腺/精子→male。
  如果文本同时涉及medical和gender，两个type都要返回
- person: 昵称、别名、非正式称呼（如"老王"、"小李"）
- location: 隐含的地点引用（如"那个地方"、"我们公司"）

规则：
1. 只找隐含的、间接的信息，不要重复明确说出的内容
2. 一段文本可以同时属于多个类型——全部返回
3. 宁可多报不要漏报——对隐私保护来说，漏检比误报更危险
4. 注意文化背景推断（宗教日历、饮食禁忌、社会习俗）

以JSON数组返回，每个元素包含：
- text: 原文中的文字
- type: 类型（用英文）
- start: 起始字符位置
- end: 结束字符位置

没有发现则返回 []。只返回JSON，不要其他文字。"""


# The ten types SYSTEM_PROMPT tells the model to return. A model that follows
# the prompt only ever emits one of these; anything else is a drifting model or
# a prompt-injected one choosing an attacker-controlled string.
#
# Mirrors the closed `_TYPE_MAP` allowlist every Layer-2 NER adapter applies to
# its model's labels (see `lang/zh/ner_adapter.py`) — L3 was the only detector
# ingesting a model-chosen type name unchecked. Unlike those adapters, an
# unrecognised type here is RELABELLED rather than dropped: the model still
# found a span worth protecting, and losing a detection is worse than losing a
# label. `_UNRECOGNISED_TYPE` is deliberately absent from the registry, so an
# entity carrying it keeps exactly the sensitivity (2) and `remove` strategy an
# unregistered type already had — the label stops being attacker-controlled
# without changing how the span is treated.
_ALLOWED_SEMANTIC_TYPES = frozenset(
    {
        "medical",
        "financial",
        "religion",
        "political",
        "sexual_orientation",
        "criminal",
        "biometric",
        "gender",
        "person",
        "location",
    }
)

_UNRECOGNISED_TYPE = "semantic_other"


class OllamaAdapter(SemanticAdapter):
    """Semantic PII detection via Ollama local LLM.

    Model-specific behavior (prompt prefix, timeout, confidence) is loaded
    from model_profiles.py. To add a new model, add a profile there.
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
    ):
        import os

        self._model = model or os.environ.get("OLLAMA_MODEL", "qwen3:8b")
        self._base_url = base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        _validate_ollama_host(self._base_url)
        self._profile = get_model_profile(self._model)

    def _call_ollama(self, text: str) -> requests.Response | None:
        """Call Ollama with retry. Timeout and prompt prefix from model profile.

        Returns ``None`` when no attempt produced a 200 — a connection failure
        or a non-200 status. ``detect`` turns that into a raised
        LayerUnavailableError; it stays ``None`` here so the two logging-hygiene
        branches (exception / status code) remain directly testable.
        """
        payload = {
            "model": self._model,
            "prompt": f"{self._profile.prompt_prefix}文本：{text}",
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {"temperature": 0.0},
        }
        for attempt in range(2):
            try:
                resp = requests.post(
                    f"{self._base_url}/api/generate",
                    json=payload,
                    timeout=self._profile.timeout,
                    # _validate_ollama_host() only checks the URL; requests still
                    # honours HTTP_PROXY/HTTPS_PROXY/ALL_PROXY from the environment
                    # and does NOT exempt loopback targets from them. Left ambient,
                    # a proxy silently re-routes this loopback-validated request off
                    # the box — no error, no SecurityWarning, no opt-in required —
                    # defeating the whole point of the loopback check above. Do not
                    # drop this as "redundant" with that check; it is what makes the
                    # check actually binding.
                    proxies={"http": None, "https": None},
                )
                if resp.status_code == 200:
                    return resp
                logger.warning(
                    "Ollama returned status %d (attempt %d)",
                    resp.status_code,
                    attempt + 1,
                )
            except Exception as exc:
                # Type only, never exc_info=True: a full traceback can embed
                # adapter call-frame fragments (the request URL, the payload) —
                # mirrors the Layer-3 failure log in glue/redact.py.
                logger.warning(
                    "Ollama request failed (attempt %d): %s",
                    attempt + 1,
                    type(exc).__name__,
                )
        return None

    def detect(self, text: str) -> list[NEREntity]:
        if not text:
            return []

        response = self._call_ollama(text)
        if response is None:
            # "The model was never reached" is not "the model found nothing".
            # Returning [] made the two indistinguishable one frame up: the
            # redact glue reported layer_3_status="ok" for an unreachable
            # Ollama, emitted no warning, and honoured no strict=True — the
            # exact silent-failure mode Layer-3 status reporting exists to
            # prevent. Raising routes it into the glue's existing failure
            # handler (log the type, set "error", warn, raise under strict).
            # The message carries the model name and no URL: OLLAMA_HOST may
            # embed credentials, and this string reaches the caller.
            raise LayerUnavailableError(
                f"Layer-3 semantic model {self._model!r} could not be reached "
                f"(no successful response after 2 attempts)."
            )

        try:
            llm_output = response.json().get("response", "")
            raw_entities = json.loads(llm_output)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Failed to parse LLM output as JSON")
            return []

        if not isinstance(raw_entities, list):
            return []

        entities = []
        seen: set[tuple[int, int, str]] = set()
        for item in raw_entities:
            if not isinstance(item, dict):
                continue
            entity_text = item.get("text", "")
            entity_type = item.get("type", "")
            start = item.get("start")
            end = item.get("end")

            if not entity_text or not entity_type:
                continue

            if entity_type not in _ALLOWED_SEMANTIC_TYPES:
                entity_type = _UNRECOGNISED_TYPE

            # Trust the LLM's offsets only when they are in-bounds AND actually
            # point at entity_text. Otherwise fall back to string search — and
            # recover EVERY occurrence, not just the first: an N-times-repeated
            # name with wrong offsets would otherwise collapse onto one span and
            # leak the other occurrences (missed detection > false positive).
            if (
                start is not None
                and end is not None
                and 0 <= start <= end <= len(text)
                and text[start:end] == entity_text
            ):
                spans = [(start, end)]
            else:
                spans = _find_all(text, entity_text)
                if not spans:
                    continue

            for s, e in spans:
                if (s, e, entity_type) in seen:
                    continue
                seen.add((s, e, entity_type))
                entities.append(
                    NEREntity(
                        text=entity_text,
                        type=entity_type,
                        start=s,
                        end=e,
                        confidence=self._profile.confidence,
                    )
                )

        return entities
