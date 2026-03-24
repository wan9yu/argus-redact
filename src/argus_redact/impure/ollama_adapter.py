"""Ollama adapter for Layer 3 semantic PII detection."""

from __future__ import annotations

import json
import logging

import requests

from argus_redact._types import NEREntity
from argus_redact.impure.semantic import SemanticAdapter

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """你是一个隐私分析专家。分析以下文本，找出所有隐含的个人身份信息（PII），包括：
- 昵称、别名、非正式称呼（如"老王"、"小李"）
- 隐含的地点引用（如"那个地方"、"我们公司"）
- 上下文中可推断身份的描述（如"住在XX小区的那个医生"）
- 敏感话题引用（如"那件事"指代特定事件）

不要重复已经明显的实体（如完整人名、电话号码）。只找regex和NER可能遗漏的隐含PII。

以JSON数组格式返回，每个元素包含：
- text: 原文中的文字
- type: person/location/organization/event
- start: 在原文中的起始字符位置
- end: 在原文中的结束字符位置

如果没有发现隐含PII，返回空数组 []

只返回JSON，不要其他文字。"""

DEFAULT_CONFIDENCE = 0.7


class OllamaAdapter(SemanticAdapter):
    """Semantic PII detection via Ollama local LLM."""

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
    ):
        import os

        self._model = model or os.environ.get("OLLAMA_MODEL", "qwen2.5:32b")
        self._base_url = base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def detect(self, text: str) -> list[NEREntity]:
        if not text:
            return []

        try:
            response = requests.post(
                f"{self._base_url}/api/generate",
                json={
                    "model": self._model,
                    "prompt": f"文本：{text}",
                    "system": SYSTEM_PROMPT,
                    "stream": False,
                    "options": {"temperature": 0.0},
                },
                timeout=30,
            )
        except Exception:
            logger.warning("Ollama request failed", exc_info=True)
            return []

        if response.status_code != 200:
            logger.warning("Ollama returned status %d", response.status_code)
            return []

        try:
            llm_output = response.json().get("response", "")
            raw_entities = json.loads(llm_output)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Failed to parse LLM output as JSON")
            return []

        if not isinstance(raw_entities, list):
            return []

        entities = []
        for item in raw_entities:
            if not isinstance(item, dict):
                continue
            entity_text = item.get("text", "")
            entity_type = item.get("type", "")
            start = item.get("start")
            end = item.get("end")

            if not entity_text or not entity_type:
                continue

            # Validate span against original text
            if start is not None and end is not None:
                if end > len(text) or start < 0:
                    continue
                if text[start:end] != entity_text:
                    # LLM gave wrong offsets, try to find it
                    idx = text.find(entity_text)
                    if idx == -1:
                        continue
                    start, end = idx, idx + len(entity_text)
            else:
                idx = text.find(entity_text)
                if idx == -1:
                    continue
                start, end = idx, idx + len(entity_text)

            entities.append(
                NEREntity(
                    text=entity_text,
                    type=entity_type,
                    start=start,
                    end=end,
                    confidence=DEFAULT_CONFIDENCE,
                )
            )

        return entities
