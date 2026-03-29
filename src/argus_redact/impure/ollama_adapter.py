"""Ollama adapter for Layer 3 semantic PII detection."""

from __future__ import annotations

import json
import logging

import requests

from argus_redact._types import NEREntity
from argus_redact.impure.semantic import SemanticAdapter

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """你是隐私分析专家。分析文本中所有隐含的敏感个人信息。

检测类型（用英文返回 type）：
- medical: 暗示疾病、症状、就医、服药、身体状况
- financial: 暗示收入水平、债务、经济状况、消费能力
- religion: 暗示宗教信仰、宗教活动（周五请假→主麻日；不吃猪肉→伊斯兰饮食禁忌；特定节日→宗教节日）
- political: 暗示政治立场、党派倾向、政治活动
- sexual_orientation: 暗示性取向、亲密关系模式
- criminal: 暗示违法经历、服刑、释放后处境
- biometric: 暗示生物特征数据采集（刷脸、指纹等）
- gender: 通过生理特征推断性别。重要：怀孕/产假/预产期→female；前列腺/精子→male。如果文本同时涉及medical和gender，两个type都要返回
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

DEFAULT_CONFIDENCE = 0.7


class OllamaAdapter(SemanticAdapter):
    """Semantic PII detection via Ollama local LLM."""

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
    ):
        import os

        self._model = model or os.environ.get("OLLAMA_MODEL", "qwen3:8b")
        self._base_url = base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def _call_ollama(self, text: str) -> requests.Response | None:
        """Call Ollama with retry."""
        payload = {
            "model": self._model,
            "prompt": f"文本：{text}",
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {"temperature": 0.0},
        }
        for attempt in range(2):
            try:
                resp = requests.post(
                    f"{self._base_url}/api/generate",
                    json=payload,
                    timeout=30,
                )
                if resp.status_code == 200:
                    return resp
                logger.warning(
                    "Ollama returned status %d (attempt %d)",
                    resp.status_code,
                    attempt + 1,
                )
            except Exception:
                logger.warning(
                    "Ollama request failed (attempt %d)",
                    attempt + 1,
                    exc_info=True,
                )
        return None

    def detect(self, text: str) -> list[NEREntity]:
        if not text:
            return []

        response = self._call_ollama(text)
        if response is None:
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
