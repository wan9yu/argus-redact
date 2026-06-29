"""Presidio bridge — use Presidio detection with argus-redact reversible replacement.

Presidio detects PII entities. argus-redact replaces them with reversible
pseudonyms and per-message keys.

Usage:
    from argus_redact.integrations.presidio import PresidioBridge

    bridge = PresidioBridge()
    redacted, key = bridge.redact("John Smith called 555-123-4567", language="en")
    restored = bridge.restore(llm_output, key)
"""

from __future__ import annotations

from argus_redact._types import NEREntity, PatternMatch
from argus_redact.impure.ner import NERAdapter
from argus_redact.pure.restore import restore

# Map Presidio entity types to argus-redact types
_PRESIDIO_TYPE_MAP = {
    "PERSON": "person",
    "PHONE_NUMBER": "phone",
    "EMAIL_ADDRESS": "email",
    "CREDIT_CARD": "credit_card",
    "US_SSN": "ssn",
    "LOCATION": "location",
    "NRP": "organization",
    "ORGANIZATION": "organization",
    "DATE_TIME": "date",
    "US_DRIVER_LICENSE": "id_number",
    "US_PASSPORT": "passport",
    "IP_ADDRESS": "ip_address",
    "URL": "url",
}


class PresidioBridge:
    """Bridge between Presidio detection and argus-redact reversible replacement.

    Uses Presidio's AnalyzerEngine for entity detection, then applies
    argus-redact's per-message key replacement and restore.
    """

    def __init__(self, analyzer=None):
        """Initialize with an optional custom Presidio AnalyzerEngine."""
        self._analyzer = analyzer

    def _get_analyzer(self):
        if self._analyzer is None:
            from presidio_analyzer import AnalyzerEngine

            self._analyzer = AnalyzerEngine()
        return self._analyzer

    def redact(
        self,
        text: str,
        *,
        language: str = "en",
        salt: int | bytes | None = None,
        key: dict | None = None,
        config: dict | None = None,
    ) -> tuple[str, dict]:
        """Detect PII with Presidio, replace with argus-redact.

        Routes through public argus_redact.redact() via the _pre_detected
        private kwarg, inheriting:
        - MAX_INPUT_SIZE guard
        - isinstance(text, str) check
        - Profile resolution
        - English grammar normalization
        - types / types_exclude filter
        - Telemetry emission
        - Key file persistence

        Returns (redacted_text, key) — same interface as argus_redact.redact().
        """
        # Mirror argus_redact.redact() guards so they fire before Presidio analysis
        if not isinstance(text, str):
            raise TypeError(f"text must be a string, got {type(text).__name__}")

        from argus_redact.pure.normalize import MAX_INPUT_SIZE

        if len(text) > MAX_INPUT_SIZE:
            raise ValueError(
                f"Input text ({len(text)} chars) exceeds maximum allowed size "
                f"({MAX_INPUT_SIZE} chars). Split into smaller chunks."
            )

        analyzer = self._get_analyzer()
        results = analyzer.analyze(text=text, language=language)

        if not results:
            return text, key if key is not None else {}

        entities = []
        for r in results:
            mapped_type = _PRESIDIO_TYPE_MAP.get(r.entity_type, r.entity_type.lower())
            entities.append(
                PatternMatch(
                    text=text[r.start : r.end],
                    type=mapped_type,
                    start=r.start,
                    end=r.end,
                    confidence=r.score,
                )
            )

        # Route through public redact() — inherits all pipeline guarantees
        import argus_redact

        redacted, result_key = argus_redact.redact(
            text,
            lang=language,
            salt=salt,
            config=config,
            key=key,
            _pre_detected=entities,
        )
        return redacted, result_key

    def restore(self, text: str, key: dict) -> str:
        """Restore pseudonyms to originals. Same as argus_redact.restore()."""
        return restore(text, key)


class PresidioNERAdapter(NERAdapter):
    """Use Presidio's AnalyzerEngine as an argus-redact NER adapter.

    Plug Presidio's 46+ entity types into argus-redact's pipeline:

        from argus_redact.integrations.presidio import PresidioNERAdapter
        from argus_redact import redact

        adapter = PresidioNERAdapter()
        # Use with detect_ner() or patch into redact() pipeline
    """

    def __init__(self, analyzer=None, language: str = "en"):
        self._analyzer = analyzer
        self._language = language

    def load(self) -> None:
        if self._analyzer is None:
            from presidio_analyzer import AnalyzerEngine

            self._analyzer = AnalyzerEngine()

    def detect(self, text: str) -> list[NEREntity]:
        if not text:
            return []
        if self._analyzer is None:
            self.load()

        results = self._analyzer.analyze(text=text, language=self._language)
        entities = []
        for r in results:
            mapped_type = _PRESIDIO_TYPE_MAP.get(r.entity_type, r.entity_type.lower())
            entities.append(
                NEREntity(
                    text=text[r.start : r.end],
                    type=mapped_type,
                    start=r.start,
                    end=r.end,
                    confidence=r.score,
                )
            )
        return entities
