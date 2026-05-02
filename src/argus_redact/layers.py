"""Layer naming SSOT — single source of truth for the detection pipeline.

Downstream consumers (Gateway concepts, Whitepaper, Landing) import from this
module rather than coining their own L1/L1b/L2/L3 terminology. Centralizing the
names here eliminates documentation drift across repos.

PatternMatch.layer is an integer field; L1b is a sub-stage of L1 (evidence
scoring on regex candidates) and its candidates flow through with layer=1.
The string sentinel ``LAYER_REGEX_EVIDENCE = "1b"`` exists so docs and the
LAYER_NAMES mapping can refer to L1b without inventing a fractional layer
index.
"""

from __future__ import annotations

from typing import Final

LAYER_REGEX: Final[int] = 1
LAYER_NER: Final[int] = 2
LAYER_SEMANTIC: Final[int] = 3

LAYER_REGEX_EVIDENCE: Final[str] = "1b"

LAYER_NAMES: Final[dict[int | str, str]] = {
    LAYER_REGEX: "L1: regex pattern matching with prefix/suffix context",
    LAYER_REGEX_EVIDENCE: (
        "L1b: evidence scoring on regex candidates (PII proximity, honorifics, kinship)"
    ),
    LAYER_NER: "L2: NER model (HanLP / spaCy) for open-vocabulary entities",
    LAYER_SEMANTIC: "L3: semantic LLM judgment (Ollama-backed)",
}
