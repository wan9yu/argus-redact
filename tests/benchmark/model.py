"""Unified data models for benchmark evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Entity:
    """A single PII entity in a text sample."""

    text: str
    type: str  # argus-redact canonical type: phone, email, ssn, person, ...
    start: int | None = None
    end: int | None = None


@dataclass
class Sample:
    """One labeled example: input text + expected PII entities."""

    text: str
    lang: str
    entities: list[Entity]


@dataclass
class TypeMetrics:
    """Per-type TP/FP/FN counters."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


# PII classes for honest recall reporting. argus is strong on STRUCTURED
# identifiers and best-effort on FREE-TEXT entities (which depend on NER), so a
# single blended recall hides that split — especially for English. Single source:
# free-text is the small explicit set; every other type is structured.
FREE_TEXT_TYPES = frozenset({"person", "location", "address", "organization"})


def pii_class(pii_type: str) -> str:
    """'free_text' for NER-dependent entity types, else 'structured'."""
    return "free_text" if pii_type in FREE_TEXT_TYPES else "structured"


@dataclass
class Result:
    """Evaluation result for one benchmark run."""

    dataset: str
    mode: str
    lang: str
    n_samples: int
    tp: int = 0
    fp: int = 0
    fn: int = 0
    per_type: dict[str, TypeMetrics] = field(default_factory=dict)
    elapsed_s: float = 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def docs_per_sec(self) -> float:
        return self.n_samples / self.elapsed_s if self.elapsed_s > 0 else 0.0

    def by_class(self) -> dict[str, TypeMetrics]:
        """Aggregate per-type counters into PII classes (structured / free_text).

        Honest reporting: lets a reader see that (e.g. for English) structured-
        identifier recall is high while free-text-entity recall is low, instead of
        one blended number that hides the split.
        """
        classes: dict[str, TypeMetrics] = {}
        for etype, m in self.per_type.items():
            c = classes.setdefault(pii_class(etype), TypeMetrics())
            c.tp += m.tp
            c.fp += m.fp
            c.fn += m.fn
        return classes

    def to_dict(self) -> dict:
        return {
            "dataset": self.dataset,
            "mode": self.mode,
            "lang": self.lang,
            "n_samples": self.n_samples,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "elapsed_s": round(self.elapsed_s, 2),
            "docs_per_sec": round(self.docs_per_sec, 1),
            "per_type": {
                k: {
                    "tp": v.tp,
                    "fp": v.fp,
                    "fn": v.fn,
                    "precision": round(v.precision, 4),
                    "recall": round(v.recall, 4),
                    "f1": round(v.f1, 4),
                }
                for k, v in sorted(self.per_type.items())
            },
            "by_class": {
                cls: {
                    "tp": v.tp,
                    "fp": v.fp,
                    "fn": v.fn,
                    "precision": round(v.precision, 4),
                    "recall": round(v.recall, 4),
                    "f1": round(v.f1, 4),
                }
                for cls, v in sorted(self.by_class().items())
            },
        }
