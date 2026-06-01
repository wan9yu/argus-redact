"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact import layers
from argus_redact._metadata import (
    GDPR_SPECIAL_CATEGORIES,
    HIPAA_PHI_CATEGORIES,
    PIPL_REFERENCES,
)
from argus_redact._types import PseudonymLLMResult, RedactReport
from argus_redact.exceptions import SessionStateError
from argus_redact.glue.redact import redact
from argus_redact.glue.redact_pseudonym_llm import (
    PseudonymPollutionError,
    redact_pseudonym_llm,
)
from argus_redact.pure.pseudonym import max_pseudonym_length
from argus_redact.pure.replacer import SecurityWarning, is_strategy_reversible
from argus_redact.pure.restore import check_restore_safety, restore, wipe_key
from argus_redact.pure.risk import assess_risk
from argus_redact.streaming import StreamingRedactor

__version__ = "0.6.9"
__all__ = [
    # ─── Layer 1 — primitive (frozen at 1.0) ───
    "redact",
    "restore",
    "assess_risk",
    "check_restore_safety",
    "wipe_key",
    "is_strategy_reversible",
    "max_pseudonym_length",
    "SecurityWarning",
    "SessionStateError",
    "PseudonymPollutionError",
    # ─── Layer 2 — compose (best-effort; also at argus_redact.compose.*) ───
    "redact_pseudonym_llm",
    "StreamingRedactor",
    # ─── Compliance metadata SSOT (re-exported from _metadata) ───
    "GDPR_SPECIAL_CATEGORIES",
    "HIPAA_PHI_CATEGORIES",
    "PIPL_REFERENCES",
    # ─── Type aliases ───
    "PseudonymLLMResult",
    "RedactReport",
    # ─── Internal SSOT modules ───
    "layers",
    # ─── Version ───
    "__version__",
]
