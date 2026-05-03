"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact import layers
from argus_redact._types import PseudonymLLMResult, RedactReport
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

__version__ = "0.6.2"
__all__ = [
    "redact",
    "redact_pseudonym_llm",
    "restore",
    "check_restore_safety",
    "wipe_key",
    "assess_risk",
    "is_strategy_reversible",
    "max_pseudonym_length",
    "PseudonymLLMResult",
    "PseudonymPollutionError",
    "RedactReport",
    "SecurityWarning",
    "StreamingRedactor",
    "layers",
    "__version__",
]
