"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact._types import PseudonymLLMResult, RedactReport
from argus_redact.glue.redact import redact
from argus_redact.glue.redact_pseudonym_llm import (
    PseudonymPollutionError,
    redact_pseudonym_llm,
)
from argus_redact.pure.pseudonym import max_pseudonym_length
from argus_redact.pure.restore import check_restore_safety, restore, wipe_key
from argus_redact.pure.risk import assess_risk

__version__ = "0.5.0"
__all__ = [
    "redact",
    "redact_pseudonym_llm",
    "restore",
    "check_restore_safety",
    "wipe_key",
    "assess_risk",
    "max_pseudonym_length",
    "PseudonymLLMResult",
    "PseudonymPollutionError",
    "RedactReport",
    "__version__",
]
