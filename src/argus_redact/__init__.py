"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact._types import RedactReport
from argus_redact.glue.redact import redact
from argus_redact.pure.pseudonym import max_pseudonym_length
from argus_redact.pure.restore import check_restore_safety, restore, wipe_key
from argus_redact.pure.risk import assess_risk

__version__ = "0.4.13"
__all__ = [
    "redact", "restore", "check_restore_safety", "wipe_key", "assess_risk",
    "max_pseudonym_length",
    "RedactReport",
    "__version__",
]
