"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact._types import RedactReport
from argus_redact.glue.redact import redact
from argus_redact.pure.restore import check_restore_safety, restore, wipe_key
from argus_redact.pure.risk import assess_risk

__version__ = "0.4.10"
__all__ = [
    "redact", "restore", "check_restore_safety", "wipe_key", "assess_risk",
    "RedactReport",
    "__version__",
]
