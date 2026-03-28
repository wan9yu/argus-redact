"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact._types import RedactReport
from argus_redact.glue.redact import redact
from argus_redact.pure.restore import restore
from argus_redact.pure.risk import assess_risk

__version__ = "0.1.10"
__all__ = ["redact", "restore", "assess_risk", "RedactReport", "__version__"]
