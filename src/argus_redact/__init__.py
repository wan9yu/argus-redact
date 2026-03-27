"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact.glue.redact import redact
from argus_redact.pure.restore import restore

__version__ = "0.1.8"
__all__ = ["redact", "restore", "__version__"]
