"""argus-redact: Encrypt PII, not meaning. Locally."""

from argus_redact.glue.redact import redact
from argus_redact.pure.restore import restore

__all__ = ["redact", "restore"]
