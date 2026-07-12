"""Exception types raised by argus-redact.

This module collects shared exception classes:

- SessionStateError — raised by integration adapter classes (LangChain
  RestoreRunnable, LlamaIndex RestoreTransform) when their paired redact
  helper has not yet produced a key, or has been .reset().
- LayerUnavailableError — raised when an explicitly-requested detection layer
  (e.g. ``mode="ner"``) cannot be satisfied.
- SecurityWarning — emitted when a misconfiguration would silently weaken
  redaction. Lives here (rather than ``pure.replacer``, its historical home)
  so ``pure.security_events`` can import it at module level without an
  import cycle; re-exported from ``pure.replacer`` for backward compatibility.

Other exception types remain in their origin modules:
- argus_redact.glue.redact_pseudonym_llm.PseudonymPollutionError
"""

from __future__ import annotations


class SessionStateError(RuntimeError):
    """Raised when an integration helper's session state is missing or inconsistent.

    Typical cause: RestoreRunnable.invoke() / RestoreTransform.__call__()
    called before any RedactRunnable.invoke() / RedactTransform.__call__()
    has produced a key in the paired instance, or after .reset() cleared it.
    """


class LayerUnavailableError(RuntimeError):
    """Raised when an explicitly-requested detection layer cannot be satisfied.

    e.g. ``redact(text, mode="ner")`` when no NER model is installed. Distinct
    from graceful ``mode="auto"`` degradation (which warns + signals status).
    """


class SecurityWarning(UserWarning):
    """Emitted when a misconfiguration would silently weaken redaction."""
