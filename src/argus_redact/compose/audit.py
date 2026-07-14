"""compose.audit — compliance-as-artifact (Theme B, v0.7.18).

A caller-owned, append-only, PII-free, hash-chained AuditLedger that is BOTH the
audit trail and the tamper-evident record, plus collect_security_events to gather
the shared security_event schema from any redact/restore detailed result.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Callable

_LEDGER_SCHEMA_VERSION = 1


def collect_security_events(result) -> list[dict]:
    """Extract PII-free security events uniformly. Handles a RedactReport
    (``.security_events``), a redact 3-tuple / restore 2-tuple (trailing details
    dict), or anything else (→ []). Tolerant by design."""
    if hasattr(result, "security_events"):
        return list(result.security_events)
    if isinstance(result, tuple) and result and isinstance(result[-1], dict):
        return list(result[-1].get("security_events", []))
    return []


def _sanitize_event(e: dict) -> dict:
    """PII-free projection of a security_event: keep type/reason_code/count; DROP
    the free-form ``detail`` so the ledger never depends on producer discipline."""
    return {
        "type": e.get("type", "security"),
        "reason_code": e["reason_code"],
        "count": e["count"],
    }


def _canonical_bytes(
    seq, timestamp, kind, type_counts, security_events, content_digest, prev_hash
) -> bytes:
    payload = {
        "seq": seq,
        "timestamp": timestamp,
        "kind": kind,
        "type_counts": type_counts,
        "security_events": security_events,
        "content_digest": content_digest,
        "prev_hash": prev_hash,
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _digest(data: bytes, hmac_key: bytes | None) -> str:
    if hmac_key is not None:
        return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    """One PII-free, hash-chained audit record. Stores counts, detail-stripped
    events, and one-way digests only — never originals or a pseudonym map."""

    seq: int
    timestamp: str
    kind: str
    type_counts: dict[str, int]
    security_events: tuple[dict, ...] = ()
    content_digest: str | None = None
    prev_hash: str = ""
    entry_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "kind": self.kind,
            "type_counts": dict(self.type_counts),
            "security_events": [dict(e) for e in self.security_events],
            "content_digest": self.content_digest,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEntry":
        # Re-sanitize on load: the PII-free invariant is enforced by _sanitize_event
        # on the append() write path, but a stored/hand-crafted dict is untrusted
        # input — a tampered or forged file could carry a free-form `detail` on a
        # security_event. Running it through _sanitize_event again here is a no-op
        # for an honest ledger (append() already sanitized) and strips PII for a
        # dishonest one, so it never enters memory either way.
        return cls(
            seq=d["seq"],
            timestamp=d["timestamp"],
            kind=d["kind"],
            type_counts=dict(d["type_counts"]),
            security_events=tuple(_sanitize_event(e) for e in d.get("security_events", ())),
            content_digest=d.get("content_digest"),
            prev_hash=d.get("prev_hash", ""),
            entry_hash=d.get("entry_hash", ""),
        )


class AuditLedger:
    """Append-only, PII-free, hash-chained audit ledger. One structure = the audit
    trail (#18) AND the tamper-evident record (#26). Keyless SHA-256 chain by
    default (append-only integrity); pass ``hmac_key=`` for forge-resistance.
    Caller-owned (like keys) — no global state, no I/O.

    Honesty caveat: under the keyless default, "tamper-evident" covers accidental
    corruption and interior edits, not a determined adversary — anyone who controls
    the store can recompute a self-consistent chain from scratch. Pass
    ``hmac_key=`` (kept off the store) for forge-resistance against that threat."""

    def __init__(
        self,
        *,
        hmac_key: bytes | None = None,
        clock: Callable[[], str] | None = None,
    ):
        self._entries: list[AuditEntry] = []
        self._hmac_key = hmac_key
        self._clock = clock or (lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    @property
    def head_digest(self) -> str:
        return self._entries[-1].entry_hash if self._entries else ""

    def append(
        self,
        kind: str,
        *,
        type_counts: dict[str, int],
        security_events=(),
        content_digest: str | None = None,
    ) -> AuditEntry:
        seq = len(self._entries)
        timestamp = self._clock()
        prev_hash = self.head_digest
        # One copy of the caller's dict (isolates from later mutation); the freshly
        # built `sanitized` dicts are already isolated. Both are only read from here
        # on, so `_canonical_bytes` receives them directly (no extra copy) and the
        # stored entry reuses the same objects — append and verify hash identically.
        tc = dict(type_counts)
        sanitized = tuple(_sanitize_event(e) for e in security_events)
        entry_hash = _digest(
            _canonical_bytes(seq, timestamp, kind, tc, sanitized, content_digest, prev_hash),
            self._hmac_key,
        )
        entry = AuditEntry(
            seq=seq,
            timestamp=timestamp,
            kind=kind,
            type_counts=tc,
            security_events=sanitized,
            content_digest=content_digest,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Recompute the chain: seq order, prev_hash links, and each entry_hash.
        Returns False on any break (reorder / deletion / modification).

        Detects interior modification / reorder / deletion, but NOT tail-truncation
        (dropping the most-recent entries) on its own — detect that by persisting
        ``head_digest`` externally and comparing after load.

        Under the keyless default, this does NOT detect full-chain forgery: an
        adversary who controls the store can recompute a self-consistent chain
        (correct seq/prev_hash/entry_hash throughout) and ``verify()`` will return
        True on it. Pass ``hmac_key=`` (kept off the store, never persisted by
        ``to_dict``) for forge-resistance against that threat."""
        prev = ""
        for i, e in enumerate(self._entries):
            if e.seq != i or e.prev_hash != prev:
                return False
            # Stored fields are already isolated (frozen entry) and only read here,
            # so they hash directly — the same values `append` serialized.
            expected = _digest(
                _canonical_bytes(
                    e.seq,
                    e.timestamp,
                    e.kind,
                    e.type_counts,
                    e.security_events,
                    e.content_digest,
                    e.prev_hash,
                ),
                self._hmac_key,
            )
            if not hmac.compare_digest(expected, e.entry_hash):
                return False
            prev = e.entry_hash
        return True

    def record_redact(self, detailed_result, *, content_digest: str | None = None) -> AuditEntry:
        """Sugar: append a PII-free 'redact' entry from a redact(detailed=True)
        3-tuple. type_counts counts detections; content_digest defaults to the
        one-way SHA-256 of the redacted text. The key is never touched."""
        redacted = detailed_result[0]
        details = detailed_result[-1]
        counts: dict[str, int] = {}
        for e in details.get("entities", []):
            counts[e["type"]] = counts.get(e["type"], 0) + 1
        if content_digest is None:
            content_digest = hashlib.sha256(redacted.encode("utf-8")).hexdigest()
        return self.append(
            "redact",
            type_counts=counts,
            security_events=collect_security_events(detailed_result),
            content_digest=content_digest,
        )

    def record_restore(self, detailed_result, *, content_digest: str | None = None) -> AuditEntry:
        """Sugar: append a PII-free 'restore' entry from a restore(detailed=True)
        2-tuple. No type_counts (restore detects nothing); content_digest stays
        None by default — the restore output is recovered plaintext, never
        auto-digested (caller may pass one)."""
        return self.append(
            "restore",
            type_counts={},
            security_events=collect_security_events(detailed_result),
            content_digest=content_digest,
        )

    def to_dict(self) -> dict:
        return {
            "schema_version": _LEDGER_SCHEMA_VERSION,
            # Marker only — never the key itself. Lets from_dict fail loudly instead
            # of silently returning verify() == False when the key is forgotten.
            "hmac": self._hmac_key is not None,
            "entries": [e.to_dict() for e in self._entries],
        }

    @classmethod
    def from_dict(cls, d: dict, *, hmac_key: bytes | None = None) -> "AuditLedger":
        version = d.get("schema_version")
        if version != _LEDGER_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported audit ledger schema_version {version!r}; "
                f"this build supports {_LEDGER_SCHEMA_VERSION}"
            )
        if d.get("hmac") and hmac_key is None:
            raise ValueError("this ledger was written with hmac_key=; pass hmac_key= to load it")
        ledger = cls(hmac_key=hmac_key)
        ledger._entries = [AuditEntry.from_dict(e) for e in d.get("entries", [])]
        return ledger
