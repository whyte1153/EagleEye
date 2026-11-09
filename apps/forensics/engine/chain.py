"""Tamper-evident custody log (pure Python).

Each event stores the hash of the previous event and its own hash:

    event_hash = SHA-256( prev_hash || canonical_json(payload) )

Changing, removing or re-ordering any past event breaks every later hash, so
``verify_chain`` can detect it.  This shows tampering *happened*; it cannot
prevent someone with database access from rewriting the whole chain, so export
reports (and ideally the latest hash) to external storage.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

GENESIS = "0" * 64


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def event_hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + canonical(payload)).hexdigest()


def make_payload(*, evidence_id: str, seq: int, action: str, actor: str, detail: str, ip: str, timestamp: str) -> dict:
    return {"evidence_id": evidence_id, "seq": seq, "action": action, "actor": actor,
            "detail": detail, "ip": ip or "", "timestamp": timestamp}


@dataclass(frozen=True)
class ChainResult:
    ok: bool
    checked: int
    broken_at: int | None = None  # seq of first bad event
    reason: str = ""


def verify_chain(events) -> ChainResult:
    """``events``: iterable of dicts with ``payload``, ``prev_hash`` and ``event_hash``, ordered by seq."""
    prev, expected_seq, count = GENESIS, 1, 0
    for ev in events:
        payload = ev["payload"]
        if payload["seq"] != expected_seq:
            return ChainResult(False, count, payload["seq"], "Missing or re-ordered event (sequence gap).")
        if ev["prev_hash"] != prev:
            return ChainResult(False, count, payload["seq"], "Link to the previous event does not match.")
        if event_hash(prev, payload) != ev["event_hash"]:
            return ChainResult(False, count, payload["seq"], "Event content does not match its recorded hash.")
        prev, expected_seq, count = ev["event_hash"], expected_seq + 1, count + 1
    return ChainResult(True, count)
