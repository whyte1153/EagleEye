"""Tamper-evident chain of custody.

Every custody event stores the SHA-256 of (previous event's hash + its own
fields).  Editing, deleting or re-ordering any earlier event breaks every hash
after it, and ``verify_chain`` reports where.  (This proves tampering with the
log; it cannot stop a database administrator from rewriting the *entire* chain,
so export or ship the latest hash somewhere outside the database as well.)
"""
from __future__ import annotations

import hashlib

GENESIS = "0" * 64


def compute_entry_hash(prev_hash: str, evidence_id: str, action: str, actor: str, detail: str,
                       created_iso: str, ip: str) -> str:
    material = "\x1f".join([prev_hash, evidence_id, action, actor, detail, created_iso, ip or ""])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify_chain(entries: list[dict]) -> tuple[bool, int | None, str]:
    """``entries`` oldest-first dicts with keys evidence_id, action, actor, detail, created_iso, ip, prev_hash, entry_hash.

    Returns (ok, index_of_first_bad_entry, message).
    """
    prev = GENESIS
    for i, e in enumerate(entries):
        if e["prev_hash"] != prev:
            return False, i, f"Entry {i + 1} does not link to the entry before it (entries removed, inserted or re-ordered)."
        expected = compute_entry_hash(prev, e["evidence_id"], e["action"], e["actor"], e["detail"],
                                      e["created_iso"], e.get("ip", ""))
        if expected != e["entry_hash"]:
            return False, i, f"Entry {i + 1} has been altered (its hash does not match its contents)."
        prev = e["entry_hash"]
    return True, None, f"{len(entries)} entries verified."
