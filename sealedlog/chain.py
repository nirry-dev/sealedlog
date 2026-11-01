"""The hash chain: how an entry is sealed, and how a chain is verified.

Each record carries the seal of the one before it, and its own seal is a hash
over its contents *including* that previous seal. So the seals form a chain:
change any record — its content, its order, or a record before it — and every
seal from there on stops matching. The head seal is a fingerprint of the whole
log; record it somewhere the writer can't reach and the chain proves nothing was
altered up to that point.

Sealing is SHA-256 by default (anyone can verify; anchor the head externally),
or keyed HMAC-SHA256 when a secret key is given (nobody can forge without it).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Union

__all__ = ["GENESIS", "canonical", "seal_record", "Record", "Verification", "verify_records"]

GENESIS = "sealedlog:genesis:v1"

Key = Union[str, bytes, None]


def canonical(obj: Any) -> str:
    """A deterministic JSON string: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _key_bytes(key: Key) -> Optional[bytes]:
    if key is None:
        return None
    return key.encode("utf-8") if isinstance(key, str) else key


def seal_record(seq: int, ts: str, prev: str, entry: Any, *, key: Key = None) -> str:
    """The seal for one record: a hash over its fields and the previous seal."""
    preimage = canonical({"seq": seq, "ts": ts, "prev": prev, "entry": entry}).encode("utf-8")
    kb = _key_bytes(key)
    if kb is not None:
        return hmac.new(kb, preimage, hashlib.sha256).hexdigest()
    return hashlib.sha256(preimage).hexdigest()


@dataclass(frozen=True)
class Record:
    seq: int
    ts: str
    prev: str
    seal: str
    entry: Any

    def to_dict(self) -> dict:
        return {"seq": self.seq, "ts": self.ts, "prev": self.prev, "seal": self.seal, "entry": self.entry}


@dataclass(frozen=True)
class Verification:
    """The result of checking a chain. Truthy when intact."""

    ok: bool
    count: int
    head: Optional[str]
    broken_seq: Optional[int] = None
    reason: Optional[str] = None

    def __bool__(self) -> bool:
        return self.ok


def verify_records(records: Iterable[Record], *, genesis: str = GENESIS, key: Key = None) -> Verification:
    """Walk a chain and confirm every seal and link. Stops at the first break."""
    prev = genesis
    expected = 0
    count = 0
    head: Optional[str] = None
    for r in records:
        if r.seq != expected:
            return Verification(False, count, head, r.seq, f"out of sequence (expected {expected}, got {r.seq})")
        if r.prev != prev:
            return Verification(False, count, head, r.seq, "broken link (prev does not match the previous seal)")
        if seal_record(r.seq, r.ts, r.prev, r.entry, key=key) != r.seal:
            return Verification(False, count, head, r.seq, "tampered (seal does not match the record's contents)")
        prev = r.seal
        head = r.seal
        expected += 1
        count += 1
    return Verification(True, count, head)
