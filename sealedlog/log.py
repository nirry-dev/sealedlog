"""A sealed, append-only log stored as one JSON record per line (JSONL)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from .chain import GENESIS, Key, Record, Verification, seal_record, verify_records

__all__ = ["Log", "LogError"]


class LogError(ValueError):
    """A log line could not be read as a sealed record."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Log:
    """A tamper-evident append-only log at *path*.

    Pass *key* (a str/bytes secret) to seal with HMAC so the chain can't be
    forged without it; otherwise sealing is plain SHA-256 and anyone can verify
    — record the :meth:`head` somewhere separate to anchor it.
    """

    def __init__(self, path, *, genesis: str = GENESIS, key: Key = None) -> None:
        self.path = path
        self.genesis = genesis
        self.key = key
        self._tail_cache: Optional[tuple] = None  # (next_seq, prev_seal)

    def records(self) -> Iterator[Record]:
        """Yield every record, in order."""
        try:
            handle = open(self.path, encoding="utf-8")
        except FileNotFoundError:
            return
        with handle:
            for lineno, raw in enumerate(handle, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    yield Record(seq=d["seq"], ts=d["ts"], prev=d["prev"], seal=d["seal"], entry=d["entry"])
                except (json.JSONDecodeError, KeyError, TypeError) as err:
                    raise LogError(f"{self.path}:{lineno}: malformed record: {err}") from None

    def _tail(self) -> tuple:
        if self._tail_cache is None:
            seq, prev = 0, self.genesis
            for r in self.records():
                seq, prev = r.seq + 1, r.seal
            self._tail_cache = (seq, prev)
        return self._tail_cache

    def head(self) -> Optional[str]:
        """The latest seal — a fingerprint of the whole log — or ``None`` if empty."""
        seq, prev = self._tail()
        return prev if seq > 0 else None

    def append(self, entry: Any, *, ts: Optional[str] = None) -> Record:
        """Seal *entry* onto the end of the log and return its record."""
        try:
            json.dumps(entry)
        except TypeError as err:
            raise LogError(f"entry is not JSON-serializable: {err}") from None
        seq, prev = self._tail()
        ts = ts or _now()
        seal = seal_record(seq, ts, prev, entry, key=self.key)
        record = Record(seq=seq, ts=ts, prev=prev, seal=seal, entry=entry)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
        self._tail_cache = (seq + 1, seal)
        return record

    def verify(self) -> Verification:
        """Check the whole chain; see :class:`~sealedlog.chain.Verification`."""
        return verify_records(self.records(), genesis=self.genesis, key=self.key)
