"""sealedlog — a tamper-evident, append-only log.

Every entry is sealed with a hash over its contents and the seal before it, so
the records form a chain: alter any one — its content, its order, or anything
earlier — and the seals stop matching from there on. The head seal fingerprints
the whole log; record it somewhere separate and you can prove nothing was changed.

    >>> from sealedlog import Log
    >>> log = Log("audit.jsonl")
    >>> log.append({"actor": "svc", "action": "deploy", "ok": True})   # doctest: +SKIP
    >>> log.verify().ok                                                # doctest: +SKIP
    True

Pure standard library. SHA-256 by default, or keyed HMAC-SHA256 with a secret.
"""

from .chain import GENESIS, Record, Verification, canonical, seal_record, verify_records
from .log import Log, LogError

__version__ = "0.1.0"

__all__ = [
    "Log",
    "LogError",
    "Record",
    "Verification",
    "verify_records",
    "seal_record",
    "canonical",
    "GENESIS",
    "__version__",
]
