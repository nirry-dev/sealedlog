# sealedlog

**A tamper-evident, append-only log.**

Every entry is sealed with a hash over its own contents *and the seal before it*,
so the records form a chain. Change any one of them — its content, its order, or
anything earlier — and every seal from that point stops matching. The head seal
fingerprints the whole log; record it somewhere the writer can't reach, and you
can prove the log wasn't altered up to that point.

```python
from sealedlog import Log

log = Log("audit.jsonl")
log.append({"actor": "svc", "action": "deploy", "ok": True})
log.append({"actor": "ops", "action": "rotate-key"})

log.verify().ok   # True
log.head()        # 'c6ba9c09…'  — publish this to anchor the log
```

No dependencies — just the Python standard library. Python 3.9+.

---

## Why

An audit log is only worth as much as its resistance to editing. A plain file
can be rewritten by anyone who can write to it, and you'd never know. sealedlog
makes edits *evident*: it hashes each record into the next, so the smallest
change breaks the chain and `verify` points straight at the first broken record.
It's the sealed-record idea from [Lype](https://nirry.net/lype) — which publishes
its head after every night so its own history can't be quietly rewritten — pulled
out as one small, readable library.

## Install

```bash
pip install sealedlog
```

Or vendor the `sealedlog/` package — it's pure standard library, no build step.

## Use it

### In Python

```python
from sealedlog import Log

log = Log("audit.jsonl")             # or Log(path, key="secret") for keyed sealing
record = log.append({"event": "x"})  # seals the entry, returns its Record
log.head()                           # the latest seal, or None if empty
log.verify()                         # Verification(ok=..., count=..., head=..., broken_seq=..., reason=...)

for r in log.records():
    r.seq, r.ts, r.seal, r.entry
```

`verify()` is truthy when the chain is intact; when it isn't, `broken_seq` and
`reason` say which record failed and how.

### On the command line

```bash
sealedlog append audit.jsonl --message "deployed v2"
echo '{"actor":"svc","action":"rotate-key"}' | sealedlog append audit.jsonl --stdin
sealedlog verify audit.jsonl      # "OK - N record(s), head …"  (exit 1 if broken)
sealedlog head  audit.jsonl       # the head seal, to anchor elsewhere
sealedlog cat   audit.jsonl       # the records
```

`verify` exits non-zero when the chain is broken, so it drops into a check:
`sealedlog verify audit.jsonl || alert`.

## How it seals

Each record stores `{seq, ts, prev, seal, entry}`, one JSON object per line. The
seal is `SHA-256` over a canonical encoding of `{seq, ts, prev, entry}` — and
`prev` is the previous record's seal, which is what chains them. By default
anyone can recompute and verify; pass a **key** and sealing uses HMAC-SHA256
instead, so no one can forge the chain without the secret.

## What it catches — and what it doesn't

- **Catches** any edit to a record, any reordering, and any insertion or deletion
  in the middle of the log: the seals or the links stop matching, and `verify`
  names the first broken record.
- **Doesn't catch, on its own,** truncation of the *newest* records (a shorter
  chain is still internally consistent) or a wholesale rewrite by someone who can
  recompute every unkeyed seal. The defenses are the two this tool gives you:
  **record the head** somewhere separate (then a rewrite can't reproduce it), or
  **use a key** (then no one can forge a seal at all).

## What it is not

- **Not a logging framework.** It's the integrity layer; point your existing
  logging at it, or append the records you need to prove.
- **Not a blockchain or a timestamp authority.** No consensus, no network, no
  trusted clock — just a local chain you anchor yourself.

## License

MIT. Part of [Nirry Labs](https://nirry.net) — local-first AI and security tools,
dependency-light and auditable by design.
