# Contributing to sealedlog

Thanks for taking a look. sealedlog is small on purpose — a hash chain and a file
— and its whole value is that you can read it and trust it.

## Ground rules

- **Standard library only.** No runtime dependencies. Tests use `unittest`.
- **Every change comes with a test.** The sealing and verification are pure
  functions tested directly (`tests/test_chain.py`), and the file behavior —
  including real tamper scenarios — is tested end to end (`tests/test_log.py`).
- **Don't weaken the seal.** The canonical form must stay deterministic, and a
  change that lets a tampered chain verify is a bug, not a feature.
- **Be honest about limits.** sealedlog is tamper-*evident*, not magic; the
  README is clear about tail truncation and head anchoring, and it should stay
  that way.

## Running the tests

```bash
python -m unittest discover -s tests -t .
```

No install needed — the tests import the package from the repo root.

## Scope

In: the chain, the append-only log, keyed sealing, and verification. Out: a
logging framework, networking, consensus, or trusted timestamps. Security reports
go to **info@nirry.net** — see [SECURITY.md](SECURITY.md).
