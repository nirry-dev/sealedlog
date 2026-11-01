# Changelog

All notable changes to sealedlog are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-11-01

First release.

### Added
- `Log(path)` — a tamper-evident, append-only log stored as JSONL: `.append(entry)`
  seals an entry into the chain, `.verify()` walks the chain and reports the first
  break (`broken_seq`, `reason`), `.head()` returns the latest seal, `.records()`
  reads them back. Pass `key=` for keyed HMAC-SHA256 sealing instead of SHA-256.
- The pure core: `seal_record`, `canonical`, and `verify_records` with a
  `Verification` result — testable without touching a file.
- A `sealedlog` command-line tool: `append` (`--message` / `--entry` / `--stdin`,
  `--key-file`), `verify` (`--json`, non-zero exit when broken), `head`, and
  `cat`. Also runnable as `python -m sealedlog`.
- Pure standard library.
