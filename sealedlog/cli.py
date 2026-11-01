"""Command line: append to, verify, and read a sealed log.

    sealedlog append audit.jsonl --message "deployed v2"
    echo '{"actor":"svc","action":"rotate-key"}' | sealedlog append audit.jsonl --stdin
    sealedlog verify audit.jsonl
    sealedlog head audit.jsonl

Exit status: `verify` returns 0 if the chain is intact and 1 if it's broken;
other commands return 0 on success and 2 for a bad call or an unreadable log.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .chain import canonical
from .log import Log, LogError


def _key(args):
    if getattr(args, "key_file", None):
        with open(args.key_file, "rb") as f:
            return f.read().strip()
    return None


def _cmd_append(args) -> int:
    sources = [args.message is not None, args.entry is not None, args.stdin]
    if sum(sources) != 1:
        print("sealedlog: give exactly one of --message, --entry, or --stdin", file=sys.stderr)
        return 2
    if args.message is not None:
        entry = {"message": args.message}
    else:
        text = sys.stdin.read() if args.stdin else args.entry
        try:
            entry = json.loads(text)
        except json.JSONDecodeError as err:
            print(f"sealedlog: entry is not valid JSON: {err}", file=sys.stderr)
            return 2
    try:
        record = Log(args.path, key=_key(args)).append(entry)
    except (OSError, LogError) as err:
        print(f"sealedlog: {err}", file=sys.stderr)
        return 2
    print(record.seal)
    return 0


def _cmd_verify(args) -> int:
    log = Log(args.path, key=_key(args))
    try:
        result = log.verify()
    except (OSError, LogError) as err:
        if args.json:
            print(json.dumps({"ok": False, "reason": str(err)}))
        else:
            print(f"sealedlog: BROKEN — {err}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"ok": result.ok, "count": result.count, "head": result.head, "broken_seq": result.broken_seq, "reason": result.reason}))
    elif result.ok:
        print(f"OK - {result.count} record(s), head {result.head or '(empty)'}")
    else:
        print(f"sealedlog: BROKEN at seq {result.broken_seq}: {result.reason} ({result.count} record(s) verified)", file=sys.stderr)
    return 0 if result.ok else 1


def _cmd_head(args) -> int:
    try:
        head = Log(args.path, key=_key(args)).head()
    except (OSError, LogError) as err:
        print(f"sealedlog: {err}", file=sys.stderr)
        return 2
    if head is None:
        print("(empty log)", file=sys.stderr)
        return 0
    print(head)
    return 0


def _cmd_cat(args) -> int:
    log = Log(args.path)
    try:
        for r in log.records():
            if args.json:
                print(json.dumps(r.to_dict(), ensure_ascii=False))
            else:
                print(f"{r.seq}\t{r.ts}\t{r.seal}\t{canonical(r.entry)}")
    except (OSError, LogError) as err:
        print(f"sealedlog: {err}", file=sys.stderr)
        return 2
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sealedlog", description="A tamper-evident, append-only log.")
    p.add_argument("-V", "--version", action="version", version=f"sealedlog {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    ap = sub.add_parser("append", help="seal an entry onto the log")
    ap.add_argument("path")
    ap.add_argument("--message", metavar="TEXT", help="append {\"message\": TEXT}")
    ap.add_argument("--entry", metavar="JSON", help="append this JSON value")
    ap.add_argument("--stdin", action="store_true", help="append JSON read from stdin")
    ap.add_argument("--key-file", metavar="FILE", help="HMAC key file (keyed sealing)")
    ap.set_defaults(func=_cmd_append)

    vp = sub.add_parser("verify", help="check the chain is intact")
    vp.add_argument("path")
    vp.add_argument("--json", action="store_true")
    vp.add_argument("--key-file", metavar="FILE", help="HMAC key file (must match)")
    vp.set_defaults(func=_cmd_verify)

    hp = sub.add_parser("head", help="print the head seal")
    hp.add_argument("path")
    hp.add_argument("--key-file", metavar="FILE")
    hp.set_defaults(func=_cmd_head)

    cp = sub.add_parser("cat", help="print the records")
    cp.add_argument("path")
    cp.add_argument("--json", action="store_true")
    cp.set_defaults(func=_cmd_cat)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
