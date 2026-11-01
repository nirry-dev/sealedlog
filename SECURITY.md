# Security Policy

## Reporting a vulnerability

Please report security issues privately to **info@nirry.net** rather than in a
public issue. A chain that verifies after being tampered with is the bug that
matters most — include the records that reproduce it. You'll get an
acknowledgement, and a fix or a clear explanation.

## Threat model

sealedlog makes editing a log **evident**, within clear limits:

- It detects any change to a record, any reordering, and any insertion or
  deletion in the middle of the chain.
- On its own it does **not** detect truncation of the newest records (a shorter
  chain is still consistent), nor a full rewrite by someone who can recompute
  every unkeyed seal. The two defenses are part of the design: **anchor the head**
  somewhere the writer can't reach, and/or seal with a **secret key** (HMAC) so
  the chain can't be forged.
- There is no trusted clock: the timestamp is the writer's own.

## Supported versions

Fixes land on the latest release.
