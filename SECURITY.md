# Security policy

© Gatemark Systems Limited 2026

Report a suspected vulnerability in Pipesure Check or this Action privately to Gatemark Systems Limited through this repository's private vulnerability reporting ("Report a vulnerability" on the Security tab). Do not open a public issue.

We acknowledge a report within two working days.

## What this Action trusts

- The shop's Ed25519 key pinned in `action.yml` (`PIPESURE_PUBLIC_KEY`), published at `https://shop.gatemark.net/.well-known/pipesure-licence-key.json`. Every download's manifest must verify against it, and the file's SHA-256 must match the manifest, before the file is run. A download is never piped into a shell.
- TLS to `shop.gatemark.net`; a plain-http address is refused.
- Your licence, sent only as a request header (never on a command line) and read by the binary from the environment; only its decoded non-secret claims (owner and expiry) appear in the report, never the bearer licence token itself.

The binary itself is read-only: it reads the checkout and the saved API answers and makes no network call of its own.
