#!/usr/bin/env bash
# © Gatemark Systems Limited 2026. All rights reserved. Licensed under the Gatemark Pipesure Check Licence v0.1.
# Byte-for-byte parity gate between action.yml's install step body and scripts/install-pipesure.sh.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION_FILE="${1:-$ROOT_DIR/action.yml}"
SCRIPT_FILE="${2:-$ROOT_DIR/scripts/install-pipesure.sh}"

if [ ! -f "$ACTION_FILE" ]; then
  echo "parity: missing action file: $ACTION_FILE" >&2
  exit 1
fi
if [ ! -f "$SCRIPT_FILE" ]; then
  echo "parity: missing canonical script: $SCRIPT_FILE" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/pipesure-parity.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

python3 -c '
import sys, yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    doc = yaml.safe_load(f)
steps = doc["runs"]["steps"]
install = [s for s in steps if s.get("id") == "install"]
if len(install) != 1:
    sys.exit("expected exactly one step with id: install")
body = install[0]["run"]
if not body.endswith("\n"):
    body += "\n"
with open(sys.argv[2], "w", encoding="utf-8") as out:
    out.write(body)
' "$ACTION_FILE" "$tmp/from-action.sh"

# Strip only the leading shebang and file-header comment block before `set -euo pipefail`.
awk 'found || /^set -euo pipefail$/ { found=1; print }' "$SCRIPT_FILE" > "$tmp/from-script.sh"

if [ ! -s "$tmp/from-script.sh" ]; then
  echo "parity: $SCRIPT_FILE has no install body starting with set -euo pipefail" >&2
  exit 1
fi

if ! diff -u "$tmp/from-script.sh" "$tmp/from-action.sh"; then
  echo "parity: action.yml install step body differs from $SCRIPT_FILE" >&2
  exit 1
fi
