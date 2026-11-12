#!/usr/bin/env bash
# © Gatemark Systems Limited 2026. All rights reserved. Licensed under the Gatemark Pipesure Check Licence v0.1.
# Canonical install step body for gatemark/pipesure-check-action (synced at release with
# scripts/install-pipesure.sh in pipesure-check; scripts/check-parity.sh verifies action.yml embeds it verbatim).
# Inputs, all from the environment:
#   PIPESURE_LICENCE     the licence (ps1.…) from the shop; required, sent as a bearer header, never on a command line
#   PIPESURE_SHOP        https://shop.gatemark.net
#   PIPESURE_VERSION     the release to install, v0.4.0
#   PIPESURE_PUBLIC_KEY  the shop's Ed25519 public key (43 base64url characters) that signs the manifest
#   PIPESURE_TMP         a scratch folder (RUNNER_TEMP or Agent.TempDirectory)
# Outputs: PIPESURE (the binary) and PIPESURE_DOWNLOAD (the download id) are written to
# $GITHUB_ENV (and download to $GITHUB_OUTPUT) when set, else printed as ADO logging commands.

set -euo pipefail
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) target=x86_64-unknown-linux-musl ;;
  Linux-aarch64|Linux-arm64) target=aarch64-unknown-linux-musl ;;
  Darwin-arm64) target=aarch64-apple-darwin ;;
  *) echo "pipesure: no binary for $(uname -s) $(uname -m) (Linux x86_64 or arm64, macOS arm64; Windows x64 uses the PowerShell step)" >&2; exit 2 ;;
esac
if [ -z "${PIPESURE_LICENCE:-}" ]; then
  echo "pipesure: a licence is required: buy credits at $PIPESURE_SHOP, redeem them for a licence (POST /v1/redeem), store it as the secret PIPESURE_LICENCE and pass it to this step" >&2
  exit 2
fi
valid_licence() { local LC_ALL=C; case "$1" in ""|*[!A-Za-z0-9._-]*) return 1 ;; esac; }
if ! valid_licence "$PIPESURE_LICENCE"; then
  echo "pipesure: the licence contains invalid characters (expected only A-Za-z0-9._-)" >&2
  exit 2
fi
if [ "$PIPESURE_PUBLIC_KEY" = unpinned ] || [ "${#PIPESURE_PUBLIC_KEY}" -ne 43 ]; then
  echo "pipesure: no key is pinned in this version of the install step, so a download cannot be verified; use a released version" >&2
  exit 2
fi
case "$PIPESURE_SHOP" in https://*) ;; *) echo "pipesure: the shop address must be https" >&2; exit 2 ;; esac
no_ctl() { local LC_ALL=C; case "$1" in *[[:cntrl:]]*) return 1 ;; esac; }
if [ -z "${PIPESURE_TMP:-}" ] || ! no_ctl "$PIPESURE_TMP"; then
  echo "pipesure: PIPESURE_TMP must be non-empty and must not contain control characters" >&2
  exit 2
fi
tmp="$PIPESURE_TMP/pipesure-dl"
mkdir -p "$tmp"
bin="$tmp/pipesure"
rm -f "$bin"
# The licence reaches curl through its configuration on stdin: it is never an argument.
code="$(printf 'header = "Authorization: Bearer %s"\n' "$PIPESURE_LICENCE" | curl --silent --show-error --max-time 120 --config - --dump-header "$tmp/headers.txt" --output "$bin" --write-out '%{http_code}' "$PIPESURE_SHOP/v1/dl/pipesure-check/$PIPESURE_VERSION/$target")"
if [ "$code" = 000 ] || [ ! -f "$bin" ]; then
  echo "pipesure: could not reach the shop at $PIPESURE_SHOP (curl exit above)" >&2
  exit 2
fi
if [ "$code" != 200 ]; then
  echo "pipesure: the shop refused the download (HTTP $code): $(tr -d '\r\n' < "$bin" | head -c 400)" >&2
  exit 2
fi
header() { { tr -d '\r' < "$tmp/headers.txt" | grep -i "^$1:" || true; } | tail -n 1 | sed 's/^[^:]*:[[:space:]]*//'; }
m64="$(header X-Pipesure-Manifest)"
sig="$(header X-Pipesure-Manifest-Sig)"
if [ -z "$m64" ] || [ -z "$sig" ]; then echo "pipesure: the shop sent no signed manifest" >&2; exit 2; fi
b64url() { local s="${1//-/+}"; s="${s//_//}"; case $(( ${#s} % 4 )) in 2) s="$s==" ;; 3) s="$s=" ;; esac; printf '%s' "$s" | base64 -d; }
# The pinned raw key as a DER SubjectPublicKeyInfo: the fixed Ed25519 prefix, then the 32 bytes.
{ printf '\060\052\060\005\006\003\053\145\160\003\041\000'; b64url "$PIPESURE_PUBLIC_KEY"; } > "$tmp/key.der"
openssl pkey -pubin -inform DER -in "$tmp/key.der" -out "$tmp/key.pem"
b64url "$sig" > "$tmp/manifest.sig"
printf 'psm1.%s' "$m64" > "$tmp/manifest.msg"
# openssl's own errors (no Ed25519 or -rawin support: LibreSSL on macOS, an old build) are shown as
# such, apart from a signature that does not verify.
if ! verdict="$(openssl pkeyutl -verify -pubin -inkey "$tmp/key.pem" -rawin -in "$tmp/manifest.msg" -sigfile "$tmp/manifest.sig" 2>"$tmp/openssl.err")"; then
  if [ -s "$tmp/openssl.err" ] && ! grep -qi "verification failure" "$tmp/openssl.err"; then
    echo "pipesure: openssl could not verify the manifest (OpenSSL 1.1.1 or later with Ed25519 is needed; on macOS use Homebrew's openssl@3): $(tr -d '\n' < "$tmp/openssl.err" | head -c 300)" >&2
    exit 2
  fi
  echo "pipesure: the manifest signature does not verify against the pinned key; the file is not run" >&2
  exit 1
fi
case "$verdict" in *"Verified Successfully"*) ;; *) echo "pipesure: openssl gave no verdict on the manifest signature; the file is not run" >&2; exit 1 ;; esac
b64url "$m64" > "$tmp/manifest.json"
if ! python3 -c '
import json, sys
def no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key: " + k)
        d[k] = v
    return d
with open(sys.argv[1], "r", encoding="utf-8") as f:
    obj = json.load(f, object_pairs_hook=no_dups)
if not isinstance(obj, dict):
    raise ValueError("manifest must be a JSON object")
out = []
for k in ("sha256", "version", "target"):
    v = obj.get(k)
    if not isinstance(v, str):
        raise ValueError("missing string field: " + k)
    out.append(v)
dl = obj.get("download", "")
if dl is None:
    dl = ""
if not isinstance(dl, str):
    raise ValueError("download must be a string")
out.append(dl)
for v in out:
    if "\n" in v or "\r" in v or "\x00" in v:
        raise ValueError("control character in manifest field")
with open(sys.argv[2], "w", encoding="utf-8") as out_f:
    out_f.write("\n".join(out) + "\n")
' "$tmp/manifest.json" "$tmp/manifest.fields" 2>/dev/null; then
  echo "pipesure: the signed manifest is not valid JSON; the file is not run" >&2
  exit 1
fi
{
  IFS= read -r sha
  IFS= read -r version
  IFS= read -r mtarget
  IFS= read -r download
} < "$tmp/manifest.fields"
if [ "$version" != "$PIPESURE_VERSION" ] || [ "$mtarget" != "$target" ]; then
  echo "pipesure: the manifest is for $version $mtarget, not $PIPESURE_VERSION $target; the file is not run" >&2
  exit 1
fi
case "$sha" in *[!0-9a-f]*|"") echo "pipesure: the manifest carries no digest" >&2; exit 1 ;; esac
if command -v sha256sum >/dev/null; then
  echo "$sha  $bin" | sha256sum --check --strict --quiet
else
  actual="$(shasum -a 256 "$bin" | cut -d ' ' -f 1)"
  if [ "$actual" != "$sha" ]; then echo "pipesure: the file does not match the manifest's SHA-256" >&2; exit 1; fi
fi
case "$download" in *[!A-Za-z0-9_-]*|"") download=unknown ;; esac
chmod +x "$bin"
echo "pipesure: installed $PIPESURE_VERSION for $target, download $download (verified against the signed manifest)"
if [ -n "${GITHUB_ENV:-}" ]; then
  eof="PIPESURE_EOF_$(openssl rand -hex 12)"
  {
    printf 'PIPESURE<<%s\n%s\n%s\n' "$eof" "$bin" "$eof"
    printf 'PIPESURE_DOWNLOAD<<%s\n%s\n%s\n' "$eof" "$download" "$eof"
  } >> "$GITHUB_ENV"
else
  echo "##vso[task.setvariable variable=PIPESURE]$bin"
  echo "##vso[task.setvariable variable=PIPESURE_DOWNLOAD]$download"
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  eof="PIPESURE_EOF_$(openssl rand -hex 12)"
  printf 'download<<%s\n%s\n%s\n' "$eof" "$download" "$eof" >> "$GITHUB_OUTPUT"
fi
