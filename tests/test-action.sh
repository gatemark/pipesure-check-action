#!/usr/bin/env bash
# © Gatemark Systems Limited 2026. All rights reserved. Licensed under the Gatemark Pipesure Check Licence v0.1.
# Automated test harness for pipesure-check-action: local TLS mock shop, Ed25519 manifest signing,
# composite step execution, and parity drift detection.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pipesure-action-test.XXXXXX")"
SERVER_PIDS=()

cleanup() {
  local pid
  for pid in "${SERVER_PIDS[@]:-}"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

PASS=0
FAIL=0

pass() {
  PASS=$((PASS + 1))
  printf 'PASS: %s\n' "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  printf 'FAIL: %s\n' "$1" >&2
}

assert_eq() {
  local got="$1" want="$2" msg="$3"
  if [ "$got" = "$want" ]; then
    pass "$msg"
  else
    fail "$msg (got '$got', want '$want')"
  fi
}

# Extract the three composite step scripts from action.yml.
python3 -c '
import os, sys, yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    doc = yaml.safe_load(f)
out_dir = sys.argv[2]
for idx, step in enumerate(doc["runs"]["steps"]):
    p = os.path.join(out_dir, f"step-{idx}.sh")
    with open(p, "w", encoding="utf-8") as out:
        out.write("#!/usr/bin/env bash\n")
        out.write(step["run"])
        if not step["run"].endswith("\n"):
            out.write("\n")
    os.chmod(p, 0o700)
' "$ROOT_DIR/action.yml" "$WORK"

# Determine current host target matching action.yml.
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) HOST_TARGET=x86_64-unknown-linux-musl ;;
  Linux-aarch64|Linux-arm64) HOST_TARGET=aarch64-unknown-linux-musl ;;
  Darwin-arm64) HOST_TARGET=aarch64-apple-darwin ;;
  *) echo "unsupported test host $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

# Generate ephemeral Ed25519 signing keypair (and a second wrong keypair) + localhost TLS cert.
KEYS_DIR="$WORK/keys"
mkdir -p "$KEYS_DIR"
openssl genpkey -algorithm Ed25519 -out "$KEYS_DIR/shop.key.pem" >/dev/null 2>&1
openssl genpkey -algorithm Ed25519 -out "$KEYS_DIR/wrong.key.pem" >/dev/null 2>&1

SHOP_PUB_B64URL="$(python3 -c '
import base64, subprocess, sys
der = subprocess.check_output(["openssl", "pkey", "-in", sys.argv[1], "-pubout", "-outform", "DER"])
assert len(der) == 44 and der[:12] == b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"
print(base64.urlsafe_b64encode(der[12:]).decode("ascii").rstrip("="))
' "$KEYS_DIR/shop.key.pem")"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEYS_DIR/tls.key.pem" \
  -out "$KEYS_DIR/tls.cert.pem" \
  -days 1 \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1

# Create a benign mock pipesure payload script that records execution to $PIPESURE_EXEC_MARKER.
PAYLOAD_BIN="$WORK/mock-pipesure-bin"
cat > "$PAYLOAD_BIN" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ -n "${PIPESURE_EXEC_MARKER:-}" ]; then
  printf 'ran:%s\n' "$*" >> "$PIPESURE_EXEC_MARKER"
fi
cmd="${1:-}"
case "$cmd" in
  default-branch)
    file="${2:-}"
    [ -f "$file" ] || exit 1
    python3 -c '
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    d = json.load(f)
if "message" in d or "default_branch" not in d:
    sys.exit(1)
print(d["default_branch"])
' "$file"
    ;;
  check)
    shift
    out=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --out) out="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    mkdir -p "$out"
    status="Held"
    reason="all controls held"
    if [ ! -f "$out/api/repo.json" ]; then
      status="Blocked"
      if [ -f "$out/api/repo.json.error" ]; then
        reason="$(tr -d '\r\n' < "$out/api/repo.json.error")"
      else
        reason="repository answer: no API answer was saved"
      fi
    fi
    python3 -c '
import json, os, sys
out, status, reason = sys.argv[1], sys.argv[2], sys.argv[3]
licence_claim = "Licensed to Example Org until 2026-12-31"
report = {"verdict": status, "reason": reason, "licence": licence_claim}
with open(os.path.join(out, "report.json"), "w", encoding="utf-8") as f:
    json.dump(report, f)
with open(os.path.join(out, "report.html"), "w", encoding="utf-8") as f:
    f.write(f"<html><body>{status}: {reason} ({licence_claim})</body></html>\n")
with open(os.path.join(out, "report.sarif"), "w", encoding="utf-8") as f:
    json.dump({"version": "2.1.0", "runs": [{"properties": {"licence": licence_claim}}]}, f)
with open(os.path.join(out, "summary.md"), "w", encoding="utf-8") as f:
    f.write(f"# Pipesure Check\n\n- Verdict: {status}\n- {licence_claim}\n")
' "$out" "$status" "$reason"
    ;;
  *)
    exit 2
    ;;
esac
EOF
chmod +x "$PAYLOAD_BIN"
PAYLOAD_SHA="$(sha256sum "$PAYLOAD_BIN" | cut -d ' ' -f 1)"

sign_manifest() {
  local manifest_json="$1" key_pem="$2"
  python3 -c '
import base64, subprocess, sys, tempfile
m_bytes = sys.argv[1].encode("utf-8")
key_pem = sys.argv[2]
m64 = base64.urlsafe_b64encode(m_bytes).decode("ascii").rstrip("=")
msg = ("psm1." + m64).encode("ascii")
with tempfile.NamedTemporaryFile() as mf, tempfile.NamedTemporaryFile() as sf:
    mf.write(msg)
    mf.flush()
    subprocess.check_call([
        "openssl", "pkeyutl", "-sign", "-inkey", key_pem,
        "-rawin", "-in", mf.name, "-out", sf.name
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sig = sf.read()
sig64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
print(m64)
print(sig64)
' "$manifest_json" "$key_pem"
}

start_server() {
  local routes_file="$1" tls="${2:-no}"
  local srv_dir
  srv_dir="$(mktemp -d "$WORK/srv.XXXXXX")"
  local port_file="$srv_dir/port"
  local log_file="$srv_dir/requests.jsonl"
  : > "$log_file"
  if [ "$tls" = "tls" ]; then
    python3 "$ROOT_DIR/tests/mock_servers.py" \
      --routes "$routes_file" \
      --port-file "$port_file" \
      --log-file "$log_file" \
      --tls-cert "$KEYS_DIR/tls.cert.pem" \
      --tls-key "$KEYS_DIR/tls.key.pem" &
  else
    python3 "$ROOT_DIR/tests/mock_servers.py" \
      --routes "$routes_file" \
      --port-file "$port_file" \
      --log-file "$log_file" &
  fi
  local pid=$!
  SERVER_PIDS+=("$pid")
  local tries=0
  while [ ! -s "$port_file" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "mock server exited before writing port" >&2
      exit 1
    fi
    tries=$((tries + 1))
    if [ "$tries" -ge 100 ]; then
      echo "timed out waiting for mock server port" >&2
      exit 1
    fi
    sleep 0.05
  done
  STARTED_PORT="$(tr -d '\r\n' < "$port_file")"
  STARTED_LOG="$log_file"
}

load_github_env() {
  local env_file="$1"
  python3 -c '
import shlex, sys
lines = open(sys.argv[1], "r", encoding="utf-8").read().splitlines()
i = 0
while i < len(lines):
    line = lines[i]
    if "<<" in line:
        k, delim = line.split("<<", 1)
        i += 1
        vals = []
        while i < len(lines) and lines[i] != delim:
            vals.append(lines[i])
            i += 1
        val = "\n".join(vals)
        print(f"export {k}={shlex.quote(val)}")
    elif "=" in line:
        k, val = line.split("=", 1)
        print(f"export {k}={shlex.quote(val)}")
    i += 1
' "$env_file"
}

# Build routes for the TLS mock shop covering valid and tampered paths.
VALID_MANIFEST="{\"sha256\":\"$PAYLOAD_SHA\",\"version\":\"v0.4.0\",\"target\":\"$HOST_TARGET\",\"download\":\"dl_test001\"}"
{
  IFS= read -r VALID_M64
  IFS= read -r VALID_SIG
} < <(sign_manifest "$VALID_MANIFEST" "$KEYS_DIR/shop.key.pem")

{
  IFS= read -r WRONG_KEY_M64
  IFS= read -r WRONG_KEY_SIG
} < <(sign_manifest "$VALID_MANIFEST" "$KEYS_DIR/wrong.key.pem")

WRONG_SHA_MANIFEST="{\"sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"version\":\"v0.4.0\",\"target\":\"$HOST_TARGET\",\"download\":\"dl_badsha\"}"
{
  IFS= read -r WRONG_SHA_M64
  IFS= read -r WRONG_SHA_SIG
} < <(sign_manifest "$WRONG_SHA_MANIFEST" "$KEYS_DIR/shop.key.pem")

WRONG_VER_MANIFEST="{\"sha256\":\"$PAYLOAD_SHA\",\"version\":\"v0.3.9\",\"target\":\"$HOST_TARGET\",\"download\":\"dl_badver\"}"
{
  IFS= read -r WRONG_VER_M64
  IFS= read -r WRONG_VER_SIG
} < <(sign_manifest "$WRONG_VER_MANIFEST" "$KEYS_DIR/shop.key.pem")

WRONG_TGT_MANIFEST="{\"sha256\":\"$PAYLOAD_SHA\",\"version\":\"v0.4.0\",\"target\":\"sparc64-unknown-linux-gnu\",\"download\":\"dl_badtgt\"}"
{
  IFS= read -r WRONG_TGT_M64
  IFS= read -r WRONG_TGT_SIG
} < <(sign_manifest "$WRONG_TGT_MANIFEST" "$KEYS_DIR/shop.key.pem")

SHOP_ROUTES="$WORK/shop-routes.json"
python3 -c '
import json, sys
p_bin, t = sys.argv[1], sys.argv[2]
(vm, vs, wm, ws, sm, ss, verm, vers, tm, ts) = sys.argv[3:13]
routes = {
    f"/ok/v1/dl/pipesure-check/v0.4.0/{t}": {
        "status": 200, "body_file": p_bin,
        "headers": {"X-Pipesure-Manifest": vm, "X-Pipesure-Manifest-Sig": vs}
    },
    f"/bad-sig/v1/dl/pipesure-check/v0.4.0/{t}": {
        "status": 200, "body_file": p_bin,
        "headers": {"X-Pipesure-Manifest": wm, "X-Pipesure-Manifest-Sig": ws}
    },
    f"/bad-sha/v1/dl/pipesure-check/v0.4.0/{t}": {
        "status": 200, "body_file": p_bin,
        "headers": {"X-Pipesure-Manifest": sm, "X-Pipesure-Manifest-Sig": ss}
    },
    f"/bad-ver/v1/dl/pipesure-check/v0.4.0/{t}": {
        "status": 200, "body_file": p_bin,
        "headers": {"X-Pipesure-Manifest": verm, "X-Pipesure-Manifest-Sig": vers}
    },
    f"/bad-tgt/v1/dl/pipesure-check/v0.4.0/{t}": {
        "status": 200, "body_file": p_bin,
        "headers": {"X-Pipesure-Manifest": tm, "X-Pipesure-Manifest-Sig": ts}
    },
    f"/no-headers/v1/dl/pipesure-check/v0.4.0/{t}": {
        "status": 200, "body_file": p_bin, "headers": {}
    },
    f"/refused/v1/dl/pipesure-check/v0.4.0/{t}": {
        "status": 403, "body": "licence expired", "headers": {}
    },
}
with open(sys.argv[13], "w", encoding="utf-8") as f:
    json.dump(routes, f)
' "$PAYLOAD_BIN" "$HOST_TARGET" \
  "$VALID_M64" "$VALID_SIG" \
  "$WRONG_KEY_M64" "$WRONG_KEY_SIG" \
  "$WRONG_SHA_M64" "$WRONG_SHA_SIG" \
  "$WRONG_VER_M64" "$WRONG_VER_SIG" \
  "$WRONG_TGT_M64" "$WRONG_TGT_SIG" \
  "$SHOP_ROUTES"

start_server "$SHOP_ROUTES" tls
SHOP_PORT="$STARTED_PORT"
SHOP_LOG="$STARTED_LOG"

run_install_case() {
  local subpath="$1" licence="$2" pubkey="$3" scheme="${4:-https}"
  local case_dir
  case_dir="$(mktemp -d "$WORK/case.XXXXXX")"
  : > "$case_dir/gh_env"
  : > "$case_dir/gh_out"
  set +e
  CURL_CA_BUNDLE="$KEYS_DIR/tls.cert.pem" \
  PIPESURE_LICENCE="$licence" \
  PIPESURE_TMP="$case_dir/tmp" \
  PIPESURE_SHOP="${scheme}://127.0.0.1:${SHOP_PORT}${subpath}" \
  PIPESURE_VERSION="v0.4.0" \
  PIPESURE_PUBLIC_KEY="$pubkey" \
  PIPESURE_EXEC_MARKER="$case_dir/executed" \
  GITHUB_ENV="$case_dir/gh_env" \
  GITHUB_OUTPUT="$case_dir/gh_out" \
  bash "$WORK/step-0.sh" >"$case_dir/stdout" 2>"$case_dir/stderr"
  CASE_RC=$?
  set -e
  CASE_DIR="$case_dir"
}

# --- 001 Case 1: valid signed manifest + end-to-end composite steps ---
run_install_case "/ok" "ps1.test_lic" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "0" "001: valid signed manifest exits 0"

API_ROUTES="$WORK/api-ok-routes.json"
cat > "$API_ROUTES" <<'EOF'
{
  "/repos/octo/demo": {"status": 200, "body": "{\"default_branch\":\"main\",\"visibility\":\"private\"}"},
  "/repos/octo/demo/branches/main": {"status": 200, "body": "{\"protected\":true}"},
  "/repos/octo/demo/rules/branches/main": {"status": 200, "body": "[]"}
}
EOF
start_server "$API_ROUTES" no
API_OK_PORT="$STARTED_PORT"

# Create a minimal git checkout for step 1 (`git ls-tree HEAD`).
SAMPLE_REPO="$WORK/sample-repo"
mkdir -p "$SAMPLE_REPO"
git -C "$SAMPLE_REPO" init -q
git -C "$SAMPLE_REPO" config user.email "test@example.invalid"
git -C "$SAMPLE_REPO" config user.name "Test"
echo "hi" > "$SAMPLE_REPO/README.md"
git -C "$SAMPLE_REPO" add README.md
git -C "$SAMPLE_REPO" commit -q -m "init"

(
  eval "$(load_github_env "$CASE_DIR/gh_env")"
  export PIPESURE_EXEC_MARKER="$CASE_DIR/executed"
  export GH_TOKEN="tok_test001"
  export OUT="$CASE_DIR/report-out"
  export ROOT="$SAMPLE_REPO"
  export GITHUB_API_URL="http://127.0.0.1:${API_OK_PORT}"
  export GITHUB_REPOSITORY="octo/demo"
  export FAIL_ON=""
  export PIPESURE_LICENCE="ps1.test_lic"
  export GITHUB_OUTPUT="$CASE_DIR/gh_out_run"
  bash "$WORK/step-1.sh"
  bash "$WORK/step-2.sh"
)
if [ -f "$CASE_DIR/report-out/report.json" ] && [ -f "$CASE_DIR/report-out/api/files.txt" ]; then
  pass "001: composite steps 2 and 3 produce report.json and api/files.txt"
else
  fail "001: composite steps 2 and 3 missing expected outputs"
fi

# --- 001 Negative cases: tampered signature, SHA-256, version, target, missing headers, HTTP, unpinned key, missing licence, shop 403 ---
run_install_case "/bad-sig" "ps1.test_lic" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "1" "001: tampered Ed25519 signature rejected with exit 1"
assert_eq "$( [ -e "$CASE_DIR/executed" ] && echo yes || echo no )" "no" "001: tampered signature never executes payload"

run_install_case "/bad-sha" "ps1.test_lic" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "1" "001: tampered binary SHA-256 rejected with exit 1"
assert_eq "$( [ -e "$CASE_DIR/executed" ] && echo yes || echo no )" "no" "001: tampered SHA-256 never executes payload"

run_install_case "/bad-ver" "ps1.test_lic" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "1" "001: wrong manifest version rejected with exit 1"

run_install_case "/bad-tgt" "ps1.test_lic" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "1" "001: wrong manifest target rejected with exit 1"

run_install_case "/no-headers" "ps1.test_lic" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "2" "001: missing manifest headers rejected with exit 2"

run_install_case "/ok" "ps1.test_lic" "$SHOP_PUB_B64URL" "http"
assert_eq "$CASE_RC" "2" "001: plain-HTTP shop URL rejected with exit 2"
if grep -q '"authorization": "Bearer ps1.test_lic"' "$SHOP_LOG"; then
  pass "001: mock TLS shop received Bearer licence header on valid download"
else
  fail "001: mock TLS shop log missing expected Bearer licence header"
fi

run_install_case "/ok" "ps1.test_lic" "unpinned"
assert_eq "$CASE_RC" "2" "001: unpinned key rejected with exit 2"

run_install_case "/ok" "ps1.test_lic" "shortkey"
assert_eq "$CASE_RC" "2" "001: wrong-length key rejected with exit 2"

run_install_case "/ok" "" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "2" "001: empty licence rejected with exit 2"

run_install_case "/refused" "ps1.test_lic" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "2" "001: HTTP 403 shop refusal rejected with exit 2"

# --- 001 Parity drift check (positive + negative) ---
if bash "$ROOT_DIR/scripts/check-parity.sh" >/dev/null 2>&1; then
  pass "001: action.yml install body matches scripts/install-pipesure.sh byte-for-byte"
else
  fail "001: action.yml install body drifted from scripts/install-pipesure.sh"
fi

DRIFT_COPY="$WORK/drifted-install.sh"
cp "$ROOT_DIR/scripts/install-pipesure.sh" "$DRIFT_COPY" 2>/dev/null || : > "$DRIFT_COPY"
printf '# drift\n' >> "$DRIFT_COPY"
if bash "$ROOT_DIR/scripts/check-parity.sh" "$ROOT_DIR/action.yml" "$DRIFT_COPY" >/dev/null 2>&1; then
  fail "001: parity check failed to detect drifted script"
else
  pass "001: parity check fails closed on any 1-line difference"
fi

# --- 003 Regression: GitHub API non-2xx responses leave no settings file and record *.error ---
API_ERR_ROUTES="$WORK/api-err-routes.json"
cat > "$API_ERR_ROUTES" <<'EOF'
{
  "/repos/octo/forbidden": {
    "status": 403,
    "body": "{\"message\":\"Resource not accessible by integration\"}"
  },
  "/repos/octo/partial": {
    "status": 200,
    "body": "{\"default_branch\":\"main\",\"visibility\":\"private\"}"
  },
  "/repos/octo/partial/branches/main": {
    "status": 404,
    "body": "{\"message\":\"Branch not found\"}"
  },
  "/repos/octo/partial/rules/branches/main": {
    "status": 500,
    "body": "Internal Server Error"
  }
}
EOF
start_server "$API_ERR_ROUTES" no
API_ERR_PORT="$STARTED_PORT"

ERR_OUT_403="$WORK/out-003-403"
PIPESURE="$PAYLOAD_BIN" \
GH_TOKEN="tok_test003" \
OUT="$ERR_OUT_403" \
ROOT="$SAMPLE_REPO" \
GITHUB_API_URL="http://127.0.0.1:${API_ERR_PORT}" \
GITHUB_REPOSITORY="octo/forbidden" \
bash "$WORK/step-1.sh" 2>"$WORK/step1-003.err"

PIPESURE="$PAYLOAD_BIN" \
OUT="$ERR_OUT_403" \
ROOT="$SAMPLE_REPO" \
FAIL_ON="" \
PIPESURE_LICENCE="ps1.test_lic" \
GITHUB_OUTPUT="$WORK/gh_out_003" \
bash "$WORK/step-2.sh"
assert_eq "$( [ -e "$ERR_OUT_403/api/repo.json" ] && echo yes || echo no )" "no" "003: HTTP 403 leaves no repo.json"
assert_eq "$( [ -f "$ERR_OUT_403/api/repo.json.error" ] && grep -q 'HTTP 403' "$ERR_OUT_403/api/repo.json.error" && echo yes || echo no )" "yes" "003: HTTP 403 writes repo.json.error with HTTP status"
assert_eq "$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print("yes" if r["verdict"]=="Blocked" and "HTTP 403" in r["reason"] else "no")' "$ERR_OUT_403/report.json")" "yes" "003: HTTP 403 produces Blocked verdict with HTTP 403 in reason"

ERR_OUT_PARTIAL="$WORK/out-003-partial"
PIPESURE="$PAYLOAD_BIN" \
GH_TOKEN="tok_test003" \
OUT="$ERR_OUT_PARTIAL" \
ROOT="$SAMPLE_REPO" \
GITHUB_API_URL="http://127.0.0.1:${API_ERR_PORT}" \
GITHUB_REPOSITORY="octo/partial" \
bash "$WORK/step-1.sh" 2>/dev/null
assert_eq "$( [ -f "$ERR_OUT_PARTIAL/api/repo.json" ] && echo yes || echo no )" "yes" "003: HTTP 200 repo.json is saved"
assert_eq "$( [ -e "$ERR_OUT_PARTIAL/api/branch.json" ] && echo yes || echo no )" "no" "003: HTTP 404 leaves no branch.json"
assert_eq "$( [ -e "$ERR_OUT_PARTIAL/api/rules.json" ] && echo yes || echo no )" "no" "003: HTTP 500 leaves no rules.json"
assert_eq "$( [ -f "$ERR_OUT_PARTIAL/api/branch.json.error" ] && grep -q 'HTTP 404' "$ERR_OUT_PARTIAL/api/branch.json.error" && [ -f "$ERR_OUT_PARTIAL/api/rules.json.error" ] && grep -q 'HTTP 500' "$ERR_OUT_PARTIAL/api/rules.json.error" && echo yes || echo no )" "yes" "003: HTTP 404/500 write branch.json.error and rules.json.error"

# --- 005 Regression: licence containing quotes, backslashes or newlines rejected before curl ---
INJ_ROUTES="$WORK/inj-routes.json"
cat > "$INJ_ROUTES" <<'EOF'
{
  "/injected": {"status": 200, "body": "injected-reached"}
}
EOF
start_server "$INJ_ROUTES" no
INJ_PORT="$STARTED_PORT"
INJ_LOG="$STARTED_LOG"

INJ_LICENCE="$(printf 'ps1.abc"\nurl = "http://127.0.0.1:%s/injected"' "$INJ_PORT")"
run_install_case "/ok" "$INJ_LICENCE" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "2" "005: licence with quote and newline curl directive exits 2"
assert_eq "$(wc -l < "$INJ_LOG" | tr -d ' ')" "0" "005: injected curl config URL is never contacted"

run_install_case "/ok" 'ps1.abc"def' "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "2" "005: licence with double quote exits 2"

run_install_case "/ok" 'ps1.abc\def' "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "2" "005: licence with backslash exits 2"

run_install_case "/ok" "ps1.abc def" "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "2" "005: licence with space exits 2"

run_install_case "/ok" $'ps1.abc\n' "$SHOP_PUB_B64URL"
assert_eq "$CASE_RC" "2" "005: licence with trailing newline exits 2"

assert_eq "$(python3 -c '
import re, sys
txt = open(sys.argv[1], "r", encoding="utf-8").read()
fence = chr(96) * 3
blocks = re.findall(fence + r"sh\n(.*?)" + fence, txt, flags=re.S)
ok = len(blocks) >= 2 and all("[!A-Za-z0-9._-]" in b for b in blocks if "--config -" in b)
print("yes" if ok else "no")
' "$ROOT_DIR/README.md")" "yes" "005: README curl --config examples validate key/licence format"

# --- 002 Regression: GH_TOKEN passed via curl --config stdin, never in curl argv (/proc/*/cmdline) ---
API_SLOW_ROUTES="$WORK/api-slow-routes.json"
cat > "$API_SLOW_ROUTES" <<'EOF'
{
  "/repos/octo/slow": {
    "status": 200,
    "delay_ms": 400,
    "body": "{\"default_branch\":\"main\",\"visibility\":\"private\"}"
  },
  "/repos/octo/slow/branches/main": {"status": 200, "body": "{\"protected\":true}"},
  "/repos/octo/slow/rules/branches/main": {"status": 200, "body": "[]"}
}
EOF
start_server "$API_SLOW_ROUTES" no
API_SLOW_PORT="$STARTED_PORT"
API_SLOW_LOG="$STARTED_LOG"

SENTINEL_GH_TOKEN="tok_cmdline_002"
CMDLINE_LEAK_FILE="$WORK/cmdline-leak-002"
python3 -c '
import glob, os, sys, time
sentinel = sys.argv[1].encode("utf-8")
out_path = sys.argv[2]
uid = os.getuid()
deadline = time.monotonic() + 2.5
leaked = False
while time.monotonic() < deadline and not leaked:
    for p in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            st = os.stat(p)
            if st.st_uid != uid:
                continue
            data = open(p, "rb").read()
        except OSError:
            continue
        parts = data.split(b"\x00")
        exe = os.path.basename(parts[0]) if parts else b""
        if exe == b"curl" and sentinel in data:
            leaked = True
            break
    time.sleep(0.02)
with open(out_path, "w", encoding="utf-8") as f:
    f.write("leaked\n" if leaked else "clean\n")
' "$SENTINEL_GH_TOKEN" "$CMDLINE_LEAK_FILE" &
SAMPLER_PID=$!

OUT_002="$WORK/out-002"
PIPESURE="$PAYLOAD_BIN" \
GH_TOKEN="$SENTINEL_GH_TOKEN" \
OUT="$OUT_002" \
ROOT="$SAMPLE_REPO" \
GITHUB_API_URL="http://127.0.0.1:${API_SLOW_PORT}" \
GITHUB_REPOSITORY="octo/slow" \
bash "$WORK/step-1.sh" 2>/dev/null

wait "$SAMPLER_PID" || true
assert_eq "$(tr -d '\r\n' < "$CMDLINE_LEAK_FILE")" "clean" "002: GH_TOKEN never appears in curl /proc/*/cmdline argv"
assert_eq "$( [ -f "$OUT_002/api/repo.json" ] && grep -q "\"authorization\": \"Bearer $SENTINEL_GH_TOKEN\"" "$API_SLOW_LOG" && echo yes || echo no )" "yes" "002: API call still authenticates via stdin curl --config and saves repo.json"

OUT_002_BAD="$WORK/out-002-bad"
INJ_GH_TOKEN="$(printf 'tok_bad"\nurl = "http://127.0.0.1:%s/injected"' "$INJ_PORT")"
PIPESURE="$PAYLOAD_BIN" \
GH_TOKEN="$INJ_GH_TOKEN" \
OUT="$OUT_002_BAD" \
ROOT="$SAMPLE_REPO" \
GITHUB_API_URL="http://127.0.0.1:${API_SLOW_PORT}" \
GITHUB_REPOSITORY="octo/slow" \
bash "$WORK/step-1.sh" 2>/dev/null
assert_eq "$( [ ! -e "$OUT_002_BAD/api/repo.json" ] && [ "$(wc -l < "$INJ_LOG" | tr -d ' ')" = "0" ] && echo yes || echo no )" "yes" "002: malformed GH_TOKEN with quote/newline cannot inject curl directives"

printf '\nSummary: pass=%d fail=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
