#!/usr/bin/env bash
# © Gatemark Systems Limited 2026. All rights reserved. Licensed under the Gatemark Pipesure Check Licence v0.1.
# Local and CI gate runner for pipesure-check-action.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f ".github/workflows/ci.yml" ]; then
  echo "ci-local: missing .github/workflows/ci.yml" >&2
  exit 1
fi

# 1. Strict YAML parse (rejects duplicate keys and syntax errors) on action.yml and workflows.
python3 -c '
import glob, sys, yaml

class StrictLoader(yaml.SafeLoader):
    pass

def construct_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    pairs = loader.construct_pairs(node, deep=deep)
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise yaml.MarkedYAMLError("duplicate YAML key", node.start_mark, f"duplicate key {k!r}", node.start_mark)
        seen.add(k)
    return dict(pairs)

StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)

files = ["action.yml"] + sorted(glob.glob(".github/workflows/*.yml"))
for path in files:
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.load(f, Loader=StrictLoader)
    if not isinstance(doc, dict):
        sys.exit(f"{path}: expected YAML mapping at root")
print(f"yaml check ok ({len(files)} files)")
'

# 2. actionlint on workflows and local composite action interface.
actionlint
actionlint - <<'EOF'
on: push
permissions:
  contents: read
jobs:
  lint-local-action:
    runs-on: ubuntu-latest
    steps:
      - id: p
        uses: ./
        with:
          licence: ps1.lint_stub
          path: .
          output: pipesure-report
          fail-on: did-not-hold
      - run: echo "${{ steps.p.outputs.report }} ${{ steps.p.outputs.download }}"
EOF

# 3. shellcheck on repository scripts, tests, and every embedded run: step in action.yml and workflows.
shellcheck scripts/*.sh tests/*.sh
python3 -c '
import glob, subprocess, sys, yaml

for path in ["action.yml"] + sorted(glob.glob(".github/workflows/*.yml")):
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    steps = []
    if "runs" in doc and isinstance(doc["runs"], dict):
        steps.extend((f"{path}:step[{i}]", s) for i, s in enumerate(doc["runs"].get("steps", [])))
    if "jobs" in doc and isinstance(doc["jobs"], dict):
        for jname, job in doc["jobs"].items():
            for i, s in enumerate(job.get("steps", [])):
                steps.append((f"{path}:job[{jname}]:step[{i}]", s))
    for label, step in steps:
        if "run" in step:
            p = subprocess.run(["shellcheck", "-s", "bash", "-"], input=step["run"], text=True)
            if p.returncode != 0:
                sys.exit(f"shellcheck failed on {label}")
print("shellcheck embedded steps ok")
'

# 4. Byte-compare parity gate between action.yml install step and scripts/install-pipesure.sh.
bash scripts/check-parity.sh

# 5. Mock-shop and composite-action regression suite.
bash tests/test-action.sh
