# Pipesure Check for GitHub Actions

Pipeline assurance for GitHub Actions workflows: what was checked, with evidence. Read-only; nothing leaves your runner.

© Gatemark Systems Limited 2026. All rights reserved. Pipesure Check is licensed under the Gatemark Pipesure Check Licence v0.1 (see [LICENSE](LICENSE)). This repository holds the Action only: no source and no binary.

## Buy, redeem, store, add the step

1. **Buy credits** at [shop.gatemark.net](https://shop.gatemark.net). You get a credit key (`psk_…`), shown once.
2. **Redeem** credits for a licence for your repositories (a Check is 100 credits for one repository, 3 runs in 7 days; monthly plans cover more):

   ```sh
   case "${PIPESURE_KEY:-}" in ""|*[!A-Za-z0-9._-]*) echo "invalid credit key" >&2; exit 2 ;; esac
   printf 'header = "Authorization: Bearer %s"\n' "$PIPESURE_KEY" | \
     curl -s --config - https://shop.gatemark.net/v1/redeem \
     -d '{"product":"check-spot","repos":["your-org/your-repo"],"idempotency_key":"first-redeem"}'
   ```

   The answer's `licence` field is the licence (`ps1.…`). It names the repositories, the owner and the expiry.
3. **Store the licence** as the repository secret `PIPESURE_LICENCE`. Never commit it or print it.
4. **Add the step** as `.github/workflows/pipesure.yml`. The job grants `contents: read` and `actions: read` only:

   ```yaml
   name: Pipesure Check

   on:
     push:
       branches: [main]
     pull_request:

   permissions:
     contents: read
     actions: read

   jobs:
     pipesure:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
           with:
             persist-credentials: false
         - uses: gatemark/pipesure-check-action@v0.4.0
           with:
             licence: ${{ secrets.PIPESURE_LICENCE }}
         - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
           with:
             name: pipesure-report
             path: pipesure-report
   ```

   For the strongest pin, use the full commit hash of the release you reviewed instead of `v0.4.0`. `v0` moves to the latest release.

The step downloads the pinned Pipesure Check release from the shop with your licence (pay before download), verifies the shop's signed manifest against the Ed25519 key pinned in `action.yml`, checks the file's SHA-256 against that manifest, reads three repository-settings answers with the job's token, then runs offline over the checkout and writes `report.json`, `report.html`, `report.sarif` and `summary.md` to `pipesure-report/`, plus the job summary. The report says who it is licensed to and until when, and carries the download's fingerprint. SARIF upload is off by default (it needs `security-events: write`). The step only reports; set `fail-on: did-not-hold` to fail it when any control did not hold.

## Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `licence` | none: **required** | The licence from the shop, from a secret |
| `token` | `${{ github.token }}` | Read-only GitHub API calls |
| `path` | `.` | The checkout to read |
| `output` | `pipesure-report` | Where the four report forms go |
| `fail-on` | empty | `did-not-hold` fails the step when any check did not hold |

Outputs: `report` (path to `report.json`), `download` (the download id stamped into the binary).

## Fingerprinted downloads

Every copy the shop serves is stamped with a download id (the report and `pipesure --version` print it as `fingerprint dl_…`) and recorded against your licence. This is leak tracing and honest statistics, not copy protection: a copy that leaks traces to the download it came from. Each served copy therefore has its own SHA-256, which is why the Action pins the shop's signing key and verifies a per-download manifest rather than one digest.

## Other runners

Linux x86_64 and arm64 runners are supported by this Action. ADO pipelines use the steps template in the Pipesure Check documentation (bash and PowerShell steps, the same download and verification). A macOS arm64 engineer's laptop can download with the same licence:

```sh
case "${PIPESURE_LICENCE:-}" in ""|*[!A-Za-z0-9._-]*) echo "invalid licence" >&2; exit 2 ;; esac
printf 'header = "Authorization: Bearer %s"\n' "$PIPESURE_LICENCE" | \
  curl -sS --config - -o pipesure -D headers.txt \
  https://shop.gatemark.net/v1/dl/pipesure-check/v0.4.0/aarch64-apple-darwin
```

(the licence goes to curl through its configuration on stdin, never as a command-line argument)

then verify `X-Pipesure-Manifest` and `X-Pipesure-Manifest-Sig` from `headers.txt` against the key at `https://shop.gatemark.net/.well-known/pipesure-licence-key.json` before running it (the Action's `run:` step shows the exact openssl commands).

## Documentation and help

Documentation: [gatemark.net/docs/](https://gatemark.net/docs/). Pipesure Review adds a Gatemark reviewer who re-performs the checks: [gatemark.net/pipesure/](https://gatemark.net/pipesure/). To report a vulnerability, see [SECURITY.md](SECURITY.md).

The report is not a certification and not legal advice.
