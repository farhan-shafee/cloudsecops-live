# Guarded transport validation record

This records executed offline evidence, not AWS authentication or live readiness.
Starting reviewed head was `5a08dab7c99f8ad356ed1a806267d113a89bbe90`.
PR#6's45-file scope, nine exact-head PR jobs, resolved original P2, fresh no-findings
review, clean mergeability/base/ancestry and local worktree were independently checked.
Normal merge `da8fcbcde05a4e7a7e66e9c8efb26e892211d465` has parents
`7b8435f8e93c375f83501baace45468ee5e6e9c1` and the reviewed head; its tree is
`7520b34f32bf50806040a04897c681cd2f05199c`. Main was rechecked unchanged during work.
No required checks were configured through branch protection; actual job outcomes were
verified without claiming otherwise. Work uses `codex/phase1b-aws1-guarded-transport`.

## Executed local acceptance

On2026-11-04, Python3.14.8 completed **1,405unit tests and11subtests, no failures/skips**
in89.80seconds on the corrected implementation. This includes279independently authored
SDK/receipt cases plus8new boundary/CI/coverage tests. All old1,118units remain present.
Earlier runs are not used as final corrected-source acceptance.

Actual branch counters, not combined line/branch percentages:

| New module | Covered branches / total | Branch coverage |
| --- | ---: | ---: |
| `integrations/aws_sdk/transport.py` |168/192 |87.50% |
| `integrations/aws_cloudtrail/cli_receipts.py` |146/164 |89.02% |

Original ingestion/detection and five offline-AWS module gates are retained, as are the
full-database package line and thirteen application-security branch gates. No exclusions
were added. Local unit-only coverage cannot establish execution of database paths.

Ruff format/lint, strict mypy (37source files), structural Terraform check, secret/private
identifier scan (187files at the recorded scan), dependency compatibility, hash-locked
pip-audit (no known vulnerabilities), sdist/wheel build and isolated wheel import/demo
passed. SDK versions are boto3/botocore1.43.123; CLI output contract is AWS CLI2.37.11,
not an installed or executed AWS CLI. Official SDK/transitive licenses were reviewed and
are documented in operations. Original MIT code and upstream dependency licenses remain
distinct. Terraform source, provider lock, native harness and migrations001–003 are
unchanged. The only preexisting collector edit clarifies its obsolete interface docstring.

## PostgreSQL capacity failure and isolated acceptance requirement

The local full sequential attempt stopped at its first new integration test's existing
41-table snapshot: `DiskFull`, unable to resize a shared-memory segment to32MiB.
Read-only diagnostics found61/64MiB shared-memory usage,2,438retained test databases and
approximately416MiB/512MiB container memory. No new native-crash signatures, restart or
OOM kill appeared in the bounded diagnostic window; health remained good. The historical
SIGSEGV and the precise allocation-growth cause remain unproven.

Private receipt `.tools/receipts/phase1b-aws1-postgres-python314.json` honestly records
1failure/0passed/0skipped; private raw logs are retained. No data/volume/shared-memory
file was deleted, and no process/container/resource setting was changed. Local full
PostgreSQL acceptance is **BLOCKED**, not passed or waived. The existing isolated,
sequential real-PostgreSQL CI jobs must execute all174integration cases, including four
new SDK/receipt quarantine tests, with zero required skips. Their exact-head results and
native Terraform1.17.1/provider6.71.0 init/validate/schema results belong to the PR check
records and final delivery report; this source document does not predeclare future CI.

## Independent security review and fixes

Independent test authors established missing-feature REDs, then exercised wrong/expired
account/role/session, owner guards, pagination/delete markers, version/metadata changes,
partial reads, throttling/TLS/network failures, forged flags and synthetic-workflow denial.
Receipt tests cover official-format output, malformed/oversized/deep/nonfinite JSON,
standard/backfill disagreement, missing/unrelated/duplicate members, scope/version/hash
substitution, missing diagnostics, output-contract changes and before/after continuity.

The fresh whole-branch reviewer found a material P2: pinned botocore could eagerly buffer
unbounded control-response bytes before the adapter's checks. A client-free reproduction
accepted11,534,536bytes of XML. The correction forces streamed receipt before SDK
buffering and guards raw reads before parsing. The independent reproduction now rejects
at1,048,577bytes and closes the stream. The reviewer also found the resulting HEAD
compatibility defect; corrected behavior passes actual botocore HEAD parsing for128B
and2MiB object metadata with zero response-body bytes. Tests also cover replaced HTTP
sessions/send guards, malformed lengths, no-read1 bodies and interrupted/error streams.
The independent reviewer reported no remaining material finding after those corrections.

Fresh published-head review on PR#7 at `c3c0ed9bf568f24d7404efe78586275263d87338`
then identified a P2 precision defect: the receipt validator incorrectly required
whole-second retained retrieval datetimes, although the collector preserves fractional
UTC clocks. Root and an independent test author reproduced it before correction. A
separate retained-time validator now preserves fractions in exact bracket comparisons;
requested interval and serialized receipt timestamps remain strict whole-second UTC.
Ten new tests cover123/456microseconds, exact outside-bracket and reversed fractions,
naive/non-UTC rejection and strict request precision. A second reviewer independently
checked23precision/boundary cases without finding a remaining material issue. The full
1,405-unit run and rebuilt isolated wheel above include this fix. Fresh corrected-head
CI/re-review is required; the original review and CI cannot approve the changed commit.

DNS, response headers and HTTP chunk framing still lack hard wall-clock cancellation.
This is an explicit unmet future live-runner gate, not a claimed total deadline.
Prepared receipts cannot establish execution provenance, cryptographic signatures,
authenticated chain coverage or actual version-observation provenance. Digest archive
hashes are declarations only; retained log archive/content equality is separately checked.
Every result remains unauthenticated and unavailable for trusted findings or closure.

## Reproduction

After the README hash-locked setup, run:

```text
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m pytest --cov=cloudsecops_live --cov-branch --cov-fail-under=0 --cov-report=json --cov-report=xml
python scripts/check_coverage.py --require-aws --require-aws1
python scripts/check_terraform.py
python scripts/check_secrets.py
python -m pip_audit --require-hashes --disable-pip -r requirements-dev.lock --strict --progress-spinner off
python -m build --no-isolation
python -m cloudsecops_live.integrations.aws_cloudtrail
```

Do not rerun the complete local PostgreSQL suite under its current capacity failure.
Use the required isolated CI jobs for full database/HTTPS/crash/replay/restore acceptance.
No AWS client factory/live command, credentials, API, Terraform plan/apply, infrastructure,
Wazuh or source-authentication promotion was used. Wazuh remains NO-GO at measured
5.588–5.900GiB Windows availability versus required12GiB. Live owner decisions remain
in [readiness](AWS_LIVE_READINESS.md). The feature PR must remain open and unmerged.
