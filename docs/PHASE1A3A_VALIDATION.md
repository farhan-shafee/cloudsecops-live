# Phase 1A-3A validation record

Scope: offline synthetic evidence and a loopback HTTPS analyst workspace. Starting main is normal PR #3 merge `51643025451fdd3d23e0b5280dc529004e8d1ccd`, exact approved head `cdf2ad4a18dc5b823bc9cd5d802736b2a79995d4`, tree `6852dd040d5700107fd352a0e3c699b85e33f971`. Premerge verification confirmed all 50 changed files, eight successful exact-head PR jobs, resolved original P2, fresh Codex no-findings review, no blocking reviews/conflicts, clean tree and correct repository/remote. No branch protection was bypassed. The new workspace branch is delivered separately and must remain unmerged.

## Reproducible acceptance

Use the locked development setup and isolated PostgreSQL service from the README. Run:

```text
python -m ruff format --check .
python -m ruff check .
python -m mypy
python scripts/check_secrets.py
python -m pytest --cov=cloudsecops_live --cov-branch --cov-fail-under=0 --cov-report=
python scripts/run_integration.py --receipt .tools/receipts/workspace.json -- --cov=cloudsecops_live --cov-append --cov-branch --cov-fail-under=0 --cov-report=json --cov-report=xml
python scripts/check_coverage.py --require-durable --require-security
python -m pip_audit --require-hashes --disable-pip -r requirements-dev.lock --strict --progress-spinner off
python -m build --no-isolation
```

Required PostgreSQL tests fail on unavailable configuration/service or missing backup tools; skipped or empty integration suites fail the runner. Databases and private backups are retained; no reset/deletion is part of acceptance. The fixture has a finite 128-database per-run capacity bound. Local Windows private temporary test roots require the project-private permissions used by the runner. Sanitized receipts bind versions, source/test hashes, source revision/dirty state and counts. Local precommit receipts describe a dirty implementation checkout; exact published-commit CI artifacts supply the remote execution evidence.

Local Windows Python 3.12.16 and 3.14.8 each pass **410 unit tests plus 11 subtests and 104 real PostgreSQL integration tests**, with zero failures/errors/skips. The four final ACL portability tests were added after the initial unit collection; both complete unit suites were rerun and appended to coverage of the unchanged production source. Both integration receipts are under `.tools/receipts/phase1a3a-python312.json` and `phase1a3a-python314.json`. PostgreSQL is 17.11. Original ingestion branch coverage is **92.86%**, detection **100%**; the foundation line gate and complete-package >=90% line gate remain intact. No source/branch exclusions were added.

| Security module | Lines | Actual branches (both Python versions) |
| --- | --- | --- |
| Authentication/session selection | 95.83% | 88.24% |
| HTTP/application security | 96.03% | 89.29% |
| SQL authorization/session/note store | 98.92% | 93.75% |
| Role provisioning/privilege validation | 98.71% | 98.00% |
| Private runtime configuration | 98.94% | 96.88% |
| TLS/private-file boundary | 96.74% | 88.24% |
| Interactive provisioning/serving CLI | 96.12% | 86.84% |

All seven actual branch measurements are independently gated at >=85%. Entire-package line coverage is 94.69% (Python 3.12) and 94.57% (3.14); package branches are 86.91% on both. The unchanged worker/outbox group remains transparently reported at 75% branches, not relabeled as >=85%. Required negative cases remain mandatory independently of percentages.

Formatting, lint, strict typing on both versions, secret/identifier scan, current strict dependency audit, source/wheel build, isolated installed-wheel SQL/template resources and the original synthetic demo pass. Real HTTPS smoke is part of each required database run. CI still defines eight jobs: four Linux/Windows Python 3.12/3.14 validation jobs, two advisory-audit jobs and two PostgreSQL security/recovery jobs. A workflow definition is not a successful run. Exact published-head remote CI outcomes are recorded in the PR/delivery report, not inherited from PR #3 or an earlier workspace revision.

## Migration and existing lab

The existing populated project lab was privately backed up and upgraded from v1 to v2. All 22 legacy tables remain, all non-ledger legacy logical rows are unchanged, and every original v1 receipt field is unchanged. The ledger appends v2 and seven new tables produce 29 total tables. Complete store verification passed. No user account was automatically created and no retained database was reset or deleted. Sanitized local receipt: `.tools/receipts/phase1a3a-existing-lab-upgrade.json`; private dump remains outside Git.

Real PostgreSQL tests additionally cover fresh install, populated upgrade, migration failure rollback, idempotence, checksum and incompatible-catalog rejection, preserved legacy NUL bytea with accurate replay rejection, original permanent NUL quarantine and atomic batches/checkpoints. Binary backup/restore compares every logical table and retained evidence, including authentication/session hashes, assignments, notes and audit. A no-owner/no-ACL restore target denies runtime CONNECT before trusted security repair; original fingerprints and post-repair restricted SQL denials are required. Same-cluster restore is tested; cross-host role/configuration recovery is not.

## Adversarial review and observed boundaries

Independent review identified and corrected column ACL gaps, oversized revision/note projections, NULL pagination bypass, missing runtime database-owner/CREATE checks, restore connection exposure, owner default-function PUBLIC execution and a stale migration-version CLI receipt. Reviewed security hashes now bind database/schema/column/default authority, owner-created future functions lack PUBLIC execution, and maintenance-created current functions are explicitly revoked in their migration transaction. No stored fingerprint is replaced to accept drift.

Acceptance exercises wrong credentials, persistent throttles/restart behavior, session fixation/expiry/revocation/rotation, forged roles/headers/cookies and hash bearers; unauthorized cases, historical revisions, findings, exact variants and lineage; reviewer/auditor write denials; missing/expired/replayed/action-mismatched CSRF; Host/Origin/cross-site attacks; malformed/oversized input, injection/traversal and stored HTML escaping. Actual restricted SQL logins cannot overwrite evidence/trust/findings/jobs/history, read direct tables, assume owner/verifier or cross-account capabilities. Independent expected answers are literal statuses and row deltas, not generated by authorization/detection functions.

Real transaction faults include audit-insert rejection and termination of the exact restricted PostgreSQL backend while a note exists inside its uncommitted transaction and waits before audit. Both roll back note, audit and nonce use; a repaired retry with the same nonce commits one note and one audit. Different nonces append concurrently; replayed shared nonce commits once. The HTTP outage check separately returns sanitized 503 with no durable mutation. Real HTTPS smoke starts a separate server process and verifies its generated certificate explicitly, without disabled TLS checks or OS trust changes.

## Dependencies and licensing

Runtime versions are pinned and transitive hashes retained in `requirements-runtime.lock`; development/build/test versions use `requirements-dev.lock`. Python 3.12 and 3.14 are supported; framework minimum dependencies are used without frontend, AI, queue or remote identity services. No upstream application code was copied. Original project MIT licensing does not replace dependency licenses.

Reviewed installed distribution metadata/license files: FastAPI/Argon2-cffi/Pydantic/AnyIO/annotated packages/typing-inspection/h11 use MIT; Argon2 bindings MIT; CFFI MIT-0; Uvicorn/Starlette/Jinja/MarkupSafe/Click/IDNA/pycparser use BSD licenses; cryptography Apache-2.0 OR BSD-3-Clause; OpenTelemetry API and tzdata Apache-2.0; typing-extensions PSF-2.0; Psycopg and its binary package LGPL-3.0-only. Dependency notices stay in their distributions. FastAPI's passive OpenTelemetry API dependency installs no exporter/SDK or telemetry service. HTTPX is a test/smoke dependency, not a runtime requirement. No cloud SDK or AWS credential is introduced. Advisory audit is a point-in-time check, not a guarantee of no vulnerabilities.

## Limitations and stop boundary

Evidence remains synthetic and unauthenticated; cases remain unreviewed. Notes grant no approval, verification, closure or response authority. Local host/database administrators and full private web configuration compromise remain trusted/high-impact boundaries. No MFA, password reset, public hosting, cross-host disaster recovery, authentic AWS/Wazuh, independent verifier or operational efficacy is claimed. Two users operated by one person simulate duties. All human interview assessment remains NOT_RUN.

GO is limited to review of Phase 1A-3A after actual exact-head CI succeeds. Phase 1A-3B needs separate authorization for evidence-bound recommendations, distinct reviewer approval, independently restricted verification and guarded closure. No later implementation is started.
