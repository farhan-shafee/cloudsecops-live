# Phase1B-AWS-0 validation and remaining gates

Scope: offline AWS collection/authenticity contracts and Terraform source preparation, with no real source authentication or infrastructure. Starting main `7b8435f8e93c375f83501baace45468ee5e6e9c1` and tree `c3c0eb17964d1002e71cfedae144140da1f49c7d` were independently verified against GitHub, the local main and clean checkout. The capacity-blocked Wazuh branch remains unchanged. Work is isolated on `codex/phase1b-aws-offline-foundation`.

## Implemented boundary

Package0.5.0 adds `integrations/aws_cloudtrail`: separate immutable AWS-shaped models, bounded parser, injected read transport, complete paired-marker listing, exact-version bounded retrieval and metadata, raw archive/content hashes, complete-record normalization/deduplication/conflicts, an atomic in-memory checkpoint reference, controlled digest assessments and a deterministic in-memory demo. No AWS SDK, network client or credential discovery is present. Explicit public reports omit account/key/ARN/location/raw-record material.

Only syntax/canonicalization helpers are shared with the unchanged synthetic parser. Checkpoint/batch fingerprints bind source schema, parser, canonicalization and shared syntax version, so a parser upgrade cannot silently reuse an accepted checkpoint. The same-checkpoint race returns the retained content-identical receipt even when read timestamps differ; different content/configuration is rejected. Partial stream reads are supported with finite byte and1024-call bounds. Entire polls are staged before checkpoint CAS; the reference ledger has no process-crash durability claim.

No stronger source classification is available: controlled valid signature/chain/member checks still yield `pending_source_authentication`; the authentication gate always rejects. There is no path into trusted detection, machine receipts or case closure. Source version history/delete markers are deliberately rejected rather than skipped. A final HEAD sweep checks previously staged objects, but an S3 listing/HEAD interval is not an atomic remote snapshot. New/late objects and backfill reconciliation remain future work.

Migrations001–003, existing synthetic parser/detector, persistence/worker/workflow authority and dependency locks remain unchanged. No new migration is justified for this in-memory offline contract. PostgreSQL tests independently require a permanent AWS-envelope quarantine, with every preexisting logical row/checkpoint/finding/case/workflow record unchanged in both empty and populated stores.

## Authenticity and Terraform limitations

[The sourced design](architecture/AWS_OFFLINE_SOURCE.md) requires future expected identity/configuration checks, exact original S3 version custody, supported AWS CLI original-location validation, separate standard/backfill chains and exact validated file membership. CloudTrail digest entries hash exact uncompressed content, not gzip bytes or canonical JSON. The supported CLI has no VersionId option. Exit0 alone, unrelated membership, valid local checksums or a caller's JSON flag never establishes authenticity. No CLI validation or AWS API was executed.

The [Terraform native-JSON source](../infra/aws-offline/README.md) selects `us-east-1`, pins AWS provider6.71.0 and declares only a private versioned SSE-S3 archive, management trail/integrity and distinct limited collector/verifier/test-actor roles. Exact prefix/version permissions, SourceArn conditions, separate externally provisioned provisioning/cleanup identities, non-destructive retention and prevent_destroy are checked against a closed structural policy. Mutation tests independently remove/widen required controls and require rejection.

**Blocked tool validation:** Terraform is not installed. Terraform fmt/validate, provider schema loading, checksum lock generation and effective IAM/service-policy compatibility are **NOT_RUN**, not passed. The local checker parses bounded native JSON and compares reviewed structures/expressions; it is not Terraform or an IAM evaluator. No provider/tool was downloaded and no plan/apply/destroy ran. AWS role trust, organization policies, actual bucket-policy delivery, original/version validation and pricing/retention/cleanup behavior remain future live gates.

## Executed acceptance

Final local totals below come from the completed frozen-source run. Exact published-head CI and fresh review are recorded on the new PR and delivery report; PR#5's prior results cannot approve this revision.

- Initial complete existing-unit snapshot passed612 old tests; concurrently introduced new Terraform test was red before its checker existed. Stale concurrent development snapshots are not final acceptance.
- New parser tests, independent adversarial tests and controlled digest outcomes pass after corrections.
- New real PostgreSQL AWS-boundary tests:2passed, zero skips, within the complete acceptance below.
- Ruff format/lint and strict mypy pass. The private identifier/secret scan initially caught four literal test-only account-shaped identifiers; they were replaced with explicit in-memory generation without weakening the scanner. The complete scan then passed.
- Hash-locked dependency audit reports no known vulnerabilities; Python dependencies are unchanged. Original implementation remains MIT and separately licensed Terraform/provider tooling was neither installed nor copied.

Final clean local acceptance on Windows, Python3.14.8, PostgreSQL17.11, psycopg3.3.7 and pytest9.2.0:

| Measurement | Observed result |
| --- | --- |
| Complete unit suite |904passed plus11subtests; no failures or skips |
| New offline AWS tests within that suite |238passed, including40archive-binding regressions |
| Terraform structural policy/mutation tests within that suite |54passed |
| Complete real PostgreSQL suite |170passed,0failures,0errors,0skips;924.37seconds |
| Full-package lines / actual branches |96.23% /90.12%, no source exclusions |
| Coverage.py combined line/branch metric |94.61% |
| Original ingestion / detection branches |93.45% /100.00%; original >=90% gates retained |
| Original foundation lines |97.25%; original >=90% gate retained |
| All13existing security-module branch gates |Passed individually at >=85% |
| Retained test databases created by the final complete run |174; no database cleanup |
| Frozen source/integration-fixture hash comparisons |71matched after execution |

New module actual branch coverage, independently enforced at >=85% each:

| AWS module | Branch coverage |
| --- | --- |
| `models.py` |90.00% |
| `parsing.py` |90.48% |
| `collection.py` |92.16% |
| `validation.py` |100.00% |
| `demo.py` |100.00% |

The original durable groups remain separately reported: persistence76.85%, worker/outbox75.00% and cases88.46% branches. These are measurements, not newly invented85% gates. Existing complete-package line and per-security-module requirements were preserved.

The private corrected-source harness receipt is `.tools/receipts/phase1b-aws0-reviewfix-python314.json`, timestamped2026-11-03T23:43:02.167379Z. It records real process termination, isolated backend interruption, transaction rollback, migration/restore, direct-role denials, loopback HTTPS and backup/restore acceptance. It identifies the precommit dirty tree honestly; hashes bind the executed source and integration fixtures, which were rechecked before commit. Private diagnostics and database access remain outside Git.

An earlier full database run also passed170tests, but its merged coverage contained stale line measurements after the parser-version-binding correction. That measurement was discarded. An attempted rerun exposed Windows temporary/cache ACL errors before tests could run. No permissions or existing directories were reset: a new private pytest base directory and disabled cache plugin permitted clean coverage from scratch. The initial published head passed864units and170database tests. After the fresh-review correction, coverage was again restarted for the complete904-unit then170-database sequence above. Tests and coverage requirements were not weakened.

After acceptance, PostgreSQL remained healthy with0restarts, `OOMKilled=false` and unchanged1CPU/512MiB/64MiBshared-memory/pids128 limits. A bounded read-only log check since2026-11-03T22:39:45Z found0new native-crash or exhaustion signatures. This is observation of this sequential window, not proof that the historical engine failure was fixed.

## Review corrections

Independently authored failures reproduced escaping/regressing marker acceptance, inconsistent page ordering and an earlier object changing during a later retrieval. The corrected collector validates marker scope/order and final current-version continuity across all staged objects. A short-read regression reproduced rejection of legitimate chunked streams; bounded incremental reads now pass. Additional tests enforce expiry between stages, malformed/error results, bounded retries, checkpoint CAS/interruption/lost acknowledgment, whole-record conflicts, schema/limit/identity types, stream failures and all unavailable-authentication cases.

Independent IAM review found that ListObjectVersions needs `s3:ListBucketVersions`. Both read roles and the source policy now include it under exact bucket/prefix/account conditions, retaining GetObject and GetObjectVersion for current HEAD and exact-version retrieval. No broad runtime administration or write scope was introduced. Independent local cross-review found no remaining material issue at its reviewed source; fresh published-head review remains separate evidence.

Fresh PR#6 review at the initial published head `7fd54543d588bfcd7d80d99e92898e7d32ae49cf` found a P2 archive/content binding defect. Independent hashes could agree with a controlled member while retained content did not come from the retained archive. Authentication stayed unavailable, but the consistency result was incorrect. A root reproduction and30independent failing tests established the issue before correction. The fix reuses unchanged bounded gzip expansion, requires byte equality, validates exact nested types and size/current-version metadata, and returns fixed non-sensitive reasons. Forty independent archive-binding tests pass, including malformed/truncated/CRC/ISIZE/trailing/concatenated archives, exact/one-over byte budgets, high-ratio expansion, forged content/member hashes and valid recompression. The assessment scope is expressly byte/member consistency, not normalized-event or acquisition authentication. The full corrected-source local acceptance above is complete; fresh exact-head remote CI/re-review is recorded separately on PR#6 and the delivery report.

## Reproduce and stop boundary

```text
python -m cloudsecops_live.integrations.aws_cloudtrail
python scripts/check_terraform.py
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m pytest --cov=cloudsecops_live --cov-branch --cov-fail-under=0 --cov-report=
python scripts/run_integration.py --receipt .tools/receipts/aws-offline.json -- --cov=cloudsecops_live --cov-append --cov-branch --cov-fail-under=0 --cov-report=json --cov-report=xml
python scripts/check_coverage.py --require-durable --require-security --require-aws
python scripts/check_secrets.py
python -m pip_audit --require-hashes --disable-pip -r requirements-dev.lock --strict --progress-spinner off
python -m build --no-isolation
```

Use the existing protected local PostgreSQL setup and run complete database suites sequentially. Missing database/tools or required skips fail acceptance. Test databases are retained, not deleted. No parallel stress or Docker/WSL resource change belongs to these commands.

Wazuh remains **NO-GO**: the latest read-only baseline has six Windows availability samples of5.588–5.900GiB against required12GiB. The previous PostgreSQL native SIGSEGV cause remains unproven; sequential tests do not establish an engine fix. No SIEM requirement is waived by reordered independent development.

GO is limited to review of this offline foundation after final local/remote acceptance. Live AWS, real-source trust, Wazuh installation, infrastructure, budget/spending, production deployment and a cloud exercise remain **NO-GO** without separate authorization and unmet acceptance gates. The new PR must remain unmerged. Human interview results remain NOT_RUN.
