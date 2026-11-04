# CloudSecOps Live

Phase1B-OPS-1 adds a **fail-closed disposable-CI test harness** with cluster-wide capacity
checks, connection-disabled database creation and a private durable provenance journal.
It rejects local enrollment and implicit DSN fallback before a database connection.
The retained workstation cluster remains blocked; no retained database or role is
modified, and no cleanup, restart or resource increase is supplied. See the
[safety and capacity contract](docs/PHASE1B_OPS1_SAFETY.md) and
[GitHub governance assessment](docs/TEST_HARNESS_GOVERNANCE.md). New exact-head CI,
including the separate `PostgreSQL harness safety` job, and independent review remain
pending until executed and inspected; a workflow definition is not a passing run.

PR#7 was normally merged at `1400427df348b06f47e1415e8734aa82bf074305`, preserving
reviewed tree `9fad3b5d56afbc4dfe610e08d26a6b39854267f0`. This milestone uses the separate
`codex/phase1b-ops1-test-harness-safety` branch and will remain an unmerged review PR.
The historical PostgreSQL SIGSEGV remains unexplained, and local full PostgreSQL suites
remain **NO-GO**. Wazuh installation and live AWS activity remain unauthorized.

Phase1B-AWS-1 adds an **offline-tested guarded SDK adapter** and fixed-version CLI receipt preparation, while Wazuh remains blocked by measured workstation memory limits. The adapter accepts explicitly configured injected clients; it creates no SDK sessions, discovers no credentials and exposes no live command. Tests use fake/Stubber clients with socket denial. AWS-shaped records and every prepared receipt remain unauthenticated and cannot create trusted findings or close cases. The synthetic pipeline and migrations001–003 remain intact. See the [owner live-readiness packet](docs/AWS_LIVE_READINESS.md), [implementation plan](docs/PHASE1B_AWS1_PLAN.md), [CLI receipt contract](docs/architecture/AWS_CLI_RECEIPT_CONTRACT.md) and [independent interview lab](docs/labs/PHASE1B_AWS1_INTERVIEW_LAB.md).

After the hash-locked Python setup below, run the deterministic credential-free demonstration:

```powershell
.venv\Scripts\python.exe -m cloudsecops_live.integrations.aws_cloudtrail
.venv\Scripts\python.exe scripts/check_terraform.py
```

Expected: three AWS-shaped fixture events, `authenticated=false`, pending source authentication, controlled digest consistency and `AWS_AUTHENTICATION_UNAVAILABLE`. The Terraform command checks reviewed source structure/IAM assumptions only. Phase1B-AWS-0R adds a separate mandatory [native Terraform/provider gate](docs/TERRAFORM_NATIVE_VALIDATION.md) in credential-free disposable CI; its exact-head results must pass independently. Native schema compatibility does not prove effective IAM, service delivery or AWS evidence authenticity. See [AWS source design](docs/architecture/AWS_OFFLINE_SOURCE.md), [offline operations](docs/AWS_OFFLINE_OPERATIONS.md), [validation record](docs/PHASE1B_AWS_OFFLINE_VALIDATION.md), [Terraform preparation](infra/aws-offline/README.md) and [no-AI lab](docs/labs/PHASE1B_AWS_FOUNDATION_INTERVIEW_LAB.md).

Run the new controlled failures without AWS access:

```powershell
.venv\Scripts\python.exe -m pytest tests/test_aws_sdk_transport.py tests/test_aws_cli_receipts.py tests/test_aws1_boundaries.py -q
```

PR#6 was normally merged at `da8fcbcde05a4e7a7e66e9c8efb26e892211d465` after verifying its exact authorized45-file head and nine successful PR jobs, including native Terraform. SDK/API success and CLI exit0 are not signed-source authentication. Live access, provisioning, test activity and cleanup each need separate owner authorization; no live work is authorized here.

An AWS-first security engineering portfolio and training environment. The intended full workflow is:

**Actual AWS event → trusted ingestion → preserved evidence → tested detection → analyst investigation → reviewed response recommendation → independently verified outcome.**

## Implemented investigation workspace: Phase 1A-3B

The first executable slice is implemented: **explicitly synthetic CloudTrail-shaped gzip → bounded parsing → preserved compressed/content provenance → normalized events → deterministic inventory-burst candidate findings**.

The foundation now also persists synthetic originals and normalized events in isolated local PostgreSQL, advances transactional checkpoints, runs leased detection jobs, and creates revisioned unreviewed draft cases with an offline test outbox. Restart/replay and backup/restore tests exercise this local boundary. Internal SHA-256 values establish consistency within their stated domain, never AWS source authenticity or detection efficacy.

The local FastAPI workspace provides explicitly provisioned accounts, Argon2id, hashed server sessions, per-case grants, evidence/history and audited analyst notes. Phase 1A-3B adds immutable no-action recommendations, distinct reviewer decisions, a separately executed restricted consistency verifier and guarded synthetic exercise closure. New source batches invalidate authority; changed closed exercises require explicit audited reopening. Machine finding/case history remains separate and unreviewed. Restricted SQL identities enforce these boundaries. Browser serving requires loopback TLS with no machine-wide trust changes. See [workflow setup and the real HTTPS demonstration](docs/REVIEWED_WORKFLOW_OPERATIONS.md), the [authority/state model](docs/architecture/REVIEWED_WORKFLOW.md) and [workspace security](docs/architecture/ANALYST_WORKSPACE.md).

Corrected [PR #3](https://github.com/farhan-shafee/cloudsecops-live/pull/3) was normally merged at `51643025451fdd3d23e0b5280dc529004e8d1ccd` after verifying the exact approved head, 50-file scope, eight successful exact-head PR jobs, resolved P2 and fresh no-findings review. Phase 1A-3A PR #4 was subsequently normally merged at `c205b4acc4c28650b10def0f8cc8c121deb727ea` after verifying its exact approved 52-file head, eight passing PR jobs and fresh no-findings review. Phase 1A-3B is delivered separately for review.

Phase 0 [PR #1](https://github.com/farhan-shafee/cloudsecops-live/pull/1) was merged only after verifying its exact authorized head, seven-file documentation scope and clean mergeability. No required checks existed; none were represented as passing.

## Run the synthetic demo

Python 3.12 and 3.14 are tested; the supported range is >=3.12,<3.15. Persistence uses the pinned Psycopg driver; parsing and detection remain standard-library code. Development tools are pinned with transitive hashes. From the repository root on Windows PowerShell:

```powershell
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.venv\Scripts\python.exe -m cloudsecops_live import-synthetic fixtures/synthetic/inventory-burst.json.gz
.venv\Scripts\python.exe -m cloudsecops_live detect-synthetic fixtures/synthetic/inventory-burst.json.gz
```

On Linux, use `python3.12 -m venv .venv` and `.venv/bin/python` for subsequent commands. Setup downloads tools; import/detection operate offline. See the [complete command and schema guide](docs/OFFLINE_FOUNDATION.md).

Expected demo: one `AWS-LAB-001` v1.0 **synthetic candidate**, exactly `demo-001`, `demo-002`, `demo-003`, at 0/30/60 seconds, `authenticated=false`, with T1580 context and benign explanations. The [literal expected fixture](fixtures/synthetic/inventory-burst.expected.json) is independent of detector output. A burst alone does not establish malicious activity.

## Implemented boundaries

- Bounded single-member gzip and UTF-8/JSON parsing; strict synthetic envelope; duplicate-key/nonfinite/invalid-Unicode rejection; size, node, nesting, decoded-string, record and numeric limits before tree allocation where applicable.
- Separate exact archive, decompressed-content and canonical complete-record hashes, immutable references and explicit parser/schema/canonicalization versions. The original standalone commands return in-memory results; the explicit `db-*` commands durably preserve compressed originals and versioned derivatives in PostgreSQL.
- Full-record deduplication and conflict detection, including unknown fields. Conflicts suppress every finding in the supplied batch and return exit `3`.
- Exact assumed-role credential-session separation and inclusive 60-second windows. Overlapping qualifying windows sharing evidence merge transitively; disjoint components remain separate.
- Deterministic JSON, bounded qualification reasons and structured non-sensitive errors. Fixture labels/flags cannot grant verified AWS status.
- Formatting, lint/type checks, adversarial tests, measured line/branch coverage, package build/install checks, dependency audit and secret/identifier scanning including expanded gzip fixtures. Linux/Windows Python 3.12/3.14 workflows are defined; actual run outcomes belong to the PR/check records.

The project does not claim production SOC experience, operational incident authority or real-world detection efficacy. Source-project tests inspected during Phase 0 are separate from tests executed for this implementation. Original project code is [MIT licensed](LICENSE); no upstream code was copied, and tool dependencies retain their own licenses.

## Documentation and training

| Document | Purpose |
| --- | --- |
| [Test-harness safety](docs/PHASE1B_OPS1_SAFETY.md) | Disposable-CI capacity, private creation provenance, quarantine and retained-data preservation |
| [Test-harness governance](docs/TEST_HARNESS_GOVERNANCE.md) | Observed branch-protection gaps and the separately authorized owner protection plan |
| [Reviewed-workflow operations](docs/REVIEWED_WORKFLOW_OPERATIONS.md) | Distinct review, restricted verifier, real HTTPS success/failure and audited reopen demo |
| [Reviewed-workflow validation](docs/PHASE1A3B_VALIDATION.md) | Executed acceptance, module coverage, permission denials, recovery and limitations |
| [Workflow authority/state model](docs/architecture/REVIEWED_WORKFLOW.md) | Separate human state, exact bindings, verifier scope, locks and migration003 |
| [Reviewed-workflow interview lab](docs/labs/PHASE1A3B_INTERVIEW_LAB.md) | No-AI integrity/authenticity, replay, TOCTOU, verification and closure exercises |
| [Workspace setup](docs/WORKSPACE_OPERATIONS.md) | Protected account provisioning, local TLS, smoke test and session operations |
| [Workspace security model](docs/architecture/ANALYST_WORKSPACE.md) | Database permission matrix, object access, notes and restore quarantine |
| [Workspace interview lab](docs/labs/PHASE1A3A_INTERVIEW_LAB.md) | Independent no-AI authentication, SQL, browser and transaction exercises |
| [Persistence contracts](docs/architecture/PERSISTENCE_CONTRACTS.md) | Database invariants, leases, revisions and trust limits |
| [Recovery runbook](docs/FAILURE_AND_RECOVERY.md) | Isolated setup, exact durable demo and failure diagnosis |
| [Durability interview lab](docs/labs/PHASE1A2_INTERVIEW_LAB.md) | No-AI crash/replay, late evidence and restore assessment |
| [Offline foundation](docs/OFFLINE_FOUNDATION.md) | Executable interfaces, schemas, hash domains, limits, commands and exit codes |
| [No-AI interview lab](docs/labs/PHASE1A1_INTERVIEW_LAB.md) | Explain the rule, troubleshoot an injected fault and modify a test |
| [System design](docs/architecture/SYSTEM_DESIGN.md) | Full target architecture, trust boundaries and live vertical slice |
| [Reuse audit](docs/architecture/REUSE_AUDIT.md) | Six source snapshots, implementation evidence and license boundaries |
| [Threat model](docs/architecture/THREAT_MODEL.md) | Abuse cases, controls and residual risks |
| [Cloud cost and safety](docs/architecture/CLOUD_COST_AND_SAFETY.md) | Future AWS cost model, IAM, retention and teardown gates |
| [Delivery roadmap](docs/DELIVERY_ROADMAP.md) | Implemented subset and remaining milestone acceptance gates |
| [Interview mastery](docs/INTERVIEW_MASTERY.md) | Capability assessment and evidence requirements; no earned mastery claim |
| [Implementation plan](docs/PHASE1A1_PLAN.md) | Scope, interfaces, decisions and delivery ledger |

## Run the durable demo

The following is the historical local setup sequence, retained for a future separately
authorized recovery. **Do not run it on the currently blocked workstation.** Starting a
service, provisioning accounts, migrations and durable demo writes require separate
owner permission and capacity review. This milestone authorizes none of those local
operations. The test runner supports only its explicitly identified disposable hosted-CI
service; it cannot enroll this local cluster. Read the
[current stop conditions and recovery runbook](docs/FAILURE_AND_RECOVERY.md) first.

```powershell
.venv\Scripts\python.exe scripts/local_postgres.py start
.venv\Scripts\python.exe -m cloudsecops_live workspace roles-setup --maintenance-config .tools/private/local-postgres.json
.venv\Scripts\python.exe -m cloudsecops_live db-migrate --maintenance
.venv\Scripts\python.exe -m cloudsecops_live workspace pipeline-add --maintenance-config .tools/private/local-postgres.json --kind collector --config .tools/private/collector.json
.venv\Scripts\python.exe -m cloudsecops_live workspace pipeline-add --maintenance-config .tools/private/local-postgres.json --kind worker --config .tools/private/worker.json
.venv\Scripts\python.exe -m cloudsecops_live db-ingest --checkpoint demo-1 fixtures/synthetic/inventory-burst.json.gz
.venv\Scripts\python.exe -m cloudsecops_live db-work --limit 64
.venv\Scripts\python.exe -m cloudsecops_live db-cases
.venv\Scripts\python.exe -m cloudsecops_live db-deliver --limit 64
.venv\Scripts\python.exe -m cloudsecops_live db-verify
```

Expect one synthetic candidate and one unreviewed draft case. Reimport the same checkpoint without creating another delivery or revision. `db-deliver` records only an offline local test acknowledgment. The runbook explains pending work, exit codes, resource limits, retained test databases and recovery verification.

Normal ingestion uses the private collector configuration; worker, delivery and inspection commands use the worker configuration. They reject maintenance credentials. Provision each file once and preserve it; commands refuse overwrite. The explicit `--maintenance` path is for trusted migration/recovery work and retains owner authority. Web and verifier configurations contain neither pipeline nor maintenance credentials.

## Next boundary

The synthetic no-action workflow remains separate from offline AWS preparation. A verified synthetic receipt is not AWS source authentication, benign-intent proof or incident validation; exercise closure is not containment or remediation. Review the test-harness correction and its isolated CI evidence first. Any future local acceptance recovery or bounded read-only AWS inspection requires separate owner authorization, identity/capacity review and the applicable live-runner gates. Live source authentication, Wazuh, cloud response, public deployment and AI remain unimplemented. Two accounts operated by one person do not establish independent authority. The Phase1B-OPS-1 PR must remain unmerged; no cleanup or live exercise follows automatically.

Do not commit real cloud evidence, account identifiers, private names, credentials, tokens, Terraform state/plans or unsanitized screenshots. Public fixtures use named synthetic placeholders. Budgets and billing alerts are not spending caps; no cloud expenditure is authorized by this subphase.
