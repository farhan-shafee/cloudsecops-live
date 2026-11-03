# CloudSecOps Live

An AWS-first security engineering portfolio and training environment. The intended full workflow is:

**Actual AWS event → trusted ingestion → preserved evidence → tested detection → analyst investigation → reviewed response recommendation → independently verified outcome.**

## Current status: Phase 1A-3A local analyst workspace

The first executable slice is implemented: **explicitly synthetic CloudTrail-shaped gzip → bounded parsing → preserved compressed/content provenance → normalized events → deterministic inventory-burst candidate findings**.

The foundation now also persists synthetic originals and normalized events in isolated local PostgreSQL, advances transactional checkpoints, runs leased detection jobs, and creates revisioned unreviewed draft cases with an offline test outbox. Restart/replay and backup/restore tests exercise this local boundary. Internal SHA-256 values establish consistency within their stated domain, never AWS source authenticity or detection efficacy.

The local FastAPI workspace adds explicitly provisioned accounts, Argon2id passwords, expiring server-side sessions, per-case grants, read-only evidence/history and version-bound append-only analyst notes with atomic audit. Restricted per-account PostgreSQL identities enforce case access and write limits. Browser serving requires loopback TLS; no machine-wide trust changes are made. See the [setup and smoke commands](docs/WORKSPACE_OPERATIONS.md) and [permission model](docs/architecture/ANALYST_WORKSPACE.md).

Corrected [PR #3](https://github.com/farhan-shafee/cloudsecops-live/pull/3) was normally merged at `51643025451fdd3d23e0b5280dc529004e8d1ccd` after verifying the exact approved head, 50-file scope, eight successful exact-head PR jobs, resolved P2 and fresh no-findings review. Phase 1A-3A is delivered separately for review.

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

After the setup above, follow the [local setup and recovery runbook](docs/FAILURE_AND_RECOVERY.md):

```powershell
.venv\Scripts\python.exe scripts/local_postgres.py start
.venv\Scripts\python.exe -m cloudsecops_live workspace roles-setup --maintenance-config .tools/private/local-postgres.json
.venv\Scripts\python.exe -m cloudsecops_live db-migrate
.venv\Scripts\python.exe -m cloudsecops_live db-ingest --checkpoint demo-1 fixtures/synthetic/inventory-burst.json.gz
.venv\Scripts\python.exe -m cloudsecops_live db-work --limit 64
.venv\Scripts\python.exe -m cloudsecops_live db-cases
.venv\Scripts\python.exe -m cloudsecops_live db-deliver --limit 64
.venv\Scripts\python.exe -m cloudsecops_live db-verify
```

Expect one synthetic candidate and one unreviewed draft case. Reimport the same checkpoint without creating another delivery or revision. `db-deliver` records only an offline local test acknowledgment. The runbook explains pending work, exit codes, resource limits, retained test databases and recovery verification.

## Next boundary

Phase 1A-3B requires separate authorization for evidence-bound recommendations, distinct reviewer decisions, an independently restricted verifier and guarded closure. This workspace implements none of those authorities. Live AWS collection, signed-digest authentication, Wazuh, response, public deployment and AI remain unimplemented. Synthetic evidence is unauthenticated; cases remain unreviewed. Two users operated by one person do not establish independent authority.

Do not commit real cloud evidence, account identifiers, private names, credentials, tokens, Terraform state/plans or unsanitized screenshots. Public fixtures use named synthetic placeholders. Budgets and billing alerts are not spending caps; no cloud expenditure is authorized by this subphase.
