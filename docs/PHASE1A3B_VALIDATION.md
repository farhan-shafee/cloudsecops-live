# Phase 1A-3B validation record

Scope: offline synthetic investigations, distinct review, restricted independent consistency verification and guarded no-action exercise closure. No cloud action, AWS collection, Wazuh, AI, public deployment or paid service is implemented or authorized by this milestone.

## Starting revision and merge

PR#4 was independently rechecked immediately before normal merge: exact head `45c85db8ff01e85ca5919ff45399ba383d1dd9f0`, main base,52 changed files, eight successful exact-head PR CI jobs, fresh same-head Codex no-findings review, no unresolved blocking findings, clean mergeability, unchanged main, correct ownership/remote and clean checkout. Its [PR CI run](https://github.com/farhan-shafee/cloudsecops-live/actions/runs/41692458644) is evidence for that head only.

Merge `c205b4acc4c28650b10def0f8cc8c121deb727ea` has parents `51643025451fdd3d23e0b5280dc529004e8d1ccd` and the approved head, and preserves reviewed tree `77dcdfe5b3c5cdbc2e47556c8921fb9f03bc852b`. No protection was bypassed. All new work is on `codex/phase1a3b-reviewed-verification-closure`; the new review PR must remain unmerged.

Final migration003 SHA256: `e13f62b8315a5320bdab2008d409dae2d85b94a358b6315cf2b59ec9f4f95808`. Independent checker source SHA256: `bedcc062d7f5452964ca06b69f3d9d2d4463f37240eba838430f0193dac3069e`, checker1.0, policy `synthetic-aws-lab-001-independent/1`. Migrations001/002, parser/detector source and dependency locks remain unchanged.

## Reproduce acceptance

Use the hash-locked README setup and project-local PostgreSQL. In the activated development environment:

```text
python -m ruff format --check .
python -m ruff check .
python -m mypy
python scripts/check_secrets.py
python -m pytest --cov=cloudsecops_live --cov-branch --cov-fail-under=0 --cov-report=
python scripts/run_integration.py --receipt .tools/receipts/reviewed.json -- --cov=cloudsecops_live --cov-append --cov-branch --cov-fail-under=0 --cov-report=json --cov-report=xml
python scripts/check_coverage.py --require-durable --require-security
python -m pip_audit --require-hashes --disable-pip -r requirements-dev.lock --strict --progress-spinner off
python -m build --no-isolation
```

Run complete database suites sequentially. `CSL_TEST_DSN` may select an explicitly protected, loopback project test service; `CSL_POSTGRES_CONTAINER` identifies its exact local Docker container for required binary backup tools. Neither value belongs in public receipts. Missing configuration, unavailable PostgreSQL/backup tools, skipped or empty integration suites fail acceptance. Tests create fresh `csl_test_...` databases and delete none. The finite per-run ceiling remains192.

Local acceptance uses Windows clients and PostgreSQL17.11 in a separately named local acceptance cluster at the original1CPU/512MiB/64MiB shared-memory limits. Linux/Windows validation and Linux PostgreSQL jobs are defined in CI. A workflow definition is not a successful run; exact published-head CI/review outcomes belong to the PR and delivery report, not PR#4's old results.

| Local runtime | Unit tests | PostgreSQL tests | Failures/errors/skips | Retained test databases |
| --- | --- | --- | --- | --- |
| Python3.14.8 |612 +11 subtests |168 |0/0/0 |172 |
| Python3.12.16 |612 +11 subtests |168 |0/0/0 |172 |

The complete database runs took866.72seconds on3.14 and890.57seconds on3.12. Receipts are `.tools/receipts/phase1a3b-python314.json` and `.tools/receipts/phase1a3b-python312.json`; all production Python/SQL and integration-test hashes in both match the frozen source. Local precommit receipts accurately record the verified base commit plus a dirty implementation checkout. Exact published-tree CI artifacts provide the later committed-source evidence.

## Coverage

Actual Python branch measurements are gated per module, with no source/branch/pragma exclusions. SQL state-machine branches are **not** measured by Python coverage; independent real PostgreSQL privilege, race and rollback tests supply their acceptance evidence.

| Security module | Lines, both Python versions | Actual branches, both Python versions |
| --- | --- | --- |
| `workspace_auth` |95.83% |88.24% |
| `workspace_web` |96.42% |90.48% |
| `workspace_store` |98.92% |93.75% |
| `workspace_roles` |98.34% |96.43% |
| `workspace_config` |98.94% |96.88% |
| `workspace_tls` |96.74% |88.24% |
| `workspace_cli` |96.88% |91.07% |
| `workflow_store` |100% |100% |
| `workflow_web` |100% |100% |
| `independent_verifier` |98.24% |94.26% |
| `verifier_runtime` |100% |100% |
| `verifier_cli` |100% |100% |
| `pipeline_roles` |97.24% |91.30% |

All13 security modules independently require at least85% actual branches. Original ingestion remains92.86% and detection100% on both runtimes. Foundation lines are97.07% on3.14 and97.30% on3.12; their original gates remain intact. Complete-package lines are95.80% on3.14 and95.87% on3.12, with89.55% branches on both. Persistence branches76.85%, worker/outbox75% and cases88.46% remain transparently reported; they are not relabeled as passing the new security-module threshold. Required negative tests cannot be waived by aggregate coverage.

## Implemented inventory and authority

New Python modules: `workflow_store`, `workflow_web`, `independent_verifier`, `verifier_runtime`, `verifier_cli`, `pipeline_roles`. Existing database, workspace, CLI and machine-audit interfaces are extended. Three escaped templates provide queue, current workflow and individually selected historical recommendation views. The public HTTPS demonstration script and no-AI lab accompany the implementation.

Migration003 adds12 tables, for41 total: `ws_workflows`, `ws_recommendations`, `ws_reviews`, `ws_verifiers`, `ws_verifier_grants`, `ws_verification_requests`, `ws_verifications`, `ws_closures`, `ws_transitions`, `ws_workflow_csrf`, `ws_pipeline_identities`, `ws_pipeline_batches`. All29 prior tables and original receipt fields/v2 UUID remain. See the [complete authority and state model](architecture/REVIEWED_WORKFLOW.md).

| Identity | Allowed authority | Explicitly excluded |
| --- | --- | --- |
| Assigned analyst | Read assigned evidence/history; append notes and immutable recommendations | Review, machine receipts, closure, source mutation |
| Distinct assigned reviewer | Read queue/evidence; decide and perform guarded synthetic closure/reopen | Self-review, recommendations, machine receipts, cloud actions |
| Assigned auditor | Read-only assigned evidence/history | Every mutation |
| Case-scoped verifier | Named snapshot/original reads; computed local-consistency receipts | Human sessions/decisions, closure, arbitrary archive access, owner authority |
| Database-scoped collector | Necessary source/checkpoint/quarantine/queued-job columns within current-batch protocol | Human/auth/audit reads, machine publication, orphan source writes |
| Database-scoped worker | Necessary processing/finding/case/outbox columns through statement guards | Original replacement, human/auth/audit reads, review or receipt fabrication |
| Offline maintenance | Explicit migrations, provisioning and protected recovery | Normal browser, verifier or pipeline request handling |

Human state is distinct from machine history: open → recommended → approved/rejected; approved → verified/contradicted/inconclusive; only a current verified result plus all guards permits synthetic closure. Material source/finding/case changes invalidate authority atomically; closed → reopen_required → explicit audited reopen → new workflow. No execution attempt, generic action endpoint, target or containment adapter exists.

## Independent review and adversarial observations

Material review findings were corrected before delivery:

- Refresh roles/assignments and checker pins after lock waits; recheck bound author, reviewer and verifier authority through commit.
- Require a succeeded current-generation job, not only equal publication counters, and hold its lock in the pipeline-first order.
- Replace owner-based normal pipeline commands with restricted identities and UUID-scoped capabilities. Native SQL proves a source login cannot CONNECT to another dataset.
- Enforce the protocol for direct machine SQL. Seven orphan mutations fail without a same-transaction, actual-actor, server-instance batch marker. Missing/disabled mappings and caller-set flags cannot bypass it.
- Serialize worker material writes before tuple locks and atomically invalidate/audit human authority. A raw worker update waits behind an in-flight closure, then makes its retained closure require reopening. Audit failure rolls back both facts and workflow state.
- Bound history to20 metadata summaries plus one full current/selected version; broaden catalog checks to all non-system namespaces and literal system-prefix handling.
- Label the machine case explicitly as an unreviewed synthetic draft. Correct the test helper's parameterized audit-prefix query; expected HTTP rejection statuses were unchanged.

The native protocol suite independently reproduced orphan writes and the closure race before guards, and stale-server-marker acceptance before the epoch predicate. All six cases pass after correction. Actual PostgreSQL tests also cover96 marker/helper permission denials, source and session forgery, self/unassigned/auditor review, CSRF replay/expiry, Host/Origin/cross-site rejection, XSS escaping, SQL/path abuse, stale/concurrent decisions, negative verification and latest-receipt enforcement.

Existing parser/detector, duplicate/conflict, NUL quarantine, jobs, lineage, offline outbox and recovery tests remain mandatory. Real faults include review/verification/closure backend termination after domain insertion but before audit; verifier process death before/after commit; atomic audit rejection; and exact retry/replay observations. A controlled exception, a killed process, a terminated database session and an HTTP503 are reported as distinct evidence.

## Migration, restore and demonstration

Fresh migration, populated-v2 upgrade, failed-migration rollback, idempotence, incompatible checksum/catalog rejection and preserved legacy NUL replay failure pass in both full suites. The populated upgrade includes accounts, live hashed sessions, CSRF, pre-login challenges, throttles, grants, notes and audit, preserving every prior logical row and both receipts. Existing reviewer membership gains only the scoped capability through migration.

Protected binary dump/restore compares all41 tables/originals. Runtime CONNECT is quarantined before loading no-owner/no-ACL objects. Security reconstruction must match the original complete fingerprint; it never rebaselines drift. Actual SQL denials and resumed scoped verification are checked afterward. Server-instance markers reject old-epoch authorization; this does not establish cross-host credential/recovery support.

The existing populated lab was privately backed up and upgraded from v2 to v3. All29 prior tables remain; every prior non-ledger logical row, both original receipts and the v2 UUID remain unchanged. The total is41 tables. Store consistency and repeated migration invocation pass. No account was automatically created and no database was reset/deleted. Its older maintenance config initially failed the private-file ACL check; inherited extra access was removed from that config and its password file, with both byte hashes unchanged, before backup/migration. Sanitized receipt: `.tools/receipts/phase1a3b-existing-lab-upgrade.json`; the dump remains private.

The standalone demonstration passes in a separately named retained database on the original local cluster: the public three-call fixture is ingested by the restricted collector, published by the restricted worker, recommended/reviewed through real certificate-verified loopback HTTPS, independently checked in a separate verifier process and synthetically closed. Test accounts use explicitly generated random passwords; no default runtime account/password is created.

A source change after verification makes the held close form return409. A fresh recommendation/review/verification then closes the exercise. A second late source makes that closure historical, and the reviewer explicitly reopens it. Final state is **open**, with3 originals,5 events,3 machine revisions,2 recommendations,2 reviews,2 verification receipts,1 retained closure and10 workflow transitions. All ten workflow transitions have corresponding audit records; source/pipeline actor stamps prove the initial restricted path. Complete store verification passes. The receipt records `source_kind=synthetic`, `authenticated=false`, `scope=offline_synthetic_only`, certificate verification true, no secrets and zero cloud actions. Sanitized receipt: `.tools/receipts/phase1a3b-operational-demo.json`.

Both full suites separately pass both required real HTTPS demonstrations, including stale closure rejection, retained closure history and explicit reopening.

Exact setup/account/grant/TLS/verifier and smoke commands are in [reviewed-workflow operations](REVIEWED_WORKFLOW_OPERATIONS.md). Browser serving is loopback HTTPS only; certificate verification is explicit and no system trust store is modified. Passwords, SQL credentials, cookies, keys and dumps stay private.

## Limits and stop boundary

Evidence is synthetic and unauthenticated. The checker independently reconstructs the scenario from complete originals but shares the bounded syntactic parser; a successful proof establishes local consistency, not benign intent, real exercise authorization, absence of unseen activity or AWS authenticity. Its code/credential custody, database administrator and host remain trusted. Shared OS-account processes are not an OS isolation boundary. Two user accounts are a laboratory simulation of duties.

The original shared-cluster parallel stress run failed and included a native PostgreSQL backend crash; its cause remains unproven. All data was retained, original limits restored and evidence/catalog receipts rechecked. Final functional acceptance is sequential and isolated. See the [incident and resource policy](FAILURE_AND_RECOVERY.md#one-cpu-resource-policy-and-the-observed-stress-incident); clean-cluster success is not an engine-crash fix.

No human interview score is earned: [the practical lab](labs/PHASE1A3B_INTERVIEW_LAB.md) remains NOT_RUN. MFA, independent organizational authority, public hosting, cross-host disaster recovery, authenticated AWS collection/digests, SIEM query receipts and operational detection efficacy remain absent or unproven. Exercise closure is not containment or remediation.

GO is limited to review of this offline Phase1A-3B implementation after complete local and exact-head CI acceptance. Phase1B remains NO-GO until separate review/merge authorization and live-source authenticity, IAM/safety/cost, retention and hardware/SIEM readiness gates. Leave the new PR open and stop; no later implementation follows automatically.
