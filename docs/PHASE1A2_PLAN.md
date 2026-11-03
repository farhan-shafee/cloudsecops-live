# Durable Evidence and Recovery Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans task by task. Tests precede implementation; a separate reviewer checks the complete branch.

**Goal:** Persist the existing bounded synthetic pipeline with transactional jobs, revisioned draft cases and independently tested recovery.

**Architecture:** A bounded PostgreSQL dataset stores compressed originals, immutable complete-record variants and delivery references. Transactions serialize dataset changes and generation publication; short claims use database-clock leases and fencing tokens. Case revisions and an idempotent offline outbox preserve history without claiming AWS authenticity or SIEM delivery.

**Tech stack:** Python 3.12/3.14, PostgreSQL 17.11, Psycopg 3.3.7, explicit checksum-checked SQL migrations. Existing parser/detector algorithms and tests remain unchanged.

**Spec:** Owner's Phase 1A-2 request, supplied 2026-11-03. Scope is offline synthetic evidence only; no AWS, Wazuh, HTTP service, frontend, human approvals, response or AI integration.

## Global constraints

- Work only in this repository and branch `codex/phase1a2-durable-evidence-recovery`.
- Starting merged main: `fee9da54bb4be5db44009441cdc887571a695459`; reviewed PR #2 head: `d70f5c64e3bc38692fefc2dbffb08eef97da7649`.
- Original bytes live in PostgreSQL: one transaction and one backup boundary. Hashes never authenticate AWS origin.
- Hard dataset caps: 64 raw objects, 100 MiB compressed total, 100 MiB expanded total, 10,000 delivered records; each source retains Phase 1A-1 limits. No unbounded replay or queues.
- Database access is loopback only and restricted to explicitly named project lab/test databases. Local generated credentials remain ignored; no real-system credentials enter CI.
- Keep all Phase 1A-1 tests and its 90% ingestion/detection branch gates. Report persistence coverage separately.
- No destructive volume cleanup. Test databases created by the test runner are retained unless an operator explicitly scopes cleanup.

## Review focus

1. A newly committed conflict or bridge must immediately mark existing conclusions pending, before detection runs.
2. An expired worker must not publish after another worker claims its job.
3. A sink receipt committed before worker death must replay without a duplicate logical effect.
4. Missing, mismatched or corrupt raw evidence must fail recovery, never become an empty detection result.
5. A restored database must validate every stored byte/hash, record reference, finding and case revision before being called recovered.

## Tasks

### 1. Isolated environment and dependency review

Files: `compose.phase1a2.yml`, `scripts/local_postgres.py`, dependency locks and CI.

- [x] Verify PR #2 exact head, 35 files, six successful jobs, no reviews/conflicts, clean worktree; normal merge and verify tree.
- [x] Assess Docker and local capacity read only; no unrelated resources modified.
- [x] Review and pin official PostgreSQL digest and Psycopg release/license.
- [x] Test resource-name, loopback, private configuration and non-destructive lifecycle helpers.
- [x] Start project-only database with finite resources and generated ignored credentials.

### 2. Schema, immutable storage and ingestion

Files: `src/cloudsecops_live/{database,storage}.py`, `src/cloudsecops_live/sql/001_initial.sql`, integration tests.

Interfaces: `Database(dsn)`, `Database.connect()`, `Database.migrate()`, `Database.check_schema(conn)`, `ingest(db, sources, checkpoint=...)`, `load_logs(conn)` and `verify_store(db)`.

- [x] Write negative migration, duplicate/conflict, quota, malformed atomicity and version tests; observe failures.
- [x] Implement SQL checks, uniqueness, foreign keys, immutable history triggers and checksum migration ledger.
- [x] Parse all bounded sources before transaction; atomically commit raw bytes, variants, references, checkpoint, generation and required detection job. Mark old conclusions pending in that transaction.
- [x] Reject missing/stale/future migrations and altered source/record hashes; no trusted-source insertion interface.

### 3. Leased workers, draft revisions and offline outbox

Files: `src/cloudsecops_live/{worker,cases,outbox,durable_cli}.py`, CLI dispatch and tests.

Interfaces: `claim_job(db, lease_seconds=30)`, `run_job(db, claim, fault=None)`, `work_once(db)`, `deliver_once(db, fault=None)`; all acknowledgment follows commit.

- [x] Hand-author expected three-event, late-extension, bridge and conflict results before implementation.
- [x] Implement finite retries, fenced lease completion, expired-lease recovery and terminal states.
- [x] Reuse existing detector over validated originals; persist exact immutable findings and evidence associations.
- [x] Initial cases derive from finding identity; extensions retain case identity; bridges supersede every parent with lineage. Append revisions/timeline/audit and outbox atomically.
- [x] Exercise fault points before/after commit and sink receipt/ack; verify idempotency and stale worker rejection.

### 4. Independent persistence/recovery acceptance

Files: `tests/integration/`, retained sanitized execution receipts, backup/restore tools.

- [x] Run integration suite against fresh explicitly named test databases; absence of PostgreSQL fails required integration job.
- [x] Test simultaneous workers, genuine subprocess termination, database interruption, controlled transaction faults, corrupt evidence and optimistic revision conflicts.
- [x] Dump and restore to a new database without deleting the original; validate complete evidence and referential integrity.
- [x] Retain source revision, fixture hashes, versions, test counts and fault-method labels in sanitized receipts.

### 5. Documentation, adversarial review and delivery

Files: README, roadmap, architecture/threat model, recovery runbook, interview materials and `docs/labs/PHASE1A2_INTERVIEW_LAB.md`.

- [x] Document setup, exact commands, state models, failure diagnosis and remaining Phase 1A gaps.
- [x] Run format/lint/types, original regressions, integration/recovery, coverage, scans and builds on supported Python versions.
- [x] Independent whole-branch security review; fix material findings and rerun affected checks.
- [ ] Commit, publish, verify remote tree/PR diff and actual CI. Leave Phase 1A-2 PR unmerged and stop. Delivery is recorded in the PR/final report after local validation.

## Decisions and execution record

The owner supplied implementation authorization and detailed acceptance criteria. Routine design choices follow those constraints without an additional approval gate. PostgreSQL byte storage is chosen over a filesystem store to avoid a distributed commit boundary; future authoritative S3 originals remain a separate trust boundary. A global dataset lock is intentionally conservative for this small bounded lab.

Local implementation, independent review and both-version validation are recorded in [the validation record](PHASE1A2_VALIDATION.md). All five material review findings are resolved. Exact remote CI remains a delivery check, not an inferred local result.
