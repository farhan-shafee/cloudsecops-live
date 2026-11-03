# Local failure and recovery runbook

Scope: project-only, offline PostgreSQL and synthetic fixtures. Preserve originals and diagnostics. Never use a database failure as evidence that no security activity occurred.

## Reproducible setup

Run from the repository root with Python 3.12 or 3.14 and Docker Desktop/Engine available:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.\.venv\Scripts\python.exe scripts/local_postgres.py start
.\.venv\Scripts\python.exe -m cloudsecops_live db-migrate
.\.venv\Scripts\python.exe -m cloudsecops_live db-ingest --checkpoint demo-1 fixtures/synthetic/inventory-burst.json.gz
.\.venv\Scripts\python.exe -m cloudsecops_live db-work --limit 64
.\.venv\Scripts\python.exe -m cloudsecops_live db-cases
.\.venv\Scripts\python.exe -m cloudsecops_live db-deliver --limit 64
.\.venv\Scripts\python.exe -m cloudsecops_live db-verify
```

Linux uses `python3.12 -m venv .venv` and `.venv/bin/python` for the same commands. The launcher uses Docker Compose, project-specific names, a loopback port, bounded CPU/memory/processes and a generated private local secret. Its `status` and `stop` commands inspect or stop only the named project. Stop retains the volume. No destroy/prune command exists. The private local DSN configuration is `.tools/private/local-postgres.json`; do not print, commit or share it.

The fixture creates three unique events and one synthetic candidate draft. Repeating the same checkpoint returns the original receipt and produces no extra case revision. Hashes and local integrity validation never authenticate AWS. `db-deliver` yields only a local test receipt.

## First discriminating checks

| Symptom | Read next | Expected decision |
| --- | --- | --- |
| Database operation fails | `scripts/local_postgres.py status`; check Docker and free space | Preserve pending work; restore project connectivity. Do not switch to hosted services. |
| Schema missing/incompatible | Confirm checkout/installed wheel and migration revision | Fresh authorized lab: run `db-migrate`. Existing incompatible data: preserve it and investigate; do not erase the ledger or edit its checksum. |
| Ingestion rejected | Read bounded error code and validate fixture structure/limits | Fix the source or leave it quarantined; no partial event acceptance. Do not weaken bounds or relabel it trusted. |
| Ingestion committed, no case | `db-status`, then `db-work --limit 64` | Pending/leased/dead work differs from a successful no-finding result. Check rule predicates and conflicts. |
| Worker died | Inspect job status, attempt and lease expiry | Active leases are not reclaimed. After expiry, a bounded worker retries with a new fencing token. Never manually acknowledge the old job. |
| Case becomes pending/withdrawn | Inspect new generation, conflicts and revision history | Late or conflicting evidence invalidates the previous conclusion. Retain all revisions and lineage. |
| Outbox pending after sink receipt | Inspect outbox status and offline sink idempotency key | Retry after lease expiry; one logical sink effect is expected. A local receipt supplies no SIEM visibility. |
| Evidence hash/reference mismatch | Stop publication and preserve database/backup | Treat as corrupt/incomplete evidence, never silently rebuild an empty dataset. Restore into a separate fresh database and verify it. |

CLI codes: `0` completed requested operation, `2` validation/configuration/integrity rejection, `3` ingestion conflict, `64` usage, `70` internal failure, `75` database failure or required work still pending. A zero ingestion exit acknowledges only the committed ingestion stage. `db-status` is an inspection command and may return zero while its JSON explicitly reports pending work.

## Independent recovery test and retained evidence

```powershell
.\.venv\Scripts\python.exe scripts/run_integration.py --receipt .tools/receipts/local.json
```

This requires PostgreSQL and fails if it is absent. The harness creates only fresh `csl_test_...` databases, exercises migrations, concurrency, faults, real child termination, session interruption and backup/restore, and writes sanitized execution evidence under `.tools/`. It never deletes a database. Reruns use fresh instances; retained test databases consume disk space. Check capacity between runs. Destructive cleanup requires an operator's explicit list/scope and a separate decision after preserving needed evidence. Never run global Docker pruning.

CI supplies a disposable PostgreSQL service and test-only credentials. No AWS or production credentials are involved. Required integration jobs cannot silently skip. Dumps remain private; retain only sanitized test counts, versions, fixture hashes and command/source identities for review.

Not tested here: actual power loss, filesystem corruption below PostgreSQL, host administrator compromise, replication failover, cross-host restores or live-source completeness. Future authoritative AWS S3 originals will require separate authenticity and retrieval receipts; this store cannot replace them.
