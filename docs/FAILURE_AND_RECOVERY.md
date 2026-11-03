# Local failure and recovery runbook

Scope: project-only, offline PostgreSQL and synthetic fixtures. Preserve originals and diagnostics. Never use a database failure as evidence that no security activity occurred.

Phase 1A-3A adds [workspace operations](WORKSPACE_OPERATIONS.md) and [restricted SQL identities](architecture/ANALYST_WORKSPACE.md). The migration/maintenance identity stays outside runtime configuration. Run explicit `workspace roles-setup` before a fresh latest migration. All 22 legacy tables remain; seven workspace tables are added by forward migration 002. Never edit migration 001 or reset a retained database to repair compatibility failures.

## Reproducible setup

Run from the repository root with Python 3.12 or 3.14 and Docker Desktop/Engine available:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.\.venv\Scripts\python.exe scripts/local_postgres.py start
.\.venv\Scripts\python.exe -m cloudsecops_live workspace roles-setup --maintenance-config .tools/private/local-postgres.json
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

## Workspace backup and protected restore

Stop browser serving and preserve private runtime configuration, TLS material and cluster role recovery material separately from the database dump. A database dump does not contain cluster LOGIN roles or their passwords. Backups contain password hashes, session-token hashes, case assignments, notes and audit: treat them as sensitive. The integration suite executes real `pg_dump --format=custom --no-owner --no-privileges` and `pg_restore --no-owner --no-privileges --exit-on-error`, comparing logical hashes of every table and original evidence.

The following is an explicit maintenance procedure, not a browser/API feature. Use the private maintenance connection with a local PostgreSQL client, without a password argument:

1. Create a separately named `csl_test_<lowercase_letters_digits_underscores>` target owned by the **same maintenance role** from `template0`. Preserve the source and every retained test database. Immediately execute `REVOKE CONNECT ON DATABASE <quoted_target_identifier> FROM PUBLIC` **before restoring any objects**. Do not grant runtime roles CONNECT yet; keep the web process stopped. Use a fixed reviewed identifier or a driver's identifier quoting, never interpolate untrusted text.
2. Restore the private dump into that target. Until security repair commits, runtime logins must fail to connect. Default PUBLIC function execution in a no-ACL restore is unsafe without this database connection quarantine.
3. Ensure the original stable roles and mapped per-account LOGIN identities still exist. Same-cluster tests retain them. Cross-host roles, secrets and TLS/configuration recovery are not implemented or tested; do not claim a successful cross-host recovery from a database dump alone.
4. Create a new private maintenance JSON pointing only to the fresh target using the same private-file protections as the launcher. Run `workspace restore-security --maintenance-config <private_target_config>`. The helper validates checksums/structure, reapplies owner/grants and scoped CONNECT, then requires the **original full fingerprint** in the same transaction. Unexpected schema/ACL/owner state must fail; never update the stored hash to accept it.
5. Run `db-verify --config <private_target_config>` (use `db-verify --help` for the shared CLI option placement), compare every table/original hash, validate each actual runtime SQL identity and test forbidden direct SQL. Privately redirect runtime DSNs to the target; validate the exact TLS origin/certificate and run the verified HTTPS smoke before serving.

The original v1 ledger checksum/catalog algorithm remains intact. Version 2 additionally binds owners, table/column/function/default ACLs, database owner/ACL and public schema authority. Database name is excluded from the security identity so a separately named target can match; maintenance ownership must match. Catalog drift, runtime database ownership/CREATE, schema CREATE, direct table/column privileges or unexpected role memberships prevent startup. Restoration does not rebaseline the ledger.

Legacy NUL evidence may remain as bytea. Migration preserves it without parsing; replay verification remains incompatible and reports a validation failure accurately. Keep those bytes, quarantine receipts and database intact. New escaped/decoded NUL sources are permanently quarantined before JSONB persistence, without accepted events, checkpoint movement, findings or partial batches. An incompatible legacy replay is not repaired by editing the evidence.

The harness retains a finite maximum of 128 fresh test databases per run, with local capacity checked before increasing the previous 96 limit for the expanded acceptance suite. This is a fixture resource bound, not an exemption from tests or coverage. Every rerun still creates distinct named databases and deletes none.
