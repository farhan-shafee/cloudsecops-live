# Local failure and recovery runbook

AWS2 failures are lifecycle observations only. A deadline/cancellation/protocol/budget failure returns no accepted payload; unconfirmed shutdown remains a failed security boundary. Retain the sanitized `IsolatedResult.to_public_dict()` and keep private worker responses out of logs/public artifacts. A delayed OS launch may need background cleanup; no future live work may start while cleanup is uncertain. See [runner limits](architecture/AWS_SECURE_RUNNER.md). No retained PostgreSQL resource or migration changes; local full-suite acceptance remains NO-GO and must use the disposable hosted service.

## Phase1B-OPS-1: stop local acceptance and preserve provenance

The current retained workstation cluster remains **NO-GO** for complete PostgreSQL
acceptance. Do not run the historical local setup or integration commands below on it.
This milestone authorizes source changes and disposable hosted-CI tests only: no
retained-database connection, cleanup, restart, volume change or resource-limit increase.
PR#7 was normally merged as `1400427df348b06f47e1415e8734aa82bf074305`, tree
`9fad3b5d56afbc4dfe610e08d26a6b39854267f0`; the harness correction stays on its separate
unmerged review branch.

The follow-up read-only inventory counted 2,442 databases and 9,444 roles. It preserved
the 61/64 MiB shared-memory observation, actual 32 MiB allocation failure and historical
native SIGSEGV. The allocator-growth and native-crash causes remain unproven. All
retained databases/roles, both volumes, backups, case history, migration receipts and
legacy NUL evidence remain protected. A generated-looking name, missing configuration
reference, inactivity or passing CI grants no disposal authority.

The runner now requires an explicit disposable hosted-CI service contract and canonical
private journal. Local enrollment and implicit private-DSN fallback fail before any
database connection. Whole-context advisory serialization prevents cooperating suites
from overlapping, and every CREATE receives current global capacity/identity/resource
checks. The fixed 200-database, 1,536-role/reserve-32 and 192-per-run bounds are ceilings,
not permission to use an already exhausted cluster. See the complete
[capacity and provenance contract](PHASE1B_OPS1_SAFETY.md).

New targets are created with `ALLOW_CONNECTIONS false`, recorded with exact private
name/OID/owner/cluster/storage bindings, and denied PUBLIC CONNECT before
maintenance connections are enabled. A `ready` journal transition is still pending
migration completion. Only `provisioned` or an explicit `rejected` terminal state closes
an attempt; a `migrate=False` target records `unmigrated_target_ready` rather than
pretending a migration or restore finished. The private append-only journal remains
outside temporary pytest output. Missing, torn, mismatched or incomplete provenance
blocks later creation and requires separately authorized operator review. It never
causes automatic recreation, adoption, deletion or journal repair.

Preserve the existing full PostgreSQL/HTTPS/recovery/backup suites in sequential hosted
jobs and the new separate `PostgreSQL harness safety` fault-injection service. All retain
the reviewed 512 MiB/one CPU/64 MiB shared-memory/128-PID limits. Exact-head test counts,
resource peaks, coverage and review results are pending execution, not assumed from the
workflow. Public artifacts must exclude private database identifiers, journals, DSNs,
dumps and raw exception/log output. Keep only allowlisted sanitized receipts.

Future local acceptance needs a separate authorized recovery decision and supported local
service contract. A separately named fresh environment could avoid the full retained
pool but would not explain the original crash. Any cleanup proposal needs independently
reviewed provenance, exact owner allowlists, preservation/hold checks, backups and verified
restores; no cleanup mechanism or command is implemented here. See the
[GitHub governance plan](TEST_HARNESS_GOVERNANCE.md); protection settings are unchanged.

Phase1B-AWS-1 adds no database schema or AWS intake path. Rejected SDK/CLI observations
remain outside accepted synthetic evidence; no receipt can grant authentication or
closure. Keep originals/version observations privately when diagnosing a future approved
source mismatch. Do not retry permanent identity/owner/TLS/schema failures as empty
success. The existing sequential PostgreSQL, backup/restore, NUL quarantine and legacy
evidence behavior remains required. A new native backend crash stops acceptance and
preserves diagnostics; the historical SIGSEGV cause remains unproven. No Wazuh resource
gate is waived. See [AWS operations](AWS_OFFLINE_OPERATIONS.md).

### Phase1B-AWS-1 local allocation stop

At2026-11-04T04:16Z, the first new guarded-boundary integration test failed while taking
the existing41-table snapshot: PostgreSQL could not allocate a32MiB shared-memory
segment. The suite stopped immediately. A read-only check found61/64MiB `/dev/shm`
used,2,438retained test databases and approximately416MiB/512MiB container memory.
No other client session was active at the diagnostic sample. Accumulated retained
database/statistics state is a plausible contributor, not a proven root cause.

The container remained healthy with0restarts, `OOMKilled=false` and0new native-crash
signatures in the bounded log window; the allocation error itself is a new observed
local capacity failure. Private failure receipt and raw diagnostic logs are retained.
Do not call this a passed local acceptance or a fix for the historical SIGSEGV. No
database, shared-memory file or volume was deleted; no process/container was restarted
or resource limit increased. Further local database suites are blocked pending a
separately authorized capacity/retention decision. Complete PostgreSQL acceptance must
run in the existing isolated sequential CI service; report its exact-head result
separately. A future operator may propose a separately named isolated test service or
owner-reviewed retained-data policy, never automatic cleanup of these databases.

Scope: project-only, offline PostgreSQL and synthetic fixtures. Preserve originals and diagnostics. Never use a database failure as evidence that no security activity occurred.

Phase 1A-3A adds [workspace operations](WORKSPACE_OPERATIONS.md) and [restricted SQL identities](architecture/ANALYST_WORKSPACE.md). The migration/maintenance identity stays outside runtime configuration. Run explicit `workspace roles-setup` before a fresh latest migration. All 22 legacy tables remain; seven workspace tables are added by forward migration 002. Never edit migration 001 or reset a retained database to repair compatibility failures.

Phase1A-3B adds migration003 and twelve workflow/verifier/pipeline-identity tables, preserving all29 previous tables and the v2 UUID. The current total is41 tables. [Reviewed-workflow operations](REVIEWED_WORKFLOW_OPERATIONS.md) describes restricted service custody, current review/receipt/closure gates and auditable invalidation/reopen. No human transition rewrites the machine case or raw evidence. Human, collector, worker and verifier CONNECT must stay quarantined on restore until v3 ownership/grants/default ACL and original-fingerprint comparison commit.

## Reproducible setup

Historical setup for a future separately authorized local environment follows. It is
not approved for execution on the currently blocked workstation. Starting services,
provisioning roles, migrations and application writes require their own owner permission
and capacity review. The new CI-only integration harness provides no local enrollment.
When those future prerequisites have been separately satisfied, the historical commands
use Python 3.12 or 3.14 from the repository root:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.\.venv\Scripts\python.exe scripts/local_postgres.py start
.\.venv\Scripts\python.exe -m cloudsecops_live workspace roles-setup --maintenance-config .tools/private/local-postgres.json
.\.venv\Scripts\python.exe -m cloudsecops_live db-migrate --maintenance
.\.venv\Scripts\python.exe -m cloudsecops_live workspace pipeline-add --maintenance-config .tools/private/local-postgres.json --kind collector --config .tools/private/collector.json
.\.venv\Scripts\python.exe -m cloudsecops_live workspace pipeline-add --maintenance-config .tools/private/local-postgres.json --kind worker --config .tools/private/worker.json
.\.venv\Scripts\python.exe -m cloudsecops_live db-ingest --checkpoint demo-1 fixtures/synthetic/inventory-burst.json.gz
.\.venv\Scripts\python.exe -m cloudsecops_live db-work --limit 64
.\.venv\Scripts\python.exe -m cloudsecops_live db-cases
.\.venv\Scripts\python.exe -m cloudsecops_live db-deliver --limit 64
.\.venv\Scripts\python.exe -m cloudsecops_live db-verify
```

Linux uses `python3.12 -m venv .venv` and `.venv/bin/python` for the same commands. The launcher uses Docker Compose, project-specific names, a loopback port, bounded CPU/memory/processes and a generated private local secret. Its `status` and `stop` commands inspect or stop only the named project. Stop retains the volume. No destroy/prune command exists. The private local DSN configuration is `.tools/private/local-postgres.json`; do not print, commit or share it.

The fixture creates three unique events and one synthetic candidate draft. Repeating the same checkpoint returns the original receipt and produces no extra case revision. Hashes and local integrity validation never authenticate AWS. `db-deliver` yields only a local test receipt.

Provision the collector and worker private files once; existing files are never overwritten. Normal commands select those restricted identities, with actual catalog checks on connection. They cannot use maintenance credentials implicitly. `--maintenance` is the explicit owner-authority path for migration, protected restore verification or deliberate operator repair. It is never a normal web, verifier, collector or worker configuration.

## First discriminating checks

| Symptom | Read next | Expected decision |
| --- | --- | --- |
| Database operation fails | `scripts/local_postgres.py status`; check Docker and free space | Preserve pending work; restore project connectivity. Do not switch to hosted services. |
| Schema missing/incompatible | Confirm checkout/installed wheel and migration revision | Fresh authorized lab: run `db-migrate --maintenance`. Existing incompatible data: preserve it and investigate; do not erase the ledger or edit its checksum. |
| Ingestion rejected | Read bounded error code and validate fixture structure/limits | Fix the source or leave it quarantined; no partial event acceptance. Do not weaken bounds or relabel it trusted. |
| Ingestion committed, no case | `db-status`, then `db-work --limit 64` | Pending/leased/dead work differs from a successful no-finding result. Check rule predicates and conflicts. |
| Worker died | Inspect job status, attempt and lease expiry | Active leases are not reclaimed. After expiry, a bounded worker retries with a new fencing token. Never manually acknowledge the old job. |
| Case becomes pending/withdrawn | Inspect new generation, conflicts and revision history | Late or conflicting evidence invalidates the previous conclusion. Retain all revisions and lineage. |
| Outbox pending after sink receipt | Inspect outbox status and offline sink idempotency key | Retry after lease expiry; one logical sink effect is expected. A local receipt supplies no SIEM visibility. |
| Evidence hash/reference mismatch | Stop publication and preserve database/backup | Treat as corrupt/incomplete evidence, never silently rebuild an empty dataset. Restore into a separate fresh database and verify it. |

CLI codes: `0` completed requested operation, `2` validation/configuration/integrity rejection, `3` ingestion conflict, `64` usage, `70` internal failure, `75` database failure or required work still pending. A zero ingestion exit acknowledges only the committed ingestion stage. `db-status` is an inspection command and may return zero while its JSON explicitly reports pending work.

## Independent recovery test and retained evidence

The command below is the hosted-CI runner entry point. It rejects an ordinary local
invocation before connecting, and no retained private DSN is discovered automatically.
Do not set CI-looking environment variables or manufacture a service contract to bypass
the local stop. Only the reviewed disposable hosted service may supply the contract.

```powershell
.\.venv\Scripts\python.exe scripts/run_integration.py --receipt .tools/receipts/local.json
```

In its authorized hosted environment this requires PostgreSQL and fails if it is absent.
The harness creates only fresh, journaled connection-quarantined targets after global
capacity checks, exercises migrations, concurrency, faults, real child termination,
session interruption and backup/restore, and writes sanitized execution evidence under
`.tools/`. It never deletes a database. Reruns cannot bypass unresolved provenance or
cluster-wide caps. Destructive cleanup requires a separate owner decision and exact
allowlist after preserving needed evidence. Never run global Docker pruning.

CI supplies a disposable PostgreSQL service and test-only credentials. No AWS or production credentials are involved. Required integration jobs cannot silently skip. Dumps remain private; retain only sanitized test counts, versions, fixture hashes and command/source identities for review.

Not tested here: actual power loss, filesystem corruption below PostgreSQL, host administrator compromise, replication failover, cross-host restores or live-source completeness. Future authoritative AWS S3 originals will require separate authenticity and retrieval receipts; this store cannot replace them.

## Workspace backup and protected restore

Stop browser serving and preserve private runtime configuration, TLS material and cluster role recovery material separately from the database dump. A database dump does not contain cluster LOGIN roles or their passwords. Backups contain password hashes, session-token hashes, case assignments, notes and audit: treat them as sensitive. The integration suite executes real `pg_dump --format=custom --no-owner --no-privileges` and `pg_restore --no-owner --no-privileges --exit-on-error`, comparing logical hashes of every table and original evidence.

The following is an explicit maintenance procedure, not a browser/API feature. Use the private maintenance connection with a local PostgreSQL client, without a password argument:

1. Create a separately named `csl_test_<lowercase_letters_digits_underscores>` target owned by the **same maintenance role** from `template0`. Preserve the source and every retained test database. Immediately execute `REVOKE CONNECT ON DATABASE <quoted_target_identifier> FROM PUBLIC` **before restoring any objects**. Do not grant runtime roles CONNECT yet; keep the web process stopped. Use a fixed reviewed identifier or a driver's identifier quoting, never interpolate untrusted text.
2. Restore the private dump into that target. Until security repair commits, runtime logins must fail to connect. Default PUBLIC function execution in a no-ACL restore is unsafe without this database connection quarantine.
3. Ensure the original stable roles and mapped per-account LOGIN identities still exist. Same-cluster tests retain them. Cross-host roles, secrets and TLS/configuration recovery are not implemented or tested; do not claim a successful cross-host recovery from a database dump alone.
4. Create a new private maintenance JSON pointing only to the fresh target using the same private-file protections as the launcher. Run `workspace restore-security --maintenance-config <private_target_config>`. The helper validates checksums/structure, reapplies owner/grants and scoped CONNECT, then requires the **original full fingerprint** in the same transaction. Unexpected schema/ACL/owner state must fail; never update the stored hash to accept it.
5. Run `db-verify --maintenance --config <private_target_config>` (use `db-verify --help` for the shared CLI option placement), compare every table/original hash, validate each actual runtime SQL identity and test forbidden direct SQL. Privately redirect runtime DSNs to the target; validate the exact TLS origin/certificate and run the verified HTTPS smoke before serving.

The original v1 ledger checksum/catalog algorithm remains intact. Version 2 additionally binds owners, table/column/function/default ACLs, database owner/ACL and public schema authority. Database name is excluded from the security identity so a separately named target can match; maintenance ownership must match. Catalog drift, runtime database ownership/CREATE, schema CREATE, direct table/column privileges or unexpected role memberships prevent startup. Restoration does not rebaseline the ledger.

Legacy NUL evidence may remain as bytea. Migration preserves it without parsing; replay verification remains incompatible and reports a validation failure accurately. Keep those bytes, quarantine receipts and database intact. New escaped/decoded NUL sources are permanently quarantined before JSONB persistence, without accepted events, checkpoint movement, findings or partial batches. An incompatible legacy replay is not repaired by editing the evidence.

The harness retains a finite maximum of192 fresh test databases per run. Before increasing the previous128 limit for Phase1A-3B, host free capacity (C397GB/D861GB) and the project PostgreSQL filesystem (877,398,708KiB available) were rechecked. Execution receipts now record the actual retained database count separately from test count. This is a fixture resource bound, not an exemption from tests or coverage. Every rerun still creates distinct named databases and deletes none.

Retained development databases can contain earlier, unmerged migration003 prototypes. Their checksums intentionally differ from the frozen implementation. Preserve them as test artifacts; do not rewrite their ledgers or reset them to make current startup pass. Use a freshly named test database. The original populated v2 lab has a separate protected final upgrade receipt.


## Reviewed-workflow recovery diagnosis

Treat human state separately from machine case status. A pending generation, stale recommendation, revoked author/reviewer assignment, disabled verifier, expired receipt, changed manifest/checker or latest negative result blocks closure; it must not be repaired by manually setting a closed/verified flag. Additions to source provenance invalidate prior authority in the same ingestion transaction. Inspect immutable transitions/audit and the current effective binding. After a material change to a previously closed exercise, publish the current generation and use the explicit reviewer reopen flow with a reason. A new merged case requires fresh grants and scoped verifier authority.

A verifier process can lose its acknowledgment before or after commit. Retry the same bounded run reference: an uncommitted request/receipt/audit rolls back; a matching committed request returns its retained receipt once. Conflicting replay fails. The CLI cannot accept a supplied verdict. If installed checker bytes differ from the pinned source digest, preserve existing receipts and provision explicitly reviewed new authority; never update old receipt/source fingerprints to accept new code silently.

Binary restore acceptance includes recommendation versions, approvals/rejections, requests, verified/negative receipts, closures, invalidation/reopen history, sessions/grants and all originals. Restore may not reactivate stale authority: run catalog/store verification, actual restricted SQL denials and the real local HTTPS smoke only after security reconstruction. The maintenance and verifier credentials must remain separate from web configuration. No source-authentication, host power-loss, cross-host or live incident-response guarantee follows from these tests.


## One-CPU resource policy and the observed stress incident

Run complete local PostgreSQL suites sequentially. Independent transactional concurrency/race tests remain enabled inside each suite. Application connections explicitly set `max_parallel_workers_per_gather=0` and `max_parallel_maintenance_workers=0`, keeping per-query and utility parallel workers out of the bounded one-CPU lab. This is separate from allowing two independent transactions to contend on locks. Literal server GUC tests prove the policy and environment-override resistance. See [PostgreSQL17 resource settings](https://www.postgresql.org/docs/17/runtime-config-resource.html).

An initial attempt to run both complete Python-version database suites simultaneously exhausted the container's64MiB POSIX shared memory (two32MiB resize failures), followed by a PostgreSQL17.11 backend SIGSEGV and recovery. The logged active statement was the unchanged002 migration. Cgroup records showed no OOM kill, but heavy memory reclaim; no native core was available, so the native crash cause remains unproven. Do not describe the resource mitigation as an engine crash fix or claim those failed runs passed.

The existing volume/databases were retained. A temporary768MiB limit was applied while recovery was assessed; the original512MiB cap was restored without reset/deletion/restart. The retained v2 catalog matched its original receipt, and compressed/content hashes verified before further work. Failed sanitized execution receipts remain private under `.tools/receipts/*-parallel-stress-failed.json`. Subsequent acceptance uses fresh named databases and sequential full runs. This incident remains a documented local stress/recovery limitation, not evidence of host power-loss durability or production readiness.

Final Phase1A-3B acceptance also uses a separately named local cluster, `cloudsecops-live-phase1a3b-acceptance`, on `127.0.0.1:55433`, with the same pinned17.11 image,1CPU,512MiB memory and64MiB shared memory. Its private test credential and retained volume are separate from the existing lab on55432; no original credential, database or volume is reset. Complete Python-version database suites run sequentially. A clean-cluster success does not establish the cause of the earlier native crash. The existing populated v2 lab receives its own protected backup, receipt comparison and forward upgrade verification.
