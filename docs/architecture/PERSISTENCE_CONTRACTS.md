# Offline persistence contracts

Phase 1A-2 adds a local PostgreSQL boundary to the [offline foundation](../OFFLINE_FOUNDATION.md). Everything accepted is synthetic and unauthenticated. No database row, local checksum, draft case or sink receipt is an AWS authenticity receipt.

Phase 1A-3A adds [restricted local workspace identities](ANALYST_WORKSPACE.md), expiring hashed sessions, per-case access, append-only notes and atomic note audit. These are additional tables/functions under forward migration 002; the original 22 tables, immutable evidence, worker/checkpoint and outbox contracts remain. Migration 001 and its original ledger fields are unchanged. The engine validates contiguous numbered checksums and the live prior catalog before atomic migration. A separate full v2 fingerprint includes owner/ACL/function/default/column and database/schema authority; it cannot be silently replaced during restore. [Recovery](../FAILURE_AND_RECOVERY.md#workspace-backup-and-protected-restore) requires a connection-quarantined target before loading a no-ACL dump, explicit role reconstruction and original-fingerprint validation before runtime access.

## Storage and transactions

PostgreSQL 17.11 is pinned by official image digest; Psycopg 3.3.7 is pinned with package hashes. PostgreSQL 17 remains supported through November 2029 ([version policy](https://www.postgresql.org/support/versioning/)). The driver supports Python 3.12 and 3.14 ([Psycopg installation](https://www.psycopg.org/psycopg3/docs/basic/install.html)). Psycopg's LGPL license remains separate from this project's original-code MIT license.

Compressed originals use `bytea` in the same database as their metadata and derivatives. This deliberately avoids a filesystem/database two-phase commit. Per-object parser limits remain unchanged. The dataset permits at most 64 raw objects, 100 MiB compressed total, 100 MiB expanded total, 10,000 delivered record references, 256 committed batches, 10,000 raw deliveries and 1,000 quarantine errors. These limits also bound recordless imports. An operator must archive or explicitly start a new dataset when full; retention eviction is not implemented.

Original compressed bytes, exact expanded-content hashes, complete canonical record bytes, normalized fields, parser/schema/canonicalization versions and all delivery references are retained. Database checks verify compressed and canonical hash domains; replay reparses originals and compares every derivative. Different gzip headers create different raw objects while identical complete records retain one event identity. Unknown source-field changes create a second immutable variant and a conflict.

The full event identity has a SQL uniqueness constraint: `(source_kind, account, region, event_id)`. Foreign keys connect deliveries, variants, findings, revisions and timelines. Append-only triggers reject normal updates/deletes of originals, variants, history and audit entries. The local database owner can bypass these controls; this is neither WORM storage nor administrator-proof audit integrity.

`csl.pipeline` is a singleton generation row. Ingestion locks it, validates existing evidence, applies quotas and commits originals, events, delivery references, batch receipt, checkpoint and the required detection job together. New material evidence also marks existing current findings/cases pending. A checkpoint identifies one exact request; reusing it for different bytes or labels fails. Repeating the same checkpoint returns its retained receipt without another delivery. The receipt describes ingestion committed, with downstream pending work explicit.

## Migration boundary

An explicit SQL migration runs transactionally under an advisory lock. The ledger records the SQL checksum and a restore-stable catalog fingerprint covering columns, constraints, trigger definitions and function bodies. Operational entry points reject missing, stale, future, altered or incomplete schema state. A failed migration rolls back its DDL. There is no automatic destructive downgrade or silent reinterpretation of old parser records.

## Worker boundary

Jobs move through `queued → leased → succeeded`, with `retryable`, `dead` and `superseded` alternatives. Claims use `FOR UPDATE SKIP LOCKED`, an unguessable claim token, a database-clock expiry and at most three attempts. Completion rechecks the token and live expiry inside the publication transaction. A replacement claim fences an expired worker. The dataset row stays locked across bounded reconstruction, detection and publication so a newer ingestion cannot race the snapshot. This conservative serialization favors correctness over throughput for a small lab. PostgreSQL documents the underlying [locking behavior](https://www.postgresql.org/docs/17/explicit-locking.html).

Findings, finding/evidence associations, case revisions, timeline entries, audit records, outbox records, published generation and job completion commit together. Acknowledgment follows commit. A crash before commit rolls back; a crash after commit may lose the acknowledgment, and replay observes the durable result. A bounded worker invocation does not promise the whole queue drained: CLI output/exit status exposes remaining work.

## Draft case identity and revisions

All cases remain unreviewed synthetic lab drafts. Initial identity is a domain-separated hash of the initial finding ID. A later component overlapping one prior case retains its case ID and appends a revision. A component joining multiple prior cases gets a deterministic merged identity, explicit parent links, and superseding revisions for every parent. No outdated parent remains current. Conflicts withdraw affected conclusions rather than overwriting their earlier revisions. An identical replay adds no revision.

Each revision records its finding, exact ordered evidence, complete-record hashes, session, event-time boundaries, rule version/definition digest, T1580 rationale, benign explanations and visibility limits. Its fingerprint binds this payload. Revision updates compare the expected current revision transactionally; a stale revision fails. Machine revision is not a human investigation conclusion or approval.

## Offline outbox

The outbox distinguishes `queued`, `attempted`, `retryable`, `failed` and `locally_acknowledged`. Claims are leased and fenced. The test sink commits an idempotency key and exact payload fingerprint before the sender records acknowledgment. A crash in between safely retries the same logical message. Historical superseded revisions remain historical messages; later revisions explicitly carry their new state.

The only sink is a PostgreSQL offline test table. There is no network transport, Wazuh alert, searchable SIEM record or authenticated SIEM query receipt. Local acknowledgment must never be labeled SIEM delivery.

## Recovery acceptance

`verify_store` reparses originals, compares hashes/versions/complete variants, checks delivery/checkpoint coverage and validates derived finding/revision/timeline/outbox links. Backup tests use PostgreSQL's [custom dump and restore](https://www.postgresql.org/docs/17/app-pgdump.html), restore into a newly named database and compare all logical rows plus evidence validation. A dump alone is not a tested backup. Private dumps and connection material stay outside Git.

The test suite labels controlled Python fault injection separately from genuinely killed child processes and terminated PostgreSQL sessions. These demonstrate specific local transaction boundaries, not host power-loss durability, storage-device reliability, HA or production disaster recovery.
