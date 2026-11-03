# Phase 1A-2 validation record

Scope: synthetic-only local persistence and recovery. Starting main/new-feature commit: `fee9da54bb4be5db44009441cdc887571a695459`, the verified normal merge of PR #2 at reviewed head `d70f5c64e3bc38692fefc2dbffb08eef97da7649`. No AWS, SIEM, application deployment or human-approved response was exercised.

## Local validation

Windows Python 3.14.8 and Python 3.12.16 each passed **260 unit tests plus 11 subtests and 61 required PostgreSQL integration tests**, with zero integration skips. Each run used fresh explicitly named databases in isolated PostgreSQL 17.11. Retained sanitized JSON execution receipts are under `.tools/receipts/phase1a2-python314-local.json` and `.tools/receipts/phase1a2-python312-local.json`. They bind source/test file hashes, Python/Psycopg/PostgreSQL versions, source revision/dirty state, counts and fault methods. They are local generated evidence; remote exact-commit CI artifacts are the publication proof.

| Coverage | Python 3.14 lines / branches | Python 3.12 lines / branches |
| --- | --- | --- |
| Complete package | 92.72% / 83.73% | 93.00% / 83.73% |
| Persistence (`database`, `storage`) | 87.85% / 74.74% | 87.85% / 74.74% |
| Worker/outbox | 91.24% / 75.00% | 91.49% / 75.00% |
| Draft cases | 96.15% / 88.46% | 96.15% / 88.46% |

Actual ingestion branch coverage is **90.96%**, detection **100%**, on both versions. The original foundation line gate and complete database-suite package line gate remain at least 90%. New groups are measured separately; no source or branch exclusions were added. Lower new-module branch measurements remain visible rather than being relabeled as 90% coverage.

Formatting, linting, strict package typing, dependency audit, secret/identifier scan, diff validation, source-distribution/wheel build and installed-wheel migration-resource/import/demo checks passed. Psycopg 3.3.7 and its binary distribution are pinned; runtime-only and development lock files include package hashes. Dependencies retain their own licenses.

## Recovery mechanisms actually exercised

- Controlled Python exceptions immediately before/after ingestion and detection commits, and around sink receipt/acknowledgment commits.
- Genuine child-process kills while a worker waits immediately before or after transaction commit; recovery distinguishes rollback from an already committed result.
- `pg_terminate_backend` on this test's own connection to demonstrate transaction interruption and recovery.
- Manual stop/start of only the project PostgreSQL container, preserving its volume: stored evidence verified, replay stayed idle and the demo case remained revision 1. Sanitized receipt: `.tools/receipts/restart.json`.
- Simultaneous job claims and outbox delivery, active/expired leases, stale claims and retry exhaustion.
- Actual `pg_dump` custom archive and `pg_restore` into a second fresh database; every logical table is compared, original bytes/references are revalidated and source data stays unchanged.
- Independent hand-derived late extension and seven-event bridge results, both old parents superseded with lineage, and optimistic revision rejection.
- Corrupt/missing originals, normalized derivatives, whole case subtrees, lineage and consistently rehashed false event timelines are rejected.

Private database dumps and credentials are not committed. Test databases and the project volume are retained; destructive cleanup needs explicit scope. These tests do not establish host power-loss, storage-device, cross-host disaster recovery or production availability guarantees.

Before publication, migration source newlines were normalized to the exact Git artifact and fresh-database integration tests rerun. The earlier three-event demo database was preserved under a project archive name; no database or volume was deleted. This avoids silently rewriting a previously stored migration checksum.

## Independent security review

All five material findings were fixed and re-reviewed: unsafe administrative libpq routing; remote Docker routing/default-context inheritance; incomplete reciprocal case/lineage recovery validation; acknowledgment loss on the outbox's final attempt; and CLI parsing bypassing durable quarantine metadata. Regression tests cover each.

Residual limitations: the database owner can bypass triggers; the Docker volume has no portable hard disk quota; repeated retained test databases consume disk; a failed quarantine metadata write can report the database error instead of the initial source-validation code, while still failing safely. No verified AWS source, searchable SIEM alert, human-reviewed case, response authority, operational efficacy or production experience is claimed.

## Delivery boundary

CI defines eight jobs: four Windows/Linux validation combinations, two dependency-audit jobs and two required PostgreSQL recovery jobs. Database jobs reject skipped/empty integration suites and retain sanitized receipt/coverage artifacts. Exact remote commit, PR number and observed CI outcomes are reported in the PR and final delivery report; this document does not assert a run that has not yet occurred.

**GO for offline Phase 1A-2 review**, subject to actual remote CI. **NO-GO for live AWS, SIEM, public deployment or response.** Remaining Phase 1A gaps include authenticated analyst/reviewer access, recommendation/version binding, human review/closure and independent verifier integration. A separately authorized Phase 1A-3 can address local analyst/review contracts; nothing here starts it.

## PR #3 P2 remediation

The reviewed PR head accepted decoded NUL strings before canonicalization/normalization. NUL in a
normalized field then failed PostgreSQL JSONB insertion as a database error rather than a permanent
source error with durable quarantine. The fix rejects U+0000 throughout the decoded JSON tree as
`NUL_CHARACTER` and adds that reason to the durable source-error allowlist. A related quarantine
constraint issue is handled without editing SQL: public `INVALID_UTF8` is stored as
`INVALID_UNICODE`, because the existing reason constraint permits only letters and underscores.

Before the fix, the new parser/CLI tests produced 19 failures and the real PostgreSQL tests confirmed
JSONB rejection and CLI exit 75. After the fix, 23 new parser/CLI cases and 13 new integration cases
pass. Full local validation on both Python 3.12.16 and 3.14.8 passed **283 unit tests plus 11 subtests
and 74 PostgreSQL integration tests**, without skips. This includes every prior crash/replay and
backup/restore test. Sanitized receipts are retained at `.tools/receipts/pr3-nul-python312.json` and
`.tools/receipts/pr3-nul-python314.json`.

Real database assertions compare all 22 tables: malformed-input rejection changes only quarantine
metadata, preserving existing bytes/history and leaving checkpoints, generations, jobs, findings and
cases unchanged. A separately labeled controlled validation fault before ingestion commit verifies
actual SQL rollback followed by committed quarantine; normal NUL rejection occurs before any data
transaction. Legacy unknown-field/error-message NUL fixtures retain exact bytes/hashes but fail
closed on verification and later ingestion. This compatibility limitation is explicit in the
[parser contract](OFFLINE_FOUNDATION.md); historical evidence is never rewritten or deleted.

Ingestion branch coverage is **92.86%**, detection **100%**. Complete-package lines/branches are
**92.97%/84.46%** on Python 3.14 and **93.24%/84.46%** on 3.12. Persistence branches are 75%,
worker/outbox 75%, and cases 88.46%. All existing gates and exclusions policy remain unchanged.
Formatting, linting, strict typing, dependency/secret scans, source/wheel builds and installed-wheel
checks passed. The installed wheel preserves the literal baseline finding ID and verifies the
existing NUL-free lab store. All migrations are byte-identical to the reviewed head. Fresh remote
commit CI and re-review are recorded in PR #3; earlier runs/reviews are not approval of this fix.
