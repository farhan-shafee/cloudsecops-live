# Test harness safety implementation plan

**Goal:** Bound disposable PostgreSQL test growth and retain exact private creation provenance without touching retained local resources.

**Architecture:** Require an explicit hosted disposable-service contract. Hold one advisory lock in the fixed administrative database for the entire run, including role creation, and a private journal lock. Recheck global catalog counts and measured resource headroom before each creation. Create with connections disabled; persist intent, catalog identity and ACL confirmation before enabling connections. Uncertainty stops the run and subsequent attempts.

**Authorization:** Phase 1B-OPS-1 permits source changes and disposable hosted acceptance only. No local PostgreSQL operations, cleanup, service changes, AWS or Wazuh. Existing migrations and application behavior stay unchanged.

## Tasks

- [x] Verify main1400427/tree9fad, normal PR7 merge, clean checkout and preservation decision.
- [x] Trace all creation, restore and upgrade paths; independently review governance and quarantine options.
- [x] Add independently tested capacity policy and explicit service/cluster/volume binding. No ambient private-DSN fallback.
- [x] Add private append-only, fsynced, bounded, locked provenance journal and conservative interrupted-run reconciliation.
- [x] Route every test database creation through serialized preflight and creation-time connection quarantine.
- [x] Add negative unit and real disposable PostgreSQL tests, including interruption, concurrency and actual connection denial.
- [x] Extend existing sequential hosted acceptance without weakening earlier gates; publish only sanitized aggregate receipts.
- [x] Document limits, preservation, recovery boundaries and owner-applied repository protection plan.
- [ ] Independently review; run local credential-free checks and exact-head hosted acceptance; correct findings.
- [ ] Commit, push, open one PR, verify remote tree, actual CI and fresh review; leave unmerged.

## Acceptance

Existing successful hosted baseline:178created databases/174tests from a fresh four-database cluster. Proposed global cap200, role cap1024 with32reserved roles, unchanged192per-run cap. Role/resource thresholds are provisional until measured on this branch's disposable CI. Missing observations fail closed. No count, name or journal establishes disposal authority for historical resources.
