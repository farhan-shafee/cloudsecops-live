# Phase 1A-2 practical interview lab

Status: exercises available; human assessment **NOT_RUN**. Automated regression tests do not establish interview mastery or production security experience.

Use the isolated environment and commands in the [recovery runbook](../FAILURE_AND_RECOVERY.md). Complete the timed work without AI assistance. An assessor supplies fresh synthetic IDs/times and chooses the fault. Do not contact AWS, install a SIEM or use another project's database.

## Explain from memory: 15 minutes

Draw source → PostgreSQL originals/variants → checkpoint/job → finding → draft revision/outbox. Mark transaction and trust boundaries. Explain why losing raw evidence makes a security conclusion irreproducible; why uniqueness must be enforced by PostgreSQL; and why atomicity means neither a case without evidence nor acknowledgment before commit.

Explain read-committed isolation, row locking, short claims, lease expiry and fencing tokens. Describe how duplicate delivery differs from conflicting complete records, including an unknown source field changed by one byte. Explain how idempotency allows a retry after acknowledgment loss without creating another logical event/case/sink effect.

State clearly: local storage and hashes do not authenticate AWS; a candidate burst does not establish malicious intent; an outbox acknowledgment is not an authenticated searchable SIEM receipt; all cases are unreviewed lab drafts.

## Practical exercises: 50 minutes

1. **Durability and replay, 10 minutes.** Import the public fixture, run one worker and record exact event/finding/case identities. Restart the worker process and repeat the same checkpoint. Show committed evidence, one finding, one initial draft revision and unchanged identities. Explain what the ingestion acknowledgment promises.
2. **Competing records, 10 minutes.** Make a fresh synthetic fixture with a changed unknown field under one existing event identity. Predict the result before running it. Show both preserved variants, a conflict, pending then withdrawn conclusions, and the earlier revision still present. Do not edit database constraints to obtain a pass.
3. **Crash diagnosis, 15 minutes.** The assessor kills a worker before or after commit, or terminates its database connection. Identify the first missing durable boundary from job, generation, evidence and outbox records. Distinguish active from expired leases; recover through bounded replay. Prove that unsaved work was not acknowledged and that an old claim cannot publish.
4. **Late evidence and independent test, 15 minutes.** Hand-write expected results for events at 0/20/40 and 100/120/140 seconds, then add 70 seconds. Predict the seven exact IDs, superseded parents and new merged case lineage. Modify one regression test for an unseen timestamp or credential-session change, explain the expected answer without calling production detection logic, and run it. Show why late evidence can invalidate a previous conclusion.

## Restore challenge: 20 minutes

Explain the test harness's backup/restore case, then run it against a fresh database. Identify which data the dump preserves, how originals and referential links are verified, and why a dump file alone is insufficient. Diagnose one seeded missing reference or hash mismatch without treating it as an empty successful result. Keep private dumps and credentials out of Git. Do not delete retained databases without explicit scope.

## Measurable rubric

| Area | Points | Passing evidence |
| --- | --- | --- |
| Transaction/identity explanation | 0–4 | Correct boundaries, full identity, uniqueness and acknowledgment ordering |
| Replay and duplicate/conflict handling | 0–4 | Exact counts/IDs and retained complete variants; no inflated findings |
| Lease/crash investigation | 0–4 | Evidence-based diagnosis, fenced old claim and successful bounded recovery |
| Late revision and test modification | 0–4 | Independently predicted seven IDs, both parents superseded, lineage and passing unseen test |
| Restore and uncertainty | 0–4 | Fresh restore validation, corruption rejection and explicit authenticity/SIEM limits |

Score 0 for unsupported/unrun work, 1 for explanation with help, 2 for normal operation with unresolved negative controls, 3 for independent correct execution and diagnosis, and 4 for defending an unseen variation. Pass: at least 16/20, every area at least 3, all required observable results, and no hard fail. Record commit, versions, seed, exact IDs/counts, fault mechanism, elapsed time, assistance and assessor. A second operator's reproduction is separate evidence.

Hard fail: unauthorized resources/credentials, deletion outside an explicitly approved scope, hidden failures, fabricated evidence, calling synthetic data authentic AWS telemetry, calling the local sink a SIEM alert, or claiming a machine draft is human reviewed.
