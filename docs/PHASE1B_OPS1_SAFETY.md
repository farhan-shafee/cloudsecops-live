# Phase 1B-OPS-1 test-harness safety contract

This milestone changes offline source code and disposable hosted-CI tests. It does not
authorize operations against retained local databases, start an acceptance cluster,
perform cleanup or change PostgreSQL/Docker resources. Local full-suite acceptance
remains **NO-GO**.

## Preserved incident and starting point

The verified starting main is `1400427df348b06f47e1415e8734aa82bf074305`, tree
`9fad3b5d56afbc4dfe610e08d26a6b39854267f0`, the normal merge of PR #7. The dedicated
branch is `codex/phase1b-ops1-test-harness-safety`.

The preceding read-only investigation found 2,442 retained databases and 9,444 roles,
61/64 MiB POSIX shared-memory use and a PostgreSQL failure to allocate another 32 MiB.
The container was healthy without a new restart or OOM kill in the observed window.
All ten inspected POSIX segments were mapped by a live PostgreSQL process; they were
not established to be orphaned. Retained database/catalog/statistics accumulation is a
plausible contributor, not proof of the allocator's purpose or the native-crash cause.
The historical SIGSEGV remains unexplained. A healthy status does not prove capacity.

The private preservation decision authorizes zero deletions. Preserve all retained
databases and roles, project and acceptance volumes, backups, diagnostics, migration
receipts, case history and historical NUL-containing originals. UUID-shaped names,
missing configuration references and momentary inactivity are not disposal evidence.
There is no deletion mechanism in this milestone.

## Architecture and creation boundary

The harness uses four small modules:

| Module | Responsibility |
| --- | --- |
| `scripts/test_capacity.py` | Strict global capacity observations and fixed limits. |
| `scripts/test_service.py` | Explicit disposable-CI service/cluster identity contract and fresh-cluster bootstrap. |
| `scripts/test_provision.py` | Serialized database creation, connection quarantine and receipt transitions. |
| `scripts/test_journal.py` | Private durable append-only creation provenance and incomplete-state detection. |

`scripts/run_integration.py` and every integration fixture, including migration,
upgrade and restore targets, must use the same boundary. A direct pytest invocation
must not recover a retained local DSN or bypass service identification. This milestone
supports an explicitly identified disposable hosted-CI service; it does not supply a
local override for the exhausted cluster.

The held administrative session takes a bounded advisory lock for the complete
integration run. The same session retains serialization through capacity observations,
database creation, connection-quarantine establishment and role provisioning. Contending
cooperating harness runs fail rather than starting concurrent complete suites. External
maintenance that ignores the lock is outside this cooperative protocol; disposable
service isolation is therefore mandatory.

Before **every** creation, compare SQL cluster identity with the intended service,
validate the Docker container/backing storage identity and obtain current global
catalog and resource observations. Missing, malformed, stale or mismatched required
observations deny creation. A failed preflight never triggers resource reclamation,
automatic database adoption or a switch to another connection.

## Fixed capacity envelope

These are ceilings and minimum headroom, not allocation promises. They are not command
line knobs for making a failing workstation pass.

| Gate before database creation | Required bound |
| --- | --- |
| Total cluster databases, including templates/project DBs | New total must not exceed 200. |
| Total cluster roles, including PostgreSQL predefined roles | Maximum 1,024; reserve 32 role slots before creation/provisioning. |
| Databases created by one run | At most 192. |
| Free data filesystem | At least 2 GiB. |
| Free physical Docker backing filesystem | At least 5 GiB. |
| Free `/dev/shm` | At least 36 MiB. |
| Container memory envelope | Reviewed 512 MiB limit, with at least 32 MiB working-set headroom. |
| Container process envelope | Reviewed 128-PID limit, with at least 16 remaining. |
| CPU quota/capacity | At least one CPU in the reviewed isolated envelope. |
| OOM-kill evidence | Zero; unsupported or missing observation rejects. |

Memory working-set headroom must use documented cgroup/cache semantics rather than
mistaking Docker's cache-adjusted display for all memory consumption. Do not count swap
as RAM, add WSL availability to Windows physical availability or count the Linux virtual
filesystem's apparent size as extra physical disk. Data and backing filesystem free
space are distinct gates, even when one physical filesystem backs both.

The existing successful hosted acceptance receipts recorded 174 tests and 178 database
creations on Python 3.12 and 3.14. A fresh four-database service would finish that workload
at approximately 182 databases. The 200-global and 192-run bounds retain a small finite
margin while preventing repeated successful runs from accumulating indefinitely. The
32-MiB allocation failure motivates 36 MiB shared-memory headroom: room for that request
plus a small margin, not evidence that 36 MiB fixes the historical SIGSEGV.

Prior CI did not record global role peaks or all resource extrema. The role, disk,
working-set and process margins are conservative acceptance policies that must be
demonstrated by the new disposable-CI observations. Do not call them proven until that
run passes. Never raise them to admit the retained local cluster. If mandatory new tests
exceed an envelope, stop and investigate rather than hiding tests, reusing retained
databases, increasing container memory or silently skipping acceptance.

## Private creation provenance and interruption

Create a private journal before issuing `CREATE DATABASE`. Each attempt records a unique
run ID, source revision, harness version, intended name, creating test, migration/restore
purpose, timestamp and retention disposition. After server confirmation, bind the exact
name, OID, owner and cluster/service/storage identity. Record outcomes and bounded error
codes without raw PostgreSQL exception text.

Writes are append-only, serialized across processes and durably flushed. A hash chain
detects changed or incomplete journal records; it is local consistency evidence, not a
signature or protection against a privileged host attacker. The private journal must
outlive temporary pytest directories. Existing incomplete creation states across runs
block further provisioning pending operator review. A journal-write failure before
creation denies the operation; failure after a possibly committed create records or
leaves an uncertain state and must never be presented as success.

Use `CREATE DATABASE ... TEMPLATE template0 ALLOW_CONNECTIONS false`. PostgreSQL then
rejects all connections from creation. While disabled, confirm name/OID/owner, revoke
PUBLIC connection privileges and verify the resulting catalog state before enabling
the maintenance connection path. Migration/restore must retain its existing security
reconstruction boundary. Database privileges are not inherited from template0, and a
later REVOKE alone leaves an avoidable CREATE-to-REVOKE exposure window. See the official
[PostgreSQL 17 CREATE DATABASE contract](https://www.postgresql.org/docs/17/sql-createdatabase.html).

A `ready` transition remains nonterminal while migration is pending. Only `provisioned`
or an explicit `rejected` terminal transition closes an attempt. With `migrate=False`,
`provisioned` records an `unmigrated_target_ready` outcome; it does not claim that a
restore or migration has completed.

A crash before creation leaves recorded intent; a crash after creation leaves a
connection-disabled or otherwise explicitly incomplete target. Neither case allows
automatic recreation, adoption, deletion or a fabricated completion receipt. An operator
must reconcile the exact cluster/name/OID/owner and journal transition under separately
authorized inspection. The journal grants no disposal authority.

Never log passwords, DSNs, evidence, session secrets or private configuration. Private
database/cluster/storage identifiers stay in the private journal, not public test
artifacts. Public receipts contain sanitized versions, counts, source/harness hashes,
aggregate capacity results and bounded failure codes. Do not upload the journal, JUnit
payloads, dumps, container inspection objects or arbitrary logs.

Directory entries and journal checkpoints are synchronized before creation. Power-loss
durability relies on the hosted Linux filesystem honoring POSIX fsync; Windows units
exercise process interruption and locking, not Windows directory power-loss durability.
Backup/restore helpers also require the enrolled CI service and a generated test target;
they cannot fall back to host tools or the retained Compose service.

## Mandatory acceptance and delivery record

The first hosted attempt stopped before creation on an invalid observation. Fixed-stage
diagnostics identified the data-filesystem lookup: `df`'s displayed mount label did not
match the queried directory. The corrected probe queries each fixed operand separately,
frames its single bounded numeric row, and keeps Docker volume identity independent
from display labels. Alias, missing-frame and ambiguous-row regressions preserve denial
for unsupported measurements. No resource threshold was increased or bypassed.

Offline units exercise capacity boundaries, missing identity/observations, journal
serialization/durability, malformed/truncated chains, error redaction and public-receipt
allowlisting. Required real PostgreSQL tests run only on the separately identified
disposable hosted-CI service. They cover global database/role denial, low headroom,
concurrent attempts, journal failure, CREATE failure, interruption around CREATE and
quarantine, actual denied connections, receipt recovery and successful bounded execution.
Fault-injection cases must not leave an unresolved state hidden from later ordinary
provisioning; retain private evidence and use their explicitly isolated CI scope.

Preserve every existing parser/detector, NUL quarantine, application authorization,
synthetic verifier/closure, AWS SDK/receipt, native Terraform, HTTPS, crash/replay and
backup/restore gate. Full PostgreSQL runs stay sequential. No mandatory case may be
skipped to obtain a coverage percentage or green job.

The following slots deliberately remain pending until executed evidence exists:

| Validation evidence | Status before publication |
| --- | --- |
| Final unit counts and new-module branch coverage | Pending final-source run. |
| Linux/Windows formatting, lint, typing, package and security checks | Pending exact-head CI. |
| PostgreSQL 3.12/3.14 complete suites and capacity peaks | Pending disposable exact-head CI. |
| Native Terraform and locked-provider regression | Pending exact-head CI. |
| Independent adversarial review and corrected-source re-review | Pending final diff. |
| Published commit/tree, PR and actual job outcomes | Pending publication verification. |

Record final executed numbers in the PR/final delivery report; do not replace pending
slots with assumptions. The new PR remains open and unmerged. See
[governance assessment](TEST_HARNESS_GOVERNANCE.md) for observed unenforced checks and
the separately authorized owner protection plan.

## Future local recovery conditions

This change does not authorize even a diagnostic connection to the retained cluster.
Keep local full-suite execution blocked. Existing CI results demonstrate only their
fresh isolated workload, not repair of the workstation.

Future local acceptance requires separate owner authorization, independent capacity and
service-identity review, protected-data preservation, an explicit resource envelope and
a supported local contract. A separately named fresh environment may avoid the already
full shared-memory pool, but does not explain or repair the original native crash.
Any proposal to remove retained databases requires exact provenance, explicit allowlists,
backups and verified restores, dependency/hold checks and a separate cleanup decision.
No such action follows from this journal or a green CI run.

Wazuh remains NO-GO under the established physical-memory gate. AWS account readiness,
temporary non-root inspection, deployment and source authentication remain separate
unapproved activities; this milestone supplies none of their authority.
