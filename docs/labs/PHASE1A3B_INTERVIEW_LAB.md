# Phase 1A-3B practical interview lab: reviewed synthetic exercise closure

Human exercise status: **NOT_RUN**. This document records no human score or independent
organizational approval. Automated acceptance tests support the implementation; they do not
complete this assessment.

Complete the exercises without AI assistance. Source, local documentation, PostgreSQL
documentation and handwritten notes are allowed. Write expected HTTP statuses, database
changes and verifier verdicts before running each experiment. Retain wrong predictions and
explain their correction. The assessor supplies expected results independently of the
application's detection, authorization and verifier functions.

## Preparation and boundaries

Preparation is outside the 100-minute assessment. An operator provisions an explicitly named
fresh retained PostgreSQL test database, two synthetic cases, an analyst, two assigned
reviewers, an unassigned reviewer, an auditor and a separately configured case-scoped
verifier. The assessor records grants and duties privately before the candidate starts.
Provision separately restricted collector and worker credentials as well. Keep their private
files separate from the web, verifier and maintenance files. Normal ingestion uses the
collector; publication, store verification and local delivery use the worker. Maintenance
credentials are reserved for explicit provisioning, migration and recovery.

Use [workspace operations](../WORKSPACE_OPERATIONS.md), the
[implementation policy](../PHASE1A3B_PLAN.md) and the
[recovery runbook](../FAILURE_AND_RECOVERY.md). Keep passwords, SQL credentials, session and
CSRF values, keys and dumps private. Enter passwords through protected prompts. The verifier
file must be separate from the web configuration. Record aliases, statuses, counts and
sanitized receipts; never credentials or full private request captures.

Use only the assigned loopback services. Verify the generated certificate explicitly. Do
not disable certificate verification, change machine trust, contact AWS/Wazuh/public hosts,
execute cloud actions or reset/drop retained databases. A controlled owner-level corruption
or audit fault belongs only in the assessor's disposable-in-purpose, retained test database,
with exact catalog restoration in a `finally` block. Administrators and custody of the
verifier's code/credential are trusted boundaries.

## Minutes 0–15: explain authority and create a recommendation

Draw browser → HTTPS application → per-account authentication/data functions, then draw the
separate verifier process and its SQL identity. Mark which process may read original gzip
bytes and which identities may append a recommendation, review, receipt or closure.
Add the collector and worker to the diagram. Perform real synthetic ingestion, publication,
store verification and local delivery through their separate credentials. Prove those
operations create only machine evidence/history and allowed machine audit kinds. Explain
why the normal CLI must reject an owner DSN or a forged config role label; only an explicit
maintenance invocation may select maintenance authority.

Sign in as the assigned analyst. Inspect the current machine revision, fingerprint,
synthetic provenance, evidence references, benign explanations and visibility gaps. Create
one recommendation with your rationale, counterevidence and gaps. Prove that the action is
`NO_ACTION_AUTHORIZED_EXERCISE`, conclusion is `authorized_synthetic_exercise` and targets
are empty. Explain why analyst text cannot authenticate AWS activity or establish real
exercise authorization. Show that the machine case remains an unreviewed synthetic draft.

Predict and demonstrate rejection of a requested action, target, URL, command, role, author,
trust promotion or caller-supplied verifier result. Show an unassigned case and an unknown
case yield indistinguishable 404 responses. Preserve original evidence and machine rows.

## Minutes 15–30: review and bind exact authority

Use the assigned reviewer queue and approve the exact recommendation version/hash. Explain
why account names alone are insufficient and why the reviewer must remain enabled,
assigned and distinct from the author. Demonstrate that the analyst, auditor and unassigned
reviewer cannot approve or reject. Demonstrate that another assigned reviewer cannot replace
an already final decision. Reject a separate recommendation version and show it cannot close.

Predict the results of a missing, expired, replayed, wrong-action and wrong-session CSRF
challenge, a forged role header and an altered workflow version or recommendation hash.
Demonstrate the predicted failures and zero unintended rows/audits. Show that a new immutable
recommendation version supersedes authority without deleting its preceding review history.

## Minutes 30–50: independently verify synthetic consistency

Run the verifier as a separate process using only its private configuration and the
recommendation ID/version. The CLI accepts references, not a verdict flag. Inspect the
sanitized result and the case-bound request's complete bounded manifest. Explain why another
archive in that manifest can contain other case records, why that context is needed for
conflict/bridge detection and why the web process receives no archive-download interface.

Reconstruct by hand three unique successful EC2 `DescribeInstances` calls for one exact
AssumedRole credential session at 0, 20 and 60 seconds. Predict **verified**. Move the last
call beyond 60 seconds, separate a credential session or replace one successful operation:
predict **contradicted** for intact complete originals refuting that claim. Demonstrate
overlapping triples can connect a component spanning more than 60 seconds.

Predict **inconclusive** for missing/corrupt originals, inconsistent compressed/expanded or
canonical-record hashes and unsupported evidence versions. Explain why duplicate deliveries
do not create three unique events and why any full-record conflict blocks positive proof.
Show that benign inventory/pagination/retry explanations remain possible after a verified
burst predicate. Verification establishes synthetic consistency only, not AWS authenticity,
malicious intent, actual exercise authorization or absence of unseen activity.

Using the verifier's actual restricted connection, prove direct receipt INSERT, table
SELECT, schema CREATE, owner `SET ROLE`, human review and closure are denied. Request an
original outside its pinned manifest and a recommendation outside its case scope; both must
fail without disclosure. Explain why a compromised trusted verifier/host is outside the
claim, rather than describing the receipt as remote attestation.

Repeat independent SQL denial probes using the actual collector and worker connections.
Both must be unable to read passwords, session hashes, human workflow rows or the audit
table, and unable to write recommendations, reviews, verification receipts or closures.
Direct audit insertion and a human workflow kind passed to the machine audit helper must
fail. Demonstrate denied raw updates, migration/CREATE/owner escalation and cross-role
capabilities. Show the collector cannot publish findings or set worker lease/status fields;
show the worker cannot ingest originals or forge server-owned history/receipt defaults.
Reject a NUL-bearing source through the collector and prove only durable quarantine metadata
was added, with no accepted batch or checkpoint movement. Redirect each raw credential to
an independent dataset: PostgreSQL must deny CONNECT before any original can be read.

## Minutes 50–65: guarded closure, expiry and late evidence

Close through the same reviewer who approved, using the latest matching verified receipt.
Prove the other assigned reviewer cannot substitute. Inspect the immutable closure and its
audit while the machine case remains current and unreviewed. Predict refusal for an expired
30-minute recommendation, expired review, expired receipt of at most 10 minutes, disabled
reviewer/verifier, removed assignment, or a later contradicted/inconclusive receipt.

Commit a new synthetic source batch without publishing its worker result. The old authority
must immediately become ineffective; a held closure form must fail. Repeat with added
duplicate provenance and explain why even unchanged event generation invalidates authority.
Contrast an exact checkpoint replay, which creates no batch and remains idempotent.

Publish the worker result. Inspect `reopen_required`, the retained closure and invalidation
audit. Have a current assigned reviewer explicitly reopen before a new recommendation.
Create a late bridge joining two cases; prove neither parent grant nor old approval/receipt
authorizes the successor. Superseded parents cannot be reopened as current cases.

## Minutes 65–85: transaction faults and races

For review, verification and closure, prepare the real restricted store before injecting the
assessor's audit failure. Explain why changing the catalog before startup can instead cause
schema validation to reject startup. Assert domain write, audit, token/request consumption
and workflow transition roll back together. Restore the exact catalog and retry the same
operation; require exactly one durable result.

Use the controlled advisory-lock barrier after domain insertion and before audit. Identify
exactly one backend by the fresh test database and its restricted role; terminate only that
PID. Demonstrate rollback and a successful retry. For verifier acknowledgement loss, retry
the same run reference and recover the identical receipt without a second receipt/audit.

Race two final decisions, a shared nonce and closure against new ingestion/publication.
Record the actual outcomes and explain the pipeline → current job → case → workflow → authority lock
order. A valid serial order must never leave current closed authority for a changed source.
Distinguish genuine backend termination, process death, controlled exceptions and an HTTP
503; evidence for one is not evidence for all four.

Bypass the Python wrapper and use the collector's actual SQL connection. An INSERT column
grant alone must not authorize an orphan original, variant, checkpoint or job: accepted
source writes require a batch recorded in that same top transaction on the current server
instance. A stale server marker must fail even if its full transaction ID and actor match. A
previously committed batch, forged caller GUCs and a batch rolled back to a savepoint must
not supply that authority. Releasing a savepoint containing a legitimate batch must preserve
its authority for the surrounding transaction. Neither runtime can edit or read the private
transaction marker or directly execute the internal guard functions.

Pause a reviewer closure after its last binding check and before its audit commits. Attempt
a direct collector source write and a worker finding-status change. Both must wait at the
database serialization boundary. A committed material change must then preserve the closure
record, append invalidation audit and leave `reopen_required`, with old authority ineffective.
Inject a machine-change audit failure and prove both the machine change and invalidation
roll back. Explain why locks acquired only by Python cannot protect against the SQL
credential itself, and how non-login owners' security-definer statement triggers enforce
the server-side rule without accepting caller flags as authority.

## Minutes 85–100: restore and explain remaining gaps

Create a binary backup containing notes, multiple recommendation versions, review outcomes,
requests/receipts, a closure and a reopened state. Restore into a separately named retained
database with PUBLIC CONNECT revoked before loading. Prove both web and verifier identities
cannot connect before trusted security repair. Repair against original structural/security
fingerprints; never replace a receipt to accept drift. Compare every old/new logical row and
original hash, then repeat restricted SQL denials and resume an eligible workflow.
Include the collector and worker mappings and restricted grants in that comparison. Prove
neither can CONNECT before repair, then resume ingestion/publication through those identities
after repair. A same-database-identity restore intentionally recovers its scoped capabilities;
an independently initialized database with a different retained identity must remain denied.

Explain same-cluster restore versus untested cross-host credential reconstruction. Identify
what remains before authentic cloud collection, independent operational authority, response
execution, public hosting or a production SOC claim. None of those later activities belongs
to this exercise.

## Independent scoring and assessment record

The assessor awards 0–4 for each dimension: authority/assignment separation; exact snapshot
and source binding; independent semantic proof and limitations; concurrency/atomic audit;
least privilege and restore; and clear independent predictions/evidence. Maximum: 24.
Each awarded point requires an observed behavior or explanation, not a coverage percentage.

A passing interview requires at least 18/24, no dimension below 2, and no critical failure.
Critical failures include exposing credentials, disabling TLS checks, inventing a successful
receipt, using the production detector as the expected-result oracle, closing a stale or
negative result, bypassing reviewer separation, changing migrations 001/002, resetting a
retained database, using maintenance authority for normal pipeline work, or executing a cloud
action. These rubric choices assess the exercise;
they are not a certification or production-readiness claim.

Record date, assessor, environment/source revision, each prediction and observation,
incorrect predictions and explanations, sanitized artifact locations, per-dimension scores
and unresolved gaps. All human exercises and scores remain **NOT_RUN** until that record is
completed by a human assessor.
