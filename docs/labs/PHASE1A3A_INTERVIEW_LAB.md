# Phase 1A-3A practical interview lab: secure analyst workspace

Human exercise status: **NOT_RUN**. No human score, independent reproduction or mastery claim is
recorded by this document. Automated tests are supporting evidence, not a completed interview.

Complete the exercises without AI assistance. Local source, documentation, PostgreSQL documentation,
tests and handwritten notes are allowed. Predict each result before running the request or test.
Keep an incorrect prediction in the record and explain the correction; do not change an expectation
silently to match the application.

## Preparation and scope

An operator prepares the isolated environment using [Workspace operations](../WORKSPACE_OPERATIONS.md).
Preparation is outside the 90-minute assessment. Use a fresh, explicitly named retained test database
and synthetic evidence selected by the assessor. Provision an analyst, reviewer and auditor with
distinct accounts, plus two cases with different grants. The assessor records which identities may
read each case and which account may append notes before the candidate sees any results.

Choose passwords interactively through the supported owner command. There are no default passwords.
Never place passwords, raw session or CSRF tokens, password hashes, private keys, database credentials
or private dumps in process arguments, transcripts, screenshots, Git or public receipts. Keep any
necessary request captures private and redact their secrets before reporting results. Use aliases
such as `session-before-rotation` in the assessment record.

Run only against the assigned loopback service. Trust the generated certificate explicitly in the
test client; do not use `verify=False`, disable hostname verification or modify an OS/browser trust
store. Do not contact AWS, Wazuh, public hosts or another project's database. Keep retained databases
and evidence; do not reset, drop or recreate them as a troubleshooting shortcut. A controlled fault
belongs only in the assessor's fresh test database, with its restoration in a `finally` block.

Use the virtual environment's Python for commands below: `.venv\Scripts\python.exe` on Windows or
`.venv/bin/python` on Linux. The operator supplies private configuration paths through the documented
workflow. The human status for every exercise below starts as **NOT_RUN**.

## Minutes 0–12: draw the boundary, then prove HTTPS and sign-in

Draw browser → loopback HTTPS application → gate/authentication/data PostgreSQL identities. Mark
where passwords are verified, where case grants are checked, and which credentials the web process
holds. Explain the difference between an account selector and proof of an authenticated session.

With the configured port free, run the real HTTPS helper; it starts and stops its own server:

```text
python scripts/workspace_smoke.py --config <private-runtime-config> --username <assigned-analyst>
```

Enter the password only at the protected prompt. Show the sanitized success receipt. Explain how
the client establishes certificate and IP-name trust without changing a machine trust store. Predict
and then demonstrate failure when using an unrelated local certificate as the client's trust anchor;
do not replace the server certificate or key to manufacture the result.

Try one unknown account and one wrong password through fresh login forms. Both must return generic
401 failures without identifying which credential was wrong. Explain why each attempt needs its own
pre-login cookie and CSRF challenge. In the isolated test harness, consume the account's bounded
attempt budget, recreate the application instance, and show that the throttle persists in PostgreSQL
and no session was created. Do not clear throttle rows to continue; use a separately provisioned
exercise account or wait for the documented window.

Explain the reviewed Argon2id parameters and why unreviewed hash parameters must be rejected before
verification. Describe the two-slot hashing bound and what happens when both slots are occupied.

## Minutes 12–23: session lifecycle and disabled accounts

Before testing, write the expected result for each operation below. Use a private client cookie jar;
record only cookie attribute names, response status and database counts.

1. Inspect the session cookie's `__Host-` name, `Secure`, `HttpOnly`, `SameSite=Strict`, root path and
   absence of `Domain`. Explain what TLS and these attributes do, and which attacks they do not stop.
2. Seed an arbitrary session cookie before sign-in. Successful authentication must replace it with
   fresh random material. A forged role header or cookie must not authorize a request.
3. Rotate a session using its action-specific CSRF form. The previous token must stop working and
   the new token must work. Log out and prove the new token is also unusable.
4. In a fresh fixture, expire a session server-side. Show that an old protected GET returns 303 to
   `/login`; a protected mutation with that invalid session returns 401 and creates no note.
5. Have the operator disable an exercise account. Its existing session must lose access. A fresh
   sign-in with the correct password must still fail generically, with no new session row.

Locate the hash-only session storage. Without printing either value, test that the stored digest
cannot serve as a bearer token. Explain the fixed server expiry, revocation and why stealing the
private all-account runtime configuration is a larger compromise than stealing one restricted DSN.

## Minutes 23–35: assignment, history and exact evidence

As the analyst, list assigned cases. Predict the exact visible case IDs from the assessor's grant
sheet, then compare them with the result. Request an existing unassigned case and a nonexistent case:
both must return the same 404 body. Repeat for a historical revision and a finding belonging to the
other case. Demonstrate an unassigned note POST also returns 404 without changing note/audit counts.

Open an assigned case revision's evidence link. Identify its event key, canonical record hash,
source reference, record index, archive hash and expanded-content hash. Explain what each identifies
and why none authenticates the synthetic source as AWS telemetry. No raw archive download endpoint
is part of this workspace.

The assessor supplies a retained alternative variant for the same event identity. The original
revision's exact event-key/hash pair must remain readable, while substituting the alternative hash
must return 404. Knowing a valid hash elsewhere is insufficient authorization.

Using synthetic late evidence, supersede two parent cases with a merged case. A grant on a parent
must not grant access to the new child. A lineage link must not expose an unassigned endpoint.
Preserve and inspect the old authorized revision instead of replacing it with the latest result.

## Minutes 35–45: prove the PostgreSQL permission boundary

Use the private fixture's restricted connections, not maintenance credentials, for these probes.
Record SQLSTATE or a fixed denial label rather than a driver exception containing connection data.
Keep every probe in a transaction that rolls back, including probes that unexpectedly succeed.

Demonstrate that an authentication identity can retrieve only its mapped account's password hash
through its named function, without printing the hash, and cannot read case tables. Demonstrate that
the data identity can execute assigned-case functions but cannot read password hashes or issue
direct table/sequence writes. Reviewer and auditor identities must read only their assignments and
must fail both SQL and HTTP note attempts, even with a forged analyst header.

Try direct user-role updates, grant insertion/deletion, note mutation, audit insertion, `SET ROLE
csl_ws_owner`, a foreign capability role, and changing the owner's default privileges. All must be
denied. Explain why changing one's own default privileges is a different probe from changing the
owner's privileges. PostgreSQL may permit a temporary table: create a harmless temporary `ws_users`
shadow and show it cannot alter the qualified security-definer identity lookup. Explain the pinned
search path and why `SESSION_USER`, rather than a caller-supplied user ID, fixes identity.

## Minutes 45–57: CSRF, input bounds and escaped content

Get a fresh analyst note form for a current assigned revision. Submit independently predicted
negative requests: missing nonce, another action's nonce, expired nonce, a cross-origin POST and a
duplicate or mismatched Host. CSRF/authority rejections must return 403 with zero new notes/audits.
Submit one valid note, then replay its nonce: the first request appends once; the replay returns 403
and adds nothing. Explain why a valid cookie and `SameSite` alone do not replace a one-use challenge.

Demonstrate malformed/duplicate form fields and an unexpected content type returning 400, an
oversized request body returning 413, and invalid pagination being rejected. Explain the difference
between rejecting an input and trusting a requested role, evidence path or workflow authority.

Save a synthetic note containing `<script>window.labMarker=1</script>` and inspect its rendered HTML.
It must appear as text, with markup escaped and no execution. Repeat with an untrusted source-record
field containing an image/event-handler fragment. Preserve the original canonical evidence; escaping
belongs at rendering. Show the CSP and no-store headers, and explain why CSP supplements escaping.

## Minutes 57–75: stale forms, atomic audit and concurrent notes

Record baseline note and `workspace_note` audit counts. Hold a form for revision 1, then ingest late
synthetic evidence so the case becomes pending. Submitting the held form must return 409 and append
nothing. Run the real worker, then retry the old form against the new machine revision/fingerprint:
it must still return 409. Reload the current form before submitting a new legitimate note. A note
does not approve, verify, close or change the machine assessment.

Use the controlled audit-insert trigger failure demonstrated by the integration fixture, only in
its fresh database. Construct the restricted store before injecting the trigger so the experiment
reaches the atomic note transaction. Explain why injecting a schema fault before application startup
may instead cause schema validation to reject startup. On audit failure, require all three results:
zero new notes, zero new audit events and the nonce still unused. Restore the trigger/function in
`finally`, then retry the same nonce and require exactly one note and one linked audit event. Do not
add a production fault flag or weaken a privilege to make this test run.

Start two restricted connections together using a barrier, not an arbitrary sleep. With two distinct
valid nonces for the same current revision, both notes and both audit events must append. With one
shared nonce, exactly one note/audit pair may commit. Explain the case-row lock, the transaction's
CSRF consumption and why notes must not overwrite each other or advance the machine revision.

## Minutes 75–90: unseen variation and evidence handoff

The assessor chooses one unseen variation: a swapped revision's evidence hash, a stale fingerprint,
an auditor attempting a direct write, concurrent nonce reuse, or a database connection failure during
a mutation. Write a narrow independent test before inspecting the analogous regression test. State
literal expected statuses and exact row-count changes; do not call production authorization logic
to generate the expected answer. Demonstrate the rejection and unchanged durable state. A database
failure must not become an empty successful result or a successful note acknowledgment.

Use the named integration tests as follow-up evidence, not as the source of your predictions:

```text
python -m pytest tests/test_workspace_auth.py tests/test_workspace_security_unit.py -q
python -m pytest tests/integration/test_workspace_security.py -q
python -m pytest tests/integration/test_workspace_https.py tests/integration/test_workspace_restore.py -q
```

Required PostgreSQL tests must run against the explicit isolated service; a skip is not a pass.
Explain why restore must reconstruct trusted ownership/grants and verify the original security
fingerprint after a dump made without owner/privilege metadata. Describe how canonical row hashes
can compare all restored tables without publishing password hashes or session material.

Hand over the commit, Python/PostgreSQL versions, synthetic seed, grant sheet, predicted/observed
statuses, exact count deltas, sanitized commands, fault restoration evidence and remaining failures.
Mark each exercise `PASS`, `FAIL` or `NOT_RUN`, with elapsed time, assistance and assessor identity.
Retain the private evidence separately. Do not represent this exercise as a penetration test of a
production system or proof that a database owner cannot tamper with the store.

## Independent assessment rubric

Score each area from 0 to 4: **0** unrun/unsupported; **1** explanation only or substantial help;
**2** normal operation with an unresolved negative control; **3** independent execution with correct
predictions and diagnosis; **4** correct execution and defense of an unseen assessor variation.

| Area | Required observable evidence | Score/status |
| --- | --- | --- |
| TLS and authentication | Explicit certificate trust; generic failures; persisted throttle; reviewed bounded hashing | NOT_RUN |
| Session lifecycle | Fixation replacement; hash cannot act as bearer; rotation/logout/expiry/disablement enforced | NOT_RUN |
| Assignment and evidence | Indistinguishable denied reads; exact revision/variant match; no inherited child grant or lineage leak | NOT_RUN |
| SQL least privilege | Actual restricted-login denials; no owner/foreign-capability escalation; safe temporary shadow | NOT_RUN |
| CSRF and request bounds | Action/expiry/replay/Origin/Host checks; bounded malformed requests; unchanged rejected-write counts | NOT_RUN |
| Escaping and provenance | Note/source HTML escaped; originals preserved; headers inspected; synthetic authenticity limits stated | NOT_RUN |
| Atomicity and staleness | Pending/revision rejection; audit fault rolls back note and nonce; successful repaired retry | NOT_RUN |
| Concurrency and independent test | Distinct nonces append twice; shared nonce once; hand-written unseen expectation and durable effects | NOT_RUN |

Pass requires at least **26/32**, every area at least **3**, all required observations and no hard
fail. A second operator's reproduction is separate evidence. An assessor records a result only
after observing the work; the checked-in human assessment remains **NOT_RUN** until that occurs.

Hard fail: using unauthorized resources or credentials; disclosing secrets; bypassing TLS trust;
deleting retained evidence/databases; leaving an injected fault behind; weakening assertions or
security controls to hide a failure; fabricating results; treating synthetic hashes as authenticated
AWS evidence; or describing an analyst note as approval, verification, closure or response authority.
