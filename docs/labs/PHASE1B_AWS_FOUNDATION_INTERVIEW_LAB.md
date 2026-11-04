# Phase1B AWS offline foundation: practical interview lab

Human assessment status: **NOT_RUN**. Every exercise, panel, score and independent human
reproduction below is **NOT_RUN**. Software tests and the deterministic demo do not award
human points, live AWS experience, source authenticity or production readiness.

Complete the cold exercises without AI assistance. Local source, documentation and
handwritten notes are allowed. The assessor selects faults independently, records the
expected outcome before execution and observes the candidate's reasoning and changes.
The candidate predicts status, state, side effects and stop conditions before each run,
then preserves wrong predictions and corrections rather than editing the record afterward.

## Preparation and boundaries

Preparation is outside the proposed 100-minute exercise. Use an isolated local checkout
and the project's prepared Python environment. The assessor records exact commit/tree,
runtime, local test commands and selected fault seeds. Use only generated fictional
AWS-shaped data, temporary local fixtures and fake transports. Keep the tracked example
configuration placeholder-only; generate account/key-shaped values in memory as the
existing test helpers do. Do not borrow real data or credentials for realism.

Read [offline operations](../AWS_OFFLINE_OPERATIONS.md),
[source architecture](../architecture/AWS_OFFLINE_SOURCE.md),
[Terraform source limitations](../../infra/aws-offline/README.md) and
[the implementation plan](../PHASE1B_AWS_OFFLINE_PLAN.md).
This lab requires no AWS command, sign-in, SDK, credential inspection, real event
collection, Terraform provider download/plan/apply/destroy, PostgreSQL provisioning,
Wazuh install/query or paid service. It grants none of those permissions. Do not weaken
the unconditional authentication gate or route these fixtures into synthetic storage.

The only demonstration command required is local:

```text
python -m cloudsecops_live.integrations.aws_cloudtrail
```

Run selected local tests as needed. Full regression/database acceptance belongs to the
supported sequential harness, not concurrent stress. A new native database crash stops
the exercise and requires preserving diagnostics. No reset/drop of retained stores or
Docker/WSL resource adjustment belongs in this lab.

## Minutes 0–15: draw the trust boundary

Draw generated gzip bytes → bounded AWS-shaped parser → fake collection protocol → staged
batch → in-memory CAS checkpoint → controlled digest assessment → blocked authentication
gate. Separately draw the existing synthetic parser/database/reviewer/verifier/closure
path. Identify the missing adapters; do not connect them with a trust claim.

Run the demo twice and compare its public output. Explain the three unique records,
pending state, controlled consistency result, `authenticated=false`, unavailable
authentication gate and absence of trusted findings. Inspect the public allowlist and
explain why it excludes account IDs, access key IDs, ARNs, locations and complete events.
Describe a private receipt's purpose without copying private material into the report.

Explain all five source classes: existing synthetic, implemented AWS-shaped unverified,
future pending real, unavailable authenticated real, and invalid/conflicting. Explain why
the demo's pending state does not mean a real AWS source was acquired. Predict and prove
that a forged `authenticated=true` object and a consistent controlled assessment both fail
`require_authenticated`. Predict raw AWS-envelope rejection by the synthetic CLI.

## Minutes 15–35: preserve evidence before deriving labels

Write a new local test proving that an unknown field changes the complete-record hash
without changing the scoped identity. Show the immutable archive bytes, decompressed
bytes, separate SHA-256 values, canonical record and record index. Explain why a
recompressed gzip can preserve content while changing archive bytes, and why AWS digest
content comparison cannot use the archive hash.

The assessor supplies one nested NUL key/value, one duplicate-key or nonfinite-number
input, and one resource-limit boundary. Predict rejection and prove a fixed error without
raw payload disclosure. Demonstrate exact-limit acceptance versus one-over rejection.
Do not relax the parser or derive expected results by calling its own internal helper.

Explain matching numeric recipient account, commercial Region, UUID event ID and
Management category checks. Show a general management operation remains representable.
Compare a coherent assumed-role session, an unsupported actor and an inconsistent session.
Prove that unsupported actor details remain hashed evidence, and that the observed actor
need not be the configured collector role. Explain event-time versus session-creation
ordering and why session correlation establishes neither AWS origin nor benign intent.

## Minutes 35–55: complete a bounded poll

Use a fake two-page service listing with a key/version-ID marker pair. Record each
requested pair and prove that all pages are staged before checkpoint commit. The assessor
chooses a malformed response, a missing marker component, a repeated pair or a budget
exhaustion. Predict the fixed failure and prove no partial commit. Explain why an error is
not an empty successful scan and why the service marker pair differs from AWS CLI
`NextToken` pagination.

The assessor changes the expected role unique ID while leaving its name unchanged, then
expires the observed caller session. Prove rejection before the next S3-shaped operation.
Explain which fields a future genuine STS response supplies, and which Region/expiry
observations need another trusted source. A fake matching observation is not IAM proof.

Present an older object version and a delete marker. Prove current strict rejection and
explain the deliberate acceptance gap. Do not fix the exercise by discarding those entries.
Explain why even a complete supplied poll is not an atomic S3 snapshot.

## Minutes 55–70: bind retrieval, replay and conflicts

The assessor selects a returned-version/owner mismatch, a short/extra stream byte, a read
failure or a stream-close failure. Prove exact bounded reading, sanitized failure, stream
closure where applicable and zero checkpoint advancement. Show original references and
both hash domains survive a successful read.

Change an earlier object's current version during a later object's retrieval. Explain and
exercise the final all-object recheck. State the finite interval it observes and why it
cannot promise forever immutability after the check.

Deliver the same event twice, then change an unknown field under its identity. Explain
the separate unique-identity, duplicate-delivery and conflicting-variant counts; preserve
each source object. Exercise exact committed replay, changed-scope checkpoint reuse and
a stale CAS generation. Explain lost acknowledgement versus interruption before commit.
Demonstrate that replay can avoid another fake transport call, while process restart loses
this in-memory ledger. Do not claim database durability.

## Minutes 70–90: refuse plausible authenticity claims

The assessor supplies controlled outcomes for a missing/delayed digest, invalid signature,
broken standard chain, broken backfill chain, missing member and contradictory exact
member hashes. Predict pending, invalid or conflicting results and prove the authentication
gate remains closed. Then provide internally consistent valid observations and show that
consistency can pass while authenticity stays unavailable.

Explain the future supported CLI obligations from the primary sources linked in the
architecture: online validation at original S3 locations; only referenced members;
independent standard/backfill chains; exact per-file scope and coverage; regional key and
fingerprint selection; metadata custody; delivery-time versus event-time intervals; and
uncompressed content hashes. Explain why exit zero, empty output, file naming, local
checksums and authored receipt JSON are insufficient.

Identify the critical binding gap: AWS digest members do not carry VersionId and supported
`validate-logs` has no VersionId switch. Explain what an independently retained pinned
retrieval, exact signed member and observed continuity must establish before a future
authentication claim. Do not implement or execute a live command as the answer.

## Minutes 90–100: give an accurate readiness handoff

Inspect the Terraform JSON design and local structural checker. Name the distinctions
between source policy checks, Terraform/provider validation, effective IAM and live service
delivery. In a temporary source copy, select a privilege-widening or removed-retention-guard
mutation and demonstrate checker rejection. Do not download a provider or invoke Terraform.
Record provider/schema/plan/apply/destroy evidence as **NOT_RUN**.

Explain separate collector, verifier, test actor, provisioning and cleanup authority;
private state/plan/receipt custody; no automatic evidence deletion; and why versioning or
`prevent_destroy` is not administrator-proof WORM or a spending cap. Name the remaining
current-price, identity, policy, retention, delivery and teardown gates before live use.

State Wazuh **NO-GO**: six latest availability samples were 5.588–5.900 GiB, below the
12 GiB readiness gate, with WSL sharing host RAM. No rented fallback or installation is
authorized. State that the historical PostgreSQL SIGSEGV cause is unproven and that
sequential acceptance is not proof of a native-engine fix. End with a precise offline
capability statement and the next missing evidence, without claiming real AWS/SIEM work.

## Independent 100-point rubric

Award points only after observing the human perform the task and inspect the retained
prediction/result record. A test-suite pass, this document's existence or an unobserved
written answer earns no practical credit. The assessor chooses at least one new fault;
repeating a memorized test without diagnosis does not satisfy its criterion.

| Capability | Points | Observable scoring anchors | Human result |
| --- | ---: | --- | --- |
| Trust and source separation | 15 | 5: correct five-class boundary; 5: demonstrate unconditional trust rejection and synthetic separation; 5: explain sanitized output and private custody. | NOT_RUN |
| Bounded parser and complete evidence | 20 | 5: distinct original/content/canonical domains; 5: independent unknown-field test; 5: malformed/NUL/nonfinite and exact-boundary proof; 5: scope/session/category reasoning without dropping unsupported actors. | NOT_RUN |
| Identity and complete pagination | 15 | 5: role unique-ID/expiry rejection before reads; 5: correct paired-page traversal and failure/no-commit proof; 5: history/delete-marker rejection and snapshot limitation. | NOT_RUN |
| Exact retrieval, continuity and conflicts | 15 | 5: bounded exact stream/ref/owner checks; 5: final earlier-object-drift rejection with interval caveat; 5: independently demonstrate duplicate versus conflicting full-record evidence. | NOT_RUN |
| Retry and checkpoint semantics | 10 | 5: classify transient retries and exhaustion; 5: stale CAS/interruption/replay demonstration with no process-crash durability claim. | NOT_RUN |
| Digest authenticity reasoning | 15 | 5: missing/invalid/contradictory outcomes; 5: consistent observations still blocked; 5: supported CLI membership/hash/chain/version-ID gap explained without invented proof. | NOT_RUN |
| Infrastructure and operational honesty | 10 | 4: source-only policy mutation and provider/effective-IAM distinctions; 3: private receipt and live authorization gates; 3: accurate Wazuh/database/retention/cost limitations. | NOT_RUN |
| Total | 100 | No human score is recorded until the complete observed assessment. | NOT_RUN |

Suggested qualification: at least 80/100, at least half the points in every row, and no
critical boundary failure. Contacting live AWS, using real credentials/data, bypassing
authentication to gain findings/closure, silently discarding contradictory evidence or
claiming an unperformed live/provider/SIEM result stops assessment and requires explicit
remediation before reassessment. A score never authorizes a later live milestone.

## Assessor receipt and interview statement

Retain exact source revision/runtime, assessor identity/independence limits, timestamps,
fault seeds, pre-run predictions, selected commands, sanitized results, resulting local
changes, diagnoses and per-row reasons privately. Publish only a reviewed summary and
explicit scope. Do not retain credentials or full sensitive request captures. Update human
statuses only after the observed exercise; all checked-in human results remain **NOT_RUN**.

An accurate current statement is: "I built an offline AWS-shaped evidence boundary with
bounded parsing, fake versioned collection, exact byte/record provenance, staged in-memory
checkpoint semantics and a deliberately unavailable authenticity gate. Supported real AWS
validation, durable acquisition and SIEM integration remain future work."

Do not replace that statement with "I validated CloudTrail from AWS," "I proved effective
IAM," "I fixed the native database crash," or "I deployed Wazuh" on this milestone's evidence.
