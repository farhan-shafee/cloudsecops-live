# Offline AWS foundation operations

Status: Phase1B-AWS-0, 2026-11-03. This runbook operates only on generated local data and
fake services. It grants no AWS sign-in, credential discovery, live API, infrastructure,
Wazuh, deployment, paid-service or response permission. The separate
[source architecture](architecture/AWS_OFFLINE_SOURCE.md) records the contracts and caveats;
the [infrastructure README](../infra/aws-offline/README.md) describes source-only Terraform.

## Deterministic local demonstration

Use the project's already prepared Python environment, from the repository root:

```text
python -m cloudsecops_live.integrations.aws_cloudtrail
```

This command creates three generated AWS-shaped management records in memory, uses
`DemoTransport` and `MemoryLedger`, assesses controlled digest observations, and prints an
allowlisted JSON summary. It has no AWS client or network configuration hook. It does not
read AWS configuration, load credentials or persist a checkpoint. The existing synthetic
commands remain separate and reject these raw AWS-shaped envelopes.

Expected behavior, rather than a captured acceptance receipt:

| Public field | Expected value |
| --- | --- |
| `source_kind` | `aws_shaped_unverified` |
| `authenticated` | `false` |
| `unique_event_count` | `3` |
| `object_count` / `listing_pages` | `1` / `1` |
| `duplicate_event_count` / `conflict_count` | `0` / `0` |
| `state` | `pending_source_authentication` |
| `controlled_digest_consistency` | `true` |
| `authentication_gate` | `AWS_AUTHENTICATION_UNAVAILABLE` |
| `trusted_findings_available` | `false` |

Repeated execution with unchanged code and Python/zlib runtime produces the same public summary and batch ID. Different gzip implementations can preserve identical content with different archive hashes; that is a byte-provenance distinction, not an authentication change. The
ID is a content/configuration binding, not AWS proof. The summary omits resolved account
IDs, access keys, role/trail ARNs, bucket names, object paths, raw events and bytes. A
successful exit means the offline exercise completed; the explicit authentication gate
still blocks trust. Do not replace the pending state with a verified label for a demo.

## Local checks and acceptance record

These credential-free commands inspect local source or run controlled tests:

```text
python -m pytest tests/test_aws_parsing.py tests/test_aws_collection.py tests/test_aws_validation.py tests/test_aws_offline_boundary.py tests/test_aws_adversarial.py
python scripts/check_terraform.py
python -m pytest tests/test_terraform.py
```

Run broader unit and PostgreSQL acceptance sequentially under the established project
resource limits. Do not run competing database suites or repeat memory-exhaustion stress.
Use the existing [recovery runbook](FAILURE_AND_RECOVERY.md) for a real new backend crash:
stop, preserve diagnostics and report the event; do not relabel a restart as a fix.
The offline AWS module needs no PostgreSQL service. Its separate database-boundary test
can be included by the established integration harness; it is not a live AWS test.

**Final acceptance record:** see [the validation record](PHASE1B_AWS_OFFLINE_VALIDATION.md) and new PR/delivery report for the exact
commit/tree, runtimes, executed commands, unit/integration counts, per-module actual
branch coverage, format/lint/types, secret/dependency/build checks and exact-head remote
CI/review outcomes. Local acceptance is recorded in that validation document; external
publication results belong to the PR and delivery report. No independent human reproduction
or effective IAM result is claimed.

Terraform is unavailable locally. `terraform fmt`, initialization, provider-schema
validation, provider installation/lock verification, plan, apply and destroy are
**NOT_RUN**. The standard-library source checker is a closed structural allowlist with
mutation tests; its pass is not Terraform/provider validation or an evaluation of effective
IAM. No real `tfvars`, state, saved plan or credentials belong in the tracked source folder.

## Controlled failure practice

Use temporary local fixtures or fake transports. Generate obviously fictional
AWS-shaped identifiers in memory; do not paste real identifiers/credentials into tests,
captured output, issues or commits. Preserve the candidate's prediction and the sanitized
actual result. The no-AI [practical lab](labs/PHASE1B_AWS_FOUNDATION_INTERVIEW_LAB.md)
provides independent tasks and scoring.

| Controlled fault | Required interpretation |
| --- | --- |
| Wrong account, Region, role unique ID, assumed-role ARN or expired identity observation | Stop before a new S3-shaped operation; role-name equality alone is insufficient. |
| Failed/malformed page, missing marker component, repeated pair, page/object budget exceeded | No complete poll and no checkpoint advancement; never substitute an empty successful scan. |
| Version history, delete marker or `null` VersionId | Current strict rejection. Do not silently skip history to make a poll succeed. |
| Returned reference/owner mismatch, short/long stream, stream failure or current-version drift | Reject the staged poll with a fixed error; do not commit partial evidence. |
| Earlier object changes while a later one is read | Final all-object current-version recheck rejects the poll; later changes remain possible after the interval. |
| Identical event repeated versus changed unknown field for the same identity | Count the identical delivery as a duplicate; preserve changed complete records as conflicts. |
| Stale CAS generation, interruption before commit, replay after a committed lost acknowledgement | Reject stale/partial commit; exact committed replay returns the retained in-memory batch without another transport call. Process restart durability remains absent. |
| Missing/delayed/invalid/contradictory controlled digest observations | Pending, invalid or conflicting assessment as appropriate; no path authenticates the source. |
| All controlled checks marked valid, local hashes correct, exact member provided | Consistency can pass, but state stays pending and `require_authenticated` still raises `AWS_AUTHENTICATION_UNAVAILABLE`. |
| `authenticated=true`, forged receipt JSON or raw AWS input sent to synthetic CLI/storage | No promotion into accepted synthetic evidence, trusted findings or human closure. |

`listing_complete=true` describes the bounded supplied poll, not a frozen S3 snapshot.
Before/after/final current-version checks observe continuity across a finite interval,
not forever immutability. `MemoryLedger` is an atomic in-process reference, not the
durable synthetic database checkpoint. A cached replay does not revalidate current AWS
identity or state.

## Private evidence and public summaries

The current demo uses no private source. A future authorized live implementation must
define custody and retention before gathering real evidence. A future private receipt
must bind at least the following material without exposing secrets:

| Private material | Required binding or limitation |
| --- | --- |
| Scope and caller observations | Approved account/Region, exact role ARN and unique role ID, trail, original bucket/prefixes, genuine caller account/ARN/UserId, observation time, client Region and session-expiry provenance. STS itself supplies neither Region nor expiry. |
| Listing evidence | Original service requests/responses, both continuation markers, all pages including versions/delete markers, parsing success, budgets, start/end times and explicit completion/reconciliation scope. |
| Acquisition evidence | Exact bucket/key/VersionId and returned VersionId/owner, object size and metadata, bounded original bytes, archive/content hashes, retrieval times and version observations around the whole collection/validation interval. |
| Digest evidence | Original standard/backfill digest bytes and locations, current signature/algorithm metadata, backfill-generation metadata, relevant regional public keys/fingerprints and coverage/gaps. |
| Supported validation execution | Reviewed CLI version/provenance, exact bounded invocation/scope, complete stdout/stderr and exit status, per-file valid/invalid results, exact membership and unresolved intervals. |
| Local processing evidence | Exact code/tree and parser/canonicalization versions, complete record hashes/references, duplicates/conflicts, retry/failure history, checkpoint/store guarantees and any custody transfer. |

Do not retain secret access keys, session tokens, credential files, authorization headers
or debug traces containing credentials as proof. Raw CloudTrail records can contain access
key IDs, source IPs, principals and sensitive request details even when no secret key is
present. Protect raw source, configuration, state, plans and private receipts; publish
only reviewed aliases, counts, version/hash references that are safe to disclose, statuses,
scope labels and explicit gaps. A checksum of a locally authored receipt proves neither
AWS origin nor independent operator authority.

The public allowlist is separate from private storage. New output fields require a
specific disclosure review; redacting a few known secret strings from arbitrary raw JSON
is not an adequate public-output contract. Real private receipts and an adapter to retain
them do not exist in this milestone.

## Future live gates: reference only, not authorization

No live AWS command is required by this runbook or lab. Operation names below describe
future design work; they are not instructions to sign in, configure credentials or run a
command now. Obtain a separately explicit authorization naming the account, identities,
Region, resources, finite exercise window, spend, retention and permitted operations
before any dependent access.

1. Review tooling provenance, effective identity/resource/organization policies, short-lived
   role custody and expected role unique IDs. A future genuine `GetCallerIdentity` must
   match the approved scope before archive reads. Separately address session expiry and
   regional-client provenance. No broad administrator fallback is acceptable.
2. Resolve Terraform/provider compatibility, private state locking/encryption/recovery,
   exact provisioning/cleanup permissions, the saved plan, current regional pricing,
   existing/organization trails, duplicate-copy costs and notification/retention ownership.
   Structural source checks satisfy none of those live gates.
3. Implement and independently test the bounded real transport, full history/delete-marker
   policy, drift/reconciliation, original-version custody, errors and durability. AWS CLI
   pagination tokens and S3 service marker pairs must not be mixed.
4. Implement supported original-location validation, both standard/backfill chains,
   signature/public-key handling, complete per-file evidence and exact imported membership.
   `validate-logs` has no VersionId switch and does not validate local files: reconcile
   the pinned version and uncompressed-content hash explicitly. Exit zero alone is not
   sufficient. [AWS supported command](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/validate-logs.html)
5. Establish a separate authenticated-real contract and independently enforced ingestion,
   findings, case/review and closure boundaries. An approved reviewer cannot turn a local
   consistency result into AWS source authenticity. Demonstrate required negative paths
   before enabling any stronger claim.
6. Reassess SIEM feasibility and record actual end-to-end persisted/query evidence only in
   a separately authorized milestone. Wazuh remains **NO-GO**: six latest available-RAM
   samples were 5.588–5.900 GiB against the 12 GiB gate. WSL uses the same host RAM. No
   install, resource change or rented substitute is approved by this offline work.

CloudTrail digest hashes cover uncompressed content; a raw gzip SHA-256 is a different
domain. Backfill and delayed delivery require explicit coverage reconciliation. None of
the current controlled enums executes that cryptography. See the sourced
[authenticity design](architecture/AWS_OFFLINE_SOURCE.md) before proposing implementation.

The historical PostgreSQL SIGSEGV cause remains unproven. Neither subsequent sequential
acceptance nor this demonstration proves a native PostgreSQL fix. All human lab/mastery
assessment remains **NOT_RUN**.
