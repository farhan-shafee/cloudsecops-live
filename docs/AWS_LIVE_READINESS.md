# AWS live readiness: owner decision packet

Phase1B-AWS-3 supplies [fixed fixture-only workers](architecture/AWS_FIXED_WORKERS.md)
and explicit role/session/MFA consistency contracts. It does not supply credential
delivery, actual temporary issuance or network-enabled live assembly. The owner's
November4 audit is dated input: separate metadata-only inspection from future
collector and verifier identities. The existing inspection role must not receive
evidence-object reads. Exact live policy bytes and current effective authorization
are unverified; see the [source difference report](PHASE1B_AWS3_PERMISSION_DIFFERENCES.md).

Before a new read-only run, privately approve current account/role/immutable RoleId,
MFA issuance evidence, short-lived expiry, session owner/custody, fixed APIs, numeric
budgets, time window and stop responsibility. Do not reuse a root/admin IAM-user
connection or infer session issuance from policy simulation. The dated lack of trails
and buckets does not authorize creating them. Historical budget alerts are not caps
or spending authorization. Prior one-time inspection permission does not authorize a
new session. Provisioning, test activity, collection/authentication and cleanup each
need their own explicit scope and approval.

Phase1B-AWS-2 prepares [offline runner controls](architecture/AWS_SECURE_RUNNER.md), not execution permission. Before read-only inspection the owner still needs an exact approved non-root temporary role/immutable ID, actual issuance/expiry and private delivery, effective IAM/boundary/SCP review, a fixed trusted worker assembly, verified CLI2.37.11 artifacts and bounded internal calls, private receipts and a stop/recovery owner. No credential is read here. The earlier ChatGPT AWS connection must not be assumed suitable. Source authentication, provisioning, test activity and cleanup remain separate permissions.

Status: **NO-GO for live access or provisioning**. Phase1B-AWS-1 prepares offline code.
There is no live collection command or authenticated-source constructor. Completing this
packet does not itself authorize AWS access. Keep the signed decision record, resolved
identities, account details and receipts privately outside Git; commit only sanitized
references. Do not paste credentials into a document, command argument or chat.

## Four separate permissions

| Permission | Owner must explicitly authorize | Does not authorize |
| --- | --- | --- |
| Read-only inspection | Named dedicated account, region, role/session, fixed APIs, source allowlist, time window and request/byte limits | Provisioning, changing trails, test-actor activity or deletion |
| Provisioning | Reviewed source/tree, effective permissions, state custody, resources, retention and approved cost exposure | Test activity, collection outside scope or cleanup |
| Test activity | Exact read-only exercise, named actor, event count/window, expected benign purpose | Containment, generic commands or unrelated resource actions |
| Cleanup | Exact inventory including all versions, hold review, backup/restore proof, responsible operator and time | Premature evidence deletion, broad account cleanup or removal by runtime roles |

All four are currently **UNAPPROVED**. PR review or offline test success cannot imply any
of them. No real identifiers or resolved resource names are required in this public file.

## Required private decisions and evidence

| Decision | Required record before live work |
| --- | --- |
| Account authority | Owner confirms dedicated authorized sandbox, permitted organization/account policies and no production links. Read-only costs still require approval. |
| Region and window | One selected commercial region (source proposes `us-east-1`), UTC start/end, maximum calls/pages/bytes and immediate stop authority. |
| Trusted identities | Exact role ARN plus immutable role unique ID, owner of each temporary session, expiry/MFA policy and distinct collector/verifier/test/provisioner/cleanup roles. No root or repository keys. |
| Existing CloudTrail | Inspect existing account and organization trails, home region, logging status, selectors, delivery errors, bucket/prefix, integrity history and duplicate-copy charges. Do not create a second trail by assumption. |
| Effective authorization | Owner reviews identity policies, trust policies, boundaries, session policies, SCPs, resource policies and regional conditions. Static Terraform shape/schema is not proof of effective IAM. |
| Cost estimate | Save current regional SKU/calculator evidence, expected retained current/noncurrent GB, digests, state, receipts, requests/pages/retries and transfer. Approve maximum exposure and stop threshold. No free-tier assumption. |
| Billing notification | Named recipient privately confirmed, delivery tested, billing visibility delegated and delayed/missing-alert response defined. Alerts are not spending caps; no budget is configured here. |
| Retention and holds | Choose retention/hold policy and ongoing storage funding. Current source has no expiry and preserves versions indefinitely; the old30-day model is a pricing window, not deletion authority. Reconcile this explicitly before resource creation. |
| State custody | Private encrypted state, exclusive writer/locking design, recovery owner, backups, tested restoration and private access logs. No state, plans or private tfvars in Git. Backend selection is not implemented. |
| Evidence custody | Private access-controlled originals, CLI stdout/stderr, tool provenance, exact-version observations and signed-validation receipts, with sanitized public summaries. Define loss/corruption handling and retention. |
| Cleanup ownership | Separate named authority, exact deletion inventory/current and noncurrent versions, hold release, retained receipts, review of `prevent_destroy` changes and responsibility for ongoing charges. Runtime identities have no cleanup power. |
| Stop and recovery | Stop on wrong identity/region/owner, expiry, unexpected source, digest gaps, changed versions, missing membership, denied TLS, budget uncertainty, new database crash or loss of local capacity. Preserve evidence; revoke the affected session through the authorized owner process. |

## Pricing and operational readiness

Public [CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/) and
[trail-cost guidance](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-trail-manage-costs.html)
were checked on2026-11-03: first-copy management delivery differs from additional-copy,
data/Insights/Lake charges. S3 storage and requests still cost money. The current
[S3 pricing page](https://aws.amazon.com/s3/pricing/) is region-dependent and dynamic;
this review did not capture a complete current regional SKU quote. **Current owner-specific
estimate remains BLOCKED**, not inferred from an older model. The illustrative planning
envelopes in [cost and safety](architecture/CLOUD_COST_AND_SAFETY.md) are not quotes or caps.

Retained versions, digests and receipts can grow without bound under current indefinite
preservation. Resolve funded retention versus reviewed cleanup before provisioning; do
not add automatic expiry merely to satisfy a target price. No compute, NAT, RDS, data
events, Insights, Lake or hosted SIEM is in the prepared footprint.

Wazuh remains **NO-GO**: measured Windows available physical RAM5.588–5.900GiB versus
required12GiB. No limit changes, unrelated workload shutdown or substitute paid host is
authorized. The historical PostgreSQL SIGSEGV after shared-memory exhaustion remains
unexplained. Sequential acceptance is supported; it is not proof of an engine fix.
The2026-11-04 local sequential attempt also stopped on shared-memory allocation failure
at61/64MiB used, with2,438retained test databases. No new native crash/restart occurred.
Local full-suite readiness is now blocked until an owner-approved capacity/retention
decision; isolated CI results do not repair this workstation's resource condition.

## Smallest next permission request

After this PR is reviewed, request a separately bounded **read-only readiness inspection**
using an owner-provided temporary session, exact identity/region and explicit API allowlist.
Confirm caller identity, existing trail configuration/status and approved archive metadata
only, with owner-reviewed request/cost limits and no provisioning or test exercise.
The live client-assembly/operator entry point is a future separately reviewed change.
It must enforce cancellation/deadlines across DNS, response headers and individual
chunk-header reads: ordinary SDK connect/read timeouts and body byte limits do not
prove a hard operation wall-clock deadline. Process isolation may be necessary.
Do not use this milestone's tests or fake receipt as permission to execute it.

Real-source authentication additionally needs verified supported AWS CLI installation,
original-location access, complete standard/backfill chains, exact expected membership,
validated decompressed hashes and bracketed source-version continuity. `validate-logs`
does not select a VersionId. Conflicting, missing, delayed or changed evidence stays
untrusted. No synthetic approval or closure authority transfers to AWS-shaped data.
