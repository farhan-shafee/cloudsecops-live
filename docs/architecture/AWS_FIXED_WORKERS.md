# Fixed offline AWS workers and identity readiness

Phase1B-AWS-3 adds three named worker facades under `integrations/aws_readiness`.
They execute fictional, bounded response tapes under the existing AWS2 process
supervisor. They create no SDK clients, assume no role, discover no credentials and
make no AWS request. There is no live CLI or authenticated-source constructor.

Starting protected main is `58d008c4744c7f2f7560bddc6fcdc19516ef6298`, tree
`2d1d8c37a2a9a1094f74b17046ffcdb5e7fcc0cc`. This source milestone changes no SQL
migration, retained database, container, credential, deployment or GitHub ruleset.

## Executable boundary

| Named facade | Fixed worker | Permitted fixture observations |
| --- | --- | --- |
| `run_posture_inspection` | `inspect_posture` | Exact caller/role metadata, explicitly requested inline policy names, attached-policy counts, trail/bucket inventory and account Block Public Access |
| `run_archive_collection` | `collect_archive` | Existing exact-version archive collection and bounded AWS-shaped parser |
| `run_archive_verification` | `verify_archive` | Separately identified fixture reacquisition with independently supplied ordered content hashes |

Each facade closes over one literal private worker reference and a package-derived
import root. Requests contain no worker selector, module, import path, command,
endpoint, callback, client or credential factory. The generic AWS2 supervisor remains
an internal trusted-code mechanism; this registry does not expose it as a dispatcher.

Requests are immutable canonical JSON, limited to512KiB,64 tape entries,24 nesting
levels and30,000 nodes. They contain exact expected/observed identity and issuance
metadata, a fixed purpose, UTC reference time, reducible `BudgetPolicy`, and data-only
responses/fault labels. Archive requests additionally require the exact existing
`AwsScope` and checkpoint; verifier requests require expected content hashes. Secret
and token fields are prohibited. The access-key identifier in issuance metadata is
private and is never returned in public receipts. Workers construct one literal
fictional credential object; requests cannot deliver real secret/token material.

Fixed code determines the call sequence. A tape cannot select another operation:
unsupported operations, unexpected parameters, order changes, unused responses and
error-shaped/non200 responses reject. Counts include failed attempts and retries.
The shared policy caps calls/pages/operations/bytes/retries/elapsed time; it cannot
raise AWS2 ceilings. The outer parent watchdog independently bounds stalled work,
cancellation and owned-process cleanup. Its original scheduling/OS and Linux trusted
process-group limitations still apply; this is not a hostile-native-code sandbox.
The child retains AWS2's numeric-loopback-only socket guard and stripped environment.

Posture reads only eight fixed operation types: STS identity, four IAM role metadata
operations, CloudTrail trail inventory, S3 bucket inventory and S3control account
public-access configuration. Pagination is complete and bounded; empty inventory is
valid. Discovered names never expand into object reads, managed-policy downloads or
trail/bucket configuration reads. Policy contents are observed, not evaluated.
Unknown inline names, attachments or a permissions boundary produce an explicit
`owner_review_required` state. No posture result establishes effective permissions.
Budget, Organizations, root MFA and administrator-user policy inspection are outside
this worker; the earlier29-call owner audit is not rerun or fully reproduced.

Archive workers retain account/region/role, bucket-owner, prefix, exact version,
before/after current-version continuity, complete-record conflicts and separate
compressed/content hashes. Collection conflict state survives the readiness wrapper.
The verifier independently reacquires the fixture data under a distinct purpose and
compares content hashes; it does not validate signed digests, assess incident truth,
write machine receipts or acquire the existing synthetic verifier's SQL authority.

## Temporary-session assembly

`assemble_session` takes separately declared `ExpectedIdentity`, `SessionIssuance`,
`StsObservation`, one explicit static `botocore.credentials.Credentials`, and UTC time.
It requires account, `us-east-1`, exact approved IAM/assumed-role ARNs, immutable
`AROA` RoleId and matching STS UserId/session name. Root/IAM-user/admin-shaped roles,
wrong identities, missing/expired/future leases, long-lived key shapes, default or
refreshable credential objects, unknown provenance and absent MFA observations reject.
Issuance must be positive and at most one hour; current STS/MFA observations must be
within60seconds and inside the issuance interval. Checks repeat during dispatch.

Collector and verifier each require distinct same-account posture and complementary
archive-role bindings, labeled by purpose. Role name reuse cannot establish separation;
ARN and immutable RoleId reuse reject. Posture requires no invented trail or bucket,
so the dated observation of an empty account is representable without fabricating
archive resources. Future resources/roles remain subject to separate owner approval.

The independently declared ASIA access-key identifier must match the supplied static
credential. A private snapshot binds key, secret, token, method and optional account
ID. Added instance callbacks or later component changes reject without invoking a
provider or refresh method. Existing injected SDK transports now also check these
static components before/after service and body reads. Neither module resolves any
default session or accesses profiles, environment credentials, IMDS or credential files.

These contracts check consistency of supplied observations. GetCallerIdentity does
not report region, issuance, expiry, MFA, policy privileges or which credential produced
an independently supplied observation. A provenance string or MFA=true is not proof.
An innocently named role can still be administrative. Actual issuance, non-root session
custody, MFA enforcement and effective IAM require future independently observed
acceptance. The current owner/OS and installed project code remain trusted.

## Least privilege and static source difference

See the exact [permission difference report](../PHASE1B_AWS3_PERMISSION_DIFFERENCES.md)
and [standalone inspection template](../../infra/iam-readiness/README.md). Inspection
has metadata-only authority; it has neither `GetObject` nor `HeadObject` (the latter
also requires S3 object-read authority). Collector and verifier remain separate.

The sole Terraform policy delta adds collector `cloudtrail:GetInsightSelectors` on
the exact configured trail with `us-east-1` condition, matching the existing SDK call.
No role/resource/trust/provider/lock/retention policy is changed. Existing runtime
role-principal trusts lack MFA conditions; they differ from the dated named-user/MFA
audit-role observation. This gap is recorded, not silently fixed or deployed. The
actual audit inline-policy bytes were not supplied, so no exact live policy diff or
effective authorization claim is possible. The audit role is not imported or widened.

## Trust, privacy and live stop conditions

Every worker/public budget/session receipt remains `authenticated=false`, with
`trusted_findings_available=false` and `closure_available=false`. No SDK success,
hash match, policy template or prepared CLI2.37.11 receipt can enter trusted findings,
recommendations or case closure. Machine/source state remains distinct from process
completion and fixture consistency. Raw role/account names, session identifiers,
policies, request bodies and credentials are omitted from worker public output.

The supplied November4 account observations are dated owner input, not newly verified
facts. Resolved identifiers and the source receipts remain private. The current lack
of approved trails/buckets prevents archive readiness; the existing inspection role
must not gain evidence-object access merely to make collection work.

Before a live milestone: obtain explicit bounded read-only authorization; approve
exact current role/RoleId and actual temporary issuance/MFA/custody; evaluate effective
policies/trusts/boundaries/session policies and current account context; review a fixed
network-enabled client assembly (the present registry remains fixture-only); establish
private receipts and stop responsibility. Collection additionally needs separately
authorized resources/permissions, retention/cost/state ownership and exact source scope.
Signed validation, standard/backfill membership, original-version continuity and an
independently enforced authentic-source intake remain future work.

Wazuh RAM and retained PostgreSQL remain NO-GO. No local full PostgreSQL suite, cleanup,
container restart or uncontrolled stress run is authorized by this milestone. The
historical native SIGSEGV and intermittent Windows ACL-probe timeout remain unresolved;
their original failures and later successful retries stay separate evidence.
