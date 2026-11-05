# AWS4A: disabled posture network worker

Scope: [Issue11](https://github.com/farhan-shafee/cloudsecops-live/issues/11) and the
[owner permission clarification](https://github.com/farhan-shafee/cloudsecops-live/issues/11#issuecomment-6670869085).
This is offline implementation preparation. Production execution always rejects;
there is no live activation path, AWS command or authenticated-source constructor.
All examples/tests use fictional temporary material, fake clients or controlled
numeric-loopback faults. Actual test, coverage, review and CI outcomes must be bound
to the reviewed revision; this architecture document is not an execution receipt.

## Entrypoint and authority boundary

`integrations/aws_posture/registry.py` captures one literal worker and bootstrap under
the existing independent parent watchdog. `PostureRequest` has exactly a schema
version, opaque decision reference and nonce. Its serialized form is bounded to8KiB;
unknown fields, credential material, paths, endpoints, operation selectors and enabling
flags reject. The request validator is standard-library-only.

The child starts under native owned-process containment before the parent sends its
start gate. The separate posture bootstrap installs default-deny Python network and
process guards, imports no parent dependency search paths and reaches only the pure
request validator and disabled worker. `worker.execute` unconditionally raises
`AWS4A_EXECUTION_DISABLED` after request validation. It cannot load an owner file,
redeem a session or construct an SDK client. No environment, JSON, CLI or reference
value changes that result. The original fixture bootstrap, socket guard and AWS3
worker facades remain separate.

An `OwnerDecision` records exact purpose/account/region/role unique identity, UTC
window, reviewed source revision, finite budgets, complete inline-policy fingerprints,
CA fingerprint and owner/custody/effective-IAM/network references. Its digest binds
every field and the literal operation set. References may remain `pending`; its only
accepted review state is `pending`. Complete-looking hashes do not become approval.
Its public form always reports execution disabled and authentication, findings and
closure unavailable. Private account identifiers and policy bodies stay outside Git.

`CredentialCapabilityRef` is opaque metadata with no redemption operation.
`OfflineSessionCapability` supports fictional in-process tests only: one use, exact
decision digest and nonce, originating PID, complete expected identity and valid time
window. Same-process concurrent redemption has one winner; failed redemption consumes
the handle. Foreign processes reject before touching an inherited lock. Repr, copying
and pickling do not export session material. This is not an OS credential-delivery
broker or evidence of real custody. No credential travels in the worker's JSON frame,
arguments, diagnostic output or public receipt.

## Fixed inspection scope

The internal engine accepts trusted-code injected clients. Requests cannot select
clients, operations, endpoints or arbitrary call parameters. The scope is one
explicit account, posture role and `us-east-1`:

| Service/API operation | Binding and purpose |
| --- | --- |
| STS `GetCallerIdentity` | Exact account, assumed-role ARN and RoleId/session UserId |
| IAM `GetRole` | Exact role name, ARN and immutable RoleId; unsupported boundary metadata rejects |
| IAM `ListRolePolicies` | Complete bounded inventory equals the expected policy-name set |
| IAM `GetRolePolicy` | Exact role/policy name and canonical complete-document SHA256 |
| IAM `ListAttachedRolePolicies` | Complete bounded inventory; any attachment rejects |
| CloudTrail `ListTrails` | Complete bounded regional inventory, minimized to a count |
| S3 `ListBuckets` | Complete bounded account inventory, minimized to a count |
| S3 Control `GetPublicAccessBlock` | Exact `AccountId`; all four account BPA fields exactly boolean `true` |

These are eight operation types, not eight calls. For one inline policy, no retries
and single-page lists, the initial identity/role/policy checks, inventory and account
check take eight calls; final policy/role/STS rereads take five more: thirteen total.
Extra approved policies, pages and explicit retries consume the same aggregate
budgets. Policy and identity rereads detect observed drift, not an atomic IAM snapshot
or complete effective-permission evaluation. A friendly role name or matching policy
hash does not prove least privilege.

Successful complete empty trail/bucket lists are valid zero counts. They do not prove
the continued absence of resources or authorize their creation. Denied, malformed,
incomplete or ambiguous service responses never become empty success. Unknown policy
names/attachments, substituted identities, conflicting role IDs, missing pagination
fields, repeated tokens and expired sessions reject. The account BPA requirement is
an owner acceptance condition: missing, unknown, false or non-boolean values reject.

## Account-level S3 permission decision

The owner explicitly retained S3 Control
`GetPublicAccessBlock(AccountId=approved_account)` and IAM action
`s3:GetAccountPublicAccessBlock`. The account policy statement keeps `Resource: "*"`
with exact `StringEquals`/`s3:ResourceAccount` matching the approved account. AWS4A
neither changes IAM nor introduces `s3:GetBucketPublicAccessBlock`, bucket requests,
fallback principals or broader permission retries.

The [S3 account BPA permission guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html#access-control-block-public-access-permissions)
and [S3 Control API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetPublicAccessBlock.html)
describe account-level inspection. The conflicting operation-to-action row in the
[Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html)
remains an unresolved live-preflight limitation. Offline schema or mutation tests
cannot settle effective AWS authorization. A permission error stops the run; it does
not justify a substitution, IAM edit or live probe in this milestone.

## SDK, wire and deadline controls

The internal builder uses pinned packaged botocore models, explicit static bound
session material and five fixed clients. It creates no SDK Session or provider chain;
profiles, IMDS, external model paths, plugins, ambient endpoints and proxies are not
consulted. The packaged CA bytes must match the decision digest. Regional HTTPS/TLS
validation, endpoint/configuration and credential-object identity are checked before
dispatch. SDK internal retries are disabled; only the engine can reserve a bounded
explicit retry. SDK debug logging is suppressed in the private child construction
path rather than publishing signing material.

The logical reservation fixes service, operation and exact canonical parameters.
The SDK parameter hook verifies that reservation. Immediately before transport, the
final serialized HTTP method, endpoint, headers, query/body and decoded operation
parameters must match the same one-use reservation. Later SDK event handlers cannot
substitute another role, account, policy or API. Redirects, arbitrary hosts, bucket
routes, proxy headers and unsupported bodies reject.

The shared ceiling charges logical request reservations, actual request bodies and
plaintext HTTP status/header/chunk-framing/body bytes. Conservative double charging
is possible; failed calls, pages and retries are not refunded. This is not packet-level
TLS/TCP accounting. The raw reader enforces response bytes, bounded status/header/chunk
lines and header counts before the HTTP/SDK parser consumes them. Every fixed API's
successful raw body is checked before SDK model parsing: closed JSON fields with no
duplicate keys, exact XML roots and unique result wrappers, closed list/member fields,
exact booleans and consistent continuation markers. XML entity/doctype, encoded hostile
input and unknown/duplicate account BPA or policy fields reject before lossy SDK
parsing can hide them. Later JSON-tree bounds add defense in depth; they do not replace
raw framing limits.

Existing maximum ceilings remain64calls,16pages,16non-retry operations,2retries,
10MiB aggregate charged bytes and30seconds; a decision can only reduce them. The
engine also bounds each inventory to64items. Cooperative monotonic checks cannot
interrupt blocked DNS, TLS, response-header or chunk-header reads. The independent
parent watchdog covers work and owned-process cleanup; cancellation, crash, deadline
or unknown cleanup cannot produce a successful evidence receipt. Local fault tests
exercise these paths without contacting an AWS endpoint.

## Results, privacy and live stop gates

The fake inspection result publishes counts, all-enabled BPA status, budget counters
and explicit `execution_state=disabled`, `source_kind=aws_shaped_unverified`,
`authenticated=false`, `effective_permissions_verified=false`,
`signed_source_authentication_available=false`, `trusted_findings_available=false`
and `closure_available=false`. No SDK result or decision/capability reference can
enter the synthetic findings/recommendation/closure authority path. A successful SDK
response would not prove CloudTrail delivery, signed-log validation or benign intent.

Current live gates include independent owner approval of exact source/identity/window,
actual short-lived non-root MFA issuance, a real private OS credential broker, effective
IAM and the unresolved S3 mapping, reviewed OS egress/containment, TLS/CA policy,
cost/stop responsibility and private receipt custody. Python guards are supplemental;
they are not a firewall or sandbox against hostile native/same-user code. These limits
keep production non-activatable. The historical private CLI session ended and cannot
be reused. AWS4B signed-source authentication, collection and source-trust promotion
are separate future work, not acceptance supplied by these tests.

Migrations001–003, retained evidence, SQL permissions and Terraform/IAM sources stay
unchanged. PostgreSQL acceptance runs only sequentially in the identified disposable
hosted-CI service. The retained workstation remains NO-GO after shared-memory pressure;
the historical SIGSEGV root cause is unproven. The original Windows ACL-probe timeout
and successful retry remain separate evidence of an unresolved intermittent issue.
Wazuh remains NO-GO under its measured physical-memory gate. None is repaired or
waived by AWS4A. See [owner readiness](../AWS_LIVE_READINESS.md),
[operations](../AWS_OFFLINE_OPERATIONS.md) and the
[independent lab](../labs/PHASE1B_AWS4A_INTERVIEW_LAB.md).
