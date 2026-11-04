# AWS3 permission source differences and remaining identity gaps

Status: offline source review, 2026-11-04. The owner-supplied November4 audit recorded
29 bounded calls. Those dated observations inform the design; they are not repeated
here and establish no future or current account posture. Actual account identifiers,
user/role names, credential/session values and audit receipts remain private.

The exact inline policy bytes of the owner's existing inspection role were not
provided. An exact live-policy diff and effective IAM evaluation are therefore
**unverified**. This milestone neither manages/imports that role nor widens its policy.
The standalone [inspection template](../infra/iam-readiness/README.md) is source for a
later separate review, not evidence that any live role has these permissions.

## Complete Terraform source inventory and sole change

Starting source is protected main `58d008c4744c7f2f7560bddc6fcdc19516ef6298`, reviewed
tree `2d1d8c37a2a9a1094f74b17046ffcdb5e7fcc0cc`. The source contains three runtime
`aws_iam_role` resources and three matching inline `aws_iam_role_policy` resources.
No IAM attachment, permission boundary, credential/session or inspection-role resource
is added. The existing resource, trust, provider, lock and variable structures stay intact.

| Source policy | Before | After | Exact permission difference |
| --- | --- | --- | --- |
| Collector | 6 statements, 10 distinct actions | 7 statements, 11 distinct actions | One new `InspectTrailInsights` statement: `cloudtrail:GetInsightSelectors`, `${local.trail_arn}`, `aws:RequestedRegion = us-east-1` |
| Verifier | 10 statements, 23 distinct actions | Unchanged | Already has the same narrowly scoped insight read in its separate statement |
| Test actor | 1 statement, 1 action | Unchanged | `ec2:DescribeInstances` in `us-east-1` only |

The existing SDK adapter calls `GetInsightSelectors` unconditionally while inspecting
the approved trail. Collector source previously omitted that permission. AWS3 adds
exactly that read; it adds no CloudTrail Insight configuration, trail write, wildcard
trail ARN, additional region or billable resource. `GetInsightSelectors` supports a
trail ARN in the [CloudTrail authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudtrail.html).

The original six collector statements retain their exact actions, resources and
conditions: prefix-bound `ListBucket`/`ListBucketVersions`, bucket location, original
and exact-version object reads, three existing trail reads, regional public-key reads
and caller identity. The verifier's extra IAM-role inspection, seven archive
configuration reads, insight selectors and regional event history remain unchanged.
Neither runtime policy receives `AssumeRole`, `PassRole` or mutation authority.

The independent AWS3 checker removes only the exact appended collector statement and
requires the remainder's canonical JSON SHA256 to equal the pre-AWS3 source baseline.
The existing structural checker independently constructs the entire expected source
and accepts this same narrow addition. Mutation tests reject extra/missing/duplicate
insight statements, wildcard resources, removed/wrong region conditions, write actions,
new principals, verifier changes and trust changes. The source comparison is not an
IAM simulator, Terraform/provider acceptance or live authorization result.

## Trust and issuance differences remain unresolved

Each existing Terraform runtime trust names one exact externally supplied **role**
principal and permits only `sts:AssumeRole`. The three trust documents have no MFA
condition. The provider separately names an exact provisioning role for Terraform's
own `AssumeRole` configuration; provisioning, cleanup and the three trusted operator
roles must remain distinct from the managed runtime roles and from one another.

The dated inspection observation described a named **user** principal with an MFA
trust condition. That differs from the repository's exact external-role principals
and absent MFA trust conditions. AWS3 records this principal/MFA gap and changes no
trust document. It does not claim that the existing template matches the observed
inspection role, propagates MFA through role chaining or establishes issuer authority.
Separate explicit issuance, MFA, expiry and credential bindings remain required
unverified observations in the new session contract.

`GetCallerIdentity` returns caller identity information and requires no permission,
even under an explicit deny. It cannot prove issuance time, expiry, MFA, requested
region or effective policy. See [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).

## Inspection, collection and verification stay distinct

| Purpose | Capability and source scope | Excluded from this purpose |
| --- | --- | --- |
| `posture` | Exactly eight fixed metadata operations; empty trail/bucket inventory is valid. Four role-read actions target one exact inspection role; account/region parameters remain bound separately. | Object/head/version access, role assumption/passing, arbitrary managed-policy reads, resource creation and mutation |
| `collector` | The existing prefix/version-bound archive reader and exact regional trail inspection, including the single added insight read. | IAM inspection, trail changes, object writes, provisioning and automatic cleanup |
| `verifier` | Existing reviewed archive/version reads plus its exact runtime-role/archive configuration/history observations. | Evidence authenticity without a real source verifier, mutation and trusted findings/closure |

The new fixed inspector has no dynamic SDK factory, service/operation selector or
source-code input. Its data-only fictional transport uses the exact SDK operation
names. In particular, account Block Public Access is
`s3control:GetPublicAccessBlock` with IAM action `s3:GetAccountPublicAccessBlock`;
it is not the bucket-scoped `s3:GetBucketPublicAccessBlock`. The required account
permission is documented in the [S3 Block Public Access permission table](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html#access-control-block-public-access-permissions).

The immutable operation profiles describe each complete policy capability ceiling,
including preserved future CLI-support reads. The named fixture workers are narrower:
archive tapes allow only caller identity and S3 version/list/head/get operations.
The profile mapping is not a generic operation dispatcher and does not claim that
every listed capability has an implemented or live-tested worker operation.

`ListAllMyBuckets`, account `GetAccountPublicAccessBlock` and `ListTrails` lack
resource-level ARN scoping and therefore use `Resource: *`; the template retains
supported account and requested-region conditions where applicable. The four IAM
actions support exact [role ARN scoping](https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html).
`HeadObject` requires `s3:GetObject`, so treating it as an innocuous metadata-only
inspection permission would introduce object retrieval authority. See the
[S3 authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html).

The template's eight-action `Deny`/`NotAction` guardrail grants nothing and is not
applied to the current inspection role. Other policies could still broaden resources
within those eight actions; complete current policy bytes, boundaries, SCPs and other
controls were not evaluated. Unknown or unapproved attached-policy observations must
not silently broaden the fixed worker's operation/request scope or become successful
authorization receipts.

All SDK/facade results remain unauthenticated preparation. No call, receipt JSON,
matching local policy, source hash, apparent MFA flag or consistency check can authorize
AWS trust, synthetic ingestion, a trusted finding or reviewed case closure. No live
AWS collection, credential access, AssumeRole execution, Terraform plan/apply/destroy,
local PostgreSQL/Docker operation, Wazuh installation or deployment occurred here.
