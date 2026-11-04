# Offline posture-inspection policy source

`posture-inspection.policy.json` is an **unapplied, placeholder-only policy template**
for the fixed AWS3 posture worker. It is outside `infra/aws-offline` because that
directory deliberately retains its closed four-file inventory. It creates no role,
changes no existing audit role and supplies no AWS credentials or SDK client factory.

`${INSPECTION_ACCOUNT_ID}` and `${INSPECTION_ROLE_PATH_AND_NAME}` are private binding
markers, not AWS policy variables or known live identifiers. The tracked file must
remain unrendered. A later, separately authorized review would need the exact private
role ARN, complete current policies, boundaries, organization controls and trust.
`permissions.posture_policy` can construct a fresh, syntactically exact private binding
in memory; it neither applies that policy nor proves that the role exists.

The fixed profile contains eight operations and eight distinct IAM action names:

| SDK service and operation | IAM action | Reviewed source scope |
| --- | --- | --- |
| `sts:GetCallerIdentity` | `sts:GetCallerIdentity` | `Resource: *`; identity observation only |
| `cloudtrail:ListTrails` | `cloudtrail:ListTrails` | `Resource: *`; `aws:RequestedRegion = us-east-1` |
| `s3:ListBuckets` | `s3:ListAllMyBuckets` | `Resource: *` |
| `s3control:GetPublicAccessBlock` | `s3:GetAccountPublicAccessBlock` | `Resource: *`; exact `s3:ResourceAccount` |
| `iam:GetRole` | `iam:GetRole` | One exact inspection-role ARN |
| `iam:ListRolePolicies` | `iam:ListRolePolicies` | The same exact role ARN |
| `iam:GetRolePolicy` | `iam:GetRolePolicy` | The same exact role ARN |
| `iam:ListAttachedRolePolicies` | `iam:ListAttachedRolePolicies` | The same exact role ARN |

`DenyOtherActions` is an explicit `Deny` with `NotAction` containing exactly those
eight action names. It adds no permission and makes unintended additional action
allows incompatible with this source profile. It is a proposed guardrail, not a
policy applied to the owner's current role. It does not by itself constrain another
policy's broader resource grants *within* those eight actions. Complete live policy
evaluation remains unverified; fixed worker request scopes and rejection of unknown
policy observations remain separate software boundaries.

There is no `s3:HeadObject` IAM action. `HeadObject` requires object retrieval
permission, so neither `HeadObject`, `GetObject` nor object versions belong to this
inspection worker. `sts:AssumeRole`, `iam:PassRole`, policy mutation and provisioning
are also absent. List results may legitimately be empty; denied, malformed or
incomplete responses are not empty successful inventories.

`GetCallerIdentity` needs no IAM permission, including when explicitly denied. Its
presence in this source communicates the allowed operation; a successful call cannot
prove effective IAM, region, MFA, credential issuance/expiry or AWS log authenticity.
No metadata observation can authorize a trusted finding or reviewed closure.

Credential-free source checks:

```powershell
.venv\Scripts\python.exe scripts/check_aws3_permissions.py
.venv\Scripts\python.exe scripts/check_terraform.py
```

These checks compare exact reviewed JSON source and the single collector Terraform
permission delta. They do not invoke AWS, Terraform, a credential provider or a live
IAM evaluator. See the [permission difference report](../../docs/PHASE1B_AWS3_PERMISSION_DIFFERENCES.md).

Primary references, reviewed 2026-11-04: [S3 actions and scopes](https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html),
[account Block Public Access permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html#access-control-block-public-access-permissions),
[S3 Control account API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetPublicAccessBlock.html),
[CloudTrail actions and scopes](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudtrail.html),
[IAM role-read actions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html),
and [STS identity limitations](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
