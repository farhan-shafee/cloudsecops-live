# Offline AWS infrastructure source

Status: Phase1B-AWS-0 source preparation, 2026-11-03. This directory has not
created or contacted AWS resources. Terraform is unavailable on this machine;
`terraform fmt`, initialization and provider-schema validation have **not run**.
No provider packages or checksums were downloaded, and there is no provider
dependency lock file. This source is not approved for deployment.

The reviewed source uses Terraform's native JSON syntax in `main.tf.json`.
[`check_terraform.py`](../../scripts/check_terraform.py) is a closed structural
policy allowlist, not Terraform validation, an expression evaluator, effective
IAM analysis or evidence of successful CloudTrail delivery. Intentional changes
require reviewing both the source and its static policy. Only the three tracked
files belong in this directory; put private input, state, plans and receipts in
an approved private location outside the source tree.

## Proposed footprint

- One dedicated sandbox account, fixed `us-east-1`, one single-region,
  non-organization CloudTrail trail. Management read and write events and log
  integrity delivery are enabled. Global-service events are included. There are
  no data, network activity or Insights event selectors.
- One private S3 bucket with all four public-access blocks, bucket-owner-enforced
  ownership, versioning and explicit SSE-S3 encryption. CloudTrail service writes
  require the exact trail ARN, source account and bucket-owner-full-control ACL,
  restricted to this account's regional log and digest prefixes. Other writers
  and non-TLS access are denied by the bucket policy.
- Three roles with a one-hour maximum session duration and distinct exact
  pre-existing trusted role principals: collector, independent verifier and
  test actor. There are no IAM users, keys, wildcard trusted principals or
  runtime `sts:AssumeRole` grants.
- A separate pre-existing provisioning role is selected explicitly in the
  provider, with `allowed_account_ids` guarding the privately supplied expected
  account. Cleanup is a different pre-existing role. Neither authority is
  created or granted by this source. All five external role inputs must be
  distinct, in the expected account, and different from the three managed roles.

There are no EC2 instances, VPC/NAT resources, public IPv4 addresses, hosted
databases, KMS keys, CloudWatch delivery, SNS/SQS, paid scanners, Config, Security
Hub, GuardDuty, Inspector, CloudTrail Lake, hosted AI, marker buckets or remote
state services. No backend, data sources, modules, provisioners, executable hooks
or credential-discovery commands are declared.

## Permissions and limits

The collector can list objects and versions only in the regional log/digest
prefixes, read current objects and exact object versions, obtain bucket location,
inspect the named trail and retrieve
regional CloudTrail signing public keys. Future validation tooling must supply
the exact trail, bucket, prefix and bounded interval; `DescribeTrails` is not
granted. Enabling digest delivery does not validate any files. AWS's CLI validates
original-location files referenced by digests and requires online access, which
is outside this task.

The verifier has its own trust/policy and the same archive reads. It can read
the exact archive's policy/ownership/encryption/versioning/lifecycle controls,
the three runtime roles and their inline/attached-policy inventory, named trail
selectors/status, and regional event history. `ListPublicKeys`, `LookupEvents`
and `GetCallerIdentity` need wildcard resources; these statements are separate
from resource-scoped reads. History access is regional rather than constrained
by IAM to a case or time window: future software must bound it. The verifier
does not receive arbitrary managed-policy contents; unexpected attachments
require an inconclusive result and owner review rather than broader access.

The test actor's only identity-policy action is `ec2:DescribeInstances`, with
`Resource = "*"` because that action has no resource-level scope, and a
`us-east-1` requested-region condition. An empty inventory is sufficient;
creating an instance is unnecessary. `GetCallerIdentity` does not require an
identity-policy grant and must still be checked privately before future use.

These policies alone do not prove effective IAM permissions: external identity
policies, role trust custody, permissions boundaries, organization controls,
resource policies and administrator changes remain unverified. The verifier
cannot assume the collector, provisioner or cleanup role through these policies.
Separate sessions do not establish separate hosts or independent people.

## Retention without automatic deletion

Every managed resource has literal `prevent_destroy = true`; the bucket has
`force_destroy = false`, and role deletion cannot force-detach policies. No
expiration, noncurrent-version deletion, transitions, multipart cleanup or
Object Lock is configured. The bucket policy denies lifecycle configuration,
and object/version/bucket deletion is denied except to the exact external
cleanup role. That exception grants no deletion permission itself.

This is a deliberate Phase1B-AWS-0 override of the earlier proposed 30-day
automatic S3 expiration in [the cost plan](../../docs/architecture/CLOUD_COST_AND_SAFETY.md).
Preserve evidence until a later explicit retention/hold review. Storage,
noncurrent versions and incomplete uploads can continue accumulating costs;
there is no automatic age-based purge or spending cap.

`prevent_destroy` protects Terraform operations while the resource declaration
remains present. Removing the declaration, changing the guard or using an AWS
administrator can bypass it. Versioning provides recovery, not WORM. There is
no time-enforced minimum retention, Object Lock or administrator-proof archive.
The cleanup principal is powerful and this source cannot enforce its human
review procedure. A later cleanup requires reviewed exact resources/versions,
preservation/hold decisions, separate cleanup permissions and an independently
approved configuration change; no cleanup command is supplied here.

## Checks performed and future gates

Run the credential-free checks from the repository root:

```text
python scripts/check_terraform.py
python -m pytest tests/test_terraform.py
```

The checker uses only bounded local file reads and the Python standard library.
It rejects duplicate JSON keys, unexpected entries, missing/private inputs,
changed trust or policy expressions, added services and removed guards. It
does not execute Terraform or read AWS configuration, credentials or environment
variables. Mutation tests exercise privilege widening and destructive settings.

The provider is pinned exactly to `hashicorp/aws = 6.71.0`, checked against the
[official release](https://github.com/hashicorp/terraform-provider-aws/releases/tag/v6.71.0)
on 2026-11-03. Terraform must be at least 1.9 for cross-variable input validation
and below 2.0. An exact provider version is not a checksum-verified installation.
Future work must obtain reviewed official tooling, inspect signed release
checksums and generate/review a cross-platform dependency lock file before any
provider installation. Use a clean temporary validation copy for any later
credential-free `terraform init -backend=false` and `terraform validate`;
initialization downloads packages and needs its own authorized network scope.
Keep credentials and credential-loading hooks absent during that check. Do not
treat the static source check as satisfying this compatibility gate.

Any future plan/apply is a separate authorization gate. First privately confirm
dedicated account ownership, approved identities, region, baseline/organization
trails and duplicate-copy costs, current regional prices, owner-approved spend
alerts, trust relationships, precise provisioning/cleanup policy actions and
state locking/encryption/recovery. The final provisioning policy is not supplied:
IAM role/policy creation is privilege-sensitive and requires review against
provider behavior; no AdministratorAccess fallback is acceptable. Source/state
may contain sensitive identifiers even when Terraform marks outputs sensitive.

Then review a privately saved plan and independently test actual service
delivery, digest membership and version continuity, role denials, unexpected
attachments/configuration drift and bounded collection. No plan, apply, destroy,
AWS authentication/call, real event collection, Docker or Wazuh action belongs
to this offline source task. Database migrations 001–003 are unaffected.

## Primary references

No additional Python dependency is introduced. Original project code remains MIT;
the declared AWS provider is separately [MPL2.0 licensed](https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/v6.71.0/LICENSE).
The absent Terraform CLI has its own [BSL1.1 terms](https://github.com/hashicorp/terraform/blob/main/LICENSE),
which are not replaced by this repository's MIT license. No provider/tool binary or
upstream implementation was copied into this project. Review the exact selected
tool release and package checksums before a separately approved installation.

- [Terraform JSON configuration](https://developer.hashicorp.com/terraform/language/syntax/json)
  and [validation behavior](https://developer.hashicorp.com/terraform/cli/commands/validate).
- [Terraform lifecycle limitations](https://developer.hashicorp.com/terraform/language/meta-arguments/lifecycle)
  and [AWS provider account guard](https://registry.terraform.io/providers/hashicorp/aws/6.71.0/docs#allowed_account_ids).
- [Pinned CloudTrail resource documentation](https://github.com/hashicorp/terraform-provider-aws/blob/v6.71.0/website/docs/r/cloudtrail.html.markdown)
  and [AWS bucket-policy pattern](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html).
- [CloudTrail original-location validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html),
  [S3 ownership/ACL compatibility](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html)
  and [service-principal conditions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalservicename).
- [EC2 resource/region examples](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ExamplePolicies_EC2.html)
  and [GetCallerIdentity authorization](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
