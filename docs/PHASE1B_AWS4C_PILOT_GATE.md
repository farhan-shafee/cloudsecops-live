# AWS4C — Offline pilot bootstrap decision gate

**Status: OFFLINE DESIGN / LIVE NO-GO.** This is an additive safety
checkpoint. It does not enable AWS4A, authorize credentials, start CloudTrail,
change Terraform source, install AWS tools, read customer data, or grant
authority to create or delete any cloud resource.

## Why this exists

The retained, reviewed `infra/aws-offline/main.tf.json` requires five
distinct pre-existing operator roles. They are not the three managed roles
Terraform proposes to create. An initial independent live IAM inventory of the
pilot account on November 7, 2026 found **zero of these five pre-existing
operator roles**. Only the separately limited security-auditor and budget-reader
roles were present for CloudSecOps. Using either of them as a provisioner,
collector or verifier would be a scope expansion, not an implementation fix.

The Terraform provider is pinned to v6.71.0 and Terraform to v1.17.1.
Its provider configuration assumes one exact pre-existing provisioner role.
The template has no remote Terraform state backend. The target resource graph
would create one CloudTrail trail, one private versioned S3 archive, its
associated configuration and three runtime IAM roles. It does **not**
automatically build the external operator roles or the secured state store.

The live Gate A evidence was separately accepted: the account is standalone,
all 17 account-enabled Regions returned zero trails, account S3 Block Public
Access 4/4 is true, and an account-wide S3 listing returned zero buckets. The
monthly $5 cost budget has actual-spend notifications with thresholds
50/80/100% and one verified email subscriber. AWS Budgets is **not a hard cost
cap**, and historical receipt confirmation does not prove alert delivery.
These observations do not authorize provisioning.

## Offline decision input

`python scripts/check_aws4c_pilot.py PATH_TO_PRIVATE_MANIFEST.json`

The equivalent module invocation is `python -m scripts.check_aws4c_pilot
PATH_TO_PRIVATE_MANIFEST.json`. Both real subprocess startup paths have offline
regression tests; either returns exit code `1` when required approvals are absent.

The script reads at most 16KiB of bounded JSON, rejects duplicate keys,
nonfinite numbers, symlinks, unsupported keys and a changed reviewed
infrastructure source. It prints generic blockers without echoing account
identifiers, resource names, emails, credential material or manifest contents.
It does **not** use boto3, the AWS CLI, Terraform, PowerShell, shell commands,
network sockets or environment-based account/credential discovery.

The private document requires exactly:

- Five distinct externally created operator role ARNs and immutable RoleIds,
  with independent evidence of MFA trust, effective permissions and custody.
  External operator roles must use `/cloudsecops-operators/`; audit/budget
  inspection roles cannot substitute. A named pre-existing provisioner must
  be separately scoped to the exact reviewed resource graph.
- Distinct encrypted S3 backend bucket and state key
  `cloudsecops-live/aws4c/terraform.tfstate`; versioning, four public-access
  protections, Terraform-native `use_lockfile`, restricted exclusive writer,
  access-policy review and tested backup restoration. The state bucket is a
  **separately approved resource**, not the evidence archive.
- Manually reviewed 90-day retention *checkpoint* without automatic expiry;
  independently identified cleanup authority and ongoing cost/funding owner.
  No automatic evidence deletion and no implied `prevent_destroy` override.
- Independent native egress/process containment, exact transport/API budgets,
  genuine CloudTrail signing-key provenance and source/trust gate reviews.
- Three *separately documented* human decisions: identity/state setup,
  precise resource scope/cost, and retention/cleanup.

A schema-valid document still prints **"live resource execution NOT
authorized"**. Approval statements in a JSON file are untrusted claims;
their originals, signer/owner identity, recency, role unique IDs and actual AWS
effective policies must be verified outside this tool. Neither a clean static
check nor a merged PR is deployment authority.

## Proposed operational order (not executed)

1. Independent approval of the operator-role bootstrap permissions and exact
   MFA-backed trust matrix. Create five distinct pre-existing operator roles
   **only** after reviewing each role's maximum actions/resources and temporary
   credential issuance/custody. Do not use the connected administrator
   integration as a runtime provisioner.
2. Choose/create the separate private state backend, with encrypted versioned
   S3, scoped read/write/lock permissions, `use_lockfile=true`, one writer,
   independently verified backup/restore, and no state/plan copies in Git.
   Terraform native S3 locking avoids a new DynamoDB lock table.
3. Independently review provider role chaining; runtime-role trust (role ARN
   and immutable RoleId), target S3 and CloudTrail policy, cost model,
   forecast/notification latency, and retention/legal/forensic hold.
4. Obtain one explicit *resource-level* owner authorization covering an exact
   plan, named bucket(s), IAM roles, CloudTrail trail, source commit, approved
   region, maximum ongoing exposure, stop criteria and separate cleanup owner.
5. Only then consider a bounded live plan/apply. Separately approve one harmless
   `ec2:DescribeInstances` event, short signed-digest capture, genuine key
   provenance, original-location S3 object versions and independent verification.
   Real-source data remains untrusted until all cryptographic and custody
   requirements are met.

The existing CloudTrail trail source enables log-file integrity validation,
which begins delivering digests in approximately one hour. Independent
validation of full standard/backfill chains requires original S3 locations,
delivery version continuity, regional public key binding and explicit interval
coverage; a valid digest alone does not authenticate its acquisition.

The local BitLocker inspection on Chopin returned an unavailable CIM query.
**Local Terraform state encryption has not been verified.** No local state
storage was created as a workaround.

## Authoritative documentation

- [Terraform S3 remote state and native lockfile](https://developer.hashicorp.com/terraform/language/backend/s3)
- [Terraform state sensitive-data security](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)
- [AWS CloudTrail signed digest validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html)
- [CloudTrail pricing, first vs additional management-event copies](https://aws.amazon.com/cloudtrail/pricing/)
- [S3 pricing, retained versions, operations and transfer](https://aws.amazon.com/s3/pricing/)

**Frozen infrastructure contract** remains in `infra/aws-offline/`; do not
modify its tracked examples, IAM expressions, backend behavior or deployment
state in a hidden local script.
