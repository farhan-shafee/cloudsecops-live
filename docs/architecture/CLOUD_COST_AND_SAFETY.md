# Cloud cost and safety

## Phase1B-AWS-0 offline override

This milestone creates source/contracts only: zero AWS calls, provisioning, budget configuration or spend. Fixed `us-east-1` [Terraform source](../../infra/aws-offline/README.md) has no compute, NAT, RDS, data events, Insights, paid scanner or hosted SIEM. Private inputs have no real defaults and must never replace tracked placeholders. Collector/verifier are read-only; the test actor has only regional DescribeInstances. Provisioning/cleanup remain separate externally reviewed authorities.

Preserve evidence until explicit retention/cleanup review: versioning, `force_destroy=false`, `prevent_destroy` and no automatic current/noncurrent expiry. This overrides the earlier proposed30-day lifecycle for this unprovisioned design. These controls are not WORM and do not restrain a trusted administrator from changing policy. Retained versions can accumulate later charges; no monthly-price guarantee follows. Reprice region/SKUs and review source delivery, versions, backups and exact deletion inventory before separately authorized provisioning/cleanup. No budget or notification destination is configured.

Wazuh remains NO-GO: six recheck samples had5.588–5.900GiB Windows availability against required12GiB. Do not add WSL availability or swap to physical RAM, change global limits, prune evidence, stop unrelated services or rent a substitute host. The historical PostgreSQL SIGSEGV remains unexplained; use only supported sequential regression validation and stop on any new native crash.

Status: Phase 0 plan, 2026-11-03. **No AWS resources or paid services were enabled during this review.** No credentials were configured and no AWS exercises ran. Amounts are USD planning estimates for proposed `us-east-1`; taxes, existing account charges and local hardware/electricity are excluded.

## Smallest footprint

One dedicated account, one single-region CloudTrail management trail with read/write events and integrity validation, one private versioned S3 archive, short-lived scoped roles, and minimal Terraform state storage. API, database, worker and Wazuh run locally. The inventory test requires zero EC2 instances. A separate empty marker bucket is needed only for later posture/response work.

Do not enable CloudTrail data/network events, Insights, Lake, Config, Security Hub, GuardDuty, Inspector, CloudWatch Logs delivery, managed OpenSearch, RDS, NAT gateways, EC2 hosts, EKS, public IPv4 addresses or hosted AI for the first slice. Each adds cost/complexity requiring separate approval. Their absence limits visibility; no complete cloud coverage is implied.

[CloudTrail pricing](https://aws.amazon.com/cloudtrail/pricing/) documents a free first delivered copy of management events and charges for additional copies/other event classes. S3 remains chargeable. Inspect existing and organization trails before creation: another copy may change the model. No-charge event history is a verification aid, not the archive/digest path.

## Concrete planning model

Use 30 days with no Free Tier credits/promotions. Retained GB includes noncurrent versions, digests, state and receipts. Request counts include both collectors, verifier, retries, validation and reconciliation; every listing page counts.

| Input | Model rate | Evidence/uncertainty |
| --- | --- | --- |
| First management trail copy | $0 delivery | AWS pricing checked 2026-11-03; S3 still charged |
| Extra management copies | $2 / 100,000 events | AWS pricing checked; avoid them |
| S3 Standard storage | $0.023 / GB-month | AWS [storage cost example](https://aws.amazon.com/blogs/storage/monitor-data-transfer-costs-related-to-amazon-s3-replication/) supports planning rate; recheck current regional table before apply |
| S3 PUT/COPY/POST/LIST | $0.005 / 1,000 | Same AWS example supports rate; recheck region |
| S3 GET | $0.0004 / 1,000 | Model input; current-region Standard SKU not independently captured in Phase 0 |
| Internet download | $0.09 / GB | Conservative model input; no aggregate allowance deducted; reprice region/allowance |
| Budget monitoring/notifications | $0 | [AWS Budgets pricing](https://aws.amazon.com/aws-cost-management/aws-budgets/pricing/); omit reports/action budgets |
| Customer-managed KMS | $0 selected | SSE-S3; no customer-managed keys enabled |
| AWS compute/database/SIEM hosting | $0 selected | No hosting resources planned; local resources are excluded, not free infrastructure |

The [S3 pricing page](https://aws.amazon.com/s3/pricing/) uses dynamic regional tables not fully captured by this review. These inputs are not a current AWS quote. Save a dated calculator/rate receipt privately and recompute exact region/SKU before apply. This is an explicit spend gate.

Formula: `C = retained_GB * 0.023 + PUT_LIST / 1000 * 0.005 + GET / 1000 * 0.0004 + download_GB * 0.09 + extra_management_events / 100000 * 2`.

| Scenario | Retained GB | PUT/LIST | GET | Download GB | Extra management events | Monthly model |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Small lab target | 2 | 25,000 | 50,000 | 1 | 0 | $0.281 ≈ $0.29 |
| Conservative envelope | 10 | 100,000 | 250,000 | 10 | 0 | $1.73 |
| Misconfiguration example | 100 | 1,000,000 | 2,000,000 | 100 | 1,000,000 | $37.10 |

The last row excludes accidentally enabled compute/NAT/paid security services and is not a worst case. Five-minute polling of two prefixes alone is about 17,280 LIST calls/month before pages/retries; measure the 25,000 assumption. Data events stay disabled; enabling them adds separate event and downstream charges.

Proposed operating target: under $2/month incremental AWS cost for the envelope, with **owner approval of a $5 monthly alert budget** before live use. No amount is an enforceable cap. Local Wazuh requires its [documented hardware allocation](https://documentation.wazuh.com/current/quickstart.html); unavailable capacity stops the SIEM gate rather than authorizing a rented host.

## Access boundaries

Use short-lived sessions through the owner's existing approved sign-in flow after Phase 1 authorization. Never root or long-lived repository keys. Do not commit credentials in `.env`. This plan does not configure an identity provider or require secrets during Phase 0.

| Identity | Proposed access | Exclusions |
| --- | --- | --- |
| Bootstrap/provisioner | Reviewed Terraform apply/destroy for named trail, buckets and roles; narrowly reviewed IAM creation/pass-role if necessary | Not used by runtime. General AdministratorAccess is not an acceptable final policy. |
| Collector | `sts:GetCallerIdentity`; prefix-conditioned `s3:ListBucket`, `s3:GetBucketLocation`, `s3:GetObject`, `s3:GetObjectVersion`; necessary CloudTrail read/public-key calls for validation | No writes/deletes, policy/trail changes or response |
| Test actor | `ec2:DescribeInstances`, requested-region restriction | No creates/modifies or broad S3/IAM access. Document why `Resource=*` is necessary for an API lacking resource-level scope. |
| Verifier | Distinct session/role, archive reads, relevant CloudTrail configuration/history and exact policy/configuration reads | No response/provisioning or collector impersonation; bounded IAM inventory |
| Optional checkpoint writer | New uniquely named receipts under a separate approved private prefix | No source/digest overwrite/delete; not enabled until separately tested |
| Later responder | Only `s3:PutBucketPublicAccessBlock` on one exact non-logging marker bucket | No account-level block changes, IAM, archive, ACL/policy, encryption, retention or object deletion. This permission also permits deleting that bucket's block configuration; application policy forbids it. |
| Teardown | Manually invoked exact-resource deletion after retention review | Absent from runtime and PR CI |

Use AWS's [CloudTrail bucket policy pattern](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html), restricting service writes to the exact trail with `aws:SourceArn`. Require TLS, Block Public Access, ownership controls, default SSE-S3 and versioning. Prefixes use private expected-account configuration; never publish resolved account IDs/ARNs. No application/human writer in the authoritative log prefix. Test live delivery with the selected ownership/policy combination; static policy text alone is insufficient.

Before apply, review final bootstrap policy, trust policies, resource policies, session duration and validation-tool API actions against actual provider/tool behavior. Do not discover missing permissions through broad enumeration outside the lab. Keep provisioning, read-only runtime and cleanup credentials separate.

For the later responder, IAM scopes `PutBucketPublicAccessBlock` to a bucket but cannot require all four request flags to be true. AWS also uses this permission for [DeletePublicAccessBlock](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeletePublicAccessBlock.html). The approved-action adapter permits only the strengthening operation; account-level blocking remains on and outside responder permissions. Treat responder compromise as capable of clearing/removing that bucket's block configuration and test independent detection of such drift. Do not describe application restrictions as an IAM guarantee. AWS documents the [most restrictive account/bucket combination](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html); this protection does not remove the need to monitor changes.

## Safe exercise procedure

1. Confirm owner authorization, dedicated account/region, no production links, local capacity, current cost receipt, notification recipient and reviewed teardown inventory.
2. Record a bounded exercise window/run ID. Check STS identity privately; abort mismatches.
3. Review saved Terraform plan privately and scan it for identifiers/secrets. A separately approved apply creates only the footprint. State/plans remain encrypted/private. Use locked local state initially or a separately approved backend with documented bootstrap/lock/recovery.
4. Make three read-only inventory calls. Stop on errors, unexpected resources/region or throttling; do not broaden access. No exploit traffic, password guessing, credential harvesting or Internet targets.
5. Collect actual events/digests. Malformed/spoofed inputs use offline labeled fixtures; never upload fake logs to the trail prefix. Do not weaken account public-access protections or logging.
6. Use the Phase 1 no-action recommendation; independently verify and close only with adequate evidence. Unexpected writes/gaps stop the exercise.
7. End active polling after the bounded run (proposed two-hour maximum), with later manually bounded reconciliation for delayed files/digests. Never loop indefinitely. Review inventory/cost and tear down or explicitly record retained resources.

## Billing controls and stop conditions

Propose account-wide actual-spend alerts at $1, $2 and $5 and a forecast alert where available. Verify delivery to the owner's chosen recipient. Tag supported resources with project, lab environment, private owner and expiry, and inspect untaggable/global costs too. Phase 0 does not create alerts or choose notification destinations.

[AWS documents notification delay](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html). Budgets, anomalies, quotas and region restrictions are not spending caps. Even budget actions can be delayed and leave storage charges. Do not automatically destroy evidence on an alert.

Stop new exercises/collection on unexpected paid services, identity mismatch, excess volume, unexplained cost, cache at 80%, missing delivery, invalid digests or repeated denial. Preserve evidence and inspect inventory. Alerts do not authorize deletion. The application does not poll chargeable Cost Explorer/query APIs.

## Retention and teardown

Proposed private retention: raw logs/digests/case receipts 30 days; indexed SIEM data 14 days; quarantine 7 days; database backups 30 days. Record and price open-case holds. Configure current/noncurrent expiration and incomplete multipart cleanup; ordinary object expiry alone leaves versioned costs. Digests must not expire before their logs. No Glacier minimum-duration classes or Object Lock initially.

Teardown is reviewed work beyond `terraform destroy`:

1. Stop exercises/jobs; save private final resource/case/cost inventory. Export required encrypted receipts and verify their hashes/readability.
2. Record retained evidence, reason, expiry and deletion owner. Holds skip archive deletion and leave explicitly reported costs.
3. Stop/delete only the named lab trail after preservation approval; inspect delivery state. AWS's bucket-policy guidance warns misconfigured trails can keep retrying delivery and incur charges until removed.
4. Verify resolved exact bucket names, ownership and inventory against the allowlist. With cleanup credentials, remove approved objects, **all versions/delete markers**, multipart uploads and state/backend objects only after dependencies. No account-wide wildcard deletes or default `force_destroy`.
5. Destroy reviewed lab resources, remove temporary permissions/sessions, stop Wazuh and remove approved caches/secrets. Do not delete shared identity/billing contacts.
6. Independently inventory regional resources plus global S3/IAM/CloudTrail against baseline. Include manual/bootstrap resources outside Terraform and retain private destroy/inventory receipts.
7. Recheck billing after 24–48 hours and after the next billing update/month close. Report retained storage and delayed charges. Until then, infrastructure cleanup can be verified while billing closure remains pending.

Teardown cannot guarantee an immediate zero bill. Owner approval of spend, retention and evidence deletion is required before live exercises.
