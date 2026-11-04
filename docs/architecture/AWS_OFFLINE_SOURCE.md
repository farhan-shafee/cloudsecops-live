# AWS offline source boundary

Acquisition metadata is a future implementation contract, not an invented AWS response schema. STS GetCallerIdentity does not return region or expiry; those must be bound to the configured client and credential provider. S3 GetObject does not return an authoritative owner-account field: the future transport must send ExpectedBucketOwner, retain evidence of that successful request guard, and reconcile actual returned VersionId, size and modification metadata. Current ObjectBody.owner_account is only a controlled transport observation. These fields cannot independently authenticate a source. [S3 GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)

Status: Phase1B-AWS-0 offline source preparation, 2026-11-03. The implementation has no
AWS SDK, credential discovery, sign-in, AWS subprocess or network transport. It accepts
AWS-shaped bytes and controlled in-memory service observations. It cannot authenticate a
real AWS source, produce trusted findings, create a reviewed case or authorize closure.
Offline implementation permission is not permission for later AWS access or provisioning.

Read with the [operations guide](../AWS_OFFLINE_OPERATIONS.md),
[infrastructure source](../../infra/aws-offline/README.md),
[threat model](THREAT_MODEL.md) and [cost and safety plan](CLOUD_COST_AND_SAFETY.md).
Execution results belong in the final acceptance record; this design is not a test receipt.

## Source classes and authority

This registry describes current boundaries and future states. It does not add authenticated
values to the existing synthetic provenance enum or make a future class constructible.

| Class | Current representation | Permitted meaning |
| --- | --- | --- |
| Existing synthetic | Existing synthetic parser, contracts and PostgreSQL/workflow path | Labeled exercise evidence; `authenticated=False`. Existing synthetic no-action authority remains limited to its own reviewed workflow. |
| AWS-shaped unverified | New `AwsLog`, `AwsEvent`, `AwsSession`, collection and controlled assessment types | Bounded offline parsing/consistency only; `source_kind=aws_shaped_unverified`, `authenticated=False`. Implemented now. |
| Pending real source authentication | Future authorized acquisition with incomplete source evidence | Future only. No live transport or real-source intake is supplied here. |
| Authenticated real source | Future supported cryptographic validation and complete exact-source binding | Unavailable. No current receipt, flag, constructor, API or database path grants this authority. |
| Invalid or conflicting | Rejected input, invalid controlled assessment or preserved conflicting record/member variants | No trust or findings authority. Conflicts require resolution with evidence, not selection of a convenient variant. |

The offline demo uses the state string `pending_source_authentication`. Its data remains
AWS-shaped fixture data; that string is not evidence of real acquisition. A controlled
`VALID` outcome is an input to a consistency exercise, not an AWS signature-verification result.

The new types are separate from `ParsedLog`, `NormalizedEvent` and the existing synthetic
identity contracts. The synthetic CLI rejects the raw AWS `Records` envelope. The new
module provides no storage migration or adapter into the accepted synthetic evidence,
detection, reviewed-workflow or closure paths. Migrations 001–003 are unchanged.
`require_authenticated(value)` rejects every value with `AWS_AUTHENTICATION_UNAVAILABLE`,
including forged objects and an otherwise consistent controlled assessment.

## Parser and immutable evidence

The [models](../../src/cloudsecops_live/integrations/aws_cloudtrail/models.py) define a frozen
`AwsScope` containing expected account, commercial Region, exact collector role ARN and
trusted role unique ID, exact trail ARN, bucket and regional log/digest prefixes. The
account is an ASCII numeric account shape; ARN accounts/Regions and both fixed prefix
roots must agree. Wildcards, URIs, controls, traversal and unbounded prefixes are rejected.
This validates a configuration's shape and internal consistency, not resource existence,
ownership, effective permissions or authority to access it. Private resolved values stay
outside Git and public receipts.

`parse_aws_shaped(data: bytes, scope: AwsScope, *, limits: Limits) -> AwsLog` accepts one
gzip member with the exact root envelope `{"Records":[...]}`. Caller-supplied root trust or
source flags are rejected. The AWS-shaped boundary reuses only the existing ingestion
1.0.0 bounded gzip/JSON/timestamp helpers and canonicalization 1.0. The old synthetic
envelope and normalization rules are not widened.

| Parser bound | Default and hard ceiling |
| --- | ---: |
| Compressed archive | 10 MiB |
| Expanded content | 100 MiB |
| Records | 10,000 |
| Nesting depth | 32 |
| Decoded string length | 4,096 code points |
| Preflight nodes | 200,000 |
| Number token length | 128 |

Limits may be reduced. Strict parsing rejects duplicate keys, nonfinite/oversized numbers,
invalid Unicode/UTF-8, NUL characters in keys or values, malformed/trailing/concatenated
gzip, invalid record schemas and wrong categories. Scope checks require matching
`recipientAccountId` and `awsRegion`, a UUID-shaped `eventID`, and Management events.
General management operations are retained; the parser is not restricted to one detector's
inventory event names. The identity key is `(account, region, lowercase event UUID)`.

Each immutable `AwsLog` retains exact archive bytes, exact decompressed content bytes,
their separate SHA-256 values, its event tuple and fixed versions:
`aws-offline/1`, parser `1.0.0`, canonicalization `1.0`. Every event retains its original
record index, complete canonical record and SHA-256 before deriving fields. Unknown
record fields affect that hash; a nested `authenticated` field remains untrusted data.
Canonicalization preserves decimal precision and is separate from the unchanged raw bytes.

A coherent AWS-shaped assumed-role identity can produce an `AwsSession`, with issuer ARN,
access key ID, actor account/Region and UTC creation time. The actor need not be the
collector role or have the recipient account: cross-account actors can be represented.
Unsupported or inconsistent actors remain complete hashed events with `session=None` and
an identity reason. Neither a session correlation nor an event name establishes benign
intent, complete visibility or source authenticity.

## Collection contract and its limits

The [collection protocol](../../src/cloudsecops_live/integrations/aws_cloudtrail/collection.py)
is dependency-injected. Only fake transports are provided. A future concrete transport
must bound network duration and body allocation before returning; accepting a protocol
object does not establish that an arbitrary implementation honors those obligations.

The contract checks a recent caller observation before S3-shaped operations and again
throughout the poll. It requires exact account, configured Region, assumed-role ARN and
`UserId` role-ID prefix matching `AwsScope.role_id`, plus unexpired session observations.
Role name alone is insufficient when a role can be deleted and recreated. The current
freshness allowance is 60 seconds. A future adapter must obtain the genuine STS response
and obtain Region/session expiry from its explicit client and credential provider:
STS `GetCallerIdentity` returns `Account`, `Arn` and `UserId`, not Region or expiry, and
requires no permission grant. [AWS GetCallerIdentity reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)

The poll stages all pages under the exact log prefix before retrieval or checkpoint
commit. The default limits are 32 pages, 16 objects, 10 MiB total archive bytes, 50 MiB
total expanded bytes, 10,000 delivered records and at most three classified attempts per
read. Configured ceilings are 256 pages, 64 objects, 10 MiB archive, 100 MiB content and
three attempts; the parser's record ceiling remains in force. Only `RetryableReadError`
receives bounded retries. Other transport errors are sanitized failures.

Service pagination requires both next key and next version-ID markers, nonempty bounded
values, no repeated pair, no backwards key and a final nontruncated page with no next
marker. Missing, malformed, truncated or oversized listing evidence is not an empty
successful poll. `ListObjectVersions` requires `s3:ListBucketVersions`, includes versions
and delete markers, and may return malformed XML even with HTTP 200; a future adapter
must parse the response successfully. The result is complete only for this supplied
prefix/poll, not an atomic snapshot of a changing bucket.
[AWS ListObjectVersions reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html)

The current contract deliberately rejects `null` versions, delete markers, nonlatest
versions and multiple versions of a key. It does not silently skip them or select a
preferred history. A normal versioned bucket with overwrites/deletions may therefore
fail this collector. Supporting complete version history, delete semantics and bounded
reconciliation remains a future acceptance gap.

For each accepted reference, the collector checks current version before retrieval,
requires matching returned reference and owner account, reads at most listed size plus
one byte, requires exact size, closes the stream and checks current version afterward.
It preserves the version reference, retrieval interval and parser byte/hash evidence.
After all reads it rechecks every object's current version before commit, catching an
earlier object changed during a later read. These observations bound an interval; they
cannot prevent later changes or establish permanent immutability. A version-specific S3
`GetObject` selects a particular object version, whereas omission selects current content;
ETag is an opaque identifier, not a CloudTrail signature.
[AWS GetObject reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)

All delivered records remain in their source objects. Across the staged batch, identical
canonical records for one identity count as duplicate deliveries; different complete
records for that identity remain explicit conflicts. Unknown fields participate. Public
`unique_event_count` counts distinct identity keys, and duplicate counts count repeated
identical variants, not a license to erase a conflicting variant. The batch ID binds the
scope/limit/version fingerprint and ordered source-version/archive/content-hash material.

`MemoryLedger` commits the complete immutable batch and checkpoint through an in-process
lock and generation compare-and-swap. A failed poll does not advance its checkpoint;
stale generations and changed-scope reuse are rejected. Exact committed replay returns
the cached batch without another transport call. That is a historical replay, not a fresh
identity/continuity check. The ledger has no database, disk persistence, restart recovery,
cross-process transaction or crash-durability guarantee. It is not the earlier durable
synthetic batch/checkpoint implementation.

## Controlled digest assessment and future authenticity

The [assessment boundary](../../src/cloudsecops_live/integrations/aws_cloudtrail/validation.py)
accepts typed `ControlledValidation` test observations. It checks command outcome,
completeness, observed continuity, standard/backfill/signature outcomes, local byte hashes,
and exact member location/version/content hash. Independently rehashed byte domains are
insufficient: retained content must equal bounded decompression of the exact retained
archive. Strict nested types, byte ceilings, exact declared size and current non-delete,
non-null-version metadata are checked before consistency can pass. Missing or delayed observations stay
pending; invalid checks stay invalid; contradictory exact-member hashes conflict.
Even the consistent path returns `AWS_AUTHENTICATION_UNAVAILABLE` with
`authenticated=False`. The dataclass is not a signed authoritative receipt, CLI-output
parser, cryptographic validator or supported AWS acquisition implementation.

`consistency_passed` covers archive/content and controlled digest-member byte consistency
only. It does not verify normalized-event derivation, approved collection scope, retrieval
timing or actual S3 continuity; caller-supplied observations cannot establish those facts.
Those remain independent future acquisition/authentication and trusted-ingestion gates.

Future authenticity must use the supported CloudTrail validation behavior and preserve
the evidence needed to bind its result to the imported file. The AWS CLI requires online
access and original S3 locations; it cannot validate a local download. It validates only
digest-referenced members and processes standard and backfill chains separately. A future
run needs explicit trail, Region, bucket/prefix, bounded UTC interval and verbose per-file
results, including every imported file's exact location and any unvalidated interval.
[AWS CLI integrity-validation guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html)

AWS digest members contain bucket, key and a hash of **uncompressed log content**. They do
not contain a VersionId. The previous-digest hash also covers uncompressed content. The
current signature is S3 object metadata; backfill-generation metadata helps select the
appropriate signing key. Digest intervals describe delivery time, which may differ from
event time. Missing digests can reflect delayed/out-of-order redelivery, while disabled
validation or stopped logging can create genuine coverage gaps. Empty authenticated
digests and absent digests are different evidence.
[AWS digest structure](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html)

`DigestMember.version_id` is therefore a local future binding requirement, not a field
AWS signed in its digest. The supported `validate-logs` command has no VersionId option.
A successful current-key check cannot by itself attest a separately downloaded historical
version or the raw gzip container. A future implementation must reconcile exact pinned
retrieval, signed bucket/key/content membership, and observed version continuity, with a
documented treatment of changes and history.
[Supported validate-logs options](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/validate-logs.html)

Signature validation must precede trusting member hashes. Public keys must come from the
digest's delivery Region, cover the relevant signing time and match its fingerprint;
validity periods may overlap. An offline verifier needs securely retained original digest
bytes, newest-signature metadata and the necessary AWS public keys. Re-serialized JSON
is not the original signed content. These capabilities are future work here.
[AWS custom-validation specification](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html),
[AWS ListPublicKeys reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_ListPublicKeys.html)

CLI exit zero and a local receipt checksum are not sufficient authenticity evidence.
The generic exit code describes command/service success; it does not replace exact
membership, chain coverage or version binding. No assumption is made that every integrity
failure necessarily produces nonzero status in every supported CLI version.
[AWS CLI return codes](https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-returncodes.html)

The AWS CLI paginator's opaque `NextToken`/`--starting-token` is separate from the S3
service marker pair. A later adapter must document which layer its receipt represents;
`--no-paginate` or a truncated `--max-items` result cannot supply complete listing proof.
[AWS CLI list-object-versions reference](https://docs.aws.amazon.com/cli/latest/reference/s3api/list-object-versions.html)

## Infrastructure and readiness

Terraform JSON source and a closed structural policy checker prepare a reviewable minimal
design. Terraform is absent on this machine: formatting, initialization, provider-schema
validation, provider installation/checksum lock verification, plan, apply and destroy are
**NOT_RUN**. Structural allowlist/mutation checks do not prove provider compatibility,
effective IAM, successful service delivery, ownership or cost. Runtime read roles are
distinct from the test actor and external provisioning/cleanup authority. Retention
guards are not administrator-proof WORM; see the infrastructure README for the exact
source and remaining state, policy, retention and deployment gates.

Wazuh remains **NO-GO**. The latest six read-only Windows availability samples were
5.588–5.900 GiB, below the 12 GiB readiness gate; WSL shares that physical RAM. No install,
resource change, rented fallback, sender or SIEM query receipt is supplied. The historical
PostgreSQL SIGSEGV followed shared-memory exhaustion during simultaneous suites; its cause
remains unproven. Sequential supported acceptance is separate evidence, not a native
engine fix. Neither blocker is waived by the offline AWS demonstration.
