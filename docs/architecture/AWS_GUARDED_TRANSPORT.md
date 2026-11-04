# Guarded injected AWS SDK transport

This offline-tested adapter implements `ReadTransport`; it does not authorize live AWS
access. Boto3/botocore1.43.123 are pinned with hashes. There is no client factory, default
session, credential discovery, live CLI or authenticated-source constructor. Dedicated
injected clients are mutated to install request/raw-response guards and must not be shared
with unrelated work. A trusted local operator can replace Python objects; this is not a
sandbox against code executing in the same process.

## Inputs and supported calls

`AwsSdkTransport(scope, lease, sts_client=..., s3_client=..., cloudtrail_client=...,
clock=..., limits=...)` requires the existing immutable `AwsScope` and `SessionLease`.
The lease contains UTC issue/expiry, expected assumed-role principal/user ID and temporary
access-key identifier; private fields are hidden from repr. It contains no password,
secret access key or session token. Those remain only in the injected clients' shared
explicit static credential object. Refreshable/ambient credentials are rejected.

| Method | Fixed operation and purpose |
| --- | --- |
| `caller_identity` | GetCallerIdentity; bind exact account, role unique ID and session; region/expiry come from explicit configuration, not imaginary STS response fields |
| `list_versions` | ListObjectVersions; exact bucket/prefix/ExpectedBucketOwner/MaxKeys, paired opaque continuation, preserve versions and delete markers |
| `head_current` | HeadObject without VersionId; observe current version and bounded metadata before/after collection |
| `get_object` | GetObject with exact VersionId and ExpectedBucketOwner; bounded streaming, byte equality and closure |
| `inspect_trail` | GetTrail/GetTrailStatus/GetEventSelectors/GetInsightSelectors on exact trail; strict management-only single-region source configuration |

The existing collector owns complete bounded pagination, final version continuity,
staging and checkpoint CAS. It rejects historical/deleted/null-version inputs rather
than silently omitting them. The SDK adapter preserves those observations so this policy
can operate. The checkpoint ledger remains an in-memory reference, not AWS durability.
STS identity is checked immediately before source/configuration operations; local lease
and client bindings are checked before/after operations and each read.

## Request and response boundary

Only exact commercial regional HTTPS endpoints are accepted. TLS verification must be
enabled; proxies must be empty. Clients share the same explicit temporary credential
object, fixed signature settings, connect timeout<=10seconds, read timeout<=30seconds and
`total_max_attempts=1` (zero SDK retries). Classified transient reads may consume the
existing collector's bounded attempt budget. TLS, ownership, identity, source and malformed
responses fail permanently with fixed non-sensitive codes; raw service messages are not
included. Modeled Insights-disabled observations are distinct from empty success.
Partially read/interrupted bodies fail permanently at this acquisition boundary; no
partial-body resume is attempted. A future collector must start a fresh bounded attempt
with new continuity checks rather than treating partial content as a complete object.

An installed HTTP send guard forces streamed receipt before the pinned SDK's eager
buffering, restores request mode, rejects prebuffered responses and installs a raw-byte
guard before parsing. Control/error bodies are capped at1MiB by default; successful object
bodies are bounded by the10MiB object limit plus a one-byte excess probe. Raw reads use
`read1(..., decode_content=False)`, at most64KiB per read, with byte/read-call/lease checks
and close-on-failure. Raw read-call ceiling is1,024. Application object reads separately
enforce declared size and1,024calls. Limits may be reduced; no exclusion hides error paths.
HEAD metadata Content-Length describes the object, while its actual HTTP body is empty.

These are payload and per-I/O safeguards. DNS, response headers and HTTP chunk framing
are not subject to a safely cancellable total deadline here. A future approved live runner
must enforce process/operation cancellation and tool/client provenance. Neither current
timeouts nor a test clock proves compliance with an owner's full wall-clock operating
window. The pinned private botocore/urllib3 compatibility must be re-reviewed on upgrade.

The prepared Terraform collector IAM does not include GetInsightSelectors; the separate
verifier role does. Choose an explicitly approved inspection role or fail closed; this
adapter does not acquire roles, broaden policy or invoke AssumeRole. Static IAM shape and
native provider validation do not establish effective account permissions.

## Authority and acceptance

SDK responses supply acquisition observations, not AWS signed-source authenticity. Every
collection/inspection result remains AWS-shaped unverified. Prepared
[CLI receipts](AWS_CLI_RECEIPT_CONTRACT.md) cannot bridge into accepted synthetic events,
findings, recommendations or closure. No database migration or new web route is added.

Independent tests use fake clients, real pinned service models under Stubber, scripted raw
HTTP responses and denied Python sockets. Real PostgreSQL boundary tests require permanent
quarantine with no accepted events/checkpoint/case mutation. Full database/HTTPS/recovery
acceptance runs sequentially in isolated CI; the current local shared-memory capacity
failure is documented separately in [recovery](../FAILURE_AND_RECOVERY.md).
Owner decisions and live-only gaps remain in [readiness](../AWS_LIVE_READINESS.md).

Sources: official [credentials](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html),
[configuration](https://docs.aws.amazon.com/boto3/latest/guide/configuration.html),
[retry semantics](https://docs.aws.amazon.com/boto3/latest/guide/retries.html),
[version listing](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html),
[exact retrieval and owner protection](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)
and [Insights inspection](https://docs.aws.amazon.com/boto3/latest/reference/services/cloudtrail/client/get_insight_selectors.html).
