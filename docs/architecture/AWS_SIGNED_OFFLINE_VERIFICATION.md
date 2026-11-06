# Offline signed CloudTrail verification: AWS4B

AWS4B adds a pure offline verification boundary under
`integrations/aws_cloudtrail/signed/`: contracts, bounded parsing, cryptographic
checks and bundle verification. `verify_bundle` consumes supplied original bytes,
independently supplied trusted public-key bindings and retained acquisition/version
observations. It creates no AWS client, subprocess, live command, database connection
or workflow authority. The existing `cryptography==50.0.2` dependency supplies the
reviewed RSA implementation; this project does not implement RSA arithmetic.

The starting protected main is `5394044239e6eecc199722e3a1040b4a8df858eb`, tree
`5cb28b36730296e44ebe256b3396fda2e4924d22`, the normal PR#12 merge. The historical
signing-session P2, failing pre-fix regressions and corrected acceptance evidence
remain preserved. AWS4A production dispatch remains unconditionally disabled, and
its final SigV4/session binding, budgets and process watchdog remain unchanged.

## What the result establishes

A successful result establishes cryptographic consistency of the supplied fixture
bundle against the separately supplied key and acquisition assumptions. Every result
retains `authenticated=false`, `trusted_findings=false` and `may_close=false`.
There is no authenticated-source constructor or bridge to synthetic findings,
recommendations, reviewer approval, independent incident verification or case closure.
An internally consistent fixture is not evidence that AWS delivered it.

Public output is a bounded summary of checks and limitations. Original bucket/key,
account and role identities, evidence bytes, acquisition observations and detailed
receipts belong in private custody. Tests contain fictional identifiers and generated
fixture signatures; no real private key, credential or sensitive AWS evidence belongs
in Git. Tool versions, passing tests and hashes do not authenticate their own inputs.

## Signature and hash domains

AWS documents a four-part UTF-8 signing string: the digest's original ending timestamp,
its `bucket/key` path, SHA-256 hex of its original uncompressed bytes, and the previous
digest signature hex, separated by LF. Preserve the original bytes and timestamp
representation; do not reserialize parsed JSON or use the archive hash in that string.
The RSA algorithm is PKCS#1 v1.5 with SHA-256. For a starting digest, the final component
is the literal `null`; this matches the pinned AWS CLI implementation. No additional
newline or `s3://` prefix is added. [AWS custom-validation specification](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html),
[AWS CLI2.37.11 reference implementation](https://github.com/aws/aws-cli/blob/2.37.11/awscli/customizations/cloudtrail/validation.py)

| Retained value | Meaning |
| --- | --- |
| Compressed archive SHA-256 | Custody of the exact retained gzip bytes; not the signed member hash |
| Uncompressed digest SHA-256 | Input to the signature string and previous-digest link |
| Uncompressed log SHA-256 | Compared with the signed digest member's `hashValue` |
| Canonical complete-record fingerprint | Parser identity/conflict handling; cannot replace the signed original byte domain |
| S3 ETag | Never treated as a CloudTrail digest, signature or authoritative content hash |

Signature verification precedes accepting a digest's member hashes. Signed membership
binds bucket, exact key and uncompressed content hash. It does **not** sign an S3
VersionId or the gzip container. Each accepted member must also match independently
retained acquisition/version observations and independently recomputed archive/content
hashes. Deleted, overwritten, conflicting, missing or ambiguous observations fail
closed; matching ETags or CLI exit0 cannot replace these checks.
[AWS digest fields and metadata](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html)

## Keys, rotation and time

Public keys arrive through a separate trusted input, never a key selected from an
untrusted digest or bundled as its own authority. Match the fingerprint and delivery
Region to the exact retained DER key and its approved validity interval. Key-rotation
intervals may overlap; overlapping validity is not permission to choose an arbitrary
key. Unknown, substituted, ambiguous or out-of-interval material fails closed. AWS's
fingerprint is an identifier supplied by its key API; do not invent a different
fingerprint algorithm or treat an attacker-supplied fingerprint as trust.
[AWS ListPublicKeys](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_ListPublicKeys.html),
[AWS public-key format](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PublicKey.html)

The standard digest interval describes log delivery, not event occurrence. A delayed
log can legitimately contain older events. Backfill key selection uses retained
`backfill-generation-timestamp` metadata instead of assuming that its historical
digest ending time was its generation time. This metadata and the supplied validity
observations are assumptions of the offline test, not independently authenticated
AWS facts. [AWS backfill metadata](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html)

## Chains, coverage and replay

Standard and backfill chains are checked independently. Links bind the previous exact
location, original uncompressed hash and signature. A start/restart has all five
previous-digest fields null; a restart inside a required continuous interval does
not silently repair missing coverage. Missing members, conflicting branches, altered
links, unexpected restarts and inconsistent intervals prevent a successful complete
assessment. Supplied expected interval and terminal/head bindings prevent replay of
an older valid chain as the requested one. They are explicit trusted inputs, not
fresh observations obtained by this implementation.

Backfill digests form a separate chain and need not exist for every standard interval.
No supplied backfill objects is not proof that AWS had none. A verified supplied chain
does not independently establish complete S3 inventory or absence of later backfills.
The receipt must retain that limitation. Empty signed digests differ from missing
digests; neither proves absence of compromise or complete real-world visibility.
[AWS standard/backfill validation semantics](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html)

The supported conservative profile requires each present supplied chain to cover
the requested interval with adjacent delivery boundaries. A sparse backfill chain
outside that profile reports `incomplete`; this does not declare its signatures
invalid or claim that AWS promises hourly backfills. An explicit supplied previous
anchor can bound a partial historical chain. It must match the same trail, chain,
previous location, content hash, signature and boundary time. The anchor's version
and provenance remain supplied assumptions because AWS does not sign a VersionId.

Private successful assessments retain the requested plan, key fingerprints/DER pins
and validity intervals, per-digest chain/key-time/signature hash and exact object and
complete-record bindings. Failed assessments retain no partially accepted bindings.
The public summary exposes none of those private identifiers or hashes.

## Supported bounded profile

This milestone supports the explicit same-Region, single-account, versioned-object
profile only. Unsupported organization, cross-Region or unknown format behavior is
rejected rather than inferred. Limits are ceilings, not permission for live collection:

| Bound | Maximum |
| --- | ---: |
| Requested interval | 24 hours |
| Digests / logs | 32 / 32 |
| Compressed bytes per object | 1 MiB |
| Expanded bytes per object | 4 MiB |
| Total expanded bundle | 16 MiB |
| Total log records | 10,000 |

Existing strict JSON/gzip controls and complete-record conflict handling remain in
force. An identical event delivered twice cannot inflate a count; changed unknown
fields still participate in conflict detection. No historical migration, database
schema, retained source or accepted synthetic parser behavior is changed.

## Reproduce offline checks

After the repository's existing hash-locked Python setup, run from its root:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_aws_signed_parsing.py tests/test_aws_signed_verification.py tests/test_aws_signed_boundaries.py tests/test_aws_signed_gates.py -q
```

This invokes local fixtures only. Do not run `aws`, discover credentials, start the
retained PostgreSQL service or interpret a green unit suite as hosted acceptance.
Exact test totals, coverage, native Terraform outcomes, all ten required CI results
and fresh review must be recorded against the final commit after execution. The
existing CLI2.37.11 receipt contracts remain offline and unauthenticated; this module
does not execute `validate-logs` or replace its future live acceptance.
See the [CLI contract](AWS_CLI_RECEIPT_CONTRACT.md) and
[independent practical lab](../labs/PHASE1B_AWS4B_INTERVIEW_LAB.md).

## First separately authorized live-source acceptance

Before any real evidence can be considered, a different owner authorization must
approve current account/Region/trail/source scope, a non-root short-lived MFA session,
genuine key provenance/custody and the actual bounded read-only acquisition runner.
Resolve the account S3 permission-mapping discrepancy without widening the audit role
implicitly. Review effective IAM, TLS, egress, process containment, cost, private
receipt storage and stop responsibility. This milestone grants none of that access.

Live acceptance must retain current original-location digest signature metadata,
backfill generation metadata, exact source versions and before/after continuity
observations; reconcile complete standard/backfill inventory and stable chain coverage;
and compare supported CLI2.37.11 validation with exact expected signed membership.
CLI exit0 alone is insufficient. Explain any missing, delayed, restarted, conflicting
or changed interval explicitly. Only a separately reviewed authenticated-source intake
could later grant trust, and it must still not equate integrity with benign intent.
Read the [owner readiness packet](../AWS_LIVE_READINESS.md).

Wazuh remains blocked by physical-memory capacity. Retained local PostgreSQL remains
NO-GO; hosted disposable sequential CI does not authorize cleanup, restart or local
acceptance. The native PostgreSQL SIGSEGV root cause and original Windows ACL-probe
timeout remain unresolved; preserve the subsequent successful retry separately.
