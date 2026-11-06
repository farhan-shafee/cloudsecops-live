# AWS4B signed CloudTrail verification: independent practical lab

Human mastery assessment: **NOT_RUN**. Complete without an AI assistant or AWS access.
Use only repository fixtures and generated test material. Do not read credential
files, issue sessions, invoke AWS CLI, create IAM resources, run Terraform plan/apply,
start PostgreSQL or install Wazuh. A reviewer assesses actual results, not memorized
terminology or a passing badge. Read the
[offline architecture](../architecture/AWS_SIGNED_OFFLINE_VERIFICATION.md),
[AWS custom-validation specification](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html)
and [CLI receipt boundary](../architecture/AWS_CLI_RECEIPT_CONTRACT.md).

From the repository root after hash-locked setup:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_aws_signed_verification.py -q
```

Before modifying a copied fixture, write the expected result, the failed boundary and
the exact authority fields that must remain false. Retain source revision, commands,
sanitized failures and explanations privately. Never publish account-specific source
locations, raw evidence, session material or private keys. Do not change the production
worker or remove acceptance gates to make an exercise pass.

## Practical exercises

1. **Reconstruct the signing bytes.** Trace `verify_bundle` through contracts, parsing,
   crypto and verification. Independently construct a fixture digest's signing string
   from its original timestamp, bucket/key, uncompressed hash and previous signature.
   Explain literal `null` for a starting digest, LF separators and why JSON
   reserialization is unsafe. Change one byte of the original uncompressed digest
   while leaving its signature unchanged. Show signature failure. A matching hash
   computed from the changed file is not a repair.
2. **Separate hash domains.** Record compressed/archive and decompressed/content
   hashes for one fictional object. Recompress the same content with different gzip
   metadata. Explain which hash changes, which signed member hash stays the same and
   why custody observations must still reject an unexpected archive replacement.
   Substitute an ETag or archive SHA-256 for a signed member hash; demonstrate failure.
3. **Attack key selection.** Supply another generated fixture key with the same claimed
   fingerprint, wrong Region or wrong validity interval. Predict rejection and verify
   it. Exercise a valid key rotation with overlapping intervals; explain why the exact
   independently supplied key binding is required. Show that a bundled public key
   cannot authenticate itself. Explain the absence of real AWS key provenance here.
4. **Inspect standard and backfill separately.** Remove a middle standard digest,
   change a previous hash or signature, and substitute a backfill link into a standard
   chain. Each must fail its own chain checks. Explain why an old event timestamp can
   be valid in a newly delivered log, and why backfill key time uses generation
   metadata. Identify the fact that this metadata is not separately authenticated by
   a supplied fixture signature.
5. **Test restart, coverage and replay.** Insert a starting digest into the middle of
   the requested continuous interval; do not treat its valid standalone signature as
   full coverage. Replay an older valid complete chain against the requested date/head
   bindings. Explain why it fails. Remove all backfill inputs and explain why that
   cannot establish that AWS delivered no backfills. Name the independent inventory
   evidence still missing from the offline test.
6. **Bind source membership and versions.** Change only a fictional bucket, key,
   VersionId, current/delete observation, or before/after continuity observation.
   Show rejection, even when content hashes match. Explain precisely which signed
   fields bind the source and why AWS does not sign VersionId in the digest. A valid
   CLI-shaped exit0 receipt with an unrelated validated member must remain insufficient.
7. **Exercise full-record semantics.** Replay one identical log event and verify that
   duplicates cannot inflate counts. Change an unknown complete-record field while
   retaining its event identity; demonstrate conflict rather than selecting a useful
   variant. Explain why normalization alone would hide this change. Neither result
   grants trusted findings or synthetic-workflow closure authority.
8. **Probe bounds without resource stress.** Use reduced fixture limits or one-over
   test cases for digest/log counts, compressed/expanded sizes, total expanded bytes,
   records, malformed JSON and unsupported formats. Show deterministic, non-sensitive
   rejection without printing input content. Do not generate uncontrolled decompression
   bombs or run retained local database suites.
9. **Attempt authority forgery.** Add an authenticated flag, successful CLI status,
   caller-selected trust label or fabricated closure claim to a controlled input.
   Demonstrate rejection or an unauthenticated failure result. For every accepted
   fixture, show `authenticated=false`, `trusted_findings=false`, `may_close=false`.
   Explain why mathematical signature validity under a fixture key is not AWS origin,
   actor intent, incident confirmation or proof of no compromise.
10. **Write the first-live acceptance handoff.** List separate owner decisions for
    bounded read-only access, any later provisioning, test activity and cleanup.
    Identify genuine public-key custody, retained signature metadata, exact source
    versions, before/after observations, complete standard/backfill inventory,
    supported CLI2.37.11 parity and exact membership. Preserve effective-IAM/S3 mapping,
    temporary issuance/MFA, OS containment and private evidence limitations. Explicitly
    retain PostgreSQL and Wazuh NO-GO plus the unresolved SIGSEGV and original ACL
    timeout/separate retry; no fixture success fixes these operational conditions.

## Independent rubric

The assessor chooses at least one unannounced mutation per category. Expected
outcomes come from the documented invariants and independently calculated bytes,
not from copying the verifier's current result into an expected-value assertion.

| Category | Points | Required evidence |
| --- | ---: | --- |
| Signature and byte domains | 20 | Independent signing-string derivation, literal-null handling, tampered signature failure and archive/content distinction |
| Keys and source membership | 20 | Substituted/wrong-Region/out-of-interval key rejection; exact bucket/key/content and independent version binding explained |
| Chains, coverage and replay | 20 | Missing/mutated/cross-chain/restart/replay failures; no invented backfill absence or event-time coverage claim |
| Hostile input and authority | 20 | Bounded malformed/oversized input rejection, full-record conflicts and all three authority flags false |
| Operational handoff | 20 | No real access, private receipts, genuine live prerequisites, effective-IAM limitations and preserved historical blockers |

Pass requires at least85/100 and successful rejection of every assigned security
fault. A mandatory rejection failure overrides aggregate score. AWS/credential access,
trust promotion, hidden failing tests, retained-database operations, IAM change or
production worker activation is an automatic fail. Record shortcomings and a new
independent reassessment date; automated software acceptance does not award human
mastery, live AWS acceptance or production security experience.
