# Guarded AWS transport: independent practical assessment

Work without an AI assistant, live AWS, credentials, metadata access or provisioning.
Use the hash-locked setup in README and generated fixtures in `tests/aws_sdk_helpers.py`.
Timebox90minutes. The assessor keeps the expected results below hidden until grading.
Record commit, versions, commands, observed error codes, test outcomes and limitations.
Human mastery remains NOT_RUN until independently observed; automated tests are separate.

## Practical tasks

1. Explain identity versus authorization versus authenticity. Trace `SessionLease`, STS
   account/role unique ID/session binding and expiry. Identify why a human-readable role
   name or a successful SDK response does not establish trusted CloudTrail delivery.
2. Run `python -m pytest tests/test_aws_sdk_transport.py -q`. Add an independently expected
   test for a wrong role session, then explain the earliest rejected call and why no S3
   read should occur. Distinguish transport retries from SDK retries.
3. Build a two-page fake version listing with a delete marker. Demonstrate both opaque
   pagination markers and `ExpectedBucketOwner` on list, HEAD and exact-version GET.
   Diagnose an omitted owner guard, wrong VersionId and an apparently empty error page.
4. Inject short reads, then an interrupted/oversized stream. Show legal partial reads
   remain supported while byte/read-call/expiry limits stop the invalid read and the
   collector advances no checkpoint. Explain compressed versus decompressed hash domains.
5. Run `python -m pytest tests/test_aws_cli_receipts.py -q`. Trace the pinned verbose output
   grammar. Remove one expected member while leaving exit0; change a before/after version;
   introduce standard/backfill disagreement. Predict outcomes before running each test.
6. Explain signed digest membership, chain gaps and original locations. Show which required
   fields CLI human output omits. Demonstrate why adding `authenticated=true`, substituting
   unrelated successful output or matching only compressed SHA cannot grant authority.
7. Trace the old synthetic CLI and durable quarantine boundary. Show that an AWS-shaped
   record or prepared receipt cannot become a synthetic reviewed/closed case. Run only the
   existing authorized sequential PostgreSQL harness if an assessor supplies local access.
8. Review `docs/AWS_LIVE_READINESS.md`: propose four separate owner decisions. Identify
   unresolved effective IAM, retention/holds/cost, state custody and source authenticity.
   Explain why Wazuh memory and the historical PostgreSQL crash remain separate blockers.

## Assessor expectations

| Task | Independent expected result | Points |
| --- | --- | ---: |
| Identity | Temporary explicit credentials, trusted account/region/role ID, expiry; no ambient/default session, no credential disclosure |15 |
| STS failure | Wrong/expired identity rejected before source access; error reveals no response/secret; SDK retry budget cannot multiply outer budget |10 |
| S3 | Every page/version/delete marker retained; paired continuation; exact bucket/prefix/owner/version enforced; no generic bucket collection |15 |
| Stream | Partial reads succeed; interrupted/oversized/expired stream fails with no committed batch; close and bounds demonstrated |15 |
| Receipt | Missing member, changed version and chain disagreement cannot produce consistent authentication; exit0 insufficient |15 |
| Authenticity | CLI output not a signed receipt; exact content membership and version continuity required; every current result authFalse |10 |
| Workflow | No accepted AWS event/finding/case authority; permanent quarantine/no checkpoint demonstrated using independent assertions |10 |
| Owner readiness | Four distinct permissions, current regional quote still missing, indefinite storage costs, Wazuh and native-crash caveats retained |10 |

Pass>=85/100 with every security-negative task demonstrated. Hard fail for real AWS
access, credential disclosure, weakening tests, claiming authentication from fixtures,
using AWS-shaped data to close a case or treating an alert/approval as remediation.
For an unseen variation, swap one raw digest location and one retained object version
without changing the log count. Candidate must localize both bindings and explain the
result before editing code. Reassess after a provider/SDK/CLI output-contract change.
