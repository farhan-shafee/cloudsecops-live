# AWS4A posture worker: independent offline practical lab

Human assessment: **NOT_RUN**. Complete without AI or AWS connectivity. Use only
fictional fixtures and controlled numeric-loopback servers. Do not read credential
files, invoke AWS CLI, start PostgreSQL, change containers or edit IAM/Terraform.
Read the [architecture](../architecture/AWS_POSTURE_NETWORK.md),
[owner permission clarification](https://github.com/farhan-shafee/cloudsecops-live/issues/11#issuecomment-6670869085)
and [live-readiness gates](../AWS_LIVE_READINESS.md).

After the repository's hash-locked Python setup, use the existing test environment:

```powershell
.venv\Scripts\python.exe -m pytest tests/test_aws4a_contracts.py tests/test_aws4a_budget.py tests/test_aws4a_engine.py tests/test_aws4a_clients.py tests/test_aws4a_wire.py tests/test_aws4a_process.py -q
.venv\Scripts\python.exe scripts/check_aws3_permissions.py
.venv\Scripts\python.exe scripts/check_terraform.py
```

These commands provide software evidence only. Before each deliberate failure, write
the expected error category, whether any fake dispatch should occur and which receipt
fields must remain false. Keep source revision, commands and sanitized results for the
assessor. Do not include private account identifiers, policy bodies or session material.

## Practical tasks

1. Trace `run_posture_network` through the literal bootstrap to `worker.execute`.
   Explain native containment, the parent start gate, standard-library-only request
   parsing and why the result is always `AWS4A_EXECUTION_DISABLED`. Add `enabled`,
   `credentials` or `endpoint` to a copied request. Demonstrate rejection without
   owner-record lookup or client construction. Explain why a new environment flag
   would violate the milestone rather than complete it.
2. Alter one field of a fictional owner decision at a time: source revision, immutable
   RoleId, UTC end, policy fingerprint and nonce binding. Predict which changes modify
   its digest or reject redemption. Demonstrate exactly one winner for concurrent
   capability redemption and failure after a consumed attempt. Explain why the
   in-process test capability is not real OS custody, actual issuance or approval.
3. From the fixed eight-operation table, independently count the single-policy path.
   Explain the thirteen-call minimum and the five final rereads. Inject a changed final
   policy hash or STS UserId; the run must fail. Explain what a change between two
   successful rereads could hide and why matching policy bytes do not compute effective
   IAM or resolve permissions boundaries/session-policy effects.
4. Compare account S3 Control `GetPublicAccessBlock(AccountId=approved_account)` with
   bucket `GetPublicAccessBlock`. State the retained IAM action and exact
   `s3:ResourceAccount` condition. Inject a bucket path, missing AccountId and another
   account header. Each must reject before fake send. Describe the conflicting SAR
   mapping as unresolved live preflight; do not repair it with new permission or a
   live probe. An account permission denial must remain failure.
5. Demonstrate valid zero-trail/zero-bucket results from complete successful fake
   pages. Then replace one page with AccessDenied, an error-shaped empty response,
   missing pagination metadata or repeated token. None may produce successful empty
   inventory. Separately replace an account BPA value with false, null or integer1;
   all must fail the owner's exact-boolean-true requirement.
6. Inspect both SDK parameter and final wire guards. Add an independent regression
   test that changes an IAM RoleName in a later SDK event handler after logical
   reservation. Show that the final serialized request fails before transport. Then
   test a changed policy name or S3 Control account header. Removing the final wire
   binding in a disposable working copy must make this test fail; restore it before
   continuing. Do not weaken another test or change approved runtime code permanently.
7. Use the controlled tests for overlong headers/chunk lines, encoded XML entity
   declarations and unknown raw BPA fields. Explain why bounding a parsed SDK dict
   alone is too late, and why unknown fields cannot safely be discarded first.
   Distinguish charged plaintext HTTP bytes from TLS/TCP packet accounting. Set a
   fictional aggregate budget one byte below the required charge and prove rejection.
8. Run the isolated DNS/TLS/header/chunk-stall tests in `test_aws4a_process.py`.
   Explain why botocore connect/read timeouts alone are insufficient. Show the parent
   deadline/cancellation receipt and owned-tree cleanup; a failed cleanup may not yield
   successful evidence. Do not kill unrelated processes. Explain the remaining OS
   scheduling/native-code and Python-guard limitations honestly.
9. Inspect a sanitized fake result. Identify every false authentication/findings/
   closure field and explain why a successful STS response, matching SHA256 or prepared
   CLI2.37.11 receipt cannot authenticate AWS logs. Name the missing exact signed-file
   membership, standard/backfill chains and version-continuity work without implementing
   AWS4B. Explain why this result cannot authorize the synthetic approval/closure path.
10. Write a one-page handoff naming current live blockers: owner authorization,
    short-lived non-root MFA issuance, real broker/custody, effective IAM/S3 mapping,
    OS egress/containment, TLS/CA, cost/stop responsibility and private receipts. Preserve
    the ended historical CLI session, unproven PostgreSQL SIGSEGV, original ACL timeout
    with separate successful retry, and PostgreSQL/Wazuh NO-GO conditions. No software
    test may be presented as a fix or a live acceptance run.

## Independent rubric and expected evidence

The assessor scores explanations and retained actual results, not confidence or a CI
badge. Each category is20points:

| Category | Full-credit evidence |
| --- | --- |
| Dispatch and authority | Closed request rejects extra fields; production path always disabled; pending metadata/fictional capability do not grant authority |
| Identity and policy drift | Correct thirteen-call trace; changed immutable identity/policy fails; one-use redemption; effective-IAM and reread race limitations explained |
| S3 scope and response semantics | Exact account API/action/condition retained; bucket/account substitutions and denials fail; valid zero counts and exact BPA booleans distinguished |
| Wire, budgets and lifecycle | Independent final-wire mutation test; bounded framing/bytes; watchdog and owned-tree cleanup evidence; no timeout/sandbox overclaim |
| Trust, privacy and operational handoff | No secret output; all authority flags false; source authenticity remains future work; historical failures and live blockers preserved |

Pass requires at least85/100 and rejection of every assigned security fault. Missing
or unexplained mandatory rejection is a fail regardless of score. Actual AWS or
credential access, IAM changes, hidden failing tests, unrelated process termination,
retained-database operations, a live activator or trust-promotion claim is an automatic
fail. The assessor records source revision, observed outcomes and remediation privately.
Automated acceptance does not award human mastery or production experience.
