# Fixed workers and least-privilege identities: independent practical lab

Human assessment: **NOT_RUN**. Complete without AI or AWS connectivity. Use only
fictional fixtures; do not read credential files, start PostgreSQL or alter containers.
Read the [architecture](../architecture/AWS_FIXED_WORKERS.md) and
[permission difference report](../PHASE1B_AWS3_PERMISSION_DIFFERENCES.md).

After the repository's hash-locked Python setup, run:

```powershell
.venv\Scripts\python.exe -m pytest tests/test_aws3_sessions.py tests/test_aws3_registry.py tests/test_aws3_workers.py tests/test_aws3_sdk_binding.py -q
.venv\Scripts\python.exe scripts/check_aws3_permissions.py
.venv\Scripts\python.exe scripts/check_terraform.py
```

1. Trace `run_posture_inspection` to the literal worker and independent watchdog.
   Explain why a JSON module name cannot select executable code. Inject an extra
   `worker` field into a copied fictional request and demonstrate rejection.
2. Change only STS UserId's RoleId in a fixture. Predict the rejection before running.
   Then reuse the posture RoleId for a collector while changing its friendly name.
   Explain immutable identity, MFA observations and why neither proves effective IAM.
3. Add an inline policy name to inventory without adding it to the explicit name
   allowlist. Show owner-review-required, with no new policy read. Explain why even a
   requested policy's returned JSON is not a reviewed effective-permission result.
4. Propose `s3:HeadObject` for posture inspection. Demonstrate capability rejection;
   explain its `s3:GetObject` IAM requirement and why the existing audit role stays
   inspection-only. Compare collector and verifier scopes without widening either.
5. Change the current object version after retrieval and separately change an unknown
   source field under the same event identity. Show continuity rejection versus full
   record conflict. Distinguish gzip custody SHA256 from digest content SHA256.
6. Inject the fixed stall fault and demonstrate bounded owned-tree shutdown. Inspect
   only the task-owned process receipt; do not terminate any unrelated process. Show
   that failed cleanup/cancellation cannot produce successful evidence.
7. Add a per-instance credential callback or replace a token on an existing static
   object. Prove failure without invoking the callback or dispatching any fake client.
8. Review the sole Terraform collector permission delta and write a short explanation
   of the unchanged trust/MFA gap. Explain why a provider-schema pass does not prove
   role assumption, effective policies or CloudTrail delivery.
9. Explain why fixture consistency, a successful SDK response and CLI exit0 cannot
   authenticate AWS evidence or authorize the existing synthetic closure workflow.

The assessor grades independently from retained test output and code explanations:
20points fixed dispatch/deadlines;20 identity/session/substitution;20 least privilege
and trust gap;20 version/hash/conflict handling;20 privacy/authenticity/live stop gates.
Pass requires at least85/100 and every injected security failure rejected. Any actual
AWS request, credential access, administrator fallback, hidden failing test, unrelated
process kill or trust-promotion claim is an automatic fail. Record observed results,
source revision and assessor privately; automated CI grants no human mastery score.
