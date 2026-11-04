# Secure runner practical interview lab

Complete without AI, real credentials, AWS requests, PostgreSQL or Docker operations. Use the existing hash-locked Python environment. Explain each expected outcome before running it.

```powershell
.venv/Scripts/python.exe -m pytest tests/test_aws_runner_process.py tests/test_aws_runner_faults.py -q
.venv/Scripts/python.exe -m pytest tests/test_aws_runner_contracts.py tests/test_aws_cli_preflight.py tests/test_aws_runner_sdk_budget.py -q
```

Linux uses `.venv/bin/python`. These commands use fictional clients and numeric-loopback fault servers only.

| Exercise | Independently expected evidence | Points |
| --- | --- | --- |
| Draw parent, supervisor, gated worker and descendants. Explain where the monotonic deadline starts and why socket timeouts cannot interrupt hung DNS/chunk parsing. | One absolute deadline, cleanup reserve, no successful receipt after unconfirmed cleanup. | 15 |
| Run the TLS/header/chunk/body stall tests. Change one server to stop sending midway. Explain deadline versus malformed/partial-response failure. | Bounded termination; failed/deadline receipt, no accepted payload or source trust. | 15 |
| Run owned child/grandchild and unrelated sentinel tests. Explain Linux group restrictions and Windows Job inheritance. | Every owned live descendant stops; sentinel survives; arbitrary native-code sandbox is explicitly unproven. | 15 |
| Change a fictional immutable role ID while keeping the display name; expire the session and substitute a different assumed-role suffix. | Permanent identity/lease rejection before source access. A friendly role name cannot prove nonadministrative permissions. | 15 |
| Reduce operation, call, byte and retry limits independently. Demonstrate a failed attempt consuming capacity. | No refund, no unexpected API dispatch, sticky rejection prevents a later success. | 15 |
| Supply correct CLI version text with the wrong artifact/platform or changed after-hash. Then provide internally consistent fabricated observations. | Inconsistent observations fail; even consistent observations remain unauthenticated and cannot close a case. | 10 |
| Explain a launch API that returns after the deadline, cancellation racing completion and a database capacity failure. | Unknown cleanup blocks live readiness; cancellation cannot retain success; no local database suite or cleanup is attempted. | 10 |
| Add one independent regression assertion without copying production logic. Review the final diff for credentials and trust promotion. | Assertion tests a concrete outcome, fixed sanitized error and unchanged synthetic authority. | 5 |

Pass requires at least 85/100 and every safety boundary correct. Any real AWS request, credential lookup, unrelated process kill, claimed source authentication, skipped failure or retained database operation fails the lab regardless of score. An evaluator should check real receipts/assertions, not confidence of explanation.
