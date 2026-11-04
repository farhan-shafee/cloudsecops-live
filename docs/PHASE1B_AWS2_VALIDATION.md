# AWS2 offline validation record

Starting main: `5e860dffb3e13b82121afa8e7b82e8d43a2ad639`, tree `ec98d22dafb0eb1a1d2a2f72d9e5b95588d98b79`. Work is isolated on `codex/phase1b-aws2-secure-live-runner`. No AWS, credentials, retained database, Docker, Wazuh or deployment operation is part of this acceptance.

## Local evidence

The final Python3.14.8 Windows run passed **2,051 tests and 11 subtests**, with no skips. Ruff formatting/lint and strict mypy passed. Existing hash-locked boto3/botocore1.43.123 were used, with no dependency changes. Dependency audit reported no known vulnerabilities; the unchanged secret/identifier scan, Terraform structural gate and wheel/sdist build passed. The native Terraform gate is separate and requires hosted execution; a structural pass is not native validation.

The existing Python3.12 virtual environment lacked botocore and failed initial collection. Its attempted hash-locked repair stalled and only that task-owned installer was terminated. Acceptance uses the existing pinned Python3.14 environment locally and both required Python versions in hosted CI. An exploratory full run during source edits failed nine new runner tests; that run is not accepted. Stable full reruns passed after the fixes. No old test or gate was relaxed.

Actual branch measurements for the final local report are recorded in private `coverage.json` and checked by `scripts/check_coverage.py --require-aws --require-aws1 --require-aws2`. Contracts, CLI preflight, SDK budget and process modules must each reach85%. Bootstrap, socket and native containment measurements remain visible without exclusions; Windows percentages do not claim Linux execution. Full-database package coverage remains90% and every earlier security/foundation threshold remains mandatory in disposable CI.

Real owned processes and numeric-loopback sockets cover hung resolver simulation, TLS/header/chunk/body stalls, interrupted/oversized/malformed responses, cancellation races, child/grandchild cleanup, unrelated sentinel survival, late creation and delayed gates. Fake SDK assembly covers exact identity, budget enforcement and mutating-operation denial inside the isolated worker. Two scripted HTTP responses share a three-byte body cap: the first succeeds and the second is rejected/closed before exposure. No successful lifecycle receipt follows a security failure.

## Independent review corrections

- Enforced the operation ceiling at actual SDK dispatch, including STS.
- Preserved the exact existing disabled-Insights observation while permanently rejecting malformed error metadata/status types.
- Rechecked absolute cutoff during gate writes and before child imports/action; prevented delayed dispatch after a deadline.
- Hid private response bytes/import paths from representations and bounded the complete framed IPC protocol.
- Made unknown Linux owned-member state fail closed, including readable zombies mixed with unreadable/malformed live members.
- Required explicit provenance observations; sanitized malformed trusted configuration and huge numeric inputs.

The independent source review found no unresolved material issue after readback and targeted verification. This does not replace fresh review of the published final commit. [Architecture](architecture/AWS_SECURE_RUNNER.md) states the trusted-code, OS scheduling, late-creation, CLI provenance and effective-IAM limitations.

## Reproduction and hosted gate

```powershell
.venv/Scripts/python.exe -m ruff format --check .
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m mypy
.venv/Scripts/python.exe -m pytest --cov=cloudsecops_live --cov-branch --cov-fail-under=0 --cov-report=json --cov-report=xml
.venv/Scripts/python.exe scripts/check_coverage.py --require-aws --require-aws1 --require-aws2
.venv/Scripts/python.exe scripts/check_secrets.py
.venv/Scripts/python.exe scripts/check_terraform.py
.venv/Scripts/python.exe -m pip_audit --require-hashes --disable-pip -r requirements-dev.lock --strict --progress-spinner off
.venv/Scripts/python.exe -m build --no-isolation
```

Linux uses `.venv/bin/python`. Do not run `scripts/run_integration.py` against retained local resources. Required hosted checks remain the four Ubuntu/Windows Python3.12/3.14 validate jobs, two sequential PostgreSQL recovery jobs, isolated PostgreSQL harness safety, native Terraform/provider security and two dependency audits. Their actual exact-head outcomes and fresh published review belong to the PR/final delivery receipt; no workflow definition or earlier main run establishes those results.

**Live AWS remains NO-GO.** Readiness requires separately authorized real temporary identity/issuance, effective permissions, a fixed approved live worker assembly, verified tool artifacts and CLI-internal budgets, private custody, owner scope/window/cost/retention/recovery decisions and later source authenticity acceptance. Wazuh and retained PostgreSQL capacity stops remain unchanged.
