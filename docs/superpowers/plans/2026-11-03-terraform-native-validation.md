# Native Terraform validation implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement and independently review the bounded tasks below.

**Goal:** Close PR#6's native Terraform/provider validation gap without AWS access or changing evidence authority.

**Architecture:** A separate CI-only native harness verifies official tool/provider provenance, works in a fresh credential-free copy and permits only dependency locking, formatting, initialization, validation and schema inspection. The existing Python structural policy remains a separate mandatory check. Generated locks are reviewed before being accepted as source.

**Tech Stack:** Python standard library, isolated GnuPG, Terraform1.17.1, hashicorp/aws6.71.0, Ubuntu24.04 GitHub Actions.

**Spec:** Owner's Phase1B-AWS-0R request; starting commit6142c08b4a72412bb6674f46d06417c36bacb47f on codex/phase1b-aws-offline-foundation.

## Global constraints

- Keep PR#6 open and unmerged; main7b8435f8e93c375f83501baace45468ee5e6e9c1 and Wazuh branch unchanged.
- No AWS credential discovery/authentication/API, plan/apply/destroy/import/refresh, remote backend, cloud resource or Wazuh changes.
- Do not modify application authority, source classifications, migrations001–003, dependency locks, accepted data or container limits.
- Run complete local PostgreSQL suites sequentially; preserve retained databases and the unproven historical SIGSEGV limitation.
- Run native tools in disposable CI, not on the memory-constrained workstation; no global tooling/PATH/trust changes.

## Review focus

- Execution before artifact signature/hash verification, including a different executable selected through PATH.
- Registry signing-key assertions without the independently published full vendor fingerprint.
- Missing/forged cross-platform locks and implicit provider upgrades.
- Credential/proxy/Terraform environment hooks, extra configuration, backend/module or private-variable injection.
- Partial native output/schema checks misreported as complete validation or effective IAM proof.

### Task1: Independently specified security regressions and source corrections

Files: tests/test_terraform_security.py, scripts/check_terraform.py, infra/aws-offline/main.tf.json.

- [ ] Reproduce missing exact CLI pin, reserved bucket-name exclusions and the documented service-principal TLS exception with independently authored tests.
- [ ] Make only justified source/policy corrections; retain every original mutation test.
- [ ] Add strict support for the reviewed provider lock while keeping unexpected-file rejection.

### Task2: Verified native harness and independent failure tests

Files: scripts/terraform_native.py, tests/test_terraform_native.py, .github/workflows/ci.yml.

- [ ] Tests first: malformed/incomplete validation JSON/schema, wrong provider/lock/platform hashes, poisoned synthetic environment and bounded/sanitized failure behavior.
- [ ] Verify vendor key fingerprint and detached signatures, signed manifest entries and reviewed artifact pins before tool execution. Bind the actual installed provider binary to the verified archive.
- [ ] Use an isolated empty HOME/config/credential environment and an exact command allowlist. Check native JSON/configuration, actual provider schema, both platforms' official dependency lock and repeated read-only initialization/validation.
- [ ] Add one Ubuntu native CI job using existing SHA-pinned Actions and read-only permissions. Bootstrap may emit a proposed official lock for review, but missing committed locks must fail acceptance.

### Task3: Native observation and lock review

Files: infra/aws-offline/.terraform.lock.hcl and native validation documentation.

- [ ] Retrieve the official dependency-generated lock from the isolated CI receipt, inspect the exact AWS source/version, signed zh hashes and Linux/Windows h1 coverage; do not hand-author hashes.
- [ ] Fix any actual native incompatibility with a regression. Remove bootstrap invocation from the final ordinary validation job.
- [ ] Require normal native init/validate/schema and subsequent read-only lock validation to pass independently of the structural checker.

### Task4: Regression, review and publication

- [ ] Run full units, coverage, formatting/lint/types, security/dependency/package checks and one complete sequential local PostgreSQL acceptance.
- [ ] Independently review final source, harness, IAM assumptions and retention/cleanup limitations. Preserve synthetic-only authority and the Wazuh NO-GO.
- [ ] Commit/publish only this existing branch; verify exact remote tree, all old/new PR and push CI jobs and fresh exact-head Codex review.
- [ ] Record source/tool versions, cryptographic observations, native results, exact changed scope and remaining live-only gates. Leave PR#6 unmerged and stop.
