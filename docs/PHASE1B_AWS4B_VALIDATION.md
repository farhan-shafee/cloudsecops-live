# AWS4B offline verification and acceptance record

Starting protected main is `5394044239e6eecc199722e3a1040b4a8df858eb`, tree
`5cb28b36730296e44ebe256b3396fda2e4924d22`. Local/remote identity, clean checkout
and active ten-check/no-bypass ruleset were independently verified before branching.

## Observed local results

- Windows/Python3.14.8: **3,157 passed**, zero failures/skips,251.91seconds;
  includes all3,001 existing tests and156 new signed-verification/gate tests.
- Fourteen malformed/bounded parser tests failed against unimplemented functions
  before passing. An independent test author observed98 bundle regressions fail
  against the verifier stub before implementation. This does not claim every new
  test was observed RED, or that these are live AWS acceptance tests.
- Tests use real ephemeral in-memory RSA signatures, independently authored AWS
  signing strings, original gzip/JSON bytes and literal expected rejection results.
  Private keys are never serialized or retained. No real AWS material is used.
- Formatting, lint, strict mypy, secret/identifier scan, structural Terraform and
  permission-difference checks pass. The scanner examined292 files before this
  validation document was added; final publication reruns the complete scan.
- Hash-locked dependency audit found no known vulnerabilities. Its local advisory
  cache read produced an access warning; the audit itself completed successfully.
  No dependencies, lockfiles, IAM/Terraform source or historical migrations changed.
- Sdist/wheel built successfully, and all five new signed-package modules are
  present in the current0.6.0 wheel. Existing older local build artifacts remain.

Every new branching security module has an independent85% actual-branch gate,
without source exclusions or weakened historical gates. Contracts have no branches.
Full-package database coverage is accepted only by the hosted disposable database
jobs; the local report honestly includes unexecuted database paths.

## Independent adversarial review

A fresh independent reviewer ran all156 focused tests with no coverage-file mutation
and found no material security findings. Separate memory-only probes rejected CRLF,
trailing LF, missing root `null` and `s3://` signing-path substitutions. Review covered
key substitution/rotation, anchors/heads, exact membership, supplied version custody,
complete-record conflicts, bounds, public privacy and permanently false authority.

The reviewer independently consulted official AWS documentation. The root separately
retrieved the official pinned CLI2.37.11 source at its documented commit, confirming
PKCS#1 v1.5/SHA-256 and literal `null` handling; no AWS CLI was executed. No AWS code
was copied into the implementation. The implemented code is original project code.

## Preserved security and operational boundaries

The AWS4A production worker remains unconditionally disabled. Existing SigV4/session
binding, five-service boundaries, deadlines, process containment, synthetic parser,
CLI2.37.11 contract, database/workflow source and migrations are unchanged. Historical
P2 stop/RED/corrected/merge receipts remain byte-identical and private.

Local retained PostgreSQL remains NO-GO; no local database integration, restart,
cleanup or volume operation was performed. Its historical native SIGSEGV cause is
unproven. Wazuh remains blocked by physical memory. The earlier Windows ACL-probe
timeout and successful retry remain distinct historical observations, not a fixed bug.

## Publication gates

Exact commit/tree, changed-file manifest, ten PR and ten push job conclusions, native
Terraform init/validate/schema/read-only lock evidence, disposable PostgreSQL results
and fresh exact-head Codex review belong to the PR and private ignored delivery
receipt after execution. These are mandatory; local tests and workflow source alone
do not establish them. The new PR must remain open and unmerged.

Every result is **offline supplied-key consistency**, never AWS-origin authentication,
trusted findings or closure authority. Sparse backfill coverage conservatively reports
incomplete. Inventory, public-key custody, source observations and freshness need a
separately authorized live-source acceptance described in the
[architecture](architecture/AWS_SIGNED_OFFLINE_VERIFICATION.md).
