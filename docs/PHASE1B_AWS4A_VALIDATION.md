# AWS4A offline validation and review record

Starting protected main: `1d9e978946760325a4005f5306a15ac102430a8f`, tree
`2633851638ffa22ed5e52c12463a05019c3e8fc8`. Scope is
[Issue11](https://github.com/farhan-shafee/cloudsecops-live/issues/11) with the
[owner permission clarification](https://github.com/farhan-shafee/cloudsecops-live/issues/11#issuecomment-6670869085).
The private owner-facts, linked ended CLI-session receipt and retained permission
blocker were read before implementation. Their contents remain private.

## Observed local validation

- Windows/Python3.14.8 full unit/adversarial suite: **2,904 passed**, zero failures
  or skips,193.61seconds. The original2,413 unit regressions also passed separately.
- Ruff formatting/lint and strict mypy passed (68 source files). A fresh complete
  secret/identifier scan passed276 files. The only new scanner exceptions describe literal
  public source hashes and a deliberately rejected fictional basic-auth URL.
- Dependency audit completed with no known vulnerabilities. A private advisory-cache
  read warning affected caching, not the successful audit outcome. Dependency pins
  and lockfiles are unchanged.
- Structural Terraform and IAM difference checks passed. Native init/validate/schema
  and read-only lock verification remain a separate mandatory hosted check.
- Sdist and wheel built successfully. All twelve posture-package files are present.
  Hosted installation/smoke checks remain required.

Local all-package coverage is83.44% lines and78.61% branches, including unexecuted
database paths. The full disposable-database job still requires the existing90%
package-line gate and individual security gates. Foundation lines97.25%, ingestion
branches93.45%, detection branches100%; all previous AWS gates passed unchanged.

| New module | Actual covered branches | Branch coverage |
| --- | ---: | ---: |
| requests | 10/10 | 100% |
| contracts | 28/28 | 100% |
| capability | 14/14 | 100% |
| budget | 44/44 | 100% |
| engine | 76/76 | 100% |
| clients | 38/38 | 100% |
| wire | 163/172 | 94.77% |
| registry | 2/2 | 100% |
| bootstrap | 24/24 | 100% |
| network | 12/12 | 100% |
| worker | No branches; 5/5 lines | 100% lines |

No exclusions hide protocol stubs or unexecuted code. Native subprocess/TLS behavior
is accepted separately from these in-process percentages. The Windows ACL-probe tests
passing in this run do not resolve the historical intermittent timeout.

## Independent adversarial review

The independent reviewer executed489 focused tests and separately reproduced thirteen
raw-response ambiguities using actual pinned SDK parsing with fictional credentials
and replaced HTTP sends. All thirteen now reject with a sticky failed budget. The
review found no remaining material defect in the final source set. That local review
is separate from the required fresh final-commit Codex review and exact-head CI.

Corrections include:

- Accept genuine boolean `MaxAttemptsReached` metadata on a successful single-attempt
  SDK response while requiring explicit `RetryAttempts=0`.
- Bind the final serialized operation and every parameter to the same one-use logical
  reservation. A later SDK event handler cannot change a role, policy, account or token
  after validation and still dispatch.
- Validate every fixed API's raw successful reply before SDK models discard fields.
  Duplicate JSON keys, conflicting XML result wrappers, unknown fields, ambiguous
  booleans and incomplete/contradictory pagination cannot fabricate empty inventory.
- Bound response/status/header/chunk bytes before framing, keep the header counter
  across interim/status-like lines, and reject DTD/entity and wide-encoded NUL payloads.
- Reject nondata capability nonces before comparison hooks; a failed redemption still
  consumes the same-process fictional handle.

Positive controls exercise all eight SDK operation types, thirteen calls for one
inline policy, a complete empty inventory and a real numeric-loopback TLS handshake.
The installed response wrapper is tested before header/chunk parsing. Separate owned
process faults cover TLS, headers, chunks, interrupted/oversized bodies, uncooperative
work, crash, cancellation and cleanup. Matching fake replies remain unauthenticated.

New disposable-PostgreSQL tests snapshot all41 existing tables, including human review,
verification and closure, before attempted ingestion of a posture observation or its
forged trusted variant. Expected effect is one permanent quarantine entry, with no
checkpoint/evidence/workflow change. These tests must run only in hosted disposable CI;
local collection of their four test cases is not database acceptance.

## Preserved boundaries

No dependency pins, migration001–003, Terraform/IAM source, SQL authority or deployment
settings were changed. Literal reviewed byte fingerprints protect the original fixture
bootstrap, socket guard and AWS3 facade; the shared supervisor only gains a closed
internal selector for the separate fixed bootstrap. Existing fixture behavior remains
covered by all prior regressions.

Production always rejects at `AWS4A_EXECUTION_DISABLED` after strict request validation.
There is no live flag, owner-file loader, broker, executable live command or approved
constructor. Private decision references are pending observations. The one-use offline
capability is neither a real credential-delivery mechanism nor proof of OS custody.
No real AWS request, credential discovery/issuance, IAM change, provisioning, source
collection or source-authentication promotion was performed.

The account S3 Control operation, `s3:GetAccountPublicAccessBlock` and exact-account
condition stay unchanged. The conflicting AWS SAR operation row remains a live-preflight
limitation. Permission denial is permanent failure; no bucket/API/policy substitution
or principal fallback is supplied.

Retained-local PostgreSQL and Wazuh remain NO-GO. No retained database/role, container
or volume was operated on. The historical PostgreSQL SIGSEGV root cause remains
unproven. The original Windows ACL-probe timeout and successful retry remain separate
evidence of an intermittent issue; AWS4A does not claim to fix either.

## Reproduction and delivery evidence

Use the repository's existing hash-locked Python setup. The full unit suite excludes
database acceptance by design and reports unexecuted database code honestly:

```powershell
.venv\Scripts\python.exe -m ruff format --check .
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m mypy
.venv\Scripts\python.exe -m pytest --cov=cloudsecops_live --cov-branch --cov-fail-under=0 --cov-report=json --cov-report=xml
.venv\Scripts\python.exe scripts/check_coverage.py --require-aws --require-aws1 --require-aws2 --require-aws3 --require-aws4
.venv\Scripts\python.exe scripts/check_secrets.py
.venv\Scripts\python.exe scripts/check_terraform.py
.venv\Scripts\python.exe scripts/check_aws3_permissions.py
.venv\Scripts\python.exe -m pip_audit --require-hashes --disable-pip -r requirements-dev.lock --strict --progress-spinner off
.venv\Scripts\python.exe -m build --no-isolation
```

Every new branching security module has its own85% actual-branch floor. The unconditional
disabled worker instead requires100% measured lines and zero branches; adding an
unreviewed branch makes that gate fail. No source exclusions or old gate reductions
were introduced. Ten job names, sequential disposable PostgreSQL and native Terraform
1.17.1/provider6.71.0 gates are preserved.

Final hosted PR/push job conclusions, exact commit/tree, review marker and bounded
source/diff receipt belong to the PR and private ignored delivery receipt. Workflow
definitions, a prior review, a structural Terraform pass and local test collection do
not establish those results. The review PR remains open and unmerged. Live AWS, real
custody/egress/OS containment, effective IAM and AWS4B source authentication remain
separate owner-authorized gates.
