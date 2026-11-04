# AWS3 offline validation record

This record describes local validation on Windows/Python3.14.8 before publication.
Starting protected main: `58d008c4744c7f2f7560bddc6fcdc19516ef6298`, tree
`2d1d8c37a2a9a1094f74b17046ffcdb5e7fcc0cc`. Published commit/tree, actual hosted
check conclusions and fresh exact-head Codex review belong to the feature PR and
final delivery receipt. This document does not infer their outcome from workflow YAML.

## Observed local checks

- Full credential-free unit/adversarial suite: **2,413 passed**, zero failures/skips,
 208.51seconds. Existing PostgreSQL suites are excluded by the ordinary unit runner
 and must pass separately on the identified disposable hosted service.
- Ruff format/lint and strict mypy: passed (56 source files). Secret/identifier scan
 passed with no findings; no scanner baseline or threshold was changed.
- Hash-locked development dependency audit: no known vulnerabilities. A local advisory
 cache read warning degraded caching only; the audit completed successfully.
- Both independent static Terraform/permission checkers passed. Native provider
 init/validate/schema/readonly-lock acceptance remains a separate required hosted job.
- Sdist/wheel build passed; all seven readiness package files are included. No
 dependency pins, lockfiles or migrations were changed. Hosted wheel installation
 and command smoke checks remain required.
- An independent adversarial reviewer ran **367 focused tests** and found no remaining
 material finding after corrections. That review is separate from final-head Codex.

The local all-package measurements are **80.22% lines,74.91% branches**, honestly
including unexecuted database paths. The full database job must still satisfy the
existing90% package-line and individual security gates. Foundation lines97.25%;
ingestion branches93.45%; detection branches100%. No coverage exclusions were added.

| New security module | Actual branches | Branch coverage |
| --- | ---: | ---: |
| sessions | 75/76 | 98.68% |
| permissions | 14/14 | 100% |
| requests | 78/80 | 97.50% |
| registry | 6/6 | 100% |
| transport | 43/44 | 97.73% |
| workers | 25/26 | 96.15% |

Every module has its own85% branch gate. Existing SDK transport87.37%, CLI receipt,
AWS2 and original security/ingestion/detection gates remain unchanged and mandatory.

## Faults and independent review corrections

Regression tests reject wrong/root/user/admin-shaped identity, immutable RoleId or
purpose reuse, missing/expired/substituted temporary credentials, absent MFA/issuance
observations, implicit provider callbacks, unauthorized calls, denied/error pages,
bad pagination, source version/hash changes, stale fixture observations, budget
exhaustion, cancellation and deadlines. Fake responses cannot create successful
authenticated evidence. Oversized scalar/aggregate/fanout/integer/escaped strings
reject before JSON serialization/allocation; exact512KiB legitimate requests pass.

Independent review corrected four boundary/claim issues: source conflict state was
obscured by readiness state; same-object credential callbacks/components could evade
the older SDK check; unknown policy metadata lacked explicit owner-review state;
requested inline-policy names were labeled as if their contents had been reviewed.
Tests now preserve conflicting source state, prevent callback invocation/dispatch,
require owner review and explicitly report unverified policy contents/effective IAM.

Actual owned Windows child demonstrations succeeded for the three named facades,
returning only unauthenticated observations. A configured stall request returned a
deadline result in612.921ms inside an800ms total budget; pre-cancellation returned no
payload; changed evidence returned a failed result. Each reported owned-tree cleanup.
This measures lifecycle outcomes, not live AWS traffic or which network phase ran.
OS scheduling and process-creation limitations remain as documented in AWS2.
Sanitized detailed local logs, coverage/XML and demo receipts are ignored/private.

## Preservation and remaining gates

No AWS request, credential discovery, role assumption, provisioning, Terraform plan,
local PostgreSQL operation, Docker change, Wazuh installation or deployment occurred.
Retained databases/roles/volumes and migrations001–003 remain intact. The original
Windows ACL-probe timeout and successful retry remain separate historical evidence;
the intermittent failure and historical PostgreSQL SIGSEGV are not claimed fixed.

The active main ruleset requires ten checks, a PR, resolved conversations and normal
merge-only integration, with no bypass actors; it currently requires zero approving
reviews. This milestone changes no protection. CI/review must be freshly verified
at the final published source. The PR stays open and unmerged.

**Live AWS remains NO-GO.** Owner-approved real issuance/MFA/private custody, current
effective IAM and a reviewed network-enabled fixed assembly are absent. The dated
audit is not repeated. Existing audit-role object reads remain prohibited; actual
policy bytes were unavailable. See [remaining owner decisions](AWS_LIVE_READINESS.md)
and [exact source permission differences](PHASE1B_AWS3_PERMISSION_DIFFERENCES.md).
