# Test-harness governance and proposed branch protection

This is a read-only assessment and an owner-reviewable protection plan. It does not
change GitHub settings, grant merge permission or prove that a later revision passed.

## Observed configuration

On 2026-11-04 the connected GitHub read API returned the following for
`farhan-shafee/cloudsecops-live`:

| Observation | Result |
| --- | --- |
| `main` commit | `1400427df348b06f47e1415e8734aa82bf074305` |
| `main` tree | `9fad3b5d56afbc4dfe610e08d26a6b39854267f0` |
| Branch `protected` | `false` |
| Reported protection enabled | `false` |
| Reported required check contexts | Empty |
| Repository rulesets, including parents | Empty array |
| Direct branch-protection detail | HTTP 403: integration lacks access |

The branch response and empty ruleset listing show no enforced CI/review protection
at the inspected revision. The 403 limits administrative-detail visibility; it is
not evidence that a protection requirement passed. No setting was changed or bypassed.

All nine check runs on that main revision reported success. The earlier PR #7 run
[41774478731](https://github.com/farhan-shafee/cloudsecops-live/actions/runs/41774478731)
also had nine successful jobs. These observations do not approve this milestone's new
commit. Fresh exact-head CI and review must be inspected after publication.

Readback endpoints:

- [Main branch](https://api.github.com/repos/farhan-shafee/cloudsecops-live/branches/main).
- [Repository rulesets](https://api.github.com/repos/farhan-shafee/cloudsecops-live/rulesets?includes_parents=true).
- [Inspected main checks](https://api.github.com/repos/farhan-shafee/cloudsecops-live/commits/1400427df348b06f47e1415e8734aa82bf074305/check-runs).

## Proposed owner-applied policy

The owner should separately authorize and apply an **active** branch ruleset targeting
`refs/heads/main`, with an empty bypass list. An equivalent classic protection rule must
also apply to administrators. This document is not an instruction to apply it now.

Require a pull request, at least one independent approving review from a suitable
write-authorized reviewer, dismissal of stale approvals, approval of the most recent
reviewable push and resolution of review conversations. The author must not supply
their own approval through another interface. If no independent reviewer is available,
leave the PR blocked rather than creating a bypass.

Require the following exact job names, selecting GitHub Actions as their expected
source, and require branches to be up to date before merging:

| Required check name |
| --- |
| `validate (ubuntu-24.04, 3.12)` |
| `validate (ubuntu-24.04, 3.14)` |
| `validate (windows-2025, 3.12)` |
| `validate (windows-2025, 3.14)` |
| `PostgreSQL recovery (py3.12)` |
| `PostgreSQL recovery (py3.14)` |
| `Native Terraform and provider security` |
| `dependency-audit (ubuntu-24.04)` |
| `dependency-audit (windows-2025)` |
| `PostgreSQL harness safety` |

The first nine are observed existing checks, not nine security approvals. The tenth is
the new separately isolated harness job proposed by this milestone; require it after
reviewing its actual exact-head publication and execution. Its definition is not proof
that it passed, nor does the nine-job starting-main run include it.
Avoid duplicate job names across workflows. Preserve the complete sequential PostgreSQL
suite, backup/restore, HTTPS, unit, coverage, native Terraform and security gates.

Block force pushes and deletion. Do not require linear history: this project uses normal
merge commits to preserve reviewed parents and trees. Do not add deployment requirements,
cloud federation or credentials to satisfy a test-only milestone. Keep administrator,
automation and emergency bypasses absent; any future policy exception requires a separate
owner decision and recorded review.

Fresh Codex review with no material findings remains an additional exact-head review
requirement. A comment saying "no findings" is not automatically a GitHub approving
review or required status check. Do not manufacture an approval or assume an older
review covers a changed source tree.

## Verification after separately authorized configuration

An owner with suitable read permissions should privately retain the exact ruleset or
protection readback, target branch, expected check source, review requirements, bypass
list and UTC time. Confirm that direct main updates, force pushes and deletions are
blocked and that an ordinary disposable PR cannot merge with missing/failed checks or
without its required independent review. Do not test this by rewriting main, weakening
settings or merging a deliberately failing change.

GitHub may accept `skipped` or `neutral` required-check conclusions. Therefore each
mandatory test job must itself reject missing tests, skips, missing providers, missing
capacity observations and incomplete receipts. Protection configuration does not replace
inspection of actual job results, source revision, tree, test counts and failures.

Before each future merge, recheck head, base, scope, exact-head runs, review threads,
mergeability and policy. Stop on drift or access uncertainty. A successful isolated CI
run does not authorize cleanup of local databases or repair the local capacity incident.

Policy behavior follows the official [GitHub protected-branch documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and [ruleset documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

