# Secure live runner preparation implementation plan

> **For agentic workers:** Use test-first implementation and independent review. This milestone is offline only.

**Goal:** Bound trusted AWS readiness worker execution without granting AWS access or evidence authenticity.

**Architecture:** A parent watchdog owns a gated process and its operating-system containment. Pure identity, budget and CLI preflight contracts remain separate from the existing SDK, receipt parser and synthetic database authority. Only numeric loopback network simulations are permitted in prepared workers.

**Tech stack:** Python 3.12–3.14, standard-library process/IPC and native Windows Job Objects or Linux owned process groups; existing pinned SDK and test tools.

**Spec:** Owner's Phase 1B-AWS-2 request. Starting main `5e860dffb3e13b82121afa8e7b82e8d43a2ad639`, tree `ec98d22dafb0eb1a1d2a2f72d9e5b95588d98b79`.

## Constraints and rulings

- Exactly one feature branch, `codex/phase1b-aws2-secure-live-runner`, and one unmerged PR. No live AWS, credentials, Terraform plan/apply/destroy, retained PostgreSQL, Wazuh or deployment operations.
- Existing migrations, all prior checks and the ten required jobs remain intact. Database acceptance runs only in disposable hosted CI.
- Work in the verified clean checkout on the dedicated branch; no additional worktree or feature branch is needed.
- The detailed owner specification authorizes implementation. Routine design choices are resolved here without another approval cycle.
- Worker code and local import references are trusted program code, never request fields. This is a cancellation boundary, not an arbitrary native-code sandbox. Linux workers must not escape their owned session/group; Windows children cannot break away from their Job.
- Reserve cleanup within the monotonic total budget. OS scheduling, kernel responsiveness and process-creation limitations must be reported honestly; unknown cleanup never yields success.
- Version/provenance observations and every prepared receipt remain unauthenticated. Effective AWS permissions and real credential issuance remain future live gates.

## Review focus

Late process creation must remain gated and be cleaned without releasing work. Completion with surviving descendants must fail closed. Same human-readable role names with changed immutable IDs must fail. Every failed attempt and aggregate byte count must consume capacity. CLI version text alone cannot establish binary provenance.

## Tasks

- [ ] Add independently expected identity/budget and CLI preflight tests, observe failure, implement pure strict contracts.
- [ ] Add native process tests, observe failure, implement gated bootstrap, offline network guard, owned-tree containment and parent watchdog with bounded IPC and sanitized receipts.
- [ ] Bind operation/byte budgets to injected SDK clients without changing original SDK behavior; test rejected calls and aggregate limits.
- [ ] Add real loopback fault simulations for TLS, headers, chunks, body and stream interruption; test DNS blocking, cancellation races, descendants and unrelated-process survival.
- [ ] Extend coverage and existing CI without changing check names, database resource policy or native Terraform gate. Update architecture, threat model, operations, readiness, roadmap and interview exercises.
- [ ] Run offline checks, hosted sequential database/native Terraform acceptance, independent adversarial review and fresh exact-head Codex review. Fix material findings, publish one PR and leave it unmerged.

## Starting governance evidence

Ruleset `26545782` is active for `refs/heads/main`, requires the ten existing GitHub Actions contexts with strict/up-to-date checks, PRs and resolved conversations. Required approving reviews are zero; the suggested independent-approval policy is not enforced. Public API visibility did not disclose bypass actors or classic-protection details. No settings are changed and no merge is authorized.
