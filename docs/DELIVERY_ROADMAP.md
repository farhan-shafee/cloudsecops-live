# Delivery roadmap

Status: target roadmap with Phases 1A-1 through Phase 1A-3B offline progress recorded below, 2026-11-03. Later work remains gated.
Read with the [system design](architecture/SYSTEM_DESIGN.md), [threat model](architecture/THREAT_MODEL.md), [cost and safety plan](architecture/CLOUD_COST_AND_SAFETY.md), and [reuse audit](architecture/REUSE_AUDIT.md).
Offline parsing/detection, durable PostgreSQL evidence/jobs/unreviewed draft cases and a restricted local authenticated analyst workspace are implemented. Human review and guarded closure now apply only to synthetic no-action exercises. No live AWS, SIEM or complete authentic Phase1 acceptance is claimed.
Local Phase 0 document validation is recorded below. Remote branch/PR delivery and available check status are reported separately in the PR and delivery report.

## Phase 1A-3B checkpoint

The owner conditionally authorized PR#4 merge at exact reviewed head `45c85db8ff01e85ca5919ff45399ba383d1dd9f0`. Immediately before normal merge, all52 files, eight successful exact-head PR jobs, fresh completed Codex no-findings review, no blocking threads, clean mergeability, unchanged main, correct remote and clean checkout were verified. Merge `c205b4acc4c28650b10def0f8cc8c121deb727ea` preserves tree `77dcdfe5b3c5cdbc2e47556c8921fb9f03bc852b`. Implementation is isolated on `codex/phase1a3b-reviewed-verification-closure`.

Implemented scope and boundaries are in [workflow architecture](architecture/REVIEWED_WORKFLOW.md) and [operations](REVIEWED_WORKFLOW_OPERATIONS.md): fixed no-action recommendations, distinct reviewer decisions, separate restricted verifier, guarded synthetic closure and auditable material-change reopening. Migration003 preserves all old data/migrations and adds explicit human state plus database-enforced pipeline transaction boundaries. Actual test counts, security coverage and independent-review corrections are in the [validation record](PHASE1A3B_VALIDATION.md); exact-head remote CI/review outcomes belong to the published PR/delivery report. A workflow definition is not a successful run. Human mastery remains NOT_RUN; the [new no-AI lab](labs/PHASE1A3B_INTERVIEW_LAB.md) provides a separate assessment.

Stop at the new unmerged review PR. Phase1B readiness remains a review decision, not permission to collect AWS, install Wazuh, enable cloud resources or deploy. Remaining gates include authentic source/digest completeness and signed-file binding, scoped effective live IAM, cost/retention/teardown approval, feasible SIEM hardware and actual query receipts. Local synthetic consistency and reviewed exercise closure satisfy none of those live evidence gates.

## Phase 1A-3A checkpoint

The corrected PR #3 exact approved head `cdf2ad4a18dc5b823bc9cd5d802736b2a79995d4`, 50-file scope, eight successful PR CI jobs, resolved original P2 thread, fresh Codex no-findings review, clean tree, correct remote/base and clean mergeability were independently rechecked immediately before normal merge. Merge `51643025451fdd3d23e0b5280dc529004e8d1ccd` retains its reviewed tree `6852dd040d5700107fd352a0e3c699b85e33f971`. Work is isolated on `codex/phase1a3a-secure-analyst-workspace`.

Implemented: local loopback HTTPS FastAPI/Jinja pages; protected local account provisioning; Argon2id; hashed opaque server sessions; persistent throttles; per-case SQL authorization; exact-record evidence/history/lineage views; CSRF and browser boundaries; current-version notes with atomic audit; distinct restricted auth/data identities; forward migration 002, privilege drift checks and quarantined restore repair. Original parser, NUL quarantine, durable jobs/replay, case revisions and outbox contracts remain in scope. See [workspace operations](WORKSPACE_OPERATIONS.md), [security design](architecture/ANALYST_WORKSPACE.md), [validation](PHASE1A3A_VALIDATION.md) and [independent lab](labs/PHASE1A3A_INTERVIEW_LAB.md).

Stop after the unmerged Phase 1A-3A review PR. Recommended separately authorized Phase 1A-3B boundary: exact evidence/revision-bound recommendations, distinct reviewer approval, independent verifier SQL authority and guarded closure, with stale/replay/self-review/contradictory-verification tests. No cloud execution, Wazuh, public hosting or AI is supplied by that recommendation. Accounts operated by one person remain a lab simulation. Human mastery remains NOT_RUN.

## Phase 1A-2 checkpoint

The owner authorized conditional PR #2 merge and offline PostgreSQL development/testing. Exact head `d70f5c64e3bc38692fefc2dbffb08eef97da7649`, all 35 reviewed files, six successful CI jobs, clean worktree/mergeability and absence of blocking reviews were verified. Normal merge `fee9da54bb4be5db44009441cdc887571a695459` retains the exact reviewed tree. Work proceeds on `codex/phase1a2-durable-evidence-recovery`.

Implemented scope: local PostgreSQL compressed originals and immutable versioned variants, full-identity uniqueness, delivery references, bounded quarantine, atomic batches/checkpoints, fenced finite jobs, deterministic persisted findings, revisioned unreviewed cases/lineage, offline outbox and integrity verification. See [persistence contracts](architecture/PERSISTENCE_CONTRACTS.md), [recovery commands](FAILURE_AND_RECOVERY.md) and [Phase 1A-2 lab](labs/PHASE1A2_INTERVIEW_LAB.md). Actual counts, coverage and exact remote CI outcomes belong to the execution receipts and PR delivery report.

Remaining Phase 1A gaps: analyst authentication/authorization, distinct human review and closure, recommendation/version binding, independent verifier service and complete application integration. Remaining live gates include authentic AWS collection/signed-digest binding and actual SIEM query receipts. These are not supplied by synthetic persistence tests. Recommended next scope is a separately authorized local analyst/review milestone; no automatic progression.

## Delivery rules and owner decisions

### Phase 1A-1 checkpoint

The owner explicitly authorized original-code MIT licensing, the conditional Phase 0 merge, and offline Phase 1A-1 implementation. PR #1's reviewed head `db23de05862535ecfce8ac616a7adcc74aafa3e8`, seven-file scope and clean mergeability were verified; merge commit `25b7aad40b218a8de96014b9c3fe9bd628a53bd1` has the identical reviewed tree. No checks existed and none were asserted passing.

Implemented: standard-library Python package, strict bounded synthetic gzip/JSON import, separate hash domains, immutable versioned normalized records, complete-record duplicate/conflict handling, exact-session `AWS-LAB-001`, deterministic JSON/CLI, independent adversarial tests, pinned tooling/CI and original-code MIT license. Read the [offline guide](OFFLINE_FOUNDATION.md), [implementation plan](PHASE1A1_PLAN.md) and [practical lab](labs/PHASE1A1_INTERVIEW_LAB.md). Human mastery remains unassessed.

Executed local Windows Python 3.14 validation passes 197 tests; ingestion actual branch coverage 90.96%, detection 100%, package lines 96.44% (combined line/branch 95.19%), with no exclusions. Python 3.12 independently passes the same 197 tests and branch gates (96.73% package lines, 95.47% combined). Format/lint/strict typing, secret scan including compressed fixtures, locked installation, strict dependency audit, build and isolated installed-wheel demo pass. Final remote CI and publication identities will be recorded in the Phase 1A-1 PR/delivery report; a workflow definition alone is not a successful run.

This completes only a subset of Phase 1A. It does not complete the earlier durable database/job/case/reviewer/verifier/UI gates or prove AWS authenticity. No AWS access, credentials, provisioning, Wazuh, PostgreSQL, FastAPI, deployment or paid services were enabled. The historical Phase 0 stop rule below describes that phase; this explicit new authorization permits only the stated offline subset. New decisions about cloud account/hardware/spend remain pending before their dependent live gates.

Recommendation for Phase 1A-2: review offline durable-evidence, transaction/job and case/version contracts next, including crash/replay, stale-review invalidation and migration/restore tests. Select the exact persistence scope before implementing it; do not begin it in Phase 1A-1. Live AWS/SIEM/action milestones remain NO-GO without their separate authorizations.

Historical Phase 0 authorization record: work stopped at its documentation/review PR without merge, credentials, apply, paid services or Phase 1 work. At that time offline and live approvals were separate and neither had been granted. The new explicit authorization above subsequently permits the verified merge and Phase 1A-1 offline subset only.
Any further authorization must identify the permitted subgate. Offline implementation approval and live cloud/apply approval remain separate decisions.
Passing an offline gate permits consideration of the next gate, not automatic deployment or expenditure.
Keep private acceptance receipts outside Git; publish only reviewed sanitized summaries with exact source revision, test scope, date, limitations, and remaining work.

Resolve the remaining decisions below before their dependent full Phase 1A/live milestones. The original-code MIT license and Phase 1A-1 offline scope are now authorized; this subphase does not depend on an AWS account or Wazuh capacity:

| Decision | Required owner record / stop condition |
| --- | --- |
| Project license | Choose the destination license and attribution policy before copying source or distributing implementation. Preserve upstream MIT notices for substantial reused portions; check dependency licenses separately. |
| Scope | Dedicated sandbox account, one explicit region (`us-east-1` proposed), no production links, and a finite exercise window. Do not publish resolved identifiers. |
| Local hardware | Confirm a Linux Wazuh VM allocation of 4 vCPU, 8 GiB RAM, 50 GB storage, plus capacity for the application/database. Missing capacity stops the SIEM gate; rented hosting is not approved. |
| Roles and people | Name analyst/reviewer users and distinct collector, test-actor, verifier, provisioner, and cleanup identities. Document shared-host and single-operator limitations. |
| Cost and retention | Accept the proposed under-$2/month operating target, $5 monthly alert budget, delayed-alert risk, retention/holds, notification recipient, and cleanup responsibility. These are not spending caps. |
| Approval scope | Record permission for offline code separately from later resource creation, authorized exercise, retained spend, and deletion. A PR approval alone does not imply these permissions. |

Before every live gate, refresh the dated regional price estimate, existing/organization trail inventory, hardware check, exact IAM policies, private baseline resource inventory, and rollback/teardown procedure.
Pause on scope/identity mismatch, invalid evidence, unexplained cost or volume, unexpected writes, insufficient capacity, or unresolved critical test failures. Preserve receipts; never substitute synthetic results for missing live evidence.

## Phase 0 — reviewable design only

Dependencies: read-only source audit, exact local commit provenance, architecture alternatives, threat analysis, and cost assumptions.

Acceptance criteria:

1. README clearly identifies proposed versus implemented capability and links every delivery document.
2. Reuse audit covers all six source repositories, exact inspected revisions, dirty/provenance limitations, license boundaries, and reuse/adapt/replace/avoid decisions.
3. Architecture, threat model, cost plan, this roadmap, and mastery plan describe the same first slice and trust boundaries.
4. Every milestone below has dependencies, observable acceptance evidence, tests, and an explicit stop/go gate.
5. Review checks find no raw cloud evidence, private identifiers, credentials, Terraform state/plans, copied source, or runtime/deployment changes.
6. A documentation review PR targets `main`, includes the actual checks run and unresolved owner decisions, and remains unmerged.

Executed local validation on 2026-11-03: all seven required Markdown files present, 24 relative links/anchors valid, 75 commit-pinned citations covering 60 unique source paths checked against inspected Git objects or connected GitHub content, balanced code fences, and all 11 mastery capabilities present. Two upstream-only routing files were inspected through connected GitHub. Cost arithmetic recomputed to $0.281, $1.73 and $37.10. A basic secret/account-identifier pattern scan found no matches; diff review checked private-name/context disclosures and scope. All six audited source working trees remained clean. These are document/inspection checks, not execution of source-project tests or a comprehensive secret-scanner attestation.

Historical Phase 0 result: `git diff --check` passed; runtime, AWS, SIEM, signature-verification, scanner and mastery tests were NOT_RUN, and no runtime/CI implementation existed at that point. Phase 1A-1 offline validation is recorded in the checkpoint above. Current regional S3 model rates, hardware capacity, effective live IAM and live reproducibility remain unverified. Phase 0 review corrected hash-domain/version-binding and responder-permission caveats before delivery.

Recommendation: **GO for the bounded Phase 1A offline scope after owner approval of the listed decisions; NO-GO for live/apply work until Phase 1B readiness and separate cloud authorization.** This is a recommendation, not permission to begin.
Stop: submit the review artifact and wait for explicit owner direction. Phase 0 completion is not Phase 1 authorization.

## Phase 1 — one complete authentic no-action investigation

Objective: actual AWS `DescribeInstances` events → original S3 logs/digests → trusted Python finding → persisted/queryable local Wazuh alert → case → reviewed no-action → independent read-only verification.
Phase 1 is complete only when all three subgates below pass, including the live end-to-end exercise and reproduction/cleanup receipts.

### Phase 1A — offline implementation and independent tests

Dependencies: explicit owner approval for offline implementation, resolved license/hardware direction, and accepted Phase 0 scope.
Build one Python/FastAPI package, separate worker/verifier processes, local PostgreSQL, migrations, and minimal server-rendered analyst pages. Do not add cloud credentials or execute live AWS calls.
Pin compatible runtime/tool versions and review dependency licenses/advisories; do not assume version compatibility from this proposal.

Acceptance criteria:

1. Strict versioned contracts distinguish synthetic/unverified/pending/verified/conflicting sources. Only the collector assigns source class; request fields cannot elevate trust.
2. Original compressed bytes have exact source/version/length and `archive_sha256` references; exact decompressed bytes have separate `content_sha256` for CloudTrail digest comparison. Normalized events retain record index and parser version. Quarantine captures bounded failure reasons.
3. Transactional ingestion, uniqueness, checkpoints, jobs, leases, audit entries, and outbox survive retries/crashes without duplicate events, findings, cases, or acknowledged-but-unsaved work.
4. `AWS-LAB-001` requires three unique successful management `DescribeInstances` events in an inclusive 60-second event-time window, keyed by account, region, issuer, and exact session.
5. Overlapping qualifying windows sharing events merge for the bounded exercise; disjoint windows remain distinct. Late evidence revises the case and invalidates stale review.
6. Cases show evidence, timeline, hypothesis, counterevidence, false positives, visibility gaps, and uncertainty. No-action recommendations never create execution attempts.
7. Server-side authorization, distinct reviewer, recommendation/evidence/version binding, expiry, optimistic concurrency, and audit records govern review and closure.
8. A separate checker returns `verified`, `contradicted`, or `inconclusive`; failed/inconclusive verification blocks closure. The no-action path has no cloud mutation interface.
9. Offline tests and CI below pass for the named commit; receipts record command/tool versions, source revision, fixture-set hash, counts, failures/skips, and dirty state.

Tests: use independent expected answers and hand-derived detection cases; do not regenerate expected results using the detector being tested.
Measure and retain line/branch coverage for the implementing revision. Proposed acceptance is at least 90% branch coverage for ingestion, detection/correlation and case/review/closure modules, plus every named security-negative scenario passing regardless of aggregate percentage. Record exclusions/skips with review rationale. Coverage measures exercised code paths, not detection effectiveness.
Cover 59/60/61-second windows, equal timestamps, two versus three calls, duplicate IDs, denied/missing-readOnly calls, different sessions/accounts/regions, shuffled/late records, and overlapping/disjoint windows.
Reject wrong source, changed bytes, conflicting duplicate content, oversized/deep JSON, compression expansion, missing digests, and unsupported records. A validator exit zero with no exact file membership must not establish trust. Test compressed-versus-uncompressed hash confusion, unrelated/empty digests, backfill, and source/digest replacement during validation; follow the system design's exact-file binding protocol.
Exercise database uniqueness/concurrency, worker crash points, lease expiry, checkpoint restart, outbox retry, reviewer races, self-approval, expired/replayed review, changed evidence/targets, and false closure requests.
Add two credential sessions with the same role/session name; missing session discriminator; complete-source-record changes omitted by normalization; harmless file/compression differences; duplicate JSON keys; and parser-version changes. Test explicit AWS error fields versus null read-only responses. Only the verifier service may write machine verification receipts; analyst/reviewer direct API or database attempts must fail, and process database roles cannot bypass the workflow.
Test object authorization, expired sessions, CSRF/origin enforcement, stored script escaping, traversal, malformed requests, and public-export redaction with nested identifiers.

Stop/go: offline passing results permit a Phase 1B readiness review. They do not prove AWS delivery, valid signatures, Wazuh persistence, deployment safety, or live detection.

### Phase 1B — local SIEM and cloud readiness

Dependencies: Phase 1A acceptance, owner authorization for the local installation, confirmed hardware, and a separate explicit live/apply approval before any AWS creation or exercise.
Local integration can be evaluated with clearly synthetic inputs; it cannot complete Phase 1C.

Acceptance criteria before requesting apply approval:

1. Pin and install a supported local Wazuh release; record capacity, TLS/authentication configuration, retention, and active-response-disabled checks.
2. A custom decoder/rule accepts minimized event/finding JSON with stable IDs. Retrieve a persisted alert through an authenticated index query and save its query/alert receipt; log-test output alone fails acceptance.
3. Stop Wazuh, enqueue work, restart it, and prove outbox recovery/deduplication with bounded retries and visible acknowledgment lag. A write acknowledgment alone cannot mark a finding searchable.
4. Review Terraform plan/resource allowlist, state/lock/recovery design, named cleanup steps, short-lived role/trust policies, and denied-action expectations. No broad administrator policy becomes runtime authority.
5. Collector/test actor/verifier pass offline policy checks; provisioning credentials are absent from API, ordinary worker, SIEM, and PR CI. Verify the planned test role cannot mutate resources.
6. Refresh cost inputs and existing trails, configure only owner-approved notifications after live authorization, and agree on retention/deletion and delayed-billing follow-up.
7. Plan includes only the approved trail, private versioned archive, minimal state arrangement, and scoped roles. No compute hosting, NAT, paid security services, data events, Insights, or hosted AI.

Stop/go: save a concrete private plan and readiness report for owner review. Apply, cloud credentials, the exercise, and cleanup require explicit authorization; none is granted by this document.
Wrong account/region, unsupported permissions, missing capacity, incomplete teardown, or unresolved costs stops the live gate.

### Phase 1C — authentic end-to-end acceptance

Dependencies: all earlier acceptance criteria, explicit approval of the exact plan/live exercise/spend/cleanup, and working distinct read-only identities.

Acceptance criteria:

1. Apply only the reviewed plan; compare actual resources and IAM boundaries with the private baseline/allowlist. Save plan/apply receipts privately.
2. Confirm expected STS identities and region, then make exactly three successful single-page `ec2:DescribeInstances` calls within 60 seconds using the dedicated test session. No EC2 instance is required.
3. Collect the actual CloudTrail S3 originals and covering digests through approved prefixes. Record owner, location, version, length, compressed-byte SHA-256, retrieval time, and full listing pagination.
4. Validate original locations with supported AWS tooling; save tool/version/interval/signature/chain/file-membership results. Prove before/after log/digest version continuity, compare exact uncompressed `content_sha256` to the validated digest member, and retain compressed `archive_sha256` separately. Missing/invalid/changed/ambiguous evidence blocks trusted detection and closure.
5. Python produces one `AWS-LAB-001` finding for the three unique event IDs, with the exact key/window/rule version, evidence references, benign-inventory explanation, and no compromise claim.
6. Local Wazuh receives the minimized derivative, persists an actual custom-rule alert, and returns it in an authenticated index query. Case, finding, event, outbox, and SIEM IDs reconcile.
7. Analyst creates an evidence-backed case and `NO_ACTION_AUTHORIZED_EXERCISE` recommendation. A distinct authenticated reviewer approves the exact current recommendation/evidence version.
8. Independently run verifier uses separate read-only credentials, retrieves originals/digests, and checks the three calls with a separately implemented simple predicate. It does not trust the detector's count/status.
9. Verifier also records test-role permission review and bounded available-history/configuration checks for unexpected writes, with visibility limits. It cannot prove absence of all malicious activity.
10. Closure requires current review plus a matching `verified` receipt. A mismatched event, changed recommendation, missing file, visible unexpected write, or inconclusive check keeps the case open.
11. Save private evidence and a sanitized outcome report identifying actual lab telemetry versus synthetic failure tests. Explicitly state that no containment or remediation occurred.
12. Pass the reproduction/restore/teardown gate below. Record billing follow-up as pending until its later checks finish.

Measure delivery/digest delay, collection lag, processing time, Wazuh query lag, retry/duplicate counts, disk consumption, requests/bytes, and incremental cost; do not publish invented throughput or detection efficacy.
Operate with five-minute polling, at most two hours of active polling, and manually bounded reconciliation within a 24-hour acceptance window. This timeout is not an AWS delivery guarantee.
At 24 hours without required authentic evidence, stop/investigate and leave acceptance incomplete. Never replace it with fixtures or keep polling indefinitely.

## Proposed file and interface layout

The paths below are implementation candidates only; Phase 0 does not create them.

```text
src/cloudsecops_live/
  contracts/                 # Versioned evidence, case, review, verification schemas
  ingestion/                 # AWS source guards, originals, digest adapter, normalization
  detections/                # AWS-LAB-001 and explicit correlation predicates
  cases/                     # Timeline, recommendations, review and closure rules
  evidence/                  # Private artifact references, hashing and export policy
  jobs/                      # PostgreSQL leases, checkpointing and SIEM outbox
  integrations/wazuh/        # Minimized payloads and persisted-alert query receipts
  api/                       # Authenticated routes and server-rendered pages
  worker.py                  # Collector/detection/outbox entry point
  verification/              # Independent checks and separate process entry point
migrations/                  # Constraints, jobs, review versions and audit sequences
infra/terraform/             # Reviewed AWS sandbox resources and policy tests
siem/wazuh/                  # Pinned decoder/rule and active-response-off configuration
tests/unit/                  # Independent rule/schema oracles and negative inputs
tests/integration/           # PostgreSQL, auth, outbox and local Wazuh contracts
tests/live/                  # Opt-in authorized exercise; never PR CI
fixtures/synthetic/          # Invented IDs only; explicit source labels and expected truth
scripts/                     # Bounded exercise, private validation and inventory procedures
docs/runbooks/               # Setup, investigation, reproduction, restore and teardown
.github/workflows/           # Credential-free PR validation and retained sanitized results
```

Interfaces: collection returns `CollectionRun`/`RawObject`; normalization returns source-bound `Event`; detection returns `Finding`; case service owns versioned `Case`/`Recommendation`/`Approval`; SIEM adapter returns query receipts; verifier returns `Verification`.
Expose only the explicit routes in the system design. No arbitrary upload, shell, target URL, action string, or client-selected trusted-source endpoint.
Add later `ExecutionAttempt` only after Phase 3 authorization. CI/test manifests require common source revision, producer/tool/scope/time binding and explicit dirty state; hashes alone are insufficient provenance.

## Shared validation, measurement, and operational gates

PR CI: lint/format/types, unit/database/auth tests, synthetic replay, secret/identifier checks, dependency audit, SBOM/container scanning, Terraform formatting/validation and static IAM checks as those assets exist.
Use exact locks, SHA-pinned Actions, minimum read-only tokens, no persisted checkout credentials, bounded jobs/artifact retention, and explicit missing/failed evidence handling.
PR CI has no AWS credentials, cloud calls, apply permissions, paid scanners, or hosted model keys. Offline mode disables external provider calls; mocks exercise failure contracts rather than claiming live execution.
Keep operational failures distinct from security findings. Required missing/malformed/stale/revision-mismatched evidence blocks; no green empty result. Review-required findings need a recorded disposition and cannot silently imply release approval.
Keep live checks opt-in with explicit scope/authorization and private receipts. Branch protection/reviewer administration must be verified separately; workflow text does not establish enforcement.

Proposed safety limits to implement and test: 10 MiB compressed/object, 100 MiB expanded/object, 10,000 records/object, bounded JSON depth/strings, 2 GiB cache, pause at 80% cache, bounded pagination/retries and reconciliation scope.
Select exact depth/string/page/retry limits during Phase 1A; record rationale and test both boundary values and one-over-limit rejection. Numeric limits here are proposals, not benchmark results.
Retention proposal: raw logs/digests/receipts and backups 30 days, indexed SIEM data 14 days, quarantine 7 days; open-case holds require priced expiry/owner records. Digests outlive corresponding logs.

Reproduction/restore/teardown acceptance requires:

1. A second operator follows clean setup instructions, runs offline tests, and explains failures without unrecorded configuration. If unavailable, independent reproduction remains unproven.
2. Restore a private database/evidence backup; verify hashes/readability, review/version bindings, audit continuity and replay behavior. An old backup must reveal missing checkpoints rather than hide later activity.
3. Under separate live authorization, reproduce the finite exercise and query Wazuh/case/verifier receipts for the named revision. Do not reuse historical receipts as a new run.
4. Stop jobs; preserve approved encrypted evidence; review holds/deletion; inventory exact owned resources. Perform only explicitly approved cleanup, including versions/delete markers/multipart uploads and non-Terraform bootstrap resources.
5. Independently compare regional/global resource inventory with baseline; remove temporary access and stop local services/caches as approved. Save retained-resource reasons, expiry, owner, and ongoing cost.
6. Recheck charges after 24–48 hours and the next billing update/month close. Report infrastructure cleanup and billing closure separately; `terraform destroy` alone passes neither.

## Phase 2 — bounded posture and vulnerability assessment

Dependencies: complete Phase 1 receipts and reproduction gate, owner approval of added scope, updated threats/cost/IAM review. This remains read-only in AWS.
Implement timestamped S3 public-access/encryption/versioning assessments and explicitly bounded IAM static checks, with unknown/unsupported states and independently authored expected snapshots.
Add scans of this repository and its built application image using actual supported tools, exact versions/database timestamps, raw reports, SBOM, required-evidence checks, stable occurrence fingerprints, and expiring scoped exceptions.
Acceptance: every finding identifies resource/component, rule/version, observed evidence, limitations and case linkage; demonstrate one genuine local code/dependency/configuration finding and its later re-scan outcome without installing an intentionally vulnerable default runtime.
Test unsupported IAM/combined-policy semantics, stale snapshots, missing resources, failed/empty scanners, wrong scan modes, duplicate downgrade, moved occurrences, and exception scope/expiry. Missing evidence never becomes PASS.
Independent fresh reads/re-scans verify the named postcondition; static IAM findings do not claim effective permissions and vulnerability matches do not prove exploitability.
Stop/go: actual read-only assessment and real scan receipts must pass review before proposing cloud-changing response. No Config/Inspector/GuardDuty or other paid service is implicitly enabled.

## Phase 3 — one tightly scoped human-approved response

Dependencies: Phase 2 acceptance; explicit owner approval of the exact action/marker/role/initial state/spend; refreshed threat/IAM/cost/cleanup review; offline action-policy and independent-verifier tests.
Only allowed action: set all four bucket public-access-block flags to true on one exact, empty, non-logging marker bucket. Account-level blocking remains enabled throughout.
Exact-resource IAM cannot constrain the four Boolean request values. Test the application adapter's value allowlist and verify that the responder cannot alter account-level blocking; document residual bucket-flag tampering risk if the responder is compromised.
The same permission also authorizes deleting the bucket's block configuration. Prove the adapter exposes no removal operation and document that IAM alone does not prevent it.
Never weaken controls to manufacture a finding, modify logging/evidence buckets, or add IAM/ACL/policy/encryption/delete/arbitrary-command actions. If already compliant, report a no-op; it does not demonstrate a mutation.
Acceptance: authenticated distinct reviewer approves exact target/action/evidence/version/expiry; executor rechecks ownership/marker/preconditions, records one idempotent attempt, and uses an exact-resource restricted role.
Test bypass, wrong target/account, stale/replayed approval, concurrent change, revoked role, partial failure, and timeout-to-unknown. Retry only after fresh state checks establish the prior outcome; API success alone cannot close.
Independent read-only verifier retrieves current flags and source evidence with separate credentials/checker; unchanged/contradictory/inconclusive state blocks closure. Preserve before/after reads, approval, attempt, verification and audit receipts.
Stop/go: complete one authorized live action and independently observed postcondition, plus cleanup review, before claiming response capability. No automatic rollback may weaken protection.

## Phase 4 — optional assistance or a second UI

Dependencies: explicit owner approval, demonstrated workflow need after earlier phases, and a written comparison with the working deterministic/server-rendered baseline.
AI candidate: sanitized bounded summaries only, schema-constrained claims citing existing evidence IDs, explicit unknowns, no tools/credentials/action authority, versioned model/prompt and cost limits.
Acceptance: adversarial log/prompt-injection and unsupported-citation tests, measured task benefit/error rate against human-reviewed cases, privacy/provider review, bounded spend, and complete investigation with AI disabled. Reject unsupported output.
Next.js candidate: only a measured analyst interaction need that existing pages cannot reasonably meet; preserve API authorization/version/approval contracts and test the entire browser-to-database flow.
Stop/go: if benefit, hardware, privacy, evaluation quality or operating cost is unproven, retain the existing workflow and defer the addition. Neither option is required to complete the security platform's first three phases.
