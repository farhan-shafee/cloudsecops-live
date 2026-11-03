# Reviewed Investigation, Verification and Closure Implementation Plan

> Use test-first implementation, independent adversarial acceptance and whole-branch review. The owner's Phase 1A-3B specification authorizes this work; routine policy choices below are implementation decisions, not additional cloud authority.

**Goal:** A local analyst recommendation, distinct human decision, separately executed restricted synthetic-consistency verification and guarded no-action exercise closure, with auditable invalidation and reopening.

**Starting point:** Normal PR #4 merge `c205b4acc4c28650b10def0f8cc8c121deb727ea`, exact approved head `45c85db8ff01e85ca5919ff45399ba383d1dd9f0`, identical tree `77dcdfe5b3c5cdbc2e47556c8921fb9f03bc852b`. Immediately before merge: 52-file scope, eight successful exact-head PR jobs, completed same-head Codex no-findings review, no review threads/blocking reviews, clean mergeability, unchanged main `51643025451fdd3d23e0b5280dc529004e8d1ccd`, correct remote and clean checkout. Feature branch: `codex/phase1a3b-reviewed-verification-closure`.

**Architecture:** Extend the existing FastAPI/Jinja workspace and parameterized SQL-function boundary. Add migration 003 and explicit human workflow tables, preserving machine findings/cases and migrations 001/002. A separate verifier process and private configuration use only a dedicated restricted case grant, never web or maintenance credentials.

**Tech stack:** Existing Python 3.12/3.14, Psycopg/PostgreSQL17, FastAPI/Jinja, Argon2id and loopback TLS. No new service/framework or cloud/AI dependency.

## Fixed boundaries and policy

- Only action `NO_ACTION_AUTHORIZED_EXERCISE`, conclusion `authorized_synthetic_exercise`, `execution_targets=[]`, `source_kind=synthetic`, `authenticated=false`. There is no executor, cloud action, arbitrary target, URL or command interface.
- Analyst-authored rationale/counterevidence/gaps are plain-text assertions, never independent facts. Supporting evidence is derived from exact stored record associations.
- Recommendation lifetime 30 minutes; review expiry bounded by recommendation expiry; verification receipt lifetime at most 10 minutes and bounded by the recommendation. The original author must remain an enabled assigned analyst. The approving reviewer must also perform closure and remain enabled, assigned and distinct from the author. This is a conservative policy decision, not institutional independence.
- Stable recommendation ID per case, immutable numbered versions. One final approve/reject decision per version. A new recommendation supersedes prior authority without changing history.
- Every state mutation includes optimistic workflow-version and exact current machine-revision/fingerprint preconditions. Session and assignment checks occur after serialization locks, using server state.
- Human state is separate: `open -> recommended -> approved|rejected -> verified|contradicted|inconclusive -> closed`. Verification results are receipts; failed results never close. New source batches invalidate prior authority; a previously closed state becomes `reopen_required`, retaining its closure. A currently assigned reviewer explicitly appends `reopened` before a new recommendation. Superseded machine parents cannot be reopened as current cases; merged successors inherit no grants/authority.
- Conservative snapshot policy: every newly committed source batch, including added duplicate provenance, invalidates authority. An exact checkpoint replay adds no batch and remains idempotent. This avoids silently accepting a different complete-original/reference manifest under an unchanged generation.
- Lock order: pipeline row, current-generation job SHARE lock, case row, workflow row, then principal/session/grant and action token/recommendation rows in a documented consistent order. Align session rotation/logout/disable operations where needed using forward replacements, never edits to migration002. Worker publication also locks pipeline before job/case; no new path may acquire pipeline while holding a case.
- Current generation must be fully published with its job succeeded, case and finding current, conflict-free, exact current recommendation/approval/policy/source manifest/checker bindings, and enabled scoped verifier authority. Equal generation counters alone do not bypass pending/failed/missing current work. Expired/stale/inconclusive/contradicted state stays open.
- Historical lists contain at most20 scalar recommendation summaries with total/truncation metadata; one full current or explicitly selected immutable version is read at a time.
- All append records are immutable, every transition/audit atomic; audit failure aborts the whole mutation. Finite per-case recommendation/receipt/history/request bounds and bounded payloads/pagination apply.

## Verifier scope and independence

Each explicit maintenance-provisioned verifier LOGIN has an enabled mapping and case grant. Credentials live in a private verifier file, absent from workspace configuration. Only named begin/read-original/finish functions are executable, with no direct table access, schema/database CREATE, owner membership, account/password/session access, recommendation/review or closure authority.

A separate NONLOGIN verifier function owner preserves the web function owner's no-archive-bytes boundary. Default PUBLIC EXECUTE is revoked globally for both function owners, with exact signature grants and version-aware catalog fingerprints. Collector and worker receive separate restricted identities with exact machine-column grants and allowlisted machine-audit writes; all runtime authority remains separate from maintenance.

Begin pins a one-use request and the exact recommendation/approval/case/generation plus complete bounded dataset manifest. A complete dataset is necessary because the rule suppresses all findings for any full-record conflict and another original can extend/bridge a component. Raw fetch accepts only IDs in that case-bound request manifest. Full gzip archives may contain other case records; this is explicit verifier-only context access, not a web download or arbitrary archive browser. Fetch one bounded archive at a time; never aggregate all archive bytes into a PostgreSQL JSON response.

The verifier recalculates compressed and exact expanded hashes, canonical full records and delivery membership. Common bounded syntax validation may be reused, but the proof must independently derive raw record identity, AssumedRole consistency, qualification and correlation; it must not call production detection/qualification/finding-building helpers or trust stored normalized decisions. Document any shared parsing limitation. Unknown fields and finite decimal types remain part of complete-record hashes.

Independent correlation: sort qualifying unique events per exact credential session; union each consecutive triple whose first-to-last event-time span is inclusively <=60 seconds. Compare the entire connected component, including exact ordered evidence/hash/identity/count/session/timeline and independent finding/case fingerprints. A component may span over60 seconds through overlapping windows. Conflict, missing/corrupt originals, stale scope and unsupported versions cannot yield verified.

Verdicts: intact complete originals refuting a semantic claim produce `contradicted`; insufficient/corrupt/unsupported/unavailable coherent evidence produces `inconclusive`; only every required proof passing yields `verified`. Each receipt states synthetic consistency only, never AWS authentication, real exercise authorization, benign intent or absence of unseen activity. CLI accepts references, never a verdict flag. The verifier service's code and credential custody are trusted; this is not remote attestation against a compromised verifier/host/admin.

Finish rechecks the locked current snapshot, original manifest, approval, role/grant, expiry and checker policy; consumes the request and inserts receipt+audit atomically. Idempotent retry returns the same exact result, conflicting replay fails. Closure uses the latest matching receipt, so an older verified result cannot bypass a later negative result.

## Task 1 — Database workflow and migration

Files: `sql/003_reviewed_workflow.sql`, `database.py`, `workspace_roles.py`, `workspace_store.py`, new `workflow_store.py`, and database-focused tests.

- [x] Write real PostgreSQL fresh/v2 populated upgrade, immutable-row, exact-role denial, expiry/race and restore tests before SQL implementation.
- [x] Generalize migration/receipt/restore latest-version handling while preserving original v1/v2 checksum and catalog algorithms and the v2 database UUID. Never rebaseline prior receipts.
- [x] Add separate workflow-state, recommendation versions, review decisions, verifier identity/grants/requests/receipts, closure and immutable transition records; exact inventory named in tests.
- [x] Add server-side recommendation/review/close/reopen/read-queue functions and explicit authority/snapshot invalidation triggers with atomic audit.
- [x] Add restricted verifier begin/original/finish functions, separate owner, exact grants/defaults, runtime catalog validation and maintenance provision/disable helpers.
- [x] Add separately provisioned collector/worker identities, exact machine-column grants, protected configuration and actual catalog validation. Require explicit maintenance selection for owner-based offline operations; deny human/authentication/audit reads and review/receipt authority to both pipeline identities.
- [x] Prove actual auth/data/gate/verifier SQL cannot mutate or assume unrelated authorities; preserve quarantined restore and original full-fingerprint comparison.

## Task 2 — Independent verifier

Files: new `independent_verifier.py`, `verifier_runtime.py`, `verifier_cli.py`, with literal expected unit tests and restricted PostgreSQL runtime tests.

- [x] Write hand-derived 60-second boundary, credential separation, full-record conflict, complete/incomplete scope, overlapping/disjoint/bridged and benign-interpretation expected cases.
- [x] Implement independent semantic reconstruction and explicit integrity/semantic/scope checks, bounded sanitized verdict details and reproducible checker version/digest.
- [x] Implement one-archive-at-a-time restricted runtime, private config loading, fail-closed SQL identity validation and reference-only CLI. No caller verdict/source-trust input.
- [x] Prove production detector helper substitutions cannot turn an invalid independent proof into verified; preserve malformed/NUL parser boundaries and raw bytes.
- [x] Test staleness between begin/read/finish, disabled verifier, duplicate finish, real termination before/after commit and recovery without duplicate receipt/audit.

## Task 3 — Analyst and reviewer HTTP workflow

Files: new `workflow_web.py` and templates, narrow integration in `workspace_web.py`/CLI, HTTP/security tests.

- [x] Add assigned analyst recommendation form and exact binding/history/receipt inspection; reviewer queue and approve/reject/close/reopen forms.
- [x] Add one-use action-specific CSRF bound to workflow version/recommendation/case; reuse HTTPS/Host/Origin/cookie/body/escaping/session protection for every route.
- [x] Reject forged roles/result/targets/action fields, unassigned resources and all auditor/analyst review/closure attempts with non-enumerating object behavior.
- [x] Show synthetic/unreviewed machine state separately from reviewed human exercise state, current effectiveness, uncertainty, benign interpretations and visibility gaps.

## Task 4 — Independent acceptance and operational demonstration

Files: new workflow integration fixtures/tests, `scripts/reviewed_workflow_smoke.py`, existing coverage/CI extension.

- [x] Keep original workspace fixture stable. Add assigned second reviewer, unassigned reviewer and private case-scoped verifier credentials only to new fixture.
- [x] Test mandatory role/object/CSRF/expiry/source/identity/catalog/SQL denials, duplicate concurrent approvals, stale verification and negative-result closure.
- [x] Test actual interrupted approval/verification/closure transactions, audit failure, process death before/after commit, idempotent retries and lock-order races with ingestion/worker publication.
- [x] Real loopback HTTPS demo: synthetic ingestion/worker -> analyst recommendation -> distinct reviewer -> separately executed restricted verifier -> reviewer closure; then late evidence prevents old closure and requires auditable reopen. No secrets in argv/output.
- [x] Fresh, populated upgrade and binary backup/restore of every old/new row; preserve legacy NUL bytes and fail-closed replay behavior. Measure fresh database calls and recheck capacity before any finite test-bound increase; delete none.
- [x] Retain all previous gates; add >=85% actual branches for new security modules with no exclusions, no mandatory skip, Linux/Windows package/HTTP compatibility, dependency/secret scans and credential-free CI.

## Task 5 — Review, documentation and delivery

- [x] Update README, architecture/permission/threat/persistence docs, recovery/operations, roadmap/mastery; add no-AI `docs/labs/PHASE1A3B_INTERVIEW_LAB.md` with independent rubric and NOT_RUN human status.
- [x] Independent adversarial whole-branch review, correct material issues and rerun affected/full suites.
- [ ] Commit feature branch, publish via normal push or already-authorized GitHub integration, verify exact remote tree/head, open new PR, check actual exact-head CI and fresh review. Leave unmerged.
- [ ] Report scoped Phase1B readiness gaps; stop after Phase1A3B. No Wazuh/AWS setup, deployment, AI, action execution or later milestone implementation.

Implementation and complete local acceptance are recorded in [the validation report](PHASE1A3B_VALIDATION.md). Publication, exact-head CI/review and the stop-boundary report are completed after this source commit and recorded in the review PR and delivery report. These last two checklist entries intentionally remain pending in the prepublication source tree.
