# Interview mastery and practical assessment

Phase1B-AWS-0 adds the [offline AWS foundation lab](labs/PHASE1B_AWS_FOUNDATION_INTERVIEW_LAB.md): CloudTrail, IAM, S3 versions, hash domains, signed membership, pagination, identity/session correlation and failure handling. Human exercises remain **NOT_RUN** until completed without AI and independently scored. Fake transports and structural Terraform tests demonstrate software boundaries, not AWS operational experience, effective live IAM or SIEM deployment. Wazuh capacity and actual queryable-alert evidence remain separate unmet gates.

Status: training plan with Phase 1A-1 through Phase 1A-3B executable practice available, 2026-11-03. **The human mastery assessment remains NOT_RUN.** Automated offline tests have run; local PostgreSQL integration/recovery tests are separate from live exercises, deployment or AWS actions, which remain unperformed. Passing software tests does not establish human mastery, a complete live platform or production experience.

## Phase 1A-3B practice now available

The [reviewed exercise no-AI lab](labs/PHASE1A3B_INTERVIEW_LAB.md) covers integrity versus authenticity, benign inventory triage, exact version-bound review, separation of duties, restricted independent verification, transactional state machines, replay, TOCTOU, audit failures and late evidence. Explain why verified local consistency cannot establish AWS authenticity, benign intent or remediation. Practical tasks include role/assignment revocation races, wrong-window claims, failed audit and explicit reopening. The independent rubric and all human results remain NOT_RUN. This phase supplies synthetic practice for portions of C06/C07/C08/C09; it grants no live or institutional authority.

## Phase 1A-3A practice now available

Use the [secure-workspace no-AI lab](labs/PHASE1A3A_INTERVIEW_LAB.md) and [actual permission model](architecture/ANALYST_WORKSPACE.md) to demonstrate authentication versus authorization, object grants, password hashing, session revocation, CSRF/XSS/SQL boundaries, TLS/cookies, direct SQL denials and atomic version-bound notes/audit. The lab includes deliberately failing tasks and an independent scoring rubric. Automated security tests do not award C07 mastery: only synthetic no-action review/consistency verification is implemented, and human performance has not been assessed. C08 practical assessment remains NOT_RUN until an assessor observes the cold exercises.

## Phase 1A-2 practice now available

Use the [durability and recovery lab](labs/PHASE1A2_INTERVIEW_LAB.md) to explain transactions, full-record conflicts, idempotency, lease fencing, outbox limits and late evidence. Perform crash diagnosis, a fresh restore and an independent test change without AI. The measurable 20-point rubric does not award any capability score until observed; every human assessment remains NOT_RUN.

## Phase 1A-1 practice now available

Use the [30-minute no-AI lab](labs/PHASE1A1_INTERVIEW_LAB.md) with the implemented [offline parser/detector](OFFLINE_FOUNDATION.md). Explain exact hash domains, complete-source conflicts, full credential-session keys and inclusive 60-second windows; troubleshoot an injected duplicate/read-only error; write an independent negative test and demonstrate that it catches its intended bug.

The automated test suite provides implementation evidence for portions of C02/C03/C09, including malicious-input rejection and reproducible synthetic findings. It does not award any C01–C11 score. Until independently assessed, every human capability/panel below remains NOT_RUN. C04 SIEM, live source authenticity, human-reviewed cases, response and optional AI remain future work. Persistent unreviewed synthetic drafts are now available.

Use the [system design](architecture/SYSTEM_DESIGN.md), [threat model](architecture/THREAT_MODEL.md), [cost and safety plan](architecture/CLOUD_COST_AND_SAFETY.md) and [delivery roadmap](DELIVERY_ROADMAP.md) as the assessment contract. Resolve contradictions before assessing; do not quietly relax acceptance criteria to obtain a pass.

## Prerequisites and evidence rules

- Start offline with explicitly synthetic, reviewer-authored inputs and independent expected results. Use a disposable local environment for break/fix work; preserve baseline inputs.
- Live Phase 1 requires the roadmap's owner authorization, dedicated account/region, scoped short-lived roles, private evidence storage, current price receipt, local Wazuh capacity and teardown review. This document grants no cloud or spending permission.
- Record the task, allowed scope, input hashes, repository commit, tool versions, UTC interval, expected/observed results, errors, assessor and result. A screenshot alone cannot establish source trust or reproducibility.
- Keep originals, identifiers, credentials, plans/state and raw receipts private. Publish only reviewed sanitized summaries with private evidence references; clearly label synthetic versus actual AWS lab observations.
- A proposed task is `NOT_RUN`; failed tools are `ERROR/UNKNOWN`; missing evidence is `INCONCLUSIVE`. Never convert them to a clean result, zero events or completed response.
- Cold rounds permit the editor, terminal and supplied language reference, but no AI, copied project implementation or previously generated solution. Later assisted work must record assistance separately.

## Eleven-capability assessment matrix

Each row requires explanation, practical work and a break/fix demonstration. Timings are targets after the necessary milestone exists; they are not claims that setup or asynchronous CloudTrail delivery completes within the interview.

| ID / capability | Prerequisites | Practical interview task | Break/fix lab | Proof artifacts and measurable acceptance |
| --- | --- | --- | --- | --- |
| C01 / Isolated AWS sandbox, Terraform and least privilege | Authorized dedicated account/region, private plan/state, policy snapshots, separate provisioning/runtime/cleanup identities and dated price inputs | Explain plan; classify five IAM requests; calculate three cost scenarios and design teardown | Explicit deny/session restriction, missing SCP visibility, unexpected region, extra trail copy and retained object versions | Policy worksheet with five correct allow/deny/unknown decisions; plan and baseline/final inventory; reproduce $0.281/$1.73/$37.10 model totals; explain `Resource=*` for `DescribeInstances`, budget delay and pending billing closure |
| C02 / Actual audit ingestion, identity and raw provenance | Offline fixtures first; scoped live collector, original-object references and supported CloudTrail validation tooling | Trace three actual authorized calls; bind exact compressed bytes/version/length to signed-digest membership and normalized records | Wrong account/owner, denied read, pagination, throttling, altered bytes, missing digest, forged JSON identity and decompression limit | Private collection/validation manifests and exact membership receipt; all eight faults handled without trust promotion or lost pages; denial is not empty success; explain signature/key/chain trust and coverage limits |
| C03 / Deterministic detections, MITRE, correlation and tests | Versioned event contract, independent expected fixtures, full actor/session key | Implement/explain `AWS-LAB-001`: three unique events in an inclusive 60-second event-time window; justify T1580 | Duplicate/conflicting ID, out-of-order delivery, 60-second boundary, unrelated sessions and late arrival | Code/rule hash, expected/observed event-ID sets and tests; stable repeat/permutation results, conflict rejection and correct boundaries; mapping is behavior context, not maliciousness proof |
| C04 / Real, feasible SIEM integration | Local Wazuh resource gate, pinned compatible deployment, active response disabled | Query the persisted alert by finding/event IDs and explain decoder, rule, index and time fields | Stop SIEM delivery, restart/replay outbox, corrupt a decoder field, hide one expected event | Decoder/rule versions, payload hash, alert/index/query receipt; exact expected IDs recover without lost case linkage; count-only matching and transport ACK alone do not pass; no unapproved rented fallback |
| C05 / Cloud configuration, vulnerability assessment and remediation verification | Bounded read-only S3/IAM scope, timestamped snapshots, scanner/database versions and later mutation gate | Assess public-access/encryption/versioning snapshots and a known vulnerable fixture; specify an independently read postcondition | Missing permission, stale snapshot, scanner timeout, unavailable database, accepted change with unchanged state | Expected/observed assessment and scan receipts for all five controls; errors remain unknown, vulnerability is not exploitability, API success is not remediation; Phase 1 cloud repair remains proposed |
| C06 / Incident evidence, triage, timelines and conclusions | Evidence-backed findings, timeline, hypotheses/counterevidence and versioned case | Triage the inventory burst as an authorized exercise; separate severity, confidence, urgency and incident declaration | Add a contrary event, missing interval and material late evidence | Case timeline, supported disposition, gaps and recommendation; every conclusion cites evidence; material updates reopen/invalidate stale review; no compromise claim from burst alone |
| C07 / Human-approved response, restrictions, audit and independent verification | Authenticated analyst/reviewer, exact bindings, separate read-only verifier; Phase 1 has no executor | Review no-action, independently recheck the three calls and visible writes, and defend closure limits | Self-review, expired/stale/changed-scope approval, concurrent decisions, missing verifier access and success receipt with unchanged state | Per-target review/audit/verification receipts; reject every bypass, commit one current review, block contradicted/inconclusive closure; no-action has no execution receipt; later stale/race/unknown scenarios must pass |
| C08 / Secure API, persistent data and analyst workspace | Authenticated sessions, object roles, CSRF/origin controls, migrations and PostgreSQL transactions | Read one permitted case and perform a version-checked write with atomic audit/outbox behavior | Cross-user read, expired session, CSRF, stored script, duplicate job, crash before checkpoint and concurrent update | Request/DB receipts and tests for all seven faults; no unauthorized disclosure, lost update or partial event/case/outbox commit; stale writes return a documented conflict |
| C09 / CI/CD, IaC/dependency security and reproducibility | Version locks, pinned actions, independent test oracle, SBOM and scanner metadata | Trace a result to commit/tool/database versions and trusted workflow producer; explain IaC checks and separate apply authority | Stale receipt, untrusted PR, scanner failure, dependency fixture and tampered expected result | Provenance and check receipts; reject revision/producer mismatch, expose error as unknown, detect fixture/oracle tampering, preserve expiring exceptions; PR CI has no AWS credentials; second operator reproduces exact revision |
| C10 / Optional evidence-grounded AI with no autonomous actions | Deterministic path works without AI, sanitized inputs, output schema and evidence-ID validator; no provider activation required | Review an offline candidate summary against evidence; if AI later exists, record model/prompt versions and assess the same corpus | Hostile log instruction, fabricated citation, unsupported conclusion, raw-data request and disabled model | Offline contract/attack results or explicitly labeled model-run receipts; reject all five unsafe outputs, preserve unknowns; no tools/credentials/approval rights or autonomous production-security actions; scored separately |
| C11 / Interview labs, troubleshooting and rubrics | Completed relevant implementation milestone, independent assessor seed and private receipt template | Complete the cold round and applicable timed panels; explain one new fault without AI | Assessor changes a boundary, removes proof or presents a plausible but false production claim | Timed code/explanation, diagnosis, scores and scope labels; cold tasks/panels pass without hidden assistance; name the next discriminating read and stop condition; distinguish inspected tests from executed results |

For C01, reason through the exact request and applicable identity/resource policies, permissions boundaries, session policies, SCPs and explicit denies. Do not reduce every principal/resource-policy case to a universal intersection formula. Missing policy visibility prevents an exhaustive effective-permission claim.

## Core Phase 1 interview demonstration

This is the first end-to-end assessment after implementation and live authorization. Prepare actual private receipts in advance; the interviewer reviews them during the timed demonstration. CloudTrail/digest waiting is asynchronous, with the design's 24-hour acceptance bound, not an interview-time service guarantee.

1. Show the authorized account/region and narrow test-role scope privately; name the provisioner, collector, actor and verifier boundaries. Confirm the test requires zero EC2 instances.
2. Identify three successful single-page `ec2:DescribeInstances` calls within 60 seconds. The exercise record or user-agent hint is correlation context, not source authentication.
3. Follow each event into an exact original S3 object/version and its compressed `archive_sha256`, then compare exact decompressed `content_sha256` to its validated signed-digest member. Explain version continuity around original-location CLI validation, key/chain trust and backfill; enabling validation alone is insufficient.
4. Show strict normalization and the versioned deterministic burst result, its session key, complete event-ID set and T1580 rationale. Explain benign inventory, SDK retries and pagination as alternative causes.
5. Query the actual Wazuh index for matching event/finding IDs. Show decoded fields, persisted alert, query interval, decoder/rule versions and durable-outbox receipt.
6. Open the linked case; explain timeline, hypotheses, counterevidence and visibility. Recommend `NO_ACTION_AUTHORIZED_EXERCISE`, explicitly recording that no containment or remediation occurred.
7. Show a distinct authenticated review of the exact current recommendation. A second login controlled by one person demonstrates workflow separation, not independent institutional authority.
8. Show the independently run read-only verifier's retrieval/checks, expected/observed state and limits. Close only with current matched review and adequate verification; otherwise leave open.
9. End with a sanitized proof package connecting source, rule, SIEM query, case, review and verification; identify every missing proof and every proposed later capability.

If live evidence is delayed or absent, demonstrate the offline path under a synthetic label and record the live demonstration as pending. Do not upload forged CloudTrail data or reuse synthetic receipts as proof of AWS collection.

## Cold explanation and code round: 60 minutes without AI

| Minutes | Exact task | Required observable result |
| --- | --- | --- |
| 0-10 | Draw the AWS-to-case-to-verifier path from memory; mark seven trust boundaries and state who may mutate AWS | Separate delivery identity, event actor, source integrity, inference, review and authority; name pending/invalid provenance behavior |
| 10-35 | Write a pure Python burst evaluator over a supplied strict normalized event contract; validate outcome/action/source/session and dedup identity before counting | Three unique qualifying IDs in inclusive 60 seconds per full key; deterministic ordered evidence; conflicting duplicate fails; no I/O, credentials or API calls |
| 35-50 | Write independent table-driven expected results before executing the supplied harness | Cover 2-event negative, 3-event positive, exact-60 positive, just-over-60 negative, repeat duplicate, conflicting duplicate, reversed order, different sessions, failed action and missing identity |
| 50-60 | Explain one failing result and propose a minimal correction; state what the tests cannot prove | Trace source records and boundary condition; distinguish software correctness from source trust, detection efficacy and response authority |

The assessor supplies fresh event IDs/timestamps and hidden variations. Merely matching candidate counts fails the evidence requirement. Review source IDs and rule inputs, not only the final Boolean.

## Timed challenge panels

Run these after offline prerequisites exist. The assessor selects new values and failure locations; task clocks exclude provisioning, installations and AWS delivery waits. Every panel starts with a 2-minute scope/safety statement within its allotted time.

| Panel | Time | Exact challenge and passing demonstration |
| --- | --- | --- |
| Provenance and IAM | 25 min | Given one forged actor field, one valid but unrelated digest and five policy requests, locate the trust break; reject unsupported membership and classify allow/deny/unknown without editing policy or contacting unapproved resources |
| Detection and investigation | 25 min | Given duplicate/reordered events across two sessions and one late event, identify exact findings, T1580 rationale and false positives; revise the case and invalidate old review rather than change prior evidence |
| SIEM troubleshooting | 20 min | Diagnose a seeded failure among outbox, collector, decoder, custom rule and index time filter; prove the first broken boundary with IDs and receipts, then replay safely and query exact recovered IDs |
| API and database | 25 min | Replay one cross-user read, missing-CSRF write and two writes against one case version; demonstrate authorization rejection, one committed version transition and atomic audit/outbox records; explain lease-expiry/crash recovery |
| Delivery and vulnerability | 20 min | Inspect a wrong-commit receipt, fork PR and scanner database failure alongside a known finding; reject false provenance, preserve unknown status and propose a bounded exception without declaring the scan clean |
| Cost and teardown | 20 min | Recalculate target/envelope/misconfiguration totals, then add one million extra management-copy events; identify all-version storage, requests and download effects; produce a retained-resource list and staged teardown/billing verification |

Troubleshooting answers must state observed symptom, competing explanations, the next discriminating read, expected outcomes and the stopping condition. Guessing a fix or broadening permissions without evidence does not earn the practical score.

### Assessor fault cards and expected reasoning

- **Three rows, two identities:** repeated delivery of one event ID does not supply the third unique call. A different session cannot complete the original session's burst. Conflicting content under the same dedup identity blocks trust rather than winning by arrival order.
- **Delivery order differs from event time:** reverse input order and replay after a crash. Findings must retain the same event-ID set; a late material event produces a versioned revision and invalidates old review. Explain the finite reconciliation/retention boundary.
- **Same role name, different credentials:** present two sessions with identical role/session names but distinct access-key identities/issuance context. They must not form a combined burst; missing session discrimination is unknown, not permission to join.
- **Normalizer drops a field:** change an unknown field on the same event ID. Full-source-record comparison must reveal a conflict even if normalized fields match; identical records in differently compressed files remain duplicate deliveries.
- **Analyst submits verified:** directly call the verification-write route with an analyst/reviewer session and a forged verifier field. Reject it using authenticated service authority; distinct restricted database roles must also prevent bypass.
- **Hash matches, provenance does not:** a local checksum can establish byte consistency with a supplied file, not service origin. Distinguish compressed preservation hash from uncompressed digest-member hash. Require exact original location/version continuity and validated membership; a signed unrelated interval does not cover the file, and CLI validation of current locations does not automatically validate an older cached version.
- **Valid chain, missing logging:** distinguish validated retained-file integrity from event-selector coverage, unsupported regions, disabled data events and possible logging disruption. Neither digest success nor event-history absence proves that every activity was captured.
- **Alert query is empty:** inspect source/outbox IDs, collector receipt, decoder output, rule firing, index status and time range in that order of dependency. Retain the first failing observation instead of calling the source clean.
- **Read permission denied:** record denied/unknown, do not silently clear the finding or widen the role. Identify the exact missing authorized read and whether the remaining evidence supports any narrower conclusion.
- **Worker loses its lease:** use a transaction and unique idempotency key; demonstrate that checkpoint advancement cannot precede durable event/finding/case/outbox persistence. A transport replay may produce duplicate delivery without duplicate logical findings.
- **Two reviewers race:** both start from one version; exactly one current transition may commit. Preserve the rejected request/audit outcome without overwriting the winning decision or inheriting its authority.
- **Scan tool returns no findings and nonzero exit:** preserve tool/database/error state; the assessment is unknown. A genuinely successful clean run requires scope, tool/database versions and trustworthy completion evidence.

### Cost arithmetic card

Use only the dated model in the cost plan; reprice before any future live apply. With its assumptions, the target is `2*0.023 + 25*0.005 + 50*0.0004 + 1*0.09 = $0.281`.
The envelope is `10*0.023 + 100*0.005 + 250*0.0004 + 10*0.09 = $1.73`. One million additional management-copy events add `$20`; they do not multiply storage cost by the same factor.
The misconfiguration case totals `$37.10` before any accidentally enabled compute/NAT/security services. It is not a worst-case bound. Request units are thousands; every pagination page and retry counts.
Ask why deleting current objects leaves noncurrent versions/delete markers, why retained evidence can keep billing, and why a completed destroy does not close delayed billing. Required answer: exact inventory, retention decision and later independent bill checks.

## Later response and optional AI panels

Later response exercises remain offline until the separate mutation gate passes. The only proposed cloud-changing action is setting all four public-access-block flags to true on one allowlisted non-logging marker bucket; account-level blocking stays enabled. No exercise requires exposing a bucket, changing IAM, deleting resources or weakening protections.

In a 30-minute simulated response panel, the assessor presents stale evidence, expired approval, a changed target, a precondition race and a timeout after submission. Bind authorization to exact recommendation/evidence/targets/policy/version; perform fresh precondition reads; reject stale scope; record timeout as unknown and independently read state before any retry. Show that idempotency in the application cannot eliminate an external administrator race.

Then present an accepted API request whose observed postcondition is unchanged, followed by partial visibility. The candidate must record failed/inconclusive verification, retain the case and explain bounded recovery checks. An HTTP success, an approval record or absence of an error is never effectiveness proof. Any later live receipt must name its limited actual outcome separately from simulation results.

Optional C10 is assessed separately and adds no points to the ten mandatory capabilities' score. In 15 minutes, inject hostile instructions, a fabricated evidence ID and a request to reveal raw records into sanitized log text or offline candidate output. Require rejection/containment, deterministic citation validation, explicit unknowns and a working investigation with AI disabled. No model/provider deployment is required; a later model receives no credentials, tools, approval rights or execution authority.

## Grading and progression

Score each capability 0-4 using the same scale. A score requires recorded evidence at that level; plans, polished narration and source-project tests inspected elsewhere are not executed proof.

| Score | Meaning | Evidence required |
| --- | --- | --- |
| 0 | Unassessed or unsupported | No completed current task; keep `NOT_RUN` visible |
| 1 | Can explain with help | Correct basic model and limitations, but cannot independently perform the task |
| 2 | Can complete normal path | Repeatable happy-path artifacts with assistance or unresolved negative controls |
| 3 | Can implement, break and diagnose independently | Cold explanation/task plus every listed row acceptance/negative control, provenance-bound receipts and stated residual risk |
| 4 | Can defend and transfer the skill | Level 3 plus an unseen assessor variation, justified tradeoff and independently reproduced artifact by a second operator |

- **Foundation readiness:** all ten mandatory capabilities at least 2/4 using explicitly offline work; this is interview preparation, not permission to deploy. C10 is optional and reported separately as 0-4 or not assessed.
- **Independent interview readiness:** at least 33/40 overall, each mandatory capability at least 3/4, cold round and applicable panels passed, and no hard fail. Every assessed capability must identify offline versus actual-lab evidence; optional AI never raises or lowers this denominator.
- **Phase 1 proof qualification:** additionally require the complete actual AWS-to-Wazuh-to-reviewed-no-action-to-verifier chain above, all roadmap gates, current receipts and reproducibility. Scores cannot substitute for missing live evidence.
- **Later mutation qualification:** requires separate owner authorization and delivery gates plus C05/C07 at 4/4 on stale/race/unknown/postcondition simulations; no score itself authorizes a live action.
- Reassess after material rule, schema, permission, trust-path or workflow changes. Keep prior results with their exact commit; do not inherit a prior pass for edited code or stale evidence.

Hard fail the assessment for unauthorized cloud/spend changes, scope broadening, disclosure of private identifiers/secrets, fabricated or relabeled evidence, bypassed approval, suppression of unknown/contradictory outcomes, or unsupported production/containment/efficacy claims. Stop the affected exercise, preserve the failure record and require a fresh supervised assessment after correction; a high total cannot offset a hard fail.

## Assessor record and honest interview language

For each attempt record: capability/panel, commit and versions, source class, prerequisites/authorization reference, task seed, time, expected versus observed evidence IDs, faults introduced, errors/unknowns, score, assistance, assessor, residual gaps and next reassessment trigger. Store private evidence separately and link only sanitized artifact references here.

Current human assessment record: **all eleven capabilities NOT_RUN; all panels NOT_RUN; no earned mastery, live integration or remediation claim.** Phase 1A-1 automated tests are a separate software-validation record. Update human scores only after observed assessment; separate an independent operator's reproduction from two local accounts controlled by the author.

An accurate eventual statement would be: "In an authorized AWS sandbox, I traced three read-only inventory calls through validated CloudTrail evidence, a deterministic rule, Wazuh, a reviewed no-action case and a separate read-only verifier." Use it only after those live receipts exist. Until then say: "I implemented and tested the offline synthetic evidence, detection, persistence, authenticated workspace and reviewed no-action consistency workflow; live AWS source validation and SIEM integration remain future work."
