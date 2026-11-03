# Threat model

Status: Phase 0 proposal, 2026-11-03. Controls are requirements, not installed protections. See the [system design](SYSTEM_DESIGN.md) and [delivery gates](../DELIVERY_ROADMAP.md).

## Assets, actors and scope

Assets: private raw logs/digests, source locations, role sessions, configuration snapshots, backups, conclusions, reviewer identity, approvals, audit records, dependencies, Terraform state and the AWS bill. Read-only telemetry can expose account structure and personal data.

Adversaries include an unauthenticated local-network user; a malicious/compromised analyst; an actor generating misleading AWS events; a compromised dependency, CI job or SIEM; malicious log text targeting a browser or optional model; and operator error. Account root, local administrator and hypervisor compromise remain high-impact residual risks. Hashes do not prevent privileged deletion, and two accounts on one laptop do not establish institutional separation of duties.

Trust zones: AWS control plane, source archive, collector/parser, database/API, browser, Wazuh VM, verifier, optional AI provider, CI and public GitHub. Review changes against the [data-flow diagram](SYSTEM_DESIGN.md#deployment-and-trust-boundaries).

## Abuse cases and required checks

| ID / boundary | Abuse or failure | Required control and test | Residual risk / failure behavior |
| --- | --- | --- | --- |
| T01 / source | Forged JSON claims an approved account or authentic source class. | Collector assigns source class; STS guard, owner/prefix/trail allowlist, TLS, restricted service writer, signed-digest membership. Inject fixture/wrong-account objects; neither becomes trusted. | Account administrators can disrupt logging; trust in AWS remains. Wrong identity stops collection. |
| T02 / archive/parser | Replacement, missing digest, truncation, decompression bomb. | Preserve bytes/version/length, verify hash/signature/file membership, bound decompression/JSON/schema; test changed bytes and missing referenced file. | Versioning is not immutable. Invalid/pending provenance blocks trusted findings and closure. |
| T03 / durable ingestion | Duplicates, reorder or late delivery cause false bursts or lost findings. | Transactional checkpoint, uniqueness/conflict checks, event-time windows, reconciliation; crash/retry/boundary tests. | Events beyond retained scope need reopened investigation; show blind intervals. |
| T04 / detection | Missing session identity joins unrelated actors; mappings imply unsupported attack conclusions. | Require full correlation key; cross-account/session/negative tests; record mapping rationale and limits. | Benign inventory creates alerts; no measured field-efficacy claim. |
| T05 / API/browser | Unauthorized evidence reads, CSRF, stored XSS, traversal, injection, stolen sessions. | Object authorization, local TLS, server-side expiring sessions, CSRF/origin checks, escaping, parameterized SQL, evidence IDs and size limits; cross-user/expired-session/script tests. | Host compromise exposes sessions; no public hosting in Phase 1. |
| T06 / approval | Client asserts reviewer role, self-approves, replays old review or changes targets. | Server-side role lookup, distinct reviewer, exact version/evidence/action/target/policy binding, expiry, optimistic concurrency; test each stale/replay variation. | One person with two logins is lab workflow practice, not institutional independence. |
| T07 / execution | Retry repeats mutation, stale precondition hits wrong target, generic command escalates scope. | No executor in Phase 1. Later action/target allowlist, exact-resource role, fresh reads, attempt key, timeout-to-unknown and bypass/drift tests. | External administrator races remain; unknown outcome requires state read before retry. |
| T08 / conclusion | API success is represented as effective containment. | Distinct verifier identity/checker and fresh cloud reads; contradiction/inconclusive result blocks closure. Test successful receipt with unchanged state. | Shared cloud provider/host remain; prove only named postconditions. |
| T09 / SIEM | Outage loses data, malicious alert authorizes action, active response changes hosts. | Durable outbox, payload hash/IDs, positive index-query acknowledgment, bounded retries; no action routing; active response disabled. Test VM outage/replay. | Derivative store can lag and consumes local resources. |
| T10 / supply chain | Package/action steals credentials or substitutes stale evidence. | Pin locks/actions, minimum CI token, no AWS credentials on PRs, scanners; bind receipts to commit/tool/fixture/producer. Reject revision mismatch. | Scanners do not prove safety; exceptions expire. |
| T11 / publication | Logs, screenshots, plans or secrets enter Git history. | Exclude evidence/state/plans, synthetic fixtures, allowlisted exports, identifier/secret scan and human diff review. Test nested sensitive values. | Pattern scans miss contextual secrets; history persists. No real raw event becomes a public fixture. |
| T12 / optional AI | Log text requests policy bypass, exfiltration, invented facts or approval. | AI deferred. Later minimize inputs, mark text untrusted, no tools/credentials, exact citation/schema checks, adversarial corpus and human review. | Hallucinations/provider handling remain; reject unsupported output and retain deterministic workflow. |
| T13 / costs | Polling, data events or forgotten infrastructure creates a bill. | Dedicated account, disabled unapproved services, bounded calls/time/volume, manual timeout, budget notifications and teardown inventory. Test bounds offline. | Alerts lag and are not caps; owner accepts financial exposure before live use. |
| T14 / audit | Decisions are edited or an old backup hides activity. | Append-only application role, transactional audit, sequenced hash chain and periodic private external checkpoint, restore/gap tests. | DB/host administrator can rewrite records and chain; no forensic immutability claim. |

## Security invariants

1. Synthetic, conflicting or unverified evidence cannot become authentic through a request field, checkbox or model output.
2. Ingestion/detection roles cannot mutate cloud controls. Provisioner credentials are absent from API, SIEM and ordinary workers. Source trust also requires the system design's exact-file binding: separate compressed/uncompressed hash domains, validated digest membership and source/digest version continuity.
3. Conclusions cite supporting evidence, counterevidence, visibility interval and uncertainty. Missing telemetry is not evidence of safety.
4. A review authorizes one recommendation version; material evidence changes require review again. Cloud action is impossible in Phase 1.
5. Failed/unknown execution and verification stay visible and block closure. Never fall back to simulated success. Later bucket-flag values are enforced by the action adapter, not IAM; account-level blocking must remain beyond responder authority.
6. Public artifacts contain no real identifiers or private infrastructure details. Private raw data is never sent to a model by default.

## Deferred controls and residual exposure

No implementation verifies these invariants yet. Host protection, disk encryption, backup security and account ownership require operator confirmation. High availability, enterprise identity, organization-wide SCPs, multi-tenancy, off-account immutable evidence and independent institutional reviewers are outside initial scope. Re-review the threat model before any deployment depends on them.

The first live gate requires hostile-input, source-spoofing, approval-replay, evidence-drift, crash-recovery and cost-bound reviews. Mutation gates additionally require action-policy and independent-verification tests. Keep raw acceptance receipts private and publish sanitized summaries only.
