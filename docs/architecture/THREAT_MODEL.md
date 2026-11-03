# Threat model

Status: target threat model, 2026-11-03. Phase 1A-1 covers [offline parsing/detection](../OFFLINE_FOUNDATION.md); Phase 1A-2 adds [local persistence and recovery controls](PERSISTENCE_CONTRACTS.md). Phase 1A-3A implements [local authentication, per-case authorization and append-only notes](ANALYST_WORKSPACE.md). Live-source trust, reviewer approval, independent verification and response controls remain requirements. See the [system design](SYSTEM_DESIGN.md) and [delivery gates](../DELIVERY_ROADMAP.md).

## Assets, actors and scope

Assets: private raw logs/digests, source locations, role sessions, configuration snapshots, backups, conclusions, reviewer identity, approvals, audit records, dependencies, Terraform state and the AWS bill. Read-only telemetry can expose account structure and personal data.

Adversaries include an unauthenticated local-network user; a malicious/compromised analyst; an actor generating misleading AWS events; a compromised dependency, CI job or SIEM; malicious log text targeting a browser or optional model; and operator error. Account root, local administrator and hypervisor compromise remain high-impact residual risks. Hashes do not prevent privileged deletion, and two accounts on one laptop do not establish institutional separation of duties.

Trust zones: AWS control plane, source archive, collector/parser, database/API, browser, Wazuh VM, verifier, optional AI provider, CI and public GitHub. Review changes against the [data-flow diagram](SYSTEM_DESIGN.md#deployment-and-trust-boundaries).

## Implemented local workspace boundary

Phase 1A-3A addresses hostile browser requests and malicious account actions through both HTTP checks and actual restricted PostgreSQL identities. See the [permission matrix](ANALYST_WORKSPACE.md). The normal web configuration contains no owner/maintenance/collector credential. Each account has distinct auth and data LOGIN roles bound through `SESSION_USER`; capabilities expose only named security-definer functions. Reviewer/auditor data identities cannot mutate notes, evidence, sessions or audit. No runtime identity owns objects, can create database/schema objects, can assume owner/verifier roles or receives direct table/column DML. Startup validates these restrictions and the full security catalog, including column grants and database ownership.

Passwords use reviewed bounded Argon2id parameters and protected interactive provisioning. Random opaque sessions persist only hashed tokens; disabled, expired, rotated and revoked bearers fail. Persistent finite throttle buckets and one-use pre-login/session CSRF challenges survive server restart. Per-object grants are rechecked for lists, findings, exact record variants, historical revisions and lineage; unauthorized identifiers get the same 404. New merged cases do not inherit grants. No fixture, request header, cookie role field or note can elevate source trust or authority.

Loopback-only TLS, exact HTTPS Host/Origin checks, cross-site rejection, Secure/HttpOnly/SameSite cookies, no CORS, restrictive CSP, escaped Jinja output, parameterized SQL, bounded request bodies/processing and no-store responses contain browser attacks. Generic client failures and disabled debug/access logs limit secret disclosure. Notes use a current machine revision/fingerprint, row lock, one-use nonce and atomic author-bound note/audit insertion; failure cannot partially commit. Historical evidence and findings remain immutable to runtime users.

Restore targets must revoke PUBLIC CONNECT before a no-owner/no-ACL restore; runtime connectivity returns only when security reconstruction and the original full fingerprint validate atomically. Otherwise temporarily PUBLIC security-definer helpers could expose restored data. The tested restore preserves identities, session hashes, grants, notes and audit; cluster roles/private config are separately protected and not supplied by a database dump.

Residual risks: a local administrator, maintenance superuser or full web-process/private all-account configuration compromise can impersonate configured users or bypass routine SQL controls. Individual account SQL credential theft is scoped to that identity, but it is still a credential compromise. Login throttling permits local denial of service; MFA, remote identity, host isolation, public-server hardening and cross-host recovery are absent. Truncated history/note/source projections expose their total counts; they are not completeness claims. Evidence remains synthetic and unauthenticated, accounts are a lab simulation, and reviewer approval/verifier/closure/containment are absent. Security tests are not a penetration-test certification or evidence of field detection efficacy.

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

Offline parser/detector tests verify bounded inputs, synthetic trust restrictions, complete-record conflicts and session separation. They do not verify the live-source, approval, durable-audit or response invariants. Host protection, disk encryption, backup security and account ownership require operator confirmation. High availability, enterprise identity, organization-wide SCPs, multi-tenancy, off-account immutable evidence and independent institutional reviewers are outside initial scope. Re-review the threat model before any deployment depends on them.

The first live gate requires hostile-input, source-spoofing, approval-replay, evidence-drift, crash-recovery and cost-bound reviews. Mutation gates additionally require action-policy and independent-verification tests. Keep raw acceptance receipts private and publish sanitized summaries only.


## Phase 1A-2 database and worker risks

New trust boundary: hostile synthetic input enters an isolated loopback PostgreSQL lab through the bounded parser. Bytea originals and derivatives commit together; database uniqueness/FKs/version and synthetic-only checks prevent routine identity/trust drift. Full-record conflicts and new evidence mark prior conclusions pending before acknowledgment. No database flag or caller field grants AWS authenticity.

Worker races use a locked generation, SKIP LOCKED claims, database-clock leases, finite attempts and claim-token fencing. Cases append revisions and bridge lineage; stale optimistic revisions fail. The offline outbox records local receipts separately from SIEM visibility and reconciles committed receipts after acknowledgment loss, including the final attempt.

Recovery verification checks raw/normalized hashes, all source references, supporting findings, reciprocal case coverage, revisions, event timelines, lineage and outbox receipts. Independent negative tests remove or corrupt these artifacts. Genuine process termination and database-session interruption complement controlled exceptions; they do not demonstrate disk/power-loss or HA resilience.

Resource controls bound compressed/expanded bytes, records, raw objects, batches, quarantine errors, leases and attempts. Docker has project-specific names, loopback publication, CPU/memory/PID limits and generated ignored credentials; ambient remote Docker/libpq routing is rejected. Test databases are retained until explicitly scoped cleanup, so repeat runs consume disk. Ordinary Docker volumes have no portable hard disk quota.

Residual risks: the local owner/admin can bypass triggers or edit storage, shared-host compromise remains possible, private credentials/dumps require OS protection, and PostgreSQL storage/WAL may exceed evidence-byte limits. No authenticated analyst roles, independent review/closure, external SIEM receipt, live-source authenticity, power-loss guarantee or production operational efficacy is claimed. See [persistence contracts](PERSISTENCE_CONTRACTS.md) and [recovery runbook](../FAILURE_AND_RECOVERY.md).
