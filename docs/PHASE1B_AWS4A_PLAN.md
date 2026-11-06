# AWS4A gated posture network worker implementation plan

> **For agentic workers:** Use test-first implementation, disjoint file ownership, existing Python tooling and independent adversarial review. Do not commit individually; publication follows whole-tree validation.

**Goal:** Implement a separate fixed posture worker and guarded SDK engine while making production execution non-activatable in this milestone.

**Architecture:** The public entrypoint launches only a literal posture bootstrap under the existing parent watchdog. Its closed request carries references only; the child fails closed before credentials/client construction. Private decision/capability contracts and a fixed, bounded eight-operation SDK engine are exercised with fictional credentials, fake clients and numeric-loopback fault servers. A shared supervisor helper retains unchanged fixture behavior; the original fixture bootstrap, socket guard and AWS3 facades stay byte-for-byte unchanged.

**Tech stack:** Python3.12/3.14, existing pinned botocore/boto3 and standard-library process/HTTP tools. No dependency, IAM, Terraform, SQL or infrastructure changes.

**Spec:** [Issue11](https://github.com/farhan-shafee/cloudsecops-live/issues/11) and [owner permission clarification](https://github.com/farhan-shafee/cloudsecops-live/issues/11#issuecomment-6670869085). Verified main `1d9e978946760325a4005f5306a15ac102430a8f`, tree `2633851638ffa22ed5e52c12463a05019c3e8fc8`.

## Constraints and rulings

- One branch `codex/phase1b-aws4a-gated-posture-network`; one unmerged PR. No AWS, actual credentials, IAM, provisioning, CloudTrail collection, source-authentication promotion, deployment, retained PostgreSQL/Docker or Wazuh operations.
- Private owner facts and linked CLI receipt on Chopin were read and cross-checked. Their successful historical CLI session ended and cannot be reused. No private identifiers/policies/receipts enter Git or public artifacts.
- Owner explicitly resolved the documentation blocker for offline work: retain `s3control:GetPublicAccessBlock(AccountId=approved_account)` and `s3:GetAccountPublicAccessBlock`/exact-account condition. Never add bucket permission, bucket fallback or broaden IAM. Keep the contradictory SAR operation row as an unresolved live-preflight limitation.
- Production execution has no activator, environment flag, JSON toggle or approved-source constructor. All caller-supplied approval/verification labels are rejected or remain pending. Complete-looking metadata cannot enable a run.
- Owner decision metadata binds exact identity, code/scope, UTC window, finite budgets, expected inline-policy fingerprints, owner/custody/effective-IAM/network references and CA digest. References alone prove none of these; review state remains pending.
- Credential design uses an opaque, one-use scope/nonce/PID-bound private capability, never credential material in JSON/arguments/logs/files. Only an explicitly named offline capability can be redeemed by fake-client tests. A real OS broker and independently approved custody/egress/containment remain live blockers.
- Fixed client construction uses packaged pinned models and explicit static credentials, no default SDK session/provider chain, profiles, IMDS, plugins, external model paths, proxies or caller-selected endpoints/factory. SDK internal retries are disabled.
- Existing BudgetPolicy ceilings can only decrease. Count failed attempts/pages, explicit retries, operations, request bodies and response bytes; reject before exceeding bounds. Bound headers/chunk lines before framing/parse and preserve the independent total deadline through cleanup.
- No arbitrary process creation is part of the worker. Separate deny-by-default Python egress/process guards supplement native owned-tree containment; they are not a hostile-native-code OS sandbox. That limitation blocks live activation.
- Preserve ten CI names, all previous gates, native Terraform1.17.1/provider6.71.0 and sequential disposable PostgreSQL acceptance. Historical SIGSEGV/ACL timeout/retry remain unresolved evidence.
- The detailed issue and explicit resume authorize routine design/implementation choices; no additional design-approval cycle is required.

## Shared interfaces

Package `cloudsecops_live.integrations.aws_posture`:

- `contracts.PostureRequest(decision_ref: str, nonce: str)`; closed versioned metadata, no credentials/paths/endpoints/operations/toggles.
- `contracts.PolicyBinding(name: str, sha256: str)`.
- `contracts.OwnerDecision(record_id, expected: ExpectedIdentity, window_start, window_end, budget: BudgetPolicy, inline_policies: tuple[PolicyBinding,...], source_revision, owner_ref, custody_ref, effective_iam_ref, network_ref, ca_sha256, review_state="pending")`; `.digest`, `.check(now)`, `.to_metadata()`, `.public_dict()`; never enables execution.
- `contracts.PostureClients(sts, iam, cloudtrail, s3, s3control)` is a private trusted-code injection bundle, with fields excluded from repr. It is never deserialized from requests.
- `capability.OfflineSessionCapability(session: BoundSession, decision_digest, nonce)` binds current PID and is one-use. `.redeem(decision, nonce, now) -> BoundSession` checks identity/time/scope; serialization and repr never expose material. A separate `CredentialCapabilityRef` is metadata only and cannot redeem a real credential.
- `budget.PostureBudget(decision, session, *, clock, monotonic)`; `.check()`, `.before_call(service, operation, params, retry=False)`, `.authorize_parameters(service, operation, params)`, `.before_send(service)`, `.consume_request_bytes(n)`, `.consume_response_bytes(n)`, `.invalidate()`, `.public_dict()`. Validation precedes dispatch; unknown/denied outcomes never turn into empty success.
- `engine.inspect_posture(decision, session, clients, *, clock, monotonic, budget=None) -> dict` uses only literal method calls and returns minimized unauthenticated observations. It rechecks STS/RoleId at completion, expected complete inline-policy hashes, zero unapproved attachments/boundary, full bounded pagination and exact all-enabled account BPA fields. All-false/missing/unexpected or ambiguous/denied responses reject.
- `clients.build_fixed_clients(decision, session, budget) -> PostureClients` is internal and never called by the disabled public worker. Fixed endpoints/configuration only; tests replace transport internals with controlled responses and never dispatch externally.
- `wire` bounds raw HTTP before header/chunk framing and validates fixed HTTPS endpoints, CA/configuration, no proxies/redirect/retry leakage. Wire counters may conservatively include logical reservation overhead; never undercount actual bodies/framing.
- `registry.run_posture_network(request, *, timeout=5.0, cancel=None) -> IsolatedResult` captures one fixed worker/bootstrap. `bootstrap` installs a separate deny-by-default guard; `worker.execute` returns only disabled failure in this milestone.

## Tasks

- [x] Contracts/capabilities: independently specified negative tests, observe RED, implement strict pending records and one-use fictional capability binding. Own contracts.py/capability.py and tests/test_aws4a_contracts.py/tests/aws4a_helpers.py.
- [x] Engine/budget: test wrong identity/recreation/MFA/expiry, policy substitution, denied/throttled pages, exact account BPA, incomplete/cyclic pagination and every budget. Own budget.py/engine.py and tests/test_aws4a_engine.py/tests/test_aws4a_budget.py.
- [x] SDK/wire: test provider-chain denial, pinned endpoints/CA/proxies/retries, request bytes, preparse response/line limits, SDK substitution and malformed replies. Own clients.py/wire.py and tests/test_aws4a_clients.py/tests/test_aws4a_wire.py.
- [x] Fixed process integration: test disabled gate/no credential or client lookup, bounded IPC, cancellation/crash/late spawn/cleanup and separate egress/escape denial. Root owns registry/bootstrap/worker/network and the minimal shared process helper plus tests/test_aws4a_process.py and fixed test probes.
- [x] Add new individual85% branch gates and preserve old tests/ten CI contexts. Update README, architecture/threat/readiness/operations/roadmap and validation/permission limitations; no4B implementation.
- [x] Independently review combined source; fix material findings. Run full local offline validation; no local PostgreSQL.

Publication evidence is recorded separately at the exact final commit: commit/push, identical remote tree, actual hosted ten-check CI, fresh Codex review and a bounded source/diff receipt. Leave the single review PR unmerged.

## Review focus

Credential/owner-reference labels must not mint authority; credentials must not enter IPC or diagnostics; bucket API/action and AccountId substitutions must fail; response framing must be bounded before parser allocation; SDK-internal retries/redirects must not escape budget; role recreation/policy drift must invalidate observations; cancellation/cleanup uncertainty must never yield successful evidence. Inspect all of these independently before publication.
