# Fixed worker and least-privilege identity readiness implementation plan

> **For agentic workers:** Use test-first implementation, disjoint source ownership and independent adversarial review. Execute within the owner's offline-only authorization.

**Goal:** Bind named readiness workers to distinct inspection, collection and verification capabilities without granting live AWS access or evidence authenticity.

**Architecture:** Three named facade functions close over immutable, reviewed AWS2 worker references; requests cannot select code, imports, commands, endpoints or client factories. Identity-only inspection supports empty trail/bucket inventory. Separate issuance/MFA observations and explicit static credential bindings feed strict session contracts; archive scopes remain separate and require distinct collector/verifier identities. Worker execution uses data-only fictional transport tapes behind the existing process supervisor and its offline network guard.

**Tech stack:** Existing Python3.12–3.14, pinned botocore, standard-library JSON/process tools, unchanged dependency locks and native Terraform toolchain.

**Spec:** Owner's Phase1B-AWS-3 request. Starting protected main `58d008c4744c7f2f7560bddc6fcdc19516ef6298`, tree `2d1d8c37a2a9a1094f74b17046ffcdb5e7fcc0cc`.

## Global constraints and rulings

- One branch: `codex/phase1b-aws3-fixed-worker-identity-readiness`; one unmerged PR. No AWS requests, credential access, AssumeRole execution, Terraform plan/apply/destroy, deployment, Wazuh or retained local PostgreSQL operations.
- The detailed owner specification authorizes implementation. Resolve routine design choices using the existing architecture; no additional permission cycle is needed.
- Dated owner-supplied November4 account observations are design inputs only. Keep actual identifiers/account receipts private. No account inspection is repeated or simulated as a real session.
- Preserve all ten protected checks, previous coverage gates, migrations, retained data and synthetic workflow authority. Real PostgreSQL acceptance runs only in the existing sequential disposable CI service.
- Do not manage/import/widen the existing audit role. No S3 object access or HeadObject in its inspection capability; HeadObject requires object-retrieval permission. Provisioner, cleanup and test-actor authorities stay separate.
- Existing Terraform has a narrow collector metadata gap: its SDK trail check calls GetInsightSelectors, absent from collector policy. Add only that exact regional trail read to collector source; keep verifier/trust/resources unchanged and report exact differences. No IAM resource is provisioned.
- GetCallerIdentity cannot establish region, issue/expiry, MFA or effective IAM. Required separate issuance/MFA observations remain unverified. No returned or caller-supplied flag can authenticate evidence, authorize findings or close cases.
- AWS2 low-level trusted test mechanism remains internal; the new facade exposes neither WorkerRef nor dynamic selection. This remains a trusted-code lifecycle boundary, not a hostile native-code sandbox.

## Review focus

Same-object credential mutation must fail; empty inventory must not become an error or an invented archive; denied/error pages cannot become empty success; unapproved attached policies must not expand reads; collector/verifier identities must remain distinct; deadline and source-version changes must yield negative unauthenticated receipts.

## Tasks

- [x] Write independent identity/MFA/lease/substitution tests, observe RED, implement strict session contracts and private binding.
- [x] Write fixed facade/worker tests, observe RED, implement named metadata/archive workers with bounded data-only fake transport and no dynamic code inputs.
- [x] Harden the existing SDK against in-place secret/token substitution without credential refresh/discovery.
- [x] Produce exact least-privilege policy source, permission matrix/difference report and mutation tests; correct only the narrow collector Terraform discrepancy.
- [x] Add cross-boundary/fault tests and AWS3 branch gates while preserving the existing ten jobs and resource policy. Update architecture, threat model, readiness/operations, roadmap and no-AI lab.
- [x] Run offline local checks; independently review and fix material findings. See [executed local validation](PHASE1B_AWS3_VALIDATION.md).
- [ ] Publication acceptance: one PR, exact-head hosted native/database/security CI and fresh final-head review. Recorded on the published PR/final receipt rather than predeclared in source. Leave unmerged and stop.
