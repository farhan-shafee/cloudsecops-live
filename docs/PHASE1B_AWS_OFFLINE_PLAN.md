# Offline AWS foundation implementation plan

The owner's Phase1B-AWS-0 specification authorizes this offline milestone. Starting main is `7b8435f8e93c375f83501baace45468ee5e6e9c1`, tree `c3c0eb17964d1002e71cfedae144140da1f49c7d`. Work uses `codex/phase1b-aws-offline-foundation`; the Wazuh branch remains intact.

## Design decisions

Extend neither the synthetic account rules nor its trusted storage path. A separate AWS-shaped parser and dependency-injected collection protocol preserve original bytes and complete-record provenance while every result remains unauthenticated and unusable for findings or human closure. Reuse only the existing version-pinned bounded syntax/canonicalization helpers; preserve the old parser, detector, migrations001–003 and workflow policy. No database migration is justified for an in-memory offline preparation boundary.

Alternatives considered: adding a real SDK client would introduce forbidden credential discovery/network behavior; broadening the synthetic parser would blur source/version semantics. Separate types and an unavailable authentication gate keep those boundaries explicit. The selected Terraform representation is native `.tf.json`, allowing dependency-free structural policy checks; it does not substitute for Terraform/provider validation or effective IAM evaluation.

## Work and acceptance

- [x] Independently source current AWS digest, original-location, pagination, identity and version-binding obligations.
- [x] Test before implementation: strict scope, AWS-shaped normalization, exact byte hashes, malformed/NUL/forged-trust inputs, genuine identity formats distinct from synthetic identities.
- [x] Implement bounded typed fake-transport contracts for identity, paired-marker version listing, exact version retrieval and current-version continuity. Listing failure/truncation is never an empty successful scan.
- [x] Stage a complete bounded poll before a compare-and-swap checkpoint commit. Preserve exact replay, changed checkpoint rejection, duplicate variants and conflict information; failures produce no partially committed batch. This store is explicitly an in-memory test reference, not production durability.
- [x] Assess controlled digest outcomes and exact membership/hash/version continuity without implementing cryptography or accepting authentication. Even consistent fixture receipts cannot open the future trust gate.
- [x] Add an offline deterministic demonstration, sanitized public summaries and mandatory negative tests for trusted ingestion/closure bypasses.
- [x] Create fixed-region minimal Terraform design: private versioned archive, management trail/integrity, separate collector/verifier/test actor, external provisioning/cleanup authority, no destructive expiry or broad runtime administration. Test structural policy mutations independently.
- [x] Extend credential-free CI, per-module branch reporting and packaging. Retain all earlier tests and gates. No CI AWS calls, credentials or Terraform plan/apply.
- [x] Run ordinary regression suites sequentially using the supported existing PostgreSQL limits. Do not rerun parallel memory-exhaustion stress or change Docker/WSL resources. A new native backend crash stops work and preserves diagnostics.
- [x] Update README, architecture/threat/cost/roadmap and no-AI interview lab. Preserve Wazuh NO-GO and unproven historical PostgreSQL crash cause.
- [x] Independent adversarial review; correct material issues; rerun affected/full acceptance and record executed-source hashes.

Commit/publication, exact remote-tree verification and fresh PR CI/review are delivery steps recorded on the new unmerged PR and final report. The source validation record does not predeclare those external outcomes.

## Important failure classes

Wrong/expired identity must stop before S3 access. Paired pagination markers must progress with bounded pages/objects and include delete markers. An error/malformed page or a changing current version prevents checkpoint advancement. Unknown fields affect canonical hashes. Archive and uncompressed-content SHA256 are different domains. Supported CLI validation has no VersionId option, validates online original locations, and only examines referenced members; exit0/empty output cannot establish file membership or historical-version binding. Delayed/backfill chains and gaps remain explicit. No caller flag, receipt JSON or local hash establishes AWS authenticity.

## Preserved readiness blocker

Phase1B-1 stopped before installation/implementation. The read-only recheck recorded six Windows availability samples of5.588–5.900GiB, all below the required12GiB. WSL availability draws from the same physical RAM. Wazuh remains NO-GO; no SIEM acceptance is waived. The earlier PostgreSQL SIGSEGV followed shared-memory exhaustion during simultaneous suites; cause remains unproven. Supported sequential acceptance is distinct evidence and is not a native-engine fix.
