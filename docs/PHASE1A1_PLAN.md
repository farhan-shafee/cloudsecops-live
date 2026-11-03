# Phase 1A-1 offline foundation plan

> **For agentic workers:** Execute the approved offline scope with test-first development and independent review. This plan records implementation decisions; it does not authorize later milestones.

**Goal:** Synthetic CloudTrail gzip bytes → bounded parsing → immutable provenance references → normalized events → reproducible inventory-burst candidate findings.

**Architecture:** One standard-library-only Python package. Pure parser/detector interfaces and a local CLI; no network integrations or persistence service.

**Tech stack:** Python >=3.12,<3.15; pinned development/build/check tools and a hash-locked development requirements file. Local Python 3.14 is available; Linux/Windows CI exercises 3.12 and 3.14.

**Spec:** [Phase 0 system design](architecture/SYSTEM_DESIGN.md) and the owner's Phase 1A-1 request. The owner explicitly authorizes offline implementation, original-code MIT licensing and conditional Phase 0 merge only.

## Constraints

- No AWS access, credential configuration, provisioning, Wazuh installation, deployment, paid services or modifications to other repositories.
- No PostgreSQL, FastAPI, UI, live source authentication or signed-digest validator in this subphase.
- Original implementation; no upstream code copied. MIT license for original project code.
- Never expose raw input values in parser errors. Fixture/caller fields cannot elevate source trust.
- Preserve compressed and exact decompressed hashes separately. Normalized/canonical hashes are additional, distinct domains.
- Explicit versions are bound into source records and outputs. Unsupported versions require rejection, not silent reinterpretation.

## Review focus

- Reject oversized gzip/JSON and structure before unbounded decompression/tree allocation; bound nodes, numeric tokens, nesting, strings and records.
- Detect changes to unknown source fields before normalization; duplicate delivery must not inflate counts.
- Reject role/session inconsistencies and distinguish credentials sharing the same role/session name.
- Canonical numeric handling must not silently collapse distinct source values through binary float rounding.
- Input permutation preserves findings, while genuinely changed archive/content bytes correctly change their provenance hashes.

## Interfaces and ownership

Root owns `contracts.py`, `errors.py`, `ingestion.py`, `cli.py`, package entry points and demo documentation. A detector implementer owns `detection.py` and detector unit tests. An independent test author owns adversarial integration tests and test fixtures. A tooling implementer owns pyproject/lock/CI/license/gitignore/check scripts. File ownership prevents concurrent edits.

Shared contracts are immutable dataclasses. `EventIdentity(source_kind, account, region, event_id)` is ordered. `SessionIdentity(account, region, issuer_arn, access_key_id, creation_time)` follows Phase 0's exact credential-session key. `RecordReference(source_ref, record_index, archive_sha256, content_sha256)` retains every delivery. `NormalizedEvent` exposes identity, event_time, event_source, event_name, event_category, event_type, read_only, has_error, session, identity_reason, canonical_record, record_sha256, references and version fields. `ParsedLog` contains immutable raw archive/content evidence and events. Source kind is always `synthetic`; provenance states are synthetic/unverified/pending/conflicting, with no verified state or AWS authenticator.

`parse_file(path: Path, *, limits: Limits = Limits()) -> ParsedLog` and `parse_bytes(data: bytes, *, source_ref: str = "fixture.json.gz", limits: Limits = Limits()) -> ParsedLog` never perform network operations. Limits default to 10 MiB compressed, 100 MiB expanded, 10,000 records, depth 32, decoded string 4096 characters, 200,000 nodes and numeric token length 128. Tests use smaller limits for exact boundaries. Gzip integrity/trailing data are validated; JSON must be a strict explicit synthetic envelope: `{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[...]}`. Synthetic accounts use `LABACCOUNT_A`-style placeholders, not real account numbers; keys use `SYNTHETIC_KEY_A`-style labels. This intentionally differs from an authentic AWS identity schema.

`detect(logs: Sequence[ParsedLog]) -> DetectionReport` deduplicates by full identity, compares versioned complete canonical source records, and fails closed for the whole batch on conflicting identities. Identical deliveries merge references. It emits findings only as synthetic candidates; exact evidence IDs, count, key, rule version, window and limitations are mandatory. Nonqualifying reasons use bounded enums. Finding IDs depend on stable record identity/content and rule/session/window, never input order or file gzip headers.

Canonical source JSON v1 sorts object keys, preserves array order and strings, uses distinct integer/decimal types and exact finite Decimal values (no binary-float conversion), and emits UTF-8 with deterministic escaping. Duplicate keys, surrogate code points, nonfinite numbers and unsupported values reject. Unknown record fields remain part of the canonical bytes/hash. Canonical/schema/parser versions are recorded together.

Rule `AWS-LAB-001` v1.0: exactly the Phase 0 qualification conditions; at least three unique qualifying IDs in inclusive 60-second event-time windows per full session key. Use all maximal qualifying windows; union only windows sharing evidence IDs, transitively. Disjoint components remain separate even when a group's total span exceeds 60 seconds. Finding window records min/max event time in the merged component, with an explanation that a component may span longer than one qualifying window.

## Tasks and gates

- [x] Verify exact PR #1 head/scope/clean mergeability, merge with expected-head protection, verify identical merged tree, create requested branch.
- [x] Write contract/parser tests; run them failing; implement immutable schemas, bounded parser and provenance. Run targeted tests, then full suite.
- [x] Detector implementer writes failing independent-literal unit tests, implements pure rule and overlap/dedup logic, then runs tests. Independent test author adds adversarial parser/detector/CLI coverage without deriving expected results from production helpers.
- [x] Tooling task pins reviewed dependencies/Actions, locks transitive dependencies with hashes, configures strict checks and Linux/Windows CI, adds MIT license and secret/dependency checks without application/cloud credentials.
- [x] CLI tests first, then explicit import/detect commands, deterministic JSON and fixed structured errors/exit codes. No trust-promotion flag or raw-value error echo.
- [x] Run formatter/linter/types/full tests with line+branch coverage (>=90% branch in ingestion/detection), build and install/test wheel, dependency and secret checks. Fix material review/CI defects without weakening assertions.
- [x] Update README/roadmap/mastery, add practical no-AI lab and exact demo commands. Record actual results separately from proposed later work.
- [ ] Independent whole-change adversarial review, commit/publish branch, open PR against main, inspect actual CI and fix failures. Leave Phase 1A-1 PR unmerged.

## Delivery ledger

Phase 0 merged at `25b7aad40b218a8de96014b9c3fe9bd628a53bd1`, with reviewed tree `929a9a9a76a04365e297acc869f40b4856422984`. No check runs/statuses existed at merge; none were asserted passing. Offline feature branch: `codex/phase1a1-offline-evidence-detection`.

Ruling: work in the clean existing checkout on the explicitly requested dedicated branch; no additional worktree is necessary. The approved spec is sufficiently detailed to proceed without another design-approval round.

Local implementation record: parser baseline tests failed on missing implementation; independent detector/adversarial suites failed on stubs; CLI tests failed before implementation. Review reproduced early-allocation and timestamp defects, plus compressed secret-scan bypass. Regression tests failed first, fixes then passed; both reviewers cleared their scoped corrections. Exhaustive independent comparison of 3,432 short timestamp vectors found no detector window/overlap error. Local Windows Python 3.14 validation: 194 tests, ingestion branches 90.96%, detection branches 100%, package lines 96.44%, combined 95.19%, no exclusions. Build and isolated wheel demo passed. Hosted CI results remain separately recorded by the PR/checks rather than inferred from this ledger.
