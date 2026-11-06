# AWS4B offline signed CloudTrail verification plan

Starting protected main: `5394044239e6eecc199722e3a1040b4a8df858eb`, tree
`5cb28b36730296e44ebe256b3396fda2e4924d22`. User scope is the AWS4B request.

Goal: verify supplied CloudTrail-format signatures, chains and exact log membership
offline, without creating an AWS-origin authentication or workflow authority boundary.

Architecture: an isolated `aws_cloudtrail/signed` package consumes immutable public-key
material, an explicit scope/interval/head manifest and retained acquisition observations.
It uses existing bounded syntax defenses and pinned cryptography 50.0.2. Existing
synthetic, CLI 2.37.11, collection and AWS4A modules remain unchanged.

The documented custom-validation algorithm is appropriate for this explicitly
authorized offline milestone. The alternative of merely parsing CLI success text
cannot prove a signature; invoking the supported CLI online is outside authorization.
No new CLI command, collector, database path, network transport or migration is added.

## Constraints and review focus

- SHA-256 covers original uncompressed bytes; compressed custody hashes are separate.
- RSA PKCS#1 v1.5/SHA-256; exact LF signing string, including `null` for a root.
- Independent public DER SHA-256 pins, fingerprint identifiers, Region and validity
  periods; no invented fingerprint algorithm or key retrieval.
- Separate standard/backfill heads, previous links and supplied coverage. Backfill
  absence is an unproven supplied observation, never authenticated completeness.
- Signed members do not bind S3 VersionId. Check retained before/retrieval/after
  observations separately and explicitly describe their unproven provenance.
- Bounded bytes, JSON depth/strings/objects, keys, digests, members and total events.
- Reject duplicate/conflicting objects, gaps, restarts, wrong heads and unknown formats.
- Reparse complete logs; identical duplicate events do not inflate unique counts;
  conflicts in fields discarded by normalization still reject the bundle.
- Public reports omit all source identifiers, hashes, keys, payloads and timestamps.
- No caller claim or successful result can authorize findings, approval or closure.

## Tasks

1. [x] Independently verify local/remote protected main and existing boundaries;
   research official AWS spec and pinned CLI implementation. Baseline CLI tests102 passed.
2. [x] Author independent ephemeral-key fixtures and failing signature/membership/
   chain regressions. No private key serialization or real evidence in Git.
3. [x] Implement bounded contracts, digest parser, signature verification and bundle
   reconciliation; observe RED then GREEN. Preserve all existing source checksums.
4. [x] Add per-module85% branch gates without weakening prior gates; document exact
   supported formats, assumptions, live limitations and reproducible offline commands.
5. [x] Full local unit/adversarial, format/lint/types, secrets, dependency, build and
   structural Terraform checks; no retained-local PostgreSQL operations.
6. [x] Independent adversarial review; STOP on a material security finding.
7. [ ] Commit/push one branch and open one unmerged PR. Verify exact source tree,
   all ten hosted checks including native Terraform and disposable PostgreSQL, and
   fresh exact-head Codex review. STOP on a material finding; do not merge.

## Execution ledger

Implementation choices: use the explicitly requested branch in the existing clean
checkout; no additional worktree or unrelated Git configuration changes. Existing
cryptography pin suffices. Native Terraform and full database acceptance run in the
existing disposable hosted service because retained local PostgreSQL remains NO-GO.
AWS docs and official source were read as public documentation only; no AWS API called.

Local completion:3,157 passed in251.91seconds; focused156 passed. Independent review
found no material findings. A conservative supplied-backfill coverage restriction is
documented explicitly. The Python3.14 dataclasses.replace exception-type change is
accepted by the trust-forgery test on both supported runtimes; denial remains mandatory.
The first wheel inventory probe accidentally selected a preserved0.1.0 build; the
explicit current0.6.0 artifact was then checked successfully without deleting history.
