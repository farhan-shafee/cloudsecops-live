# Secure Analyst Workspace Implementation Plan

> Use test-driven implementation and an independent whole-branch security review. The owner's Phase 1A-3A gates are the specification; this plan records routine implementation decisions.

**Goal:** Authenticated local browser access to assigned synthetic cases, immutable evidence/history and append-only analyst notes with atomic audit.

**Starting point:** Normal PR #3 merge `51643025451fdd3d23e0b5280dc529004e8d1ccd`, reviewed head `cdf2ad4a18dc5b823bc9cd5d802736b2a79995d4`, identical tree. Exact 50-file scope, eight successful PR jobs, resolved P2 and fresh no-findings review were reverified. Branch: `codex/phase1a3a-secure-analyst-workspace`.

## Fixed boundaries

- No AWS, Wazuh, public deployment, AI, approval, verification, closure or response implementation.
- Preserve migration 001 exactly and all original records, byte/hash/version/provenance contracts, NUL rejection, checkpoints, workers, outbox, revisions and recovery tests.
- FastAPI with escaped server-rendered HTML, no frontend framework. Explicit loopback HTTPS only, no trust-store changes.
- Existing original-module coverage gates remain; all seven new workspace authentication/session, HTTP, SQL authorization/provisioning, configuration, TLS and CLI modules target at least 85% actual branches without exclusions.

## Identity and permission design

Each application account has **two distinct restricted PostgreSQL LOGIN identities** with generated server-only credentials: authentication and data. `SESSION_USER` maps each identity to exactly one provisioned account. The authentication identity can obtain only its own password hash and manage only its own sessions; it cannot read case data. The data identity can execute assigned-case read functions; analyst data identities alone may execute the note function. Reviewer and auditor data identities are read-only. Neither identity owns schema objects, tables or functions, has direct table/sequence DML, or can administer roles. A separately restricted gate identity manages bounded pre-login challenges and persistent throttles only.

Stable non-login capability roles grant named function execution; a non-login, non-superuser workspace owner owns new security-definer functions/tables and receives only necessary legacy reads plus audit insertion/sequence use. A reserved verifier role gets no grants. Migration/maintenance/collector credentials never appear in web configuration. Cluster-role setup and account provisioning are explicit offline owner commands. Full compromise of the web process/private all-account configuration can impersonate configured accounts; per-account SQL identities limit a stolen individual database credential, not host compromise.

Functions derive identity from `SESSION_USER`, never request user IDs/role labels. Every data operation checks the raw opaque session token, enabled account, current role and current per-case grant. Only token hashes persist; functions hash raw tokens internally, and a stored hash cannot act as a bearer token. Raw archives are not downloaded: a permitted case/revision authorizes only its exact event/record-hash association. New merged cases require new explicit grants.

## Migration and restore

Migration 002 is forward-only. The engine validates an exact contiguous checksum prefix and the live previous catalog before applying DDL, preserving ledger row 1 and every legacy table. It appends a new row; it never replaces a stored fingerprint. The new fingerprint includes owners, ACL/default privileges and function signatures/security settings. Dynamic login attributes/memberships are validated separately. A structural fingerprint permits a narrowly scoped trusted restore-security step to reapply expected ownership/grants after `--no-owner --no-privileges` restoration, then require the original full fingerprint; altered structures remain rejected. No migration reparses or rewrites legacy NUL evidence.

## Browser/session design

- Argon2id: 64 MiB, three iterations, one lane, 32-byte result, random 16-byte salt; benchmark and bound concurrent hashing.
- Protected interactive `getpass` provisioning; no default passwords or password process arguments.
- Random 256-bit session material plus random account selector, fixed 30-minute server expiry, revocation/logout and explicit rotation invalidating the old token.
- Persistent pre-login challenge and bounded account/global attempt windows, generic login failures, bounded session/CSRF tables.
- One-use CSRF challenges tied to account/session/action/case/revision and server expiry. Note consumption, note insertion and audit commit together.
- Notes require current machine revision/fingerprint and current case status while holding its row lock. Different valid nonces may append concurrent notes without overwriting; nonce replay commits once; a machine revision change makes the old form stale.
- Strict HTTPS scheme/Host/Origin checks, Secure/HttpOnly/SameSite=Strict `__Host-` cookies, restrictive CSP and headers, no CORS/debug/docs endpoints, no sensitive caching or request/access logs.
- Bounded form bodies, strings, pagination and database processing. No caller-specified evidence paths, URLs, SQL, trust levels or workflow authority.

## Tasks and interfaces

### 1. Migrations, privileges and SQL workspace boundary

Files: `database.py`, `sql/002_workspace.sql`, `workspace_store.py`, `workspace_roles.py`.

- [x] Add fresh/upgrade/rollback/checksum/restore tests before implementation.
- [x] Implement explicit role setup, dynamic account mappings and least-privilege validation.
- [x] Preserve `_MIGRATION`/v1 checksum compatibility; support numbered forward migrations and exact live-prefix checks.
- [x] Implement bounded preauth/throttle, own-account session/CSRF functions, case/history/variant readers and atomic notes/audit.
- [x] Test actual analyst/auditor/auth/gate SQL denials, no owner membership, temp-schema shadowing and restore privilege reconstruction.

Python boundary: `WorkspaceStore(auth_db, data_db)` exposes `identity`, `password_hash`, `create_session`, `session`, `issue_csrf`, `revoke`, `rotate`, `list_cases`, `case`, `evidence`, `add_note`. Gate functions use `GateStore(gate_db).challenge/consume/throttle`. Only fixed SQL entry points are invoked with parameterized arguments.

### 2. Authentication, HTTP application and local HTTPS

Files: `workspace_auth.py`, `workspace_web.py`, templates, `workspace_config.py`, `workspace_cli.py`, `workspace_tls.py`, CLI dispatch.

- [x] Write wrong-password/session/fixation/revocation/CSRF/object access and escaping tests first.
- [x] Implement bounded Argon verification, trusted account configuration, opaque session selection and generic failures.
- [x] Implement login/logout/rotation, assigned cases/details/history/findings/exact evidence and analyst notes.
- [x] Generate local self-signed certificate with IP SAN; require explicit local TLS for serving; test missing/bad configuration failure.
- [x] Run real HTTPS smoke with a client trusting only the generated certificate, never `verify=False`.

### 3. Independent adversarial acceptance and CI

Files: new workspace unit/integration tests, HTTPS smoke script, existing CI extension and coverage reporter.

- [x] Preserve all existing tests and prove every named negative case with HTTP responses and actual database effects.
- [x] Fresh and populated-v1 upgrades preserve data; failed 002 rolls back; legacy NUL remains preserved and replay-incompatible.
- [x] Back up/restore populated identities, hashed sessions, grants, notes and audit; reapply/validate security and repeat direct SQL denial checks.
- [x] Run original and workspace suites, separate >=85% security branch gates, lint/types/scans/builds and real HTTPS smoke. Required tests cannot silently skip.

### 4. Review, documentation and delivery

- [x] Update README, architecture/threat model, roadmap, recovery and mastery materials, including the no-AI Phase 1A-3A interview lab.
- [x] Independent adversarial review; fix material findings and rerun affected/full checks.
- Publish feature branch and verify exact remote tree, open PR, inspect actual CI and fix failures. Leave PR unmerged and stop before Phase 1A-3B. Publication outcomes belong to the exact-head PR/check record and final delivery report; this committed plan records prepublication validation.
