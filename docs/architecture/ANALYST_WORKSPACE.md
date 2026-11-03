# Local analyst workspace

Phase 1A-3B extends these preserved authentication/evidence boundaries with [reviewed synthetic workflows](REVIEWED_WORKFLOW.md). Reviewer accounts now receive narrowly scoped review/close/reopen function authority; the reserved verifier capability is activated only for explicitly provisioned separate case-scoped service logins. The original Phase 1A-3A behavior below is historical where marked read-only/reserved. Web identities still cannot read archive bytes or write machine receipts.

Phase 1A-3A adds authenticated browser access to assigned synthetic cases. It reads machine findings, case revisions and exact evidence records, and lets an analyst append investigation notes. Evidence remains synthetic and unauthenticated. The auditor remains read-only. Phase1A-3B gives the reviewer only the bound synthetic no-action decisions described in REVIEWED_WORKFLOW.md, with no machine-verification or cloud-response authority. There is no AWS, Wazuh, AI or public deployment integration in this workspace.

The implementation uses FastAPI, escaped server-rendered HTML, PostgreSQL security-definer functions and explicit loopback HTTPS. The configured origin is one exact `https://127.0.0.1:<port>` address. A local certificate with the matching IP SAN is required; the application does not install a system trust root. Scheme, Host and mutation Origin checks run before route handling. Cookies use the `__Host-` prefix, Secure, HttpOnly, SameSite=Strict and Path=/, without a Domain attribute. Responses prohibit caching and apply a restrictive content security policy. Request/access logging and interactive API documentation are disabled.

## Identity and credentials

Offline maintenance commands explicitly set up cluster roles, create the gate identity and provision each application account. Provisioning prompts for the application password with `getpass`; no application password or generated PostgreSQL password is a process argument. Argon2id uses 64 MiB, three iterations, one lane, a 32-byte output and a random 16-byte salt. Application passwords are 12–128 characters and must satisfy the implemented whitespace, NUL and Unicode checks. At most two password hashing or verification operations run concurrently; acquiring that capacity is bounded to one second.

Each account has two distinct PostgreSQL LOGIN roles with separately generated server-side credentials:

- The **authentication identity** reads only its own password hash and manages only its own sessions and CSRF challenges through named functions.
- The **data identity** reads only its assigned cases and exact associated evidence. An analyst data identity can additionally execute the append-note function.

`SESSION_USER` binds each SQL identity to one account row. SQL functions do not accept an account ID, author ID or role label as authority. Startup checks distinguish the authentication and data mappings, require the two identities to refer to the same enabled account, and compare the database identity with the private configuration. Role names combine a hash of the persisted database UUID with a random account ID; names remain below PostgreSQL's identifier limit.

The gate and per-account DSNs, TLS private key and account-selector mapping reside in OS-restricted private files. Maintenance, migration and collector credentials are absent from web configuration. Password-bearing role DDL disables statement logging and error-statement logging within its provisioning transaction, and public errors use fixed codes. PostgreSQL LOGIN roles are NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION and NOBYPASSRLS; they have only their expected capability memberships without ADMIN option.

A stolen individual SQL credential is limited by that account's SQL boundary. A compromised host or web process with the complete private account configuration can impersonate configured accounts. Separate identities on one machine do not establish independent institutional control.

## Permission matrix

Stable capability roles are NONLOGIN. Runtime identities receive database CONNECT, `csl` schema USAGE and allowlisted function execution through those roles. They receive no direct table or sequence privileges, including column-level privileges, and own no database, schema, table or function.

| Identity or role | Assigned capability | Permitted workspace operations |
| --- | --- | --- |
| Gate LOGIN | `csl_ws_gate` | Create and consume pre-login challenges, update persistent attempt buckets, read the nonsecret schema receipt. No password hashes or case data. |
| Account authentication LOGIN | `csl_ws_auth` | Read its own enabled identity and password hash; create, revoke and rotate its own sessions; issue its own session-bound CSRF challenges; read the schema receipt. No case or evidence reads. |
| Analyst data LOGIN | `csl_ws_reader`, `csl_ws_notes` | Validate its own session; read assigned cases, history, notes and exact evidence; append an attributed note with valid session, assignment, revision, fingerprint and one-use CSRF. |
| Reviewer data LOGIN | `csl_ws_reader`, `csl_ws_reviews` after003 | Assigned reads and distinct bound review/guarded closure/permitted reopen. No note or machine-receipt grant. |
| Auditor data LOGIN | `csl_ws_reader` | The same read-only SQL authority as reviewer. No note function grant. |
| `csl_ws_owner` | NONLOGIN object owner, no runtime membership | Own new workspace tables and functions. Read the required legacy case/evidence/source metadata and ledger; insert audit rows and use the audit sequence. A column UPDATE grant on `cases.current_revision` permits `FOR UPDATE` locking; workspace functions do not update that column. No grant to read original archive bytes. |
| `csl_ws_verifier` | NONLOGIN capability activated by003 | Only dedicated scoped service logins may begin requests, fetch pinned originals and append consistency receipts. No human membership. |
| Offline maintenance identity | Outside runtime configuration | Explicit role setup, migrations, account provisioning, case assignment, account disabling and trusted restore-security repair. Its administrative authority can bypass application controls. |

Security-definer functions belong to `csl_ws_owner` and pin `search_path` to `pg_catalog,csl,pg_temp`. Relation references are qualified. PUBLIC execution on existing functions is explicitly revoked, and internal helpers are not runtime entry points. The owner's global function default privileges remove PUBLIC execution for future functions; a schema-local revoke alone cannot subtract PostgreSQL's global default. Functions created by maintenance are explicitly restricted before runtime access. Runtime identities cannot assume owner or verifier roles. Temporary objects cannot replace the qualified workspace objects.

Every data function rechecks the enabled account, raw session bearer and current case grant. The note function also rechecks the current application role. A grant on a parent case does not grant its merged successor. Lineage links appear only when both related cases are explicitly assigned. Evidence reads require the exact `(case_id, revision, event_key, record_hash)` association; knowing a record hash or source reference grants no access. There is no arbitrary evidence path, URL or full-archive download endpoint.

## Sessions, CSRF and notes

Session tokens contain a random account selector followed by 256 bits of random session material. The selector chooses a configured connection; it is not proof of identity. PostgreSQL hashes raw bearers internally with SHA-256 and stores only their hashes. Supplying a stored hash does not authenticate. Sessions have a fixed 30-minute database-clock expiry, support explicit revocation, and do not extend on reads. Rotation invalidates the previous bearer and creates a new session atomically. Disabling an account makes existing sessions unusable.

Pre-login challenges pair a random nonce with a CSRF value; both persist only as hashes and expire after five minutes. Account sessions use one-use CSRF values tied to the account, session, action and, for notes, case and revision. They expire after ten minutes. Logout, rotation and note nonces cannot substitute for one another.

A note transaction locks the current case row and requires its current revision, fingerprint and `current` status. It derives the author from the data LOGIN, consumes the matching CSRF challenge, inserts the note and inserts its audit record in one transaction. An audit failure rolls all of those effects back. Different valid nonces can append concurrent notes; replaying one nonce commits at most once. A changed machine revision makes an old form stale. Notes do not edit original evidence, machine revisions or the legacy case timeline.

## Bounds and visibility

These limits are selected by the server, rather than supplied as authority by the browser:

| Resource | Bound |
| --- | --- |
| Application accounts | 100 |
| Username | Lowercase ASCII letter followed by letters, digits or underscores; at most 32 characters |
| Sessions | Eight retained active sessions per account; expired or revoked sessions are removed during creation |
| CSRF records | 128 per session after used/expired cleanup; ten-minute expiry |
| Pre-login challenges | 1,000 retained challenges; five-minute expiry |
| Attempt buckets | 1,000; five attempts per username per five minutes and 25 global attempts per minute |
| Browser form body | 16 KiB, at most 64 body chunks |
| Case list | Default 20, maximum 50 rows; offset 0–10,000; SQL rejects NULL bounds |
| Case history response | Latest 100 revisions, containing revision/status/fingerprint/time metadata; total count and truncation flag accompany the list |
| Notes | 4,000 characters per note; 1,000 per case; response shows latest 50 with total count and truncation flag |
| Evidence sources | At most 50 deterministic exact-record source references, with total source count |

Case lists omit full finding payloads. A case detail returns the selected revision payload separately from its bounded history. Evidence inspection returns the canonical record, normalized fields and source metadata: raw ID, compressed archive hash, expanded content hash, source reference and record index. The owner has only the named raw-object metadata column grants needed for that projection, not `archive_bytes`. Existing ingestion limits continue to bound originals, events, batches and generations; see [persistence contracts](PERSISTENCE_CONTRACTS.md).

## Migration, startup validation and restore

Migration 001 remains unchanged. Migration 002 verifies the exact contiguous checksum prefix and the live prior catalog before applying forward-only DDL. It preserves the original ledger row and legacy records and appends a new receipt. Migration does not reparse original evidence, including legacy NUL-containing evidence.

The version-1 catalog algorithm remains unchanged. The version-2 full fingerprint additionally covers owners, relation and column ACLs, function signatures/security settings, schema-local default privileges and the workspace owner's global function defaults, the current database owner/ACL, and `csl` and `public` schema ownership/ACLs. The database entry uses a constant label rather than its name so a differently named restore target can match. Dynamic LOGIN attributes and memberships are checked separately. Startup rejects a runtime LOGIN that owns the database, has database CREATE, can create in `csl` or `public`, owns workspace objects, has direct table/column/sequence privileges, or has unexpected or administrative memberships. These checks detect administrative privilege drift; they do not prevent a database administrator from changing permissions.

A no-owner/no-privileges restore must remain quarantined from runtime connections until security repair finishes:

1. Create a fresh, explicitly named restore database using the offline maintenance identity. **Immediately revoke CONNECT from PUBLIC before restoring any workspace objects.** Do not grant CONNECT to runtime identities or capability roles yet. Keep the web process stopped.
2. Restore the private dump with `--no-owner --no-privileges`. A restored security-definer helper may temporarily have default PUBLIC execution; connection quarantine prevents runtime identities from reaching it during this interval.
3. Ensure the required cluster roles and mapped LOGIN identities exist. A database dump does not recreate cluster roles or recover the separately protected runtime configuration. Same-cluster tests retain those identities; cross-cluster recovery must restore their private role/configuration material through an explicit offline procedure.
4. Run the trusted restore-security helper. It first requires the original checksums and structural fingerprint, reapplies the fixed ownership/grants and capability CONNECT permissions, then requires the **original full fingerprint**. It does not replace the receipt or adopt altered structure. The recorded maintenance ownership must also match.
5. Run complete store verification and startup identity validation before serving. Prove a runtime connection fails before repair, then prove assigned reads work and direct reads/writes and escalation remain denied afterward.

Routine migration/security setup revokes database CONNECT from PUBLIC and grants it to the stable authentication, reader, notes and gate capabilities. The maintenance database owner retains its implicit access. Protect dumps, private configuration and cluster-role recovery material as credentials; do not publish them with test receipts.

The local database or host administrator can alter data, bypass triggers and change receipts. Append-only application permissions and transactionally coupled audit provide routine-write controls, not forensic immutability or proof that an old backup contains every later action. Account ownership, OS security and recovery custody remain operator responsibilities. See the [threat model](THREAT_MODEL.md) and [recovery runbook](../FAILURE_AND_RECOVERY.md).
