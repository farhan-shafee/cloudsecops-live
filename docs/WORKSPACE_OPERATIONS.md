# Local analyst workspace operations

Phase1A-3B extends the preserved login/notes setup below. Follow [reviewed-workflow operations](REVIEWED_WORKFLOW_OPERATIONS.md) for current reviewer capability, migration003, dedicated verifier provisioning, guarded closure and explicit reopening. Statements below about absent approval/verifier features describe historical Phase1A-3A only.

Phase 1A-3A serves synthetic, unauthenticated evidence and unreviewed cases on one machine. Notes are observations, not approval, verification, closure or incident response authority. Keep the browser, server, PostgreSQL and private configuration on that machine. Two accounts operated by one person simulate duties; they are not independent organizational authority.

## Install and prepare

Use Python 3.12 or 3.14, the hash-locked development setup in the README, and the existing project-isolated PostgreSQL launcher. From the repository root in PowerShell:

```powershell
.venv\Scripts\python.exe scripts/local_postgres.py start
.venv\Scripts\python.exe -m cloudsecops_live workspace roles-setup --maintenance-config .tools/private/local-postgres.json
.venv\Scripts\python.exe -m cloudsecops_live workspace init --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --tls-dir .tools/private/workspace-tls --port 8443
.venv\Scripts\python.exe -m cloudsecops_live workspace pipeline-add --maintenance-config .tools/private/local-postgres.json --kind collector --config .tools/private/collector.json
.venv\Scripts\python.exe -m cloudsecops_live workspace pipeline-add --maintenance-config .tools/private/local-postgres.json --kind worker --config .tools/private/worker.json
.venv\Scripts\python.exe -m cloudsecops_live db-ingest --checkpoint demo-1 fixtures/synthetic/inventory-burst.json.gz
.venv\Scripts\python.exe -m cloudsecops_live db-work --limit 64
.venv\Scripts\python.exe -m cloudsecops_live db-cases
.venv\Scripts\python.exe -m cloudsecops_live db-verify
```

On Linux use `.venv/bin/python`. `roles-setup` is the explicit cluster-administrator step: it creates stable non-login capability roles. `init` validates and applies the current forward migrations, generates a restricted gate credential and writes a private runtime file. It refuses an existing runtime file. Do not rerun initialization or pipeline provisioning to overwrite a configuration. Normal pipeline commands now use collector/worker private files, not the owner. For an existing compatible database, run role setup followed by `db-migrate --maintenance`, or let the first `init` migrate it. Never alter migrations001/002 or their stored checksums. If compatibility checks fail, preserve the database and investigate or use a separately named fresh lab database.

The maintenance DSN is used only by explicit offline maintenance/provisioning commands. It is absent from `workspace.json`. That file contains generated per-account restricted database credentials and must remain private. Do not print it, include it in bug reports or copy it into source control. Account creation and file replacement are separate local operations: if a private-file write fails after provisioning, stop and have the maintenance operator reconcile the account; do not edit role mappings or rebaseline integrity hashes.

## Provision accounts and access

```powershell
.venv\Scripts\python.exe -m cloudsecops_live workspace user-add --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --username analyst_one --role analyst
.venv\Scripts\python.exe -m cloudsecops_live workspace user-add --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --username reviewer_one --role reviewer
.venv\Scripts\python.exe -m cloudsecops_live workspace user-add --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --username auditor_one --role auditor
```

Each command asks twice through protected terminal input. Choose unique passwords of 12–128 characters; there are no defaults. Passwords are never command arguments. Provisioning refuses non-interactive insecure fallback. Password hashing is Argon2id with 64 MiB, three iterations, one lane, random 16-byte salt and 32-byte output. The implementation bounds concurrent hashes to two; the local measured median was about 112 ms on this host, not a portable latency guarantee.

Copy a `case_id` from `db-cases` into the following command. Grant each permitted account explicitly; repeat with its username as needed:

```powershell
.venv\Scripts\python.exe -m cloudsecops_live workspace grant-case --maintenance-config .tools/private/local-postgres.json --username analyst_one --case-id CASE_ID_FROM_DB_CASES
```

Users with no grants see an empty list. Guessing a case, revision, finding or record identifier does not grant access. A new merged case requires its own explicit grant. Reviewer and auditor accounts have no note-writing authority. The reviewer name reserves a future workflow; this phase implements no reviewer approval.

## TLS and serving

Initialization generates a self-signed ECDSA P-256 certificate with IP SAN `127.0.0.1`, valid for 30 days, and a private key with restrictive local permissions. It installs nothing into an operating-system or browser trust store. Certificate/key matching, validity, private-file permissions, exact loopback HTTPS origin and actual restricted database identities are checked before serving. Missing, expired, altered or unsafe configuration fails closed with sanitized error JSON and exit 2.

```powershell
.venv\Scripts\python.exe -m cloudsecops_live workspace serve --config .tools/private/workspace.json
```

Visit `https://127.0.0.1:8443/login`. A browser will warn about this self-signed certificate. Inspect its fingerprint privately against the generated certificate before granting a browser-local temporary exception if your browser permits it. Do not disable certificate checks globally, add a machine-wide CA, use `localhost`, expose the port or run behind a forwarding proxy. If the browser cannot make a scoped exception, use a dedicated browser profile with explicit trust of this exact local certificate or the verified smoke client below. Stop the server with Ctrl+C. Restart after adding/removing accounts because runtime account configuration is loaded at startup; disabling an account revokes its sessions immediately in PostgreSQL even in the running process.

To replace an expired certificate, stop the server, preserve the old private directory, generate a new pair using `workspace_tls.create_tls` in a new private directory, and update the private runtime certificate/key paths through the maintenance operator. Recheck trust for the new certificate. Automatic renewal and password reset are not implemented.

## Reproducible real HTTPS smoke

Stop any server on the configured port, then run:

```powershell
.venv\Scripts\python.exe scripts/workspace_smoke.py --config .tools/private/workspace.json --username analyst_one
```

Enter the same account password privately. The command starts a real loopback TLS server, trusts only the configured certificate explicitly, signs in, reads the assigned-case list and terminates its child process. Expected sanitized JSON reports `https`, `certificate_verified`, `login` and `authenticated_read` as true. No password, cookie, DSN or token appears in its receipt or process arguments. Required integration tests also exercise an assigned-case read through this real socket; in-process HTTP tests are separate evidence. Never use `verify=False` or `curl -k` as TLS acceptance evidence.

## Sessions and notes

Opaque sessions expire after 30 minutes on the server. Only SHA-256 token hashes persist. A stored hash is not accepted as a bearer token. Logout revokes the session; rotation replaces the cookie and revokes the old token. Both require one-use CSRF challenges. Secure, HttpOnly, SameSite=Strict host cookies and sensitive-response cache prevention are mandatory. Persistent database throttles survive process restart: five attempts per account per five minutes and 25 globally per minute, with finite table capacities. Throttling deliberately permits local denial of service; it does not make this a public login service.

The case page displays current and historical machine revisions, evidence references, timeline, rationale/T1580 caveats, benign explanations, uncertainty, visibility limits and permitted lineage. It displays at most 100 historical revision summaries and 50 recent notes, with truncation counts. Lists have bounded pagination. Evidence access returns only the exact authorized record variant and bounded source metadata, never a whole gzip archive, arbitrary path or URL.

Analysts submit plain text notes of at most 4,000 characters. A note must carry the current case revision, fingerprint and one-use action-bound CSRF challenge. The database locks the current case, checks its status and version, consumes the nonce, appends author-bound note and appends audit in one transaction. Stale forms return 409; invalid CSRF returns 403; inaccessible resources return the same 404. A failed audit insert rolls the note and nonce consumption back. Independent valid note forms may both append to the same current machine revision without overwriting one another. The same nonce commits once. Notes never change machine findings or original evidence.

```powershell
.venv\Scripts\python.exe -m cloudsecops_live workspace disable-user --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --username analyst_one
```

This disables the database account mapping and revokes sessions; it does not delete notes, authorship, grants or audit history. There is no application endpoint for role changes, account creation, trust promotion or verification.

## Recovery and boundaries

Follow the [recovery runbook](FAILURE_AND_RECOVERY.md) before restore. A fresh restore target must revoke `PUBLIC CONNECT` **before** loading a dump, remain inaccessible to runtime logins while owners/ACLs are absent, and run `workspace restore-security` using maintenance authority before validation or serving. The repair requires the stored structural and original full security fingerprints; it cannot accept arbitrary catalog changes. Cluster roles and their private credentials are not in an ordinary database dump. Same-cluster restore is tested; cross-host role/credential reconstruction is a separate untested prerequisite.

Historical NUL-containing compressed bytea evidence is preserved. Migration does not reparse it. Replay verification correctly rejects it under the current parser instead of rewriting evidence or reporting a clean result. New NUL sources remain permanently quarantined with no accepted batch or checkpoint movement.

No MFA, remote identity provider, distributed throttling outside PostgreSQL, hardware isolation, cross-host disaster recovery or host-administrator resistance is claimed. Full web-process/private all-account configuration compromise can impersonate configured accounts. The database administrator remains trusted. Local TLS and separate SQL identities reduce specific risks; they do not establish production SOC readiness. See the [permission model](architecture/ANALYST_WORKSPACE.md) and [threat model](architecture/THREAT_MODEL.md).
