# Reviewed synthetic exercise operations

This runbook is Phase1A-3B only. It operates on synthetic records in the existing isolated local PostgreSQL service. It authorizes no cloud collection, containment, remediation, Wazuh, deployment or paid service. Read the [workflow/permission design](architecture/REVIEWED_WORKFLOW.md), [workspace setup](WORKSPACE_OPERATIONS.md) and [protected recovery procedure](FAILURE_AND_RECOVERY.md).

## Prepare and upgrade

Use the README's hash-locked Python3.12/3.14 setup and install this checkout. Preserve existing private files/databases. A compatible v2 database upgrades forward to003; migrations001/002, old ledger rows and v2 UUID remain unchanged. No reset/downgrade/rebaseline is a repair strategy. Historical NUL bytea remains preserved and accurately replay-incompatible.

From the repository root in PowerShell:

```powershell
$python = '.venv\Scripts\python.exe'
& $python scripts/local_postgres.py start
& $python -m cloudsecops_live workspace roles-setup --maintenance-config .tools/private/local-postgres.json
& $python -m cloudsecops_live db-migrate --maintenance
& $python -m cloudsecops_live workspace pipeline-add --maintenance-config .tools/private/local-postgres.json --kind collector --config .tools/private/collector.json
& $python -m cloudsecops_live workspace pipeline-add --maintenance-config .tools/private/local-postgres.json --kind worker --config .tools/private/worker.json
& $python -m cloudsecops_live db-ingest --checkpoint demo-1 fixtures/synthetic/inventory-burst.json.gz
& $python -m cloudsecops_live db-work --limit 64
& $python -m cloudsecops_live db-verify
& $python -m cloudsecops_live db-cases
```

Use `.venv/bin/python` on Linux. The expected initial fixture is one synthetic candidate over three unique qualifying calls at0/30/60seconds. A successful checksum/store check does not authenticate AWS. Stop if migration/schema validation or legacy replay is incompatible; preserve the source database and private backup. Test a separately named fresh database instead of altering old receipts or evidence.

Provision collector/worker files only once. Ordinary commands use these restricted identities, not the owner: ingestion defaults to `collector.json`, other pipeline commands to `worker.json`. A custom `--config` must contain the expected actual SQL identity. An explicit `--maintenance` selects the trusted operator path; use it only for deliberate maintenance and never pass it to a web or verifier process. Runtime catalog checks reject owner credentials, extra grants, unexpected role membership and disabled identities. Collector and worker cannot read authentication records or human audit payloads, create review/verification/closure rows, assume owner/verifier authority, or change immutable originals. The worker alone can publish machine revisions and drive the local test sink.

For a new workspace configuration, initialize local TLS and then provision distinct accounts:

```powershell
& $python -m cloudsecops_live workspace init --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --tls-dir .tools/private/workspace-tls --port 8443
& $python -m cloudsecops_live workspace user-add --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --username analyst_one --role analyst
& $python -m cloudsecops_live workspace user-add --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --username reviewer_one --role reviewer
& $python -m cloudsecops_live workspace user-add --maintenance-config .tools/private/local-postgres.json --config .tools/private/workspace.json --username auditor_one --role auditor
```

Skip initialization/account creation when the private configuration/accounts already exist; these commands intentionally refuse overwrite. Passwords are prompted privately with no defaults or password arguments. The existing accounts' restricted reviewer capability is added by the forward migration. Start/restart serving only after the configuration and all mapped identities validate.

Select a case ID deliberately from `db-cases`. The commands below prompt for the selected ID without placing credentials on a command line:

```powershell
$caseId = Read-Host 'Synthetic case ID from db-cases'
& $python -m cloudsecops_live workspace grant-case --maintenance-config .tools/private/local-postgres.json --username analyst_one --case-id $caseId
& $python -m cloudsecops_live workspace grant-case --maintenance-config .tools/private/local-postgres.json --username reviewer_one --case-id $caseId
& $python -m cloudsecops_live workspace grant-case --maintenance-config .tools/private/local-postgres.json --username auditor_one --case-id $caseId
& $python -m cloudsecops_live workspace verifier-add --maintenance-config .tools/private/local-postgres.json --case-id $caseId --config .tools/private/verifier.json
```

`verifier-add` is an explicit maintenance operation. It creates a dedicated NOSUPERUSER case-scoped LOGIN with generated private credentials and pins the installed checker source digest. Its output is a sanitized completion receipt; the DSN goes only into the private verifier file. The web runtime config never includes it. One scoped verifier may inspect the complete bounded synthetic generation necessary to independently test this case; it cannot browse unrelated recommendation IDs or arbitrary archive IDs. Protect its file like a credential.

## Browser workflow

```powershell
& $python -m cloudsecops_live workspace serve --config .tools/private/workspace.json
```

The server binds strictly to `https://127.0.0.1:8443`. Initialization installs no system certificate. Inspect and trust only the generated leaf certificate through a scoped browser exception/profile or the explicit-CA smoke client; never disable certificate checks globally or change machine-wide trust. Missing/expired TLS, unsafe private files, wrong origin/SQL identities or catalog drift fail closed. See the workspace TLS runbook for certificate replacement.

1. Sign in as the assigned analyst. Open the machine case, then its human-workflow link. Inspect exact evidence, timeline, rationale and visibility gaps. Submit a no-action recommendation with authored rationale/counterevidence/gaps. The server fixes action, empty targets, synthetic classification and all evidence/version bindings.
2. Use a separate browser profile/session as the assigned reviewer. Open the reviewer queue and inspect the complete bound recommendation and evidence. Approve or reject with a reason. Rejection is terminal for that version. Self-review, wrong role, missing assignment, stale version or expired recommendation must fail.
3. Run the separate verifier command below using only the private verifier configuration and exact recommendation reference shown in the workflow page. There is no browser verification-submit route and no caller verified flag.
4. Refresh as the same approving reviewer. Close only when the latest matching receipt is verified and all current-generation, conflict, expiry, identity, source and version checks pass. A closure records a synthetic exercise result, not containment or absence of compromise.

```powershell
$recommendationId = Read-Host 'Recommendation ID from workflow'
$recommendationVersion = Read-Host 'Immutable recommendation version'
& $python -m cloudsecops_live verifier --config .tools/private/verifier.json --recommendation-id $recommendationId --version $recommendationVersion
```

The checker reports `verified`, `contradicted` or `inconclusive` within `offline_synthetic_only`, always `authenticated=false`. Exit0 means a verified local consistency receipt, exit1 means a retained negative receipt, and exit2 is sanitized configuration/usage/database/reference failure. None means AWS authenticity. Retrying the same current reference recovers its committed receipt; `--run-id` accepts an explicit32-hex run reference for a deliberately separate check/idempotent retry, not a verdict or authority label.

Recommendations expire in30minutes. Receipts last at most10minutes, bounded by the recommendation. The original author must remain an enabled assigned analyst, the reviewer must remain enabled/assigned, and verifier grant/checker pins must remain current. Logging out does not rewrite historical decisions; every new mutation still requires its own live authenticated session and action-bound one-use CSRF. Disabling a participant or revoking an assignment blocks dependent current authority.

Every newly committed source batch invalidates human authority, including added duplicate provenance. After publication, a changed previously closed exercise requires an explicit assigned-reviewer reopen with a reason, then new recommendation/review/verification. Unchanged closed exercises cannot reopen. A merged successor needs fresh assignments and scoped verifier provisioning; parent grants/closures are not inherited.

## Real HTTPS operational demonstration

Stop any server using the configured port. The script starts its own loopback TLS process, uses two separate cookie jars and protected password prompts, invokes the verifier in a separate process and stops its children afterward:

```powershell
& $python scripts/reviewed_workflow_smoke.py --workspace-config .tools/private/workspace.json --verifier-config .tools/private/verifier.json --analyst analyst_one --reviewer reviewer_one --case-id $caseId
```

Expected sanitized receipt: HTTPS and certificate verification true, recommendation/distinct_review/independent_verifier/synthetic_exercise_closed true, exact case/recommendation/review/verification/closure IDs, `source_kind=synthetic`, `authenticated=false`, `final_state=closed`, and no secrets. The browser server receives no maintenance or verifier credential. The verifier receives no analyst/reviewer password. Passwords/cookies/DSNs are absent from child argv, logs and public receipts.

For a deliberate evidence-change exercise, start with an assigned **open** synthetic case and explicitly allow the offline demonstration driver to use maintenance authority:

```powershell
& $python scripts/reviewed_workflow_smoke.py --workspace-config .tools/private/workspace.json --verifier-config .tools/private/verifier.json --analyst analyst_one --reviewer reviewer_one --case-id $caseId --demonstrate-change --maintenance-config .tools/private/local-postgres.json
```

This adds controlled synthetic records only: it copies an existing bound complete record, assigns a new synthetic event ID and retains the component's median event time, preserves the original and processes the resulting new generation. First it changes evidence after verification, proves the old close form gets409, and creates/reviews/verifies a fresh version before closing. A second late delivery makes that closure historical and requires a reasoned explicit reopen. Expected extra flags: changed_evidence_blocked_closure, closed_history_preserved and audited_reopen true; final_state is **open**. `synthetic_exercise_closed=true` then reports the demonstrated historical closure, not a currently closed exercise. Inspect all transition/audit records and the new machine revisions. The driver's maintenance credential is never passed to the web/verifier process.

The positive script intentionally refuses to silently reopen an already closed case. Use the explicit material-change/reopen workflow or a separately named fresh synthetic lab. Do not delete evidence, reset the database or directly change workflow state to make a repeated demo run.

## Disable and recover

```powershell
$verifierId = Read-Host 'Verifier ID from private provisioning custody'
& $python -m cloudsecops_live workspace verifier-disable --maintenance-config .tools/private/local-postgres.json --verifier-id $verifierId
```

Disabled verifier mappings cannot begin/read/finish or support new closure, even on an existing connection. Human disabling uses the existing protected `workspace disable-user` procedure. Never print private config to obtain a public report; record only selected nonsecret identifiers through private operator custody.

Backup all41tables plus separately protected cluster role/configuration/TLS material. The [restore procedure](FAILURE_AND_RECOVERY.md#workspace-backup-and-protected-restore) must quarantine human, collector, worker and verifier CONNECT before no-owner/no-ACL restore. Run explicit restore-security, require the original v3 fingerprint, compare every logical row/original and prove restricted SQL denials before serving. Same-cluster restore is tested; cross-host credential/role recovery, power loss and administrator compromise remain outside demonstrated guarantees.
