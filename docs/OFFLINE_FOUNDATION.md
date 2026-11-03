# Phase 1A-1 offline foundation

This milestone implements a local Python package that reads explicitly synthetic gzip fixtures,
preserves evidence bytes, normalizes records and reports reproducible inventory-burst candidates.
The original parsing/detection code uses only the Python standard library. Phase 1A-2 adds the pinned
Psycopg driver for explicit `db-*` commands; see [persistence contracts](architecture/PERSISTENCE_CONTRACTS.md).
Development, build and checking tools are pinned in `requirements-dev.lock`.

The standalone import/detection commands make no network calls and authenticate no AWS source.
They do not collect CloudTrail, validate signed digests, provision infrastructure, persist cases, connect Wazuh,
provide an API/UI or perform response actions. A successful import demonstrates software behavior on
the supplied fixture. It does not establish that AWS activity occurred or that a compromise happened.

## Set up and run

Use Python 3.12, 3.13 or 3.14 from the repository root. CI is configured for Python 3.12 and 3.14 on
Linux and Windows; configured checks are distinct from an observed CI result. Installing the locked
tools may download packages. The import and detection commands themselves operate offline.

Windows PowerShell:

```powershell
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.venv\Scripts\python.exe -m cloudsecops_live import-synthetic fixtures/synthetic/inventory-burst.json.gz
.venv\Scripts\python.exe -m cloudsecops_live detect-synthetic fixtures/synthetic/inventory-burst.json.gz
```

Linux:

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m cloudsecops_live import-synthetic fixtures/synthetic/inventory-burst.json.gz
.venv/bin/python -m cloudsecops_live detect-synthetic fixtures/synthetic/inventory-burst.json.gz
```

Substitute an installed supported interpreter if necessary. The installed `cloudsecops-live` console
entry point accepts the same arguments as `python -m cloudsecops_live`.

`import-synthetic` emits raw-object metadata, normalized events, references, qualification reasons and
deduplication/conflict information. It omits findings. `detect-synthetic` emits candidate findings and
the shared evidence report. Both require one or more explicit local `.json.gz` files; directories,
symlinks and nonregular streams are rejected. Neither command offers a trust-promotion flag.

| Exit code | Meaning |
| --- | --- |
| `0` | Accepted synthetic input; zero findings is also a successful result. |
| `2` | Invalid, unsupported or over-limit input; no partial successful output. |
| `3` | Conflicting identity/content; a conflict report is emitted with no findings. |
| `64` | Invalid command-line usage. |
| `70` | Internal failure; the fixed error reports failure rather than a clean scan. |

Successful reports use JSON on stdout. Rejected-input and internal-error reports use fixed structured
JSON on stderr without echoing raw attacker-controlled values. Consumers must inspect the exit code
and conflict state, rather than interpreting an empty findings list as evidence of safety.

## Synthetic input and bounded parsing

The decompressed UTF-8 JSON must have exactly these three envelope keys:

```json
{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[]}
```

`Records` contains CloudTrail-shaped objects, with public placeholders such as `LABACCOUNT_A` and
`SYNTHETIC_KEY_A`. These deliberately differ from real account and credential formats. The complete
working example is [inventory-burst.json](../fixtures/synthetic/inventory-burst.json), with its
compressed [demo archive](../fixtures/synthetic/inventory-burst.json.gz). Do not replace placeholders
with private account, actor or credential data.

The parser rejects unsupported fixture versions, duplicate JSON keys, nonfinite numbers, invalid
Unicode/surrogates, malformed JSON, truncated/corrupt gzip and trailing data or additional gzip
members. Envelope fields cannot grant authority. Unknown record fields are accepted as untrusted
evidence and retained in the canonical record. A malformed record rejects the whole input.

| Limit | Per-file default and hard ceiling |
| --- | --- |
| Compressed bytes | 10 MiB (`10 * 1024 * 1024`) |
| Expanded bytes | 100 MiB (`100 * 1024 * 1024`) |
| Records | 10,000 |
| Nesting depth | 32; root object has depth 1 |
| Decoded string length | 4,096 characters, including object keys |
| JSON allocation nodes | 200,000, including object-key strings |
| Numeric token length | 128 characters |

The library accepts smaller positive integer `Limits` values, within these hard ceilings. Compressed
and expanded data and JSON structure are bounded before unrestricted expansion/tree allocation;
decoded strings and numeric values receive further validation. Decimal exponents have an additional
absolute bound of 308. The CLI also caps a batch at 16 files and cumulative totals of 10 MiB compressed,
100 MiB expanded and 10,000 records, including duplicate deliveries.

The public library entry points are `parse_file(path: Path, *, limits: Limits = Limits())` and
`parse_bytes(data: bytes, *, source_ref="fixture.json.gz", limits: Limits = Limits())`, returning an
immutable `ParsedLog`. `detect(logs: Sequence[ParsedLog])` returns a `DetectionReport` with
`to_dict()` and `has_conflicts`. Parser failures use `EvidenceError` with a fixed public `code`.
These interfaces do not retrieve remote objects or infer source authenticity from a caller's label.

## Evidence, versions and hash domains

The immutable parsed result keeps original archive bytes and exact expanded bytes separately.
Each record reference carries `source_ref`, its zero-based `record_index`, and archive/content hashes.
`parse_file` uses the file's basename for `source_ref`; it does not retain the full path or a globally
unique retrieval location. Different directories can contain the same basename. Use hashes and
record indices with the label, and retain your own local file mapping when location matters.

| Domain | Meaning |
| --- | --- |
| `archive_sha256` | SHA-256 of original compressed bytes, including gzip metadata. |
| `content_sha256` | SHA-256 of exact decompressed bytes before JSON parsing. |
| `record_sha256` | SHA-256 of the versioned canonical complete source record. |
| `finding_id` | SHA-256-derived identity binding the rule, versions, session, window and ordered evidence identities/content. |

These values answer different questions. Changing a gzip timestamp changes the archive hash while
leaving content unchanged. Whitespace or object-key ordering changes content bytes while potentially
preserving canonical record hashes. An unknown record-field value change participates in conflict
checking even when normalization does not expose that field. Hash equality establishes consistency
within its domain, never AWS authenticity. Reports also include `rule_definition_sha256` to identify
the declared rule definition; it is not a source-authentication receipt.

Schema `1.0`, parser `1.0.0`, canonicalization `1.0` and rule `AWS-LAB-001` version `1.0` are explicit.
Unsupported derivative versions reject rather than silently changing interpretation. Canonical JSON
sorts object keys, preserves array order and strings, emits deterministic UTF-8 JSON escaping, and
retains integer versus decimal types. Decimal parsing uses exact finite `Decimal` values without
binary-float conversion. Decimal output uses fixed notation, removes insignificant trailing zeros,
retains a decimal marker, and normalizes signed decimal zero to `0.0`; integer zero remains `0`.
Equivalent decimal spellings can share canonical bytes; exact source spelling remains available in
the expanded evidence. The exponent and token bounds prevent unbounded fixed-notation expansion.

Provenance is always synthetic and unauthenticated for accepted fixtures. The model permits
`synthetic`, `unverified`, `pending` and `conflicting` states, with no verified state or AWS
authenticator. Detected identity conflicts make the report `conflicting` and block all findings.
Input fields named `verified`, `provenance` or similar cannot promote source trust.

## Correlation and report interpretation

The unique event identity is `(source_kind, recipient account, region, event ID)`. Complete canonical
records with the same identity deduplicate; their references link the deliveries. Different canonical
content for the same identity conflicts and fails closed for the entire supplied batch.

The rule requires successful `ec2.amazonaws.com` / `DescribeInstances` management API events with
`eventCategory=Management`, `eventType=AwsApiCall`, Boolean `readOnly=true`, and a valid consistent
`AssumedRole` identity. Any presence of `errorCode` or `errorMessage`, including null or empty values,
prevents qualification. Null `responseElements` alone is permitted. Missing or inconsistent session
identity produces a bounded nonqualifying reason. Invalid field types can reject the input.

The credential-session key is `(recipientAccountId, awsRegion, sessionIssuer.arn,
userIdentity.accessKeyId, sessionContext.attributes.creationDate)`. Issuer and actor account, role,
principal ID, assumed-role ARN and issuance time must be consistent. Reusing a role/session display
name with a new credential key does not join sessions.

Three unique qualifying IDs in an inclusive 60-second event-time window qualify. The detector sorts
by time and identity, takes maximal qualifying windows, and transitively unions windows that share
evidence IDs. Disjoint components stay separate. A merged component can span more than 60 seconds;
its reported start/end are the earliest/latest component events, not a promise that every event fits
one 60-second window. Late arrivals can change the evidence component and therefore the finding ID.

Findings expose `finding_id`, rule ID/version/definition hash, all derivative versions,
`status=synthetic_candidate`, `source_kind`, `authenticated=false`, full `session`, `count`, window
start/end/explanation, ordered `evidence_event_ids`, evidence identities/record hashes, rationale,
ATT&CK T1580 mapping and limitations. The report includes delivery/unique/duplicate counts, event
qualification reasons, references and conflict details.

Input permutation preserves finding identities for unchanged evidence. It does not make entire
reports byte-identical after provenance changes: recompression changes archive hashes, moving a
record changes its source index, and renaming a file changes its source label. Findings do not depend
on gzip headers or delivery order; their evidence still refers to the actual supplied bytes.

The [literal expected demo](../fixtures/synthetic/inventory-burst.expected.json) was authored
independently of the detector. It specifies one candidate containing `demo-001`, `demo-002` and
`demo-003` at 0, 30 and 60 seconds. Adversarial tests use independently stated event sets and counts,
including negative cases, rather than generating expected answers from production helpers.
Git attributes preserve LF text bytes and treat gzip archives as binary. The fixture test checks the
retained archive hash and its exact expanded source, without assuming different Python/zlib versions
produce identical gzip headers when recompressing.

## Local verification and next exercise

Run these commands with the virtual environment's Python (`.venv\Scripts\python.exe` on Windows,
`.venv/bin/python` on Linux):

```text
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m pytest --cov=cloudsecops_live --cov-branch --cov-report=term-missing --cov-report=json
python scripts/check_coverage.py
python scripts/check_secrets.py
python -m build --no-isolation
```

The coverage script requires at least 90% actual branches in each of ingestion and detection, plus
90% package lines. Secret scanning includes tests/fixtures and performs no remote credential
verification. Dependency auditing is a separate advisory-network check; failures or unavailable
evidence fail its job. These are executable gates, not claims that a future CI run has passed.

Complete the [30-minute no-AI interview lab](labs/PHASE1A1_INTERVIEW_LAB.md) to practice explaining and
changing this slice. Running tests alone does not establish mastery, independent reproduction of a
live lab, or operational detection accuracy.
