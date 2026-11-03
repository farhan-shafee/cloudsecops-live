# Phase 1A-1 interview lab: 30 minutes without AI

Use a local checkout with the [offline setup](../OFFLINE_FOUNDATION.md#set-up-and-run) completed.
Work without AI assistance. Python documentation, source files, tests and handwritten notes are
allowed. This exercise uses synthetic files only; it needs no AWS account, credentials or network
access after setup. Completing this page is practice, not an earned mastery claim.

## Minutes 0–5: predict before running

Read `fixtures/synthetic/inventory-burst.json` and its independently written
`inventory-burst.expected.json`. Write down the exact expected event IDs, candidate count and window
endpoints. Explain why events at 0, 30 and 60 seconds qualify, and why changing 60 to 61 would remove
that three-event window. State why null `responseElements` does not imply failure here.

Run the demo with the virtual environment's Python:

```text
python -m cloudsecops_live import-synthetic fixtures/synthetic/inventory-burst.json.gz
python -m cloudsecops_live detect-synthetic fixtures/synthetic/inventory-burst.json.gz
```

On Windows, use `.venv\Scripts\python.exe`; on Linux, use `.venv/bin/python`. Compare the output with
your prediction. Identify the fields that say the source is synthetic and unauthenticated.

## Minutes 5–12: explain the evidence

Explain these points aloud, using the actual report as evidence:

1. Give all five session-key fields. Explain how the same role/session name can acquire a new key,
   and why matching only the display name would mix credentials.
2. Distinguish the compressed archive hash, exact expanded-content hash, canonical record hash and
   finding ID. Predict which change when gzip metadata changes, JSON whitespace changes, an unknown
   record field changes, or the input order changes.
3. Locate the source basename and zero-based record index. Explain why a basename alone cannot
   identify a unique retrieval location and why a hash does not authenticate an AWS source.
4. Explain duplicate versus conflicting delivery. State why a conflict suppresses all findings in the
   supplied batch, and why an empty findings list is insufficient without the exit/conflict status.
5. Explain how overlapping windows can yield a component longer than 60 seconds while disjoint
   components remain separate. Describe the effect of a late qualifying event on the finding ID.

## Minutes 12–20: troubleshoot an injected mistake

Create a scratch archive from the checked-in JSON using Python's `json`, `gzip` and `pathlib` modules.
Preserve the strict synthetic envelope and use `gzip.compress(raw_bytes, mtime=0)` when saving a
local `.json.gz` file. Keep public placeholders intact.

Choose one injection and write the expected result before running detection:

- Replace the third record with an exact copy of the first. Predict delivery, unique-event and
  duplicate counts, and explain why two unique IDs do not meet the threshold.
- Change the third record's `readOnly` to Boolean `false`. Predict qualification and findings, then
  locate the bounded reason in the report. Repeat with string `"true"` and explain why schema
  rejection differs from a valid nonqualifying event.

Inspect the command's exit status as well as its JSON. PowerShell exposes `$LASTEXITCODE`; a POSIX
shell exposes `$?`. Explain `0` accepted, `2` invalid input, `3` conflict, `64` usage and `70` internal
failure. Restore or discard your scratch inputs without changing the checked-in demo.

## Minutes 20–28: add a negative test, then prove it can fail

Choose one additional negative case and state the exact production mistake it would catch. For
example, two events using `SYNTHETIC_KEY_A` plus one using `SYNTHETIC_KEY_B`, with the same role and
session name, must produce zero candidates. Give your records literal IDs and independently write
the expected count or evidence set. Do not compute the expected answer with the detector.

Write a new local test using `tests.helpers.event` and `archive`, then `parse_bytes` and `detect`.
Keep its scope narrow and run it alone. Existing correct behavior may already pass your new test;
passing immediately does not demonstrate that the assertion detects the intended bug. On a
disposable local change, temporarily introduce the specific mistake you named, confirm the test
fails for that reason, then restore the production change. Never retain the deliberately broken
implementation. For a genuinely missing behavior, the test must fail first before implementing it.

Run your targeted test again and then the complete `python -m pytest` suite. Record the command,
observed failure reason, restored passing result and any remaining failure. Do not weaken the test
to make an unexplained failure disappear.

## Minutes 28–30: deliver a short explanation

Write five sentences: what the rule detects; what fixes the credential-session boundary; what each
hash proves; what your negative test catches; and what remains outside this offline milestone.
Include synthetic provenance and the possibility of benign inventory/pagination/retry bursts.
Make no claims about live AWS collection, signed-digest validation, compromise detection accuracy,
independent review, SIEM integration or response actions that this exercise did not perform.

A reviewer can use your predictions, terminal results and test diff to assess the explanation.
Any incorrect prediction is a useful follow-up topic; it is not repaired by silently changing the
expected answer to match the implementation.
