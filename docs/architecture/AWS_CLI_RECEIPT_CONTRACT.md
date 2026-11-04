# Offline CLI receipt preparation

This contract prepares bounded, local observations for a future, separately authorized
CloudTrail acquisition boundary. It neither runs the AWS CLI nor authenticates a source.
`assess_cli_receipt` accepts retained `RetrievedLog` objects, an independently supplied
`AwsScope`, explicit UTC start/end datetimes and optional receipt bytes. Every result has
`authenticated=False`; no result supplies trusted findings, review authority or closure.
Even complete, internally consistent fabricated observations remain
`pending_source_authentication` with `AWS_AUTHENTICATION_UNAVAILABLE`.

## Researched output pin

Research on 2026-11-03 used the current [command reference](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/validate-logs.html)
and the official AWS CLI **2.37.11** release, commit
`ba8d103af435ed848458491137947f7e7ead9f6a`. The parser contract is
`aws-cli/2.37.11/cloudtrail-validate-logs/verbose/1`, not an assertion that every 2.x
release emits compatible output. The release's [version declaration](https://github.com/aws/aws-cli/blob/ba8d103af435ed848458491137947f7e7ead9f6a/awscli/__init__.py)
identifies `2.37.11`. Source identity is recorded for review, not verified installation
provenance. No CLI was installed or invoked during this preparation.

* [Command implementation](https://github.com/aws/aws-cli/blob/ba8d103af435ed848458491137947f7e7ead9f6a/awscli/customizations/cloudtrail/validation.py),
  Git blob `150dca4815153bc5c8e30d53ffdf569d29404f3f`.
* [Unit tests](https://github.com/aws/aws-cli/blob/ba8d103af435ed848458491137947f7e7ead9f6a/tests/unit/customizations/cloudtrail/test_validation.py),
  Git blob `99aed598f47e3aa65951f3baf609eb293a9ce229`.
* [Functional output tests](https://github.com/aws/aws-cli/blob/ba8d103af435ed848458491137947f7e7ead9f6a/tests/functional/cloudtrail/test_validation.py),
  Git blob `ad386c0b1a2c16d2f871dbf7f6822296182caf3c`.

The implementation writes human text directly. `--output json` does not turn these
messages into a machine receipt. Successful verbose messages expose original S3
locations and a validity label. They do **not** expose member hashes, object VersionIds,
signing-key observations, individual digest delivery intervals or full chain coverage.
The source processes standard digests first and backfill digests separately; backfill
digest messages have a `(backfill) ` prefix. Log messages themselves have no chain label.
Summary ratios separately count standard digests, backfill digests and logs. Invalid
file messages and digest gaps go to stderr, so retaining stdout alone is insufficient.

The supported source returns one on counted invalid files, but an empty selection can
still return zero. A gap callback also does not by itself increment invalid counters.
Exit zero and the summary's minimum/maximum found times cannot establish continuous
coverage. The parser accepts a deliberately narrow exact verbose grammar; diagnostics
outside that subset fail closed. Another real CLI release requires a separately reviewed
output contract and fixtures.

## Strict envelope

The UTF-8 JSON object has exactly these keys. Timestamps use whole-second
`YYYY-MM-DDTHH:MM:SSZ`; the requested interval is nonempty and at most 24 hours.

| Key | Required content |
| --- | --- |
| `schema_version` | `aws-cli-receipt/1` |
| `tool_version` | `aws-cli/2.37.11` |
| `output_contract` | `aws-cli/2.37.11/cloudtrail-validate-logs/verbose/1` |
| `scope` | Exact `account`, `region`, `trail_arn`, `bucket`, `s3_prefix`, `start_time`, `end_time` |
| `execution` | Exact `started_at`, `completed_at`, integer `exit_code`, `stdout`, `stderr` |
| `standard_chain`, `backfill_chain` | Each exactly `outcome` and boolean `complete` |
| `sources` | Retained log-source observations; exact expected objects, no duplicates |
| `digests` | Each exactly `source` and raw uncompressed JSON string `content` |

`s3_prefix` is the optional root prepended before `AWSLogs`, without a trailing slash;
it is not the complete log or digest prefix. An empty root is explicit. The scope is
compared with the independently supplied scope/interval before any consistency claim.
There are at most 64 logs and 64 digests. Envelope size, nested JSON, source strings,
stdout/stderr, line lengths and member counts are bounded. Each parsed JSON tree is
limited to 32 nesting levels and 8,192 nodes. The output contract accepts LF text;
CRLF, locale changes and other formatting are outside this narrow grammar. Duplicate JSON keys,
nonfinite numbers, unknown wrapper keys, duplicate locations, truncated output,
ANSI escapes and unexpected control characters are rejected with sanitized reason codes.

Each source observation has exactly `bucket`, `key`, `version_id`, `archive_sha256`,
`content_sha256`, `before_version_id`, `after_version_id`, `before_observed_at` and
`after_observed_at`. Before/after observations must name the retained non-null version
and bracket both acquisition and the supplied execution interval. This is a controlled
observation, not proof that a real HEAD, download or CLI run occurred. Retained log
archive/content hashes and bounded decompression are checked through the existing
`assess_digest` consistency boundary. Digest archive hashes are retention declarations;
only the separately supplied raw digest JSON content/hash can be checked here. This
limitation is never promoted to cryptographic or archive authenticity.

Raw digest JSON must have matching `awsAccountId`, `digestS3Bucket`, `digestS3Object`,
valid `digestStartTime`/`digestEndTime` and a bounded `logFiles` list. Member entries
require original `s3Bucket`, `s3Object`, `hashValue` and `hashAlgorithm` equal to
`SHA-256`; the hash domain is the **uncompressed log content**. Other official digest
metadata may be retained but cannot establish trust. AWS signed members contain no
VersionId. A receipt cannot manufacture a signed version binding by adding one.
[Digest structure](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html)

Every supplied digest location must appear in verbose output under the correct chain,
and every verbose log must be a separately observed digest member. Every expected
retained log must appear with its exact original location and content hash. Counts must
reconcile with verbose outcomes; unrelated valid members cannot satisfy a missing expected
member. Repeated output or contradictory member hashes are rejected. A changed expected
scope, file, archive, content, version or execution binding cannot reuse the receipt.

Chain `outcome` is one of `valid`, `invalid`, `pending`, `absent`. `absent` is meaningful
only with zero supplied digests for that chain and `complete=True`; it remains a supplied
absence observation, not proof of an authenticated empty chain. `valid` requires supplied
digests and `complete=True`. Both chains must be addressed independently. Missing/pending
chains or observed coverage gaps stay incomplete; invalid chains stay invalid. Supplied
digests must cover the interval without gaps within each present chain. This interval
consistency check is not a replacement digest signature/previous-link validator.

States are `missing`, `incomplete`, `invalid`, `conflicting`, `unsupported` and
`pending_source_authentication`. The last state alone may carry
`consistency_passed=True`; it still cannot authenticate anything. Public summaries use an
explicit allowlist of schema/state/reason/count/boolean fields. They omit raw output,
accounts, ARNs, source locations, private identifiers, observation timestamps and hashes.
Fixed `unproven` labels explicitly identify execution provenance, signature, authenticated
chain coverage, source-version observations and digest archive/content binding as unavailable.

## Official-format fictional template

The following is a local string template, not an executable AWS command. It reproduces
the researched implementation's successful stdout layout with generated fictional
identifiers. Full receipts additionally require the observations above. These strings
cannot prove a CLI execution, identity, membership or signature.

```python
account = "".join(str((i + 4) % 10) for i in range(12))
region, bucket, trail = "us-east-1", "fictional-receipt-lab", "FictionalTrail"
start, end = "2026-10-01T00:00:00Z", "2026-10-01T01:00:00Z"
arn = f"arn:aws:cloudtrail:{region}:{account}:trail/{trail}"
digest = f"AWSLogs/{account}/CloudTrail-Digest/{region}/2026/10/01/example.json.gz"
log = f"AWSLogs/{account}/CloudTrail/{region}/2026/10/01/example.json.gz"
stdout = (
    f"Validating log files for trail {arn} between {start} and {end}\n\n"
    f"Digest file\ts3://{bucket}/{digest}\tvalid\n"
    f"Log file\ts3://{bucket}/{log}\tvalid\n\n"
    f"Results requested for {start} to {end}\n"
    f"Results found for {start} to {end}:\n"
    "\n1/1 digest files valid\n1/1 log files valid\n"
)
```

The [CLI integrity guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html)
requires online AWS access and original delivered S3 locations; local downloads cannot
be validated by that command. This milestone authorizes neither that access nor any
installation, credential discovery, endpoint, infrastructure or logging changes. Future
live execution needs separately authorized collection, genuine execution provenance,
signature/key validation, chain reconciliation and version continuity evidence before a
different authenticated ingestion boundary can exist.
