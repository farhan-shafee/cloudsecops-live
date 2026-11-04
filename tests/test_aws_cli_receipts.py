"""Fictional CLI observations establish consistency only, even when every claim agrees."""

import gzip
import json
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta, timezone
from hashlib import sha256

import pytest

from cloudsecops_live.integrations.aws_cloudtrail.cli_receipts import assess_cli_receipt
from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion, RetrievedLog
from cloudsecops_live.integrations.aws_cloudtrail.parsing import parse_aws_shaped
from tests.aws_helpers import BASE_TIME, archive, scope

START = BASE_TIME - timedelta(hours=1)
END = BASE_TIME + timedelta(hours=1)


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def encode(receipt):
    return json.dumps(receipt, separators=(",", ":")).encode()


def fixture():
    expected = scope()
    log = parse_aws_shaped(archive(), expected)
    reference = ObjectVersion(
        expected.bucket,
        expected.log_prefix + "2026/01/01/log.json.gz",
        "retained-log-version",
        len(log.archive_bytes),
        BASE_TIME,
    )
    retrieved = RetrievedLog(reference, log, BASE_TIME - timedelta(seconds=30), BASE_TIME)

    def observation(key, version, archive_hash, content_hash):
        return {
            "bucket": expected.bucket,
            "key": key,
            "version_id": version,
            "archive_sha256": archive_hash,
            "content_sha256": content_hash,
            "before_version_id": version,
            "after_version_id": version,
            "before_observed_at": stamp(BASE_TIME - timedelta(minutes=1)),
            "after_observed_at": stamp(BASE_TIME + timedelta(minutes=3)),
        }

    digest_key = expected.digest_prefix + "2026/01/01/digest.json.gz"
    digest = {
        "awsAccountId": expected.account,
        "digestS3Bucket": expected.bucket,
        "digestS3Object": digest_key,
        "digestStartTime": stamp(START),
        "digestEndTime": stamp(END),
        "logFiles": [
            {
                "s3Bucket": expected.bucket,
                "s3Object": reference.key,
                "hashValue": log.content_sha256,
                "hashAlgorithm": "SHA-256",
            }
        ],
    }
    content = json.dumps(digest, separators=(",", ":"))
    digest_source = observation(
        digest_key,
        "retained-digest-version",
        sha256(gzip.compress(content.encode(), mtime=0)).hexdigest(),
        sha256(content.encode()).hexdigest(),
    )
    stdout = (
        f"Validating log files for trail {expected.trail_arn} "
        f"between {stamp(START)} and {stamp(END)}\n\n"
        f"Digest file\ts3://{expected.bucket}/{digest_key}\tvalid\n"
        f"Log file\ts3://{expected.bucket}/{reference.key}\tvalid\n\n"
        f"Results requested for {stamp(START)} to {stamp(END)}\n"
        f"Results found for {stamp(START)} to {stamp(END)}:\n"
        "\n1/1 digest files valid\n1/1 log files valid\n"
    )
    receipt = {
        "schema_version": "aws-cli-receipt/1",
        "tool_version": "aws-cli/2.37.11",
        "output_contract": "aws-cli/2.37.11/cloudtrail-validate-logs/verbose/1",
        "scope": {
            "account": expected.account,
            "region": expected.region,
            "trail_arn": expected.trail_arn,
            "bucket": expected.bucket,
            "s3_prefix": "offline-lab",
            "start_time": stamp(START),
            "end_time": stamp(END),
        },
        "execution": {
            "started_at": stamp(BASE_TIME + timedelta(minutes=1)),
            "completed_at": stamp(BASE_TIME + timedelta(minutes=2)),
            "exit_code": 0,
            "stdout": stdout,
            "stderr": "",
        },
        "standard_chain": {"outcome": "valid", "complete": True},
        "backfill_chain": {"outcome": "absent", "complete": True},
        "sources": [
            observation(reference.key, reference.version_id, log.archive_sha256, log.content_sha256)
        ],
        "digests": [{"source": digest_source, "content": content}],
    }
    return (retrieved,), receipt


def assess(receipt, objects=None):
    if objects is None:
        objects, _ = fixture()
    return assess_cli_receipt(
        objects,
        scope(),
        START,
        END,
        receipt if isinstance(receipt, bytes) or receipt is None else encode(receipt),
    )


def edit_digest(receipt, action):
    """Keep declared hash internally consistent while independently changing member claims."""
    digest = receipt["digests"][0]
    value = json.loads(digest["content"])
    action(value)
    digest["content"] = json.dumps(value, separators=(",", ":"))
    digest["source"]["content_sha256"] = sha256(digest["content"].encode()).hexdigest()


def rejected(receipt, *, objects=None, state=None):
    result = assess(receipt, objects)
    assert result.authenticated is False
    assert result.consistency_passed is False
    assert result.state != "pending_source_authentication"
    if state:
        assert result.state == state
    return result


def test_missing_receipt_is_explicit_and_untrusted():
    result = assess(None)
    assert result.state == "missing"
    assert result.authenticated is False
    assert result.consistency_passed is False


def test_every_agreeing_fictional_claim_is_still_unverified():
    objects, receipt = fixture()
    result = assess(receipt, objects)
    assert result.state == "pending_source_authentication"
    assert result.reason == "AWS_AUTHENTICATION_UNAVAILABLE"
    assert result.consistency_passed is True
    assert result.authenticated is False
    assert result.source_kind == "aws_shaped_unverified"
    public = json.dumps(result.to_public_dict())
    for private in (
        scope().account,
        scope().bucket,
        scope().trail_arn,
        objects[0].reference.key,
        objects[0].reference.version_id,
        objects[0].log.content_sha256,
        "Validating log files",
    ):
        assert private not in public


@pytest.mark.parametrize(
    "key,value",
    [
        ("tool_version", "aws-cli/2.99.0"),
        ("output_contract", "aws-cli/2.37.11/unreviewed-format/9"),
    ],
)
def test_unreviewed_cli_or_output_contract_is_unsupported(key, value):
    _, receipt = fixture()
    receipt[key] = value
    rejected(receipt, state="unsupported")


@pytest.mark.parametrize(
    "key,value",
    [
        ("account", "2" * 12),
        ("region", "us-west-2"),
        ("trail_arn", "arn:aws:cloudtrail:us-east-1:" + "1" * 12 + ":trail/OtherTrail"),
        ("bucket", "other-evidence-bucket"),
        ("s3_prefix", ""),
        ("start_time", "2025-12-31T22:59:59Z"),
        ("end_time", "2026-01-01T01:00:01Z"),
    ],
)
def test_scope_or_interval_substitution_cannot_reuse_receipt(key, value):
    _, receipt = fixture()
    receipt["scope"][key] = value
    rejected(receipt, state="conflicting")


@pytest.mark.parametrize(
    "key,value",
    [
        ("bucket", "other-evidence-bucket"),
        ("key", scope().log_prefix + "different.json.gz"),
        ("version_id", "other-version"),
        ("before_version_id", "other-version"),
        ("after_version_id", "other-version"),
        ("archive_sha256", "a" * 64),
        ("content_sha256", "b" * 64),
        ("before_observed_at", stamp(BASE_TIME + timedelta(seconds=1))),
        ("after_observed_at", stamp(BASE_TIME + timedelta(minutes=1))),
    ],
)
def test_retained_source_version_hash_and_continuity_are_exact(key, value):
    _, receipt = fixture()
    receipt["sources"][0][key] = value
    rejected(receipt)


@pytest.mark.parametrize(
    "changes",
    [
        {"exit_code": 1},
        {"exit_code": True},
        {"stderr": "ERROR: generated private failure"},
        {"started_at": stamp(BASE_TIME + timedelta(minutes=4))},
        {"completed_at": stamp(BASE_TIME - timedelta(minutes=2))},
    ],
)
def test_execution_failure_stderr_and_unbracketed_times_cannot_pass(changes):
    _, receipt = fixture()
    receipt["execution"].update(changes)
    rejected(receipt)


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "all files valid\n",
        "{}",
        "1/1 log files valid\n",
        "No log files found\n",
        "\x1b[32mvalid\x1b[0m",
        "\n" * 300000,
        "x" * 2049,
    ],
)
def test_exit_zero_and_success_sounding_output_are_insufficient(stdout):
    _, receipt = fixture()
    receipt["execution"]["stdout"] = stdout
    rejected(receipt)


@pytest.mark.parametrize(
    "transform",
    [
        lambda value: value.replace("1/1 digest files valid", "0/0 digest files valid"),
        lambda value: value.replace("1/1 log files valid", "2/2 log files valid"),
        lambda value: value.replace("\tvalid\n", "\tINVALID: bad signature\n", 1),
        lambda value: value.replace("Digest file", "(backfill) Digest file", 1),
        lambda value: value[:-1],
        lambda value: value + "UNEXPECTED EXTRA OUTPUT\n",
        lambda value: value.replace("Log file\t", "Log file\t", 1).replace(
            "\n\nResults requested",
            "\nLog file\ts3://offline-evidence-lab/foreign.json.gz\tvalid\n\nResults requested",
        ),
    ],
)
def test_verbose_output_layout_counts_chain_and_truncation_are_checked(transform):
    _, receipt = fixture()
    receipt["execution"]["stdout"] = transform(receipt["execution"]["stdout"])
    rejected(receipt)


@pytest.mark.parametrize("chain", ["standard_chain", "backfill_chain"])
@pytest.mark.parametrize(
    "value",
    [
        {"outcome": "pending", "complete": False},
        {"outcome": "invalid", "complete": True},
        {"outcome": "valid", "complete": False},
    ],
)
def test_standard_and_backfill_chain_claims_are_independent(chain, value):
    _, receipt = fixture()
    receipt[chain] = value
    rejected(receipt)


@pytest.mark.parametrize(
    "field,value",
    [
        ("awsAccountId", "2" * 12),
        ("digestS3Bucket", "other-evidence-bucket"),
        ("digestS3Object", scope().digest_prefix + "different.json.gz"),
        ("digestStartTime", stamp(BASE_TIME)),
        ("digestEndTime", stamp(BASE_TIME)),
        ("logFiles", []),
    ],
)
def test_raw_digest_location_interval_and_expected_members_are_required(field, value):
    _, receipt = fixture()
    edit_digest(receipt, lambda content: content.update({field: value}))
    rejected(receipt)


@pytest.mark.parametrize(
    "field,value",
    [
        ("s3Bucket", "other-evidence-bucket"),
        ("s3Object", scope().log_prefix + "other.json.gz"),
        ("hashAlgorithm", "SHA-1"),
        ("hashValue", "0" * 64),
        ("version_id", "invented-signed-version"),
    ],
)
def test_digest_member_location_hash_algorithm_and_no_invented_version(field, value):
    _, receipt = fixture()
    edit_digest(receipt, lambda content: content["logFiles"][0].update({field: value}))
    rejected(receipt)


def test_member_hash_domain_is_uncompressed_content_not_retained_gzip():
    objects, receipt = fixture()
    assert objects[0].log.archive_sha256 != objects[0].log.content_sha256
    edit_digest(
        receipt,
        lambda content: content["logFiles"][0].update(hashValue=objects[0].log.archive_sha256),
    )
    rejected(receipt)


def test_unrelated_valid_members_cannot_satisfy_the_retained_log():
    _, receipt = fixture()
    edit_digest(
        receipt,
        lambda content: content["logFiles"][0].update(
            s3Object=scope().log_prefix + "unrelated.json.gz"
        ),
    )
    receipt["execution"]["stdout"] = receipt["execution"]["stdout"].replace(
        receipt["sources"][0]["key"], scope().log_prefix + "unrelated.json.gz"
    )
    rejected(receipt)


def test_conflicting_duplicate_member_hashes_are_not_collapsed():
    _, receipt = fixture()

    def conflict(content):
        member = deepcopy(content["logFiles"][0])
        member["hashValue"] = "f" * 64
        content["logFiles"].append(member)

    edit_digest(receipt, conflict)
    rejected(receipt)


@pytest.mark.parametrize("location", ["sources", "digests"])
def test_duplicate_source_and_digest_observations_are_rejected(location):
    _, receipt = fixture()
    receipt[location].append(deepcopy(receipt[location][0]))
    rejected(receipt)


def test_retained_archive_and_content_cannot_be_detached_from_each_other():
    objects, receipt = fixture()
    forged = replace(
        objects[0],
        log=replace(objects[0].log, archive_bytes=gzip.compress(b'{"Records":[]}', mtime=0)),
    )
    rejected(receipt, objects=(forged,))


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[]",
        b"null",
        b"\xff",
        b'{"x":NaN}',
        b'{"schema_version":"aws-cli-receipt/1","schema_version":"forged"}',
        b" " * (2 * 1024 * 1024 + 1),
    ],
)
def test_invalid_utf8_json_duplicates_nonfinite_and_size_limits_are_sanitized(raw):
    rejected(raw)


def test_unknown_wrapper_and_forged_authentication_fields_are_rejected():
    _, receipt = fixture()
    receipt.update(authenticated=True, trusted_findings_available=True)
    rejected(receipt)


def test_raw_digest_duplicate_json_keys_are_rejected_even_with_matching_hash():
    _, receipt = fixture()
    entry = receipt["digests"][0]
    entry["content"] = entry["content"].replace("{", '{"awsAccountId":"' + "2" * 12 + '",', 1)
    entry["source"]["content_sha256"] = sha256(entry["content"].encode()).hexdigest()
    rejected(receipt)


def add_digest(receipt, *, backfill=False, start=START, end=END):
    entry = deepcopy(receipt["digests"][0])
    suffix = "second_backfill.json.gz" if backfill else "second.json.gz"
    entry["source"]["key"] = scope().digest_prefix + "2026/01/01/" + suffix
    entry["source"]["version_id"] = "second-digest-version"
    entry["source"]["before_version_id"] = "second-digest-version"
    entry["source"]["after_version_id"] = "second-digest-version"
    content = json.loads(entry["content"])
    content.update(
        digestS3Object=entry["source"]["key"],
        digestStartTime=stamp(start),
        digestEndTime=stamp(end),
        logFiles=[],
    )
    entry["content"] = json.dumps(content, separators=(",", ":"))
    entry["source"]["content_sha256"] = sha256(entry["content"].encode()).hexdigest()
    receipt["digests"].append(entry)
    line = ("(backfill) " if backfill else "") + (
        f"Digest file\ts3://{scope().bucket}/{entry['source']['key']}\tvalid\n"
    )
    receipt["execution"]["stdout"] = receipt["execution"]["stdout"].replace(
        "\n\nResults requested", "\n" + line + "\nResults requested"
    )
    receipt["execution"]["stdout"] = receipt["execution"]["stdout"].replace(
        "1/1 digest files valid\n",
        "1/1 digest files valid\n1/1 backfill digest files valid\n"
        if backfill
        else "2/2 digest files valid\n",
    )


def test_complete_independent_standard_and_backfill_observations_stay_unverified():
    _, receipt = fixture()
    add_digest(receipt, backfill=True)
    receipt["backfill_chain"] = {"outcome": "valid", "complete": True}
    result = assess(receipt)
    assert result.state == "pending_source_authentication"
    assert result.consistency_passed is True
    assert result.authenticated is False


def test_observed_backfill_cannot_claim_absence():
    _, receipt = fixture()
    add_digest(receipt, backfill=True)
    rejected(receipt)


@pytest.mark.parametrize("gap", [False, True])
def test_present_standard_digest_chain_interval_coverage_is_reconciled(gap):
    _, receipt = fixture()
    edit_digest(receipt, lambda content: content.update(digestEndTime=stamp(BASE_TIME)))
    add_digest(receipt, start=BASE_TIME + timedelta(seconds=1 if gap else 0), end=END)
    result = assess(receipt)
    assert result.authenticated is False
    assert result.consistency_passed is (not gap)
    if gap:
        assert result.state == "incomplete"


@pytest.mark.parametrize("collection", ["sources", "digests"])
def test_missing_observations_cannot_be_replaced_by_verbose_success(collection):
    _, receipt = fixture()
    receipt[collection] = []
    rejected(receipt)


def test_digest_raw_content_must_match_its_observed_hash():
    _, receipt = fixture()
    receipt["digests"][0]["content"] += " "
    rejected(receipt)


def test_digest_member_count_and_nested_json_are_bounded():
    _, receipt = fixture()
    edit_digest(receipt, lambda content: content.update(logFiles=content["logFiles"] * 257))
    rejected(receipt)
    _, receipt = fixture()
    edit_digest(
        receipt, lambda content: content.update(extra=json.loads("[" * 80 + "0" + "]" * 80))
    )
    rejected(receipt)


def test_backfill_only_output_is_consistent_but_cannot_authenticate():
    _, receipt = fixture()
    entry = receipt["digests"][0]
    old_key = entry["source"]["key"]
    key = old_key.removesuffix(".json.gz") + "_backfill.json.gz"
    entry["source"]["key"] = key
    edit_digest(receipt, lambda content: content.update(digestS3Object=key))
    receipt["standard_chain"] = {"outcome": "absent", "complete": True}
    receipt["backfill_chain"] = {"outcome": "valid", "complete": True}
    receipt["execution"]["stdout"] = (
        receipt["execution"]["stdout"]
        .replace(old_key, key)
        .replace("Digest file\t", "(backfill) Digest file\t", 1)
        .replace("1/1 digest files valid", "1/1 backfill digest files valid")
    )
    result = assess(receipt)
    assert result.consistency_passed is True
    assert result.authenticated is False
    assert result.state == "pending_source_authentication"


def test_official_empty_selection_and_exit_zero_remain_incomplete():
    _, receipt = fixture()
    receipt["digests"] = []
    receipt["standard_chain"] = {"outcome": "absent", "complete": True}
    receipt["execution"]["stdout"] = (
        f"Validating log files for trail {scope().trail_arn} "
        f"between {stamp(START)} and {stamp(END)}\n\n"
        f"Results requested for {stamp(START)} to {stamp(END)}\nNo digests found\n"
    )
    rejected(receipt, state="incomplete")


def test_stdout_found_extrema_cannot_substitute_for_raw_digest_interval():
    _, receipt = fixture()
    receipt["execution"]["stdout"] = receipt["execution"]["stdout"].replace(
        f"Results found for {stamp(START)}", f"Results found for {stamp(BASE_TIME)}"
    )
    rejected(receipt, state="conflicting")


def test_repeated_valid_log_line_with_adjusted_counts_is_still_rejected():
    objects, receipt = fixture()
    line = f"Log file\ts3://{scope().bucket}/{objects[0].reference.key}\tvalid\n"
    receipt["execution"]["stdout"] = (
        receipt["execution"]["stdout"]
        .replace(line, line + line)
        .replace("1/1 log files valid", "2/2 log files valid")
    )
    rejected(receipt)


def test_log_line_requires_its_actual_verbose_digest_parent():
    objects, receipt = fixture()
    edit_digest(receipt, lambda content: content.update(digestEndTime=stamp(BASE_TIME)))
    add_digest(receipt, start=BASE_TIME)
    line = f"Log file\ts3://{scope().bucket}/{objects[0].reference.key}\tvalid\n"
    stdout = receipt["execution"]["stdout"].replace(line, "")
    receipt["execution"]["stdout"] = stdout.replace(
        "\n\nResults requested", "\n" + line + "\nResults requested"
    )
    rejected(receipt, state="conflicting")


def test_recognized_gap_diagnostic_cannot_be_ignored_with_valid_stdout():
    _, receipt = fixture()
    receipt["execution"]["stderr"] = (
        f"No log files were delivered by CloudTrail between {stamp(START)} and {stamp(END)}\n"
    )
    rejected(receipt, state="incomplete")


@pytest.mark.parametrize("value", ["\x00", "\x1b[32mforged\x1b[0m"])
def test_decoded_controls_in_optional_digest_metadata_are_rejected(value):
    _, receipt = fixture()
    edit_digest(receipt, lambda content: content.update(digestSignature=value))
    rejected(receipt)


@pytest.mark.parametrize("objects", [[], (), (object(),)])
def test_a_receipt_cannot_supply_its_own_expected_retained_object_set(objects):
    _, receipt = fixture()
    rejected(receipt, objects=objects)


def test_valid_json_number_overflow_cannot_smuggle_nonfinite_digest_metadata():
    _, receipt = fixture()
    entry = receipt["digests"][0]
    entry["content"] = entry["content"].replace("{", '{"untrustedNumber":1e999,', 1)
    entry["source"]["content_sha256"] = sha256(entry["content"].encode()).hexdigest()
    rejected(receipt)


def test_collector_retrieval_microseconds_preserve_receipt_consistency_without_authentication():
    objects, receipt = fixture()
    precise = replace(
        objects[0],
        retrieval_started=objects[0].retrieval_started.replace(microsecond=123),
        retrieval_completed=objects[0].retrieval_completed.replace(microsecond=456),
    )
    result = assess(receipt, (precise,))
    assert result.consistency_passed is True
    assert result.state == "pending_source_authentication"
    assert result.reason == "AWS_AUTHENTICATION_UNAVAILABLE"
    assert result.authenticated is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("retrieval_started", BASE_TIME - timedelta(minutes=1, microseconds=1)),
        ("retrieval_completed", BASE_TIME + timedelta(minutes=3, microseconds=1)),
    ],
)
def test_fractional_retrieval_outside_observation_bracket_is_not_rounded_into_it(field, value):
    objects, receipt = fixture()
    precise = replace(objects[0], **{field: value})
    result = rejected(receipt, objects=(precise,), state="conflicting")
    assert result.reason == "AWS_CLI_RETRIEVAL_INTERVAL_CONFLICT"


def test_retrieval_order_within_one_second_is_compared_without_rounding():
    objects, receipt = fixture()
    precise = replace(
        objects[0],
        retrieval_started=BASE_TIME.replace(microsecond=456),
        retrieval_completed=BASE_TIME.replace(microsecond=123),
    )
    result = rejected(receipt, objects=(precise,), state="conflicting")
    assert result.reason == "AWS_CLI_RETRIEVAL_INTERVAL_CONFLICT"


@pytest.mark.parametrize("field", ["retrieval_started", "retrieval_completed"])
@pytest.mark.parametrize("kind", ["naive", "non-utc"])
def test_retrieval_precision_support_still_requires_explicit_utc(field, kind):
    objects, receipt = fixture()
    value = getattr(objects[0], field).replace(microsecond=123)
    value = (
        value.replace(tzinfo=None)
        if kind == "naive"
        else value.astimezone(timezone(timedelta(hours=1)))
    )
    result = rejected(receipt, objects=(replace(objects[0], **{field: value}),), state="invalid")
    assert result.reason == "AWS_CLI_RECEIPT_TIME"


@pytest.mark.parametrize("field", ["start", "end"])
def test_requested_cli_interval_keeps_its_whole_second_contract(field):
    objects, receipt = fixture()
    start = START.replace(microsecond=123) if field == "start" else START
    end = END.replace(microsecond=456) if field == "end" else END
    result = assess_cli_receipt(objects, scope(), start, end, encode(receipt))
    assert result.state == "invalid"
    assert result.reason == "AWS_CLI_RECEIPT_TIME"
    assert result.consistency_passed is False
    assert result.authenticated is False
