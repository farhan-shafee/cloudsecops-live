"""Fixed fictional response transport. No SDK session or client can be created.

Every dispatch consumes one reviewed tape record and checks the bound temporary
session before and after it. Counts describe fixture responses, not AWS traffic.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from datetime import datetime, timedelta
from io import BytesIO
from typing import Any

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    CallerIdentity,
    Marker,
    ObjectBody,
    ObjectVersion,
    VersionPage,
)
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope
from cloudsecops_live.integrations.aws_readiness.requests import Fault, ParsedRequest, encode, utc
from cloudsecops_live.integrations.aws_readiness.sessions import BoundSession


class TapeTransport:
    """A data interpreter with a fixed call plan supplied only by project workers."""

    def __init__(self, request: ParsedRequest, session: BoundSession) -> None:
        self.request, self.session = request, session
        self._started = time.monotonic()
        self._index = self._calls = self._pages = self._operations = self._bytes = self._retries = 0
        self._failed = False
        self.check()

    def now(self) -> datetime:
        return self.request.as_of + timedelta(seconds=time.monotonic() - self._started)

    def check(self) -> None:
        if self._failed:
            raise EvidenceError("AWS3_REJECTED")
        if time.monotonic() - self._started >= self.request.policy.deadline_seconds:
            self._failed = True
            raise EvidenceError("AWS3_DEADLINE")
        try:
            self.session.check(self.now())
        except EvidenceError:
            self._failed = True
            raise

    def read(self, operation: str, parameters: dict[str, object]) -> dict[str, Any]:
        retry = False
        try:
            while True:
                self.check()
                policy = self.request.policy
                page = operation.split(":")[1].startswith("List")
                if (
                    self._calls >= policy.max_calls
                    or page
                    and self._pages >= policy.max_pages
                    or not retry
                    and self._operations >= policy.max_operations
                    or retry
                    and self._retries >= policy.max_retries
                    or self._index >= len(self.request.tape.records)
                ):
                    raise EvidenceError("AWS3_BUDGET")
                record = self.request.tape.records[self._index]
                if record.operation != operation or json.loads(record.parameters) != parameters:
                    raise EvidenceError("AWS3_TAPE_ORDER")
                self._index += 1
                self._calls += 1
                self._pages += int(page)
                self._operations += int(not retry)
                self._retries += int(retry)
                self._bytes += len(record.response)
                if self._bytes > policy.max_wire_bytes:
                    raise EvidenceError("AWS3_BUDGET")
                if record.fault is Fault.STALL:
                    time.sleep(30)
                    raise EvidenceError("AWS3_DEADLINE")
                if record.fault is Fault.SUBSTITUTE:
                    self.session.credentials.token = "fictional-substitution-never-valid"
                    self.check()
                if record.fault is Fault.DENY:
                    raise EvidenceError("AWS3_FIXTURE_DENIED")
                self.check()
                if record.fault is Fault.RETRY:
                    retry = True
                    continue
                response = json.loads(record.response)
                metadata = response.get("ResponseMetadata")
                if (
                    type(metadata) is not dict
                    or type(metadata.get("HTTPStatusCode")) is not int
                    or metadata["HTTPStatusCode"] != 200
                    or "Error" in response
                ):
                    raise EvidenceError("AWS3_FIXTURE_RESPONSE")
                return dict(response)
        except Exception:
            self._failed = True
            raise

    def identity(self) -> CallerIdentity:
        result = self.read("sts:GetCallerIdentity", {})
        expected, observed = self.request.expected, self.request.observed
        if (result.get("Account"), result.get("Arn"), result.get("UserId")) != (
            observed.account,
            observed.arn,
            observed.user_id,
        ):
            self._failed = True
            raise EvidenceError("AWS3_STS_IDENTITY")
        return CallerIdentity(
            expected.account,
            expected.region,
            observed.arn,
            observed.user_id,
            self.now(),
            self.session.lease.expires_at,
        )

    def finish(self) -> None:
        self.check()
        if self._index != len(self.request.tape.records):
            self._failed = True
            raise EvidenceError("AWS3_TAPE_UNUSED")

    def public_dict(self) -> dict[str, object]:
        return {
            "state": "rejected" if self._failed else "offline_budget_observation",
            "calls": self._calls,
            "pages": self._pages,
            "operations": self._operations,
            "fixture_response_bytes": self._bytes,
            "retries": self._retries,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }


def _reference(value: object) -> ObjectVersion:
    fields = {
        "bucket",
        "key",
        "version_id",
        "size",
        "last_modified",
        "is_delete_marker",
        "is_latest",
    }
    if type(value) is not dict or set(value) != fields:
        raise EvidenceError("AWS3_FIXTURE_RESPONSE")
    return ObjectVersion(
        value["bucket"],
        value["key"],
        value["version_id"],
        value["size"],
        utc(value["last_modified"]),
        value["is_delete_marker"],
        value["is_latest"],
    )


class ArchiveTransport:
    """Existing ReadTransport shape, restricted to the approved archive scope."""

    def __init__(self, tape: TapeTransport, scope: AwsScope) -> None:
        self._tape, self._scope = tape, scope

    def caller_identity(self) -> CallerIdentity:
        return self._tape.identity()

    def list_versions(self, expected: AwsScope, prefix: str, marker: Marker | None) -> VersionPage:
        if expected != self._scope or prefix != self._scope.log_prefix:
            raise EvidenceError("AWS3_SCOPE")
        parameters: dict[str, object] = {
            "Bucket": expected.bucket,
            "ExpectedBucketOwner": expected.account,
            "Prefix": prefix,
            "MaxKeys": 64,
        }
        if marker is not None:
            parameters.update(KeyMarker=marker[0], VersionIdMarker=marker[1])
        response = self._tape.read("s3:ListObjectVersions", parameters)
        if (
            type(response.get("versions")) is not list
            or type(response.get("truncated")) is not bool
        ):
            raise EvidenceError("AWS3_FIXTURE_RESPONSE")
        raw_marker = response.get("next_marker")
        if raw_marker is not None and (
            type(raw_marker) is not list
            or len(raw_marker) != 2
            or any(type(item) is not str for item in raw_marker)
        ):
            raise EvidenceError("AWS3_FIXTURE_RESPONSE")
        next_marker = None if raw_marker is None else (raw_marker[0], raw_marker[1])
        return VersionPage(
            True,
            tuple(_reference(item) for item in response["versions"]),
            response["truncated"],
            next_marker,
        )

    def _parameters(self, ref: ObjectVersion) -> dict[str, object]:
        if ref.bucket != self._scope.bucket or not ref.key.startswith(self._scope.log_prefix):
            raise EvidenceError("AWS3_SCOPE")
        return {
            "Bucket": self._scope.bucket,
            "ExpectedBucketOwner": self._scope.account,
            "Key": ref.key,
        }

    def head_current(self, ref: ObjectVersion) -> str:
        value = self._tape.read("s3:HeadObject", self._parameters(ref)).get("version_id")
        if type(value) is not str:
            raise EvidenceError("AWS3_FIXTURE_RESPONSE")
        return value

    def get_object(self, ref: ObjectVersion, max_bytes: int) -> ObjectBody:
        parameters = self._parameters(ref)
        parameters["VersionId"] = ref.version_id
        result = self._tape.read("s3:GetObject", parameters)
        value = result.get("body_base64")
        if (
            type(value) is not str
            or type(max_bytes) is not int
            or not ref.size + 1 <= max_bytes <= 10 * 1024 * 1024 + 1
        ):
            raise EvidenceError("AWS3_FIXTURE_RESPONSE")
        try:
            body = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise EvidenceError("AWS3_FIXTURE_RESPONSE") from None
        if len(body) >= max_bytes:
            raise EvidenceError("AWS3_FIXTURE_RESPONSE")
        # Source ownership and complete metadata are rechecked by existing collect.
        reference = _reference(result.get("reference"))
        owner = result.get("owner_account")
        if type(owner) is not str:
            raise EvidenceError("AWS3_FIXTURE_RESPONSE")
        encode(result)
        return ObjectBody(reference, owner, BytesIO(body))
