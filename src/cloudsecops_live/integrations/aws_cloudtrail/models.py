"""Immutable AWS-shaped data contracts; parsing alone never authenticates evidence."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from cloudsecops_live.errors import EvidenceError

SCHEMA_VERSION = "aws-offline/1"
PARSER_VERSION = "1.0.0"
CANONICALIZATION_VERSION = "1.0"

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(
    r"(?:af|ap|ca|eu|il|me|mx|sa|us)-"
    r"(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9][0-9]?\Z"
)
_ROLE_ID = re.compile(r"AROA[A-Z0-9]{17}\Z")
_ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/(.+)\Z")
_PATH_PART = re.compile(r"[A-Za-z0-9_+=,.@-]+\Z")
_PREFIX_PART = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_TRAIL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,126}[A-Za-z0-9]\Z")


def _is_account(value: object) -> bool:
    return isinstance(value, str) and _ACCOUNT.fullmatch(value) is not None


def _is_region(value: object) -> bool:
    return isinstance(value, str) and _REGION.fullmatch(value) is not None


def _role_parts(value: object) -> tuple[str, str] | None:
    if not isinstance(value, str) or len(value) > 640:
        return None
    match = _ROLE.fullmatch(value)
    if match is None:
        return None
    account, path = match.groups()
    parts = path.split("/")
    if (
        len(path) > 576
        or len(parts[-1]) > 64
        or ".." in path
        or any(part == "." or _PATH_PART.fullmatch(part) is None for part in parts)
    ):
        return None
    return account, parts[-1]


def _is_bucket(value: object) -> bool:
    if not isinstance(value, str) or _BUCKET.fullmatch(value) is None:
        return False
    if (
        any(part in value for part in ("..", ".-", "-."))
        or value.startswith(("xn--", "sthree-", "amzn-s3-demo-"))
        or value.endswith(("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"))
    ):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def _prefix_root(value: object, suffix: str) -> str | None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or not value.endswith(suffix)
        or ".." in value
        or any(_PREFIX_PART.fullmatch(part) is None for part in value[:-1].split("/"))
    ):
        return None
    root = value[: -len(suffix)]
    if root and not root.endswith("/"):
        return None
    return root


@dataclass(frozen=True, slots=True)
class AwsScope:
    account: str
    region: str
    role_arn: str
    role_id: str
    trail_arn: str
    bucket: str
    log_prefix: str
    digest_prefix: str

    def __post_init__(self) -> None:
        role = _role_parts(self.role_arn)
        if (
            not _is_account(self.account)
            or not _is_region(self.region)
            or role is None
            or role[0] != self.account
            or not isinstance(self.role_id, str)
            or _ROLE_ID.fullmatch(self.role_id) is None
            or not _is_bucket(self.bucket)
            or not isinstance(self.trail_arn, str)
        ):
            raise EvidenceError("INVALID_AWS_SCOPE")
        trail_start = f"arn:aws:cloudtrail:{self.region}:{self.account}:trail/"
        trail_name = self.trail_arn.removeprefix(trail_start)
        if (
            not self.trail_arn.startswith(trail_start)
            or _TRAIL_NAME.fullmatch(trail_name) is None
            or ".." in trail_name
        ):
            raise EvidenceError("INVALID_AWS_SCOPE")
        log_root = _prefix_root(
            self.log_prefix, f"AWSLogs/{self.account}/CloudTrail/{self.region}/"
        )
        digest_root = _prefix_root(
            self.digest_prefix, f"AWSLogs/{self.account}/CloudTrail-Digest/{self.region}/"
        )
        if log_root is None or digest_root is None or log_root != digest_root:
            raise EvidenceError("INVALID_AWS_SCOPE")


@dataclass(frozen=True, slots=True)
class AwsSession:
    account: str
    region: str
    issuer_arn: str
    access_key_id: str
    creation_time: datetime


@dataclass(frozen=True, slots=True)
class AwsEvent:
    identity: tuple[str, str, str]
    event_time: datetime
    event_source: str
    event_name: str
    event_category: str
    event_type: str
    read_only: bool | None
    has_error: bool
    session: AwsSession | None
    identity_reason: str | None
    canonical_record: bytes
    record_sha256: str
    record_index: int


@dataclass(frozen=True, slots=True)
class AwsLog:
    archive_bytes: bytes
    content_bytes: bytes
    archive_sha256: str
    content_sha256: str
    events: tuple[AwsEvent, ...]
    source_kind: Literal["aws_shaped_unverified"] = field(
        default="aws_shaped_unverified", init=False
    )
    authenticated: Literal[False] = field(default=False, init=False)
    schema_version: str = field(default=SCHEMA_VERSION, init=False)
    parser_version: str = field(default=PARSER_VERSION, init=False)
    canonicalization_version: str = field(default=CANONICALIZATION_VERSION, init=False)
