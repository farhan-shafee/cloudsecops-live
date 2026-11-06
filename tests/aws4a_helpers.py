"""Explicit fictional AWS4A identities and independently fixed policy bytes."""

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from botocore.credentials import Credentials

from cloudsecops_live.integrations.aws_posture.contracts import OwnerDecision, PolicyBinding
from cloudsecops_live.integrations.aws_readiness.sessions import (
    CredentialSource,
    ExpectedIdentity,
    MfaObservation,
    Purpose,
    SessionIssuance,
    StsObservation,
    assemble_session,
)
from cloudsecops_live.integrations.aws_runner.contracts import BudgetPolicy

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
NONCE = "b" * 64
POLICY_NAME = "OfflineInspectionPolicy"
POLICY_BYTES = (
    b'{"Statement":[{"Action":["sts:GetCallerIdentity"],"Effect":"Allow",'
    b'"Resource":"*","Sid":"OfflineIdentityOnly"}],"Version":"2012-10-17"}'
)


def policy_document():
    return json.loads(POLICY_BYTES)


def identity():
    account = "1" * 12
    return ExpectedIdentity(
        account,
        "us-east-1",
        f"arn:aws:iam::{account}:role/offline/OfflineInspector",
        "AROA" + "P" * 17,
        f"arn:aws:sts::{account}:assumed-role/OfflineInspector/offline",
        Purpose.POSTURE,
    )


def decision(**overrides):
    fields = {
        "record_id": "d" * 64,
        "expected": identity(),
        "window_start": NOW - timedelta(seconds=30),
        "window_end": NOW + timedelta(minutes=10),
        "budget": BudgetPolicy(),
        "inline_policies": (PolicyBinding(POLICY_NAME, sha256(POLICY_BYTES).hexdigest()),),
        "source_revision": "e" * 40,
        "owner_ref": "f" * 64,
        "custody_ref": "a" * 64,
        "effective_iam_ref": "b" * 64,
        "network_ref": "c" * 64,
        "ca_sha256": "c" * 64,
    }
    return OwnerDecision(**(fields | overrides))


def session(decision=None, *, now=NOW):
    expected = identity() if decision is None else decision.expected
    key = "ASIA" + "Q" * 16
    issued = SessionIssuance(
        now - timedelta(seconds=10),
        now + timedelta(minutes=10),
        CredentialSource.OWNER_SUPPLIED_TEMPORARY_SESSION,
        "controlled_offline_fixture",
        True,
        MfaObservation(True, "controlled_offline_fixture", now - timedelta(seconds=1)),
        key,
    )
    observed = StsObservation(
        expected.account, expected.assumed_role_arn, expected.role_id + ":offline", now
    )
    material = Credentials(
        key,
        "fictional-offline-secret-never-valid",
        "fictional-offline-token-never-valid",
        method="explicit",
    )
    return assemble_session(expected, issued, observed, material, now=now)
