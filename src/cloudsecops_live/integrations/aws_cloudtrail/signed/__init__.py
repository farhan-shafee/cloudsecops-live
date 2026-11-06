"""Offline supplied-key cryptographic verification, never source authentication."""

from cloudsecops_live.integrations.aws_cloudtrail.signed.contracts import (
    AcquiredObject,
    ChainAnchor,
    ChainSpec,
    SignedAssessment,
    SuppliedKey,
    VerificationPlan,
)
from cloudsecops_live.integrations.aws_cloudtrail.signed.verification import verify_bundle

__all__ = [
    "AcquiredObject",
    "ChainAnchor",
    "ChainSpec",
    "SignedAssessment",
    "SuppliedKey",
    "VerificationPlan",
    "verify_bundle",
]
