"""Production execution is deliberately unavailable in AWS4A."""

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.requests import PostureRequest


def execute(value: object) -> None:
    PostureRequest.from_metadata(value)
    # No decision-file loader, capability broker or live client constructor is
    # reachable. Complete-looking caller metadata cannot alter this decision.
    raise EvidenceError("AWS4A_EXECUTION_DISABLED")
