"""SDK-derived bytes and consistent CLI observations cannot gain SQL workflow authority."""

import gzip
import json

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    MemoryLedger,
    collect,
    require_authenticated,
)
from cloudsecops_live.integrations.aws_sdk.transport import AwsSdkTransport, SessionLease
from cloudsecops_live.storage import ingest
from tests.aws_helpers import BASE_TIME
from tests.aws_sdk_helpers import fixtures
from tests.integration.test_nul_quarantine import (
    assert_only_quarantine_changed,
    populate_demo,
    snapshot,
)
from tests.test_aws_cli_receipts import assess, fixture


@pytest.mark.parametrize("populated", [False, True])
@pytest.mark.parametrize("source", ["sdk", "consistent-cli-receipt"])
def test_guarded_outputs_cannot_enter_accepted_events_or_closure(
    db, populated, source, monkeypatch
):
    import socket

    def denied(*args, **kwargs):
        pytest.fail("PostgreSQL boundary test must not connect to AWS")

    # Database sockets already use libpq; these guards cover Python SDK HTTP sockets.
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    if populated:
        populate_demo(db)
    if source == "sdk":
        expected, lease, clients, _, _ = fixtures()
        transport = AwsSdkTransport(
            expected,
            SessionLease(**lease),
            sts_client=clients["sts"],
            s3_client=clients["s3"],
            cloudtrail_client=clients["cloudtrail"],
            clock=lambda: BASE_TIME,
        )
        result = collect(
            transport, expected, MemoryLedger(), "sql-boundary", clock=lambda: BASE_TIME
        )
        assert result.authenticated is False
        data = result.objects[0].log.archive_bytes
    else:
        _, receipt = fixture()
        result = assess(receipt)
        assert result.consistency_passed is True and result.authenticated is False
        data = gzip.compress(json.dumps(result.to_public_dict()).encode(), mtime=0)
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated(result)
    before = snapshot(db)
    with pytest.raises(EvidenceError, match="INVALID_FIXTURE_ENVELOPE"):
        ingest(db, [("guarded-unverified.json.gz", data)], checkpoint="aws1-blocked")
    assert_only_quarantine_changed(db, before, "aws1-blocked", reason="INVALID_FIXTURE_ENVELOPE")
