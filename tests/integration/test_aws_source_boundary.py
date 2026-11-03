"""Real PostgreSQL proves AWS-shaped input cannot enter accepted synthetic evidence."""

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.storage import ingest
from tests.aws_helpers import archive
from tests.integration.test_nul_quarantine import (
    assert_only_quarantine_changed,
    populate_demo,
    snapshot,
)


@pytest.mark.parametrize("populated", [False, True])
def test_aws_input_is_permanently_quarantined_without_partial_acceptance(db, populated):
    if populated:
        populate_demo(db)
    before = snapshot(db)
    with pytest.raises(EvidenceError, match="INVALID_FIXTURE_ENVELOPE"):
        ingest(db, [("aws-shaped.json.gz", archive())], checkpoint="aws-blocked")
    assert_only_quarantine_changed(db, before, "aws-blocked", reason="INVALID_FIXTURE_ENVELOPE")
