"""Connection boundaries reject ambient libpq routing before any network access."""

import pytest

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError


@pytest.mark.parametrize(
    "dsn",
    [
        "dbname=postgres host=127.0.0.1",
        "dbname=cloudsecops_lab host=example.com",
        "dbname=cloudsecops_lab host=localhost",
        "dbname=cloudsecops_lab host=127.0.0.1 hostaddr=8.8.8.8",
        "dbname=cloudsecops_lab host=127.0.0.1 service=production",
        "dbname=cloudsecops_lab host=127.0.0.1 options='-c search_path=evil'",
        "dbname=cloudsecops_lab host=127.0.0.1 sslcert=secret",
        "dbname=cloudsecops_lab",
        "dbname=csl_test_BAD host=127.0.0.1",
        "dbname=cloudsecops_lab host=127.0.0.1,8.8.8.8",
    ],
)
def test_reject_nonlocal_or_ambient_routes(dsn: str) -> None:
    with pytest.raises(EvidenceError, match="UNSAFE_DATABASE_DSN"):
        Database(dsn)


@pytest.mark.parametrize(
    "dsn",
    [
        "dbname=cloudsecops_lab host=127.0.0.1",
        "dbname=csl_test_storage_123 host=::1 port=55432",
        # Fixed dummy URI parser fixture; never used to authenticate a server.
        "postgresql://lab:test@127.0.0.1:55432/csl_test_unit",  # pragma: allowlist secret
    ],
)
def test_explicit_project_loopback_routes(dsn: str) -> None:
    assert Database(dsn)


def test_current_finding_requires_case_coverage() -> None:
    from cloudsecops_live.storage import _verify_case_links

    with pytest.raises(EvidenceError, match="CASE_FINDING_COVERAGE_MISMATCH"):
        _verify_case_links([{"finding_id": "f", "status": "current"}], [], [], [])


def test_superseded_parent_requires_reciprocal_lineage() -> None:
    from cloudsecops_live.storage import _verify_case_links

    cases = [
        {"case_id": "parent", "current_revision": 2, "status": "superseded"},
        {"case_id": "child", "current_revision": 1, "status": "current"},
    ]
    revisions = [
        {
            "case_id": "parent",
            "revision": 2,
            "finding_id": "old",
            "generation": 2,
            "payload": {"superseded_by": "child"},
        },
        {"case_id": "child", "revision": 1, "finding_id": "new", "generation": 2, "payload": {}},
    ]
    findings = [
        {"finding_id": "old", "status": "obsolete"},
        {"finding_id": "new", "status": "current"},
    ]
    with pytest.raises(EvidenceError, match="CASE_LINEAGE_MISMATCH"):
        _verify_case_links(findings, cases, revisions, [])


@pytest.mark.parametrize("status", ["current", "pending"])
def test_matching_active_finding_and_case_links_are_valid(status: str) -> None:
    from cloudsecops_live.storage import _verify_case_links

    _verify_case_links(
        [{"finding_id": "f", "status": status}],
        [{"case_id": "case", "current_revision": 1, "status": status}],
        [{"case_id": "case", "revision": 1, "finding_id": "f", "payload": {}}],
        [],
    )


def test_pending_finding_cannot_retain_current_case() -> None:
    from cloudsecops_live.storage import _verify_case_links

    with pytest.raises(EvidenceError, match="CASE_FINDING_COVERAGE_MISMATCH"):
        _verify_case_links(
            [{"finding_id": "f", "status": "pending"}],
            [{"case_id": "case", "current_revision": 1, "status": "current"}],
            [{"case_id": "case", "revision": 1, "finding_id": "f", "payload": {}}],
            [],
        )
