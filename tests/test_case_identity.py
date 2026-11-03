"""Case identities and fingerprints have separately authored semantic expectations."""

from cloudsecops_live.cases import case_identity, evidence_fingerprint


def test_case_identity_stable_and_merge_parent_order_independent() -> None:
    assert case_identity("finding-a") == case_identity("finding-a")
    assert case_identity("finding-a") != case_identity("finding-b")
    assert case_identity("merged", ("parent-a", "parent-b")) == case_identity(
        "merged", ("parent-b", "parent-a")
    )
    assert case_identity("merged", ("parent-a", "parent-b")) != case_identity("merged")


def test_fingerprint_binds_full_source_record_hash_and_rule() -> None:
    baseline = {"evidence": [{"record_sha256": "a"}], "rule_version": "1.0"}
    assert evidence_fingerprint(baseline) == evidence_fingerprint(dict(reversed(baseline.items())))
    assert evidence_fingerprint(baseline) != evidence_fingerprint(
        {"evidence": [{"record_sha256": "b"}], "rule_version": "1.0"}
    )
    assert evidence_fingerprint(baseline) != evidence_fingerprint(
        {"evidence": [{"record_sha256": "a"}], "rule_version": "2.0"}
    )
