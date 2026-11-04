"""Offline identity observations never confer source authentication or discovery."""

import importlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from botocore.credentials import Credentials, RefreshableCredentials

from cloudsecops_live.errors import EvidenceError

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
ACCOUNT = "1" * 12
ROLE_ID = "AROA" + "A" * 17
KEY_ID = "ASIA" + "Q" * 16
SECRET = (
    "generated-offline-only-secret-" + "Q" * 16
)  # pragma: allowlist secret - generated offline fixture, never an AWS credential
TOKEN = "generated-offline-only-session-token"


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        pytest.fail("session contracts must never discover credentials or connect")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def parts(purpose="posture"):
    sessions = importlib.import_module("cloudsecops_live.integrations.aws_readiness.sessions")
    role_name = {
        "posture": "OfflinePosture",
        "collector": "OfflineCollector",
        "verifier": "OfflineVerifier",
    }[purpose]
    peers = (
        ()
        if purpose == "posture"
        else tuple(
            sessions.PeerIdentity(
                role_arn=f"arn:aws:iam::{ACCOUNT}:role/OfflinePeer{peer_purpose.title()}",
                role_id="AROA" + ("B" if peer_purpose == "posture" else "C") * 17,
                purpose=sessions.Purpose(peer_purpose),
            )
            for peer_purpose in ("posture", "verifier" if purpose == "collector" else "collector")
        )
    )
    expected = sessions.ExpectedIdentity(
        account=ACCOUNT,
        region="us-east-1",
        role_arn=f"arn:aws:iam::{ACCOUNT}:role/{role_name}",
        role_id=ROLE_ID,
        assumed_role_arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/{role_name}/offline",
        purpose=sessions.Purpose(purpose),
        prohibited_peers=peers,
    )
    issuance = sessions.SessionIssuance(
        issued_at=BASE_TIME - timedelta(minutes=1),
        expires_at=BASE_TIME + timedelta(minutes=29),
        source=sessions.CredentialSource.OWNER_SUPPLIED_TEMPORARY_SESSION,
        provenance="offline-owner-observation",
        mfa_required=True,
        mfa=sessions.MfaObservation(True, "offline-mfa-observation", BASE_TIME),
        access_key_id=KEY_ID,
    )
    observed = sessions.StsObservation(
        ACCOUNT, expected.assumed_role_arn, f"{ROLE_ID}:offline", BASE_TIME
    )
    credentials = Credentials(KEY_ID, SECRET, TOKEN, method="explicit")
    return sessions, expected, issuance, observed, credentials


def assemble(purpose="posture", **changes):
    sessions, expected, issuance, observed, credentials = parts(purpose)
    return sessions.assemble_session(
        changes.get("expected", expected),
        changes.get("issuance", issuance),
        changes.get("observed", observed),
        changes.get("credentials", credentials),
        now=changes.get("now", BASE_TIME),
    )


def test_posture_identity_without_archive_scope_stays_unverified():
    try:
        sessions = importlib.import_module("cloudsecops_live.integrations.aws_readiness.sessions")
    except ModuleNotFoundError:
        pytest.fail("identity-only offline session assembly is not implemented")
    expected = sessions.ExpectedIdentity(
        account=ACCOUNT,
        region="us-east-1",
        role_arn=f"arn:aws:iam::{ACCOUNT}:role/OfflinePosture",
        role_id=ROLE_ID,
        assumed_role_arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/OfflinePosture/offline",
        purpose=sessions.Purpose.POSTURE,
    )
    issuance = sessions.SessionIssuance(
        issued_at=BASE_TIME - timedelta(minutes=1),
        expires_at=BASE_TIME + timedelta(minutes=29),
        source=sessions.CredentialSource.OWNER_SUPPLIED_TEMPORARY_SESSION,
        provenance="offline-owner-observation",
        mfa_required=True,
        mfa=sessions.MfaObservation(
            observed=True,
            provenance="offline-mfa-observation",
            observed_at=BASE_TIME,
        ),
        access_key_id=KEY_ID,
    )
    observed = sessions.StsObservation(
        account=ACCOUNT,
        arn=expected.assumed_role_arn,
        user_id=f"{ROLE_ID}:offline",
        observed_at=BASE_TIME,
    )
    credentials = Credentials(KEY_ID, SECRET, TOKEN, method="explicit")
    bound = sessions.assemble_session(expected, issuance, observed, credentials, now=BASE_TIME)
    bound.check(BASE_TIME)
    assert bound.credentials is credentials
    assert bound.lease.principal_arn == expected.assumed_role_arn
    assert bound.lease.user_id == f"{ROLE_ID}:offline"
    assert bound.public_dict()["authenticated"] is False
    assert bound.public_dict()["closure_available"] is False
    assert bound.public_dict()["trusted_findings_available"] is False
    assert all(value not in repr(bound) for value in (KEY_ID, SECRET, TOKEN))


@pytest.mark.parametrize("purpose", ["posture", "collector", "verifier"])
def test_metadata_roundtrip_has_no_credentials_or_authentication_claim(purpose):
    sessions, expected, issuance, observed, credentials = parts(purpose)
    for value in (expected, issuance, observed):
        wire = json.loads(json.dumps(value.to_metadata()))
        restored = type(value).from_metadata(wire)
        assert restored == value
        assert all(secret not in json.dumps(wire) for secret in (SECRET, TOKEN))
        if value is issuance:
            assert wire["access_key_id"] == KEY_ID
            assert KEY_ID not in repr(value)
        else:
            assert KEY_ID not in json.dumps(wire)
    bound = sessions.assemble_session(expected, issuance, observed, credentials, now=BASE_TIME)
    public = bound.public_dict()
    assert public["purpose"] == purpose
    assert public["state"] == "offline_unverified_session_observation"
    assert public["authenticated"] is False
    assert public["closure_available"] is False
    assert public["trusted_findings_available"] is False
    assert all(secret not in json.dumps(public) for secret in (KEY_ID, SECRET, TOKEN))
    with pytest.raises(FrozenInstanceError):
        bound._credentials = Credentials(KEY_ID, "other", TOKEN, method="explicit")


@pytest.mark.parametrize(
    "changes",
    [
        {"account": "2" * 12},
        {"account": 1},
        {"account": ""},
        {"region": "us-west-2"},
        {"role_arn": f"arn:aws:iam::{ACCOUNT}:root"},
        {"role_arn": f"arn:aws:iam::{ACCOUNT}:user/Offline"},
        {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/OfflineAdmin"},
        {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/root/Offline"},
        {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/../Offline"},
        {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/path//Offline"},
        {"role_id": "AIDA" + "A" * 17},
        {"role_id": None},
        {"assumed_role_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Other/offline"},
        {"assumed_role_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/OfflinePosture/x"},
        {"assumed_role_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/OfflinePosture/offline/extra"},
        {"purpose": "posture"},
        {"purpose": "administrator"},
        {"prohibited_peers": []},
        {"prohibited_peers": (object(),)},
    ],
)
def test_expected_identity_rejects_unscoped_or_privileged_principals(changes):
    _, expected, _, _, _ = parts()
    with pytest.raises(EvidenceError):
        replace(expected, **changes)


def test_role_paths_and_exact_session_are_bound_without_archive_resources():
    sessions, expected, issuance, observed, credentials = parts()
    expected = replace(expected, role_arn=f"arn:aws:iam::{ACCOUNT}:role/team/OfflinePosture")
    bound = sessions.assemble_session(expected, issuance, observed, credentials, now=BASE_TIME)
    assert bound.lease.principal_arn.endswith("/OfflinePosture/offline")


@pytest.mark.parametrize("purpose", ["collector", "verifier"])
def test_archive_roles_require_explicit_distinct_prohibited_peers(purpose):
    sessions, expected, _, _, _ = parts(purpose)
    own = sessions.PeerIdentity(expected.role_arn, expected.role_id, expected.purpose)
    for peers in (
        (),
        (own,),
        (replace(own, role_id="AROA" + "C" * 17),),
        (replace(own, role_arn=f"arn:aws:iam::{ACCOUNT}:role/Other"),),
        expected.prohibited_peers * 2,
    ):
        with pytest.raises(EvidenceError):
            replace(expected, prohibited_peers=peers)


def test_archive_identity_rejects_one_unrelated_peer_without_complementary_purposes():
    _, expected, _, _, _ = parts("collector")
    with pytest.raises(EvidenceError):
        replace(expected, prohibited_peers=expected.prohibited_peers[:1])


def test_peer_metadata_requires_an_explicit_known_purpose():
    sessions, _, _, _, _ = parts()
    with pytest.raises(EvidenceError):
        sessions.PeerIdentity.from_metadata(
            {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/Unrelated", "role_id": "AROA" + "B" * 17}
        )


def test_cross_account_peer_cannot_complete_archive_separation():
    _, expected, _, _, _ = parts("collector")
    foreign = replace(
        expected.prohibited_peers[0], role_arn="arn:aws:iam::" + "2" * 12 + ":role/Foreign"
    )
    with pytest.raises(EvidenceError):
        replace(expected, prohibited_peers=(foreign, *expected.prohibited_peers[1:]))


@pytest.mark.parametrize("purpose", ["collector", "verifier"])
def test_archive_peers_cover_exact_other_purposes_and_have_distinct_roles(purpose):
    sessions, expected, _, _, _ = parts(purpose)
    first, second = expected.prohibited_peers
    wrong = sessions.PeerIdentity(
        f"arn:aws:iam::{ACCOUNT}:role/Unrelated", "AROA" + "D" * 17, expected.purpose
    )
    for peers in (
        (first,),
        (second,),
        (first, wrong),
        (first, replace(second, purpose=first.purpose)),
        (first, replace(second, role_arn=first.role_arn)),
        (first, replace(second, role_id=first.role_id)),
    ):
        with pytest.raises(EvidenceError):
            replace(expected, prohibited_peers=peers)


def test_posture_can_have_no_future_peers_or_explicit_distinct_known_peers():
    sessions, expected, _, _, _ = parts()
    peer = sessions.PeerIdentity(
        f"arn:aws:iam::{ACCOUNT}:role/KnownCollector",
        "AROA" + "B" * 17,
        sessions.Purpose.COLLECTOR,
    )
    assert replace(expected, prohibited_peers=(peer,)).prohibited_peers == (peer,)
    with pytest.raises(EvidenceError):
        replace(expected, prohibited_peers=(replace(peer, purpose=sessions.Purpose.POSTURE),))
    with pytest.raises(EvidenceError):
        replace(peer, purpose="collector")


@pytest.mark.parametrize(
    "changes",
    [
        {"issued_at": BASE_TIME.replace(tzinfo=None)},
        {"issued_at": None},
        {"expires_at": BASE_TIME - timedelta(minutes=1)},
        {"expires_at": BASE_TIME + timedelta(hours=1)},
        {"source": "owner_supplied_temporary_session"},
        {"source": "environment"},
        {"provenance": ""},
        {"provenance": "bad\nobservation"},
        {"provenance": None},
        {"mfa_required": False},
        {"mfa_required": 1},
        {"mfa": None},
        {"mfa": SimpleNamespace(observed=True)},
        {"access_key_id": "AKIA" + "Q" * 16},
        {"access_key_id": "ASIAshort"},
        {"access_key_id": None},
        {"access_key_id": ""},
    ],
)
def test_issuance_requires_explicit_source_time_and_mfa(changes):
    _, _, issuance, _, _ = parts()
    with pytest.raises(EvidenceError):
        replace(issuance, **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"observed": False},
        {"observed": None},
        {"observed": 1},
        {"observed": "true"},
        {"provenance": ""},
        {"provenance": "unknown"},
        {"provenance": "unverified"},
        {"observed_at": None},
        {"observed_at": BASE_TIME.replace(tzinfo=None)},
    ],
)
def test_mfa_unknown_false_and_missing_provenance_are_rejected(changes):
    _, _, issuance, _, _ = parts()
    with pytest.raises(EvidenceError):
        replace(issuance.mfa, **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"account": "2" * 12},
        {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/Other/offline"},
        {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/OfflinePosture/other"},
        {"user_id": "AROA" + "B" * 17 + ":offline"},
        {"user_id": ROLE_ID + ":other"},
        {"observed_at": BASE_TIME + timedelta(seconds=1)},
        {"observed_at": BASE_TIME - timedelta(seconds=61)},
        {"observed_at": BASE_TIME - timedelta(minutes=2)},
    ],
)
def test_sts_observation_is_exact_and_fresh_but_cannot_supply_session_facts(changes):
    sessions, expected, issuance, observed, credentials = parts()
    with pytest.raises(EvidenceError):
        sessions.assemble_session(
            expected, issuance, replace(observed, **changes), credentials, now=BASE_TIME
        )


@pytest.mark.parametrize("field", ["arn", "user_id", "account", "observed_at"])
def test_malformed_sts_observation_is_rejected(field):
    _, _, _, observed, _ = parts()
    with pytest.raises(EvidenceError):
        replace(observed, **{field: None})


@pytest.mark.parametrize(
    "field,value",
    [
        ("arn", f"arn:aws:iam::{ACCOUNT}:root"),
        ("arn", f"arn:aws:iam::{ACCOUNT}:user/Offline"),
        ("arn", f"arn:aws:sts::{ACCOUNT}:assumed-role/Admin/offline"),
        ("user_id", "AIDA" + "A" * 17),
        ("account", "bad"),
    ],
)
def test_sts_principal_must_be_an_assumed_nonadministrative_role(field, value):
    _, _, _, observed, _ = parts()
    with pytest.raises(EvidenceError):
        replace(observed, **{field: value})


@pytest.mark.parametrize("delta", [timedelta(seconds=1), -timedelta(seconds=61)])
def test_mfa_observation_cannot_be_future_or_stale(delta):
    _, _, issuance, _, _ = parts()
    changed = replace(issuance, mfa=replace(issuance.mfa, observed_at=BASE_TIME + delta))
    with pytest.raises(EvidenceError):
        assemble(issuance=changed)


@pytest.mark.parametrize(
    "now",
    [
        BASE_TIME - timedelta(minutes=2),
        BASE_TIME + timedelta(minutes=29),
        BASE_TIME + timedelta(minutes=30),
        BASE_TIME.replace(tzinfo=None),
        None,
    ],
)
def test_bound_session_rejects_future_expired_or_invalid_clock(now):
    bound = assemble()
    with pytest.raises(EvidenceError):
        bound.check(now)


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "env"),
        ("method", "shared-credentials-file"),
        ("access_key", "AKIA" + "Q" * 16),
        ("access_key", "ASIAshort"),
        ("secret_key", ""),
        ("secret_key", None),
        ("token", None),
        ("token", ""),
        ("account_id", "2" * 12),
    ],
)
def test_only_explicit_static_temporary_credentials_can_be_bound(field, value):
    _, _, _, _, credentials = parts()
    setattr(credentials, field, value)
    with pytest.raises(EvidenceError):
        assemble(credentials=credentials)


def test_preassembly_same_role_credentials_cannot_substitute_a_different_temporary_key():
    changed = Credentials("ASIA" + "R" * 16, SECRET, TOKEN, method="explicit")
    with pytest.raises(EvidenceError):
        assemble(credentials=changed)


def test_refreshing_subclass_and_discovery_shaped_credentials_are_rejected():
    class SubclassCredentials(Credentials):
        pass

    refreshable = RefreshableCredentials(KEY_ID, SECRET, TOKEN, BASE_TIME, lambda: {}, "explicit")
    for credentials in (
        refreshable,
        SubclassCredentials(KEY_ID, SECRET, TOKEN, method="explicit"),
        SimpleNamespace(access_key=KEY_ID, secret_key=SECRET, token=TOKEN, method="explicit"),
        None,
    ):
        with pytest.raises(EvidenceError):
            assemble(credentials=credentials)


@pytest.mark.parametrize(
    "field,value",
    [
        ("access_key", "ASIA" + "R" * 16),
        ("secret_key", "substituted-private-secret"),
        ("token", "substituted-private-token"),
        ("method", "env"),
        ("account_id", ACCOUNT),
        ("get_frozen_credentials", lambda: None),
    ],
)
def test_same_object_credential_component_substitution_is_detected_without_secrets(field, value):
    bound = assemble()
    setattr(bound.credentials, field, value)
    with pytest.raises(EvidenceError) as error:
        bound.check(BASE_TIME)
    public_text = repr(bound) + str(error.value) + json.dumps(bound.public_dict())
    assert all(secret not in public_text for secret in (KEY_ID, SECRET, TOKEN, str(value)))


def test_explicit_matching_credential_account_and_maximum_hour_are_accepted():
    _, _, issuance, _, credentials = parts()
    credentials.account_id = ACCOUNT
    issuance = replace(issuance, issued_at=BASE_TIME, expires_at=BASE_TIME + timedelta(hours=1))
    bound = assemble(credentials=credentials, issuance=issuance)
    bound.check(BASE_TIME + timedelta(seconds=60))


@pytest.mark.parametrize("slot", ["expected", "issuance", "observed"])
def test_assembly_requires_exact_contract_types(slot):
    with pytest.raises(EvidenceError):
        assemble(**{slot: SimpleNamespace()})


@pytest.mark.parametrize("slot", ["expected", "issuance", "observed"])
@pytest.mark.parametrize(
    "extra",
    ["authenticated", "credentials", "region", "expires_at", "mfa", "client_factory", "source"],
)
def test_metadata_rejects_unknown_and_source_authentication_fields(slot, extra):
    _, expected, issuance, observed, _ = parts()
    value = {"expected": expected, "issuance": issuance, "observed": observed}[slot]
    wire = value.to_metadata()
    if extra in wire:
        return
    wire[extra] = "forged"
    with pytest.raises(EvidenceError):
        type(value).from_metadata(wire)


@pytest.mark.parametrize("slot", ["expected", "issuance", "observed"])
def test_metadata_rejects_missing_fields_nonobjects_and_bad_timestamps(slot):
    _, expected, issuance, observed, _ = parts()
    value = {"expected": expected, "issuance": issuance, "observed": observed}[slot]
    for wire in (None, [], {}, {**value.to_metadata(), next(iter(value.to_metadata())): None}):
        with pytest.raises(EvidenceError):
            type(value).from_metadata(wire)


def test_nested_metadata_rejects_forged_mfa_peer_source_and_times():
    _, expected, issuance, observed, _ = parts("collector")
    malformed = []
    wire = issuance.to_metadata()
    for field, value in (
        ("source", "environment"),
        ("issued_at", "not-a-time"),
        ("expires_at", 1),
        ("mfa_required", "true"),
        ("mfa", {**wire["mfa"], "authenticated": True}),
        ("mfa", {**wire["mfa"], "observed": "true"}),
        ("mfa", {**wire["mfa"], "observed_at": "bad-time"}),
    ):
        malformed.append((type(issuance), {**wire, field: value}))
    wire = expected.to_metadata()
    for field, value in (
        ("purpose", "administrator"),
        ("prohibited_peers", "peer"),
        ("prohibited_peers", [{"role_arn": "role", "role_id": "id", "future_role": True}]),
        ("prohibited_peers", [{"role_arn": "role", "role_id": "id"}]),
    ):
        malformed.append((type(expected), {**wire, field: value}))
    malformed.append((type(observed), {**observed.to_metadata(), "observed_at": "bad-time"}))
    for contract, wire in malformed:
        with pytest.raises(EvidenceError):
            contract.from_metadata(wire)


def test_bound_session_cannot_be_created_without_assembly():
    sessions, _, _, _, _ = parts()
    with pytest.raises(EvidenceError):
        sessions.BoundSession()
