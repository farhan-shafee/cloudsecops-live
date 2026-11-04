"""Credential substitution must fail before fake service access or body exposure."""

import pytest

from cloudsecops_live.errors import EvidenceError
from tests.aws_sdk_helpers import Body
from tests.test_aws_sdk_transport import make


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        pytest.fail("credential-binding regressions must never use a socket")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


@pytest.mark.parametrize("component", ["access_key", "secret_key", "token", "method", "account_id"])
def test_in_place_credential_substitution_cannot_dispatch(component):
    transport, clients, _, _ = make()
    credentials = clients["sts"]._request_signer._credentials
    setattr(credentials, component, "generated-substitution-marker")
    with pytest.raises(EvidenceError, match="AWS_SDK_CREDENTIAL_BINDING") as rejected:
        transport.caller_identity()
    assert all(client.calls == [] for client in clients.values())
    assert "generated-substitution-marker" not in str(rejected.value)


def test_injected_credential_provider_callback_is_rejected_without_calling_it():
    transport, clients, _, _ = make()
    credentials = clients["sts"]._request_signer._credentials
    invoked = []

    def forbidden_callback():
        invoked.append(True)
        raise AssertionError("must not resolve any credential provider")

    credentials.get_frozen_credentials = forbidden_callback
    with pytest.raises(EvidenceError, match="AWS_SDK_CREDENTIAL_BINDING"):
        transport.caller_identity()
    assert not invoked
    assert all(client.calls == [] for client in clients.values())


@pytest.mark.parametrize("component", ["secret_key", "token"])
def test_substitution_during_stream_read_closes_without_exposing_bytes(component):
    transport, clients, reference, data = make()
    credentials = clients["sts"]._request_signer._credentials

    class MutatingBody(Body):
        def read(self, size=-1):
            setattr(credentials, component, "generated-substitution-marker")
            return super().read(size)

    raw = MutatingBody(data)
    response = clients["s3"].responses["get_object"]()
    response["Body"] = raw
    clients["s3"].responses["get_object"] = response
    body = transport.get_object(reference, reference.size + 1).stream
    with pytest.raises(EvidenceError, match="AWS_SDK_CREDENTIAL_BINDING"):
        body.read()
    assert raw.closed
