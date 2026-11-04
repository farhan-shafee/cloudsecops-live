"""Aggregate budgets around dedicated injected clients; never constructs a client.

Use only with the existing guarded adapter inside the isolated worker. Client objects
are trusted local code, not request data. No raw exception text enters public receipts.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_runner.contracts import OperationBudget

_OPERATIONS = {
    "sts": {"get_caller_identity": "GetCallerIdentity"},
    "s3": {
        "list_object_versions": "ListObjectVersions",
        "head_object": "HeadObject",
        "get_object": "GetObject",
    },
    "cloudtrail": {
        "get_trail": "GetTrail",
        "get_trail_status": "GetTrailStatus",
        "get_event_selectors": "GetEventSelectors",
        "get_insight_selectors": "GetInsightSelectors",
    },
}
_TRANSIENT = {
    "RequestTimeout",
    "RequestTimeoutException",
    "SlowDown",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "InternalError",
    "InternalFailure",
    "InternalServerError",
}
_NETWORK = (ConnectionClosedError, ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError)


def _retryable(error: Exception) -> bool:
    if isinstance(error, _NETWORK):
        return True
    if isinstance(error, ClientError):
        response = error.response
        return (
            type(response) is dict
            and type(response.get("Error")) is dict
            and isinstance(response["Error"].get("Code"), str)
            and response["Error"].get("Code") in _TRANSIENT
            and type(response.get("ResponseMetadata")) is dict
            and type(response["ResponseMetadata"].get("HTTPStatusCode")) is int
            and response["ResponseMetadata"].get("HTTPStatusCode")
            in (400, 408, 429, 500, 502, 503, 504)
        )
    return False


class _WireBudget:
    def __init__(self, raw: Any, budget: OperationBudget) -> None:
        self._raw, self._budget = raw, budget

    def read1(self, amt: int, *, decode_content: bool) -> bytes:
        self._budget.check()
        try:
            value = self._raw.read1(amt, decode_content=decode_content)
            if not isinstance(value, bytes):
                raise EvidenceError("AWS_RUN_WIRE")
            self._budget.consume_wire_bytes(len(value))
            return value
        except Exception:
            self._budget.invalidate()
            raise

    def close(self) -> None:
        self._raw.close()


class _ClientBudget:
    def __init__(self, service: str, client: Any, budget: OperationBudget) -> None:
        self._service, self._client, self._budget = service, client, budget
        self._retry_pending: set[tuple[str, tuple[tuple[str, object], ...]]] = set()
        # These are the original guarded adapter's explicit, reviewed compatibility fields.
        self.meta = client.meta
        self._endpoint = client._endpoint
        self._request_signer = client._request_signer

    def __getattr__(self, name: str) -> Callable[..., object]:
        if name not in _OPERATIONS[self._service]:
            self._budget.invalidate()
            raise EvidenceError("AWS_RUN_OPERATION")
        operation = _OPERATIONS[self._service][name]

        def invoke(**parameters: object) -> object:
            # Validation precedes the key: hostile nested/unhashable values are denied
            # by the contract rather than interpreted or sent to an SDK client.
            self._budget.check()
            try:
                fingerprint = (operation, tuple(sorted(parameters.items())))
                hash(fingerprint)
            except (TypeError, ValueError):
                self._budget.invalidate()
                raise EvidenceError("AWS_RUN_PARAMETERS") from None
            retry = fingerprint in self._retry_pending
            if not retry:
                self._budget.begin_operation()
            self._budget.reserve_attempt(self._service, operation, parameters, retry=retry)
            try:
                result = getattr(self._client, name)(**parameters)
                self._budget.check()
                self._retry_pending.discard(fingerprint)
                return result
            except Exception as error:
                if _retryable(error):
                    self._retry_pending.add(fingerprint)
                elif (
                    self._service == "cloudtrail"
                    and operation == "GetInsightSelectors"
                    and isinstance(error, ClientError)
                    and type(error.response) is dict
                    and type(error.response.get("Error")) is dict
                    and type(error.response.get("ResponseMetadata")) is dict
                    and type(error.response["ResponseMetadata"].get("HTTPStatusCode")) is int
                    and error.response.get("Error", {}).get("Code") == "InsightNotEnabledException"
                    and error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 400
                ):
                    # The existing adapter classifies this exact modeled response
                    # as a disabled observation, rather than a failed source read.
                    self._retry_pending.discard(fingerprint)
                else:
                    self._budget.invalidate()
                raise

        return invoke


class BudgetedClients:
    """Dedicated clients with a shared run budget, prior to AwsSdkTransport wrapping.

    No implicit retries. A retry repeats the exact failed call and consumes the
    shared retry ceiling. Control/error and object body bytes share one wire cap.
    The existing adapter still validates credentials, TLS, responses and source scope.
    """

    def __init__(self, clients: Mapping[str, Any], budget: OperationBudget) -> None:
        if set(clients) != set(_OPERATIONS) or type(budget) is not OperationBudget:
            raise EvidenceError("AWS_RUN_CLIENTS")
        self.sts = _ClientBudget("sts", clients["sts"], budget)
        self.s3 = _ClientBudget("s3", clients["s3"], budget)
        self.cloudtrail = _ClientBudget("cloudtrail", clients["cloudtrail"], budget)
        sessions: set[int] = set()
        for client in clients.values():
            session = client._endpoint.http_session
            if id(session) in sessions:
                continue
            sessions.add(id(session))
            original = session.send

            def send(request: Any, delegate: Callable[[Any], Any] = original) -> object:
                budget.check()
                response = delegate(request)
                budget.check()
                response.raw = _WireBudget(response.raw, budget)
                return response

            session.send = send
