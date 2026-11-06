"""Internal fixed client assembly. The disabled public worker never calls this.

No SDK Session, provider chain, ambient model path or credential store is used.
Offline tests supply fictional BoundSession objects and replace transport sends.
"""

from __future__ import annotations

import hashlib
import json
import logging
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import botocore  # type: ignore[import-untyped]
from botocore.awsrequest import AWSResponse  # type: ignore[import-untyped]
from botocore.client import ClientCreator  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.configprovider import ConfigValueStore  # type: ignore[import-untyped]
from botocore.errorfactory import ClientExceptionsFactory  # type: ignore[import-untyped]
from botocore.exceptions import (  # type: ignore[import-untyped]
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from botocore.hooks import HierarchicalEmitter  # type: ignore[import-untyped]
from botocore.loaders import Loader  # type: ignore[import-untyped]
from botocore.parsers import ResponseParserFactory  # type: ignore[import-untyped]
from botocore.regions import EndpointResolver  # type: ignore[import-untyped]
from botocore.retryhandler import create_retry_handler  # type: ignore[import-untyped]
from botocore.translate import build_retry_config  # type: ignore[import-untyped]
from botocore.useragent import UserAgentString  # type: ignore[import-untyped]
from urllib3 import PoolManager
from urllib3.exceptions import (
    ConnectTimeoutError as WireConnectTimeout,
)
from urllib3.exceptions import (
    NewConnectionError as WireNewConnection,
)
from urllib3.exceptions import (
    ProtocolError as WireProtocolError,
)
from urllib3.exceptions import (
    ReadTimeoutError as WireReadTimeout,
)
from urllib3.util import Timeout

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.budget import PostureBudget
from cloudsecops_live.integrations.aws_posture.contracts import OwnerDecision, PostureClients
from cloudsecops_live.integrations.aws_posture.signing import FinalSigningBinding
from cloudsecops_live.integrations.aws_posture.wire import (
    GuardedSession,
    endpoint_for,
    install_response_bounds,
)
from cloudsecops_live.integrations.aws_readiness.requests import encode
from cloudsecops_live.integrations.aws_readiness.sessions import BoundSession

_SERVICES = ("sts", "iam", "cloudtrail", "s3", "s3control")
_VERSIONS = {
    "sts": "2011-06-15",
    "iam": "2010-05-08",
    "cloudtrail": "2013-11-01",
    "s3": "2006-03-01",
    "s3control": "2018-08-20",
}


def _client_endpoint(service: str, account: str) -> str:
    # The pinned S3 Control endpoint model prepends the validated AccountId.
    # Its final wire URL is still checked against endpoint_for's exact account.
    if service == "s3control":
        return "https://s3-control.us-east-1.amazonaws.com"
    return endpoint_for(service, account)


def _ca_bytes() -> bytes:
    path = Path(botocore.__file__).resolve().parent / "cacert.pem"
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("AWS4A_CA_PROVENANCE")
    with path.open("rb") as source:
        data = source.read(1024 * 1024 + 1)
    if not data or len(data) > 1024 * 1024:
        raise EvidenceError("AWS4A_CA_PROVENANCE")
    return data


def packaged_ca_sha256() -> str:
    return hashlib.sha256(_ca_bytes()).hexdigest()


def _quiet_sdk_logging() -> None:
    # Suppress only SDK/wire loggers, including preconfigured debug descendants.
    # Future children inherit this threshold. The application/root level stays
    # untouched; the actual isolated bootstrap separately discards diagnostics.
    names = tuple(logging.Logger.manager.loggerDict) + ("botocore", "boto3", "urllib3")
    for name in names:
        if any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in ("botocore", "boto3", "urllib3")
        ):
            logger = logging.getLogger(name)
            logger.setLevel(logging.CRITICAL + 1)
            logger.disabled = True


class _HTTPSAdapter:
    """No proxy/env fallback, redirects or transport retries; CA loaded from bytes."""

    def __init__(self, certificate_bytes: bytes, budget: PostureBudget) -> None:
        self._verify = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cadata=certificate_bytes.decode("ascii"))
        self._context = context
        self._ca_signature = tuple(context.get_ca_certs(binary_form=True))
        self._manager = PoolManager(
            num_pools=1,
            maxsize=1,
            ssl_context=context,
            cert_reqs=ssl.CERT_REQUIRED,
            timeout=Timeout(connect=2.0, read=2.0),
        )
        self._pool_classes_by_scheme: dict[str, Any] = {}
        install_response_bounds(self, budget)

    def check(self) -> None:
        if (
            self._verify is not True
            or self._context.verify_mode != ssl.CERT_REQUIRED
            or self._context.check_hostname is not True
            or self._context.minimum_version != ssl.TLSVersion.TLSv1_2
            or tuple(self._context.get_ca_certs(binary_form=True)) != self._ca_signature
            or self._manager.connection_pool_kw.get("ssl_context") is not self._context
            or self._manager.pool_classes_by_scheme is not self._pool_classes_by_scheme
            or set(self._pool_classes_by_scheme) != {"https"}
        ):
            raise EvidenceError("AWS4A_TLS_BINDING")

    def send(self, request: Any) -> Any:
        self.check()
        parts = urlsplit(request.url)
        target = parts.path + ("?" + parts.query if parts.query else "")
        pool = self._manager.connection_from_url(request.url)
        try:
            response = pool.urlopen(
                request.method,
                target,
                body=request.body,
                headers=request.headers,
                retries=False,
                redirect=False,
                assert_same_host=True,
                preload_content=False,
                decode_content=False,
                enforce_content_length=True,
                chunked=False,
            )
        except WireNewConnection:
            raise EndpointConnectionError(endpoint_url="approved-posture-endpoint") from None
        except WireConnectTimeout:
            raise ConnectTimeoutError(endpoint_url="approved-posture-endpoint") from None
        except WireReadTimeout:
            raise ReadTimeoutError(endpoint_url="approved-posture-endpoint") from None
        except WireProtocolError:
            raise ConnectionClosedError(endpoint_url="approved-posture-endpoint") from None
        return AWSResponse(request.url, response.status, response.headers, response)

    def close(self) -> None:
        self._manager.clear()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("AWS4A_POLICY_RESPONSE")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise EvidenceError("AWS4A_POLICY_RESPONSE")


def _policy(value: object) -> dict[str, Any]:
    try:
        if type(value) is not str or len(value) > 65536:
            raise ValueError()
        decoded = unquote(value, encoding="utf-8", errors="strict")
        document = json.loads(decoded, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if type(document) is not dict:
            raise ValueError()
        encode(document)
        return document
    except (ValueError, TypeError, RecursionError, UnicodeError, EvidenceError):
        raise EvidenceError("AWS4A_POLICY_RESPONSE") from None


def _decode_policy(parsed: Any, **kwargs: Any) -> None:
    if type(parsed) is not dict:
        raise EvidenceError("AWS4A_POLICY_RESPONSE")
    if "PolicyDocument" in parsed:
        parsed["PolicyDocument"] = _policy(parsed["PolicyDocument"])
    role = parsed.get("Role")
    if type(role) is dict and "AssumeRolePolicyDocument" in role:
        role["AssumeRolePolicyDocument"] = _policy(role["AssumeRolePolicyDocument"])


def _install_guards(
    client: Any,
    service: str,
    decision: OwnerDecision,
    session: BoundSession,
    budget: PostureBudget,
    certificate_bytes: bytes,
) -> None:
    client._endpoint.http_session.close()
    adapter = _HTTPSAdapter(certificate_bytes, budget)
    signing = FinalSigningBinding(service, client, session, budget)
    guarded = GuardedSession(service, decision.expected.account, adapter, budget, signing)
    client._endpoint.http_session = guarded

    def check(**kwargs: Any) -> None:
        budget.check()
        if (
            client._request_signer._credentials is not session.credentials
            or client._endpoint.http_session is not guarded
            or client._endpoint.host != _client_endpoint(service, decision.expected.account)
            or client.meta.config.region_name != "us-east-1"
            or client.meta.config.retries.get("total_max_attempts") != 1
            or client.meta.config.proxies != {}
        ):
            budget.invalidate()
            raise EvidenceError("AWS4A_CLIENT_BINDING")
        adapter.check()

    def parameters(params: dict[str, Any], model: Any, **kwargs: Any) -> None:
        check()
        budget.authorize_parameters(service, model.name, params)

    client.meta.events.register_first("before-parameter-build", parameters)
    client.meta.events.register_first("before-sign", check)
    if service == "iam":
        client.meta.events.register_first("after-call.iam.GetRolePolicy", _decode_policy)
        client.meta.events.register_first("after-call.iam.GetRole", _decode_policy)


def build_fixed_clients(
    decision: OwnerDecision, session: BoundSession, budget: PostureBudget
) -> PostureClients:
    """Private constructor for the eventual isolated worker, not an execution gate.

    Current production bootstrap always rejects before reaching this function.
    All executable tests replace sends and use fictional static credentials.
    """
    if (
        type(decision) is not OwnerDecision
        or type(session) is not BoundSession
        or type(budget) is not PostureBudget
        or budget.decision is not decision
        or budget.session is not session
    ):
        raise EvidenceError("AWS4A_CLIENT_BINDING")
    budget.check()
    certificate_bytes = _ca_bytes()
    if hashlib.sha256(certificate_bytes).hexdigest() != decision.ca_sha256:
        budget.invalidate()
        raise EvidenceError("AWS4A_CA_PROVENANCE")
    # This helper belongs in a fresh child. Prevent SDK/auth debug handlers from
    # disclosing signing material even if a caller configured verbose logging.
    _quiet_sdk_logging()
    package = Path(botocore.__file__).resolve().parent
    loader = Loader(
        extra_search_paths=[str(package / "data")],
        include_default_search_paths=False,
        include_default_extras=False,
    )
    store = ConfigValueStore()
    emitter = HierarchicalEmitter()
    creator = ClientCreator(
        loader=loader,
        endpoint_resolver=EndpointResolver(loader.load_data("endpoints")),
        user_agent="cloudsecops-live",
        event_emitter=emitter,
        retry_handler_factory=create_retry_handler,
        retry_config_translator=build_retry_config,
        response_parser_factory=ResponseParserFactory(),
        exceptions_factory=ClientExceptionsFactory(),
        config_store=store,
        user_agent_creator=UserAgentString("unknown", "unknown", "unknown", "3", "CPython", ""),
    )
    clients: list[Any] = []
    try:
        for service in _SERVICES:
            config = Config(
                region_name="us-east-1",
                signature_version="s3v4" if service == "s3" else "v4",
                proxies={},
                proxies_config={},
                retries={"mode": "standard", "total_max_attempts": 1},
                connect_timeout=2.0,
                read_timeout=2.0,
                max_pool_connections=1,
                parameter_validation=True,
                inject_host_prefix=False,
                ignore_configured_endpoint_urls=True,
                disable_request_compression=True,
                request_min_compression_size_bytes=10240,
                account_id_endpoint_mode="disabled",
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
                s3_disable_express_session_auth=True,
                s3={"us_east_1_regional_endpoint": "regional", "addressing_style": "path"},
            )
            client = creator.create_client(
                service,
                "us-east-1",
                endpoint_url=_client_endpoint(service, decision.expected.account),
                verify=True,
                credentials=session.credentials,
                scoped_config={},
                api_version=_VERSIONS[service],
                client_config=config,
            )
            clients.append(client)
            _install_guards(client, service, decision, session, budget, certificate_bytes)
        budget.check()
        return PostureClients(*clients)
    except Exception:
        budget.invalidate()
        for client in clients:
            client.close()
        raise EvidenceError("AWS4A_CLIENT_CONSTRUCTION") from None
