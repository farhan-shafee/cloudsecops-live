"""Reference-only verifier execution and sanitized private configuration failures."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.independent_verifier import CHECKER_DEFINITION_SHA256, source_digest
from cloudsecops_live.verifier_cli import main
from cloudsecops_live.verifier_runtime import VerifierConfig, load_config, run_verification
from tests.helpers import event
from tests.test_independent_verifier import snapshot


def config():
    return VerifierConfig(
        Database("host=127.0.0.1 port=5432 dbname=csl_test_runtime user=verifier password=private"),
        "a" * 32,
        "b" * 64,
    )


def test_runtime_reads_one_manifest_original_and_finishes_computed_report(monkeypatch):
    import cloudsecops_live.verifier_runtime as runtime

    bundle, blobs = snapshot([event("a", 0), event("b", 30), event("c", 60)])
    calls = []

    class Store:
        def __init__(self, db):
            pass

        def identity(self):
            return {
                "verifier_id": "a" * 32,
                "case_id": "b" * 64,
                "checker_policy": "synthetic-aws-lab-001-independent/1",
                "checker_version": "1.0",
                "checker_source_digest": source_digest(),
            }

        def begin(self, recid, version, run_id=None):
            calls.append(("begin", recid, version, run_id))
            return bundle

        def original(self, request_id, raw_id):
            calls.append(("original", request_id, raw_id))
            return blobs.get(raw_id)

        def finish(self, request_id, report):
            calls.append(("finish", request_id))
            assert report["result"] == "verified"
            return {"receipt_id": "c" * 32, "result": report["result"]}

    monkeypatch.setattr(runtime, "_store", lambda db: Store(db))
    assert run_verification(config(), "d" * 64, 1, "e" * 32)["result"] == "verified"
    assert [c[0] for c in calls] == ["begin", "original", "finish"]


def test_runtime_rejects_config_identity_and_case_substitution_before_reads(monkeypatch):
    import cloudsecops_live.verifier_runtime as runtime

    class Store:
        def identity(self):
            return {"verifier_id": "f" * 32, "case_id": "b" * 64}

    monkeypatch.setattr(runtime, "_store", lambda db: Store())
    with pytest.raises(EvidenceError):
        run_verification(config(), "d" * 64, 1)


@pytest.mark.parametrize(
    ("rid", "version", "run_id"),
    [
        ("https://bad", 1, None),
        ("d" * 64, True, None),
        ("d" * 64, 0, None),
        ("d" * 64, 1, "role=owner"),
        ("D" * 64, 1, None),
    ],
)
def test_runtime_rejects_nonreference_arguments(rid, version, run_id):
    with pytest.raises(EvidenceError):
        run_verification(config(), rid, version, run_id)


def test_private_config_exact_fields_and_no_credential_repr(monkeypatch):
    import cloudsecops_live.verifier_runtime as runtime

    value = {
        "dsn": "host=127.0.0.1 port=5432 dbname=csl_test_runtime user=verifier password=secret",
        "verifier_id": "a" * 32,
        "case_id": "b" * 64,
    }
    monkeypatch.setattr(runtime, "private_file", lambda path, max_bytes: json.dumps(value).encode())
    loaded = load_config(Path("private.json"))
    assert "secret" not in repr(loaded)
    value["result"] = "verified"
    with pytest.raises(ValueError):
        load_config(Path("private.json"))


def test_cli_never_echoes_secret_arguments_or_driver_failures(capsys, monkeypatch):
    import cloudsecops_live.verifier_cli as cli

    assert (
        main(["--config", "private", "--recommendation-id", "secret-argument", "--version", "1"])
        == 2
    )
    assert "secret-argument" not in capsys.readouterr().err
    monkeypatch.setattr(
        cli, "load_config", lambda path: (_ for _ in ()).throw(ValueError("private dsn secret"))
    )
    assert main(["--config", "private", "--recommendation-id", "a" * 32, "--version", "1"]) == 2
    assert "secret" not in capsys.readouterr().err


@pytest.mark.parametrize("fault", ["source", "case", "receipt", None])
def test_runtime_checker_pin_case_and_retained_receipt_binding(monkeypatch, fault):
    import cloudsecops_live.verifier_runtime as runtime

    bundle, _ = snapshot([event("a", 0), event("b", 30), event("c", 60)])
    receipt = {
        "verification_id": "c" * 32,
        "request_id": bundle["request_id"],
        "case_id": "b" * 64,
        "verifier_id": "a" * 32,
        "source_kind": "synthetic",
        "authenticated": False,
        "scope": "offline_synthetic_only",
        "result": "verified",
        "checker_version": "1.0",
        "checker_digest": CHECKER_DEFINITION_SHA256,
        "source_digest": source_digest(),
    }
    bundle["retained_receipt"] = receipt
    if fault == "case":
        bundle["case_id"] = "f" * 64
    elif fault == "receipt":
        receipt["verifier_id"] = "f" * 32

    class Store:
        def identity(self):
            return {
                "verifier_id": "a" * 32,
                "case_id": "b" * 64,
                "checker_policy": "synthetic-aws-lab-001-independent/1",
                "checker_version": "1.0",
                "checker_source_digest": "0" * 64 if fault == "source" else source_digest(),
            }

        def begin(self, *args):
            return bundle

    monkeypatch.setattr(runtime, "_store", lambda db: Store())
    if fault:
        with pytest.raises(EvidenceError):
            run_verification(config(), "d" * 64, 1)
    else:
        assert run_verification(config(), "d" * 64, 1) == receipt


@pytest.mark.parametrize(
    "document",
    [
        "[]",
        '{"dsn": "x", "dsn": "y"}',
        '{"dsn": 3, "verifier_id": "a", "case_id": "b"}',
        '{"dsn": "x", "verifier_id": 3, "case_id": "b"}',
        '{"dsn": "x", "verifier_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "case_id": 3}',
    ],
)
def test_private_configuration_rejects_duplicate_keys_and_wrong_types(document, monkeypatch):
    import cloudsecops_live.verifier_runtime as runtime

    monkeypatch.setattr(runtime, "private_file", lambda *args, **kwargs: document.encode())
    with pytest.raises(ValueError):
        load_config(Path("private.json"))


@pytest.mark.parametrize(
    ("result", "status"), [("verified", 0), ("contradicted", 1), ("inconclusive", 1)]
)
def test_cli_emits_only_receipt_references_and_explicit_scope(result, status, monkeypatch, capsys):
    import cloudsecops_live.verifier_cli as cli

    monkeypatch.setattr(cli, "load_config", lambda path: config())
    monkeypatch.setattr(
        cli,
        "run_verification",
        lambda *args: {
            "verification_id": "f" * 32,
            "request_id": "e" * 32,
            "result": result,
            "checker_version": "1.0",
            "checker_digest": CHECKER_DEFINITION_SHA256,
            "private_payload": "not public",
            "dsn": "not public",
        },
    )
    assert (
        main(["--config", "private", "--recommendation-id", "d" * 64, "--version", "1"]) == status
    )
    output = json.loads(capsys.readouterr().out)
    assert output["verification_id"] == "f" * 32
    assert output["authenticated"] is False
    assert "private_payload" not in output
    assert "dsn" not in output


def test_cli_rejects_verdict_flags_without_echoing_the_value(capsys):
    assert main(["--result", "private-payload"]) == 2
    assert "private-payload" not in capsys.readouterr().err


def test_installed_cli_entrypoint_uses_sanitized_reference_only_parser(monkeypatch, capsys):
    import cloudsecops_live.verifier_cli as cli

    monkeypatch.setattr(sys, "argv", ["verifier", "--result", "private-payload"])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(cli.__file__, run_name="__main__")
    assert stopped.value.code == 2
    assert "private-payload" not in capsys.readouterr().err
