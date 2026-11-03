"""A genuine loopback HTTPS exchange trusts only the generated local certificate."""

from __future__ import annotations

import socket

from cloudsecops_live.workspace_config import write_private_json
from scripts.workspace_smoke import run_smoke
from tests.integration.test_workspace_security import (  # noqa: F401
    PASSWORD,
    workspace,
    workspace_password_hash,
)


def test_real_https_socket_login_and_assigned_case_with_explicit_certificate(
    workspace,  # noqa: F811
    tmp_path,
):
    # Bind only to discover an unused local port; the smoke helper verifies server readiness.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = workspace.config
    from psycopg.conninfo import make_conninfo

    path = tmp_path / "runtime.json"
    write_private_json(
        path,
        {
            "origin": f"https://127.0.0.1:{port}",
            "gate_dsn": make_conninfo(**config.gate_db._values),
            "certificate": str(config.certificate),
            "key": str(config.key),
            "accounts": list(workspace.accounts.values()),
        },
    )
    result = run_smoke(path, "alice", PASSWORD, expected_case_id=workspace.cases[0]["case_id"])
    assert result == {
        "https": True,
        "certificate_verified": True,
        "login": True,
        "authenticated_read": True,
        "secrets_in_receipt": False,
    }
    assert PASSWORD not in str(result)
    assert "postgresql://" not in str(result)
