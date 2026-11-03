"""Real loopback TLS workflow and separate restricted verifier; no cloud execution."""

from __future__ import annotations

import argparse
import getpass
import gzip
import json
import re
import ssl
import subprocess
import sys
import time
import warnings
from collections.abc import Callable
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Never
from uuid import uuid4

import httpx
import psycopg

from cloudsecops_live.workspace_config import load_config


class Forms(HTMLParser):
    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: dict[str, dict[str, str]] = {}
        self.action: str | None = None
        self.pre = False
        self.proof: list[str] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self.action = values.get("action")
            if self.action:
                self.forms[self.action] = {}
        elif tag == "input" and self.action and values.get("name"):
            self.forms[self.action][str(values["name"])] = values.get("value") or ""
        elif tag == "pre":
            self.pre = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.action = None
        elif tag == "pre":
            self.pre = False

    def handle_data(self, data: str) -> None:
        if self.pre:
            self.proof.append(data)


def _page(client: httpx.Client, origin: str, case_id: str) -> tuple[Forms, dict[str, Any]]:
    response = client.get(f"{origin}/cases/{case_id}/workflow")
    if response.status_code != 200:
        raise RuntimeError("workflow_read_failed")
    parsed = Forms(response.text)
    value = json.loads("".join(parsed.proof))
    if value.get("case_id") != case_id:
        raise RuntimeError("workflow_reference_mismatch")
    return parsed, value


def _post(client: httpx.Client, origin: str, target: str, data: dict[str, str]) -> None:
    if client.post(origin + target, data=data, headers={"Origin": origin}).status_code != 303:
        raise RuntimeError("workflow_mutation_failed")


def _login(client: httpx.Client, origin: str, username: str, password: str) -> None:
    page = client.get(origin + "/login")
    if page.status_code != 200:
        raise RuntimeError("workflow_login_unavailable")
    fields = Forms(page.text).forms["/login"]
    _post(client, origin, "/login", {**fields, "username": username, "password": password})


def run_smoke(
    workspace_config: Path,
    verifier_config: Path,
    analyst: str,
    analyst_password: str,
    reviewer: str,
    reviewer_password: str,
    case_id: str,
    *,
    demonstrate_change: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Passwords stay in memory/TLS; verifier receives only private config and references.

    An optional offline operator callback adds/publishes controlled synthetic
    evidence. It is never exposed by the web application or verifier process.
    The demonstration first proves a valid close form becomes stale, then closes
    a newly reviewed version; a second change proves audited reopening.
    """
    if analyst == reviewer or not re.fullmatch(r"[0-9a-f]{64}", case_id):
        raise ValueError("distinct_assigned_identities_required")
    config = load_config(workspace_config)
    trust = ssl.create_default_context(cafile=str(config.certificate))
    command = [
        sys.executable,
        "-m",
        "cloudsecops_live",
        "workspace",
        "serve",
        "--config",
        str(workspace_config.absolute()),
    ]
    server = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with (
            httpx.Client(
                verify=trust, trust_env=False, timeout=5, follow_redirects=False
            ) as author,
            httpx.Client(verify=trust, trust_env=False, timeout=5, follow_redirects=False) as judge,
        ):
            deadline = time.monotonic() + 30
            while True:
                if server.poll() is not None:
                    raise RuntimeError("workflow_server_unavailable")
                try:
                    if author.get(config.origin + "/login").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("workflow_server_unavailable")
                time.sleep(0.1)
            _login(author, config.origin, analyst, analyst_password)
            _login(judge, config.origin, reviewer, reviewer_password)

            def recommend_review_verify() -> tuple[dict[str, str], dict[str, Any]]:
                page, _ = _page(author, config.origin, case_id)
                target = f"/cases/{case_id}/recommendations"
                _post(
                    author,
                    config.origin,
                    target,
                    {
                        **page.forms[target],
                        "rationale": "Authorized synthetic inventory; no action requested.",
                        "counterevidence": "Inventory, retries and pagination can be benign.",
                        "visibility_gaps": (
                            "Synthetic evidence cannot prove authenticity or absence."
                        ),
                    },
                )
                page, view = _page(judge, config.origin, case_id)
                rec = view["current_recommendation"]
                target = (
                    f"/cases/{case_id}/recommendations/"
                    f"{rec['recommendation_id']}/{rec['version']}/review"
                )
                _post(
                    judge,
                    config.origin,
                    target,
                    {
                        **page.forms[target],
                        "decision": "approve",
                        "reason": "Reviewed this exact synthetic recommendation and limits.",
                    },
                )
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "cloudsecops_live",
                        "verifier",
                        "--config",
                        str(verifier_config.absolute()),
                        "--recommendation-id",
                        rec["recommendation_id"],
                        "--version",
                        str(rec["version"]),
                        "--run-id",
                        uuid4().hex,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != 0:
                    raise RuntimeError("independent_verifier_failed")
                receipt = json.loads(result.stdout)
                if receipt.get("result") != "verified" or receipt.get("authenticated") is not False:
                    raise RuntimeError("independent_verifier_failed")
                page, view = _page(judge, config.origin, case_id)
                return page.forms[f"/cases/{case_id}/close"], view

            close_form, view = recommend_review_verify()
            if demonstrate_change is not None:
                demonstrate_change()
                denied = judge.post(
                    config.origin + f"/cases/{case_id}/close",
                    data={**close_form, "reason": "Stale evidence must block closure."},
                    headers={"Origin": config.origin},
                )
                if denied.status_code != 409:
                    raise RuntimeError("changed_evidence_not_rejected")
                close_form, view = recommend_review_verify()
            _post(
                judge,
                config.origin,
                f"/cases/{case_id}/close",
                {
                    **close_form,
                    "reason": "Close this reviewed synthetic no-action exercise only.",
                },
            )
            _, closed = _page(judge, config.origin, case_id)
            if closed["state"] != "closed" or not closed["closures"]:
                raise RuntimeError("synthetic_closure_failed")
            rec = closed["current_recommendation"]
            result_summary: dict[str, Any] = {
                "https": True,
                "certificate_verified": True,
                "recommendation": True,
                "distinct_review": True,
                "independent_verifier": True,
                "synthetic_exercise_closed": True,
                "source_kind": "synthetic",
                "authenticated": False,
                "scope": "offline_synthetic_only",
                "secrets_in_receipt": False,
                "case_id": case_id,
                "recommendation_id": rec["recommendation_id"],
                "recommendation_version": rec["version"],
                "review_id": rec["review"]["review_id"],
                "verification_id": rec["verification"]["verification_id"],
                "closure_id": closed["closures"][-1]["closure_id"],
                "final_state": "closed",
            }
            if demonstrate_change is not None:
                demonstrate_change()
                page, changed = _page(judge, config.origin, case_id)
                if (
                    changed["state"] != "reopen_required"
                    or changed["closures"] != closed["closures"]
                ):
                    raise RuntimeError("closure_history_or_invalidation_failed")
                target = f"/cases/{case_id}/reopen"
                _post(
                    judge,
                    config.origin,
                    target,
                    {
                        **page.forms[target],
                        "reason": "New evidence requires an explicit new auditable workflow.",
                    },
                )
                _, reopened = _page(judge, config.origin, case_id)
                if reopened["state"] != "open":
                    raise RuntimeError("audited_reopen_failed")
                result_summary.update(
                    {
                        "changed_evidence_blocked_closure": True,
                        "closed_history_preserved": True,
                        "audited_reopen": True,
                        "final_state": "open",
                    }
                )
            for client in (author, judge):
                response = client.get(config.origin + "/cases")
                _post(client, config.origin, "/logout", Forms(response.text).forms["/logout"])
            return result_summary
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


def _late_change(maintenance: Path, case_id: str) -> Callable[[], None]:
    from cloudsecops_live.storage import ingest
    from cloudsecops_live.worker import work_once
    from cloudsecops_live.workspace_cli import _maintenance

    db = _maintenance(maintenance)

    def change() -> None:
        with db.connect() as conn:
            db.check_schema(conn)
            row = conn.execute(
                "WITH ordered AS (SELECT e.event_key,e.record_hash,"
                "row_number() OVER(ORDER BY (v.normalized->>'event_time')::timestamptz,"
                "e.event_key) AS position,count(*) OVER() AS total "
                "FROM csl.cases c JOIN csl.case_revisions r ON "
                "(r.case_id,r.revision)=(c.case_id,c.current_revision) "
                "JOIN csl.finding_evidence e ON e.finding_id=r.finding_id "
                "JOIN csl.record_variants v ON "
                "(v.event_key,v.record_hash)=(e.event_key,e.record_hash) "
                "WHERE c.case_id=%s AND r.payload->>'source_kind'='synthetic' "
                "AND r.payload->'authenticated'='false'::jsonb) "
                "SELECT v.canonical_bytes FROM ordered o JOIN csl.record_variants v "
                "ON (v.event_key,v.record_hash)=(o.event_key,o.record_hash) "
                "WHERE o.position=o.total/2+1",
                (case_id,),
            ).fetchone()
            if row is None:
                raise ValueError("synthetic_demo_case_required")
        record = json.loads(bytes(row["canonical_bytes"]))
        record["eventID"] = "phase3b-late-" + uuid4().hex
        data = gzip.compress(
            json.dumps(
                {"fixture_schema_version": "1.0", "source_kind": "synthetic", "Records": [record]},
                separators=(",", ":"),
            ).encode(),
            mtime=0,
        )
        ingest(
            db, [("synthetic/phase3b-late.json.gz", data)], checkpoint="phase3b-late-" + uuid4().hex
        )
        for _ in range(64):
            if work_once(db)["status"] == "idle":
                return
        raise RuntimeError("demo_worker_still_pending")

    return change


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise ValueError("reviewed_workflow_smoke_usage")


def main() -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--workspace-config", type=Path, required=True)
    parser.add_argument("--verifier-config", type=Path, required=True)
    parser.add_argument("--analyst", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--demonstrate-change", action="store_true")
    parser.add_argument("--maintenance-config", type=Path)
    try:
        options = parser.parse_args()
        if options.demonstrate_change != bool(options.maintenance_config):
            raise ValueError("explicit_change_demo_configuration_required")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            analyst_password = getpass.getpass("Analyst password: ")
            reviewer_password = getpass.getpass("Reviewer password: ")
        result = run_smoke(
            options.workspace_config,
            options.verifier_config,
            options.analyst,
            analyst_password,
            options.reviewer,
            reviewer_password,
            options.case_id,
            demonstrate_change=_late_change(options.maintenance_config, options.case_id)
            if options.demonstrate_change
            else None,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        subprocess.SubprocessError,
        httpx.HTTPError,
        psycopg.Error,
        getpass.GetPassWarning,
    ):
        print(
            '{"error":"reviewed_workflow_smoke_failed","source_kind":"synthetic","authenticated":false}',
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
