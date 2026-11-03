"""Retained fresh and forward-upgrade databases exercise real PostgreSQL catalogs."""

from collections.abc import Callable
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_roles import (
    grant_case,
    provision_user,
    setup_roles,
    validate_identity,
)
from cloudsecops_live.workspace_store import WorkspaceStore


def test_v1_upgrade_preserves_receipt(db_factory: Callable[..., Database]) -> None:
    db = db_factory(migrate=False)
    db.migrate(target_version=1)
    with db.connect() as conn:
        before = conn.execute("SELECT * FROM csl.schema_migrations").fetchone()
    setup_roles(db)
    db.migrate()
    with db.connect() as conn:
        after = conn.execute(
            "SELECT version,checksum,schema_hash,applied_at FROM "
            "csl.schema_migrations WHERE version=1"
        ).fetchone()
        assert before == after
        Database.check_schema(conn)
    with pytest.raises(EvidenceError, match="SCHEMA_INCOMPATIBLE"):
        db.migrate(target_version=1)


def test_runtime_roles_and_own_sessions(db: Database) -> None:
    first = provision_user(db, "first", "analyst", "x" * 64)
    second = provision_user(db, "second", "auditor", "y" * 64)
    a = WorkspaceStore(Database(first["auth_dsn"]), Database(first["data_dsn"]))
    b = WorkspaceStore(Database(second["auth_dsn"]), Database(second["data_dsn"]))
    token = first["user_id"] + "." + "z" * 43
    assert a.create_session(token)["user_id"] == first["user_id"]
    assert a.session(token)
    assert b.session(token) is None
    assert a.password_hash() == "x" * 64


def test_future_owner_functions_do_not_receive_public_execute(db: Database) -> None:
    account = provision_user(db, "future_probe", "auditor", "x" * 64)
    with db.connect() as conn, conn.transaction():
        # Temporary maintenance-only CREATE authority lets the test exercise the
        # actual creating role's defaults, rather than ALTER OWNER semantics.
        conn.execute("GRANT CREATE ON SCHEMA csl TO csl_ws_owner")
        conn.execute("SET LOCAL ROLE csl_ws_owner")
        conn.execute(
            "CREATE FUNCTION csl.future_owner_probe() RETURNS integer LANGUAGE sql AS 'SELECT 1'"
        )
        conn.execute("RESET ROLE")
        conn.execute("REVOKE CREATE ON SCHEMA csl FROM csl_ws_owner")
        assert (
            conn.execute(
                "SELECT 1 FROM pg_catalog.pg_proc p JOIN "
                "pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,"
                "pg_catalog.acldefault('f',p.proowner))) a WHERE "
                "n.nspname='csl' AND p.proname='future_owner_probe' "
                "AND a.grantee=0 AND a.privilege_type='EXECUTE'"
            ).fetchone()
            is None
        )
    with pytest.raises(psycopg.Error), Database(account["data_dsn"]).connect() as conn:
        conn.execute("SELECT csl.future_owner_probe()")


def test_global_owner_default_acl_tamper_is_detected(db: Database) -> None:
    account = provision_user(db, "defaults_probe", "auditor", "x" * 64)
    auth, data = Database(account["auth_dsn"]), Database(account["data_dsn"])
    WorkspaceStore(auth, data)
    with db.connect() as conn:
        conn.execute(
            "ALTER DEFAULT PRIVILEGES FOR ROLE csl_ws_owner GRANT EXECUTE ON FUNCTIONS TO PUBLIC"
        )
    with pytest.raises(EvidenceError, match="WS_SCHEMA"):
        WorkspaceStore(auth, data)
    with db.connect() as conn:
        with pytest.raises(EvidenceError, match="SCHEMA_INCOMPATIBLE"):
            Database.check_schema(conn)


def test_failed_second_migration_preserves_exact_v1_catalog(
    db_factory: Callable[..., Database],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import cloudsecops_live.database as module

    db = db_factory(migrate=False)
    db.migrate(target_version=1)
    with db.connect() as conn:
        before = module._schema_hash(conn)
        receipt = conn.execute("SELECT * FROM csl.schema_migrations").fetchall()
    broken = tmp_path / "002_broken.sql"
    broken.write_text(module._MIGRATIONS[1].read_text() + "\nSELECT no_such_function();")
    monkeypatch.setattr(module, "_MIGRATIONS", (module._MIGRATION, broken))
    with pytest.raises(psycopg.Error):
        db.migrate()
    with db.connect() as conn:
        assert module._schema_hash(conn) == before
        assert conn.execute("SELECT * FROM csl.schema_migrations").fetchall() == receipt
        assert (
            conn.execute("SELECT to_regclass('csl.ws_users') AS found").fetchone()["found"] is None
        )


def test_previous_live_catalog_is_required_before_upgrade(
    db_factory: Callable[..., Database],
) -> None:
    db = db_factory(migrate=False)
    db.migrate(target_version=1)
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.events ADD COLUMN unexpected text")
    with pytest.raises(EvidenceError, match="SCHEMA_INCOMPATIBLE"):
        db.migrate()
    with db.connect() as conn:
        assert (
            conn.execute("SELECT to_regclass('csl.ws_users') AS found").fetchone()["found"] is None
        )


def test_restore_security_refuses_structure_and_does_not_rebaseline(db: Database) -> None:
    from cloudsecops_live.workspace_roles import restore_security

    with db.connect() as conn:
        original = conn.execute("SELECT * FROM csl.schema_migrations").fetchall()
        conn.execute("ALTER TABLE csl.ws_notes ADD COLUMN unexpected text")
    with pytest.raises(EvidenceError, match="SCHEMA_INCOMPATIBLE"):
        restore_security(db)
    with db.connect() as conn:
        assert conn.execute("SELECT * FROM csl.schema_migrations").fetchall() == original


@pytest.mark.parametrize("privilege", ["SELECT(password_hash)", "UPDATE(enabled)"])
def test_column_grants_are_detected_in_catalog_and_runtime_validation(
    db: Database,
    privilege: str,
) -> None:
    account = provision_user(db, "column_probe", "analyst", "x" * 64)
    auth, data = Database(account["auth_dsn"]), Database(account["data_dsn"])
    WorkspaceStore(auth, data)
    with db.connect() as conn:
        conn.execute(
            sql.SQL("GRANT {} ON csl.ws_users TO {}").format(
                sql.SQL(privilege), sql.Identifier(data._values["user"])
            )
        )
    # An administrator can change permissions. The safety check must detect that drift.
    with pytest.raises(EvidenceError, match="WS_SCHEMA"):
        WorkspaceStore(auth, data)
    with data.connect() as conn:
        with pytest.raises(EvidenceError, match="WS_ROLES_UNSAFE"):
            validate_identity(conn, "data")
    with db.connect() as conn:
        with pytest.raises(EvidenceError, match="SCHEMA_INCOMPATIBLE"):
            Database.check_schema(conn)


@pytest.mark.parametrize(
    "authority", ["database_owner", "database_create", "public_create", "csl_create"]
)
def test_runtime_identity_rejects_database_or_schema_administration(
    db: Database,
    authority: str,
) -> None:
    account = provision_user(db, "authority_probe", "analyst", "x" * 64)
    auth, data = Database(account["auth_dsn"]), Database(account["data_dsn"])
    WorkspaceStore(auth, data)
    with db.connect() as conn:
        role = sql.Identifier(data._values["user"])
        database = sql.Identifier(db._values["dbname"])
        if authority == "database_owner":
            statement = sql.SQL("ALTER DATABASE {} OWNER TO {}").format(database, role)
        elif authority == "database_create":
            statement = sql.SQL("GRANT CREATE ON DATABASE {} TO {}").format(database, role)
        else:
            schema = sql.Identifier("public" if authority == "public_create" else "csl")
            statement = sql.SQL("GRANT CREATE ON SCHEMA {} TO {}").format(schema, role)
        conn.execute(statement)
    with pytest.raises(EvidenceError, match="WS_SCHEMA"):
        WorkspaceStore(auth, data)
    with data.connect() as conn:
        with pytest.raises(EvidenceError, match="WS_ROLES_UNSAFE"):
            validate_identity(conn, "data")


def test_restore_target_denies_runtime_connection_until_security_repaired(
    db: Database,
    db_factory: Callable[..., Database],
) -> None:
    from cloudsecops_live.workspace_roles import restore_security
    from tests.integration.test_backup import pg_command

    account = provision_user(db, "restore_probe", "analyst", "x" * 64)
    dump = pg_command(db, "pg_dump", ["--format=custom", "--no-owner", "--no-privileges"])
    restored = db_factory(migrate=False)
    pg_command(restored, "pg_restore", ["--no-owner", "--no-privileges", "--exit-on-error"], dump)
    runtime = Database(account["data_dsn"])
    restored_runtime = Database(
        make_conninfo(
            **{
                **runtime._values,
                "dbname": restored._values["dbname"],
            }
        )
    )
    with pytest.raises(psycopg.Error):
        restored_runtime.connect()
    restore_security(restored)
    with restored_runtime.connect() as conn:
        validate_identity(conn, "data")
    with pytest.raises(psycopg.Error), restored_runtime.connect() as conn:
        conn.execute("SELECT * FROM csl.ws_users")


def test_direct_sql_pagination_and_case_projections_are_bounded(db: Database) -> None:
    from cloudsecops_live.cases import revise_case
    from cloudsecops_live.storage import ingest
    from cloudsecops_live.worker import work_once
    from tests.integration.support import add, current

    add(db, [0, 20, 40])
    work_once(db)
    case = current(db)[0]
    cid = case["case_id"]
    account = provision_user(db, "bounds_probe", "analyst", "x" * 64)
    grant_case(db, "bounds_probe", cid)
    store = WorkspaceStore(Database(account["auth_dsn"]), Database(account["data_dsn"]))
    token = account["user_id"] + "." + "z" * 43
    store.create_session(token)
    for offset, limit in ((None, 20), (0, None)):
        with store.data_db.connect() as conn:
            with pytest.raises(psycopg.Error):
                conn.execute("SELECT csl.ws_list_cases(%s,%s,%s)", (token, offset, limit))
    assert "payload" not in store.list_cases(token)[0]
    with db.connect() as conn:
        revision = conn.execute(
            "SELECT * FROM csl.case_revisions WHERE case_id=%s", (cid,)
        ).fetchone()
        assert revision is not None
        for previous in range(1, 102):
            revise_case(
                conn,
                cid,
                previous,
                revision["payload"],
                revision["finding_id"],
                revision["generation"],
            )
        conn.execute(
            "INSERT INTO csl.ws_notes(note_id,user_id,case_id,revision,fingerprint,body) "
            "SELECT md5(n::text),%s,%s,102,%s,'bounded note '||n::text "
            "FROM generate_series(1,51) n",
            (account["user_id"], cid, revision["fingerprint"]),
        )
    detail = store.case(token, cid)
    assert detail is not None
    assert len(detail["history"]) == 100
    assert detail["history_count"] == 102 and detail["history_truncated"] is True
    assert detail["history"][0]["revision"] == 3
    assert set(detail["history"][0]) == {"revision", "status", "fingerprint", "created_at"}
    assert len(detail["notes"]) == 50
    assert detail["notes_count"] == 51 and detail["notes_truncated"] is True
    reference = detail["evidence"][0]
    with db.connect() as conn:
        original = conn.execute("SELECT archive_bytes FROM csl.raw_objects LIMIT 1").fetchone()
        assert original is not None
    ingest(
        db,
        [(f"source-copy-{i:02}.gz", bytes(original["archive_bytes"])) for i in range(55)],
        checkpoint="more-source-metadata",
    )
    evidence = store.evidence(token, cid, 102, reference["event_key"], reference["record_hash"])
    assert evidence is not None
    assert evidence["source_count"] == 56 and len(evidence["sources"]) == 50
    assert set(evidence["sources"][0]) == {
        "raw_id",
        "archive_hash",
        "content_hash",
        "source_ref",
        "record_index",
    }
    with db.connect() as conn:
        metadata_only = conn.execute(
            "SELECT has_column_privilege('csl_ws_owner',"
            "'csl.raw_objects','archive_bytes','SELECT') AS bytes,"
            "has_column_privilege('csl_ws_owner','csl.raw_objects',"
            "'archive_hash','SELECT') AS metadata"
        ).fetchone()
        assert metadata_only == {"bytes": False, "metadata": True}
