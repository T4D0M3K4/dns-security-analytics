"""Verify metadata isolation, saved analytics access, and PostgreSQL ACL enforcement."""

import os
import psycopg2
from sqlalchemy import text
from sqlalchemy.engine import make_url
from superset.app import create_app
from superset import db, security_manager

TABLES = ("dns_events", "dns_event_features", "dns_window_features", "dns_alerts")


def main() -> None:
    app = create_app()
    with app.app_context():
        from superset.models.core import Database

        assert db.engine.url.host == "superset-db"
        assert db.session.execute(text("SELECT current_database()")).scalar() == os.environ["SUPERSET_METADATA_DB"]
        database = db.session.query(Database).filter_by(database_name="DNS Security Analytics (read-only)").one()
        uri = make_url(database.sqlalchemy_uri_decrypted)
        assert uri.host == "postgres" and uri.port == 5432
        if os.environ.get("SUPERSET_ADMIN_PASSWORD"):
            assert security_manager.auth_user_db(os.environ["SUPERSET_ADMIN_USER"], os.environ["SUPERSET_ADMIN_PASSWORD"])
            print("Administrator authentication verified.")
        connection = psycopg2.connect(host=uri.host, port=uri.port, dbname=uri.database,
                                      user=uri.username, password=uri.password, connect_timeout=10)
        try:
            connection.autocommit = True
            with connection.cursor() as cursor:
                cursor.execute("SHOW transaction_read_only")
                assert cursor.fetchone()[0] == "on"
                cursor.execute("SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=current_user")
                assert cursor.fetchone() == (False, False, False, False)
                cursor.execute("SELECT has_schema_privilege(current_user,'public','CREATE')")
                assert cursor.fetchone()[0] is False
                for table in TABLES:
                    cursor.execute(f"SELECT count(*) FROM public.{table}")
                    print(f"Read public.{table}: {cursor.fetchone()[0]} rows")
                    for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                        cursor.execute("SELECT has_table_privilege(current_user,%s,%s)", (f"public.{table}", privilege))
                        assert cursor.fetchone()[0] is False
            # Zero-row statements cannot change existing data even if an ACL is wrong.
            # Disable the default read-only guard explicitly to test actual permissions.
            connection.autocommit = False
            probes = [
                "DELETE FROM public.dns_events WHERE false",
                "UPDATE public.dns_events SET query=query WHERE false",
                "INSERT INTO public.dns_events (event_timestamp,zeek_uid,source_ip,source_port,destination_ip,destination_port,transport_protocol) "
                "SELECT CURRENT_TIMESTAMP,'permission-probe','192.0.2.1'::inet,0,'192.0.2.53'::inet,53,'udp' WHERE false",
            ]
            for probe in probes:
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SET TRANSACTION READ WRITE")
                        cursor.execute(probe)
                except psycopg2.errors.InsufficientPrivilege:
                    print(f"{probe.split()[0]} denied by PostgreSQL ACL (read-only default explicitly disabled).")
                else:
                    raise AssertionError("Analytics role unexpectedly has write permission")
                finally:
                    connection.rollback()
        finally:
            connection.close()
        assert not database.allow_dml and not database.allow_ctas and not database.allow_cvas
        print("Metadata isolation, service networking, saved connection, and read-only access verified.")


if __name__ == "__main__":
    main()
