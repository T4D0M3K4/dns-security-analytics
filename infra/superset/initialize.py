"""Idempotent local admin/connection setup, after Superset's own migrations."""

import os
from sqlalchemy.engine import URL
from sqlalchemy import text
from superset.app import create_app
from superset import db, security_manager


def main() -> None:
    app = create_app()
    with app.app_context():
        from superset.models.core import Database

        username = os.environ["SUPERSET_ADMIN_USER"]
        if security_manager.find_user(username=username) is None:
            user = security_manager.add_user(
                username=username, first_name="DNS", last_name="Administrator",
                email=os.environ["SUPERSET_ADMIN_EMAIL"], role=security_manager.find_role("Admin"),
                password=os.environ["SUPERSET_ADMIN_PASSWORD"],
            )
            if user is None:
                raise RuntimeError("Superset administrator creation failed")
            print("Created local Superset administrator (credentials not logged).")
        else:
            print("Existing administrator preserved; password not changed.")
        name = "DNS Security Analytics (read-only)"
        connection = db.session.query(Database).filter_by(database_name=name).one_or_none()
        if connection is None:
            connection = Database(database_name=name)
            db.session.add(connection)
        uri = URL.create(
            "postgresql+psycopg2", username=os.environ["SUPERSET_ANALYTICS_USER"],
            password=os.environ["SUPERSET_ANALYTICS_PASSWORD"], host="postgres", port=5432,
            database=os.environ["SUPERSET_ANALYTICS_DB"],
        ).render_as_string(hide_password=False)
        connection.set_sqlalchemy_uri(uri)
        connection.expose_in_sqllab = True
        connection.allow_dml = False
        connection.allow_ctas = False
        connection.allow_cvas = False
        with connection.get_sqla_engine() as engine:
            with engine.connect() as session:
                session.execute(text("SELECT count(*) FROM public.dns_events")).scalar()
        db.session.commit()
        print("Registered DNS analytics connection through postgres:5432; no datasets or charts created.")


if __name__ == "__main__":
    main()
