"""Run mutating integration tests in a new database, never in analytical data.

Run from the repository root with the editable package installed. The temporary
database is deliberately retained for diagnosis and explicit cleanup review.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import psycopg
from psycopg import sql

from dns_security_analytics.analysis.ctu import ROOT, ctu_settings, guard, read_environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extraction", type=Path, default=ROOT / "docs/public_datasets/extraction.json",
                        help="Accepted CTU extraction manifest for the read-only checks")
    args, pytest_args = parser.parse_known_args()
    if not args.extraction.is_file():
        parser.error("Extraction manifest does not exist")
    settings = ctu_settings(read_environment(ROOT / ".env.ctu"))
    guard(settings, ROOT / ".env.ctu")
    name = "dns_ctu_tests_" + uuid4().hex[:10]
    with psycopg.connect(**settings, autocommit=True) as c:
        c.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    with psycopg.connect(**{**settings, "dbname": name}, autocommit=True) as c:
        # Generic pipeline fixtures exercise the unchanged core schema. CTU
        # source constraints/views are checked read-only on the active database.
        for path in sorted((ROOT / "sql/init").glob("*.sql")):
            if not path.name.startswith("006"):
                c.execute(path.read_text())
    env = {**os.environ, "POSTGRES_HOST": settings["host"], "POSTGRES_PORT": settings["port"],
           "POSTGRES_DB": name, "POSTGRES_USER": settings["user"],
           "POSTGRES_PASSWORD": settings["password"], "RUN_DB_TESTS": "1", "RUN_CTU_TESTS": "1",
           "CTU_EXTRACTION": str(args.extraction.resolve())}
    print("Isolated integration database (retained):", name, flush=True)
    return subprocess.run([sys.executable, "-m", "pytest", "-q", *pytest_args], cwd=ROOT, env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main())
