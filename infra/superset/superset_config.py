"""Synchronous local demonstration; metadata lives in its own PostgreSQL cluster."""

import os
from sqlalchemy.engine import URL

SECRET_KEY = os.environ["SUPERSET_SECRET_KEY"]
if len(SECRET_KEY) < 32:
    raise ValueError("SUPERSET_SECRET_KEY must contain at least 32 characters")

SQLALCHEMY_DATABASE_URI = URL.create(
    "postgresql+psycopg2", username=os.environ["SUPERSET_METADATA_USER"],
    password=os.environ["SUPERSET_METADATA_PASSWORD"], host="superset-db", port=5432,
    database=os.environ["SUPERSET_METADATA_DB"],
).render_as_string(hide_password=False)
SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
CACHE_CONFIG = {"CACHE_TYPE": "SimpleCache", "CACHE_DEFAULT_TIMEOUT": 300}
DATA_CACHE_CONFIG = {"CACHE_TYPE": "SimpleCache", "CACHE_DEFAULT_TIMEOUT": 300}
FEATURE_FLAGS = {"GLOBAL_ASYNC_QUERIES": False, "ALERT_REPORTS": False}
# HTTP is served only on the host loopback interface for this demonstration.
TALISMAN_ENABLED = False
WTF_CSRF_ENABLED = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = False
