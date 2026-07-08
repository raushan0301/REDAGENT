"""PostgreSQL connection + findings persistence. STUB (Month 1, Week 2/4).

Creds come from env (DATABASE_URL / PG* vars), never committed.
"""

from __future__ import annotations

import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/redagent")


def get_connection():
    """Return a PostgreSQL connection. STUB (Week 2)."""
    # import psycopg
    # return psycopg.connect(DATABASE_URL)
    raise NotImplementedError("get_connection stub — wire psycopg (Week 2).")
