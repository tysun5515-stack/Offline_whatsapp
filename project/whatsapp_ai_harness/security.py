from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


ALLOWED_VIEWS = frozenset({
    "v_agent_dataset", "v_agent_captures", "v_agent_packets", "v_agent_flows",
    "v_agent_parties", "v_agent_calls", "v_agent_endpoints", "v_agent_crypto",
    "v_agent_rules", "v_agent_quality", "v_agent_crypto_evidence", "v_agent_geo",
    "v_agent_metrics", "v_agent_correlations", "agent_rules_fts",
})
ALLOWED_FUNCTIONS = frozenset({
    "count", "sum", "min", "max", "avg", "lower", "upper", "coalesce", "round",
    "length", "json_extract", "json_each", "date", "datetime", "strftime", "abs",
    "group_concat", "like", "match",
})


class QuerySecurityError(RuntimeError):
    pass


def _authorizer(action: int, arg1: str | None, arg2: str | None, db_name: str | None, source: str | None) -> int:
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_RECURSIVE):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION:
        function_name = (arg2 or arg1 or "").lower()
        return sqlite3.SQLITE_OK if function_name in ALLOWED_FUNCTIONS else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and (arg1 or "").lower() == "data_version":
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        table = arg1 or ""
        # FTS5 opens its own shadow tables while constructing the allowlisted
        # agent_rules_fts virtual table. No caller-controlled SQL surface exists for
        # these tables; only the fixed rule_search operator can reach them.
        if table in ALLOWED_VIEWS or table.startswith("agent_rules_fts_") or (source or "") in ALLOWED_VIEWS:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY


@contextmanager
def readonly_connection(path: Path, timeout_ms: int) -> Iterator[sqlite3.Connection]:
    uri = path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=max(timeout_ms / 1000, 0.1))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.execute("PRAGMA cache_size=-8192")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 100_000)
    conn.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 200)
    conn.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 10)
    conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
    conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 1_000)
    deadline = time.monotonic() + timeout_ms / 1000

    def progress() -> int:
        return 1 if time.monotonic() >= deadline else 0

    conn.set_progress_handler(progress, 1000)
    conn.execute("BEGIN")
    conn.set_authorizer(_authorizer)
    try:
        yield conn
    finally:
        conn.close()

