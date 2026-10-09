from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


SUPPORTED_CONTRACT = "whatsapp-live-agent-v1"
REQUIRED_VIEWS = frozenset({
    "v_agent_dataset", "v_agent_captures", "v_agent_packets", "v_agent_flows",
    "v_agent_parties", "v_agent_calls", "v_agent_endpoints", "v_agent_crypto",
    "v_agent_crypto_evidence", "v_agent_geo", "v_agent_metrics",
    "v_agent_correlations", "v_agent_rules", "v_agent_quality",
})


class LiveDatabaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveDatabase:
    database_path: Path
    database_instance_id: str
    contract_version: str
    ruleset_version: str
    current_revision: int
    summary: Dict[str, Any]

    def public_dict(self) -> Dict[str, Any]:
        return {
            "database_instance_id": self.database_instance_id,
            "contract_version": self.contract_version,
            "ruleset_version": self.ruleset_version,
            "current_revision": self.current_revision,
            **self.summary,
        }


class LiveDatabaseSource:
    def __init__(self, path: Path):
        self.path = path.resolve()

    def inspect(self, quick_check: bool = False) -> LiveDatabase:
        if not self.path.is_file():
            raise LiveDatabaseError(f"Live analysis database was not found: {self.path}")
        uri = self.path.as_uri() + "?mode=ro"
        try:
            with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only=ON")
                if quick_check and conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise LiveDatabaseError("SQLite quick_check failed")
                views = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='view'")}
                missing = REQUIRED_VIEWS - views
                if missing:
                    raise LiveDatabaseError(f"Live database is missing required views: {sorted(missing)}")
                metadata = dict(conn.execute("SELECT key,value FROM analysis_metadata"))
                if metadata.get("agent_contract_version") != SUPPORTED_CONTRACT:
                    raise LiveDatabaseError(
                        f"Unsupported live database contract {metadata.get('agent_contract_version')!r}"
                    )
                row = conn.execute("SELECT * FROM v_agent_dataset").fetchone()
                if not row:
                    raise LiveDatabaseError("Live database summary is unavailable")
                summary = dict(row)
        except sqlite3.Error as exc:
            raise LiveDatabaseError(f"Unable to inspect live database: {exc}") from exc
        instance_id = metadata.get("database_instance_id")
        if not instance_id:
            raise LiveDatabaseError("Live database has no instance identifier")
        return LiveDatabase(
            database_path=self.path, database_instance_id=instance_id,
            contract_version=metadata["agent_contract_version"],
            ruleset_version=metadata.get("agent_ruleset_version", "unknown"),
            current_revision=int(summary.pop("current_revision") or 0), summary=summary,
        )
