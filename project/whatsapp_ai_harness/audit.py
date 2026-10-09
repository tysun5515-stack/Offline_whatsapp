from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditStore:
    def __init__(self, path: Path):
        self.path = path
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with closing(self._connect()) as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS investigations (
                trace_id TEXT PRIMARY KEY, created_at_utc TEXT NOT NULL,
                question TEXT NOT NULL, route TEXT NOT NULL, dataset_id TEXT NOT NULL,
                dataset_sha256 TEXT NOT NULL, model_name TEXT, model_digest TEXT,
                scope_json TEXT NOT NULL, plan_json TEXT, trace_json TEXT NOT NULL,
                answer_package_json TEXT, displayed_answer TEXT NOT NULL,
                status TEXT NOT NULL, error TEXT, previous_hash TEXT, record_hash TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS investigations_no_update
              BEFORE UPDATE ON investigations BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS investigations_no_delete
              BEFORE DELETE ON investigations BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END;
            """)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(investigations)")}
            for definition in (
                "database_instance_id TEXT", "analysis_revision INTEGER", "evidence_snapshot_digest TEXT",
            ):
                if definition.split()[0] not in columns:
                    conn.execute(f"ALTER TABLE investigations ADD COLUMN {definition}")
            conn.commit()

    def append(self, record: Dict[str, Any]) -> None:
        with closing(self._connect()) as conn:
            # Serialize writers so the append-only hash chain cannot fork when
            # two HTTP requests finish at nearly the same time.
            conn.execute("BEGIN IMMEDIATE")
            previous = conn.execute("SELECT record_hash FROM investigations ORDER BY rowid DESC LIMIT 1").fetchone()
            previous_hash = previous[0] if previous else ""
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
            record_hash = hashlib.sha256((previous_hash + canonical).encode()).hexdigest()
            conn.execute("""INSERT INTO investigations
                (trace_id,created_at_utc,question,route,dataset_id,dataset_sha256,model_name,model_digest,
                 scope_json,plan_json,trace_json,answer_package_json,displayed_answer,status,error,previous_hash,record_hash,
                 database_instance_id,analysis_revision,evidence_snapshot_digest)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                record["trace_id"], datetime.now(timezone.utc).isoformat(), record["question"], record["route"],
                record["database_instance_id"], record.get("evidence_snapshot_digest") or "live",
                record.get("model_name"), record.get("model_digest"),
                json.dumps(record.get("scope", {}), sort_keys=True), json.dumps(record.get("plan"), sort_keys=True),
                json.dumps(record.get("trace", []), sort_keys=True), json.dumps(record.get("answer_package"), sort_keys=True),
                record["displayed_answer"], record["status"], record.get("error"), previous_hash, record_hash,
                record["database_instance_id"], record.get("analysis_revision"), record.get("evidence_snapshot_digest"),
            ))
            conn.commit()

    def get(self, trace_id: str) -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM investigations WHERE trace_id=?", (trace_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        for key in ("scope_json", "plan_json", "trace_json", "answer_package_json"):
            raw = result.pop(key)
            result[key[:-5]] = json.loads(raw) if raw is not None else None
        return result

    def list(self, limit: int = 100) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute("""SELECT trace_id,created_at_utc,question,route,
                COALESCE(database_instance_id,dataset_id) AS database_instance_id,
                analysis_revision,status,displayed_answer FROM investigations
                ORDER BY rowid DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def find_citation(self, citation_id: str) -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute("""SELECT trace_id FROM investigations
                WHERE answer_package_json LIKE ? ORDER BY rowid DESC""", (f'%"{citation_id}"%',)).fetchall()
        for row in rows:
            record = self.get(row[0])
            package = record.get("answer_package") if record else None
            if any(ref.get("citation_id") == citation_id for ref in (package or {}).get("citations", [])):
                return record
        return None

