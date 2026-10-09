"""Backup and migrate existing classified uploads into the live AI contract."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from src.analysis_readiness import backfill_registered_uploads
from src.webapp import db_analysis, db_registry


def _backup_database(source: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
        src.backup(dst)


def run(backup_dir: Path, reprocess_inconsistent: bool = True) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    analysis_backup = backup_dir / f"whatsapp_analysis.{stamp}.db"
    registry_backup = backup_dir / f"pcap_registry.{stamp}.db"
    _backup_database(db_analysis.ANALYSIS_DB_PATH, analysis_backup)
    _backup_database(db_registry.REGISTRY_DB_PATH, registry_backup)
    db_analysis.init_analysis_db(); db_registry.init_registry_db()
    initial = backfill_registered_uploads(resume=True)
    reprocessed = []
    if reprocess_inconsistent:
        from src.webapp.job_queue import enqueue_filter_job, get_job_status
        for item in initial:
            if item.get("state") != "failed":
                continue
            upload = db_registry.get_upload(item["upload_id"])
            source = upload.get("stored_path") if upload else None
            if not source or not os.path.isfile(source):
                reprocessed.append({"upload_id": item["upload_id"], "status": "not_reprocessed",
                                    "reason": "source evidence is unavailable"})
                continue
            job_id = enqueue_filter_job([item["upload_id"]], skip_filter=False)
            while True:
                status = get_job_status(job_id) or {}
                if status.get("status") in {"completed", "completed_with_errors", "failed"}:
                    reprocessed.append({"upload_id": item["upload_id"], "job_id": job_id,
                                        "status": status.get("status"), "errors": status.get("errors", [])})
                    break
                time.sleep(0.25)
    return {"backups": [str(analysis_backup), str(registry_backup)],
            "initial_backfill": initial, "reprocessed": reprocessed}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", default="migration_backups")
    parser.add_argument("--no-reprocess", action="store_true",
                        help="Validate and mark inconsistent uploads failed without reprocessing them.")
    args = parser.parse_args()
    print(json.dumps(run(Path(args.backup_dir).resolve(), not args.no_reprocess), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
