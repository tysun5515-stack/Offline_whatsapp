"""DB-1: immutable raw-capture registry and derived-filter evidence metadata."""
import hashlib
import os
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
REGISTRY_DB_PATH = os.path.join(BASE_DIR, 'pcap_registry.db')


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(REGISTRY_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _add_column(conn: sqlite3.Connection, definition: str) -> None:
    try:
        conn.execute(f"ALTER TABLE pcap_uploads ADD COLUMN {definition}")
    except sqlite3.OperationalError:
        pass


def init_registry_db() -> None:
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pcap_uploads (
            upload_id TEXT PRIMARY KEY, filename TEXT NOT NULL, stored_path TEXT NOT NULL,
            sha256_hash TEXT NOT NULL, size_bytes INTEGER NOT NULL, uploaded_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'registered', file_format TEXT, batch_id TEXT
        )
    """)
    for col in ('file_format TEXT', 'batch_id TEXT', 'capture_start_ts REAL', 'capture_end_ts REAL',
                'capture_packet_count INTEGER', 'capture_duration_s REAL', 'timestamp_precision TEXT',
                'link_types TEXT', 'capture_vantage TEXT', 'subscriber_ips TEXT',
                'filtered_path TEXT', 'filtered_sha256 TEXT', 'filtered_size_bytes INTEGER',
                'filtered_created_at TEXT', 'filtered_format TEXT', 'filtered_packet_count INTEGER', 'filtered_status TEXT'):
        _add_column(conn, col)
    conn.execute('CREATE INDEX IF NOT EXISTS idx_uploads_batch_capture ON pcap_uploads(batch_id, capture_start_ts)')
    conn.execute('CREATE TABLE IF NOT EXISTS registry_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    conn.execute("UPDATE pcap_uploads SET filtered_status='filtered_output_created' WHERE filtered_status='created' AND filtered_path IS NOT NULL")
    conn.execute("UPDATE pcap_uploads SET filtered_status='no_whatsapp_match' WHERE filtered_status='no_matches'")
    conn.execute("UPDATE pcap_uploads SET filtered_status='bypass_no_output' WHERE filtered_status='bypass_not_created'")
    conn.commit(); conn.close()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def get_upload_by_hash_and_batch(digest: str, batch_id: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    row = conn.execute('SELECT * FROM pcap_uploads WHERE sha256_hash = ? AND batch_id IS ?', (digest, batch_id)).fetchone()
    conn.close()
    return dict(row) if row else None


def register_upload(filename: str, stored_path: str, file_format: str = 'pcap',
                    batch_id: Optional[str] = None, capture_metadata: Optional[Dict[str, Any]] = None,
                    upload_id: Optional[str] = None) -> Dict[str, Any]:
    """Register an evidence copy; deduplication is intentionally limited to one case."""
    digest = sha256_file(stored_path)
    existing = get_upload_by_hash_and_batch(digest, batch_id)
    if existing:
        existing['is_duplicate'] = True
        if os.path.exists(stored_path) and os.path.abspath(stored_path) != os.path.abspath(existing['stored_path']):
            os.remove(stored_path)
        return existing
    metadata = capture_metadata or {}
    result = {'upload_id': upload_id or str(uuid.uuid4()), 'filename': filename, 'stored_path': stored_path,
              'sha256_hash': digest, 'size_bytes': os.path.getsize(stored_path),
              'uploaded_at': datetime.now(timezone.utc).isoformat(), 'status': 'registered',
              'file_format': file_format, 'batch_id': batch_id, 'is_duplicate': False,
              'capture_start_ts': metadata.get('capture_start_ts'), 'capture_end_ts': metadata.get('capture_end_ts'),
              'capture_packet_count': metadata.get('capture_packet_count'), 'capture_duration_s': metadata.get('capture_duration_s'),
              'timestamp_precision': metadata.get('timestamp_precision'), 'link_types': metadata.get('link_types'),
              'capture_vantage': metadata.get('capture_vantage'), 'subscriber_ips': metadata.get('subscriber_ips')}
    conn = _connect()
    conn.execute("""INSERT INTO pcap_uploads
        (upload_id, filename, stored_path, sha256_hash, size_bytes, uploaded_at, status, file_format, batch_id,
         capture_start_ts, capture_end_ts, capture_packet_count, capture_duration_s, timestamp_precision, link_types,
         capture_vantage, subscriber_ips)
        VALUES (:upload_id,:filename,:stored_path,:sha256_hash,:size_bytes,:uploaded_at,:status,:file_format,:batch_id,
                :capture_start_ts,:capture_end_ts,:capture_packet_count,:capture_duration_s,:timestamp_precision,:link_types,
                :capture_vantage,:subscriber_ips)""", result)
    conn.commit(); conn.close()
    return result


def get_upload(upload_id: str) -> Optional[Dict[str, Any]]:
    conn = _connect(); row = conn.execute('SELECT * FROM pcap_uploads WHERE upload_id = ?', (upload_id,)).fetchone(); conn.close()
    return dict(row) if row else None


def list_uploads() -> List[Dict[str, Any]]:
    conn = _connect(); rows = conn.execute('SELECT * FROM pcap_uploads ORDER BY COALESCE(capture_start_ts, 0) DESC, uploaded_at DESC').fetchall(); conn.close()
    return [dict(row) for row in rows]


def get_evidence_scope(start_ts: Optional[float] = None, end_ts: Optional[float] = None) -> List[Dict[str, Any]]:
    """Evidence files whose packet-capture windows overlap a requested range."""
    conn = _connect()
    where, params = ['capture_start_ts IS NOT NULL'], []
    if start_ts is not None:
        where.append('capture_end_ts >= ?'); params.append(start_ts)
    if end_ts is not None:
        where.append('capture_start_ts < ?'); params.append(end_ts)
    rows = conn.execute(f"SELECT * FROM pcap_uploads WHERE {' AND '.join(where)} ORDER BY capture_start_ts, filename", params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def latest_capture_end() -> Optional[float]:
    conn = _connect(); row = conn.execute('SELECT MAX(capture_end_ts) AS value FROM pcap_uploads WHERE capture_end_ts IS NOT NULL').fetchone(); conn.close()
    return row['value'] if row and row['value'] is not None else None


def flatten_evidence_storage_once(raw_root: str, filtered_root: str) -> bool:
    """Move legacy batch folders into immutable upload-id folders after hash verification."""
    conn = _connect(); done = conn.execute("SELECT 1 FROM registry_settings WHERE key='evidence_library_flatten_v1'").fetchone()
    if done:
        conn.close(); return False
    uploads = [dict(r) for r in conn.execute('SELECT * FROM pcap_uploads').fetchall()]
    for upload in uploads:
        for field, root, expected_hash in (('stored_path', raw_root, upload.get('sha256_hash')), ('filtered_path', filtered_root, upload.get('filtered_sha256'))):
            old_path = upload.get(field)
            if not old_path or not os.path.isfile(old_path):
                continue
            if expected_hash and sha256_file(old_path) != expected_hash:
                continue
            new_dir = os.path.join(root, upload['upload_id'])
            os.makedirs(new_dir, exist_ok=True)
            new_path = os.path.join(new_dir, os.path.basename(old_path))
            if os.path.abspath(old_path) != os.path.abspath(new_path):
                shutil.move(old_path, new_path)
                conn.execute(f'UPDATE pcap_uploads SET {field} = ? WHERE upload_id = ?', (new_path, upload['upload_id']))
    conn.execute("INSERT INTO registry_settings(key, value) VALUES('evidence_library_flatten_v1', ?)", (datetime.now(timezone.utc).isoformat(),))
    conn.commit(); conn.close()
    return True


def list_batches() -> List[Dict[str, Any]]:
    conn = _connect()
    rows = conn.execute("""SELECT batch_id, MIN(uploaded_at) AS uploaded_at, MIN(capture_start_ts) AS capture_start_ts,
        MAX(capture_end_ts) AS capture_end_ts, COUNT(*) AS file_count, SUM(size_bytes) AS total_size_bytes,
        GROUP_CONCAT(filename) AS filenames FROM pcap_uploads WHERE batch_id IS NOT NULL GROUP BY batch_id
        ORDER BY COALESCE(MIN(capture_start_ts), 0) DESC, MIN(uploaded_at) DESC""").fetchall()
    conn.close(); return [dict(row) for row in rows]


def get_batch(batch_id: str) -> List[Dict[str, Any]]:
    conn = _connect(); rows = conn.execute('SELECT * FROM pcap_uploads WHERE batch_id = ? ORDER BY capture_start_ts, filename', (batch_id,)).fetchall(); conn.close()
    return [dict(row) for row in rows]


def update_status(upload_id: str, status: str) -> None:
    conn = _connect(); conn.execute('UPDATE pcap_uploads SET status = ? WHERE upload_id = ?', (status, upload_id)); conn.commit(); conn.close()


def update_filtered_evidence(upload_id: str, path: Optional[str] = None, file_format: Optional[str] = None,
                             packet_count: int = 0, status: str = 'created') -> None:
    values: Dict[str, Any] = {'path': path, 'format': file_format, 'count': packet_count, 'status': status,
                              'sha': None, 'size': None, 'created': None}
    if path and os.path.isfile(path):
        values.update({'sha': sha256_file(path), 'size': os.path.getsize(path), 'created': datetime.now(timezone.utc).isoformat()})
    conn = _connect()
    conn.execute("""UPDATE pcap_uploads SET filtered_path=:path, filtered_sha256=:sha, filtered_size_bytes=:size,
        filtered_created_at=:created, filtered_format=:format, filtered_packet_count=:count, filtered_status=:status
        WHERE upload_id=:upload_id""", {**values, 'upload_id': upload_id})
    conn.commit(); conn.close()


def remove_filtered_evidence(upload: Dict[str, Any], status: str = 'not_created') -> None:
    path = upload.get('filtered_path')
    if path and os.path.isfile(path): os.remove(path)
    update_filtered_evidence(upload['upload_id'], status=status)


def delete_upload(upload_id: str) -> None:
    upload = get_upload(upload_id)
    if not upload: return
    for path in (upload.get('stored_path'), upload.get('filtered_path')):
        if path and os.path.isfile(path): os.remove(path)
    conn = _connect(); conn.execute('DELETE FROM pcap_uploads WHERE upload_id = ?', (upload_id,)); conn.commit(); conn.close()
    for path in (os.path.dirname(upload.get('stored_path') or ''), os.path.dirname(upload.get('filtered_path') or '')):
        if path and os.path.isdir(path) and not os.listdir(path): os.rmdir(path)


def delete_batch(batch_id: str) -> None:
    for upload in get_batch(batch_id): delete_upload(upload['upload_id'])


def clear_existing_evidence_once(raw_root: str, filtered_root: str, legacy_upload_root: str) -> bool:
    """One requested deployment reset, guarded by a durable registry marker."""
    conn = _connect(); done = conn.execute("SELECT value FROM registry_settings WHERE key='forensic_storage_reset_v1'").fetchone()
    if done:
        conn.close(); return False
    conn.execute('DELETE FROM pcap_uploads')
    conn.execute("INSERT INTO registry_settings(key, value) VALUES('forensic_storage_reset_v1', ?)", (datetime.now(timezone.utc).isoformat(),))
    conn.commit(); conn.close()
    for root in (raw_root, filtered_root, legacy_upload_root):
        if os.path.isdir(root): shutil.rmtree(root)
        os.makedirs(root, exist_ok=True)
    return True


def list_raw_evidence() -> List[Dict[str, Any]]:
    """Registered source evidence only; never mixes derived captures."""
    conn = _connect()
    rows = conn.execute("SELECT * FROM pcap_uploads WHERE stored_path IS NOT NULL AND stored_path != '' ORDER BY capture_start_ts DESC, filename").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def list_filtered_evidence() -> List[Dict[str, Any]]:
    """Only validated, materialized filtered artifacts."""
    conn = _connect()
    rows = conn.execute("SELECT * FROM pcap_uploads WHERE filtered_status IN ('filtered_output_created', 'raw_source_removed') AND filtered_path IS NOT NULL ORDER BY capture_start_ts DESC, filename").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def set_filter_state(upload_id: str, state: str) -> None:
    conn = _connect()
    conn.execute('UPDATE pcap_uploads SET filtered_status = ? WHERE upload_id = ?', (state, upload_id))
    conn.commit(); conn.close()


def delete_evidence_copy(upload_id: str, mode: str) -> bool:
    """Delete the requested evidence copy. Caller removes derived analysis indexes."""
    upload = get_upload(upload_id)
    if not upload:
        return False
    if mode == 'complete':
        delete_upload(upload_id)
        return True
    if mode == 'raw_only':
        path = upload.get('stored_path')
        if path and os.path.isfile(path): os.remove(path)
        conn = _connect()
        conn.execute("UPDATE pcap_uploads SET stored_path = '', status = 'deleted', filtered_status = CASE WHEN filtered_path IS NOT NULL THEN 'raw_source_removed' ELSE filtered_status END WHERE upload_id = ?", (upload_id,))
        conn.commit(); conn.close()
        return True
    if mode == 'filtered_only':
        remove_filtered_evidence(upload, status='not_run')
        return True
    raise ValueError('Unsupported delete mode')
