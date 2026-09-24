"""
db_analysis.py — DB-2: Derived analysis data (whatsapp_analysis.db).
Fully recomputable from the original pcap via the pipeline.
Joined to DB-1 via batch_id/upload_id in application code only.
"""
import sqlite3
import os
import json
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
ANALYSIS_DB_PATH = os.path.join(BASE_DIR, 'whatsapp_analysis.db')


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(ANALYSIS_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_analysis_db():
    """Initialise the analysis DB, creating tables only if they don't exist.
    Does NOT drop existing tables so that data survives server restarts.
    """
    conn = _connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS whatsapp_packets (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id            TEXT NOT NULL,
            upload_id           TEXT NOT NULL,
            filename            TEXT NOT NULL,
            packet_no           INTEGER NOT NULL,
            timestamp           REAL NOT NULL,
            src_ip              TEXT,
            dst_ip              TEXT,
            src_port            INTEGER,
            dst_port            INTEGER,
            protocol            TEXT,
            length              INTEGER,
            flow_id             TEXT,
            whatsapp_confidence TEXT NOT NULL,
            whatsapp_media_guess TEXT,
            sub_activity        TEXT,
            ip_ttl              INTEGER,
            is_stun_binding     INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS parties (
            party_id      TEXT PRIMARY KEY,
            batch_id      TEXT NOT NULL,
            remote_ip     TEXT NOT NULL,
            remote_port   INTEGER,
            protocol      TEXT NOT NULL,
            local_ips     TEXT,
            public_local_ip TEXT,
            packet_count  INTEGER NOT NULL,
            total_bytes   INTEGER NOT NULL,
            first_seen    REAL NOT NULL,
            last_seen     REAL NOT NULL,
            duration_s    REAL NOT NULL,
            party_type    TEXT NOT NULL,
            sub_activity  TEXT,
            media_type    TEXT,
            confidence    TEXT,
            traffic_class TEXT NOT NULL DEFAULT 'confirmed_whatsapp',
            os_hint       TEXT,
            session_start_confirmed INTEGER DEFAULT 1,
            is_p2p        INTEGER DEFAULT 0,
            media_breakdown TEXT,
            source_file   TEXT,
            source_files  TEXT
        );

        CREATE TABLE IF NOT EXISTS geo_cache (
            ip           TEXT PRIMARY KEY,
            country      TEXT,
            city         TEXT,
            latitude     REAL,
            longitude    REAL,
            asn          TEXT,
            asn_org      TEXT,
            looked_up_at REAL,
            rdns_hostname TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_packets_batch ON whatsapp_packets(batch_id);
        CREATE INDEX IF NOT EXISTS idx_packets_batch_file ON whatsapp_packets(batch_id, filename);
        CREATE INDEX IF NOT EXISTS idx_parties_batch ON parties(batch_id);

        CREATE TABLE IF NOT EXISTS sessions (
            session_id    TEXT PRIMARY KEY,
            batch_id      TEXT NOT NULL,
            party_id      TEXT NOT NULL,
            start_ts      REAL NOT NULL,
            end_ts        REAL NOT NULL,
            media_type    TEXT,
            total_bytes   INTEGER NOT NULL,
            burst_count   INTEGER NOT NULL,
            summary_text  TEXT
        );

        CREATE TABLE IF NOT EXISTS analysis_flows_v2 (
            flow_id TEXT PRIMARY KEY, upload_id TEXT NOT NULL, flow_instance INTEGER,
            endpoint_a_ip TEXT NOT NULL, endpoint_a_port INTEGER,
            endpoint_b_ip TEXT NOT NULL, endpoint_b_port INTEGER,
            protocol TEXT NOT NULL, local_subscriber_ip TEXT,
            subscriber_resolution_source TEXT, subscriber_resolution_confidence TEXT,
            first_seen REAL NOT NULL, last_seen REAL NOT NULL,
            a_to_b_packets INTEGER NOT NULL, b_to_a_packets INTEGER NOT NULL,
            a_to_b_bytes INTEGER NOT NULL, b_to_a_bytes INTEGER NOT NULL,
            media_type TEXT, confidence TEXT, schema_version TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS party_flow_links_v2 (
            party_id TEXT NOT NULL, flow_id TEXT NOT NULL,
            PRIMARY KEY (party_id, flow_id)
        );
        CREATE TABLE IF NOT EXISTS session_flow_links_v2 (
            session_id TEXT NOT NULL, flow_id TEXT NOT NULL,
            PRIMARY KEY (session_id, flow_id)
        );
        CREATE TABLE IF NOT EXISTS derived_schema_metadata (
            component TEXT PRIMARY KEY, version INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS correlation_results (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_id_a   TEXT NOT NULL,
            upload_id_b   TEXT NOT NULL,
            score         REAL NOT NULL,
            details       TEXT
        );
        
        CREATE TABLE IF NOT EXISTS batch_metrics (
            batch_id            TEXT PRIMARY KEY,
            packet_count        INTEGER NOT NULL,
            flow_count          INTEGER NOT NULL,
            whatsapp_count      INTEGER NOT NULL,
            detected_os         TEXT,
            bypass_mode         INTEGER DEFAULT 0,
            total_raw_packets   INTEGER DEFAULT 0
        );
    """)
    try:
        conn.execute("ALTER TABLE parties ADD COLUMN media_breakdown TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE parties ADD COLUMN source_file TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE parties ADD COLUMN source_files TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE parties ADD COLUMN traffic_class TEXT NOT NULL DEFAULT 'confirmed_whatsapp'")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE parties ADD COLUMN media_type TEXT")
    except Exception:
        pass
    for column in (
        "endpoint_role_source TEXT", "matched_meta_ip TEXT", "whatsapp_signals TEXT", "acceptance_reason TEXT",
        "dns_correlated_hostname TEXT", "dns_correlated_ip TEXT", "dns_response_timestamp REAL", "dns_expires_at REAL",
        "tls_cipher_suite TEXT", "tls_crypto_info TEXT", "quic_version TEXT",
        "flow_instance INTEGER", "capture_id TEXT", "endpoint_a_ip TEXT", "endpoint_a_port INTEGER",
        "endpoint_b_ip TEXT", "endpoint_b_port INTEGER", "local_subscriber_ip TEXT",
        "subscriber_resolution_source TEXT", "subscriber_resolution_confidence TEXT",
        "session_start_confirmed INTEGER DEFAULT 0"
    ):
        try:
            conn.execute(f"ALTER TABLE whatsapp_packets ADD COLUMN {column}")
        except sqlite3.OperationalError:
            pass
    for column in (
        "schema_version TEXT", "upload_id TEXT", "endpoint_a_ip TEXT", "endpoint_b_ip TEXT",
        "endpoint_a_scope TEXT", "endpoint_b_scope TEXT", "endpoint_a_ports TEXT", "endpoint_b_ports TEXT",
        "flow_ids TEXT", "a_to_b_packets INTEGER DEFAULT 0", "b_to_a_packets INTEGER DEFAULT 0",
        "a_to_b_bytes INTEGER DEFAULT 0", "b_to_a_bytes INTEGER DEFAULT 0", "local_subscriber_ip TEXT",
        "subscriber_resolution_source TEXT", "subscriber_resolution_confidence TEXT"
    ):
        try:
            conn.execute(f"ALTER TABLE parties ADD COLUMN {column}")
        except sqlite3.OperationalError:
            pass
    for column in (
        "schema_version TEXT", "capture_id TEXT", "local_subscriber_ip TEXT", "observed_span_s REAL",
        "active_media_duration_s REAL", "transition_gap_s REAL", "flow_ids TEXT", "party_ids TEXT",
        "remote_endpoints TEXT", "confidence TEXT", "duration_anomaly INTEGER DEFAULT 0"
    ):
        try:
            conn.execute(f"ALTER TABLE sessions ADD COLUMN {column}")
        except sqlite3.OperationalError:
            pass
    # Existing derived rows predate traffic_class.  Their persisted confidence
    # is the only reliable historical source for the backfill.
    conn.execute("""
        UPDATE parties
        SET traffic_class = CASE
            WHEN LOWER(COALESCE(confidence, '')) = 'unclassified' THEN 'unclassified'
            ELSE 'confirmed_whatsapp'
        END
        WHERE traffic_class IS NULL OR traffic_class = ''
    """)
    try:
        conn.execute("ALTER TABLE batch_metrics ADD COLUMN bypass_mode INTEGER DEFAULT 0")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE batch_metrics ADD COLUMN total_raw_packets INTEGER DEFAULT 0")
    except Exception:
        pass
    for column in (
        "pass1_accepted INTEGER DEFAULT 0",
        "pass2_dns_accepted INTEGER DEFAULT 0",
        "rejected_no_signal INTEGER DEFAULT 0",
        "non_ip_count INTEGER DEFAULT 0",
        "reconciliation_ok INTEGER DEFAULT 1"
    ):
        try:
            conn.execute(f"ALTER TABLE batch_metrics ADD COLUMN {column}")
        except Exception:
            pass
            
    # Add indexes for performance
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_upload ON whatsapp_packets(upload_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON whatsapp_packets(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_confidence ON whatsapp_packets(whatsapp_confidence)")
    conn.executemany(
        "INSERT OR REPLACE INTO derived_schema_metadata(component, version) VALUES (?, 2)",
        [("flows",), ("parties",), ("sessions",)],
    )
    
    conn.commit()
    conn.close()

def upsert_batch_metrics(batch_id: str, metrics: Dict[str, Any]):
    conn = _connect()
    conn.execute(
        """INSERT OR REPLACE INTO batch_metrics
           (batch_id, packet_count, flow_count, whatsapp_count, detected_os, bypass_mode, total_raw_packets,
            pass1_accepted, pass2_dns_accepted, rejected_no_signal, non_ip_count, reconciliation_ok)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (batch_id, metrics.get('packet_count', 0), metrics.get('flow_count', 0), 
         metrics.get('whatsapp_count', 0), metrics.get('detected_os', 'unknown'),
         1 if metrics.get('bypass_mode') else 0,
         metrics.get('total_raw_packets', 0),
         metrics.get('pass1_accepted', 0), metrics.get('pass2_dns_accepted', 0),
         metrics.get('rejected_no_signal', 0), metrics.get('non_ip_count', 0),
         1 if metrics.get('reconciliation_ok', True) else 0)
    )
    conn.commit()
    conn.close()

def get_batch_metrics(batch_id: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    row = conn.execute("SELECT * FROM batch_metrics WHERE batch_id = ?", (batch_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def clear_batch_packets(batch_id: str):
    """Remove all derived data for a batch before re-filtering."""
    conn = _connect()
    upload_ids = [row[0] for row in conn.execute("SELECT DISTINCT upload_id FROM whatsapp_packets WHERE batch_id = ?", (batch_id,))]
    party_ids = [row[0] for row in conn.execute("SELECT party_id FROM parties WHERE batch_id = ?", (batch_id,))]
    session_ids = [row[0] for row in conn.execute("SELECT session_id FROM sessions WHERE batch_id = ?", (batch_id,))]
    conn.executemany("DELETE FROM analysis_flows_v2 WHERE upload_id = ?", [(uid,) for uid in upload_ids])
    conn.executemany("DELETE FROM party_flow_links_v2 WHERE party_id = ?", [(pid,) for pid in party_ids])
    conn.executemany("DELETE FROM session_flow_links_v2 WHERE session_id = ?", [(sid,) for sid in session_ids])
    conn.execute("DELETE FROM whatsapp_packets WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM parties WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM sessions WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM batch_metrics WHERE batch_id = ?", (batch_id,))
    conn.commit()
    conn.close()


def insert_whatsapp_packets(batch_id: str, upload_id: str, filename: str, packets: List[Dict[str, Any]]):
    """Insert classified packets. Deduplicates by upload_id before inserting."""
    conn = _connect()
    old_flow_ids = [row[0] for row in conn.execute(
        "SELECT flow_id FROM analysis_flows_v2 WHERE upload_id = ?", (upload_id,)
    )]
    if old_flow_ids:
        conn.executemany("DELETE FROM party_flow_links_v2 WHERE flow_id = ?", [(fid,) for fid in old_flow_ids])
        conn.executemany("DELETE FROM session_flow_links_v2 WHERE flow_id = ?", [(fid,) for fid in old_flow_ids])
    conn.execute("DELETE FROM analysis_flows_v2 WHERE upload_id = ?", (upload_id,))
    conn.execute("DELETE FROM whatsapp_packets WHERE upload_id = ?", (upload_id,))

    packets_sorted = sorted(packets, key=lambda p: p['timestamp'] if p.get('timestamp') is not None else 0)

    # Chunk inserts to save memory
    CHUNK_SIZE = 10000
    for i in range(0, len(packets_sorted), CHUNK_SIZE):
        chunk = packets_sorted[i:i + CHUNK_SIZE]
        conn.executemany(
            """INSERT INTO whatsapp_packets
               (batch_id, upload_id, filename, packet_no, timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, length, flow_id, whatsapp_confidence, whatsapp_media_guess,
                sub_activity, endpoint_role_source, matched_meta_ip, whatsapp_signals, acceptance_reason,
                ip_ttl, is_stun_binding, dns_correlated_hostname, dns_correlated_ip, dns_response_timestamp, dns_expires_at,
                tls_cipher_suite, tls_crypto_info, quic_version,
                flow_instance, capture_id, endpoint_a_ip, endpoint_a_port, endpoint_b_ip, endpoint_b_port,
                local_subscriber_ip, subscriber_resolution_source, subscriber_resolution_confidence, session_start_confirmed)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    batch_id, upload_id, filename, p.get('packet_no'), p.get('timestamp'),
                    p.get('src_ip'), p.get('dst_ip'),
                    p.get('src_port'), p.get('dst_port'),
                    p.get('protocol'), p.get('length'),
                    p.get('flow_id'), p.get('whatsapp_confidence'),
                    p.get('whatsapp_media_guess'), p.get('sub_activity'),
                    p.get('endpoint_role_source'), p.get('matched_meta_ip'),
                    p.get('whatsapp_signals'), p.get('acceptance_reason'),
                    p.get('ip_ttl'), 1 if p.get('is_stun_binding') else 0,
                    p.get('dns_correlated_hostname'), p.get('dns_correlated_ip'),
                    p.get('dns_response_timestamp'), p.get('dns_expires_at'),
                    p.get('tls_cipher_suite'), p.get('tls_crypto_info'), p.get('quic_version'),
                    p.get('flow_instance'), p.get('capture_id'), p.get('endpoint_a_ip'), p.get('endpoint_a_port'),
                    p.get('endpoint_b_ip'), p.get('endpoint_b_port'), p.get('local_subscriber_ip'),
                    p.get('subscriber_resolution_source'), p.get('subscriber_resolution_confidence'),
                    1 if p.get('session_start_confirmed') else 0
                )
                for p in chunk
            ]
        )
    flow_groups: Dict[str, List[Dict[str, Any]]] = {}
    for packet in packets_sorted:
        if packet.get('flow_id'):
            flow_groups.setdefault(str(packet['flow_id']), []).append(packet)
    for flow_id, members in flow_groups.items():
        timestamps = [p['timestamp'] for p in members if p.get('timestamp') is not None]
        endpoint_a = members[0].get('endpoint_a_ip')
        endpoint_b = members[0].get('endpoint_b_ip')
        if not endpoint_a or not endpoint_b or not timestamps:
            continue
        a_packets = [p for p in members if p.get('src_ip') == endpoint_a]
        b_packets = [p for p in members if p.get('src_ip') == endpoint_b]
        conn.execute("""INSERT OR REPLACE INTO analysis_flows_v2
            (flow_id, upload_id, flow_instance, endpoint_a_ip, endpoint_a_port, endpoint_b_ip, endpoint_b_port,
             protocol, local_subscriber_ip, subscriber_resolution_source, subscriber_resolution_confidence,
             first_seen, last_seen, a_to_b_packets, b_to_a_packets, a_to_b_bytes, b_to_a_bytes,
             media_type, confidence, schema_version)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            flow_id, upload_id, members[0].get('flow_instance'), endpoint_a, members[0].get('endpoint_a_port'),
            endpoint_b, members[0].get('endpoint_b_port'), members[0].get('protocol'),
            members[0].get('local_subscriber_ip'), members[0].get('subscriber_resolution_source'),
            members[0].get('subscriber_resolution_confidence'), min(timestamps), max(timestamps),
            len(a_packets), len(b_packets), sum(p.get('length', 0) for p in a_packets),
            sum(p.get('length', 0) for p in b_packets), members[0].get('whatsapp_media_guess'),
            members[0].get('whatsapp_confidence'), 'flow-v2'))
    conn.commit()
    count = conn.execute(
        "SELECT COUNT(1) FROM whatsapp_packets WHERE upload_id = ?", (upload_id,)
    ).fetchone()[0]
    conn.close()
    return count


def insert_parties(batch_id: str, parties: List[Dict[str, Any]]):
    conn = _connect()
    old_party_ids = [row[0] for row in conn.execute("SELECT party_id FROM parties WHERE batch_id = ?", (batch_id,))]
    if old_party_ids:
        conn.executemany("DELETE FROM party_flow_links_v2 WHERE party_id = ?", [(pid,) for pid in old_party_ids])
    conn.execute("DELETE FROM parties WHERE batch_id = ?", (batch_id,))
    conn.executemany(
        """INSERT OR REPLACE INTO parties
           (party_id, batch_id, remote_ip, remote_port, protocol,
            local_ips, public_local_ip, packet_count, total_bytes, first_seen, last_seen,
            duration_s, party_type, sub_activity, media_type, confidence, traffic_class, os_hint,
             session_start_confirmed, is_p2p, media_breakdown, source_file, source_files,
             schema_version, upload_id, endpoint_a_ip, endpoint_b_ip, endpoint_a_scope, endpoint_b_scope,
             endpoint_a_ports, endpoint_b_ports, flow_ids, a_to_b_packets, b_to_a_packets,
             a_to_b_bytes, b_to_a_bytes, local_subscriber_ip, subscriber_resolution_source,
             subscriber_resolution_confidence)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                p['party_id'], batch_id, p['remote_ip'], p.get('remote_port'),
                p['protocol'], p.get('local_ips', ''), p.get('public_local_ip'),
                p['packet_count'], p['total_bytes'],
                p['first_seen'], p['last_seen'], p.get('duration_s', 0.0),
                p['party_type'], p.get('sub_activity'), p.get('media_type'), p.get('confidence'),
                p.get('traffic_class', 'confirmed_whatsapp'), p['os_hint'],
                1 if p.get('session_start_confirmed') else 0,
                1 if p.get('is_p2p') else 0,
                p.get('media_breakdown'), p.get('source_file', 'Unknown'),
                p.get('source_files', '[]'), p.get('schema_version'), p.get('upload_id'),
                p.get('endpoint_a_ip'), p.get('endpoint_b_ip'), p.get('endpoint_a_scope'), p.get('endpoint_b_scope'),
                json.dumps(p.get('endpoint_a_ports', [])), json.dumps(p.get('endpoint_b_ports', [])),
                json.dumps(p.get('flow_ids', [])), p.get('a_to_b_packets', 0), p.get('b_to_a_packets', 0),
                p.get('a_to_b_bytes', 0), p.get('b_to_a_bytes', 0), p.get('local_subscriber_ip'),
                p.get('subscriber_resolution_source'), p.get('subscriber_resolution_confidence')
            )
            for p in parties
        ]
    )
    conn.executemany(
        "INSERT OR IGNORE INTO party_flow_links_v2(party_id, flow_id) VALUES (?, ?)",
        [(p['party_id'], flow_id) for p in parties for flow_id in p.get('flow_ids', [])]
    )
    conn.commit()
    conn.close()


def get_packets(batch_id: Optional[str] = None, start_ts: Optional[float] = None, end_ts: Optional[float] = None, upload_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    conn = _connect()
    where, params = ['1 = 1'], []
    if batch_id:
        where.append('batch_id = ?'); params.append(batch_id)
    if start_ts is not None: where.append('timestamp >= ?'); params.append(start_ts)
    if end_ts is not None: where.append('timestamp < ?'); params.append(end_ts)
    if upload_ids:
        placeholders = ','.join(['?'] * len(upload_ids))
        where.append(f'upload_id IN ({placeholders})')
        params.extend(upload_ids)
    rows = conn.execute(f"SELECT * FROM whatsapp_packets WHERE {' AND '.join(where)} ORDER BY timestamp", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_file_list(batch_id: Optional[str] = None, start_ts: Optional[float] = None, end_ts: Optional[float] = None, upload_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Return summary stats for each file uploaded in a batch."""
    conn = _connect()
    where, params = ['1 = 1'], []
    if batch_id:
        where.append('batch_id = ?'); params.append(batch_id)
    if start_ts is not None:
        where.append('timestamp >= ?'); params.append(start_ts)
    if end_ts is not None:
        where.append('timestamp < ?'); params.append(end_ts)
    if upload_ids:
        placeholders = ','.join(['?'] * len(upload_ids))
        where.append(f'upload_id IN ({placeholders})')
        params.extend(upload_ids)
    where_sql = ' AND '.join(where)

    rows = conn.execute(f"""
        SELECT 
            filename,
            upload_id,
            COUNT(*) AS packet_count,
            SUM(CASE WHEN LOWER(whatsapp_confidence) = 'high' THEN 1 ELSE 0 END) AS high_conf_count,
            SUM(CASE WHEN LOWER(whatsapp_confidence) = 'medium' THEN 1 ELSE 0 END) AS med_conf_count,
            SUM(CASE WHEN LOWER(whatsapp_confidence) = 'low' THEN 1 ELSE 0 END) AS low_conf_count,
            SUM(CASE WHEN UPPER(protocol) = 'UDP' THEN 1 ELSE 0 END) AS udp_count,
            SUM(CASE WHEN UPPER(protocol) = 'TCP' THEN 1 ELSE 0 END) AS tcp_count,
            SUM(COALESCE(length, 0)) AS total_bytes,
            MIN(timestamp) AS min_ts,
            MAX(timestamp) AS max_ts
        FROM whatsapp_packets
        WHERE {where_sql}
        GROUP BY filename, upload_id
        ORDER BY filename ASC, upload_id ASC
    """, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_packets_paged(
    batch_id: Optional[str] = None,
    filename: Optional[str] = None,
    page: int = 1,
    per_page: int = 100,
    confidence: Optional[str] = None,
    protocol: Optional[str] = None,
    media_guess: Optional[str] = None,
    q: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    upload_ids: Optional[List[str]] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    any_ip: Optional[str] = None
) -> Dict[str, Any]:
    """Return paginated packets with dynamic filtering and overall file statistics."""
    page = max(1, int(page))
    per_page = max(10, min(500, int(per_page)))
    offset = (page - 1) * per_page

    where_clauses = ["1 = 1"]
    params: List[Any] = []
    if batch_id:
        where_clauses.append('batch_id = ?'); params.append(batch_id)
    if start_ts is not None:
        where_clauses.append('timestamp >= ?'); params.append(start_ts)
    if end_ts is not None:
        where_clauses.append('timestamp < ?'); params.append(end_ts)
    if upload_ids:
        placeholders = ','.join(['?'] * len(upload_ids))
        where_clauses.append(f'upload_id IN ({placeholders})')
        params.extend(upload_ids)

    if filename:
        where_clauses.append("filename = ?")
        params.append(filename)

    if src_ip:
        where_clauses.append("src_ip = ?")
        params.append(src_ip.strip())

    if dst_ip:
        where_clauses.append("dst_ip = ?")
        params.append(dst_ip.strip())

    if any_ip:
        where_clauses.append("(src_ip = ? OR dst_ip = ?)")
        params.extend([any_ip.strip(), any_ip.strip()])

    if confidence and confidence.lower() != 'all':
        where_clauses.append("LOWER(whatsapp_confidence) = LOWER(?)")
        params.append(confidence.strip())

    if protocol and protocol.upper() != 'ALL':
        where_clauses.append("UPPER(protocol) = UPPER(?)")
        params.append(protocol.strip())

    if media_guess and media_guess.lower() != 'all':
        where_clauses.append("LOWER(whatsapp_media_guess) = LOWER(?)")
        params.append(media_guess.strip())

    if q and q.strip():
        search_pattern = f"%{q.strip()}%"
        where_clauses.append(
            "(src_ip LIKE ? OR dst_ip LIKE ? OR CAST(src_port AS TEXT) LIKE ? OR "
            "CAST(dst_port AS TEXT) LIKE ? OR whatsapp_media_guess LIKE ? OR "
            "sub_activity LIKE ? OR flow_id LIKE ? OR filename LIKE ?)"
        )
        params.extend([search_pattern] * 8)

    where_sql = " AND ".join(where_clauses)
    conn = _connect()

    # 1. Total matching rows
    count_sql = f"SELECT COUNT(*) FROM whatsapp_packets WHERE {where_sql}"
    total_count = conn.execute(count_sql, params).fetchone()[0]

    # 2. Paginated rows
    data_sql = f"""
        SELECT * FROM whatsapp_packets 
        WHERE {where_sql} 
        ORDER BY packet_no ASC, timestamp ASC 
        LIMIT ? OFFSET ?
    """
    rows = conn.execute(data_sql, params + [per_page, offset]).fetchall()
    packet_rows = [dict(r) for r in rows]

    # 3. Compute file stats for current scope (filename or entire batch)
    scope_where = "1 = 1"
    scope_params = []
    if batch_id:
        scope_where += ' AND batch_id = ?'; scope_params.append(batch_id)
    if start_ts is not None:
        scope_where += ' AND timestamp >= ?'; scope_params.append(start_ts)
    if end_ts is not None:
        scope_where += ' AND timestamp < ?'; scope_params.append(end_ts)
    if upload_ids:
        placeholders = ','.join(['?'] * len(upload_ids))
        scope_where += f' AND upload_id IN ({placeholders})'
        scope_params.extend(upload_ids)
    if filename:
        scope_where += " AND filename = ?"
        scope_params.append(filename)

    stats_row = conn.execute(f"""
        SELECT
            COUNT(*) AS total_packets,
            SUM(CASE WHEN UPPER(protocol) = 'UDP' THEN 1 ELSE 0 END) AS udp_count,
            SUM(CASE WHEN UPPER(protocol) = 'TCP' THEN 1 ELSE 0 END) AS tcp_count,
            SUM(CASE WHEN LOWER(whatsapp_confidence) = 'high' THEN 1 ELSE 0 END) AS high_conf_count,
            SUM(COALESCE(length, 0)) AS total_bytes
        FROM whatsapp_packets
        WHERE {scope_where}
    """, scope_params).fetchone()

    # Count unique IPs in scope
    ip_sql = f"""
        SELECT COUNT(DISTINCT ip) FROM (
            SELECT src_ip AS ip FROM whatsapp_packets WHERE {scope_where} AND src_ip IS NOT NULL
            UNION
            SELECT dst_ip AS ip FROM whatsapp_packets WHERE {scope_where} AND dst_ip IS NOT NULL
        )
    """
    unique_ips_count = conn.execute(ip_sql, scope_params + scope_params).fetchone()[0]

    conn.close()

    total_pages = max(1, (total_count + per_page - 1) // per_page)

    file_stats = {
        "total_packets": stats_row["total_packets"] if stats_row else 0,
        "unique_ips": unique_ips_count,
        "udp_count": stats_row["udp_count"] if stats_row else 0,
        "tcp_count": stats_row["tcp_count"] if stats_row else 0,
        "high_conf_count": stats_row["high_conf_count"] if stats_row else 0,
        "total_bytes": stats_row["total_bytes"] if stats_row else 0,
    }

    return {
        "rows": packet_rows,
        "total": total_count,
        "page": page,
        "per_page": per_page,
        "pages": total_pages,
        "file_stats": file_stats
    }


def get_packet_detail(row_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve full packet details by row id."""
    conn = _connect()
    row = conn.execute("SELECT * FROM whatsapp_packets WHERE id = ?", (row_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_parties(batch_id: str) -> List[Dict[str, Any]]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM parties WHERE batch_id = ? ORDER BY packet_count DESC",
        (batch_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_geo(ip: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    row = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_geo(ip: str, data: Dict[str, Any]):
    conn = _connect()
    conn.execute(
        """INSERT OR REPLACE INTO geo_cache
           (ip, country, city, latitude, longitude, asn, asn_org, looked_up_at, rdns_hostname)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (ip, data.get('country'), data.get('city'),
         data.get('latitude'), data.get('longitude'),
         data.get('asn'), data.get('asn_org'),
         data.get('looked_up_at'), data.get('rdns_hostname'))
    )
    conn.commit()
    conn.close()


def insert_sessions(batch_id: str, sessions: List[Dict[str, Any]]):
    conn = _connect()
    old_session_ids = [row[0] for row in conn.execute("SELECT session_id FROM sessions WHERE batch_id = ?", (batch_id,))]
    if old_session_ids:
        conn.executemany("DELETE FROM session_flow_links_v2 WHERE session_id = ?", [(sid,) for sid in old_session_ids])
    conn.execute("DELETE FROM sessions WHERE batch_id = ?", (batch_id,))
    conn.executemany(
        """INSERT INTO sessions
           (session_id, batch_id, party_id, start_ts, end_ts, media_type, total_bytes, burst_count, summary_text,
            schema_version, capture_id, local_subscriber_ip, observed_span_s, active_media_duration_s,
            transition_gap_s, flow_ids, party_ids, remote_endpoints, confidence, duration_anomaly)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                s['session_id'], batch_id, s.get('party_id') or (s.get('party_ids') or ['unresolved'])[0],
                s['start_ts'], s['end_ts'], s.get('media_type') or s.get('call_type'),
                s['total_bytes'], s.get('burst_count', s.get('total_packets', 0)), s.get('summary_text'),
                s.get('schema_version'), s.get('capture_id'), s.get('local_subscriber_ip'),
                s.get('observed_span_s'), s.get('active_media_duration_s'), s.get('transition_gap_s'),
                json.dumps(s.get('flow_ids', [])), json.dumps(s.get('party_ids', [])),
                json.dumps(s.get('remote_endpoints', [])), s.get('confidence'),
                1 if s.get('duration_anomaly') else 0
            )
            for s in sessions
        ]
    )
    conn.executemany(
        "INSERT OR IGNORE INTO session_flow_links_v2(session_id, flow_id) VALUES (?, ?)",
        [(s['session_id'], flow_id) for s in sessions for flow_id in s.get('flow_ids', [])]
    )
    conn.commit()
    conn.close()

def get_sessions(batch_id: str) -> List[Dict[str, Any]]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM sessions WHERE batch_id = ? ORDER BY start_ts",
        (batch_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def clear_batch_analysis(batch_id: str):
    """Remove all analysis data for a batch."""
    conn = _connect()
    upload_ids = [row[0] for row in conn.execute("SELECT DISTINCT upload_id FROM whatsapp_packets WHERE batch_id = ?", (batch_id,))]
    party_ids = [row[0] for row in conn.execute("SELECT party_id FROM parties WHERE batch_id = ?", (batch_id,))]
    session_ids = [row[0] for row in conn.execute("SELECT session_id FROM sessions WHERE batch_id = ?", (batch_id,))]
    conn.executemany("DELETE FROM analysis_flows_v2 WHERE upload_id = ?", [(uid,) for uid in upload_ids])
    conn.executemany("DELETE FROM party_flow_links_v2 WHERE party_id = ?", [(pid,) for pid in party_ids])
    conn.executemany("DELETE FROM session_flow_links_v2 WHERE session_id = ?", [(sid,) for sid in session_ids])
    conn.execute("DELETE FROM whatsapp_packets WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM parties WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM sessions WHERE batch_id = ?", (batch_id,))
    conn.commit()
    conn.close()


def clear_upload_packets(upload_id: str) -> None:
    conn = _connect()
    flow_ids = [row[0] for row in conn.execute('SELECT flow_id FROM analysis_flows_v2 WHERE upload_id = ?', (upload_id,))]
    if flow_ids:
        conn.executemany('DELETE FROM party_flow_links_v2 WHERE flow_id = ?', [(fid,) for fid in flow_ids])
        conn.executemany('DELETE FROM session_flow_links_v2 WHERE flow_id = ?', [(fid,) for fid in flow_ids])
    conn.execute('DELETE FROM analysis_flows_v2 WHERE upload_id = ?', (upload_id,))
    conn.execute('DELETE FROM whatsapp_packets WHERE upload_id = ?', (upload_id,))
    conn.commit(); conn.close()
