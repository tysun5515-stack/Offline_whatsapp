"""
db_analysis.py — DB-2: Derived analysis data (whatsapp_analysis.db).
Fully recomputable from the original pcap via the pipeline.
Joined to DB-1 via batch_id/upload_id in application code only.
"""
import sqlite3
import os
import json
import uuid
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
ANALYSIS_DB_PATH = os.path.join(BASE_DIR, 'whatsapp_analysis.db')

AGENT_CONTRACT_VERSION = "whatsapp-live-agent-v1"
AGENT_RULESET_VERSION = "whatsapp-rules-2026-10"
AGENT_RULES = (
    ("call_count", "Call count", "A call is one qualified reconstructed session, never a packet or flow count.", "sessions"),
    ("call_direction", "Caller and callee", "Caller/callee remains unknown unless explicit signaling or analyst metadata proves initiation direction.", "limitation"),
    ("message_count", "Encrypted messages", "Encrypted traffic can show messaging-associated transport, not message content or a reliable count of individual messages.", "limitation"),
    ("relay_role", "Relay endpoints", "A STUN/TURN/Meta relay is infrastructure and must not be presented as the human peer.", "limitation"),
    ("unresolved_call", "Unresolved call candidate", "Call-like encrypted traffic remains separate from confirmed voice and video totals.", "classification"),
    ("incomplete_capture", "Incomplete capture", "Missing evidence remains incomplete and is not replaced by an inferred negotiation or role.", "limitation"),
)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(ANALYSIS_DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-32000")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA busy_timeout=30000")
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

        CREATE TABLE IF NOT EXISTS crypto_flows (
            flow_id                   TEXT PRIMARY KEY,
            upload_id                 TEXT NOT NULL,
            batch_id                  TEXT NOT NULL,
            transport                 TEXT,
            ip_version                INTEGER,
            server_ip                 TEXT,
            server_port               INTEGER,
            client_ip                 TEXT,
            client_port               INTEGER,
            server_name               TEXT,
            name_source               TEXT,
            direction_coverage        TEXT,
            start_seen                INTEGER DEFAULT 0,
            client_hello_complete     INTEGER DEFAULT 0,
            server_hello_complete     INTEGER DEFAULT 0,
            hrr_seen                  INTEGER DEFAULT 0,
            sh_is_hrr_only            INTEGER DEFAULT 0,
            evidence_tier             INTEGER,
            ch_frame_no               INTEGER,
            ch_legacy_version         TEXT,
            ch_cipher_suites_json     TEXT,
            ch_supported_groups_json  TEXT,
            ch_key_share_groups_json  TEXT,
            ch_key_share_lens_json    TEXT,
            ch_sig_algs_json          TEXT,
            ch_ext_ids_json           TEXT,
            ch_alpn_json              TEXT,
            ch_has_sni                INTEGER DEFAULT 0,
            ch_has_ech                INTEGER DEFAULT 0,
            ch_has_psk                INTEGER DEFAULT 0,
            ch_ja3                    TEXT,
            sh_frame_no               INTEGER,
            sh_neg_version            TEXT,
            sh_cipher                 TEXT,
            sh_cipher_name            TEXT,
            sh_key_share_group        TEXT,
            sh_key_share_group_name   TEXT,
            sh_key_share_len          INTEGER,
            sh_psk_selected           INTEGER DEFAULT 0,
            sh_is_hrr                 INTEGER DEFAULT 0,
            sh_ja3s                   TEXT,
            neg_kex_mode              TEXT,
            neg_group                 TEXT,
            neg_group_name            TEXT,
            neg_group_class           TEXT,
            neg_cipher                TEXT,
            neg_cipher_name           TEXT,
            neg_resumed               INTEGER DEFAULT 0,
            pqc_capability            INTEGER DEFAULT 0,
            pqc_key_share_offered     INTEGER DEFAULT 0,
            pqc_server_selected       INTEGER DEFAULT 0,
            pqc_state                 TEXT,
            pqc_basis                 TEXT,
            wa_ephemeral_key_len      INTEGER,
            wa_static_len             INTEGER,
            wa_payload_len            INTEGER,
            wa_max_opaque_len         INTEGER,
            wa_pattern_hint           TEXT,
            flag_offers_cbc           INTEGER DEFAULT 0,
            flag_offers_rsa_kex       INTEGER DEFAULT 0,
            flag_offers_sha1_sig      INTEGER DEFAULT 0,
            flag_offers_tls12         INTEGER DEFAULT 0,
            flag_negotiated_legacy    INTEGER DEFAULT 0,
            quic_version              TEXT,
            quic_dcid                 TEXT,
            quic_scid                 TEXT,
            first_seen                REAL,
            last_seen                 REAL,
            duration_s                REAL,
            total_packets             INTEGER,
            total_bytes               INTEGER,
            extractor_version         TEXT DEFAULT '1.0.0',
            registry_version          TEXT DEFAULT '2026-09',
            classification            TEXT,
            whatsapp_confidence       TEXT,
            kex_class                 TEXT,
            size_mismatch             INTEGER DEFAULT 0,
            unknown_groups_json       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_crypto_flows_upload  ON crypto_flows(upload_id);
        CREATE INDEX IF NOT EXISTS idx_crypto_flows_batch   ON crypto_flows(batch_id);
        CREATE INDEX IF NOT EXISTS idx_crypto_flows_server  ON crypto_flows(server_name, server_ip);
        CREATE INDEX IF NOT EXISTS idx_crypto_flows_pqc     ON crypto_flows(pqc_state);

        CREATE TABLE IF NOT EXISTS crypto_events (
            event_id       TEXT PRIMARY KEY,
            flow_id        TEXT NOT NULL,
            upload_id      TEXT NOT NULL,
            frame_no       INTEGER,
            ts             REAL,
            direction      TEXT,
            msg_type       TEXT,
            raw_fields_json TEXT,
            ext_ids_json   TEXT,
            bytes_len      INTEGER,
            FOREIGN KEY (flow_id) REFERENCES crypto_flows(flow_id)
        );
        CREATE INDEX IF NOT EXISTS idx_crypto_events_flow ON crypto_events(flow_id);

        CREATE TABLE IF NOT EXISTS analysis_metadata (
            key TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS analysis_upload_state (
            upload_id TEXT PRIMARY KEY, batch_id TEXT, filename TEXT, file_format TEXT,
            source_sha256 TEXT, filtered_sha256 TEXT,
            capture_start_ts REAL, capture_end_ts REAL, capture_packet_count INTEGER,
            capture_duration_s REAL, capture_vantage TEXT, subscriber_ips TEXT,
            state TEXT NOT NULL, analysis_revision INTEGER,
            contract_version TEXT NOT NULL, ruleset_version TEXT NOT NULL,
            packet_count INTEGER NOT NULL DEFAULT 0, flow_count INTEGER NOT NULL DEFAULT 0,
            party_count INTEGER NOT NULL DEFAULT 0, session_count INTEGER NOT NULL DEFAULT 0,
            crypto_flow_count INTEGER NOT NULL DEFAULT 0, crypto_evidence_count INTEGER NOT NULL DEFAULT 0,
            quality_status TEXT NOT NULL DEFAULT 'pending', result_digest TEXT,
            started_at TEXT, completed_at TEXT, error TEXT
        );
        CREATE TABLE IF NOT EXISTS analysis_quality_findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT, upload_id TEXT,
            revision_id INTEGER, severity TEXT NOT NULL, code TEXT NOT NULL,
            message TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS analysis_revision_ledger (
            revision_id INTEGER PRIMARY KEY AUTOINCREMENT, upload_id TEXT NOT NULL,
            event TEXT NOT NULL, result_digest TEXT NOT NULL, previous_hash TEXT,
            record_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS analysis_revision_no_update
          BEFORE UPDATE ON analysis_revision_ledger BEGIN SELECT RAISE(ABORT, 'revision ledger is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS analysis_revision_no_delete
          BEFORE DELETE ON analysis_revision_ledger BEGIN SELECT RAISE(ABORT, 'revision ledger is append-only'); END;
        CREATE TABLE IF NOT EXISTS agent_rules (
            rule_id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, category TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS upload_metrics (
            upload_id TEXT PRIMARY KEY, batch_id TEXT, packet_count INTEGER NOT NULL,
            flow_count INTEGER NOT NULL, whatsapp_count INTEGER NOT NULL,
            detected_os TEXT, bypass_mode INTEGER DEFAULT 0, total_raw_packets INTEGER DEFAULT 0,
            pass1_accepted INTEGER DEFAULT 0, pass2_dns_accepted INTEGER DEFAULT 0,
            rejected_no_signal INTEGER DEFAULT 0, non_ip_count INTEGER DEFAULT 0,
            reconciliation_ok INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_agent_state_status ON analysis_upload_state(state, capture_start_ts);
        CREATE INDEX IF NOT EXISTS idx_agent_quality_upload ON analysis_quality_findings(upload_id, revision_id);
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
        "subscriber_resolution_source TEXT", "subscriber_resolution_confidence TEXT",
        "role_label TEXT", "role_source TEXT", "caveat_type TEXT", "caveat TEXT",
        "is_server INTEGER DEFAULT 0", "location_reliable INTEGER DEFAULT 0"
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
            
    # Add migration for crypto_status column
    try:
        conn.execute("ALTER TABLE analysis_flows_v2 ADD COLUMN crypto_status TEXT DEFAULT 'not_run'")
    except Exception:
        pass
        
    # Add migrations for classification and whatsapp_confidence in crypto_flows
    try:
        conn.execute("ALTER TABLE crypto_flows ADD COLUMN classification TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE crypto_flows ADD COLUMN whatsapp_confidence TEXT")
    except Exception:
        pass
        
    for col in [
        "ALTER TABLE crypto_flows ADD COLUMN kex_class TEXT",
        "ALTER TABLE crypto_flows ADD COLUMN size_mismatch INTEGER DEFAULT 0",
        "ALTER TABLE crypto_flows ADD COLUMN unknown_groups_json TEXT",
        "ALTER TABLE crypto_flows ADD COLUMN sh_is_hrr_only INTEGER DEFAULT 0",
    ]:
        try:
            conn.execute(col)
        except Exception:
            pass
        
    # Null out stale tls_crypto_info data
    conn.execute("UPDATE whatsapp_packets SET tls_crypto_info = NULL WHERE tls_crypto_info IS NOT NULL")

    # Add indexes for performance
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_upload ON whatsapp_packets(upload_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON whatsapp_packets(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_confidence ON whatsapp_packets(whatsapp_confidence)")
    conn.executemany(
        "INSERT OR REPLACE INTO derived_schema_metadata(component, version) VALUES (?, 2)",
        [("flows",), ("parties",), ("sessions",)],
    )
    if not conn.execute("SELECT 1 FROM analysis_metadata WHERE key='database_instance_id'").fetchone():
        conn.execute("INSERT INTO analysis_metadata(key,value) VALUES('database_instance_id',?)", (str(uuid.uuid4()),))
    conn.executemany("INSERT OR REPLACE INTO analysis_metadata(key,value) VALUES(?,?)", (
        ("agent_contract_version", AGENT_CONTRACT_VERSION),
        ("agent_ruleset_version", AGENT_RULESET_VERSION),
    ))
    conn.executemany("INSERT OR REPLACE INTO agent_rules(rule_id,title,body,category) VALUES(?,?,?,?)", AGENT_RULES)
    conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS agent_rules_fts USING fts5(rule_id UNINDEXED,title,body,category)")
    conn.execute("DELETE FROM agent_rules_fts")
    conn.execute("INSERT INTO agent_rules_fts(rule_id,title,body,category) SELECT rule_id,title,body,category FROM agent_rules")
    _create_agent_views(conn)
    
    conn.commit()
    conn.close()


def _create_agent_views(conn: sqlite3.Connection) -> None:
    for name in (
        "v_agent_dataset", "v_agent_captures", "v_agent_packets", "v_agent_flows",
        "v_agent_parties", "v_agent_calls", "v_agent_endpoints", "v_agent_crypto",
        "v_agent_crypto_evidence", "v_agent_geo", "v_agent_metrics",
        "v_agent_correlations", "v_agent_rules", "v_agent_quality",
    ):
        conn.execute(f'DROP VIEW IF EXISTS "{name}"')
    conn.executescript("""
        CREATE VIEW v_agent_dataset AS
        SELECT
          (SELECT value FROM analysis_metadata WHERE key='database_instance_id') AS database_instance_id,
          (SELECT value FROM analysis_metadata WHERE key='agent_contract_version') AS contract_version,
          (SELECT value FROM analysis_metadata WHERE key='agent_ruleset_version') AS ruleset_version,
          COALESCE((SELECT MAX(revision_id) FROM analysis_revision_ledger),0) AS current_revision,
          COALESCE(SUM(CASE WHEN state='ready' THEN 1 ELSE 0 END),0) AS ready_upload_count,
          COALESCE(SUM(CASE WHEN state='ready_no_match' THEN 1 ELSE 0 END),0) AS no_match_upload_count,
          COALESCE(SUM(CASE WHEN state='processing' THEN 1 ELSE 0 END),0) AS processing_upload_count,
          COALESCE(SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END),0) AS failed_upload_count,
          COALESCE(SUM(CASE WHEN state='ready' THEN packet_count ELSE 0 END),0) AS packet_count,
          COALESCE(SUM(CASE WHEN state='ready' THEN flow_count ELSE 0 END),0) AS flow_count,
          COALESCE(SUM(CASE WHEN state='ready' THEN party_count ELSE 0 END),0) AS party_count,
          COALESCE(SUM(CASE WHEN state='ready' THEN session_count ELSE 0 END),0) AS session_count,
          COALESCE(SUM(CASE WHEN state='ready' THEN crypto_flow_count ELSE 0 END),0) AS crypto_flow_count,
          CASE
            WHEN SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END) > 0 THEN 'fail'
            WHEN SUM(CASE WHEN quality_status='warn' THEN 1 ELSE 0 END) > 0 THEN 'warn'
            ELSE 'pass'
          END AS quality_status
        FROM analysis_upload_state WHERE state != 'deleted';

        CREATE VIEW v_agent_captures AS
          SELECT upload_id,batch_id,filename,file_format,source_sha256,filtered_sha256,
                 capture_start_ts,capture_end_ts,capture_packet_count,capture_duration_s,
                 capture_vantage,subscriber_ips,state,analysis_revision,contract_version,
                 ruleset_version,packet_count,flow_count,party_count,session_count,
                 crypto_flow_count,crypto_evidence_count,quality_status,result_digest,
                 started_at,completed_at,error
          FROM analysis_upload_state WHERE state IN ('ready','ready_no_match');

        CREATE VIEW v_agent_packets AS
          SELECT p.id AS packet_id,p.* FROM whatsapp_packets p
          JOIN analysis_upload_state s ON s.upload_id=p.upload_id AND s.state='ready';
        CREATE VIEW v_agent_flows AS
          SELECT f.*,s.batch_id FROM analysis_flows_v2 f
          JOIN analysis_upload_state s ON s.upload_id=f.upload_id AND s.state='ready';
        CREATE VIEW v_agent_parties AS
          SELECT p.* FROM parties p
          JOIN analysis_upload_state s ON s.upload_id=p.upload_id AND s.state='ready';
        CREATE VIEW v_agent_calls AS
          SELECT x.*, x.media_type AS call_type,
                 CASE WHEN x.media_type='unresolved' THEN 'candidate' ELSE 'confirmed' END AS confirmation_class,
                 'unknown_unless_proven' AS role_status, x.burst_count AS total_packets
          FROM sessions x JOIN analysis_upload_state s ON s.upload_id=x.capture_id AND s.state='ready';
        CREATE VIEW v_agent_endpoints AS
          SELECT endpoint_ip,MIN(first_seen) AS first_seen,MAX(last_seen) AS last_seen,
                 COUNT(DISTINCT upload_id) AS capture_count,COUNT(DISTINCT flow_id) AS flow_count,
                 MAX(observed_as_subscriber) AS observed_as_subscriber
          FROM (
            SELECT upload_id,flow_id,endpoint_a_ip AS endpoint_ip,first_seen,last_seen,
                   CASE WHEN endpoint_a_ip=local_subscriber_ip THEN 1 ELSE 0 END AS observed_as_subscriber
            FROM v_agent_flows
            UNION ALL
            SELECT upload_id,flow_id,endpoint_b_ip,first_seen,last_seen,
                   CASE WHEN endpoint_b_ip=local_subscriber_ip THEN 1 ELSE 0 END
            FROM v_agent_flows
          ) WHERE endpoint_ip IS NOT NULL GROUP BY endpoint_ip;
        CREATE VIEW v_agent_crypto AS
          SELECT c.* FROM crypto_flows c
          JOIN analysis_upload_state s ON s.upload_id=c.upload_id AND s.state='ready';
        CREATE VIEW v_agent_crypto_evidence AS
          SELECT e.* FROM crypto_events e
          JOIN analysis_upload_state s ON s.upload_id=e.upload_id AND s.state='ready';
        CREATE VIEW v_agent_geo AS
          SELECT g.* FROM geo_cache g WHERE g.ip IN (SELECT endpoint_ip FROM v_agent_endpoints);
        CREATE VIEW v_agent_metrics AS
          SELECT m.* FROM upload_metrics m
          JOIN analysis_upload_state s ON s.upload_id=m.upload_id AND s.state IN ('ready','ready_no_match');
        CREATE VIEW v_agent_correlations AS
          SELECT c.* FROM correlation_results c
          JOIN analysis_upload_state a ON a.upload_id=c.upload_id_a AND a.state='ready'
          JOIN analysis_upload_state b ON b.upload_id=c.upload_id_b AND b.state='ready';
        CREATE VIEW v_agent_rules AS SELECT * FROM agent_rules;
        CREATE VIEW v_agent_quality AS
          SELECT q.* FROM analysis_quality_findings q
          LEFT JOIN analysis_upload_state s ON s.upload_id=q.upload_id
          WHERE q.upload_id IS NULL OR s.state IN ('ready','ready_no_match','failed');
    """)

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


def upsert_upload_metrics(upload_id: str, batch_id: str, metrics: Dict[str, Any]):
    """Persist authoritative per-upload metrics and refresh the legacy batch aggregate."""
    conn = _connect()
    values = (
        upload_id, batch_id, metrics.get('packet_count', 0), metrics.get('flow_count', 0),
        metrics.get('whatsapp_count', 0), metrics.get('detected_os', 'unknown'),
        1 if metrics.get('bypass_mode') else 0,
        metrics.get('total_raw_packets', metrics.get('packet_count', 0)),
        metrics.get('pass1_accepted', 0), metrics.get('pass2_dns_accepted', 0),
        metrics.get('rejected_no_signal', 0), metrics.get('non_ip_count', 0),
        1 if metrics.get('reconciliation_ok', True) else 0,
    )
    conn.execute("""INSERT OR REPLACE INTO upload_metrics
        (upload_id,batch_id,packet_count,flow_count,whatsapp_count,detected_os,bypass_mode,
         total_raw_packets,pass1_accepted,pass2_dns_accepted,rejected_no_signal,non_ip_count,reconciliation_ok)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", values)
    aggregate = conn.execute("""SELECT COALESCE(SUM(packet_count),0),COALESCE(SUM(flow_count),0),
        COALESCE(SUM(whatsapp_count),0),MAX(detected_os),MAX(bypass_mode),COALESCE(SUM(total_raw_packets),0),
        COALESCE(SUM(pass1_accepted),0),COALESCE(SUM(pass2_dns_accepted),0),
        COALESCE(SUM(rejected_no_signal),0),COALESCE(SUM(non_ip_count),0),MIN(reconciliation_ok)
        FROM upload_metrics WHERE batch_id=?""", (batch_id,)).fetchone()
    conn.execute("""INSERT OR REPLACE INTO batch_metrics
        (batch_id,packet_count,flow_count,whatsapp_count,detected_os,bypass_mode,total_raw_packets,
         pass1_accepted,pass2_dns_accepted,rejected_no_signal,non_ip_count,reconciliation_ok)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (batch_id, *aggregate))
    conn.commit(); conn.close()

def get_batch_metrics(batch_id: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    row = conn.execute("SELECT * FROM batch_metrics WHERE batch_id = ?", (batch_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def _delete_in_chunks(conn, table, col, ids, chunk=900):
    for i in range(0, len(ids), chunk):
        batch = ids[i:i+chunk]
        marks = ','.join('?' * len(batch))
        conn.execute(f"DELETE FROM {table} WHERE {col} IN ({marks})", batch)

def clear_batch_packets(batch_id: str):
    """Remove all derived data for a batch before re-filtering."""
    conn = _connect()
    upload_ids = [row[0] for row in conn.execute("SELECT DISTINCT upload_id FROM whatsapp_packets WHERE batch_id = ?", (batch_id,))]
    party_ids = [row[0] for row in conn.execute("SELECT party_id FROM parties WHERE batch_id = ?", (batch_id,))]
    session_ids = [row[0] for row in conn.execute("SELECT session_id FROM sessions WHERE batch_id = ?", (batch_id,))]
    
    if upload_ids:
        _delete_in_chunks(conn, "analysis_flows_v2", "upload_id", upload_ids)
    if party_ids:
        _delete_in_chunks(conn, "party_flow_links_v2", "party_id", party_ids)
    if session_ids:
        _delete_in_chunks(conn, "session_flow_links_v2", "session_id", session_ids)
    conn.execute("DELETE FROM whatsapp_packets WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM parties WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM sessions WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM batch_metrics WHERE batch_id = ?", (batch_id,))
    conn.commit()
    conn.close()


def insert_whatsapp_packets(batch_id: str, upload_id: str, filename: str, packets_iterable):
    """Insert classified packets directly from an iterable/generator. Returns a set of packet numbers."""
    conn = _connect()
    old_flow_ids = [row[0] for row in conn.execute(
        "SELECT flow_id FROM analysis_flows_v2 WHERE upload_id = ?", (upload_id,)
    )]
    if old_flow_ids:
        conn.executemany("DELETE FROM party_flow_links_v2 WHERE flow_id = ?", [(fid,) for fid in old_flow_ids])
        conn.executemany("DELETE FROM session_flow_links_v2 WHERE flow_id = ?", [(fid,) for fid in old_flow_ids])
    conn.execute("DELETE FROM analysis_flows_v2 WHERE upload_id = ?", (upload_id,))
    conn.execute("DELETE FROM whatsapp_packets WHERE upload_id = ?", (upload_id,))

    from itertools import islice

    CHUNK_SIZE = 10000
    flow_summaries: Dict[str, Dict] = {}
    packet_numbers = set()
    
    packet_iterator = iter(packets_iterable)
    while True:
        chunk = list(islice(packet_iterator, CHUNK_SIZE))
        if not chunk:
            break
            
        for p in chunk:
            if p.get('packet_no') is not None:
                packet_numbers.add(int(p['packet_no']))
        
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
        for p in chunk:
            fid = p.get('flow_id')
            if not fid:
                continue
            fid = str(fid)
            ea = p.get('endpoint_a_ip')
            ts = p.get('timestamp') or 0
            ln = p.get('length') or 0
            src = p.get('src_ip')
            if fid not in flow_summaries:
                flow_summaries[fid] = {
                    'upload_id': upload_id, 'flow_instance': p.get('flow_instance'),
                    'endpoint_a_ip': ea, 'endpoint_a_port': p.get('endpoint_a_port'),
                    'endpoint_b_ip': p.get('endpoint_b_ip'), 'endpoint_b_port': p.get('endpoint_b_port'),
                    'protocol': p.get('protocol'), 'local_subscriber_ip': p.get('local_subscriber_ip'),
                    'sub_src': p.get('subscriber_resolution_source'),
                    'sub_conf': p.get('subscriber_resolution_confidence'),
                    'first_ts': ts, 'last_ts': ts,
                    'a_to_b_packets': 0, 'b_to_a_packets': 0,
                    'a_to_b_bytes': 0, 'b_to_a_bytes': 0,
                    'media_type': p.get('whatsapp_media_guess'),
                    'confidence': p.get('whatsapp_confidence'),
                }
            s = flow_summaries[fid]
            s['first_ts'] = min(s['first_ts'], ts)
            s['last_ts'] = max(s['last_ts'], ts)
            if src == ea:
                s['a_to_b_packets'] += 1; s['a_to_b_bytes'] += ln
            else:
                s['b_to_a_packets'] += 1; s['b_to_a_bytes'] += ln
                
    for flow_id, s in flow_summaries.items():
        conn.execute("""INSERT OR REPLACE INTO analysis_flows_v2
            (flow_id, upload_id, flow_instance, endpoint_a_ip, endpoint_a_port, endpoint_b_ip, endpoint_b_port,
             protocol, local_subscriber_ip, subscriber_resolution_source, subscriber_resolution_confidence,
             first_seen, last_seen, a_to_b_packets, b_to_a_packets, a_to_b_bytes, b_to_a_bytes,
             media_type, confidence, schema_version)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            flow_id, s['upload_id'], s['flow_instance'], s['endpoint_a_ip'], s['endpoint_a_port'],
            s['endpoint_b_ip'], s['endpoint_b_port'], s['protocol'],
            s['local_subscriber_ip'], s['sub_src'],
            s['sub_conf'], s['first_ts'], s['last_ts'],
            s['a_to_b_packets'], s['b_to_a_packets'], s['a_to_b_bytes'],
            s['b_to_a_bytes'], s['media_type'],
            s['confidence'], 'flow-v2'))
    conn.commit()
    count = conn.execute(
        "SELECT COUNT(1) FROM whatsapp_packets WHERE upload_id = ?", (upload_id,)
    ).fetchone()[0]
    conn.close()
    return count, packet_numbers


def insert_parties(batch_id: str, parties: List[Dict[str, Any]], upload_id: Optional[str] = None):
    conn = _connect()
    if upload_id is None:
        predicate, key = "batch_id = ?", batch_id
    else:
        predicate, key = "upload_id = ?", upload_id
    old_party_ids = [row[0] for row in conn.execute(f"SELECT party_id FROM parties WHERE {predicate}", (key,))]
    if old_party_ids:
        conn.executemany("DELETE FROM party_flow_links_v2 WHERE party_id = ?", [(pid,) for pid in old_party_ids])
    conn.execute(f"DELETE FROM parties WHERE {predicate}", (key,))
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


def get_parties_scope(upload_ids: List[str], start_ts: Optional[float] = None,
                      end_ts: Optional[float] = None) -> List[Dict[str, Any]]:
    if not upload_ids:
        return []
    conn = _connect(); marks = ','.join('?' for _ in upload_ids)
    where, params = [f"upload_id IN ({marks})"], list(upload_ids)
    if start_ts is not None:
        where.append("last_seen >= ?"); params.append(start_ts)
    if end_ts is not None:
        where.append("first_seen < ?"); params.append(end_ts)
    rows = conn.execute(f"SELECT * FROM parties WHERE {' AND '.join(where)} ORDER BY packet_count DESC", params).fetchall()
    conn.close(); return [dict(row) for row in rows]


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


def insert_sessions(batch_id: str, sessions: List[Dict[str, Any]], upload_id: Optional[str] = None):
    conn = _connect()
    if upload_id is None:
        predicate, key = "batch_id = ?", batch_id
    else:
        predicate, key = "capture_id = ?", upload_id
    old_session_ids = [row[0] for row in conn.execute(f"SELECT session_id FROM sessions WHERE {predicate}", (key,))]
    if old_session_ids:
        conn.executemany("DELETE FROM session_flow_links_v2 WHERE session_id = ?", [(sid,) for sid in old_session_ids])
    conn.execute(f"DELETE FROM sessions WHERE {predicate}", (key,))
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


def get_sessions_scope(upload_ids: List[str], start_ts: Optional[float] = None,
                       end_ts: Optional[float] = None) -> List[Dict[str, Any]]:
    if not upload_ids:
        return []
    conn = _connect(); marks = ','.join('?' for _ in upload_ids)
    where, params = [f"capture_id IN ({marks})"], list(upload_ids)
    if start_ts is not None:
        where.append("end_ts >= ?"); params.append(start_ts)
    if end_ts is not None:
        where.append("start_ts < ?"); params.append(end_ts)
    rows = conn.execute(f"SELECT * FROM sessions WHERE {' AND '.join(where)} ORDER BY start_ts", params).fetchall()
    conn.close(); return [dict(row) for row in rows]

def clear_batch_analysis(batch_id: str):
    """Remove all analysis data for a batch."""
    conn = _connect()
    upload_ids = [row[0] for row in conn.execute("SELECT DISTINCT upload_id FROM whatsapp_packets WHERE batch_id = ?", (batch_id,))]
    party_ids = [row[0] for row in conn.execute("SELECT party_id FROM parties WHERE batch_id = ?", (batch_id,))]
    session_ids = [row[0] for row in conn.execute("SELECT session_id FROM sessions WHERE batch_id = ?", (batch_id,))]
    if upload_ids:
        _delete_in_chunks(conn, "analysis_flows_v2", "upload_id", upload_ids)
        _delete_in_chunks(conn, "crypto_events", "upload_id", upload_ids)
    if party_ids:
        _delete_in_chunks(conn, "party_flow_links_v2", "party_id", party_ids)
    if session_ids:
        _delete_in_chunks(conn, "session_flow_links_v2", "session_id", session_ids)
    conn.execute("DELETE FROM crypto_flows WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM whatsapp_packets WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM parties WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM sessions WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM upload_metrics WHERE batch_id = ?", (batch_id,))
    conn.execute("DELETE FROM batch_metrics WHERE batch_id = ?", (batch_id,))
    conn.commit()
    conn.close()


def clear_upload_packets(upload_id: str) -> None:
    conn = _connect()
    flow_ids = [row[0] for row in conn.execute('SELECT flow_id FROM analysis_flows_v2 WHERE upload_id = ?', (upload_id,))]
    party_ids = [row[0] for row in conn.execute('SELECT party_id FROM parties WHERE upload_id = ?', (upload_id,))]
    session_ids = [row[0] for row in conn.execute('SELECT session_id FROM sessions WHERE capture_id = ?', (upload_id,))]
    if flow_ids:
        _delete_in_chunks(conn, 'party_flow_links_v2', 'flow_id', flow_ids)
        _delete_in_chunks(conn, 'session_flow_links_v2', 'flow_id', flow_ids)
    if party_ids:
        _delete_in_chunks(conn, 'party_flow_links_v2', 'party_id', party_ids)
    if session_ids:
        _delete_in_chunks(conn, 'session_flow_links_v2', 'session_id', session_ids)
    conn.execute('DELETE FROM crypto_events WHERE upload_id = ?', (upload_id,))
    conn.execute('DELETE FROM crypto_flows WHERE upload_id = ?', (upload_id,))
    conn.execute('DELETE FROM analysis_flows_v2 WHERE upload_id = ?', (upload_id,))
    conn.execute('DELETE FROM parties WHERE upload_id = ?', (upload_id,))
    conn.execute('DELETE FROM sessions WHERE capture_id = ?', (upload_id,))
    conn.execute('DELETE FROM whatsapp_packets WHERE upload_id = ?', (upload_id,))
    conn.execute('DELETE FROM upload_metrics WHERE upload_id = ?', (upload_id,))
    conn.commit(); conn.close()


def insert_crypto_flows(batch_id: str, upload_id: str, flows: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> None:
    conn = _connect()
    
    if not flows:
        conn.close()
        return

    columns = list(flows[0].keys())
    # Ensure mandatory fields
    for f in flows:
        f['batch_id'] = batch_id
        f['upload_id'] = upload_id
    if 'batch_id' not in columns: columns.append('batch_id')
    if 'upload_id' not in columns: columns.append('upload_id')

    placeholders = ', '.join(['?'] * len(columns))
    sql = f"INSERT OR REPLACE INTO crypto_flows ({', '.join(columns)}) VALUES ({placeholders})"
    
    conn.executemany(sql, [[f.get(col) for col in columns] for f in flows])

    if events:
        evt_cols = list(events[0].keys())
        for e in events:
            e['upload_id'] = upload_id
        if 'upload_id' not in evt_cols: evt_cols.append('upload_id')
        
        evt_placeholders = ', '.join(['?'] * len(evt_cols))
        evt_sql = f"INSERT OR REPLACE INTO crypto_events ({', '.join(evt_cols)}) VALUES ({evt_placeholders})"
        conn.executemany(evt_sql, [[e.get(col) for col in evt_cols] for e in events])
        
    # Mark crypto_status as ok for these flows in analysis_flows_v2
    flow_ids = [f.get('flow_id') for f in flows if f.get('flow_id')]
    if flow_ids:
        marks = ','.join('?' for _ in flow_ids)
        conn.execute(f"UPDATE analysis_flows_v2 SET crypto_status = 'ok' WHERE flow_id IN ({marks})", flow_ids)

    conn.commit()
    conn.close()


def get_crypto_flows(upload_id: Optional[str] = None, batch_id: Optional[str] = None, pqc_state: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = _connect()
    query = "SELECT * FROM crypto_flows WHERE 1=1"
    params = []
    if upload_id:
        query += " AND upload_id = ?"
        params.append(upload_id)
    if batch_id:
        query += " AND batch_id = ?"
        params.append(batch_id)
    if pqc_state:
        query += " AND pqc_state = ?"
        params.append(pqc_state)
        
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_crypto_events(flow_id: str) -> List[Dict[str, Any]]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM crypto_events WHERE flow_id = ? ORDER BY frame_no ASC",
        (flow_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_crypto_summary(batch_id: str) -> Dict[str, Any]:
    conn = _connect()
    rows = conn.execute(
        "SELECT pqc_state, count(*) as count FROM crypto_flows WHERE batch_id = ? GROUP BY pqc_state",
        (batch_id,)
    ).fetchall()
    
    total = conn.execute("SELECT count(*) FROM crypto_flows WHERE batch_id = ?", (batch_id,)).fetchone()[0]
    legacy_flags = conn.execute(
        "SELECT count(*) FROM crypto_flows WHERE batch_id = ? AND (flag_offers_cbc=1 OR flag_offers_rsa_kex=1 OR flag_offers_sha1_sig=1)",
        (batch_id,)
    ).fetchone()[0]
    
    conn.close()
    
    summary = {
        'total_flows': total,
        'analyzed_flows': total,
        'legacy_ciphers': legacy_flags,
        'pqc_server_selected': 0,
        'pqc_key_share_offered': 0,
        'pqc_not_observed': 0,
        'states': {}
    }
    for r in rows:
        summary['states'][r['pqc_state']] = r['count']
        if r['pqc_state'] == 'server_selected':
            summary['pqc_server_selected'] = r['count']
        elif r['pqc_state'] == 'key_share_offered':
            summary['pqc_key_share_offered'] = r['count']
        elif r['pqc_state'] == 'not_observed':
            summary['pqc_not_observed'] = r['count']
        
    return summary
