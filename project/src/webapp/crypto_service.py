"""Offline, hash-bound crypto evidence extracted by local TShark."""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager

from src.webapp import db_analysis as db
from src.webapp.db_registry import get_upload

_lock = threading.Lock()
VERSION = 'tshark-offline-v1'


def enabled():
    return os.environ.get('WA_CRYPTO_ANALYSIS_ENABLED', 'true').lower() not in ('0', 'false', 'off', 'no')


@contextmanager
def connect():
    c = sqlite3.connect(db.ANALYSIS_DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.executescript('''
      CREATE TABLE IF NOT EXISTS crypto_reports_v3 (
        upload_id TEXT PRIMARY KEY, source_hash TEXT, status TEXT,
        error TEXT, updated REAL, extractor TEXT, tool_version TEXT);
      CREATE TABLE IF NOT EXISTS crypto_evidence_v3 (
        event_id TEXT PRIMARY KEY, upload_id TEXT, frame_no INTEGER,
        timestamp REAL, protocol TEXT, src_ip TEXT, dst_ip TEXT,
        src_port INTEGER, dst_port INTEGER, source_hash TEXT, fields TEXT);
      CREATE INDEX IF NOT EXISTS crypto_evidence_upload_v3 ON crypto_evidence_v3(upload_id, timestamp);
      CREATE TABLE IF NOT EXISTS crypto_claims_v3 (
        claim_id TEXT PRIMARY KEY, upload_id TEXT, source_hash TEXT,
        source TEXT, observed_at REAL, claim TEXT);
    ''')
    try:
        with c:
            yield c
    finally:
        c.close()


def analyze(upload_id):
    if not enabled():
        return {'status': 'disabled'}
    upload = get_upload(upload_id)
    if not upload:
        raise ValueError('Unknown upload')
    with _lock:
        path = upload['stored_path']
        digest = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                digest.update(chunk)
        source_hash = digest.hexdigest()
        tool = os.environ.get('WA_TSHARK_PATH') or shutil.which('tshark')
        if not tool and os.path.isfile(r'C:\Program Files\Wireshark\tshark.exe'):
            tool = r'C:\Program Files\Wireshark\tshark.exe'
        try:
            if not tool:
                raise RuntimeError('tool_unavailable: install local TShark or set WA_TSHARK_PATH')
            version = subprocess.check_output([tool, '--version'], timeout=15).decode(errors='replace').splitlines()[0]
            catalog = subprocess.check_output([tool, '-G', 'fields'], timeout=30).decode(errors='replace')
            available = {line.split('\t')[2] for line in catalog.splitlines() if line.startswith('F\t') and len(line.split('\t')) > 2}
            base = ['frame.number', 'frame.time_epoch', 'ip.src', 'ipv6.src', 'ip.dst', 'ipv6.dst', 'tcp.srcport', 'udp.srcport', 'tcp.dstport', 'udp.dstport']
            candidates = ['tcp.stream', 'tls.handshake.type', 'tls.handshake.version', 'tls.handshake.extensions_server_name', 'tls.handshake.ciphersuite', 'tls.handshake.extensions_supported_group', 'tls.handshake.extensions_key_share_group', 'tls.handshake.extensions.supported_version', 'tls.handshake.random', 'quic.version', 'quic.dcid', 'quic.scid', 'ssh.protocol', 'ssh.kex_algorithms', 'ssh.encryption_algorithms_client_to_server', 'ssh.encryption_algorithms_server_to_client', 'isakmp.exchangetype', 'isakmp.messageid', 'isakmp.transform.type', 'isakmp.transform.id']
            fields = base + [f for f in candidates if f in available]
            command = [tool, '-n', '-r', path, '-Y', 'tls.handshake or quic or ssh or isakmp', '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=a', '-E', 'aggregator=,']
            for field in fields:
                command.extend(['-e', field])
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                process = subprocess.Popen(command, stdout=output, stderr=errors)
                try:
                    process.wait(timeout=int(os.environ.get('WA_CRYPTO_TIMEOUT_SECONDS', '900')))
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                    raise RuntimeError('timeout: crypto extraction exceeded time limit')
                if process.returncode:
                    errors.seek(0)
                    raise RuntimeError('decode_failed: ' + errors.read(4096).decode(errors='replace'))
                output.seek(0)
                with connect() as c:
                    c.execute('DELETE FROM crypto_evidence_v3 WHERE upload_id=?', (upload_id,))
                    for raw in output:
                        values = raw.decode(errors='replace').rstrip('\r\n').split('\t')
                        data = dict(zip(fields, values))
                        frame = int(data['frame.number'])
                        protocol = 'ssh' if data.get('ssh.protocol') or data.get('ssh.kex_algorithms') else 'ikev2' if data.get('isakmp.exchangetype') else 'quic' if data.get('quic.version') or data.get('quic.dcid') else 'tls_tcp'
                        event_id = hashlib.sha256(f'{source_hash}:{frame}'.encode()).hexdigest()
                        c.execute('INSERT OR IGNORE INTO crypto_evidence_v3 VALUES (?,?,?,?,?,?,?,?,?,?,?)', (event_id, upload_id, frame, float(data['frame.time_epoch']), protocol, data.get('ip.src') or data.get('ipv6.src'), data.get('ip.dst') or data.get('ipv6.dst'), int(data.get('tcp.srcport') or data.get('udp.srcport') or 0), int(data.get('tcp.dstport') or data.get('udp.dstport') or 0), source_hash, json.dumps(data)))
                    c.execute('INSERT OR REPLACE INTO crypto_reports_v3 VALUES (?,?,?,?,?,?,?)', (upload_id, source_hash, 'completed', None, time.time(), VERSION, version))
            return {'status': 'completed'}
        except Exception as exc:
            with connect() as c:
                c.execute('INSERT OR REPLACE INTO crypto_reports_v3 VALUES (?,?,?,?,?,?,?)', (upload_id, source_hash, 'failed', str(exc), time.time(), VERSION, None))
            raise


def scoped(uploads, start, end):
    ids = [u['upload_id'] for u in uploads]
    summary = dict(total_flows=0, analyzed_flows=0, pqc_server_selected=0, pqc_key_share_offered=0, pqc_not_observed=0, legacy_ciphers=0)
    if not ids:
        return [], summary, []
    with connect() as c:
        marks = ','.join('?' for _ in ids)
        where = f'upload_id IN ({marks})'
        args = list(ids)
        if start is not None:
            where += ' AND last_seen >= ?'; args.append(start)
        if end is not None:
            where += ' AND first_seen < ?'; args.append(end)
        flows = [dict(r) for r in c.execute('SELECT * FROM analysis_flows_v2 WHERE '+where+' ORDER BY first_seen,flow_id', args)]
        reports = [dict(r) for r in c.execute(f'SELECT * FROM crypto_reports_v3 WHERE upload_id IN ({marks})', ids)]
        report_by_id = {r['upload_id']: r for r in reports}
        hashes = {u['upload_id']: u['sha256_hash'] for u in uploads}
        pqc = {0x11ec, 0x11eb, 0x11ed, 0x200, 0x201, 0x202, 0x6399, 0x639a}
        for f in flows:
            report = report_by_id.get(f['upload_id'], {})
            status = report.get('status', 'pending')
            if report.get('source_hash') and report['source_hash'] != hashes[f['upload_id']]:
                status = 'stale'
            events = [dict(r) for r in c.execute('SELECT * FROM crypto_evidence_v3 WHERE upload_id=? AND timestamp>=? AND timestamp<=? AND ((src_ip=? AND src_port=? AND dst_ip=? AND dst_port=?) OR (src_ip=? AND src_port=? AND dst_ip=? AND dst_port=?)) ORDER BY frame_no', (f['upload_id'], f['first_seen'], f['last_seen'], f['endpoint_a_ip'], f['endpoint_a_port'], f['endpoint_b_ip'], f['endpoint_b_port'], f['endpoint_b_ip'], f['endpoint_b_port'], f['endpoint_a_ip'], f['endpoint_a_port']))]
            f.update(transport=events[0]['protocol'] if events else 'unknown', pqc_state='incomplete_capture' if events else 'not_applicable', analysis_status=status, events=events, duration_ms=(f['last_seen']-f['first_seen'])*1000, total_packets=f['a_to_b_packets']+f['b_to_a_packets'], classification=f['media_type'], name_hint=None)
            f.update(client_ip=f['endpoint_a_ip'], client_port=f['endpoint_a_port'], server_ip=f['endpoint_b_ip'], server_port=f['endpoint_b_port'], duration_s=(f['last_seen']-f['first_seen']))
            for event in events:
                data = json.loads(event['fields'])
                if data.get('tls.handshake.extensions_server_name'): f['name_hint'] = data['tls.handshake.extensions_server_name']
                types = data.get('tls.handshake.type','').split(',')
                groups = data.get('tls.handshake.extensions_key_share_group','').split(',')
                numeric = set()
                for g in groups:
                    try: numeric.add(int(g, 0))
                    except ValueError: pass
                if '2' in types and data.get('tls.handshake.random','').replace(':','').lower() != 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c':
                    f['sh_cipher'] = data.get('tls.handshake.ciphersuite')
                    f['neg_group_name'] = data.get('tls.handshake.extensions_key_share_group')
                    if numeric & pqc: f['pqc_state'] = 'server_selected'
                elif '1' in types and numeric & pqc and f['pqc_state'] != 'server_selected': f['pqc_state'] = 'key_share_offered'
            if status != 'completed': f['pqc_state'] = status
            f['server_name'] = f['name_hint']
            summary['analyzed_flows'] += int(status == 'completed')
            summary['pqc_server_selected'] += int(f['pqc_state'] == 'server_selected')
            summary['pqc_key_share_offered'] += int(f['pqc_state'] in ('server_selected', 'key_share_offered'))
        summary['total_flows'] = len(flows)
        return flows, summary, reports
