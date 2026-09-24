import os
import shutil
from datetime import datetime, time, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, abort
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
import sys

# Ensure src is in the path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(BASE_DIR)

from src.webapp.db_registry import (
    init_registry_db, register_upload, get_upload, list_uploads, update_status, get_batch, list_batches,
    update_filtered_evidence, remove_filtered_evidence, clear_existing_evidence_once,
    get_evidence_scope, latest_capture_end, flatten_evidence_storage_once, list_raw_evidence, list_filtered_evidence, delete_evidence_copy, set_filter_state
)
from src.webapp.db_analysis import (
    init_analysis_db, insert_whatsapp_packets, insert_parties, 
    get_packets, get_parties, get_geo, upsert_geo, insert_sessions, get_sessions,
    upsert_batch_metrics, get_batch_metrics, clear_batch_packets,
    get_file_list, get_packets_paged, get_packet_detail, clear_upload_packets
)
from src.webapp.forensic_evidence import build_evidence_trail
from src.pipeline import process_pcap_to_whatsapp_packets
from src.capture_evidence import capture_metadata, write_filtered_capture
from src.party_grouper import group_into_entities
from src.session_engine import reconstruct_flow_sessions, attach_session_metrics
from src.geolocation import geolocate, reverse_dns
from src.geo_plot import generate_map_html
from src.geo_mapping import classify_remote_party
from src.geo_enrichment import enrich_parties

# India has no daylight-saving transitions, so a fixed offset avoids requiring
# the optional ``tzdata`` package on Windows Python installations.
IST = timezone(timedelta(hours=5, minutes=30), name='IST')


def _derive_parties_and_sessions(packets, scope_id, os_hint='unknown'):
    parties = group_into_entities(packets, scope_id, os_hint)
    sessions = reconstruct_flow_sessions(packets, parties)
    attach_session_metrics(parties, sessions)
    return parties, sessions




def capture_range_from_request():
    """Return [start, end) epoch bounds for inclusive IST dates."""
    start_text, end_text = request.args.get('capture_from'), request.args.get('capture_to')
    if not start_text and not end_text:
        return None, None, None
    try:
        start_date = datetime.strptime(start_text, '%Y-%m-%d').date() if start_text else None
        end_date = datetime.strptime(end_text, '%Y-%m-%d').date() if end_text else None
        if start_date and end_date and end_date < start_date:
            raise ValueError('Capture end date must not be before the start date.')
        start = datetime.combine(start_date, time.min, IST).timestamp() if start_date else None
        end = datetime.combine(end_date + timedelta(days=1), time.min, IST).timestamp() if end_date else None
        return start, end, None
    except ValueError as exc:
        return None, None, str(exc)


def capture_ist(timestamp):
    return datetime.fromtimestamp(timestamp, IST).strftime('%d %b %Y %H:%M:%S IST') if timestamp is not None else 'Unavailable'


def classify_ip_presentation(party):
    """Return the analyst-facing Core Analysis IP classification.

    Infrastructure evidence deliberately takes precedence over P2P so a
    relay's location is never presented as the likely remote call participant.
    """
    if party.get('traffic_class') == 'unclassified':
        return 'Unclassified (Bypass)', 'unclassified', (
            'Bypass-retained traffic with no WA endpoint conclusion.'
        )

    caveat_type = party.get('caveat_type') or ''
    role = party.get('role_label') or ''
    infrastructure = {
        'relay_server': ('Server (Call Relay)', 'server', 'TURN/STUN/call relay; not the actual call peer.'),
        'dns': ('Server (DNS)', 'server', 'DNS resolver.'),
        'cdn_proxy': ('Server (CDN)', 'server', 'Generic CDN/proxy edge.'),
        'hosting': ('Server (Hosting)', 'server', 'Cloud or hosting-provider endpoint.'),
        'vpn_exit': ('Server (VPN Exit)', 'server', 'VPN exit node; geographic location may be unreliable.'),
        'cgnat': ('Server (CGNAT)', 'server', 'Carrier-grade NAT gateway; not the actual device location.'),
    }
    if caveat_type in infrastructure:
        return infrastructure[caveat_type]
    if role == 'Direct Peer' and party.get('is_p2p'):
        return 'P2P (Call)', 'p2p', 'Likely direct call peer and strongest candidate for the remote participant.'
    if role == 'WhatsApp Chat Server' or caveat_type == 'whatsapp_chat':
        return 'Server (Chat)', 'server', 'WhatsApp messaging/chat infrastructure.'

    media_type = (party.get('media_type') or '').lower()
    media_labels = {
        'photo': 'Server (Media: Photo)',
        'audio': 'Server (Media: Audio)',
        'video': 'Server (Media: Video)',
    }
    if role == 'WhatsApp Media CDN' or caveat_type == 'whatsapp_cdn' or media_type in media_labels:
        label = media_labels.get(media_type, 'Server (Media: Other)')
        descriptions = {
            'Server (Media: Photo)': 'Server interaction dominated by photo-transfer traffic.',
            'Server (Media: Audio)': 'Server interaction dominated by voice-note/audio transfer traffic.',
            'Server (Media: Video)': 'Server interaction dominated by video transfer traffic.',
            'Server (Media: Other)': 'Confirmed media server interaction without a reliable photo/audio/video subtype.',
        }
        return label, 'server', descriptions[label]
    return 'Server (General)', 'server', 'Identified server interaction without a more precise purpose.'


# ---------------------------------------------------------------------------
# UI label map (Fix G/H/interface3.html requirement)
# Maps internal pipeline labels → analyst-facing display strings.
# call_stream_unresolved: kept as a valid forensic state per strategic
#   alignment; displayed with an 'Encrypted Call (Unanchored)' badge so
#   analysts know call-like traffic was observed but cannot be
#   cryptographically confirmed without a STUN cookie anchor.
# media_transfer: unified label for mmi*/mms* CDN flows (Fix C).
# xmpp_multiplex: FunXMPP TCP 5222 carries chat + call setup (Fix F).
# ---------------------------------------------------------------------------
_MEDIA_LABEL_MAP: dict = {
    'voice_call'            : 'Voice Call',
    'video_call'            : 'Video Call',
    'call_stream_unresolved': 'Encrypted Call (Unanchored)',
    'call_signaling'        : 'Call Signaling',
    'media_transfer'        : 'Media Attachment',
    'photo'                 : 'Photo',
    'audio'                 : 'Audio / Voice Note',
    'video'                 : 'Video',
    'message'               : 'Text Message',
    'dns'                   : 'DNS',
    'xmpp_multiplex'        : 'Chat / Call Signal',
    'unclassified'          : 'Unclassified',
}


def _media_display(raw_label: str) -> str:
    """Convert an internal pipeline label to a human-readable UI string.
    Falls back to capitalizing the raw label for any unlisted value."""
    if not raw_label:
        return '—'
    return _MEDIA_LABEL_MAP.get(raw_label, raw_label.replace('_', ' ').title())


def create_app():
    app = Flask(__name__)
    # This switch affects only the Interface 1 browser workflow.  Keeping the
    # legacy uploader intact makes an operational rollback a config change.
    app.config['LARGE_BATCH_UPLOAD_ENABLED'] = os.environ.get(
        'WA_LARGE_BATCH_UPLOAD_ENABLED', 'true'
    ).strip().lower() not in ('0', 'false', 'no', 'off')

    @app.errorhandler(HTTPException)
    def api_http_error_response(error):
        """Keep API request rejections machine-readable without changing pages."""
        if request.path.startswith('/api/'):
            return jsonify({'error': error.description}), error.code
        return error

    @app.errorhandler(500)
    def api_server_error_response(error):
        if request.path.startswith('/api/'):
            app.logger.exception('Unhandled API error', exc_info=error)
            return jsonify({'error': 'Unexpected server error.'}), 500
        return error
    
    # Init databases
    init_registry_db()
    init_analysis_db()
    
    RAW_PCAP_FOLDER = os.path.join(BASE_DIR, 'RAW_PCAP')
    FILTERED_PCAP_FOLDER = os.path.join(BASE_DIR, 'Filtered_PCAP')
    LEGACY_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    # Never delete or reset evidence at application startup. Storage migration is hash-verified and one-time only.
    os.makedirs(RAW_PCAP_FOLDER, exist_ok=True)
    os.makedirs(FILTERED_PCAP_FOLDER, exist_ok=True)
    flatten_evidence_storage_once(RAW_PCAP_FOLDER, FILTERED_PCAP_FOLDER)
    app.config['RAW_PCAP_FOLDER'] = RAW_PCAP_FOLDER
    app.config['FILTERED_PCAP_FOLDER'] = FILTERED_PCAP_FOLDER
    # Allow large uploads for batch PCAPs
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024 # 5GB

    def _format_for_name(filename):
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.json': return 'json'
        if ext == '.csv': return 'csv'
        if ext == '.pcapng': return 'pcapng'
        return 'pcap'

    def _raw_path(upload_id, filename):
        evidence_dir = os.path.join(app.config['RAW_PCAP_FOLDER'], upload_id)
        os.makedirs(evidence_dir, exist_ok=True)
        base, ext = os.path.splitext(filename)
        candidate, index = filename, 1
        while os.path.exists(os.path.join(evidence_dir, candidate)):
            candidate = f'{base}_{index}{ext}'; index += 1
        return candidate, os.path.join(evidence_dir, candidate)

    def _filtered_path(upload_id, filename, file_format):
        stem = os.path.splitext(filename)[0]
        extension = '.pcapng' if file_format == 'pcapng' else '.pcap'
        return os.path.join(app.config['FILTERED_PCAP_FOLDER'], upload_id, f'{stem}_WF{extension}')

    def _scope():
        job_id = request.args.get('job_id', '').strip()
        if job_id:
            from src.webapp.job_queue import get_job_status
            job = get_job_status(job_id)
            job_upload_ids = job.get('upload_ids') if job else None
            if not isinstance(job_upload_ids, list):
                return None, None, 'The requested processing-job scope is unavailable.', [], False
            uploads = [item for item in (get_upload(upload_id) for upload_id in job_upload_ids)
                       if item and item.get('stored_path')]
            if not uploads:
                return None, None, 'The requested processing job has no available evidence.', [], False
            scoped_starts = [item.get('capture_start_ts') for item in uploads if item.get('capture_start_ts') is not None]
            scoped_ends = [item.get('capture_end_ts') for item in uploads if item.get('capture_end_ts') is not None]
            start = min(scoped_starts) if scoped_starts else None
            end = (max(scoped_ends) + 0.000001) if scoped_ends else None
            return start, end, None, uploads, False

        requested_ids = [value for value in request.args.get('upload_ids', '').split(',') if value]
        if requested_ids:
            uploads = [item for item in (get_upload(upload_id) for upload_id in requested_ids) if item and item.get('stored_path')]
            if uploads:
                scoped_starts = [item.get('capture_start_ts') for item in uploads if item.get('capture_start_ts') is not None]
                scoped_ends = [item.get('capture_end_ts') for item in uploads if item.get('capture_end_ts') is not None]
                start = min(scoped_starts) if scoped_starts else None
                end = (max(scoped_ends) + 0.000001) if scoped_ends else None
                return start, end, None, uploads, False

        start, end, error = capture_range_from_request()
        is_default = False
        if not error and start is None and end is None:
            latest = latest_capture_end()
            if latest is not None:
                start, end, is_default = latest - 86400, latest + 0.000001, True
        evidence = get_evidence_scope(start, end) if not error else []
        return start, end, error, evidence, is_default

    def _filtered_scope():
        start, end, error, evidence, is_default = _scope()
        filtered = [u for u in evidence if u.get("filtered_status") == "filtered_output_created" and u.get("filtered_path") and os.path.isfile(u.get("filtered_path"))]
        return start, end, error, filtered, is_default    
    # ---------------------------------------------------------
    # Context Processor for Sidebar Data
    # ---------------------------------------------------------
    @app.context_processor
    def inject_sidebar():
        return dict(
            evidence_library=list_uploads(),
            capture_from=request.args.get('capture_from', ''),
            capture_to=request.args.get('capture_to', ''),
            ist_format=capture_ist,
        )

    # ---------------------------------------------------------
    # UI Routes
    # ---------------------------------------------------------
    @app.route('/')
    def index():
        return redirect(url_for('dashboard', **request.args))

    @app.route('/dashboard')
    def dashboard():
        batch_id = None
        start_ts, end_ts, range_error, uploads, default_scope = _filtered_scope()
        if range_error:
            return render_template('dashboard.html', active_interface=0, uploads=uploads, error=range_error,
                                   metrics={}, traffic_timeline=[], protocol_dist={}, media_dist={}, recent_parties=[],
                                   top_countries=[], top_party=None, insights=[], recent_events=[], map_html=''), 400

        # ── Default empty state ────────────────────────────────
        metrics = {
            'packet_count': 0,
            'whatsapp_count': 0,
            'unclassified_count': 0,
            'bypass_mode': False,
            'total_bytes': 0,
            'total_size_kb': '0',
            'flow_count': 0,
            'endpoint_count': 0,
            'detection_rate': 0,
        }
        traffic_timeline = []
        protocol_dist = {}
        media_dist = {}
        recent_parties = []
        top_countries = []
        top_party = None
        insights = []
        recent_events = []
        map_html = ""

        # Populate from DB if a batch is selected
        if uploads:
            upload_ids = [u['upload_id'] for u in uploads]
            packets = get_packets(None, start_ts, end_ts, upload_ids=upload_ids)
            # Persisted parties are full-case evidence. Range views are derived in memory.
            parties, _sessions = _derive_parties_and_sessions(packets, 'evidence-scope', 'unknown')
            b_metrics = None

            if packets:
                total_bytes = sum(p.get('length') or 0 for p in packets)
                total_size_kb = total_bytes / 1024
                unique_flows = b_metrics.get('flow_count', 0) if b_metrics else len(set(p.get('flow_id') for p in packets if p.get('flow_id')))
                unique_endpoints = len(set(
                    ip for p in packets
                    for ip in [p.get('src_ip'), p.get('dst_ip')]
                    if ip
                ))

                # Detection rate: fraction positively classified as WhatsApp.
                confident = sum(
                    1 for p in packets
                    if (p.get('whatsapp_confidence') or '').lower() in ('high', 'medium', 'infrastructure')
                )
                unclassified = sum(
                    1 for p in packets
                    if (p.get('whatsapp_confidence') or '').lower() == 'unclassified'
                )
                detection_rate = round(confident / len(packets) * 100, 1) if packets else 0

                metrics = {
                    'packet_count': b_metrics.get('packet_count', 0) if b_metrics else len(packets),
                    'whatsapp_count': confident,
                    'unclassified_count': unclassified,
                    'bypass_mode': bool(b_metrics and b_metrics.get('bypass_mode')),
                    'total_bytes': total_bytes,
                    'total_size_kb': f'{total_size_kb:.1f}',
                    'flow_count': unique_flows,
                    'endpoint_count': unique_endpoints,
                    'detection_rate': detection_rate,
                }

                # ── Traffic timeline (buckets of 1 second) ──────
                from collections import defaultdict
                import math
                buckets = defaultdict(int)
                for p in packets:
                    ts = p.get('timestamp') or 0
                    bucket = int(math.floor(ts))
                    buckets[bucket] += 1
                if buckets:
                    min_ts = min(buckets)
                    # Build ordered list of {label, count}
                    traffic_timeline = [
                        {'label': capture_ist(k), 'count': buckets[k]}
                        for k in sorted(buckets)
                    ]

                # ── Protocol distribution ────────────────────────
                proto_counts = defaultdict(int)
                for p in packets:
                    proto_counts[p.get('protocol') or 'Unknown'] += 1
                protocol_dist = dict(proto_counts)

                # ── Media / traffic type distribution ────────────
                # Exact-label bucketing: new pipeline values (media_transfer,
                # xmpp_multiplex, call_stream_unresolved) are correctly placed
                # instead of falling through to 'Other' via substring checks.
                _VOIP_LABELS_DB = frozenset({
                    'voice_call', 'video_call', 'call_stream_unresolved',
                    'call_signaling', 'call_media_candidate',
                })
                _MEDIA_LABELS_DB = frozenset({
                    'video', 'photo', 'audio', 'media_transfer',
                })
                _CHAT_LABELS_DB = frozenset({
                    'message', 'chat_control', 'xmpp_multiplex',
                })
                media_counts = defaultdict(int)
                for p in packets:
                    media = p.get('whatsapp_media_guess') or p.get('sub_activity') or 'Other'
                    ml = media.lower()
                    if ml in _VOIP_LABELS_DB:
                        label = 'VoIP / Call'
                    elif ml in _MEDIA_LABELS_DB:
                        label = 'Media'
                    elif ml in _CHAT_LABELS_DB:
                        label = 'Chat'
                    else:
                        label = 'Other'
                    media_counts[label] += 1
                media_dist = dict(media_counts)

            if parties:
                # ── Recent parties with geo ──────────────────────
                party_list = []
                country_bytes = defaultdict(int)
                enriched_parties = enrich_parties([dict(p) for p in parties[:10]], get_geo, upsert_geo)
                for row in enriched_parties:
                    country = row.get('geo_country')
                    if country and country != '—':
                        country_bytes[country] += row.get('total_bytes', 0)

                    party_list.append(row)
                recent_parties = party_list[:5]
                map_html = generate_map_html(party_list, height=250)

                # ── Top countries (by bytes share) ──────────────
                total_cb = sum(country_bytes.values()) or 1
                top_countries = sorted(
                    [{'country': c, 'pct': round(b / total_cb * 100, 1)}
                     for c, b in country_bytes.items()],
                    key=lambda x: x['pct'], reverse=True
                )[:5]

                # ── Top party for flow reconstruction panel ──────
                top_party = party_list[0] if party_list else None
                if top_party and not top_party.get('media_breakdown') and packets:
                    tp_remote = top_party.get('remote_ip')
                    tp_pkts = [p for p in packets if p.get('src_ip') == tp_remote or p.get('dst_ip') == tp_remote]
                    tp_counts = defaultdict(int)
                    for p in tp_pkts:
                        m = p.get('whatsapp_media_guess') or p.get('sub_activity') or 'Other'
                        ml = m.lower()
                        if 'audio' in ml or 'voice' in ml or 'voip' in ml or 'call' in ml:
                            lbl = 'VoIP'
                        elif 'video' in ml or 'image' in ml or 'media' in ml or 'photo' in ml:
                            lbl = 'Media'
                        elif 'chat' in ml or 'text' in ml or 'message' in ml or 'signal' in ml:
                            lbl = 'Chat'
                        else:
                            lbl = 'Other'
                        tp_counts[lbl] += 1
                    top_party['media_breakdown'] = ' · '.join(f"{cnt} {lbl}" for lbl, cnt in sorted(tp_counts.items(), key=lambda x: -x[1])) if tp_counts else None

                # ── Dynamic insights ─────────────────────────────
                insights = []
                if metrics['whatsapp_count'] > 0:
                    insights.append('WhatsApp traffic successfully identified')
                dominant_media = max(media_dist, key=media_dist.get) if media_dist else None
                if dominant_media:
                    insights.append(f'Major traffic is {dominant_media} based')
                if top_countries:
                    top2 = ' and '.join(c['country'] for c in top_countries[:2])
                    insights.append(f'Endpoints primarily from {top2}')
                caveated = sum(1 for p in party_list if p.get('caveat'))
                if caveated == 0:
                    insights.append('No suspicious VPN / CGNAT anomalies detected')
                else:
                    insights.append(f'{caveated} parties have geographic uncertainty (VPN/CGNAT)')
                if metrics['detection_rate'] >= 95:
                    insights.append(f'High-confidence detection: {metrics["detection_rate"]}%')

        # ── Recent activity feed from upload history ─────────
        all_uploads = list_uploads() if not uploads else uploads
        for u in (uploads or []):
            status = u.get('status', 'registered')
            if status == 'registered':
                recent_events.append({
                    'icon': 'fa-upload', 'color': 'blue',
                    'title': 'PCAP file registered',
                    'subtitle': f"{u['filename']} ({round((u.get('size_bytes') or 0)/1024, 1)} KB)",
                    'time': (u.get('uploaded_at') or '')[:16].replace('T', ' '),
                })
            elif status == 'filtered':
                recent_events.append({
                    'icon': 'fa-filter', 'color': 'teal',
                    'title': 'Traffic filtered',
                    'subtitle': f"Case {batch_id[:8] if batch_id else ''}",
                    'time': (u.get('uploaded_at') or '')[:16].replace('T', ' '),
                })
            elif status == 'analyzed':
                recent_events.append({
                    'icon': 'fa-check', 'color': 'green',
                    'title': 'Analysis finished',
                    'subtitle': f"Case {batch_id[:8] if batch_id else ''}",
                    'time': (u.get('uploaded_at') or '')[:16].replace('T', ' '),
                })
        recent_events = recent_events[:5]

        return render_template('dashboard.html',
                               active_interface=0,
                               uploads=uploads,
                               metrics=metrics,
                               traffic_timeline=traffic_timeline,
                               protocol_dist=protocol_dist,
                               media_dist=media_dist,
                               recent_parties=recent_parties,
                               top_countries=top_countries,
                               top_party=top_party,
                               insights=insights,
                               recent_events=recent_events,
                               map_html=map_html, capture_start_ts=start_ts, capture_end_ts=end_ts,
                               scope_evidence=uploads, default_scope=default_scope)


    @app.route('/interface/evidence-storage')
    def evidence_storage():
        view = request.args.get('view', 'raw')
        if view not in ('raw', 'filtered'):
            view = 'raw'
        evidence = list_raw_evidence() if view == 'raw' else list_filtered_evidence()
        return render_template('evidence_storage.html', active_interface=6, evidence=evidence, storage_view=view)
    @app.route('/interface/classification')
    def classification():
        """Read-only deep inspection of validated Filtered_PCAP evidence."""
        start_ts, end_ts, range_error, uploads, default_scope = _filtered_scope()
        upload_ids = [upload['upload_id'] for upload in uploads]
        files = get_file_list(None, start_ts, end_ts, upload_ids=upload_ids) if upload_ids else []
        metadata = {upload['upload_id']: upload for upload in uploads}
        for item in files:
            upload = metadata.get(item['upload_id'], {})
            item['size_bytes'] = upload.get('filtered_size_bytes') or 0
            item['file_format'] = upload.get('filtered_format') or upload.get('file_format') or 'pcap'
        requested_id = request.args.get('upload_id')
        selected_view = 'file' if requested_id and requested_id in metadata else 'all'
        selected_upload_id = requested_id if selected_view == 'file' else None
        return render_template('classification.html', active_interface=7, uploads=uploads, files=files,
                               selected_view=selected_view, selected_upload_id=selected_upload_id,
                               range_error=range_error, scope_evidence=uploads, default_scope=default_scope,
                               all_packet_count=sum(int(item.get('packet_count') or 0) for item in files))
    @app.route('/interface/1')
    def interface1():
        uploads = list_uploads()
        error = request.args.get('error')
        return render_template('interface1.html', 
                               active_interface=1, 
                               uploads=uploads,
                               error=error,
                               large_batch_upload_enabled=app.config['LARGE_BATCH_UPLOAD_ENABLED'])

    @app.route('/interface/2')
    def interface2():
        # Filter Traffic operates on RAW evidence; packet results are indexed
        # only after a validated Filtered_PCAP derivative has been created.
        start_ts, end_ts, range_error, uploads, default_scope = _scope()
        filtered_uploads = [upload for upload in uploads
                            if upload.get('filtered_status') == 'filtered_output_created' and upload.get('filtered_path')]
        
        # Explicitly pass upload_ids to ensure we don't bleed into overlapping captures not in the scope
        upload_ids = [u['upload_id'] for u in filtered_uploads]
        file_list = get_file_list(None, start_ts, end_ts, upload_ids=upload_ids) if filtered_uploads else []
        total_pkts = sum(item.get('packet_count', 0) for item in file_list)
        source_packet_count = sum(int(upload.get('capture_packet_count') or 0) for upload in uploads)
        filter_stats = ({'packet_count': total_pkts, 'flow_count': len(file_list),
                         'whatsapp_count': total_pkts, 'detected_os': 'unknown',
                         'bypass_mode': False} if total_pkts else None)
        return render_template('interface2.html', active_interface=2, uploads=uploads,
                               filtered_uploads=filtered_uploads, filter_stats=filter_stats,
                               source_packet_count=source_packet_count, file_list=file_list, range_error=range_error,
                               scope_evidence=uploads, default_scope=default_scope)
    @app.route('/interface/3')
    def interface3():
        batch_id = None
        start_ts, end_ts, range_error, uploads, default_scope = _filtered_scope()
        if range_error:
            return render_template('interface3.html', active_interface=3, uploads=uploads, parties=[], error=range_error), 400
        batch_metrics = None
        bypass_mode = bool(batch_metrics and batch_metrics.get('bypass_mode'))
        
        parties_data = []
        files_json = "[]"
        parties_json = "[]"
        nodes_json = "[]"
        arcs_json = "[]"
        caveated_count = 0
        map_html = ""
        
        if uploads and any(u['status'] in ('filtered', 'analyzed') for u in uploads):
            upload_ids = [u['upload_id'] for u in uploads]
            packets = get_packets(None, start_ts, end_ts, upload_ids=upload_ids)
            parties_data, _map_sessions = _derive_parties_and_sessions(packets, 'evidence-scope', 'unknown')
            parties_data = enrich_parties(parties_data, get_geo, upsert_geo)
            for p in parties_data:
                p['ip_classification'], p['ip_class_group'], p['ip_classification_description'] = classify_ip_presentation(p)
                if p.get('caveat_type') in ('vpn_exit', 'cgnat', 'private'):
                    caveated_count += 1
                if p.get('protocol') == 'TCP':
                    if p.get('session_start_confirmed'):
                        p['protocol_aware_session_label'] = 'full_session'
                    else:
                        p['protocol_aware_session_label'] = 'mid_session'
            selected_files = request.args.getlist('files')
            
            if selected_files:
                parties = [p for p in parties_data if p.get('source_file') in selected_files]
            else:
                parties = parties_data
            
            import json
            import math
            from src.webapp.db_analysis import _connect
            conn = _connect()
            time_clause, time_params = '', []
            if start_ts is not None:
                time_clause += ' AND timestamp >= ?'; time_params.append(start_ts)
            if end_ts is not None:
                time_clause += ' AND timestamp < ?'; time_params.append(end_ts)
            file_metrics_raw = conn.execute("""
                SELECT filename, COUNT(*) AS total,
                       SUM(CASE WHEN lower(whatsapp_confidence) IN ('high', 'medium', 'infrastructure') THEN 1 ELSE 0 END) AS wa,
                       SUM(CASE WHEN lower(whatsapp_confidence) = 'unclassified' THEN 1 ELSE 0 END) AS unclassified
                FROM whatsapp_packets WHERE 1 = 1 {time_clause} GROUP BY filename
            """.format(time_clause=time_clause), time_params).fetchall()
            conn.close()
            
            def generate_palette(n):
                golden_angle = 137.508
                colors = []
                for j in range(n):
                    hue = (j * golden_angle) % 360
                    sat = 65 if (j % 2 == 0) else 75
                    lit = 50 if (j % 3 != 2) else 42
                    colors.append(f'hsl({hue:.0f},{sat}%,{lit}%)')
                return colors
            
            palette = generate_palette(len(file_metrics_raw))
            
            files_data = []
            file_name_to_idx = {}
            for i, row in enumerate(file_metrics_raw):
                f_name = row['filename']
                files_data.append({
                    'n': f_name,
                    'total': row['total'] or 0,
                    'wa': row['wa'] or 0,
                    'unclassified': row['unclassified'] or 0,
                    'color': palette[i % len(palette)]
                })
                file_name_to_idx[f_name] = i

            parties_json_list = []
            nodes_dict = {}
            arcs_list = []

            # ── Per-file source device geo-positioning ─────────────────────────
            # Endpoint-pair parties own map endpoints. Do not infer a capture
            # device or invent geographic coordinates from packet direction.
            _file_client_ip = {}
            per_file_source_positions = {}

            def endpoint_node(party, side, color, files):
                ip = party.get(f'endpoint_{side}_ip') or 'Unknown endpoint'
                if ip in nodes_dict:
                    return nodes_dict[ip]['id']
                scope = party.get(f'endpoint_{side}_scope') or 'non_routable'
                lat = party.get(f'endpoint_{side}_lat')
                lon = party.get(f'endpoint_{side}_lon')
                geographic = scope == 'public' and lat is not None and lon is not None
                if geographic:
                    x, y = (lon + 180) / 360.0, (90 - lat) / 180.0
                else:
                    count = sum(1 for n in nodes_dict.values() if n.get('nonGeographic'))
                    x, y = min(.95, .06 + count * .10), .96
                node_id = f'n{len(nodes_dict)}'
                label = {'local': 'Local endpoint', 'cgnat': 'CGNAT endpoint'}.get(scope, 'Network endpoint')
                nodes_dict[ip] = {
                    'id': node_id, 'lbl': f'{ip}\n{label}', 'x': x, 'y': y,
                    'c': color, 'r': 5, 'files': files,
                    'nonGeographic': not geographic, 'scope': scope,
                }
                return node_id

            for i, p in enumerate(parties_data):
                try:
                    p_source_files = json.loads(p.get('source_files', '[]'))
                except Exception:
                    p_source_files = [p.get('source_file')]
                
                if not p_source_files and p.get('source_file'):
                    p_source_files = [p.get('source_file')]
                    
                file_indices = [file_name_to_idx.get(f) for f in p_source_files if f in file_name_to_idx]
                if not file_indices:
                    file_indices = [0]
                    
                file_idx = file_indices[0]
                
                def format_bytes(b):
                    if b >= 1048576: return f"{b/1048576:.1f} MB"
                    if b >= 1024: return f"{b/1024:.1f} KB"
                    return f"{b} B"

                color = files_data[file_idx]['color'] if file_idx is not None and file_idx < len(files_data) else '#888'
                
                pkts = p.get('packet_count', 0)
                asn = p.get('asn_org') or 'Unknown'
                country = p.get('geo_country') or 'Unknown'
                node_a = endpoint_node(p, 'a', color, file_indices)
                node_b = endpoint_node(p, 'b', color, file_indices)
                arcs_list.append({
                    'a': node_a,
                    'b': node_b,
                    'files': file_indices,
                    'proto': p.get('protocol', 'UDP'),
                    'aToBBytes': p.get('a_to_b_bytes', 0),
                    'bToABytes': p.get('b_to_a_bytes', 0)
                })

                parties_json_list.append({
                    'ip': f"{p.get('endpoint_a_ip')} ↔ {p.get('endpoint_b_ip')}",
                    'endpointA': p.get('endpoint_a_ip'),
                    'endpointB': p.get('endpoint_b_ip'),
                    'files': file_indices,
                    'proto': p.get('protocol'),
                    'pkts': pkts,
                    'bytes': format_bytes(p.get('total_bytes', 0)),
                    'dur': p.get('duration_s', 0),
                    'role': p.get('role_label', p.get('party_type')),
                    'activity': _media_display(p.get('sub_activity') or ''),
                    'activityRaw': p.get('sub_activity') or '—',
                    'conf': p.get('confidence', '—').capitalize(),
                    'trafficClass': p.get('traffic_class', 'confirmed_whatsapp'),
                    'ipClassification': p.get('ip_classification', 'Server (General)'),
                    'ipClassGroup': p.get('ip_class_group', 'server'),
                    'ipClassificationDescription': p.get('ip_classification_description', ''),
                    'country': country,
                    'city': p.get('geo_city', '—'),
                    'asn': asn,
                    'caveat': not p.get('location_reliable', True),
                    'crypto': p.get('crypto_summary'),
                    'callDuration': p.get('call_duration_s', 0),
                    'longestCall': p.get('longest_call_s', 0),
                    'callWindows': p.get('call_window_count', 0)
                })
            
            files_json = json.dumps(files_data)
            parties_json = json.dumps(parties_json_list)
            nodes_json = json.dumps(list(nodes_dict.values()))
            arcs_json = json.dumps(arcs_list)
            
            file_color_map = {f['n']: f['color'] for f in files_data}
            map_html = generate_map_html(
                parties_data,
                height=360,
                file_color_map=file_color_map,
                div_id='coreMap',
                per_file_source_positions=per_file_source_positions,
                per_file_source_ips=_file_client_ip
            )
            
        all_batches = list_batches()
            
        return render_template('interface3.html',
                               active_interface=3,
                               uploads=uploads,
                               parties=parties_data,
                               files_json=files_json,
                               parties_json=parties_json,
                               nodes_json=nodes_json,
                               arcs_json=arcs_json,
                               map_html=map_html,
                               caveated_count=caveated_count,
                               bypass_mode=bypass_mode, scope_evidence=uploads, default_scope=default_scope)

    @app.route('/interface/5')
    @app.route('/interface/report-generation')
    def interface5():
        """Generate an offline report from the current filtered-evidence scope."""
        start_ts, end_ts, range_error, uploads, default_scope = _filtered_scope()
        upload_ids = [upload['upload_id'] for upload in uploads]
        files = get_file_list(None, start_ts, end_ts, upload_ids=upload_ids) if upload_ids else []
        return render_template('interface5.html', active_interface=5, uploads=uploads,
                               files=files, range_error=range_error, scope_evidence=uploads,
                               default_scope=default_scope, capture_start_ts=start_ts,
                               capture_end_ts=end_ts,
                               excluded_evidence=max(0, len(list_uploads()) - len(uploads)))
    # DEEP_ANALYSIS_DISABLED
    # @app.route('/interface/4')
    # def interface4():
    #     batch_id = request.args.get('batch_id')
    #     uploads = get_batch(batch_id) if batch_id else []
    #     
    #     sessions = get_sessions(batch_id) if batch_id else []
    #     all_batches = list_batches()
    #     
    #     return render_template('interface4.html',
    #                            active_interface=4,
    #                            uploads=uploads,
    #                            sessions=sessions,
    #                            all_batches=all_batches)

    # ---------------------------------------------------------
    # API Routes
    # ---------------------------------------------------------
    @app.route('/api/uploads', methods=['GET'])
    def api_uploads():
        return jsonify(list_uploads())

    @app.route('/api/register', methods=['POST'])
    def api_register():
        if 'pcap_file' not in request.files:
            return redirect(url_for('interface1', error='No file part'))
        file = request.files['pcap_file']
        if file.filename == '':
            return redirect(url_for('interface1', error='No selected file'))
            
        import uuid
        upload_id = str(uuid.uuid4())
            
        filename = secure_filename(file.filename) or 'capture.pcap'
        filename, filepath = _raw_path(upload_id, filename)
        file.save(filepath)
        file_format = _format_for_name(filename)
        try:
            metadata = capture_metadata(filepath, file_format)
            metadata['capture_vantage'] = request.form.get('capture_vantage') or None
            metadata['subscriber_ips'] = request.form.get('subscriber_ips') or None
            receipt = register_upload(filename, filepath, file_format=file_format, capture_metadata=metadata, upload_id=upload_id)
        except Exception as exc:
            if os.path.exists(filepath): os.remove(filepath)
            return redirect(url_for('interface1', error=f'Invalid capture: {exc}'))
        
        return redirect(url_for('interface1'))

    @app.route('/api/register/batch', methods=['POST'])
    def api_register_batch():
        if 'pcap_file' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('pcap_file')
        if not files or all(f.filename == '' for f in files):
            return jsonify({'error': 'No selected files'}), 400
            
        import uuid
        receipts = []
        
        for file in files:
            if file.filename == '':
                continue
            raw_basename = os.path.basename(file.filename.replace('\\', '/'))
            filename = secure_filename(raw_basename) or f"capture_{uuid.uuid4().hex[:6]}.pcap"
            
            upload_id = str(uuid.uuid4())
            target_filename, filepath = _raw_path(upload_id, filename)
            file.save(filepath)
            
            ext_lower = os.path.splitext(target_filename)[1].lower()
            if ext_lower in ['.wav', '.wave', '.mp3', '.mp4', '.avi', '.jpg', '.jpeg', '.png', '.webp', '.exe']:
                if os.path.exists(filepath):
                    os.remove(filepath)
                continue

            try:
                with open(filepath, 'rb') as f_magic:
                    magic4 = f_magic.read(4)
                if magic4.startswith(b'RIFF'):
                    os.remove(filepath)
                    continue
            except Exception:
                pass

            file_format = _format_for_name(target_filename)
            try:
                metadata = capture_metadata(filepath, file_format)
                metadata['capture_vantage'] = request.form.get('capture_vantage') or None
                metadata['subscriber_ips'] = request.form.get('subscriber_ips') or None
                receipt = register_upload(target_filename, filepath, file_format=file_format, capture_metadata=metadata, upload_id=upload_id)
                receipts.append(receipt)
            except Exception as exc:
                if os.path.exists(filepath): os.remove(filepath)
                receipts.append({'filename': target_filename, 'error': f'Invalid capture: {exc}'})
            
        return jsonify({'receipts': receipts, 'registered_count': len([r for r in receipts if not r.get('error')])})

    @app.route('/api/filter', methods=['POST'])
    def api_filter():
        # Enqueue an asynchronous filter job instead of blocking
        payload = request.get_json(silent=True) or {}
        requested_ids = payload.get('upload_ids', request.form.getlist('upload_ids'))
        if requested_ids is not None and not isinstance(requested_ids, list):
            return jsonify({'error': 'upload_ids must be a list.'}), 400

        start_ts, end_ts, scope_error, scoped_uploads, default_scope = _scope()
        if requested_ids:
            uploads, seen = [], set()
            for upload_id in requested_ids:
                if isinstance(upload_id, str) and upload_id not in seen:
                    seen.add(upload_id)
                    upload = get_upload(upload_id)
                    if upload:
                        uploads.append(upload)
            if not uploads:
                return jsonify({'error': 'No registered RAW evidence was selected.'}), 404
        else:
            uploads = scoped_uploads
            
        if not uploads:
            return jsonify({'error': scope_error or 'No timestamped evidence matches this capture range.'}), 404
            
        skip_filter = request.args.get('skip_filter', 'false').lower() == 'true'
        
        from src.webapp.job_queue import enqueue_filter_job
        job_id = enqueue_filter_job([u['upload_id'] for u in uploads], skip_filter=skip_filter)
        
        return jsonify({
            'job_id': job_id,
            'scope': {'start_ts': start_ts, 'end_ts': end_ts, 'file_count': len(uploads), 'default_scope': default_scope}
        })
        
    @app.route('/api/jobs/<job_id>', methods=['GET'])
    def api_job_status(job_id):
        from src.webapp.job_queue import get_job_status
        status = get_job_status(job_id)
        if not status:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify(status)

    @app.route('/api/analyze', methods=['POST'])
    def api_analyze_scope():
        start_ts, end_ts, error, uploads, default_scope = _filtered_scope()
        if error or not uploads:
            return jsonify({'error': error or 'No evidence matches this capture range.'}), 400
        upload_ids = [u['upload_id'] for u in uploads]
        packets = get_packets(None, start_ts, end_ts, upload_ids=upload_ids)
        # Entities are intentionally derived from this date scope and are not a case-level DB artifact.
        parties, sessions = _derive_parties_and_sessions(packets, 'evidence-scope', 'unknown')
        insert_sessions('evidence-scope', sessions)
        return jsonify({'status': 'analyzed', 'scope': {'start_ts': start_ts, 'end_ts': end_ts,
                        'file_count': len(uploads), 'default_scope': default_scope},
                        'packet_count': len(packets), 'party_count': len(parties)})

    @app.route('/api/analyze/<batch_id>', methods=['POST'])
    def api_analyze(batch_id):
        uploads = get_batch(batch_id)
        if not uploads:
            return jsonify({'error': 'Batch not found'}), 404
            
        try:
            packets = get_packets(batch_id)
            
            # Bug 4 fix: extract os_hint properly so OS timeouts aren't always lost
            os_hint = 'unknown'
            b_metrics = get_batch_metrics(batch_id)
            if b_metrics and 'detected_os' in b_metrics:
                os_raw = b_metrics['detected_os']
                # format is usually "android - high confidence", we just want the first word
                os_hint = os_raw.split()[0].lower() if os_raw else 'unknown'
            
            if os_hint == 'unknown' and packets:
                from src.os_fingerprint import detect_os_hint
                os_hint, _ = detect_os_hint(packets)
                
            parties, sessions = _derive_parties_and_sessions(packets, batch_id, os_hint)
            insert_sessions(batch_id, sessions)
            
            parties = enrich_parties(parties, get_geo, upsert_geo)
                        
            insert_parties(batch_id, parties)
            for u in uploads:
                update_status(u['upload_id'], 'analyzed')
            return jsonify({'status': 'success', 'parties': len(parties)})
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    # DEEP_ANALYSIS_DISABLED
    # @app.route('/api/deep_analyze/<batch_id>', methods=['POST'])
    # def api_deep_analyze(batch_id):
    #     from src.timeline_builder import build_sessions
    #     try:
    #         packets = get_packets(batch_id)
    #         parties = get_parties(batch_id)
    #         
    #         sessions = build_sessions(batch_id, packets, parties)
    #         insert_sessions(batch_id, sessions)
    #         return jsonify({'status': 'success', 'sessions_created': len(sessions)})
    #     except Exception as e:
    #         import traceback
    #         traceback.print_exc()
    #         return jsonify({'error': str(e)}), 500

    @app.route('/api/reports/generate', methods=['POST'])
    def api_generate_report_scope():
        """Produce an offline report from validated filtered evidence only."""
        try:
            import json
            from src.webapp.report_generator import generate_report
            config = json.loads(request.form.get('config', '{}'))
            start_ts, end_ts, error, uploads, default_scope = _filtered_scope()
            if error:
                return jsonify({'error': error}), 400
            allowed = {upload['upload_id']: upload for upload in uploads}
            requested_ids = config.get('upload_ids') or list(allowed)
            if not isinstance(requested_ids, list):
                return jsonify({'error': 'upload_ids must be a list.'}), 400
            selected = [allowed[upload_id] for upload_id in requested_ids if upload_id in allowed]
            if not selected:
                return jsonify({'error': 'No validated Filtered_PCAP evidence is available in this capture range.'}), 404
            phases = config.get('phases') or ['filtration', 'classification', 'geolocation']
            return generate_report(selected, start_ts, end_ts, phases)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            return jsonify({'error': f'Invalid report request: {exc}'}), 400
        except Exception as exc:
            app.logger.exception('Report generation failed')
            return jsonify({'error': f'Report generation failed: {exc}'}), 500
    @app.route('/api/delete/batch/<batch_id>', methods=['POST'])
    def api_delete_batch(batch_id):
        from src.webapp.db_registry import delete_batch
        from src.webapp.db_analysis import clear_batch_analysis
        clear_batch_analysis(batch_id)
        delete_batch(batch_id)
        return jsonify({'status': 'deleted'})

    @app.route('/api/reset/all', methods=['POST'])
    def api_reset_all():
        """Wipe ALL pcap uploads, analysis data and uploaded files from disk.
        Preserves geo_cache (IP lookup data) and DB schemas.
        Use before submitting the codebase so no personal capture data is included.
        """
        from src.webapp.db_registry import list_uploads, delete_upload
        from src.webapp.db_analysis import _connect as _analysis_connect

        # 1. Delete every pcap file from disk and clear registry
        all_uploads = list_uploads()
        deleted_files = 0
        for u in all_uploads:
            stored = u.get('stored_path', '')
            if stored and os.path.isfile(stored):
                try:
                    os.remove(stored)
                    deleted_files += 1
                except OSError:
                    pass
        # Clear all registry records in one shot
        from src.webapp.db_registry import _connect as _registry_connect
        rc = _registry_connect()
        rc.execute("DELETE FROM pcap_uploads")
        rc.commit()
        rc.close()

        # 2. Wipe all analysis tables (keep geo_cache for re-use)
        ac = _analysis_connect()
        ac.executescript("""
            DELETE FROM whatsapp_packets;
            DELETE FROM parties;
            DELETE FROM sessions;
            DELETE FROM correlation_results;
            DELETE FROM batch_metrics;
        """)
        ac.commit()
        ac.close()

        # 3. Clear case-isolated raw and derived evidence roots.
        for root in (app.config['RAW_PCAP_FOLDER'], app.config['FILTERED_PCAP_FOLDER']):
            if os.path.isdir(root):
                for _dir, _subdirs, names in os.walk(root):
                    deleted_files += len(names)
                shutil.rmtree(root)
            os.makedirs(root, exist_ok=True)

        return jsonify({
            'status': 'reset',
            'batches_cleared': len(set(u.get('batch_id') for u in all_uploads if u.get('batch_id'))),
            'files_deleted': deleted_files,
        })


    @app.route('/api/delete/upload/<upload_id>', methods=['POST'])
    def api_delete_upload(upload_id):
        from src.webapp.db_registry import delete_upload
        delete_upload(upload_id)
        return jsonify({'status': 'deleted'})

    @app.route('/api/evidence/raw', methods=['GET'])
    def api_evidence_raw():
        return jsonify({'files': list_raw_evidence()})

    @app.route('/api/evidence/filtered', methods=['GET'])
    def api_evidence_filtered():
        return jsonify({'files': list_filtered_evidence()})

    @app.route('/api/evidence/<upload_id>', methods=['DELETE'])
    def api_delete_evidence(upload_id):
        mode = request.args.get('mode', 'complete')
        if mode not in ('complete', 'raw_only', 'filtered_only'):
            return jsonify({'error': 'Invalid deletion mode'}), 400
        try:
            if not delete_evidence_copy(upload_id, mode):
                return jsonify({'error': 'Evidence not found'}), 404
            clear_upload_packets(upload_id)
            return jsonify({'status': 'deleted', 'mode': mode})
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400

    @app.route('/api/evidence/delete-selected', methods=['POST'])
    def api_delete_selected_evidence():
        payload = request.get_json(silent=True) or {}
        ids, mode = payload.get('upload_ids', []), payload.get('mode', 'complete')
        if not isinstance(ids, list) or not ids or mode not in ('complete', 'raw_only', 'filtered_only'):
            return jsonify({'error': 'Select one or more files and a valid deletion mode.'}), 400
        deleted = []
        for upload_id in ids:
            if delete_evidence_copy(str(upload_id), mode):
                clear_upload_packets(str(upload_id)); deleted.append(upload_id)
        return jsonify({'status': 'deleted', 'mode': mode, 'upload_ids': deleted})
    @app.route('/api/evidence/<batch_id>/<upload_id>/<kind>', methods=['GET'])
    def api_download_evidence(batch_id, upload_id, kind):
        upload = get_upload(upload_id)
        if not upload or upload.get('batch_id') != batch_id:
            abort(404)
        path = upload.get('stored_path') if kind == 'raw' else upload.get('filtered_path') if kind == 'filtered' else None
        if not path or not os.path.isfile(path):
            abort(404)
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))

    @app.route('/api/evidence/<upload_id>/<kind>', methods=['GET'])
    def api_download_evidence_library(upload_id, kind):
        upload = get_upload(upload_id)
        if not upload:
            abort(404)
        path = upload.get('stored_path') if kind == 'raw' else upload.get('filtered_path') if kind == 'filtered' else None
        if not path or not os.path.isfile(path):
            abort(404)
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))

    @app.route('/api/compare/<batch_id_a>/<batch_id_b>', methods=['GET'])
    def api_compare(batch_id_a, batch_id_b):
        from src.session_comparator import compare_uploads
        from src.geo_plot import generate_map_html
        try:
            # We would need to update compare_uploads to handle batch_id if we want this to work.
            result = compare_uploads(batch_id_a, batch_id_b)
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/export/<batch_id>', methods=['GET'])
    def api_export(batch_id):
        from flask import send_file
        import tempfile
        import json
        
        sessions = get_sessions(batch_id)
        
        fd, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(sessions, f, indent=2)
            
        # Bug 3 fix: The route was missing a return statement, crashing with a Flask 500 error
        return send_file(path, as_attachment=True, download_name=f"whatsapp_case_{batch_id[:8]}_export.json")
            
    # ── Forensic Packet Browser API Endpoints ──────────────────────
    @app.route('/api/packets/files', methods=['GET'])
    def api_evidence_files():
        start_ts, end_ts, error, uploads, default_scope = _filtered_scope()
        if error:
            return jsonify({'error': error}), 400
        upload_ids = [upload['upload_id'] for upload in uploads]
        files = get_file_list(None, start_ts, end_ts, upload_ids=upload_ids) if upload_ids else []
        metadata = {upload['upload_id']: upload for upload in uploads}
        for item in files:
            upload = metadata.get(item['upload_id'], {})
            item['size_bytes'] = upload.get('filtered_size_bytes') or 0
            item['file_format'] = upload.get('filtered_format') or upload.get('file_format') or 'pcap'
        return jsonify({'all': {'view': 'all', 'packet_count': sum(int(item.get('packet_count') or 0) for item in files), 'file_count': len(files)},
                        'files': files, 'scope': {'start_ts': start_ts, 'end_ts': end_ts, 'file_count': len(uploads),
                        'indexed_packet_total': sum(int(item.get('packet_count') or 0) for item in files), 'default_scope': default_scope}})

    @app.route('/api/packets/list', methods=['GET'])
    def api_evidence_packets_list():
        start_ts, end_ts, error, uploads, default_scope = _filtered_scope()
        if error:
            return jsonify({'error': error}), 400
        allowed = {upload['upload_id']: upload for upload in uploads}
        view = request.args.get('view', 'all').lower()
        selected_id = request.args.get('upload_id')
        if view not in ('all', 'file'):
            return jsonify({'error': 'view must be all or file.'}), 400
        if view == 'file':
            if not selected_id or selected_id not in allowed:
                return jsonify({'error': 'Selected filtered evidence is unavailable in this capture range.'}), 404
            selected_ids = [selected_id]
        else:
            selected_ids = list(allowed)
        result = get_packets_paged(None, page=request.args.get('page', 1, type=int),
            per_page=request.args.get('per_page', 100, type=int), confidence=request.args.get('confidence'),
            protocol=request.args.get('protocol'), media_guess=request.args.get('media_guess'), q=request.args.get('q'),
            start_ts=start_ts, end_ts=end_ts, upload_ids=selected_ids, src_ip=request.args.get('src_ip'), dst_ip=request.args.get('dst_ip'), any_ip=request.args.get('any_ip'))
        result['selection'] = {'view': view, 'upload_id': selected_id if view == 'file' else None,
                               'filename': allowed[selected_id]['filename'] if view == 'file' else 'All Filtered Evidence'}
        result['scope'] = {'start_ts': start_ts, 'end_ts': end_ts, 'file_count': len(uploads),
                           'indexed_packet_total': result.get('file_stats', {}).get('total_packets', 0),
                           'default_scope': default_scope}
        return jsonify(result)

    @app.route('/api/packets/detail/<int:row_id>', methods=['GET'])
    def api_evidence_packet_detail(row_id):
        """Return packet evidence only when it belongs to the active filtered-evidence scope."""
        start_ts, end_ts, scope_error, uploads, default_scope = _filtered_scope()
        if scope_error:
            return jsonify({'error': scope_error}), 400
        allowed = {upload['upload_id']: upload for upload in uploads}
        packet = get_packet_detail(row_id)
        selected_id = request.args.get('upload_id')
        if not packet:
            return jsonify({'error': 'Packet no longer exists.'}), 404
        if packet.get('upload_id') not in allowed:
            return jsonify({'error': 'Packet is not available in the active filtered-evidence capture range.'}), 404
        if selected_id and packet.get('upload_id') != selected_id:
            return jsonify({'error': 'Packet does not belong to the selected filtered evidence file.'}), 404
        timestamp = packet.get('timestamp')
        if timestamp is None or timestamp < start_ts or timestamp >= end_ts:
            return jsonify({'error': 'Packet falls outside the active capture range.'}), 404
        trail = build_evidence_trail(packet)
        return jsonify({'packet': packet, 'verdict': trail['verdict'], 'evidence': trail['evidence'],
                        'exclusions': trail['exclusions'], 'summary_narrative': trail['summary_narrative'],
                        'scope': {'start_ts': start_ts, 'end_ts': end_ts, 'file_count': len(uploads),
                                  'default_scope': default_scope}})
    @app.route('/api/packets/<batch_id>/detail/<int:row_id>', methods=['GET'])
    def api_packet_detail(batch_id, row_id):
        packet = get_packet_detail(row_id)
        if not packet or packet.get('batch_id') != batch_id:
            return jsonify({'error': 'Packet not found'}), 404

        trail = build_evidence_trail(packet)
        return jsonify({
            'packet': packet,
            'verdict': trail['verdict'],
            'evidence': trail['evidence'],
            'exclusions': trail['exclusions'],
            'summary_narrative': trail['summary_narrative']
        })

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
