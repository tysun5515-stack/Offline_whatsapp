"""Evidence-library report renderer for validated Filtered_PCAP artifacts."""
import hashlib
import math
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader

from src.geo_mapping import classify_remote_party
from src.party_grouper import group_into_entities
from src.webapp.db_analysis import _connect, get_geo

IST = timezone(timedelta(hours=5, minutes=30), name='IST')

RULEBOOK = [
    {'id': 1, 'title': 'Domain Name SNI Matching', 'confidence': 'HIGH',
     'description': 'Checks TLS Server Name Indication for WhatsApp domains such as whatsapp.net and mmg.whatsapp.net.',
     'result': 'Accepted as verified WhatsApp infrastructure.'},
    {'id': 2, 'title': 'IP Infrastructure Matching', 'confidence': 'HIGH',
     'description': 'Checks whether endpoints belong to Meta/WhatsApp infrastructure and verified CIDR/ASN allocations.',
     'result': 'Accepted as WhatsApp infrastructure evidence.'},
    {'id': 3, 'title': 'WhatsApp Signalling and STUN Ports', 'confidence': 'HIGH / MEDIUM',
     'description': 'Checks known WhatsApp signalling ports and STUN/TURN negotiation on UDP port 3478.',
     'result': 'Accepted as messaging or call-negotiation evidence when corroborated.'},
    {'id': 4, 'title': 'Behavioural and Same-Server Inference', 'confidence': 'MEDIUM',
     'description': 'Uses corroborated activity and verified-server relationships for related packet flows.',
     'result': 'Accepted only as supporting WhatsApp evidence.'},
]


def _ist(value: float) -> str:
    return datetime.fromtimestamp(value, IST).strftime('%d %b %Y %H:%M:%S IST')


def _utc_ist_now() -> str:
    return datetime.now(IST).strftime('%d %b %Y %H:%M:%S IST')


def _format_bytes(value: Optional[int]) -> str:
    value = int(value or 0)
    if value < 1024:
        return f'{value} B'
    if value < 1024 * 1024:
        return f'{value / 1024:.1f} KB'
    return f'{value / (1024 * 1024):.2f} MB'


def _labelled_pie(data: Dict[str, int], size: int = 200) -> str:
    """Create an offline SVG pie chart with a legend, totals and percentages."""
    filtered = [(str(label), int(value or 0)) for label, value in data.items() if int(value or 0) > 0]
    total = sum(value for _, value in filtered)
    if not total:
        return '<p class="empty-chart">No data is available for this report section.</p>'
    colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#14b8a6', '#ec4899']
    cx = cy = size / 2; radius = size / 2 - 10; angle = 0.0
    slices = [f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" aria-label="Chart">']
    for index, (_, value) in enumerate(filtered):
        fraction = value / total
        if fraction >= 0.999999:
            slices.append(f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="{colors[index % len(colors)]}"/>')
            continue
        start = math.radians(angle)
        angle += fraction * 360
        end = math.radians(angle)
        x1, y1 = cx + radius * math.cos(start), cy + radius * math.sin(start)
        x2, y2 = cx + radius * math.cos(end), cy + radius * math.sin(end)
        large_arc = 1 if fraction > 0.5 else 0
        slices.append(f'<path d="M {cx} {cy} L {x1} {y1} A {radius} {radius} 0 {large_arc} 1 {x2} {y2} Z" fill="{colors[index % len(colors)]}"/>')
    slices.append('</svg>')
    legend = ['<div class="chart-legend">']
    for index, (label, value) in enumerate(filtered):
        legend.append(f'<div><span class="legend-dot" style="background:{colors[index % len(colors)]}"></span><strong>{label}</strong>: {value:,} ({value / total * 100:.1f}%)</div>')
    legend.append('</div>')
    return '<div class="pie-wrap">' + ''.join(slices) + ''.join(legend) + '</div>'


def _base_where(upload_ids: List[str], start_ts: Optional[float], end_ts: Optional[float]) -> Tuple[str, List[Any]]:
    placeholders = ','.join('?' for _ in upload_ids)
    clauses, params = [f'upload_id IN ({placeholders})'], list(upload_ids)
    if start_ts is not None:
        clauses.append('timestamp >= ?'); params.append(start_ts)
    if end_ts is not None:
        clauses.append('timestamp < ?'); params.append(end_ts)
    return ' AND '.join(clauses), params


def generate_report(uploads: List[Dict[str, Any]], start_ts: Optional[float], end_ts: Optional[float], phases: List[str]) -> str:
    """Render a date-scoped report from validated indexed filtered evidence only."""
    upload_ids = [upload['upload_id'] for upload in uploads]
    if not upload_ids:
        raise ValueError('No filtered evidence was selected for the report.')

    conn = _connect()
    initial_where, initial_params = _base_where(upload_ids, start_ts, end_ts)
    bounds = conn.execute(f'SELECT MIN(timestamp) AS min_ts, MAX(timestamp) AS max_ts FROM whatsapp_packets WHERE {initial_where}', initial_params).fetchone()
    if bounds['min_ts'] is None:
        conn.close()
        raise ValueError('No indexed filtered packets exist in the selected capture range.')
    effective_start = start_ts if start_ts is not None else float(bounds['min_ts'])
    effective_end = end_ts if end_ts is not None else float(bounds['max_ts']) + 0.000001
    where, params = _base_where(upload_ids, effective_start, effective_end)

    metrics = dict(conn.execute(f'''SELECT COUNT(*) AS filtered_packets, COUNT(DISTINCT flow_id) AS total_flows,
        COALESCE(SUM(length), 0) AS total_bytes FROM whatsapp_packets WHERE {where}''', params).fetchone())
    confidence_rows = conn.execute(f'''SELECT COALESCE(LOWER(whatsapp_confidence), 'unknown') AS label, COUNT(*) AS count
        FROM whatsapp_packets WHERE {where} GROUP BY label''', params).fetchall()
    media_rows = conn.execute(f'''SELECT COALESCE(whatsapp_media_guess, sub_activity, 'Unclassified') AS label, COUNT(*) AS count
        FROM whatsapp_packets WHERE {where} GROUP BY label''', params).fetchall()
    flows = [dict(row) for row in conn.execute(f'''SELECT flow_id, MIN(timestamp) AS start_time, MAX(timestamp) AS end_time,
        src_ip, dst_ip, src_port, dst_port, protocol, SUM(length) AS bytes, COUNT(*) AS packets,
        whatsapp_confidence, whatsapp_media_guess
        FROM whatsapp_packets WHERE {where} AND flow_id IS NOT NULL
        GROUP BY flow_id, src_ip, dst_ip, src_port, dst_port, protocol, whatsapp_confidence, whatsapp_media_guess
        ORDER BY start_time LIMIT 200''', params).fetchall()]
    packets = [dict(row) for row in conn.execute(f'SELECT * FROM whatsapp_packets WHERE {where} ORDER BY timestamp', params).fetchall()]
    conn.close()

    for flow in flows:
        flow['start_time_ist'] = _ist(flow['start_time'])

    # Scope calculations never imply that a full-file RAW count is a date-sliced count.
    epsilon = 0.000001
    full_capture_scope = all(
        upload.get('capture_start_ts') is not None and upload.get('capture_end_ts') is not None
        and effective_start <= float(upload['capture_start_ts']) + epsilon
        and effective_end >= float(upload['capture_end_ts']) + epsilon
        for upload in uploads
    )
    source_packet_total = sum(int(upload.get('capture_packet_count') or 0) for upload in uploads)
    filtered_packets = int(metrics['filtered_packets'] or 0)
    metrics.update({
        'source_capture_packets': source_packet_total,
        'filtered_packets': filtered_packets,
        'wa_packets': filtered_packets,
        'true_total_packets': source_packet_total if full_capture_scope else filtered_packets,
        'total_size_kb': round(int(metrics['total_bytes'] or 0) / 1024, 1),
    })

    if full_capture_scope:
        other = max(0, source_packet_total - filtered_packets)
        filtration_chart = _labelled_pie({'WhatsApp Traffic': filtered_packets, 'Other Traffic': other})
        filtration_note = f'Filtering retained {filtered_packets:,} WhatsApp packets from {source_packet_total:,} packets in the selected complete source captures.'
    else:
        distribution = {str(row['label']).replace('_', ' ').title(): int(row['count']) for row in confidence_rows}
        filtration_chart = _labelled_pie(distribution)
        filtration_note = ('The selected date range covers only part of one or more source captures. '
                           'The chart therefore shows confidence distribution for filtered packets in scope; '
                           'a RAW drop ratio is intentionally not calculated.')

    media_counts = {str(row['label']).replace('_', ' ').title(): int(row['count']) for row in media_rows}
    parties = group_into_entities(packets, 'evidence-report', 'unknown') if 'geolocation' in phases else []
    for party in parties:
        geo = get_geo(party['remote_ip']) or {}
        party.update(classify_remote_party(party['remote_ip'], str(geo.get('asn') or ''), geo.get('asn_org'),
                                           party.get('party_type', 'unknown'), party.get('remote_port'), party.get('protocol')))
        party['country'] = geo.get('country', 'Unknown')
        party['asn_org'] = geo.get('asn_org', 'Unknown')

    custody_rows = []
    for upload in uploads:
        custody_rows.append({
            'filename': upload.get('filename'), 'filtered_filename': os.path.basename(upload.get('filtered_path') or ''),
            'raw_sha256': upload.get('sha256_hash') or 'Unavailable', 'filtered_sha256': upload.get('filtered_sha256') or 'Unavailable',
            'raw_format': (upload.get('file_format') or 'PCAP').upper(), 'filtered_format': (upload.get('filtered_format') or 'PCAP').upper(),
            'raw_size': _format_bytes(upload.get('size_bytes')), 'filtered_size': _format_bytes(upload.get('filtered_size_bytes')),
            'capture_window': f"{_ist(upload['capture_start_ts'])} to {_ist(upload['capture_end_ts'])}" if upload.get('capture_start_ts') is not None and upload.get('capture_end_ts') is not None else 'Unavailable',
            'source_packets': upload.get('capture_packet_count') or 0, 'filtered_packets': upload.get('filtered_packet_count') or 0,
            'filtered_created_at': upload.get('filtered_created_at') or 'Unavailable',
        })

    report_seed = '|'.join(sorted(upload_ids) + [f'{effective_start:.6f}', f'{effective_end:.6f}'])
    report_id = hashlib.sha256(report_seed.encode('utf-8')).hexdigest()[:12].upper()
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
    return env.get_template('report.html').render(
        report_id=report_id, generated_at=_utc_ist_now(), range_start=_ist(effective_start), range_end=_ist(effective_end - epsilon),
        files=uploads, phases=phases, metrics=metrics, flow_summary=flows, geo_parties=parties,
        filtration_pie=filtration_chart, media_pie=_labelled_pie(media_counts), filtration_note=filtration_note,
        full_capture_scope=full_capture_scope, rulebook=RULEBOOK, bypass_mode=False,
        custody_rows=custody_rows,
    )